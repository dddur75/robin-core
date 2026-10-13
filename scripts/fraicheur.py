"""Surveille le créneau livré et les incidents de livraison, y compris les rejeux."""

import json
import os
import subprocess
import sys
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'src')]
MAX_SLOT_AGE = 10800  # Créneaux de 2 heures + 1 heure de tolérance.


def instant(value):
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        raise ValueError('FRESHNESS_TIME_INVALID')
    return parsed.astimezone(UTC)


def analyze(receipts, failures, now):
    latest = max((instant(item['slot_start_utc']) for item in receipts), default=None)
    age = (now - latest).total_seconds() if latest else None
    errors = []
    if latest is None:
        errors.append('AUCUN_CRENEAU_LIVRE')
    elif age < 0:
        errors.append('CRENEAU_FUTUR')
    elif age > MAX_SLOT_AGE:
        errors.append('CRENEAU_PERIME')
    if failures:
        errors.append('ECHEC_LIVRAISON')
    return {'last_slot_start_utc': latest.isoformat().replace('+00:00', 'Z') if latest else None,
            'slot_age_seconds': age, 'delivery_failures': failures, 'errors': errors}


def failed_deliveries(run_id, jobs):
    # Toutes les tentatives sont lues ; un nouveau succès ne retire pas le premier échec.
    attempts = {job['run_attempt'] for job in jobs if job['name'] in {'collecte', 'ECHEC_LIVRAISON'}
                and job['conclusion'] in {'failure', 'cancelled', 'timed_out', 'action_required'}}
    return [{'run_id': run_id, 'attempt': attempt} for attempt in sorted(attempts)]


def inventory(endpoint, key, read):
    rows, page = [], 1
    while True:
        separator = '&' if '?' in endpoint else '?'
        payload = read(f'{endpoint}{separator}per_page=100&page={page}')
        rows.extend(payload[key])
        if len(rows) >= payload['total_count']:
            break
        if not payload[key]:
            raise ValueError('FRESHNESS_INVENTORY_INCOMPLETE')
        page += 1
    if len(rows) != payload['total_count'] or len({row['id'] for row in rows}) != len(rows):
        raise ValueError('FRESHNESS_INVENTORY_CHANGED')
    return rows


def monitor(repository, read, download, now):
    from jumeau import extract_bundle

    from robin.capture.real_data_explorer import validate_source_bundle
    if repository != 'dddur75/robin-core':
        raise ValueError('FRESHNESS_REPOSITORY_INVALID')
    prefix = f'repos/{repository}'
    failures = []
    for run in inventory(f'{prefix}/actions/workflows/collecte.yml/runs', 'workflow_runs', read):
        if (run['head_branch'] == 'main' and run['event'] in {'schedule', 'workflow_dispatch'}
                and instant(run['updated_at']) >= now - timedelta(hours=24)):
            jobs = inventory(f"{prefix}/actions/runs/{run['id']}/jobs?filter=all", 'jobs', read)
            failures.extend(failed_deliveries(run['id'], jobs))
    receipts = []
    for artifact in inventory(f'{prefix}/actions/artifacts', 'artifacts', read):
        if (artifact['expired'] or not artifact['name'].startswith('robin-autonomous-lab-')
                or artifact.get('workflow_run', {}).get('head_branch') != 'main'):
            continue
        with tempfile.TemporaryDirectory(prefix='fraicheur-') as temporary:
            bundle = Path(temporary) / 'bundle'
            extract_bundle(download(f"{prefix}/actions/artifacts/{artifact['id']}/zip"), bundle)
            validated = validate_source_bundle(bundle)
            if validated.receipt.get('private_report_r2_status') != 'VERIFIED':
                raise ValueError('FRESHNESS_DELIVERY_NOT_VERIFIED')
            receipts.append(dict(validated.receipt))
    return analyze(receipts, failures, now)


def main():
    from collecte_relais import read_api
    def download(endpoint):
        result = subprocess.run(['gh', 'api', '--method', 'GET', endpoint], capture_output=True)
        if result.returncode:
            raise ValueError('FRESHNESS_ARTIFACT_READ_FAILED')
        return result.stdout
    try:
        report = monitor(os.environ['GITHUB_REPOSITORY'], read_api, download, datetime.now(UTC))
    except Exception as error:
        report = {'errors': ['FRESHNESS_CONTROL_FAILED'], 'exception_class': type(error).__name__}
    text = json.dumps(report, indent=2, sort_keys=True)
    with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as stream:
        stream.write('# Fraîcheur Robin\n\n```json\n' + text + '\n```\n')
    print(text)
    if report['errors']:
        print('::error title=Fraîcheur Robin::' + ', '.join(report['errors']))
    return int(bool(report['errors']))


if __name__ == '__main__':
    raise SystemExit(main())
