import runpy
from datetime import UTC, datetime, timedelta
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 10, 9, 13, tzinfo=UTC)


def script():
    return runpy.run_path(str(ROOT / 'scripts/fraicheur.py'))


def test_replay_does_not_mask_failed_delivery():
    receipts = [{'slot_start_utc': '2026-10-09T12:00:00Z', 'delivery_github_run_id': '123'},
                {'slot_start_utc': '2026-10-09T12:00:00Z', 'delivery_github_run_id': '124'}]
    result = script()['analyze'](receipts, [{'run_id': 123, 'attempt': 1}], NOW)
    assert result['last_slot_start_utc'] == '2026-10-09T12:00:00Z'
    assert result['errors'] == ['ECHEC_LIVRAISON']
    assert result['delivery_failures'][0]['run_id'] == 123


def test_age_uses_slot_not_upload_or_replay_time():
    ns = script()
    receipt = {'slot_start_utc': '2026-10-09T08:00:00Z', 'delivery_generated_at_utc': NOW.isoformat()}
    assert ns['analyze']([receipt], [], NOW)['errors'] == ['CRENEAU_PERIME']
    assert ns['analyze']([], [], NOW)['errors'] == ['AUCUN_CRENEAU_LIVRE']
    receipt['slot_start_utc'] = '2026-10-09T12:00:00Z'
    assert ns['analyze']([receipt], [], NOW)['errors'] == []
    assert ns['analyze']([receipt], [], NOW - timedelta(hours=2))['errors'] == ['CRENEAU_FUTUR']


def test_all_attempts_failure_survives_latest_success():
    jobs = [{'name': 'collecte', 'conclusion': 'failure', 'run_attempt': 1},
            {'name': 'collecte', 'conclusion': 'success', 'run_attempt': 2},
            {'name': 'autorisation', 'conclusion': 'success', 'run_attempt': 2}]
    ns = script()
    assert ns['failed_deliveries'](777, jobs) == [{'run_id': 777, 'attempt': 1}]


def test_inert_and_readonly():
    workflow = yaml.safe_load((ROOT / '.github/workflows/fraicheur.yml').read_text())
    assert set(workflow[True]) == {'workflow_dispatch'}
    assert workflow['permissions'] == {'actions': 'read', 'contents': 'read'}
    assert ' gate' in str(workflow)


def test_monitor_reads_verified_artifact_and_all_job_attempts(tmp_path):
    import io
    import json
    import zipfile

    from tests.capture.test_real_data_explorer import _bundle
    bundle = _bundle(tmp_path / 'bundle', run_id=123,
                     slot=NOW - timedelta(hours=1), price=2.0)
    receipt = json.loads((bundle / 'public-receipt.json').read_text())
    receipt['private_report_r2_status'] = 'VERIFIED'
    (bundle / 'public-receipt.json').write_text(json.dumps(receipt))
    data = io.BytesIO()
    with zipfile.ZipFile(data, 'w') as archive:
        for path in bundle.iterdir():
            archive.writestr(path.name, path.read_bytes())
    calls = []
    def read(endpoint):
        calls.append(endpoint)
        if '/jobs?' in endpoint:
            assert 'filter=all' in endpoint
            return {'total_count': 1, 'jobs': [{'id': 1, 'name': 'collecte',
                    'conclusion': 'failure', 'run_attempt': 1}]}
        if '/runs?' in endpoint:
            return {'total_count': 1, 'workflow_runs': [{'id': 123, 'head_branch': 'main',
                    'event': 'workflow_dispatch', 'updated_at': NOW.isoformat()}]}
        return {'total_count': 1, 'artifacts': [{'id': 77, 'expired': False,
                'name': 'robin-autonomous-lab-123', 'workflow_run': {'head_branch': 'main'}}]}
    report = script()['monitor']('dddur75/robin-core', read, lambda _: data.getvalue(), NOW)
    assert report['slot_age_seconds'] == 3600
    assert report['delivery_failures'] == [{'run_id': 123, 'attempt': 1}]
    assert report['errors'] == ['ECHEC_LIVRAISON']
    assert len(calls) == 3
