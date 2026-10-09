"""Jumeau passif : GitHub GET seulement, reconstruction locale sans réseau."""

import argparse
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from datetime import UTC, datetime
from pathlib import Path

REPOSITORY = 'dddur75/robin-stades-ng'
ROOT = Path(__file__).resolve().parents[1]
FILES = {'public-receipt.json', 'robin-real-data.json', 'robin-real-data.csv',
         'robin-real-data.html'}


def github(endpoint):
    token = os.environ.get('NG_ARTIFACTS_READ_TOKEN')
    if not token:
        raise ValueError('NG_ARTIFACTS_READ_TOKEN_ABSENT')
    result = subprocess.run(['gh', 'api', '--method', 'GET', f'repos/{REPOSITORY}/{endpoint}'],
                            env=dict(os.environ, GH_TOKEN=token), capture_output=True)
    if result.returncode:
        raise ValueError('GITHUB_READ_FAILED')
    return result.stdout


def api_json(endpoint):
    return json.loads(github(endpoint))


def inventory():
    artifacts, page = [], 1
    while True:
        payload = api_json(f'actions/artifacts?per_page=100&page={page}')
        artifacts.extend(payload['artifacts'])
        if len(artifacts) >= payload['total_count']:
            break
        if not payload['artifacts']:
            raise ValueError('ARTIFACT_INVENTORY_INCOMPLETE')
        page += 1
    if len({item['id'] for item in artifacts}) != len(artifacts):
        raise ValueError('ARTIFACT_INVENTORY_DUPLICATED')
    return [item for item in artifacts if not item['expired']
            and item['name'].startswith('robin-autonomous-lab-')]


def extract_bundle(data, destination):
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        names = archive.namelist()
        if len(names) != len(FILES) or set(names) != FILES:
            raise ValueError('ARTIFACT_FILE_SET_INVALID')
        destination.mkdir(parents=True)
        for name in sorted(FILES):
            (destination / name).write_bytes(archive.read(name))


def rebuild(code, bundles, output):
    # Un processus par dépôt évite toute réutilisation du module de référence.
    subprocess.run([sys.executable, '-I', str(Path(__file__).resolve()), '--worker',
                    '--code', str(code), '--bundles', str(bundles), '--output', str(output)],
                   check=True, env={key: value for key, value in os.environ.items()
                                    if key not in {'NG_ARTIFACTS_READ_TOKEN', 'GH_TOKEN',
                                                   'GITHUB_TOKEN', 'ODDS_API_KEY', 'THE_ODDS_API_KEY'}
                                    and not key.startswith('R2_')})


def worker(code, bundles, output):
    def no_network(event, args):
        if event in {'socket.connect', 'socket.getaddrinfo', 'subprocess.Popen'}:
            raise RuntimeError('JUMEAU_NETWORK_FORBIDDEN')
    sys.addaudithook(no_network)
    sys.path.insert(0, str(code / 'src'))
    from robin.capture.real_data_explorer import (
        AtomicExplorerStore,
        _source_semantic_sha256,
        validate_source_bundle,
    )
    from robin.capture.real_data_questions import (
        AcquisitionCatalog,
        Selection,
        acquisitions_payload,
        answer_q1,
        compare_selection,
        list_selections,
        to_csv_bytes,
        to_json_bytes,
    )
    output.mkdir(parents=True)
    sources, rejected = [], []
    for path in sorted(bundles.rglob('public-receipt.json')):
        try:
            sources.append(validate_source_bundle(path.parent))
        except BundleValidationError as error:
            if str(error) != 'SOURCE_CARRY_FORWARD_STALE':
                raise
            rejected.append([path.parent.name, str(error)])
    (output / 'rejected.json').write_text(json.dumps(rejected, sort_keys=True) + '\n')
    if not sources:
        raise ValueError('NO_ARTIFACTS')
    sources.sort(key=lambda item: (item.slot_time, int(item.delivery_run_id)))
    store = AtomicExplorerStore(output / 'store', clock=lambda: datetime(2026, 10, 5, tzinfo=UTC))
    seen = {}
    for item in sources:
        identity = (item.run_id, item.slot_start_utc)
        # Les rejeux d'une acquisition doivent porter le même stock normalisé.
        semantic = _source_semantic_sha256(item.snapshot)
        if identity in seen and seen[identity] != semantic:
            raise ValueError('ARTIFACT_REPLAY_COLLISION')
        if identity not in seen:
            store.publish(item.source)
            seen[identity] = semantic
    catalog = AcquisitionCatalog(store)
    view = catalog.view()
    if view.rejected or len(view.acquisitions) != len(seen):
        raise ValueError('ACQUISITION_REJECTED')
    (output / 'acquisitions.json').write_bytes(to_json_bytes(acquisitions_payload(catalog)))
    q1 = answer_q1(catalog)
    (output / 'q1.json').write_bytes(to_json_bytes(q1))
    (output / 'q1.csv').write_bytes(to_csv_bytes(q1))
    with (output / 'q3.sha256').open('w') as stream:
        for previous, current in zip(view.acquisitions, view.acquisitions[1:]):
            before, after = catalog.rows(previous), catalog.rows(current)
            for event in sorted({str(row['event_id']) for row in (*before, *after)}):
                for selection in list_selections(before, after, event):
                    chosen = Selection(event, selection['market_key'], selection['outcome'],
                                       selection['point'], selection['provider_key'],
                                       selection['settlement_period_key'], selection['sport_key'])
                    payload = compare_selection(previous, before, current, after, chosen)
                    digest = hashlib.sha256(to_json_bytes(payload)).hexdigest()
                    stream.write(json.dumps([previous.run_id, current.run_id, event, selection,
                                             digest], sort_keys=True) + '\n')
    for path in sorted(store.versions.glob('*/public/*')):
        target = output / 'published' / path.relative_to(store.versions)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
    shutil.rmtree(output / 'store')


def compare(reference, candidate):
    def paths(root):
        return {path.relative_to(root).as_posix() for path in root.rglob('*') if path.is_file()}
    left, right = paths(reference), paths(candidate)
    for name in sorted(left | right):
        if name not in left or name not in right:
            return name
        if (reference / name).read_bytes() != (candidate / name).read_bytes():
            return name
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker', action='store_true')
    parser.add_argument('--code', type=Path, default=ROOT)
    parser.add_argument('--bundles', type=Path)
    parser.add_argument('--reference', type=Path)
    parser.add_argument('--output', type=Path, default=Path('reports/jumeau'))
    args = parser.parse_args()
    if args.worker:
        worker(args.code, args.bundles, args.output)
        return 0
    report = {'identical': False, 'first_difference': None, 'reference_sha': None,
              'artifact_count': 0, 'checked_at_utc': datetime.now(UTC).isoformat()}
    try:
        with tempfile.TemporaryDirectory(prefix='jumeau-') as temporary:
            workspace = Path(temporary)
            bundles, reference = args.bundles, args.reference
            if reference is None:
                sha = api_json('commits/main')['sha']
                report['reference_sha'] = sha
                reference = workspace / 'reference-code'
                reference.mkdir()
                with tarfile.open(fileobj=io.BytesIO(github(f'tarball/{sha}'))) as archive:
                    archive.extractall(reference, filter='data')
                reference = next(reference.iterdir())
            if bundles is None:
                bundles = workspace / 'bundles'
                artifacts = inventory()
                report['artifact_count'] = len(artifacts)
                for item in artifacts:
                    extract_bundle(github(f"actions/artifacts/{item['id']}/zip"),
                                   bundles / str(item['id']))
            else:
                report['artifact_count'] = len(list(bundles.rglob('public-receipt.json')))
            for name, code in [('reference', reference), ('candidate', args.code)]:
                rebuild(code, bundles, workspace / name)
            report['first_difference'] = compare(workspace / 'reference', workspace / 'candidate')
            report['identical'] = report['first_difference'] is None
    except Exception as error:
        # Aucun stderr de gh, jeton, chemin privé ni contenu d'artefact dans le rapport.
        report['first_difference'] = str(error) if isinstance(error, ValueError) else type(error).__name__
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / 'rapport.json').write_text(json.dumps(report, indent=2) + '\n')
    (args.output / 'rapport.md').write_text(
        '# Jumeau Robin\n\n' + ('IDENTIQUE' if report['identical'] else 'ECART')
        + f"\n\nPremier écart : {report['first_difference']}\n"
        + f"Artefacts : {report['artifact_count']} ; référence : {report['reference_sha']}\n")
    return 0 if report['identical'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
