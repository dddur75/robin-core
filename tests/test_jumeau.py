import io
import runpy
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from tests.capture.test_real_data_explorer import _bundle

ROOT = Path(__file__).resolve().parents[1]


def script():
    return runpy.run_path(str(ROOT / 'scripts/jumeau.py'))


def test_comparison_names_first_difference(tmp_path):
    reference, candidate = tmp_path / 'ref', tmp_path / 'core'
    reference.mkdir()
    candidate.mkdir()
    (reference / 'q1.json').write_bytes(b'expected')
    (candidate / 'q1.json').write_bytes(b'changed')
    assert script()['compare'](reference, candidate) == 'q1.json'
    (candidate / 'q1.json').write_bytes(b'expected')
    assert script()['compare'](reference, candidate) is None
    (candidate / 'extra').touch()
    assert script()['compare'](reference, candidate) == 'extra'


def test_archive_rejects_extra_paths_and_missing_files(tmp_path):
    for names in [['../public-receipt.json'], ['public-receipt.json']]:
        data = io.BytesIO()
        with zipfile.ZipFile(data, 'w') as archive:
            for name in names:
                archive.writestr(name, '{}')
        with pytest.raises(ValueError):
            script()['extract_bundle'](data.getvalue(), tmp_path / 'output')


def test_rebuild_exhaustive_deterministic_and_replay(tmp_path):
    bundles = tmp_path / 'bundles'
    slot = datetime(2026, 10, 5, tzinfo=UTC)
    for index in range(3):
        _bundle(bundles / str(index), run_id=100 + index,
                slot=slot + timedelta(hours=2 * index), price=2.0 + index / 10)
    ns = script()
    reference, candidate = tmp_path / 'reference', tmp_path / 'candidate'
    ns['rebuild'](ROOT, bundles, reference)
    ns['rebuild'](ROOT, bundles, candidate)
    assert ns['compare'](reference, candidate) is None
    assert (reference / 'q1.csv').is_file()
    assert (reference / 'q3.sha256').read_text().count('\n') == 2
    assert len(list((reference / 'published').rglob('*.html'))) == 3


def test_inventory_reads_all_pages(monkeypatch):
    ns = script()
    calls = []
    def api(endpoint):
        calls.append(endpoint)
        page = int(endpoint.rsplit('=', 1)[1])
        return {'total_count': 101, 'artifacts': [{'id': n, 'name': 'robin-autonomous-lab-x',
                 'expired': False} for n in (range(100) if page == 1 else [100])]}
    ns['inventory'].__globals__['api_json'] = api
    assert len(ns['inventory']()) == 101
    assert len(calls) == 2


def test_missing_token_produces_failure_report(tmp_path, monkeypatch):
    import json
    import sys
    ns = script()
    monkeypatch.delenv('NG_ARTIFACTS_READ_TOKEN', raising=False)
    monkeypatch.setattr(sys, 'argv', ['jumeau', '--output', str(tmp_path)])
    assert ns['main']() == 1
    report = json.loads((tmp_path / 'rapport.json').read_text())
    assert report['first_difference'] == 'NG_ARTIFACTS_READ_TOKEN_ABSENT'
    assert report['identical'] is False


def test_workflow_authorized_scope():
    import yaml
    workflow = yaml.safe_load((ROOT / '.github/workflows/jumeau.yml').read_text())
    triggers = workflow[True]
    assert set(triggers) == {'schedule', 'pull_request', 'workflow_dispatch'}
    assert triggers['schedule'] == [{'cron': '17 */2 * * *'}]
    assert workflow['permissions'] == {'contents': 'read'}
    assert (ROOT / 'scripts/jumeau.py').read_text().count('NG_ARTIFACTS_READ_TOKEN') >= 1


def test_replay_is_deduplicated_and_corruption_fails(tmp_path):
    import json
    import shutil
    ns = script()
    bundles = tmp_path / 'bundles'
    slot = datetime(2026, 10, 5, tzinfo=UTC)
    _bundle(bundles / 'first', run_id=101, slot=slot, price=2.0)
    _bundle(bundles / 'replay', run_id=101, slot=slot, price=2.0, delivery_run_id=102)
    ns['rebuild'](ROOT, bundles, tmp_path / 'result')
    payload = json.loads((tmp_path / 'result/acquisitions.json').read_text())
    assert len(payload['rows']) == 1
    shutil.rmtree(bundles / 'replay')
    (bundles / 'first/robin-real-data.csv').write_bytes(b'corrupted')
    with pytest.raises(Exception):
        ns['rebuild'](ROOT, bundles, tmp_path / 'bad')


def test_stale_artifact_rejection_is_compared(tmp_path):
    import hashlib
    import json
    ns = script()
    bundles = tmp_path / 'bundles'
    slot = datetime(2026, 10, 5, tzinfo=UTC)
    _bundle(bundles / 'valid', run_id=101, slot=slot, price=2.0)
    stale = _bundle(bundles / 'stale', run_id=102, slot=slot, price=2.0)
    snapshot = json.loads((stale / 'robin-real-data.json').read_text())
    snapshot['data_role'] = 'CARRY_FORWARD_STALE'
    data = json.dumps(snapshot).encode()
    (stale / 'robin-real-data.json').write_bytes(data)
    receipt = json.loads((stale / 'public-receipt.json').read_text())
    receipt['normalized_json_sha256'] = hashlib.sha256(data).hexdigest()
    (stale / 'public-receipt.json').write_text(json.dumps(receipt))
    ns['rebuild'](ROOT, bundles, tmp_path / 'result')
    assert json.loads((tmp_path / 'result/rejected.json').read_text()) == [
        ['stale', 'SOURCE_CARRY_FORWARD_STALE']]
