import runpy
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def script():
    return runpy.run_path(str(ROOT / 'scripts/collecte_relais.py'))


def test_absent_secrets_never_authorize():
    ns = script()
    assert ns['ready']({}) is False
    env = dict.fromkeys(ns['SECRETS'], 'synthetic')
    assert ns['ready'](env) is False
    env['ACTIVE_GENERATION'] = ns['GENERATION']
    assert ns['ready'](env) is True


def test_bootstrap_single_successor_and_parent_rejected():
    ns = script()
    env = {'GITHUB_REPOSITORY': 'dddur75/robin-core', 'GITHUB_REF': 'refs/heads/main',
           'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_SHA': 'a' * 40, 'GITHUB_RUN_ID': '123',
           'ACTIVE_GENERATION': ns['GENERATION'], 'ORIGIN': 'bootstrap'}
    calls = []
    def read(path):
        if path.endswith('heads/main'):
            return {'object': {'sha': 'a' * 40}}
        return {'id': 42}
    def reconcile(**kwargs):
        calls.append(kwargs)
        return {'skipped_active': False, 'successor': {'workflow_id': 42, 'event': 'workflow_dispatch',
                'head_branch': 'main', 'run_attempt': 1, 'actor': {'login': 'github-actions[bot]'}}}
    assert ns['prepare'](env, read, reconcile, datetime(2026, 10, 9, tzinfo=UTC)) is False
    assert calls[0]['sequence'] == 1
    assert calls[0]['active_prefix'].endswith(ns['GENERATION'] + '-')
    env.update(ORIGIN='relay', CHAIN_ID='123', PARENT_RUN_ID='123', SEQUENCE='1',
               GITHUB_ACTOR='github-actions[bot]')
    with pytest.raises(ValueError):
        ns['prepare'](env, read, reconcile, datetime(2026, 10, 9, tzinfo=UTC))
    assert len(calls) == 1


def test_inert_workflow_delivery_failure_is_visible():
    workflow = yaml.safe_load((ROOT / '.github/workflows/collecte.yml').read_text())
    assert set(workflow[True]) == {'workflow_dispatch'}
    jobs = workflow['jobs']
    assert jobs['relay']['environment'] == 'robin-autonomous-relay-v1'
    assert 'ECHEC_LIVRAISON' in jobs
    assert 'needs.collecte.result' in jobs['ECHEC_LIVRAISON']['if']
    assert 'secrets.ODDS_API_KEY' in str(jobs['collecte'])


def test_control_read_accepts_objects_without_inventory_fields(monkeypatch):
    import subprocess
    ns = script()
    monkeypatch.setattr(subprocess, 'run', lambda *args, **kwargs:
                        subprocess.CompletedProcess(args[0], 0, b'{"id":42}', b''))
    assert ns['read_api']('repos/dddur75/robin-core/actions/workflows/collecte.yml') == {'id': 42}


def test_reconciliation_posts_once_even_when_response_is_ambiguous():
    ns = runpy.run_path(str(ROOT / 'scripts/reconcile_robin_relay_successor.py'))
    calls = []
    successor = {'id': 777, 'display_title': 'robin-collect-relay-' + 'a' * 64 + '-123-2'}
    def api(method, endpoint, fields):
        calls.append((method, endpoint))
        if method == 'POST':
            raise ns['GitHubControlError']('ambiguous')
        return {'total_count': int(len(calls) > 1),
                'workflow_runs': [successor] if len(calls) > 1 else []}
    result = ns['reconcile_successor'](repository='dddur75/robin-core', mode='collect',
             generation='a' * 64, chain_id='123', parent_run_id='124', sequence=2,
             successor_title=successor['display_title'], active_prefix=None, api=api,
             sleeper=lambda _: None)
    assert result['successor']['id'] == 777
    assert sum(method == 'POST' for method, _ in calls) == 1
    assert all('collecte.yml' in endpoint for _, endpoint in calls)


def test_core_cli_context_retains_old_context_and_rejects_wrong_workflow(tmp_path, monkeypatch):
    from tests.capture.test_run_recurring_real_data_cli import _github_environment, cli
    _github_environment(monkeypatch)
    args = cli._parser().parse_args(['--execute', 'ROBIN_AUTONOMOUS_LAB_20261004',
                '--manifest', str(tmp_path / 'manifest'), '--output-directory', str(tmp_path)])
    import os
    cli._validate_context(args, dict(os.environ))
    monkeypatch.setenv('GITHUB_REPOSITORY', 'dddur75/robin-core')
    with pytest.raises(cli.RecurringError):
        cli._validate_context(args, dict(os.environ))
    monkeypatch.setenv('GITHUB_WORKFLOW_REF',
                      'dddur75/robin-core/.github/workflows/collecte.yml@refs/heads/main')
    assert cli._validate_context(args, dict(os.environ))[1] == '424242'


def test_relay_wait_and_lineage_before_capture():
    ns = script()
    env = dict(GITHUB_REPOSITORY='dddur75/robin-core', GITHUB_REF='refs/heads/main',
               GITHUB_RUN_ATTEMPT='1', GITHUB_SHA='a' * 40, GITHUB_RUN_ID='124',
               ACTIVE_GENERATION=ns['GENERATION'], GENERATION=ns['GENERATION'], ORIGIN='relay',
               CHAIN_ID='123', PARENT_RUN_ID='123', SEQUENCE='1', GITHUB_ACTOR='github-actions[bot]')
    parent = dict(id=123, workflow_id=42, head_branch='main', run_attempt=1,
                  event='workflow_dispatch', conclusion='success',
                  display_title='robin-collect-bootstrap-' + ns['GENERATION'] + '-0-0')
    def read(path):
        if path.endswith('heads/main'):
            return {'object': {'sha': 'a' * 40}}
        if path.endswith('collecte.yml'):
            return {'id': 42}
        if path.endswith('/123'):
            return parent
        if path.endswith('deployment-branch-policies'):
            return {'total_count': 1, 'branch_policies': [{'name': 'main'}]}
        return {'protection_rules': [{'type': 'wait_timer', 'wait_timer': 60}],
                'deployment_branch_policy': {'protected_branches': False, 'custom_branch_policies': True}}
    def reconcile(**kwargs):
        assert kwargs['sequence'] == 2
        return {'skipped_active': False, 'successor': dict(workflow_id=42, head_branch='main',
                event='workflow_dispatch', run_attempt=1, actor={'login': 'github-actions[bot]'})}
    assert ns['prepare'](env, read, reconcile, datetime(2026, 10, 9, tzinfo=UTC)) is True
