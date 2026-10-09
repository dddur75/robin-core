"""Relais de collecte : bootstrap sans fournisseur, successeur unique avant capture."""

import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'src')]
GENERATION = '4c150973fc3d486e3738f80716019839ac2c4126644849d336e267e6929e6d87'
SECRETS = ('THE_ODDS_API_KEY', 'R2_ACCOUNT_ID', 'R2_ACCESS_KEY_ID',
           'R2_SECRET_ACCESS_KEY', 'R2_BUCKET_NAME')


def ready(env):
    return all(env.get(name) for name in SECRETS) and env.get('ACTIVE_GENERATION') == GENERATION


def prepare(env, read, reconcile, now):
    import hashlib
    repository = env['GITHUB_REPOSITORY']
    if (repository != 'dddur75/robin-core' or env['GITHUB_REF'] != 'refs/heads/main'
            or env['GITHUB_RUN_ATTEMPT'] != '1' or env['ACTIVE_GENERATION'] != GENERATION
            or now >= datetime(2026, 11, 3, 23, 59, 59, tzinfo=UTC)):
        raise ValueError('RELAY_CONTEXT_INVALID_OR_EXPIRED')
    if hashlib.sha256((ROOT / 'configs/execution/robin-autonomous-lab-trigger-recovery-v2-20261005.json').read_bytes()).hexdigest() != GENERATION:
        raise ValueError('RELAY_GENERATION_CHANGED')
    prefix = f'repos/{repository}'
    if read(f'{prefix}/git/ref/heads/main')['object']['sha'] != env['GITHUB_SHA']:
        raise ValueError('RELAY_MAIN_CHANGED')
    workflow_id = read(f'{prefix}/actions/workflows/collecte.yml')['id']
    origin = env.get('ORIGIN') or 'bootstrap'
    run_id = env['GITHUB_RUN_ID']
    chain, sequence = run_id, 1
    if origin == 'relay':
        chain, parent_id, sequence = env['CHAIN_ID'], env['PARENT_RUN_ID'], int(env['SEQUENCE'])
        if (env.get('GITHUB_ACTOR') != 'github-actions[bot]' or sequence < 1
                or parent_id == run_id or env.get('GENERATION') != GENERATION):
            raise ValueError('RELAY_PARENT_INVALID')
        parent = read(f'{prefix}/actions/runs/{parent_id}')
        if (str(parent['id']) != parent_id or parent['workflow_id'] != workflow_id
                or parent['head_branch'] != 'main' or parent['run_attempt'] != 1
                or parent['event'] not in {'workflow_dispatch', 'schedule'}):
            raise ValueError('RELAY_PARENT_INVALID')
        if sequence == 1:
            if (chain != parent_id or parent['conclusion'] != 'success'
                    or parent['display_title'] != f'robin-collect-bootstrap-{GENERATION}-0-0'):
                raise ValueError('RELAY_BOOTSTRAP_INVALID')
        else:
            if (parent['display_title'] != f'robin-collect-relay-{GENERATION}-{chain}-{sequence - 1}'
                    or parent['actor']['login'] != 'github-actions[bot]'):
                raise ValueError('RELAY_LINEAGE_INVALID')
            jobs = read(f'{prefix}/actions/runs/{parent_id}/jobs?per_page=100')['jobs']
            if sum(job['name'] == 'relay' and job['conclusion'] == 'success' for job in jobs) != 1:
                raise ValueError('RELAY_PARENT_NOT_ARMED')
        environment = read(f'{prefix}/environments/robin-autonomous-relay-v1')
        waits = [rule['wait_timer'] for rule in environment['protection_rules']
                 if rule['type'] == 'wait_timer']
        policies = read(f'{prefix}/environments/robin-autonomous-relay-v1/deployment-branch-policies')
        if (waits != [60] or environment['deployment_branch_policy'] != {
                'protected_branches': False, 'custom_branch_policies': True}
                or policies['total_count'] != 1 or policies['branch_policies'][0]['name'] != 'main'):
            raise ValueError('RELAY_WAIT_OR_BRANCH_POLICY_INVALID')
        sequence += 1
    elif origin != 'bootstrap':
        raise ValueError('RELAY_ORIGIN_INVALID')
    result = reconcile(repository=repository, mode='collect', generation=GENERATION,
                       chain_id=chain, parent_run_id=run_id, sequence=sequence,
                       successor_title=f'robin-collect-relay-{GENERATION}-{chain}-{sequence}',
                       active_prefix=f'robin-collect-relay-{GENERATION}-' if origin == 'bootstrap' else None)
    if result['skipped_active']:
        return False
    successor = result['successor']
    if (successor['workflow_id'] != workflow_id or successor['head_branch'] != 'main'
            or successor['event'] != 'workflow_dispatch' or successor['run_attempt'] != 1
            or successor['actor']['login'] != 'github-actions[bot]'):
        raise ValueError('RELAY_SUCCESSOR_INVALID')
    return origin == 'relay'


def delivery(root):
    from robin.capture.real_data_explorer import SOURCE_FILES, validate_source_bundle
    if {path.name for path in root.iterdir()} != set(SOURCE_FILES):
        raise ValueError('DELIVERY_FILE_SET_INVALID')
    receipt = validate_source_bundle(root).receipt
    accounting = receipt['accounting']
    if (receipt['private_report_r2_status'] != 'VERIFIED'
            or not 0 <= receipt['provider_requests_new'] <= 5
            or not 0 <= accounting['rolling_24h_requests'] <= 140
            or not 0 <= accounting['rolling_24h_credits'] <= 280):
        raise ValueError('DELIVERY_READBACK_OR_BUDGET_INVALID')
    return receipt


def read_api(endpoint):
    import subprocess
    result = subprocess.run(['gh', 'api', '--method', 'GET', endpoint], capture_output=True)
    if result.returncode:
        raise ValueError('RELAY_CONTROL_READ_FAILED')
    payload = json.loads(result.stdout)
    if not isinstance(payload, dict):
        raise ValueError('RELAY_CONTROL_READ_INVALID')
    return payload


def main():
    import reconcile_robin_relay_successor as relay
    env = os.environ
    if sys.argv[1] == 'gate':
        active = bool(ready(env))
        with open(env['GITHUB_OUTPUT'], 'a') as stream:
            stream.write(f'ready={str(active).lower()}\n')
        if not active:
            print('INERTE : secrets de collecte ou génération active absents.')
        return 0
    if sys.argv[1] == 'delivery':
        receipt = delivery(Path(env['RUNNER_TEMP']) / 'robin-autonomous-lab')
        with open(env['GITHUB_STEP_SUMMARY'], 'a') as stream:
            stream.write(f"Créneau livré : {receipt['slot_start_utc']} ; R2 VERIFIED ; "
                         f"compteurs : {json.dumps(receipt['accounting'], sort_keys=True)}\n")
        return 0
    collect = prepare(env, read_api, relay.reconcile_successor, datetime.now(UTC))
    with open(env['GITHUB_OUTPUT'], 'a') as stream:
        stream.write(f'collect={str(collect).lower()}\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
