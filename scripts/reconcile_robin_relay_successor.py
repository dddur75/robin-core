#!/usr/bin/env python3
"""Dispatch one Robin relay successor and reconcile its unique observation."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from collections.abc import Callable, Mapping
from typing import Any

_REPOSITORY = "dddur75/robin-stades-ng"
_WORKFLOW_ID = "321915839"
_WORKFLOW_PATH = "prospective-deep-scheduler.yml"
_ACTIVE_STATUSES = frozenset({"queued", "in_progress", "requested", "waiting", "pending"})
_GENERATION = re.compile(r"[0-9a-f]{64}")
_RUN_ID = re.compile(r"[1-9][0-9]{0,19}")
_SEQUENCE = re.compile(r"[1-9][0-9]{0,9}")
_READ_ATTEMPTS = 3
_OBSERVATION_ATTEMPTS = 30
_GH_TIMEOUT_SECONDS = 20
_MAX_INVENTORY_PAGES = 20
_MAX_INVENTORY_RUNS = 2_000

Api = Callable[[str, str, dict[str, str] | None], dict[str, object] | None]
Sleeper = Callable[[float], None]


class GitHubControlError(RuntimeError):
    """Fail-closed control-plane error with no provider or R2 effect."""


def _gh_api(
    method: str,
    endpoint: str,
    fields: dict[str, str] | None,
) -> dict[str, object] | None:
    command = ["gh", "api"]
    if method == "POST":
        command.extend(["--method", "POST", "--silent"])
    elif method == "GET":
        command.extend(["--paginate", "--slurp"])
    else:
        raise GitHubControlError("unsupported GitHub method")
    command.append(endpoint)
    if fields:
        for key, value in fields.items():
            command.extend(["-f", f"{key}={value}"])
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=_GH_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise GitHubControlError("GitHub command did not complete") from error
    if completed.returncode != 0:
        raise GitHubControlError("GitHub command returned a failure")
    if method == "POST":
        return None
    if not completed.stdout:
        raise GitHubControlError("GitHub control read was empty")
    try:
        decoded = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise GitHubControlError("GitHub control read was not valid JSON") from error
    return _merge_inventory_pages(decoded)


def _merge_inventory_pages(decoded: object) -> dict[str, object]:
    if (
        not isinstance(decoded, list)
        or not decoded
        or len(decoded) > _MAX_INVENTORY_PAGES
        or any(not isinstance(page, dict) for page in decoded)
    ):
        raise GitHubControlError("GitHub paginated inventory was invalid")
    pages = [dict(page) for page in decoded]
    raw_totals = [page.get("total_count") for page in pages]
    total = raw_totals[0]
    if not isinstance(total, int) or isinstance(total, bool):
        raise GitHubControlError("GitHub paginated inventory total was invalid")
    if any(candidate != total for candidate in raw_totals[1:]):
        raise GitHubControlError("GitHub paginated inventory totals were inconsistent")
    if not 0 <= total <= _MAX_INVENTORY_RUNS:
        raise GitHubControlError("GitHub paginated inventory total was invalid")
    runs: list[dict[str, object]] = []
    for page in pages:
        raw_runs = page.get("workflow_runs")
        if not isinstance(raw_runs, list) or any(not isinstance(run, dict) for run in raw_runs):
            raise GitHubControlError("GitHub paginated inventory page was invalid")
        runs.extend(dict(run) for run in raw_runs)
    run_ids = [run.get("id") for run in runs]
    if any(
        not isinstance(run_id, int) or isinstance(run_id, bool) or run_id <= 0 for run_id in run_ids
    ):
        raise GitHubControlError("GitHub paginated inventory run id was invalid")
    if len(runs) != total or len(set(run_ids)) != len(run_ids):
        raise GitHubControlError("GitHub paginated inventory was incomplete or duplicated")
    return {"total_count": total, "workflow_runs": runs}


def _read_json(endpoint: str, *, api: Api, sleeper: Sleeper) -> dict[str, object]:
    for attempt in range(1, _READ_ATTEMPTS + 1):
        try:
            payload = api("GET", endpoint, None)
            if not isinstance(payload, dict):
                raise GitHubControlError("GitHub control read was not a JSON object")
            return payload
        except GitHubControlError as error:
            print(
                f"GitHub API JSON read attempt {attempt}/{_READ_ATTEMPTS} failed: {error}",
                file=sys.stderr,
            )
            if attempt == _READ_ATTEMPTS:
                raise
            sleeper(float(attempt))
    raise AssertionError("unreachable")


def _runs(payload: Mapping[str, object]) -> list[dict[str, object]]:
    raw = payload.get("workflow_runs")
    if not isinstance(raw, list) or any(not isinstance(item, dict) for item in raw):
        raise GitHubControlError("workflow run inventory was invalid")
    return [dict(item) for item in raw]


def _title(run: Mapping[str, object]) -> str:
    value = run.get("display_title")
    if not isinstance(value, str):
        raise GitHubControlError("workflow run title was invalid")
    return value


def _validate_request(
    *,
    repository: str,
    mode: str,
    generation: str,
    chain_id: str,
    parent_run_id: str,
    sequence: int,
    successor_title: str,
    active_prefix: str | None,
) -> None:
    if (
        repository not in {_REPOSITORY, "dddur75/robin-core"}
        or mode not in {"probe", "collect"}
        or _GENERATION.fullmatch(generation) is None
        or _RUN_ID.fullmatch(chain_id) is None
        or _RUN_ID.fullmatch(parent_run_id) is None
        or _SEQUENCE.fullmatch(str(sequence)) is None
    ):
        raise GitHubControlError("relay successor request was invalid")
    expected_title = f"robin-{mode}-relay-{generation}-{chain_id}-{sequence}"
    if successor_title != expected_title:
        raise GitHubControlError("relay successor title was inconsistent")
    if active_prefix is not None and active_prefix != f"robin-{mode}-relay-{generation}-":
        raise GitHubControlError("active relay prefix was inconsistent")


def reconcile_successor(
    *,
    repository: str,
    mode: str,
    generation: str,
    chain_id: str,
    parent_run_id: str,
    sequence: int,
    successor_title: str,
    active_prefix: str | None,
    api: Api = _gh_api,
    sleeper: Sleeper = time.sleep,
) -> dict[str, Any]:
    """Issue at most one POST, then reconcile one exact successor."""

    _validate_request(
        repository=repository,
        mode=mode,
        generation=generation,
        chain_id=chain_id,
        parent_run_id=parent_run_id,
        sequence=sequence,
        successor_title=successor_title,
        active_prefix=active_prefix,
    )
    inventory_endpoint = (
        f"repos/{repository}/actions/workflows/"
        f"{'collecte.yml' if repository == 'dddur75/robin-core' else _WORKFLOW_ID}/runs"
        "?event=workflow_dispatch&per_page=100"
    )
    workflow_path = "collecte.yml" if repository == "dddur75/robin-core" else _WORKFLOW_PATH
    dispatch_endpoint = f"repos/{repository}/actions/workflows/{workflow_path}/dispatches"
    inventory = _runs(_read_json(inventory_endpoint, api=api, sleeper=sleeper))
    if active_prefix is not None and any(
        run.get("status") in _ACTIVE_STATUSES and _title(run).startswith(active_prefix)
        for run in inventory
    ):
        return {"skipped_active": True, "successor": None}
    if any(_title(run) == successor_title for run in inventory):
        raise GitHubControlError("relay successor already existed before dispatch")

    fields = {
        "ref": "main",
        "inputs[mode]": mode,
        "inputs[origin]": "relay",
        "inputs[generation]": generation,
        "inputs[chain_id]": chain_id,
        "inputs[parent_run_id]": parent_run_id,
        "inputs[sequence]": str(sequence),
    }
    try:
        api("POST", dispatch_endpoint, fields)
    except GitHubControlError:
        print(
            "Dispatch result was ambiguous; reconciling the exact successor without retry",
            file=sys.stderr,
        )

    for attempt in range(_OBSERVATION_ATTEMPTS):
        observed = _runs(_read_json(inventory_endpoint, api=api, sleeper=sleeper))
        matches = [run for run in observed if _title(run) == successor_title]
        if len(matches) == 1:
            return {"skipped_active": False, "successor": matches[0]}
        if len(matches) > 1:
            raise GitHubControlError("multiple exact relay successors were observed")
        if attempt + 1 < _OBSERVATION_ATTEMPTS:
            sleeper(2.0)
    raise GitHubControlError("relay successor was not observed within the bound")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Dispatch and reconcile one Robin relay")
    parser.add_argument("--repository", required=True)
    parser.add_argument("--mode", choices=("probe", "collect"), required=True)
    parser.add_argument("--generation", required=True)
    parser.add_argument("--chain-id", required=True)
    parser.add_argument("--parent-run-id", required=True)
    parser.add_argument("--sequence", required=True, type=int)
    parser.add_argument("--successor-title", required=True)
    parser.add_argument("--active-prefix")
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    try:
        result = reconcile_successor(
            repository=arguments.repository,
            mode=arguments.mode,
            generation=arguments.generation,
            chain_id=arguments.chain_id,
            parent_run_id=arguments.parent_run_id,
            sequence=arguments.sequence,
            successor_title=arguments.successor_title,
            active_prefix=arguments.active_prefix,
        )
    except GitHubControlError as error:
        print(f"ROBIN_RELAY_CONTROL_REJECTED: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
