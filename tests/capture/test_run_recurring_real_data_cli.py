from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

import scripts.run_recurring_real_data as cli
from robin.capture.contracts import canonical_json_bytes
from robin.capture.recurring_real_data import RECURRING_CLAIM_IDS, SEED_CLAIM_IDS
from robin.prospective_observatory.chronos_control_plane import ObservedObject
from robin.prospective_observatory.chronos_r2 import LatestProjection

RELAY_GENERATION = "4c150973fc3d486e3738f80716019839ac2c4126644849d336e267e6929e6d87"
WORKFLOW = Path(__file__).resolve().parents[2] / "tests/fixtures/legacy/prospective-deep-scheduler.yml"


@pytest.fixture(autouse=True)
def _authorized_recovery_stub(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        cli,
        "recover_latest_report",
        lambda *_args, **_kwargs: None,
    )


def _github_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_REPOSITORY", "dddur75/robin-stades-ng")
    monkeypatch.setenv("GITHUB_REF", "refs/heads/main")
    monkeypatch.setenv("GITHUB_EVENT_NAME", "workflow_dispatch")
    monkeypatch.setenv("GITHUB_ACTOR", "github-actions[bot]")
    monkeypatch.setenv(
        "GITHUB_WORKFLOW_REF",
        "dddur75/robin-stades-ng/.github/workflows/prospective-deep-scheduler.yml@refs/heads/main",
    )
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    monkeypatch.setenv("GITHUB_RUN_ID", "424242")
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "1")
    monkeypatch.setenv("ROBIN_RELAY_MODE", "collect")
    monkeypatch.setenv("ROBIN_RELAY_ORIGIN", "relay")
    monkeypatch.setenv("ROBIN_RELAY_GENERATION", RELAY_GENERATION)
    monkeypatch.setenv("ROBIN_RELAY_CHAIN_ID", "424200")
    monkeypatch.setenv("ROBIN_RELAY_PARENT_RUN_ID", "424241")
    monkeypatch.setenv("ROBIN_RELAY_SEQUENCE", "2")
    for name, value in cli.SAFETY_LOCKS.items():
        monkeypatch.setenv(name, value)


def _arguments(tmp_path: Path) -> list[str]:
    return [
        "--execute",
        "ROBIN_AUTONOMOUS_LAB_20261004",
        "--manifest",
        str(tmp_path / "manifest.json"),
        "--output-directory",
        str(tmp_path),
    ]


def _row(*, price: float = 1.8) -> dict[str, object]:
    return {
        "slot_start_utc": "2026-10-04T10:00:00Z",
        "sport_key": "soccer_epl",
        "sport_title": "Premier League",
        "capture_time_utc": "2026-10-04T10:17:01Z",
        "source_timestamp_utc": "2026-10-04T10:16:00Z",
        "source_timestamp_origin": "bookmaker_market_last_update",
        "event_id": "event-1",
        "match": "Home — Away",
        "home_team": "Home",
        "away_team": "Away",
        "kickoff_utc": "2026-10-05T18:00:00Z",
        "bookmaker_key": "book-a",
        "bookmaker": "Book A",
        "market_key": "h2h",
        "outcome": "Home",
        "point": None,
        "price": price,
        "quota_remaining": 19_967,
    }


def _report(*, price: float = 1.8, status: str = "REAL_DATA_PARTIAL") -> dict[str, object]:
    row = _row(price=price)
    return {
        "schema_version": "robin-autonomous-lab-private-report-v1",
        "mission_id": "ROBIN_AUTONOMOUS_LAB_20261004",
        "claim_ids": list(RECURRING_CLAIM_IDS),
        "repository_sha": "a" * 40,
        "github_run_id": "424242",
        "relay_lineage": {
            "generation": RELAY_GENERATION,
            "chain_id": "424200",
            "parent_run_id": "424241",
            "sequence": 2,
        },
        "slot_start_utc": "2026-10-04T10:00:00Z",
        "generated_at_utc": "2026-10-04T10:17:02Z",
        "status": status,
        "branches": [
            {
                "sport_key": "soccer_epl",
                "capture_time_utc": row["capture_time_utc"],
                "status": "PARTIAL" if status != "REAL_DATA_FAILED" else "INCOMPLETE",
                "row_count": 1 if status != "REAL_DATA_FAILED" else 0,
                "limitations": [],
                "diagnostic": None,
            }
        ],
        "rows": [row] if status != "REAL_DATA_FAILED" else [],
        "row_count": 1 if status != "REAL_DATA_FAILED" else 0,
        "validated_capture_count": 1 if status != "REAL_DATA_FAILED" else 0,
        "incomplete_branch_count": 0 if status != "REAL_DATA_FAILED" else 1,
        "capture_times_utc": (["2026-10-04T10:17:01Z"] if status != "REAL_DATA_FAILED" else []),
        "source_timestamp_min_utc": (
            "2026-10-04T10:16:00Z" if status != "REAL_DATA_FAILED" else None
        ),
        "source_timestamp_max_utc": (
            "2026-10-04T10:16:00Z" if status != "REAL_DATA_FAILED" else None
        ),
        "match_count": 1 if status != "REAL_DATA_FAILED" else 0,
        "bookmaker_count": 1 if status != "REAL_DATA_FAILED" else 0,
        "accounting": {
            "rolling_24h_requests": 21,
            "rolling_24h_credits": 44,
            "rolling_30d_requests": 21,
            "rolling_30d_credits": 44,
            "lifetime_requests": 21,
            "lifetime_credits": 44,
            "provider_remaining_floor": 19_967,
            "node_key": "private/accounting-node.json",
            "node_sha256": "f" * 64,
            "entries": [{"kind": "HISTORICAL_SEED"}],
        },
        "provider_requests_new": 5,
    }


class FakeStore:
    def __init__(
        self,
        *,
        current: dict[str, object],
        previous: dict[str, object] | None = None,
    ) -> None:
        self.current_key = "private/current.json"
        current_bytes = canonical_json_bytes(current)
        self.objects = {
            self.current_key: ObservedObject(
                data=current_bytes,
                metadata={"sha256": hashlib.sha256(current_bytes).hexdigest()},
            )
        }
        self.latest: LatestProjection | None = None
        if previous is not None:
            previous = dict(previous) | {
                "slot_start_utc": "2026-10-04T08:00:00Z",
                "github_run_id": "414141",
            }
            previous_rows = [
                dict(row)
                | {
                    "slot_start_utc": "2026-10-04T08:00:00Z",
                    "capture_time_utc": "2026-10-04T08:17:01Z",
                    "source_timestamp_utc": "2026-10-04T08:16:00Z",
                }
                for row in previous["rows"]  # type: ignore[index]
            ]
            previous["rows"] = previous_rows
            previous["branches"] = [
                dict(branch) | {"capture_time_utc": "2026-10-04T08:17:01Z"}
                for branch in previous["branches"]  # type: ignore[index]
            ]
            previous["capture_times_utc"] = ["2026-10-04T08:17:01Z"]
            previous["source_timestamp_min_utc"] = "2026-10-04T08:16:00Z"
            previous["source_timestamp_max_utc"] = "2026-10-04T08:16:00Z"
            previous_key = "private/previous.json"
            previous_bytes = canonical_json_bytes(previous)
            self.objects[previous_key] = ObservedObject(
                data=previous_bytes,
                metadata={"sha256": hashlib.sha256(previous_bytes).hexdigest()},
            )
            pointer = canonical_json_bytes(
                {
                    "schema_version": "robin-autonomous-lab-latest-v1",
                    "mission_id": "ROBIN_AUTONOMOUS_LAB_20261004",
                    "slot_start_utc": "2026-10-04T08:00:00Z",
                    "report_key": previous_key,
                    "report_sha256": hashlib.sha256(previous_bytes).hexdigest(),
                    "status": previous["status"],
                }
            )
            self.latest = LatestProjection(data=pointer, metadata={}, etag='"old"')

    def get_latest_projection(self, key: str) -> LatestProjection | None:
        return self.latest if key == cli.LATEST_REPORT_KEY else None

    def get_object(self, key: str) -> ObservedObject | None:
        return self.objects.get(key)


def _receipt(store: FakeStore, status: str) -> dict[str, object]:
    observed = store.objects[store.current_key]
    return {
        "schema_version": "robin-autonomous-lab-public-receipt-v1",
        "mission_id": "ROBIN_AUTONOMOUS_LAB_20261004",
        "claim_ids": list(RECURRING_CLAIM_IDS),
        "status": status,
        "repository_sha": "a" * 40,
        "github_run_id": "424242",
        "relay_lineage": {
            "generation": RELAY_GENERATION,
            "chain_id": "424200",
            "parent_run_id": "424241",
            "sequence": 2,
        },
        "slot_start_utc": "2026-10-04T10:00:00Z",
        "validated_capture_count": 1 if status != "REAL_DATA_FAILED" else 0,
        "incomplete_branch_count": 0 if status != "REAL_DATA_FAILED" else 1,
        "row_count": 1 if status != "REAL_DATA_FAILED" else 0,
        "provider_requests_new": 5,
        "provider_requests_reserved": 5,
        "provider_credits_reserved": 10,
        "credit_bound_valid": True,
        "rolling_24h_requests": 21,
        "rolling_24h_credits": 44,
        "rolling_30d_requests": 21,
        "rolling_30d_credits": 44,
        "lifetime_requests": 21,
        "lifetime_credits": 44,
        "private_report_r2_key": store.current_key,
        "private_report_r2_sha256": hashlib.sha256(observed.data).hexdigest(),
        "private_report_r2_status": "VERIFIED",
        "automatic_retries": 0,
        "purchases": 0,
        "real_bets": 0,
        "backfills": 0,
        "promotions": 0,
    }


def _workflow_validator_source() -> str:
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    validate = next(
        step for step in workflow["jobs"]["capture"]["steps"] if step.get("id") == "validate"
    )
    command = validate["run"]
    marker = "python -I - <<'PY'\n"
    return command.split(marker, 1)[1].rsplit("\nPY", 1)[0]


def _run_workflow_validator(
    runner_temp: Path,
) -> subprocess.CompletedProcess[str]:
    summary = runner_temp / "step-summary.md"
    environment = os.environ.copy()
    environment.update(
        {
            "RUNNER_TEMP": str(runner_temp),
            "GITHUB_SHA": "a" * 40,
            "GITHUB_RUN_ID": "424242",
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_REPOSITORY": "dddur75/robin-stades-ng",
            "GITHUB_STEP_SUMMARY": str(summary),
        }
    )
    return subprocess.run(
        [sys.executable, "-I", "-c", _workflow_validator_source()],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )


def test_cli_delivers_four_normalized_files_and_compares_previous_slot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _github_environment(monkeypatch)
    current = _report(price=2.0)
    store = FakeStore(current=current, previous=_report(price=1.8))
    monkeypatch.setattr(
        cli.ChronosR2ConditionalStore,
        "from_environment",
        lambda _environment: store,
    )
    monkeypatch.setattr(
        cli,
        "run_recurring_real_data",
        lambda *_args, **_kwargs: _receipt(store, "REAL_DATA_PARTIAL"),
    )

    assert cli.main(_arguments(tmp_path)) == 0
    assert {path.name for path in tmp_path.iterdir()} == {
        "public-receipt.json",
        "robin-real-data.json",
        "robin-real-data.csv",
        "robin-real-data.html",
    }
    receipt = json.loads((tmp_path / "public-receipt.json").read_text(encoding="utf-8"))
    assert (
        receipt["normalized_json_sha256"]
        == hashlib.sha256((tmp_path / "robin-real-data.json").read_bytes()).hexdigest()
    )
    assert (
        receipt["csv_sha256"]
        == hashlib.sha256((tmp_path / "robin-real-data.csv").read_bytes()).hexdigest()
    )
    assert (
        receipt["html_sha256"]
        == hashlib.sha256((tmp_path / "robin-real-data.html").read_bytes()).hexdigest()
    )
    html = (tmp_path / "robin-real-data.html").read_text(encoding="utf-8")
    assert '"changed_offer_count":1' in html
    assert "Aucun edge n’est validé" in html
    normalized = json.loads((tmp_path / "robin-real-data.json").read_text(encoding="utf-8"))
    assert normalized["schema_version"] == "robin-real-data-explorer-v2"
    assert "branches" not in normalized
    assert "entries" not in normalized["accounting"]
    assert "node_key" not in normalized["accounting"]
    assert "raw_payload_base64" not in json.dumps(normalized)
    assert '"status":"REAL_DATA_PARTIAL"' in capsys.readouterr().out
    assert receipt["relay_lineage"] == {
        "generation": RELAY_GENERATION,
        "chain_id": "424200",
        "parent_run_id": "424241",
        "sequence": 2,
    }


def test_active_workflow_validator_accepts_real_explorer_delivery_and_rejects_tampering(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _github_environment(monkeypatch)
    delivery = tmp_path / "robin-autonomous-lab"
    delivery.mkdir()
    current = _report(price=2.0)
    store = FakeStore(current=current, previous=_report(price=1.8))
    monkeypatch.setattr(
        cli.ChronosR2ConditionalStore,
        "from_environment",
        lambda _environment: store,
    )
    monkeypatch.setattr(
        cli,
        "run_recurring_real_data",
        lambda *_args, **_kwargs: _receipt(store, "REAL_DATA_PARTIAL"),
    )

    arguments = _arguments(tmp_path)
    arguments[-1] = str(delivery)
    assert cli.main(arguments) == 0

    accepted = _run_workflow_validator(tmp_path)
    assert accepted.returncode == 0, accepted.stderr

    normalized_path = delivery / "robin-real-data.json"
    normalized = json.loads(normalized_path.read_text(encoding="utf-8"))
    normalized["summary"]["row_count"] += 1
    normalized_path.write_text(json.dumps(normalized), encoding="utf-8")

    rejected = _run_workflow_validator(tmp_path)
    assert rejected.returncode != 0
    assert "AssertionError" in rejected.stderr


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("GITHUB_REPOSITORY", "someone/else"),
        ("GITHUB_REF", "refs/heads/not-main"),
        ("GITHUB_EVENT_NAME", "schedule"),
        (
            "GITHUB_WORKFLOW_REF",
            "dddur75/robin-stades-ng/.github/workflows/other.yml@refs/heads/main",
        ),
        ("GITHUB_SHA", "not-a-sha"),
        ("GITHUB_RUN_ID", "0"),
        ("GITHUB_RUN_ATTEMPT", "2"),
        ("GITHUB_ACTOR", "dddur75"),
        ("ROBIN_RELAY_MODE", "probe"),
        ("ROBIN_RELAY_ORIGIN", "bootstrap"),
        ("ROBIN_RELAY_GENERATION", "0" * 64),
        ("ROBIN_RELAY_CHAIN_ID", "not-a-run-id"),
        ("ROBIN_RELAY_PARENT_RUN_ID", ""),
        ("ROBIN_RELAY_PARENT_RUN_ID", "424242"),
        ("ROBIN_RELAY_SEQUENCE", "0"),
    ],
)
def test_cli_refuses_untrusted_relay_or_rerun_context_before_r2(
    name: str,
    value: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _github_environment(monkeypatch)
    monkeypatch.setenv(name, value)
    touched = False

    def forbidden(_environment: object) -> object:
        nonlocal touched
        touched = True
        raise AssertionError("R2 must remain untouched")

    monkeypatch.setattr(cli.ChronosR2ConditionalStore, "from_environment", forbidden)
    assert cli.main(_arguments(tmp_path)) == 2
    assert touched is False


def test_cli_preserves_failed_slot_artifact_but_returns_terminal_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _github_environment(monkeypatch)
    current = _report(status="REAL_DATA_FAILED")
    store = FakeStore(current=current)
    monkeypatch.setattr(
        cli.ChronosR2ConditionalStore,
        "from_environment",
        lambda _environment: store,
    )
    monkeypatch.setattr(
        cli,
        "run_recurring_real_data",
        lambda *_args, **_kwargs: _receipt(store, "REAL_DATA_FAILED"),
    )

    assert cli.main(_arguments(tmp_path)) == 4
    assert (tmp_path / "public-receipt.json").is_file()
    assert (tmp_path / "robin-real-data.html").is_file()


def test_cli_failed_slot_keeps_current_counts_and_labels_carried_rows_stale(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _github_environment(monkeypatch)
    previous = _report()
    previous["claim_ids"] = list(SEED_CLAIM_IDS)
    store = FakeStore(current=_report(status="REAL_DATA_FAILED"), previous=previous)
    monkeypatch.setattr(
        cli.ChronosR2ConditionalStore,
        "from_environment",
        lambda _environment: store,
    )
    monkeypatch.setattr(
        cli,
        "run_recurring_real_data",
        lambda *_args, **_kwargs: _receipt(store, "REAL_DATA_FAILED"),
    )

    assert cli.main(_arguments(tmp_path)) == 4
    receipt = json.loads((tmp_path / "public-receipt.json").read_text(encoding="utf-8"))
    snapshot = json.loads((tmp_path / "robin-real-data.json").read_text(encoding="utf-8"))
    assert receipt["row_count"] == 0
    assert receipt["display_row_count"] == 1
    assert receipt["display_data_role"] == "CARRY_FORWARD_STALE"
    assert receipt["claim_ids"] == [*RECURRING_CLAIM_IDS, *SEED_CLAIM_IDS]
    assert snapshot["claim_ids"] == [*RECURRING_CLAIM_IDS, *SEED_CLAIM_IDS]
    assert snapshot["rows"][0]["branch_status"] == "STALE"


def test_cli_rejects_corrupt_current_incident_before_using_last_usable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _github_environment(monkeypatch)
    store = FakeStore(current=_report(status="REAL_DATA_FAILED"), previous=_report())
    current = store.objects.pop(store.current_key)
    previous = store.objects["private/previous.json"]
    pointer = canonical_json_bytes(
        {
            "schema_version": "robin-autonomous-lab-latest-v2",
            "mission_id": "ROBIN_AUTONOMOUS_LAB_20261004",
            "slot_start_utc": "2026-10-04T10:00:00Z",
            "report_key": store.current_key,
            "report_sha256": hashlib.sha256(current.data).hexdigest(),
            "status": "REAL_DATA_FAILED",
            "last_usable": {
                "slot_start_utc": "2026-10-04T08:00:00Z",
                "report_key": "private/previous.json",
                "report_sha256": hashlib.sha256(previous.data).hexdigest(),
                "status": "REAL_DATA_PARTIAL",
            },
        }
    )
    store.latest = LatestProjection(data=pointer, metadata={}, etag='"failed"')
    monkeypatch.setattr(
        cli.ChronosR2ConditionalStore,
        "from_environment",
        lambda _environment: store,
    )
    runtime_called = False

    def forbidden(*_args: object, **_kwargs: object) -> dict[str, object]:
        nonlocal runtime_called
        runtime_called = True
        raise AssertionError("runtime must remain untouched")

    monkeypatch.setattr(cli, "run_recurring_real_data", forbidden)
    assert cli.main(_arguments(tmp_path)) == 2
    assert runtime_called is False
    assert not (tmp_path / "public-receipt.json").exists()


def test_previous_report_uses_last_non_empty_after_verified_empty_slot() -> None:
    current = _report(status="REAL_DATA_COMPLETE")
    current["rows"] = []
    current["row_count"] = 0
    current["match_count"] = 0
    current["bookmaker_count"] = 0
    store = FakeStore(current=current, previous=_report())
    current_object = store.objects[store.current_key]
    previous_object = store.objects["private/previous.json"]
    pointer = canonical_json_bytes(
        {
            "schema_version": "robin-autonomous-lab-latest-v2",
            "mission_id": "ROBIN_AUTONOMOUS_LAB_20261004",
            "slot_start_utc": "2026-10-04T10:00:00Z",
            "report_key": store.current_key,
            "report_sha256": hashlib.sha256(current_object.data).hexdigest(),
            "status": "REAL_DATA_COMPLETE",
            "last_usable": {
                "slot_start_utc": "2026-10-04T08:00:00Z",
                "report_key": "private/previous.json",
                "report_sha256": hashlib.sha256(previous_object.data).hexdigest(),
                "status": "REAL_DATA_PARTIAL",
            },
        }
    )
    store.latest = LatestProjection(data=pointer, metadata={}, etag='"empty"')

    selected = cli._previous_report(store)

    assert selected is not None
    assert selected["slot_start_utc"] == "2026-10-04T08:00:00Z"
    assert selected["row_count"] == 1


def test_cli_recovers_carry_forward_when_latest_was_missing_at_start(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _github_environment(monkeypatch)
    store = FakeStore(current=_report(status="REAL_DATA_FAILED"), previous=_report())
    store.latest = None
    previous = store.objects["private/previous.json"]
    current = store.objects[store.current_key]
    monkeypatch.setattr(
        cli.ChronosR2ConditionalStore,
        "from_environment",
        lambda _environment: store,
    )

    def recover_latest(*_args: object, **_kwargs: object) -> dict[str, object]:
        store.latest = LatestProjection(
            data=canonical_json_bytes(
                {
                    "schema_version": "robin-autonomous-lab-latest-v2",
                    "mission_id": "ROBIN_AUTONOMOUS_LAB_20261004",
                    "slot_start_utc": "2026-10-04T10:00:00Z",
                    "report_key": store.current_key,
                    "report_sha256": hashlib.sha256(current.data).hexdigest(),
                    "status": "REAL_DATA_FAILED",
                    "last_usable": {
                        "slot_start_utc": "2026-10-04T08:00:00Z",
                        "report_key": "private/previous.json",
                        "report_sha256": hashlib.sha256(previous.data).hexdigest(),
                        "status": "REAL_DATA_PARTIAL",
                    },
                }
            ),
            metadata={},
            etag='"recovered"',
        )
        return _receipt(store, "REAL_DATA_FAILED")

    monkeypatch.setattr(cli, "run_recurring_real_data", recover_latest)
    assert cli.main(_arguments(tmp_path)) == 4
    receipt = json.loads((tmp_path / "public-receipt.json").read_text("utf-8"))
    snapshot = json.loads((tmp_path / "robin-real-data.json").read_text("utf-8"))
    assert receipt["display_data_role"] == "CARRY_FORWARD_STALE"
    assert receipt["display_row_count"] == 1
    assert snapshot["rows"][0]["branch_status"] == "STALE"


def test_cli_repairs_closed_latest_before_reading_previous_for_next_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _github_environment(monkeypatch)
    store = FakeStore(current=_report(price=2.0), previous=_report(price=1.8))
    repaired_pointer = store.latest
    assert repaired_pointer is not None
    store.latest = None
    monkeypatch.setattr(
        cli.ChronosR2ConditionalStore,
        "from_environment",
        lambda _environment: store,
    )
    repair_completed = False

    def recover_latest(
        _config: object,
        *,
        store: FakeStore,
        clock: object,
        historical_receipt_path: Path,
    ) -> None:
        nonlocal repair_completed
        assert callable(clock)
        assert historical_receipt_path.is_absolute()
        store.latest = repaired_pointer
        repair_completed = True

    def next_success(*_args: object, **_kwargs: object) -> dict[str, object]:
        assert repair_completed is True
        current = store.objects[store.current_key]
        store.latest = LatestProjection(
            data=canonical_json_bytes(
                {
                    "schema_version": "robin-autonomous-lab-latest-v2",
                    "mission_id": "ROBIN_AUTONOMOUS_LAB_20261004",
                    "slot_start_utc": "2026-10-04T10:00:00Z",
                    "report_key": store.current_key,
                    "report_sha256": hashlib.sha256(current.data).hexdigest(),
                    "status": "REAL_DATA_PARTIAL",
                    "last_usable": {
                        "slot_start_utc": "2026-10-04T10:00:00Z",
                        "report_key": store.current_key,
                        "report_sha256": hashlib.sha256(current.data).hexdigest(),
                        "status": "REAL_DATA_PARTIAL",
                    },
                }
            ),
            metadata={},
            etag='"next"',
        )
        return _receipt(store, "REAL_DATA_PARTIAL")

    monkeypatch.setattr(cli, "recover_latest_report", recover_latest)
    monkeypatch.setattr(cli, "run_recurring_real_data", next_success)

    assert cli.main(_arguments(tmp_path)) == 0
    html = (tmp_path / "robin-real-data.html").read_text(encoding="utf-8")
    assert '"changed_offer_count":1' in html


def test_cli_rejects_private_report_hash_mismatch_without_delivery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _github_environment(monkeypatch)
    store = FakeStore(current=_report())
    receipt = _receipt(store, "REAL_DATA_PARTIAL")
    receipt["private_report_r2_sha256"] = "0" * 64
    monkeypatch.setattr(
        cli.ChronosR2ConditionalStore,
        "from_environment",
        lambda _environment: store,
    )
    monkeypatch.setattr(
        cli,
        "run_recurring_real_data",
        lambda *_args, **_kwargs: receipt,
    )

    assert cli.main(_arguments(tmp_path)) == 2
    assert not (tmp_path / "public-receipt.json").exists()


def test_cli_emits_only_structured_redacted_unexpected_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _github_environment(monkeypatch)
    store = FakeStore(current=_report())
    monkeypatch.setattr(
        cli.ChronosR2ConditionalStore,
        "from_environment",
        lambda _environment: store,
    )

    def fail(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise OSError(9, "forbidden https://provider.invalid/?apiKey=secret-value")

    monkeypatch.setattr(cli, "run_recurring_real_data", fail)
    assert cli.main(_arguments(tmp_path)) == 3
    stderr = capsys.readouterr().err
    assert "secret-value" not in stderr
    assert "apiKey" not in stderr
    lines = stderr.splitlines()
    assert lines[0] == "RECURRING_UNEXPECTED_FAILURE"
    assert json.loads(lines[1]) == {
        "stage": "RECURRING_RUNTIME",
        "code": "RECURRING_UNEXPECTED_FAILURE",
        "exception_class": "OSError",
        "errno": 9,
        "http_status": None,
    }
