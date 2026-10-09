#!/usr/bin/env python3
"""Execute one authorized scheduled slot of the Robin personal laboratory."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

_RUNTIME_SOURCE = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(_RUNTIME_SOURCE))

from robin.capture.contracts import (  # noqa: E402
    CaptureContractError,
    canonical_json_bytes,
    strict_json_loads,
)
from robin.capture.live_transport import (  # noqa: E402
    EnvironmentSecretReader,
    StrictHttpsTransport,
)
from robin.capture.real_data_dashboard import (  # noqa: E402
    build_dashboard_snapshot,
    render_dashboard_csv,
    render_dashboard_html,
)
from robin.capture.real_data_result import _write_exclusive  # noqa: E402
from robin.capture.recurring_real_data import (  # noqa: E402
    LATEST_REPORT_KEY,
    MISSION_ID,
    RecurringConfig,
    RecurringError,
    recover_latest_report,
    run_recurring_real_data,
)
from robin.capture.reprise_collecte import resolve_provider_once  # noqa: E402
from robin.prospective_observatory.chronos_control_plane import (  # noqa: E402
    ObservedObject,
)
from robin.prospective_observatory.chronos_r2 import (  # noqa: E402
    ChronosR2ConditionalStore,
    ChronosR2Error,
    LatestProjection,
)

SAFETY_LOCKS = {
    "STORAGE_PAUSED": "true",
    "P3_P4_PAUSED": "true",
    "PRODUCTION_LOCKED": "true",
    "REAL_BETS": "false",
    "NO_BET_DEFAULT": "true",
    "PROMOTION_LOCKED": "true",
    "SOCIAL_PUBLISHING_ENABLED": "false",
    "DEMO_MODE_ENABLED": "false",
    "API_FOOTBALL_CALLS_ALLOWED": "0",
}
_OUTPUT_FILENAMES = (
    "public-receipt.json",
    "robin-real-data.json",
    "robin-real-data.csv",
    "robin-real-data.html",
)
_RELAY_GENERATION = "4c150973fc3d486e3738f80716019839ac2c4126644849d336e267e6929e6d87"
_RELAY_WORKFLOW_REF = (
    "dddur75/robin-stades-ng/.github/workflows/prospective-deep-scheduler.yml@refs/heads/main"
)
_HISTORICAL_RECEIPT_PATH = (
    Path(__file__).resolve().parents[1]
    / "reports/evidence/robin-real-data-result-run-37153158456-public-receipt.json"
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run one recurring Robin data slot")
    parser.add_argument("--execute", required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    return parser


def _required(environment: Mapping[str, str], name: str) -> str:
    value = environment.get(name, "")
    if not value:
        raise RecurringError("RECURRING_GITHUB_CONTEXT_MISSING")
    return value


def _validate_context(
    arguments: argparse.Namespace, environment: Mapping[str, str]
) -> tuple[str, str, int, str, str, int]:
    if arguments.execute != MISSION_ID:
        raise RecurringError("RECURRING_EXECUTION_TOKEN_INVALID")
    if (
        environment.get("GITHUB_REPOSITORY") not in {"dddur75/robin-stades-ng", "dddur75/robin-core"}
        or environment.get("GITHUB_REF") != "refs/heads/main"
        or environment.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
        or environment.get("GITHUB_ACTOR") != "github-actions[bot]"
        or environment.get("GITHUB_WORKFLOW_REF") != (
            "dddur75/robin-core/.github/workflows/collecte.yml@refs/heads/main"
            if environment.get("GITHUB_REPOSITORY") == "dddur75/robin-core"
            else _RELAY_WORKFLOW_REF
        )
        or environment.get("ROBIN_RELAY_MODE") != "collect"
        or environment.get("ROBIN_RELAY_ORIGIN") != "relay"
        or environment.get("ROBIN_RELAY_GENERATION") != _RELAY_GENERATION
    ):
        raise RecurringError("RECURRING_GITHUB_CONTEXT_INVALID")
    repository_sha = _required(environment, "GITHUB_SHA")
    github_run_id = _required(environment, "GITHUB_RUN_ID")
    run_attempt_text = _required(environment, "GITHUB_RUN_ATTEMPT")
    chain_id = _required(environment, "ROBIN_RELAY_CHAIN_ID")
    parent_run_id = _required(environment, "ROBIN_RELAY_PARENT_RUN_ID")
    sequence = _required(environment, "ROBIN_RELAY_SEQUENCE")
    if (
        re.fullmatch(r"[0-9a-f]{40}", repository_sha) is None
        or re.fullmatch(r"[1-9][0-9]{0,19}", github_run_id) is None
        or run_attempt_text != "1"
        or re.fullmatch(r"[1-9][0-9]{0,19}", chain_id) is None
        or re.fullmatch(r"[1-9][0-9]{0,19}", parent_run_id) is None
        or re.fullmatch(r"[1-9][0-9]{0,9}", sequence) is None
        or parent_run_id == github_run_id
    ):
        raise RecurringError("RECURRING_GITHUB_CONTEXT_INVALID")
    output = arguments.output_directory
    if (
        not output.is_absolute()
        or not output.is_dir()
        or output.is_symlink()
        or any((output / name).exists() for name in _OUTPUT_FILENAMES)
    ):
        raise RecurringError("RECURRING_OUTPUT_DIRECTORY_INVALID")
    return repository_sha, github_run_id, 1, chain_id, parent_run_id, int(sequence)


def _mapping(data: bytes, code: str) -> dict[str, object]:
    try:
        value = strict_json_loads(data)
    except CaptureContractError:
        raise RecurringError(code) from None
    if not isinstance(value, dict):
        raise RecurringError(code)
    return cast(dict[str, object], value)


def _timestamp(value: object, code: str) -> datetime:
    if not isinstance(value, str):
        raise RecurringError(code)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise RecurringError(code) from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise RecurringError(code)
    return parsed.astimezone(UTC)


def _verified_report(
    observed: ObservedObject | None,
    *,
    expected_sha256: str,
    expected_slot: object,
    code: str,
) -> dict[str, object]:
    if observed is None or re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None:
        raise RecurringError(code)
    observed_sha = hashlib.sha256(observed.data).hexdigest()
    if observed_sha != expected_sha256 or observed.metadata.get("sha256") != expected_sha256:
        raise RecurringError(code)
    report = _mapping(observed.data, code)
    if (
        report.get("schema_version") != "robin-autonomous-lab-private-report-v1"
        or report.get("mission_id") != MISSION_ID
        or report.get("slot_start_utc") != expected_slot
    ):
        raise RecurringError(code)
    return report


def _previous_report(
    store: ChronosR2ConditionalStore,
) -> dict[str, object] | None:
    pointer: LatestProjection | None = store.get_latest_projection(LATEST_REPORT_KEY)
    if pointer is None:
        return None
    decoded = _mapping(pointer.data, "RECURRING_LATEST_INVALID")
    version = decoded.get("schema_version")
    report_key = decoded.get("report_key")
    report_sha = decoded.get("report_sha256")
    slot = decoded.get("slot_start_utc")
    status = decoded.get("status")
    if (
        version
        not in {
            "robin-autonomous-lab-latest-v1",
            "robin-autonomous-lab-latest-v2",
        }
        or decoded.get("mission_id") != MISSION_ID
        or not isinstance(report_key, str)
        or not isinstance(report_sha, str)
        or not isinstance(status, str)
    ):
        raise RecurringError("RECURRING_LATEST_INVALID")
    _timestamp(slot, "RECURRING_LATEST_INVALID")
    current = _verified_report(
        store.get_object(report_key),
        expected_sha256=report_sha,
        expected_slot=slot,
        code="RECURRING_LATEST_REPORT_INTEGRITY_INVALID",
    )
    if current.get("status") != status:
        raise RecurringError("RECURRING_LATEST_REPORT_INTEGRITY_INVALID")
    row_count = current.get("row_count")
    validated = current.get("validated_capture_count")
    current_usable = (
        status in {"REAL_DATA_COMPLETE", "REAL_DATA_PARTIAL"}
        and isinstance(row_count, int)
        and not isinstance(row_count, bool)
        and row_count > 0
        and isinstance(validated, int)
        and not isinstance(validated, bool)
        and validated > 0
    )
    if version != "robin-autonomous-lab-latest-v2" or current_usable:
        return current

    last_usable = decoded.get("last_usable")
    if last_usable is None:
        return None
    if not isinstance(last_usable, dict):
        raise RecurringError("RECURRING_LATEST_INVALID")
    selected = cast(Mapping[str, object], last_usable)
    previous_key = selected.get("report_key")
    previous_sha = selected.get("report_sha256")
    previous_slot = selected.get("slot_start_utc")
    previous_status = selected.get("status")
    if (
        not isinstance(previous_key, str)
        or not isinstance(previous_sha, str)
        or not isinstance(previous_status, str)
    ):
        raise RecurringError("RECURRING_LATEST_INVALID")
    _timestamp(previous_slot, "RECURRING_LATEST_INVALID")
    previous = _verified_report(
        store.get_object(previous_key),
        expected_sha256=previous_sha,
        expected_slot=previous_slot,
        code="RECURRING_LATEST_REPORT_INTEGRITY_INVALID",
    )
    if previous.get("status") != previous_status:
        raise RecurringError("RECURRING_LATEST_REPORT_INTEGRITY_INVALID")
    return previous


def _current_report(
    store: ChronosR2ConditionalStore,
    receipt: Mapping[str, object],
) -> dict[str, object]:
    report_key = receipt.get("private_report_r2_key")
    report_sha = receipt.get("private_report_r2_sha256")
    if (
        receipt.get("private_report_r2_status") != "VERIFIED"
        or not isinstance(report_key, str)
        or not isinstance(report_sha, str)
    ):
        raise RecurringError("RECURRING_PRIVATE_REPORT_REFERENCE_INVALID")
    report = _verified_report(
        store.get_object(report_key),
        expected_sha256=report_sha,
        expected_slot=receipt.get("slot_start_utc"),
        code="RECURRING_PRIVATE_REPORT_HASH_MISMATCH",
    )
    if any(
        report.get(field) != receipt.get(field)
        for field in ("mission_id", "status", "repository_sha", "github_run_id")
    ):
        raise RecurringError("RECURRING_PRIVATE_REPORT_IDENTITY_MISMATCH")
    return report


def _rows(report: Mapping[str, object]) -> tuple[dict[str, object], ...]:
    value = report.get("rows")
    if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
        raise RecurringError("RECURRING_NORMALIZED_DERIVATION_INVALID")
    return tuple(cast(dict[str, object], row) for row in value)


def _deliver(
    *,
    output_directory: Path,
    receipt: Mapping[str, object],
    current_report: Mapping[str, object],
    previous_report: Mapping[str, object] | None,
    delivery_run_id: str,
    delivery_sha: str,
    generated_at: datetime,
) -> dict[str, object]:
    current_slot = _timestamp(
        current_report.get("slot_start_utc"), "RECURRING_PRIVATE_REPORT_IDENTITY_MISMATCH"
    )
    usable_previous = previous_report
    if (
        previous_report is not None
        and _timestamp(
            previous_report.get("slot_start_utc"), "RECURRING_LATEST_REPORT_INTEGRITY_INVALID"
        )
        >= current_slot
    ):
        usable_previous = None
    try:
        snapshot = build_dashboard_snapshot(
            current_report,
            previous_report=usable_previous,
            generated_at=generated_at,
        )
        normalized_json = canonical_json_bytes(snapshot)
        _rows(current_report)
        csv_bytes = render_dashboard_csv(snapshot)
        html_bytes = render_dashboard_html(snapshot)
    except RecurringError:
        raise
    except Exception:
        raise RecurringError("RECURRING_NORMALIZED_DERIVATION_INVALID") from None
    serialized_snapshot = normalized_json.decode("utf-8")
    if any(
        forbidden in serialized_snapshot
        for forbidden in ("raw_payload_base64", "raw_object_key", '"branches"')
    ):
        raise RecurringError("RECURRING_NORMALIZED_BOUNDARY_INVALID")
    public_receipt = dict(receipt) | {
        "claim_ids": snapshot.get("claim_ids"),
        "delivery_repository_sha": delivery_sha,
        "delivery_github_run_id": delivery_run_id,
        "delivery_generated_at_utc": generated_at.isoformat().replace("+00:00", "Z"),
        "display_data_role": snapshot.get("data_role"),
        "display_data_slot_start_utc": snapshot.get("data_slot_start_utc"),
        "display_row_count": len(cast(list[object], snapshot.get("rows", []))),
        "normalized_json_sha256": hashlib.sha256(normalized_json).hexdigest(),
        "csv_sha256": hashlib.sha256(csv_bytes).hexdigest(),
        "html_sha256": hashlib.sha256(html_bytes).hexdigest(),
    }
    receipt_bytes = canonical_json_bytes(public_receipt)
    _write_exclusive(output_directory / "robin-real-data.json", normalized_json)
    _write_exclusive(output_directory / "robin-real-data.csv", csv_bytes)
    _write_exclusive(output_directory / "robin-real-data.html", html_bytes)
    _write_exclusive(output_directory / "public-receipt.json", receipt_bytes)
    return public_receipt


def _failure_stage(code: str) -> str:
    if "GITHUB" in code or "EXECUTION_TOKEN" in code:
        return "GITHUB_CONTEXT"
    if "MANIFEST" in code or "AUTHORITY" in code:
        return "MISSION_AUTHORITY"
    if "R2" in code or "REPORT" in code or "LATEST" in code:
        return "R2_READBACK"
    if "DNS" in code:
        return "DNS_RESOLUTION"
    if "PROVIDER" in code:
        return "PROVIDER_ACCESS"
    if "NORMALIZED" in code or "OUTPUT" in code:
        return "NORMALIZED_DELIVERY"
    return "RECURRING_RUNTIME"


def _emit_failure_diagnostic(code: str, error: BaseException) -> None:
    error_number = getattr(error, "errno", None)
    if not isinstance(error_number, int) or isinstance(error_number, bool):
        error_number = None
    print(code, file=sys.stderr)
    print(
        json.dumps(
            {
                "stage": _failure_stage(code),
                "code": code,
                "exception_class": type(error).__name__,
                "errno": error_number,
                "http_status": None,
            },
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ),
        file=sys.stderr,
    )


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    environment = dict(os.environ)
    try:
        (
            repository_sha,
            github_run_id,
            github_run_attempt,
            relay_chain_id,
            relay_parent_run_id,
            relay_sequence,
        ) = _validate_context(arguments, environment)
        safety_environment = {name: environment.get(name, "") for name in SAFETY_LOCKS}
        store = ChronosR2ConditionalStore.from_environment(environment)

        def clock() -> datetime:
            return datetime.now(UTC)

        config = RecurringConfig(
            manifest_path=arguments.manifest,
            output_directory=arguments.output_directory,
            repository_sha=repository_sha,
            github_run_id=github_run_id,
            github_run_attempt=github_run_attempt,
            relay_generation=_RELAY_GENERATION,
            relay_chain_id=relay_chain_id,
            relay_parent_run_id=relay_parent_run_id,
            relay_sequence=relay_sequence,
            safety_environment=safety_environment,
        )
        recover_latest_report(
            config,
            store=store,
            clock=clock,
            historical_receipt_path=_HISTORICAL_RECEIPT_PATH,
        )
        previous_report = _previous_report(store)
        receipt = run_recurring_real_data(
            config,
            store=store,
            transport_factory=lambda active_clock: StrictHttpsTransport(clock=active_clock),
            secret_reader=EnvironmentSecretReader(environment),
            resolver=lambda: resolve_provider_once(clock=clock),
            clock=clock,
        )
        current_report = _current_report(store, receipt)
        if previous_report is None:
            previous_report = _previous_report(store)
        public_receipt = _deliver(
            output_directory=arguments.output_directory,
            receipt=receipt,
            current_report=current_report,
            previous_report=previous_report,
            delivery_run_id=github_run_id,
            delivery_sha=repository_sha,
            generated_at=clock(),
        )
    except ChronosR2Error as error:
        _emit_failure_diagnostic("RECURRING_R2_CONFIGURATION_INVALID", error)
        return 2
    except RecurringError as error:
        _emit_failure_diagnostic(error.code, error)
        return 2
    except Exception as error:
        _emit_failure_diagnostic("RECURRING_UNEXPECTED_FAILURE", error)
        return 3
    print(
        json.dumps(
            public_receipt,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return (
        0
        if public_receipt.get("status") in {"REAL_DATA_COMPLETE", "REAL_DATA_PARTIAL"}
        and isinstance(public_receipt.get("validated_capture_count"), int)
        and cast(int, public_receipt["validated_capture_count"]) > 0
        else 4
    )


if __name__ == "__main__":
    raise SystemExit(main())
