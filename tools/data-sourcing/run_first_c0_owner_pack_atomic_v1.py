#!/usr/bin/env python3
"""Resident First-C0 prefetched-window wait and one-shot Owner Review Pack runner."""

from __future__ import annotations

import argparse
import json
import math
import socket
import sys
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import partial
from pathlib import Path
from typing import cast
from zoneinfo import ZoneInfo

from robin.capture.bootstrap_contracts import (
    FIRST_C0_CANARY_MINIMUM_READY_MARGIN_SECONDS,
    FIRST_C0_H2_PREFETCH_LEAD_SECONDS,
    FIRST_C0_MAXIMUM_LOCAL_WAIT_SECONDS,
    FIRST_C0_MAXIMUM_OPEN_TO_PREFLIGHT_SECONDS,
    FirstC0WindowOpenRevalidationV1,
    RealCaptureWorkspaceReceiptV1,
    RealExecutionMissionManifestV1,
)
from robin.capture.predns_orchestration import (
    FIRST_C0_PREFETCHED_WINDOW_BUNDLE_SCHEMA,
    AtomicRunnerResultV1,
    ClockV1,
    HistoricalMarkerExpectationV1,
    MarkerInspectorV1,
    MonotonicV1,
    PreDnsOrchestrationError,
    RawEvidenceVerifierV1,
    WorkspaceValidatorV1,
    _run_first_c0_owner_review_pack_once_after_owner_gate_v1,
    inspect_provider_markers_read_only_v1,
    load_first_c0_prefetch_handoff_v1,
    load_pre_dns_bundle_v1,
    revalidate_prefetched_window_open_v1,
    verify_raw_official_evidence_v1,
)
from robin.capture.provider_network import ResolverV1
from robin.capture.storage import _safe_read_bounded
from robin.capture.workspace_bootstrap import (
    assert_real_capture_workspace_receipt_current_v1,
    assert_workspace_control_artifact_destination_v1,
    load_tracked_real_execution_mission_manifest_v1,
)

_MAXIMUM_JSON_BYTES = 4_194_304
_EUROPE_PARIS = ZoneInfo("Europe/Paris")
_ZERO_EFFECT_COUNT = 0


@dataclass(frozen=True, slots=True)
class FirstC0OwnerSequenceResultV1:
    status: str
    code: str | None
    recommended_owner_sequence_start_utc: datetime | None
    window_not_before_utc: datetime | None
    window_expires_at_utc: datetime | None
    wait_monotonic_seconds: float
    window_open_receipt: FirstC0WindowOpenRevalidationV1 | None
    window_open_receipt_path: Path | None
    atomic_result: AtomicRunnerResultV1 | None


def _gate_rejected() -> FirstC0OwnerSequenceResultV1:
    return FirstC0OwnerSequenceResultV1(
        status="OWNER_GATE_REJECTED",
        code="EXECUTE_AND_OWNER_PRESENCE_REQUIRED",
        recommended_owner_sequence_start_utc=None,
        window_not_before_utc=None,
        window_expires_at_utc=None,
        wait_monotonic_seconds=0.0,
        window_open_receipt=None,
        window_open_receipt_path=None,
        atomic_result=None,
    )


def _validate_workspace_default(receipt: RealCaptureWorkspaceReceiptV1) -> None:
    assert_real_capture_workspace_receipt_current_v1(receipt)


def _clock_invalid_before_dns(
    *,
    recommended_start: datetime | None,
    window_not_before: datetime,
    window_expires: datetime,
    wait_monotonic_seconds: float,
    receipt: FirstC0WindowOpenRevalidationV1 | None,
    receipt_path: Path | None,
) -> FirstC0OwnerSequenceResultV1:
    return FirstC0OwnerSequenceResultV1(
        status="CLOCK_INVALID_BEFORE_DNS",
        code="FIRST_C0_PREFLIGHT_CLOCK_INVALID",
        recommended_owner_sequence_start_utc=recommended_start,
        window_not_before_utc=window_not_before,
        window_expires_at_utc=window_expires,
        wait_monotonic_seconds=wait_monotonic_seconds,
        window_open_receipt=receipt,
        window_open_receipt_path=receipt_path,
        atomic_result=None,
    )


def _strict_utc_clock(clock: ClockV1) -> datetime:
    value = clock()
    if value.tzinfo is None or value.utcoffset() is None:
        raise PreDnsOrchestrationError("FIRST_C0_WINDOW_CLOCK_INVALID")
    return value.astimezone(UTC)


def _timing_rejected(atomic: AtomicRunnerResultV1) -> bool:
    return bool(
        {
            "FIRST_C0_OPEN_TO_PREFLIGHT_BUDGET_EXCEEDED",
            "OWNER_REVIEW_USABLE_MARGIN_INSUFFICIENT",
            "FIRST_C0_PREFLIGHT_CLOCK_INVALID",
        }.intersection(atomic.preflight.errors)
    )


def _run_first_c0_owner_pack_atomic_v1(
    *,
    bundle_directory: Path,
    prefetch_handoff_path: Path | None,
    window_open_receipt_path: Path,
    workspace_receipt: RealCaptureWorkspaceReceiptV1,
    mission_manifest: RealExecutionMissionManifestV1,
    output_binding_path: Path,
    output_pack_directory: Path,
    resolver: ResolverV1,
    marker_inspector: MarkerInspectorV1,
    execute: bool = False,
    owner_present_for_at_least_20_minutes: bool = False,
    binding_ttl_seconds: int = 900,
    clock: ClockV1 = lambda: datetime.now(UTC),
    monotonic: MonotonicV1 = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep,
    workspace_validator: WorkspaceValidatorV1 = _validate_workspace_default,
    raw_evidence_verifier: RawEvidenceVerifierV1 = verify_raw_official_evidence_v1,
    atomic_runner: Callable[
        ...,
        AtomicRunnerResultV1,
    ] = _run_first_c0_owner_review_pack_once_after_owner_gate_v1,
) -> FirstC0OwnerSequenceResultV1:
    """Stay resident from immutable prefetch through preflight and the one pack."""

    if execute is not True or owner_present_for_at_least_20_minutes is not True:
        return _gate_rejected()
    loaded = load_pre_dns_bundle_v1(
        bundle_directory,
        raw_evidence_verifier=raw_evidence_verifier,
    )
    if loaded.workspace_receipt != workspace_receipt or loaded.mission_manifest != mission_manifest:
        raise PreDnsOrchestrationError("FIRST_C0_OWNER_SEQUENCE_AUTHORITY_MISMATCH")
    selected = loaded.campaign_selection.selected_candidate()
    now = _strict_utc_clock(clock)
    initial_monotonic = float(monotonic())
    if not math.isfinite(initial_monotonic):
        return _clock_invalid_before_dns(
            recommended_start=None,
            window_not_before=selected.window_not_before_utc,
            window_expires=selected.window_expires_at_utc,
            wait_monotonic_seconds=0.0,
            receipt=None,
            receipt_path=None,
        )
    if loaded.manifest.get("status") == "CANARY_READY_NOW":
        if selected.window_id == "H2":
            return FirstC0OwnerSequenceResultV1(
                status="STOP_TOO_LATE_BEFORE_DNS",
                code="FIRST_C0_H2_PREFETCH_REQUIRED_BEFORE_WINDOW_OPEN",
                recommended_owner_sequence_start_utc=None,
                window_not_before_utc=selected.window_not_before_utc,
                window_expires_at_utc=selected.window_expires_at_utc,
                wait_monotonic_seconds=0.0,
                window_open_receipt=None,
                window_open_receipt_path=None,
                atomic_result=None,
            )
        try:
            atomic = atomic_runner(
                bundle_directory=bundle_directory,
                workspace_receipt=workspace_receipt,
                mission_manifest=mission_manifest,
                output_binding_path=output_binding_path,
                output_pack_directory=output_pack_directory,
                resolver=resolver,
                marker_inspector=marker_inspector,
                execute=True,
                owner_present_for_review=True,
                binding_ttl_seconds=binding_ttl_seconds,
                clock=clock,
                monotonic=monotonic,
                clock_path_anchor_wall_utc=now,
                clock_path_anchor_monotonic=initial_monotonic,
                workspace_validator=workspace_validator,
                raw_evidence_verifier=raw_evidence_verifier,
            )
        except PreDnsOrchestrationError as error:
            if error.code != "FIRST_C0_PREFLIGHT_CLOCK_INVALID":
                raise
            return _clock_invalid_before_dns(
                recommended_start=None,
                window_not_before=selected.window_not_before_utc,
                window_expires=selected.window_expires_at_utc,
                wait_monotonic_seconds=0.0,
                receipt=None,
                receipt_path=None,
            )
        if "FIRST_C0_PREFLIGHT_CLOCK_INVALID" in atomic.preflight.errors:
            return _clock_invalid_before_dns(
                recommended_start=None,
                window_not_before=selected.window_not_before_utc,
                window_expires=selected.window_expires_at_utc,
                wait_monotonic_seconds=0.0,
                receipt=None,
                receipt_path=None,
            )
        timing_rejected = _timing_rejected(atomic)
        return FirstC0OwnerSequenceResultV1(
            status="STOP_TOO_LATE_BEFORE_DNS" if timing_rejected else atomic.status,
            code=(
                "FIRST_C0_PREFLIGHT_TIMING_REJECTED" if timing_rejected else atomic.hard_stop_code
            ),
            recommended_owner_sequence_start_utc=None,
            window_not_before_utc=selected.window_not_before_utc,
            window_expires_at_utc=selected.window_expires_at_utc,
            wait_monotonic_seconds=0.0,
            window_open_receipt=None,
            window_open_receipt_path=None,
            atomic_result=atomic,
        )
    recommended_start = selected.window_not_before_utc - timedelta(
        seconds=FIRST_C0_H2_PREFETCH_LEAD_SECONDS if selected.window_id == "H2" else 60
    )
    seconds_until_open = (selected.window_not_before_utc - now).total_seconds()
    if (
        loaded.manifest.get("schema_version") != FIRST_C0_PREFETCHED_WINDOW_BUNDLE_SCHEMA
        or loaded.manifest.get("status") != "PREFETCHED_FUTURE_WINDOW"
        or prefetch_handoff_path is None
    ):
        legacy_status: str
        legacy_code: str | None
        if now >= selected.window_expires_at_utc:
            legacy_status = "STOP_EXPIRED_BEFORE_DNS"
            legacy_code = "FIRST_C0_WINDOW_EXPIRED"
        elif seconds_until_open <= 0:
            legacy_status = "STOP_TOO_LATE_BEFORE_DNS"
            legacy_code = "FIRST_C0_PREFETCH_REQUIRED_BEFORE_WINDOW_OPEN"
        else:
            legacy_status = "FUTURE_OWNER_SEQUENCE_PLANNED"
            legacy_code = (
                "PREFETCH_REQUIRED_AT_RECOMMENDED_START"
                if seconds_until_open <= FIRST_C0_MAXIMUM_LOCAL_WAIT_SECONDS
                else None
            )
        return FirstC0OwnerSequenceResultV1(
            status=legacy_status,
            code=legacy_code,
            recommended_owner_sequence_start_utc=recommended_start,
            window_not_before_utc=selected.window_not_before_utc,
            window_expires_at_utc=selected.window_expires_at_utc,
            wait_monotonic_seconds=0.0,
            window_open_receipt=None,
            window_open_receipt_path=None,
            atomic_result=None,
        )
    handoff = load_first_c0_prefetch_handoff_v1(prefetch_handoff_path, loaded)
    post_handoff_wall = _strict_utc_clock(clock)
    post_handoff_monotonic = float(monotonic())
    wall_during_handoff = (post_handoff_wall - now).total_seconds()
    monotonic_during_handoff = post_handoff_monotonic - initial_monotonic
    if (
        not math.isfinite(post_handoff_monotonic)
        or wall_during_handoff < 0
        or monotonic_during_handoff < 0
        or abs(wall_during_handoff - monotonic_during_handoff) > 2.0
    ):
        return _clock_invalid_before_dns(
            recommended_start=handoff.recommended_owner_sequence_start_utc,
            window_not_before=handoff.window_not_before_utc,
            window_expires=handoff.window_expires_at_utc,
            wait_monotonic_seconds=0.0,
            receipt=None,
            receipt_path=None,
        )
    now = post_handoff_wall
    seconds_until_open = (selected.window_not_before_utc - now).total_seconds()
    if now < handoff.prefetched_at_utc:
        raise PreDnsOrchestrationError("FIRST_C0_WINDOW_CLOCK_INVALID")
    if seconds_until_open > FIRST_C0_MAXIMUM_LOCAL_WAIT_SECONDS:
        return FirstC0OwnerSequenceResultV1(
            status="FUTURE_OWNER_SEQUENCE_PLANNED",
            code=None,
            recommended_owner_sequence_start_utc=handoff.recommended_owner_sequence_start_utc,
            window_not_before_utc=handoff.window_not_before_utc,
            window_expires_at_utc=handoff.window_expires_at_utc,
            wait_monotonic_seconds=0.0,
            window_open_receipt=None,
            window_open_receipt_path=None,
            atomic_result=None,
        )
    if selected.usable_expires_at_utc - now < timedelta(
        seconds=(
            FIRST_C0_CANARY_MINIMUM_READY_MARGIN_SECONDS
            + FIRST_C0_MAXIMUM_OPEN_TO_PREFLIGHT_SECONDS
        )
    ):
        return FirstC0OwnerSequenceResultV1(
            status="STOP_TOO_LATE_BEFORE_DNS",
            code="FIRST_C0_OWNER_SEQUENCE_STARTED_TOO_LATE",
            recommended_owner_sequence_start_utc=handoff.recommended_owner_sequence_start_utc,
            window_not_before_utc=handoff.window_not_before_utc,
            window_expires_at_utc=handoff.window_expires_at_utc,
            wait_monotonic_seconds=0.0,
            window_open_receipt=None,
            window_open_receipt_path=None,
            atomic_result=None,
        )
    wait_started_at = now
    wait_started_monotonic = post_handoff_monotonic
    previous_wall = wait_started_at
    previous_monotonic = wait_started_monotonic
    clock_path_valid = True
    for _iteration in range(FIRST_C0_MAXIMUM_LOCAL_WAIT_SECONDS + 2):
        remaining = (handoff.window_not_before_utc - previous_wall).total_seconds()
        if remaining <= 0:
            break
        sleep_seconds = min(1.0, remaining)
        sleeper(sleep_seconds)
        observed_wall = _strict_utc_clock(clock)
        observed_monotonic = float(monotonic())
        wall_delta = (observed_wall - previous_wall).total_seconds()
        monotonic_delta = observed_monotonic - previous_monotonic
        if (
            not math.isfinite(observed_monotonic)
            or wall_delta < 0
            or monotonic_delta < 0
            or abs(wall_delta - monotonic_delta) > 2.0
            or wall_delta > sleep_seconds + 2.0
            or monotonic_delta > sleep_seconds + 2.0
        ):
            clock_path_valid = False
            break
        previous_wall = observed_wall
        previous_monotonic = observed_monotonic
        if (
            observed_wall >= handoff.window_expires_at_utc
            or observed_wall >= loaded.mission_manifest.expires_at
            or observed_wall - handoff.source_observed_at_utc > timedelta(seconds=1800)
        ):
            break
    else:
        clock_path_valid = False
    activation_wall = _strict_utc_clock(clock)
    activation_monotonic = float(monotonic())
    final_wall_delta = (activation_wall - previous_wall).total_seconds()
    final_monotonic_delta = activation_monotonic - previous_monotonic
    if (
        not math.isfinite(activation_monotonic)
        or final_wall_delta < 0
        or final_monotonic_delta < 0
        or abs(final_wall_delta - final_monotonic_delta) > 2.0
    ):
        clock_path_valid = False
    receipt = revalidate_prefetched_window_open_v1(
        loaded=loaded,
        handoff=handoff,
        handoff_path=prefetch_handoff_path,
        output_path=window_open_receipt_path,
        wait_started_at_utc=wait_started_at,
        wait_started_monotonic=wait_started_monotonic,
        clock_path_valid=clock_path_valid,
        clock=lambda: activation_wall,
        monotonic=lambda: activation_monotonic,
        workspace_validator=workspace_validator,
    )
    wait_elapsed = receipt.monotonic_elapsed_seconds
    if receipt.status != "READY_NOW":
        status_by_receipt = {
            "CLOCK_INVALID": "CLOCK_INVALID_BEFORE_DNS",
            "EXPIRED": "STOP_EXPIRED_BEFORE_DNS",
            "STALE": "STOP_STALE_BEFORE_DNS",
            "HARD_STOP": "STOP_TOO_LATE_BEFORE_DNS",
        }
        return FirstC0OwnerSequenceResultV1(
            status=status_by_receipt[receipt.status],
            code=f"FIRST_C0_WINDOW_{receipt.status}",
            recommended_owner_sequence_start_utc=handoff.recommended_owner_sequence_start_utc,
            window_not_before_utc=handoff.window_not_before_utc,
            window_expires_at_utc=handoff.window_expires_at_utc,
            wait_monotonic_seconds=wait_elapsed,
            window_open_receipt=receipt,
            window_open_receipt_path=window_open_receipt_path,
            atomic_result=None,
        )
    try:
        atomic = atomic_runner(
            bundle_directory=bundle_directory,
            workspace_receipt=workspace_receipt,
            mission_manifest=mission_manifest,
            output_binding_path=output_binding_path,
            output_pack_directory=output_pack_directory,
            resolver=resolver,
            marker_inspector=marker_inspector,
            execute=True,
            owner_present_for_review=True,
            binding_ttl_seconds=binding_ttl_seconds,
            prefetch_handoff_path=prefetch_handoff_path,
            window_open_receipt_path=window_open_receipt_path,
            clock=clock,
            monotonic=monotonic,
            clock_path_anchor_wall_utc=receipt.checked_at_utc,
            clock_path_anchor_monotonic=receipt.checked_monotonic,
            workspace_validator=workspace_validator,
            raw_evidence_verifier=raw_evidence_verifier,
        )
    except PreDnsOrchestrationError as error:
        if error.code != "FIRST_C0_PREFLIGHT_CLOCK_INVALID":
            raise
        return _clock_invalid_before_dns(
            recommended_start=handoff.recommended_owner_sequence_start_utc,
            window_not_before=handoff.window_not_before_utc,
            window_expires=handoff.window_expires_at_utc,
            wait_monotonic_seconds=wait_elapsed,
            receipt=receipt,
            receipt_path=window_open_receipt_path,
        )
    if "FIRST_C0_PREFLIGHT_CLOCK_INVALID" in atomic.preflight.errors:
        return _clock_invalid_before_dns(
            recommended_start=handoff.recommended_owner_sequence_start_utc,
            window_not_before=handoff.window_not_before_utc,
            window_expires=handoff.window_expires_at_utc,
            wait_monotonic_seconds=wait_elapsed,
            receipt=receipt,
            receipt_path=window_open_receipt_path,
        )
    status = "STOP_TOO_LATE_BEFORE_DNS" if _timing_rejected(atomic) else atomic.status
    return FirstC0OwnerSequenceResultV1(
        status=status,
        code=(
            "FIRST_C0_PREFLIGHT_TIMING_REJECTED"
            if status != atomic.status
            else atomic.hard_stop_code
        ),
        recommended_owner_sequence_start_utc=handoff.recommended_owner_sequence_start_utc,
        window_not_before_utc=handoff.window_not_before_utc,
        window_expires_at_utc=handoff.window_expires_at_utc,
        wait_monotonic_seconds=wait_elapsed,
        window_open_receipt=receipt,
        window_open_receipt_path=window_open_receipt_path,
        atomic_result=atomic,
    )


def _read(path: Path) -> bytes:
    return _safe_read_bounded(path.absolute(), maximum_bytes=_MAXIMUM_JSON_BYTES)


def _system_resolver(
    host: str,
    port: int,
    family: int,
    socket_type: int,
    protocol: int,
) -> Iterable[tuple[object, ...]]:
    return cast(
        Iterable[tuple[object, ...]],
        socket.getaddrinfo(host, port, family, socket_type, protocol),
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace-receipt", required=True, type=Path)
    parser.add_argument("--mission-manifest", required=True, type=Path)
    parser.add_argument("--pre-dns-bundle", required=True, type=Path)
    parser.add_argument("--prefetch-handoff", type=Path)
    parser.add_argument("--window-open-receipt", required=True, type=Path)
    parser.add_argument("--output-binding", required=True, type=Path)
    parser.add_argument("--output-pack-directory", required=True, type=Path)
    parser.add_argument("--historical-marker", required=True, type=Path)
    parser.add_argument("--historical-marker-manifest-sha256", required=True)
    parser.add_argument("--historical-marker-sha256", required=True)
    parser.add_argument("--historical-marker-acl-sha256", required=True)
    parser.add_argument("--binding-ttl-seconds", type=int, default=900)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--owner-present-for-at-least-20-minutes", action="store_true")
    return parser


def _utc_text(value: datetime | None) -> str | None:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z") if value else None


def _europe_paris_text(value: datetime | None) -> str | None:
    return value.astimezone(_EUROPE_PARIS).isoformat() if value else None


def main() -> int:
    arguments = _parser().parse_args()
    if not arguments.execute or not arguments.owner_present_for_at_least_20_minutes:
        print(
            json.dumps(
                {
                    "status": "OWNER_GATE_REJECTED",
                    "code": "EXECUTE_AND_OWNER_PRESENCE_REQUIRED",
                    "provider_dns": 0,
                    "provider_tcp": 0,
                    "provider_http": 0,
                    "secret_reads": _ZERO_EFFECT_COUNT,
                    "pack_builds": 0,
                    "owner_authorizations": 0,
                    "c0_calls": 0,
                    "effects_complete": True,
                },
                sort_keys=True,
            )
        )
        return 2
    resolver_operations = 0

    def counted_system_resolver(
        host: str,
        port: int,
        family: int,
        socket_type: int,
        protocol: int,
    ) -> Iterable[tuple[object, ...]]:
        nonlocal resolver_operations
        resolver_operations += 1
        return _system_resolver(host, port, family, socket_type, protocol)

    try:
        workspace = RealCaptureWorkspaceReceiptV1.model_validate_json(
            _read(arguments.workspace_receipt)
        )
        assert_real_capture_workspace_receipt_current_v1(workspace)
        mission = load_tracked_real_execution_mission_manifest_v1(
            Path(workspace.runtime_repository_root),
            arguments.mission_manifest,
        )
        assert_workspace_control_artifact_destination_v1(workspace, arguments.output_binding)
        assert_workspace_control_artifact_destination_v1(
            workspace,
            arguments.output_pack_directory,
        )
        assert_workspace_control_artifact_destination_v1(
            workspace,
            arguments.window_open_receipt,
        )
        marker_inspector = partial(
            inspect_provider_markers_read_only_v1,
            historical_marker=HistoricalMarkerExpectationV1(
                path=arguments.historical_marker,
                authority_manifest_sha256=arguments.historical_marker_manifest_sha256,
                raw_sha256=arguments.historical_marker_sha256,
                acl_sha256=arguments.historical_marker_acl_sha256,
            ),
        )
        result = _run_first_c0_owner_pack_atomic_v1(
            bundle_directory=arguments.pre_dns_bundle,
            prefetch_handoff_path=arguments.prefetch_handoff,
            window_open_receipt_path=arguments.window_open_receipt,
            workspace_receipt=workspace,
            mission_manifest=mission,
            output_binding_path=arguments.output_binding,
            output_pack_directory=arguments.output_pack_directory,
            resolver=counted_system_resolver,
            marker_inspector=marker_inspector,
            execute=True,
            owner_present_for_at_least_20_minutes=True,
            binding_ttl_seconds=arguments.binding_ttl_seconds,
        )
    except Exception as error:
        print(
            json.dumps(
                {
                    "status": "FAILED",
                    "code": getattr(error, "code", "FIRST_C0_OWNER_SEQUENCE_FAILED"),
                    "provider_dns": resolver_operations,
                    "resolver_operations": resolver_operations,
                    "provider_tcp": 0,
                    "provider_http": 0,
                    "secret_reads": _ZERO_EFFECT_COUNT,
                    "pack_builds": None if resolver_operations else 0,
                    "owner_authorizations": 0,
                    "c0_calls": 0,
                    "effects_complete": resolver_operations == 0,
                },
                sort_keys=True,
            )
        )
        return 2
    atomic = result.atomic_result
    print(
        json.dumps(
            {
                "status": result.status,
                "code": result.code,
                "recommended_owner_sequence_start_utc": _utc_text(
                    result.recommended_owner_sequence_start_utc
                ),
                "recommended_owner_sequence_start_europe_paris": _europe_paris_text(
                    result.recommended_owner_sequence_start_utc
                ),
                "window_not_before_utc": _utc_text(result.window_not_before_utc),
                "window_expires_at_utc": _utc_text(result.window_expires_at_utc),
                "wait_monotonic_seconds": result.wait_monotonic_seconds,
                "window_open_receipt_path": (
                    str(result.window_open_receipt_path)
                    if result.window_open_receipt_path
                    else None
                ),
                "window_open_receipt_sha256": (
                    result.window_open_receipt.canonical_receipt_sha256
                    if result.window_open_receipt
                    else None
                ),
                "preflight_errors": atomic.preflight.errors if atomic else (),
                "resolver_operations": atomic.resolver_operations if atomic else 0,
                "pack_builds": atomic.pack_builds if atomic else 0,
                "provider_dns": atomic.resolver_operations if atomic else 0,
                "provider_tcp": 0,
                "provider_http": 0,
                "secret_reads": _ZERO_EFFECT_COUNT,
                "owner_authorizations": 0,
                "c0_calls": 0,
            },
            sort_keys=True,
        )
    )
    return (
        0 if result.status in {"FUTURE_OWNER_SEQUENCE_PLANNED", "OWNER_REVIEW_PACK_CREATED"} else 2
    )


if __name__ == "__main__":
    sys.exit(main())
