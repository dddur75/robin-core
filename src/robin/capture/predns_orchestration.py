"""Reversible PRE-DNS convergence and atomic one-shot DNS-to-pack execution."""

from __future__ import annotations

import hashlib
import json
import math
import os
import stat
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal, Protocol, TypeAlias, cast
from urllib.parse import parse_qs, urlparse
from zoneinfo import ZoneInfo

from pydantic import BaseModel

from robin.capture import global_claim_boundary as global_claims
from robin.capture.bootstrap_contracts import (
    FIRST_C0_H2_PREFETCH_LEAD_SECONDS,
    FIRST_C0_H2_WINDOW_DURATION_SECONDS,
    FIRST_C0_MAXIMUM_OPEN_TO_PREFLIGHT_SECONDS,
    FIRST_C0_POST_OPEN_SAFETY_RESERVE_SECONDS,
    FIRST_C0_POST_OPEN_TOTAL_BUDGET_SECONDS,
    CampaignLeagueCorpusCountV1,
    CampaignSelectionAuthorityV1,
    CampaignWindowSelectionV1,
    FirstC0CanarySelectionV1,
    FirstC0PrefetchedWindowHandoffV1,
    FirstC0WindowOpenRevalidationV1,
    FixtureTargetSetV1,
    OfficialFixtureTargetV1,
    OwnerReviewPackV1,
    ProviderNetworkBindingV1,
    ProviderNetworkResolutionClaimV1,
    RealCaptureWorkspaceReceiptV1,
    RealExecutionMissionManifestV1,
    ScientificCorpusSnapshotV1,
    canonical_team_name_v1,
    load_campaign_selection_authority_v1,
)
from robin.capture.contracts import (
    CaptureContractError,
    canonical_json_bytes,
    canonical_sha256,
    strict_json_loads,
    strict_json_object,
)
from robin.capture.live_contracts import LIVE_ALLOWED_SPORT_KEYS
from robin.capture.official_schedule_sources import (
    DFB_DATACENTER_HTML_V1,
    LALIGA_PUBLIC_MATCHES_JSON_V1,
    MAXIMUM_SOURCE_AGE,
    OfficialFetchReceipt,
    OfficialFetchResult,
    OfficialScheduleEvidence,
    OfficialScheduleFetcher,
    OfficialScheduleSourceError,
    OfficialSourcePlan,
    OfficialSourceSpec,
    PdfTextExtractor,
    RedirectHop,
    SupportingOfficialRead,
    _extract_laliga_public_subscription,
    build_official_schedule_evidence,
    fetch_official_schedule_source,
    load_official_source_plan_bytes,
    reconcile_official_schedule_evidence,
)
from robin.capture.owner_review_pack import (
    _build_first_c0_owner_review_pack_after_atomic_binding_v1,
    _write_first_c0_owner_review_pack_after_atomic_binding_v1,
    assert_owner_review_pack_completion_current_v1,
)
from robin.capture.provider_network import (
    ResolverV1,
    _prepare_first_c0_provider_network_binding_once_after_atomic_preflight_v1,
    _valid_provider_resolution_claim_marker_v2,
)
from robin.capture.storage import (
    CaptureStorageError,
    validate_exclusive_local_directory_identity,
)
from robin.capture.workspace_bootstrap import (
    WindowsBoundaryInspector,
    assert_real_capture_workspace_receipt_current_v1,
)

PRE_DNS_BUNDLE_SCHEMA = "robin-pre-dns-owner-pack-inputs-v1"
FIRST_C0_CANARY_BUNDLE_SCHEMA = "robin-first-c0-canary-bundle-v1"
FIRST_C0_PREFETCHED_WINDOW_BUNDLE_SCHEMA = "robin-first-c0-prefetched-window-bundle-v1"
FIRST_C0_CANARY_SOURCE_PLAN_SCHEMA = "robin-first-c0-canary-source-plan-v1"
PRE_DNS_ITERATION_LEDGER_SCHEMA = "robin-pre-dns-iteration-ledger-v1"
ATOMIC_RUNNER_RECEIPT_SCHEMA = "robin-atomic-dns-owner-pack-runner-receipt-v1"
MAXIMUM_BUNDLE_ARTIFACT_BYTES = 16_777_216
MINIMUM_READY_MARGIN_SECONDS = 840
SAFETY_CUTOFF_SECONDS = 300
MAXIMUM_FREEZE_TO_SELECTOR_SECONDS = 30.0
MAXIMUM_DNS_TO_PACK_START_SECONDS = 5.0
MAXIMUM_DNS_TO_PACK_COMPLETION_SECONDS = 120.0
OFFICIAL_SCHEDULE_HORIZON_DAYS = 8
_CONTROL_MARKER_NAME = "provider-network-resolution-one-shot-v1.json"
_REVIEW_NAMES = ("DP6", "C4", "C2", "A2")
_PREFETCH_HANDOFF_NAME = "first-c0-prefetched-window-handoff-v1.json"
_WINDOW_OPEN_RECEIPT_NAME = "first-c0-window-open-revalidation-v1.json"

PreDnsStatusV1: TypeAlias = Literal[
    "PRE_DNS_READY_NOW",
    "PRE_DNS_FUTURE_WINDOW_PLANNED",
    "PRE_DNS_CONVERGENCE_EXHAUSTED",
]
RunnerStatusV1: TypeAlias = Literal[
    "PREFLIGHT_ACCEPT",
    "PREFLIGHT_REJECTED",
    "FUTURE_WINDOW_NOT_OPEN",
    "OWNER_REVIEW_PACK_CREATED",
    "POST_DNS_HARD_STOP",
]


class PreDnsOrchestrationError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class ClockV1(Protocol):
    def __call__(self) -> datetime: ...


class MonotonicV1(Protocol):
    def __call__(self) -> float: ...


class _GuardedClockPathV1:
    def __init__(
        self,
        *,
        clock: ClockV1,
        monotonic: MonotonicV1,
        anchor_wall_utc: datetime | None,
        anchor_monotonic: float | None,
    ) -> None:
        if (anchor_wall_utc is None) != (anchor_monotonic is None):
            raise PreDnsOrchestrationError("FIRST_C0_PREFLIGHT_CLOCK_INVALID")
        self._clock = clock
        self._monotonic = monotonic
        self._previous_wall = (
            _utc(anchor_wall_utc, code="FIRST_C0_PREFLIGHT_CLOCK_INVALID")
            if anchor_wall_utc is not None
            else None
        )
        self._last_observed_wall = self._previous_wall
        self._previous_monotonic = float(anchor_monotonic) if anchor_monotonic is not None else None
        if self._previous_monotonic is not None and not math.isfinite(self._previous_monotonic):
            raise PreDnsOrchestrationError("FIRST_C0_PREFLIGHT_CLOCK_INVALID")

    @property
    def last_trusted_wall_utc(self) -> datetime | None:
        return self._previous_wall

    @property
    def last_observed_wall_utc(self) -> datetime | None:
        return self._last_observed_wall

    def clock(self) -> datetime:
        current_wall = _utc(self._clock(), code="FIRST_C0_PREFLIGHT_CLOCK_INVALID")
        self._last_observed_wall = current_wall
        current_monotonic = float(self._monotonic())
        if not math.isfinite(current_monotonic):
            raise PreDnsOrchestrationError("FIRST_C0_PREFLIGHT_CLOCK_INVALID")
        if self._previous_wall is not None and self._previous_monotonic is not None:
            wall_delta = (current_wall - self._previous_wall).total_seconds()
            monotonic_delta = current_monotonic - self._previous_monotonic
            if wall_delta < 0 or monotonic_delta < 0 or abs(wall_delta - monotonic_delta) > 2.0:
                raise PreDnsOrchestrationError("FIRST_C0_PREFLIGHT_CLOCK_INVALID")
        self._previous_wall = current_wall
        self._previous_monotonic = current_monotonic
        return current_wall

    def paired_monotonic(self) -> float:
        if self._previous_monotonic is None:
            self.clock()
        if self._previous_monotonic is None:
            raise PreDnsOrchestrationError("FIRST_C0_PREFLIGHT_CLOCK_INVALID")
        return self._previous_monotonic


class WorkspaceValidatorV1(Protocol):
    def __call__(self, receipt: RealCaptureWorkspaceReceiptV1) -> None: ...


class CorpusEvidenceReaderV1(Protocol):
    def __call__(self) -> bytes: ...


class MarkerInspectorV1(Protocol):
    def __call__(
        self,
        workspace_receipt: RealCaptureWorkspaceReceiptV1,
        mission_manifest: RealExecutionMissionManifestV1,
    ) -> MarkerInspectionV1: ...


class EvidenceBuilderV1(Protocol):
    def __call__(
        self,
        source: OfficialSourceSpec,
        fetch_result: OfficialFetchResult,
        *,
        horizon_not_before_utc: datetime,
        horizon_expires_at_utc: datetime,
        pdf_text_extractor: PdfTextExtractor | None = None,
    ) -> OfficialScheduleEvidence: ...


class BindingPreparerV1(Protocol):
    def __call__(
        self,
        *,
        workspace_receipt: RealCaptureWorkspaceReceiptV1,
        mission_manifest: RealExecutionMissionManifestV1,
        campaign_selection: CampaignSelectionAuthorityV1,
        output_path: Path,
        resolver: ResolverV1,
        clock: Callable[[], datetime],
        binding_ttl_seconds: int,
        expected_global_v2_read_identity: tuple[object, ...],
        expected_global_legacy_root_identity: tuple[object, ...],
        final_pre_effect_assertion: Callable[[], None],
    ) -> ProviderNetworkBindingV1: ...


def _prepare_provider_network_binding_after_atomic_preflight_v1(
    *,
    workspace_receipt: RealCaptureWorkspaceReceiptV1,
    mission_manifest: RealExecutionMissionManifestV1,
    campaign_selection: CampaignSelectionAuthorityV1,
    output_path: Path,
    resolver: ResolverV1,
    clock: Callable[[], datetime],
    binding_ttl_seconds: int,
    expected_global_v2_read_identity: tuple[object, ...],
    expected_global_legacy_root_identity: tuple[object, ...],
    final_pre_effect_assertion: Callable[[], None],
) -> ProviderNetworkBindingV1:
    return _prepare_first_c0_provider_network_binding_once_after_atomic_preflight_v1(
        workspace_receipt=workspace_receipt,
        mission_manifest=mission_manifest,
        campaign_selection=campaign_selection,
        output_path=output_path,
        resolver=resolver,
        clock=clock,
        binding_ttl_seconds=binding_ttl_seconds,
        expected_global_v2_read_identity=expected_global_v2_read_identity,
        expected_global_legacy_root_identity=expected_global_legacy_root_identity,
        final_pre_effect_assertion=final_pre_effect_assertion,
    )


class PackBuilderV1(Protocol):
    def __call__(
        self,
        *,
        workspace_receipt: RealCaptureWorkspaceReceiptV1,
        mission_manifest: RealExecutionMissionManifestV1,
        provider_network_binding: ProviderNetworkBindingV1,
        campaign_selection: CampaignSelectionAuthorityV1,
        generated_at_utc: datetime,
        authorization_nonce: str,
        activation_nonce: str,
    ) -> OwnerReviewPackV1: ...


class PackWriterV1(Protocol):
    def __call__(self, output_directory: Path, pack: OwnerReviewPackV1) -> dict[str, Path]: ...


class RawEvidenceVerifierV1(Protocol):
    def __call__(
        self,
        source: OfficialSourceSpec,
        raw_payload: bytes,
        receipt_payload: bytes,
        evidence_payload: bytes,
        target_set: FixtureTargetSetV1,
        supporting_raw_payloads: tuple[bytes, ...],
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class PreDnsLimitsV1:
    maximum_iterations: int = 4
    maximum_official_reads: int = 20
    maximum_corpus_snapshots: int = 4
    maximum_target_set_freezes: int = 20
    maximum_selector_invocations: int = 4

    def __post_init__(self) -> None:
        if (
            not 1 <= self.maximum_iterations <= 4
            or not 5 <= self.maximum_official_reads <= 20
            or not 1 <= self.maximum_corpus_snapshots <= 4
            or not 5 <= self.maximum_target_set_freezes <= 20
            or not 1 <= self.maximum_selector_invocations <= 4
        ):
            raise ValueError("PRE_DNS_LIMITS_INVALID")


@dataclass(frozen=True, slots=True)
class PreDnsCountersV1:
    iterations: int
    official_reads: int
    supporting_official_reads: int
    corpus_snapshots: int
    corpus_validations: int
    target_set_freezes: int
    selector_invocations: int


@dataclass(frozen=True, slots=True)
class HistoricalMarkerExpectationV1:
    path: Path
    authority_manifest_sha256: str
    raw_sha256: str
    acl_sha256: str | None = None


@dataclass(frozen=True, slots=True)
class MarkerInspectionV1:
    historical_marker_unchanged: bool
    current_marker_present: bool
    historical_raw_sha256: str | None
    historical_acl_sha256: str | None
    historical_marker_path: str
    historical_authority_manifest_sha256: str
    current_authority_manifest_sha256: str
    current_local_marker: str
    current_v2_global_marker: str
    current_legacy_global_marker: str
    current_v2_root_identity: tuple[object, ...] | None = None
    current_legacy_root_identity: tuple[object, ...] | None = None

    def to_json(self) -> dict[str, object]:
        return {
            "schema_version": "robin-provider-marker-readonly-inspection-v2",
            "historical_marker_unchanged": self.historical_marker_unchanged,
            "current_marker_present": self.current_marker_present,
            "historical_raw_sha256": self.historical_raw_sha256,
            "historical_acl_sha256": self.historical_acl_sha256,
            "historical_marker_path": self.historical_marker_path,
            "historical_authority_manifest_sha256": (self.historical_authority_manifest_sha256),
            "current_authority_manifest_sha256": self.current_authority_manifest_sha256,
            "current_local_marker": self.current_local_marker,
            "current_v2_global_marker": self.current_v2_global_marker,
            "current_legacy_global_marker": self.current_legacy_global_marker,
            "filesystem_writes": 0,
        }


@dataclass(frozen=True, slots=True)
class LegacyMarkerInspectionV1:
    historical_marker_unchanged: bool
    current_marker_present: bool
    historical_raw_sha256: str | None
    historical_acl_sha256: str | None
    historical_marker_path: str
    historical_authority_manifest_sha256: str
    current_authority_manifest_sha256: str
    current_local_marker: str
    current_global_marker: str


@dataclass(frozen=True, slots=True)
class FirstC0CanaryMarkerInspectionV1:
    local_marker_path: str
    v2_global_marker_path: str
    legacy_global_marker_path: str
    local_marker_present: Literal[False]
    v2_global_marker_present: Literal[False]
    legacy_global_marker_present: Literal[False]
    inspected_read_only: Literal[True]


@dataclass(frozen=True, slots=True)
class LegacyFirstC0CanaryMarkerInspectionV1:
    local_marker_path: str
    global_marker_path: str
    local_marker_present: Literal[False]
    global_marker_present: Literal[False]
    inspected_read_only: Literal[True]


@dataclass(frozen=True, slots=True)
class FirstC0CanarySourcePlanAuthorityV1:
    source: OfficialSourceSpec
    canonical_sha256: str


@dataclass(frozen=True, slots=True)
class PreDnsResultV1:
    status: PreDnsStatusV1
    selection: CampaignWindowSelectionV1 | None
    bundle_directory: Path | None
    bundle_manifest_sha256: str | None
    recommended_refresh_utc: datetime | None
    recommended_refresh_europe_paris: str | None
    counters: PreDnsCountersV1
    iteration_codes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class LoadedPreDnsBundleV1:
    directory: Path
    manifest: Mapping[str, object]
    manifest_sha256: str
    workspace_receipt: RealCaptureWorkspaceReceiptV1
    mission_manifest: RealExecutionMissionManifestV1
    source_plan: OfficialSourcePlan | FirstC0CanarySourcePlanAuthorityV1
    campaign_selection: CampaignSelectionAuthorityV1
    target_sets: tuple[FixtureTargetSetV1, ...]
    marker_inspection: (
        MarkerInspectionV1
        | LegacyMarkerInspectionV1
        | FirstC0CanaryMarkerInspectionV1
        | LegacyFirstC0CanaryMarkerInspectionV1
    )
    prefetch_handoff: FirstC0PrefetchedWindowHandoffV1 | None = None
    prefetch_handoff_path: Path | None = None
    window_open_receipt: FirstC0WindowOpenRevalidationV1 | None = None
    window_open_receipt_path: Path | None = None


@dataclass(frozen=True, slots=True)
class RunnerPreflightV1:
    accepted: bool
    status: RunnerStatusV1
    errors: tuple[str, ...]
    checked_at_utc: datetime
    usable_margin_seconds: int
    provider_dns: Literal[0] = 0
    provider_tcp: Literal[0] = 0
    provider_http: Literal[0] = 0
    secret_reads: Literal[0] = 0
    global_v2_read_identity: tuple[object, ...] | None = None
    global_legacy_root_identity: tuple[object, ...] | None = None
    historical_marker_binding: MarkerInspectionV1 | None = None


@dataclass(frozen=True, slots=True)
class AtomicRunnerResultV1:
    status: RunnerStatusV1
    preflight: RunnerPreflightV1
    resolver_operations: int
    pack_builds: int
    binding_sha256: str | None
    pack_sha256: str | None
    receipt_path: Path | None
    hard_stop_code: str | None


def _utc(value: datetime, *, code: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise PreDnsOrchestrationError(code)
    return value.astimezone(UTC)


def _utc_text(value: datetime) -> str:
    return _utc(value, code="PRE_DNS_DATETIME_INVALID").isoformat().replace("+00:00", "Z")


def _parse_exact_utc_text(value: object, *, code: str) -> datetime:
    if not isinstance(value, str):
        raise PreDnsOrchestrationError(code)
    try:
        parsed = _utc(datetime.fromisoformat(value.replace("Z", "+00:00")), code=code)
    except (TypeError, ValueError):
        raise PreDnsOrchestrationError(code) from None
    if _utc_text(parsed) != value:
        raise PreDnsOrchestrationError(code)
    return parsed


def _json_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _is_sha256_text(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and value == value.casefold()
        and all(character in "0123456789abcdef" for character in value)
    )


def _assert_plain_directory(path: Path) -> Path:
    absolute = path.absolute()
    try:
        facts = os.lstat(absolute)
    except OSError:
        raise PreDnsOrchestrationError("PRE_DNS_OUTPUT_PARENT_INVALID") from None
    if not stat.S_ISDIR(facts.st_mode) or stat.S_ISLNK(facts.st_mode):
        raise PreDnsOrchestrationError("PRE_DNS_OUTPUT_PARENT_INVALID")
    try:
        return validate_exclusive_local_directory_identity(absolute)
    except CaptureStorageError:
        raise PreDnsOrchestrationError("PRE_DNS_OUTPUT_PARENT_INVALID") from None


def _safe_name(name: str) -> str:
    if (
        not name
        or name in {".", ".."}
        or "/" in name
        or "\\" in name
        or ":" in name
        or Path(name).name != name
    ):
        raise PreDnsOrchestrationError("PRE_DNS_BUNDLE_PATH_INVALID")
    return name


def _read_regular_bounded(path: Path, *, maximum_bytes: int) -> bytes:
    try:
        before = os.lstat(path)
        if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):
            raise OSError
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOINHERIT", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(descriptor, min(65_536, maximum_bytes + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > maximum_bytes:
                    raise OSError
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        if (before.st_dev, before.st_ino, before.st_size) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
        ):
            raise OSError
        return b"".join(chunks)
    except OSError:
        raise PreDnsOrchestrationError("PRE_DNS_ARTIFACT_READ_FAILED") from None


def _write_exclusive(path: Path, payload: bytes) -> None:
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOINHERIT", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            with os.fdopen(descriptor, "wb") as stream:
                descriptor = -1
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            if descriptor >= 0:
                os.close(descriptor)
    except OSError:
        raise PreDnsOrchestrationError("PRE_DNS_IMMUTABLE_WRITE_FAILED") from None


def _model_bytes(model: BaseModel) -> bytes:
    return canonical_json_bytes(model.model_dump(mode="json")) + b"\n"


def inspect_provider_markers_read_only_v1(
    workspace_receipt: RealCaptureWorkspaceReceiptV1,
    mission_manifest: RealExecutionMissionManifestV1,
    *,
    historical_marker: HistoricalMarkerExpectationV1,
) -> MarkerInspectionV1:
    """Inspect V2 and legacy marker facts without creating either registry."""

    local_marker = Path(workspace_receipt.control_temp_root) / _CONTROL_MARKER_NAME
    current_manifest_sha256 = mission_manifest.canonical_manifest_sha256()
    current_marker_name = f"{mission_manifest.mission_id.casefold()}-{current_manifest_sha256}.json"
    historical_marker_name = (
        f"{mission_manifest.mission_id.casefold()}-"
        f"{historical_marker.authority_manifest_sha256}.json"
    )
    try:
        current_pair = global_claims.read_global_claim_marker_pair_v2(
            workspace_receipt,
            current_marker_name,
        )
        historical_pair = global_claims.read_global_claim_marker_pair_v2(
            workspace_receipt,
            historical_marker_name,
        )
    except global_claims.GlobalClaimBoundaryError as error:
        raise PreDnsOrchestrationError(error.code) from None
    if current_pair.v2_root_identity != historical_pair.v2_root_identity:
        raise PreDnsOrchestrationError("GLOBAL_CLAIM_ROOT_IDENTITY_CHANGED")
    if current_pair.legacy_root_identity != historical_pair.legacy_root_identity:
        raise PreDnsOrchestrationError("GLOBAL_CLAIM_LEGACY_CONFLICT")
    current_payloads = tuple(
        payload
        for payload in (current_pair.v2_payload, current_pair.legacy_payload)
        if payload is not None
    )
    if current_payloads and not all(
        _valid_provider_resolution_claim_marker_v2(payload, mission_manifest)
        for payload in current_payloads
    ):
        raise PreDnsOrchestrationError("GLOBAL_CLAIM_MARKER_INVALID")
    current_present = os.path.lexists(local_marker) or bool(current_payloads)
    raw_hash: str | None = None
    acl_hash: str | None = None
    acl_exclusive = historical_marker.acl_sha256 is None
    unchanged = False
    try:
        authority_hash = historical_marker.authority_manifest_sha256
        expected_path = Path(os.path.normcase(os.path.abspath(historical_marker.path)))
        v2_historical_path = Path(os.path.normcase(os.path.abspath(historical_pair.paths.v2)))
        legacy_historical_path = Path(
            os.path.normcase(os.path.abspath(historical_pair.paths.legacy))
        )
        if expected_path == v2_historical_path:
            payload = historical_pair.v2_payload
        elif expected_path == legacy_historical_path:
            payload = historical_pair.legacy_payload
        else:
            payload = None
        if (
            len(authority_hash) != 64
            or authority_hash != authority_hash.casefold()
            or any(character not in "0123456789abcdef" for character in authority_hash)
            or payload is None
        ):
            raise PreDnsOrchestrationError("HISTORICAL_MARKER_AUTHORITY_INVALID")
        resolution_claim = ProviderNetworkResolutionClaimV1.model_validate_json(payload)
        raw_hash = _sha256(payload)
        if os.name == "nt" and historical_marker.acl_sha256 is not None:
            acl_hash, acl_exclusive = WindowsBoundaryInspector()._security_facts(
                historical_marker.path.absolute()
            )
        unchanged = (
            resolution_claim.mission_manifest_sha256 == authority_hash
            and canonical_json_bytes(resolution_claim.model_dump(mode="json")) + b"\n" == payload
            and raw_hash == historical_marker.raw_sha256
            and (
                historical_marker.acl_sha256 is None
                or (acl_hash == historical_marker.acl_sha256 and acl_exclusive)
            )
        )
    except (OSError, PreDnsOrchestrationError, ValueError):
        unchanged = False
    return MarkerInspectionV1(
        historical_marker_unchanged=unchanged,
        current_marker_present=current_present,
        historical_raw_sha256=raw_hash,
        historical_acl_sha256=acl_hash,
        historical_marker_path=str(historical_marker.path.absolute()),
        historical_authority_manifest_sha256=(historical_marker.authority_manifest_sha256),
        current_authority_manifest_sha256=current_manifest_sha256,
        current_local_marker=str(local_marker),
        current_v2_global_marker=str(current_pair.paths.v2),
        current_legacy_global_marker=str(current_pair.paths.legacy),
        current_v2_root_identity=current_pair.v2_root_identity,
        current_legacy_root_identity=current_pair.legacy_root_identity,
    )


def load_scientific_corpus_evidence_v1(
    payload: bytes,
    *,
    workspace_receipt: RealCaptureWorkspaceReceiptV1,
    evaluated_at_utc: datetime,
) -> ScientificCorpusSnapshotV1:
    if len(payload) > 4_194_304:
        raise PreDnsOrchestrationError("CAMPAIGN_CORPUS_EVIDENCE_INVALID")
    try:
        evidence = strict_json_object(payload)
    except (TypeError, ValueError):
        raise PreDnsOrchestrationError("CAMPAIGN_CORPUS_EVIDENCE_INVALID") from None
    if (
        set(evidence)
        != {
            "schema_version",
            "observed_at_utc",
            "admitted_fixture_counts",
        }
        or evidence.get("schema_version") != "robin-owner-observed-scientific-corpus-v1"
    ):
        raise PreDnsOrchestrationError("CAMPAIGN_CORPUS_EVIDENCE_INVALID")
    raw_counts = evidence.get("admitted_fixture_counts")
    raw_observed = evidence.get("observed_at_utc")
    if not isinstance(raw_counts, dict) or set(raw_counts) != set(LIVE_ALLOWED_SPORT_KEYS):
        raise PreDnsOrchestrationError("CAMPAIGN_CORPUS_COUNTS_INVALID")
    if any(
        isinstance(value, bool) or not isinstance(value, int) or value < 0
        for value in raw_counts.values()
    ):
        raise PreDnsOrchestrationError("CAMPAIGN_CORPUS_COUNTS_INVALID")
    if not isinstance(raw_observed, str):
        raise PreDnsOrchestrationError("CAMPAIGN_CORPUS_OBSERVED_AT_INVALID")
    try:
        observed = datetime.fromisoformat(raw_observed.replace("Z", "+00:00"))
    except ValueError:
        raise PreDnsOrchestrationError("CAMPAIGN_CORPUS_OBSERVED_AT_INVALID") from None
    evaluated = _utc(evaluated_at_utc, code="CAMPAIGN_CORPUS_OBSERVED_AT_INVALID")
    observed = _utc(observed, code="CAMPAIGN_CORPUS_OBSERVED_AT_INVALID")
    if (
        observed < workspace_receipt.prepared_at_utc
        or observed > evaluated
        or evaluated - observed > MAXIMUM_SOURCE_AGE
    ):
        raise PreDnsOrchestrationError("CAMPAIGN_CORPUS_NOT_CURRENT")
    return ScientificCorpusSnapshotV1.issue(
        observed_at_utc=observed,
        source_evidence_sha256=_sha256(payload),
        league_counts=tuple(
            CampaignLeagueCorpusCountV1(
                sport_key=sport_key,
                admitted_fixture_count=cast(int, raw_counts[sport_key]),
            )
            for sport_key in LIVE_ALLOWED_SPORT_KEYS
        ),
    )


def freeze_official_schedule_evidence_v1(
    evidence: OfficialScheduleEvidence,
    *,
    workspace_receipt: RealCaptureWorkspaceReceiptV1,
    created_at_utc: datetime,
) -> FixtureTargetSetV1:
    created = _utc(created_at_utc, code="OFFICIAL_SCHEDULE_FREEZE_TIME_INVALID")
    evidence_bytes = _json_bytes(evidence.to_json())
    targets = tuple(
        OfficialFixtureTargetV1.issue(
            internal_fixture_target_id=cast(
                str,
                raw["internal_fixture_target_id"],
            ),
            competition=cast(str, raw["competition"]),
            sport_key=evidence.sport_key,
            official_home_team=cast(str, raw["official_home_team"]),
            official_away_team=cast(str, raw["official_away_team"]),
            official_kickoff_utc=datetime.fromisoformat(
                cast(str, raw["official_kickoff_utc"]).replace("Z", "+00:00")
            ),
            official_source_authority=evidence.source_authority,
            source_observed_at_utc=evidence.source_observed_at_utc,
            source_evidence_sha256=_sha256(evidence_bytes),
        )
        for raw in cast(list[dict[str, object]], evidence.to_json()["fixtures"])
    )
    return FixtureTargetSetV1.issue(
        target_set_id=cast(str, evidence.to_json()["target_set_id"]),
        sport_key=evidence.sport_key,
        workspace_receipt_sha256=workspace_receipt.canonical_receipt_hash,
        created_at_utc=created,
        official_schedule_horizon_not_before_utc=evidence.horizon_not_before_utc,
        official_schedule_horizon_expires_at_utc=evidence.horizon_expires_at_utc,
        official_schedule_fixture_count=len(targets),
        official_schedule_completeness="OWNER_REVIEWED_COMPLETE_OFFICIAL_HORIZON",
        targets=targets,
    )


def _marker_from_json(
    value: object,
    *,
    workspace: RealCaptureWorkspaceReceiptV1,
    mission: RealExecutionMissionManifestV1,
) -> MarkerInspectionV1 | LegacyMarkerInspectionV1:
    if not isinstance(value, dict):
        raise PreDnsOrchestrationError("PRE_DNS_MARKER_INSPECTION_INVALID")
    common = {
        "schema_version",
        "historical_marker_unchanged",
        "current_marker_present",
        "historical_raw_sha256",
        "historical_acl_sha256",
        "historical_marker_path",
        "historical_authority_manifest_sha256",
        "current_authority_manifest_sha256",
        "current_local_marker",
        "filesystem_writes",
    }
    required_v2 = {
        *common,
        "current_v2_global_marker",
        "current_legacy_global_marker",
    }
    required_v1 = {*common, "current_global_marker"}
    marker_name = f"{mission.mission_id.casefold()}-{mission.canonical_manifest_sha256()}.json"
    try:
        marker_paths = global_claims.global_claim_marker_paths_v2(workspace, marker_name)
    except global_claims.GlobalClaimBoundaryError as error:
        raise PreDnsOrchestrationError(error.code) from None
    local_marker = Path(workspace.control_temp_root) / _CONTROL_MARKER_NAME

    def same_path(left: object, right: Path) -> bool:
        return isinstance(left, str) and os.path.normcase(os.path.abspath(left)) == (
            os.path.normcase(os.path.abspath(right))
        )

    schema = value.get("schema_version")
    if schema == "robin-provider-marker-readonly-inspection-v2":
        if (
            set(value) != required_v2
            or value.get("filesystem_writes") != 0
            or not same_path(value.get("current_local_marker"), local_marker)
            or not same_path(value.get("current_v2_global_marker"), marker_paths.v2)
            or not same_path(value.get("current_legacy_global_marker"), marker_paths.legacy)
        ):
            raise PreDnsOrchestrationError("PRE_DNS_MARKER_INSPECTION_INVALID")
        return MarkerInspectionV1(
            historical_marker_unchanged=value["historical_marker_unchanged"] is True,
            current_marker_present=value["current_marker_present"] is True,
            historical_raw_sha256=(
                value["historical_raw_sha256"]
                if isinstance(value["historical_raw_sha256"], str)
                else None
            ),
            historical_acl_sha256=(
                value["historical_acl_sha256"]
                if isinstance(value["historical_acl_sha256"], str)
                else None
            ),
            historical_marker_path=cast(str, value["historical_marker_path"]),
            historical_authority_manifest_sha256=cast(
                str, value["historical_authority_manifest_sha256"]
            ),
            current_authority_manifest_sha256=cast(str, value["current_authority_manifest_sha256"]),
            current_local_marker=cast(str, value["current_local_marker"]),
            current_v2_global_marker=cast(str, value["current_v2_global_marker"]),
            current_legacy_global_marker=cast(str, value["current_legacy_global_marker"]),
        )
    if schema == "robin-provider-marker-readonly-inspection-v1":
        if (
            set(value) != required_v1
            or value.get("filesystem_writes") != 0
            or not same_path(value.get("current_local_marker"), local_marker)
            or not same_path(value.get("current_global_marker"), marker_paths.legacy)
        ):
            raise PreDnsOrchestrationError("PRE_DNS_MARKER_INSPECTION_INVALID")
        return LegacyMarkerInspectionV1(
            historical_marker_unchanged=value["historical_marker_unchanged"] is True,
            current_marker_present=value["current_marker_present"] is True,
            historical_raw_sha256=(
                value["historical_raw_sha256"]
                if isinstance(value["historical_raw_sha256"], str)
                else None
            ),
            historical_acl_sha256=(
                value["historical_acl_sha256"]
                if isinstance(value["historical_acl_sha256"], str)
                else None
            ),
            historical_marker_path=cast(str, value["historical_marker_path"]),
            historical_authority_manifest_sha256=cast(
                str, value["historical_authority_manifest_sha256"]
            ),
            current_authority_manifest_sha256=cast(str, value["current_authority_manifest_sha256"]),
            current_local_marker=cast(str, value["current_local_marker"]),
            current_global_marker=cast(str, value["current_global_marker"]),
        )
    raise PreDnsOrchestrationError("PRE_DNS_MARKER_INSPECTION_INVALID")


def _validate_review_bytes(name: str, payload: bytes) -> Mapping[str, object]:
    try:
        review = strict_json_object(payload)
    except (TypeError, ValueError):
        raise PreDnsOrchestrationError("PRE_DNS_REVIEW_INVALID") from None
    if (
        review.get("reviewer") != name
        or review.get("verdict") != "ACCEPT"
        or review.get("p0") != 0
        or review.get("p1") != 0
        or review.get("p2") != 0
        or review.get("open_threads") != 0
    ):
        raise PreDnsOrchestrationError("PRE_DNS_REVIEW_NOT_ACCEPTED")
    return review


def _parse_redirect_hops(value: object) -> tuple[RedirectHop, ...]:
    if not isinstance(value, list):
        raise PreDnsOrchestrationError("OFFICIAL_FETCH_RECEIPT_INVALID")
    hops: list[RedirectHop] = []
    for item in value:
        if not isinstance(item, dict) or set(item) != {
            "requested_url",
            "status_code",
            "location",
        }:
            raise PreDnsOrchestrationError("OFFICIAL_FETCH_RECEIPT_INVALID")
        requested_url = item.get("requested_url")
        status_code = item.get("status_code")
        location = item.get("location")
        if (
            not isinstance(requested_url, str)
            or isinstance(status_code, bool)
            or not isinstance(status_code, int)
            or not isinstance(location, str)
        ):
            raise PreDnsOrchestrationError("OFFICIAL_FETCH_RECEIPT_INVALID")
        hops.append(RedirectHop(requested_url, status_code, location))
    return tuple(hops)


def _parse_fetch_receipt(payload: bytes) -> OfficialFetchReceipt:
    try:
        value = strict_json_object(payload)
    except (TypeError, ValueError):
        raise PreDnsOrchestrationError("OFFICIAL_FETCH_RECEIPT_INVALID") from None
    required = {
        "schema_version",
        "sport_key",
        "adapter_revision",
        "requested_url",
        "final_url",
        "official_domain",
        "observed_at_utc",
        "http_status",
        "content_type",
        "byte_count",
        "raw_sha256",
        "redirect_chain",
        "accepted",
        "rejection_code",
        "supporting_official_reads",
    }
    if set(value) != required or value.get("schema_version") != (
        "robin-official-schedule-fetch-receipt-v1"
    ):
        raise PreDnsOrchestrationError("OFFICIAL_FETCH_RECEIPT_INVALID")
    supporting_value = value.get("supporting_official_reads")
    if not isinstance(supporting_value, list):
        raise PreDnsOrchestrationError("OFFICIAL_FETCH_RECEIPT_INVALID")
    supporting: list[SupportingOfficialRead] = []
    for item in supporting_value:
        if not isinstance(item, dict) or set(item) != {
            "requested_url",
            "final_url",
            "official_domain",
            "status_code",
            "content_type",
            "byte_count",
            "raw_sha256",
            "redirect_chain",
        }:
            raise PreDnsOrchestrationError("OFFICIAL_FETCH_RECEIPT_INVALID")
        try:
            supporting.append(
                SupportingOfficialRead(
                    requested_url=cast(str, item["requested_url"]),
                    final_url=cast(str, item["final_url"]),
                    official_domain=cast(str, item["official_domain"]),
                    status_code=cast(int, item["status_code"]),
                    content_type=cast(str, item["content_type"]),
                    byte_count=cast(int, item["byte_count"]),
                    raw_sha256=cast(str, item["raw_sha256"]),
                    redirect_chain=_parse_redirect_hops(item["redirect_chain"]),
                )
            )
        except (KeyError, TypeError, ValueError):
            raise PreDnsOrchestrationError("OFFICIAL_FETCH_RECEIPT_INVALID") from None
    try:
        observed_raw = value["observed_at_utc"]
        if not isinstance(observed_raw, str):
            raise ValueError
        return OfficialFetchReceipt(
            sport_key=cast(str, value["sport_key"]),
            adapter_revision=cast(str, value["adapter_revision"]),
            requested_url=cast(str, value["requested_url"]),
            final_url=cast(str, value["final_url"]),
            official_domain=cast(str, value["official_domain"]),
            observed_at_utc=datetime.fromisoformat(observed_raw.replace("Z", "+00:00")),
            http_status=cast(int, value["http_status"]),
            content_type=cast(str, value["content_type"]),
            byte_count=cast(int, value["byte_count"]),
            raw_sha256=cast(str, value["raw_sha256"]),
            redirect_chain=_parse_redirect_hops(value["redirect_chain"]),
            accepted=cast(bool, value["accepted"]),
            rejection_code=cast(str | None, value["rejection_code"]),
            supporting_official_reads=tuple(supporting),
        )
    except (KeyError, TypeError, ValueError):
        raise PreDnsOrchestrationError("OFFICIAL_FETCH_RECEIPT_INVALID") from None


def verify_raw_official_evidence_v1(
    source: OfficialSourceSpec,
    raw_payload: bytes,
    receipt_payload: bytes,
    evidence_payload: bytes,
    target_set: FixtureTargetSetV1,
    supporting_raw_payloads: tuple[bytes, ...],
) -> None:
    receipt = _parse_fetch_receipt(receipt_payload)
    try:
        if source.adapter == LALIGA_PUBLIC_MATCHES_JSON_V1:
            if len(supporting_raw_payloads) != 1:
                raise OfficialScheduleSourceError("OFFICIAL_SUPPORTING_READ_INVALID")
            _extract_laliga_public_subscription(supporting_raw_payloads[0])
        elif supporting_raw_payloads:
            raise OfficialScheduleSourceError("OFFICIAL_SUPPORTING_READ_INVALID")
    except OfficialScheduleSourceError as error:
        raise PreDnsOrchestrationError(error.code) from None
    starts = target_set.official_schedule_horizon_not_before_utc
    expires = target_set.official_schedule_horizon_expires_at_utc
    if starts is None or expires is None:
        raise PreDnsOrchestrationError("OFFICIAL_SCHEDULE_HORIZON_INVALID")
    try:
        rebuilt = build_official_schedule_evidence(
            source,
            OfficialFetchResult(
                raw_bytes=raw_payload,
                receipt=receipt,
                supporting_official_raw_bytes=supporting_raw_payloads,
            ),
            horizon_not_before_utc=starts,
            horizon_expires_at_utc=expires,
        )
    except (OfficialScheduleSourceError, TypeError, ValueError) as error:
        raise PreDnsOrchestrationError(
            getattr(error, "code", "OFFICIAL_SCHEDULE_REPARSE_FAILED")
        ) from None
    if _json_bytes(rebuilt.to_json()) != evidence_payload:
        raise PreDnsOrchestrationError("OFFICIAL_SCHEDULE_REPARSE_MISMATCH")


def _validate_workspace_default(receipt: RealCaptureWorkspaceReceiptV1) -> None:
    assert_real_capture_workspace_receipt_current_v1(receipt)


def _publish_pre_dns_bundle_v1(
    *,
    output_parent: Path,
    status: Literal["PRE_DNS_READY_NOW", "PRE_DNS_FUTURE_WINDOW_PLANNED"],
    published_at_utc: datetime,
    workspace_receipt_bytes: bytes,
    mission_manifest_bytes: bytes,
    source_plan_bytes: bytes,
    source_plan: OfficialSourcePlan,
    raw_results: Mapping[str, OfficialFetchResult],
    evidences: tuple[OfficialScheduleEvidence, ...],
    reconciliation: Mapping[str, object],
    target_sets: tuple[FixtureTargetSetV1, ...],
    corpus_evidence_bytes: bytes,
    corpus_snapshot: ScientificCorpusSnapshotV1,
    selection: CampaignWindowSelectionV1,
    iteration_ledger: tuple[Mapping[str, object], ...],
    reviews: Mapping[str, bytes],
    marker_inspection: MarkerInspectionV1,
    counters: PreDnsCountersV1,
) -> tuple[Path, str]:
    parent = _assert_plain_directory(output_parent)
    stamp = _utc_text(published_at_utc).replace("-", "").replace(":", "").replace(".", "")
    target = parent / f"pre-dns-owner-pack-inputs-{stamp}"
    staging = parent / f".{target.name}.staging"
    if os.path.lexists(target) or os.path.lexists(staging):
        raise PreDnsOrchestrationError("PRE_DNS_BUNDLE_OUTPUT_EXISTS")
    try:
        os.mkdir(staging, 0o700)
    except OSError:
        raise PreDnsOrchestrationError("PRE_DNS_BUNDLE_STAGING_FAILED") from None
    artifacts: dict[str, bytes] = {
        "source-plan.json": source_plan_bytes,
        "workspace-receipt.json": workspace_receipt_bytes,
        "mission-manifest.json": mission_manifest_bytes,
        "scientific-corpus-evidence.json": corpus_evidence_bytes,
        "scientific-corpus-snapshot.json": _model_bytes(corpus_snapshot),
        "campaign-selection.json": _model_bytes(selection),
        "iteration-ledger.json": _json_bytes(
            {
                "schema_version": PRE_DNS_ITERATION_LEDGER_SCHEMA,
                "iterations": list(iteration_ledger),
                "counters": {
                    "iterations": counters.iterations,
                    "official_reads": counters.official_reads,
                    "supporting_official_reads": counters.supporting_official_reads,
                    "corpus_snapshots": counters.corpus_snapshots,
                    "corpus_validations": counters.corpus_validations,
                    "target_set_freezes": counters.target_set_freezes,
                    "selector_invocations": counters.selector_invocations,
                },
            }
        ),
        "provider-marker-inspection.json": _json_bytes(marker_inspection.to_json()),
        "official-schedule-reconciliation.json": _json_bytes(reconciliation),
    }
    for review_name in _REVIEW_NAMES:
        artifacts[f"review-{review_name.casefold()}.json"] = reviews[review_name]
    evidence_by_sport = {item.sport_key: item for item in evidences}
    target_by_sport = {item.sport_key: item for item in target_sets}
    for sport_key in LIVE_ALLOWED_SPORT_KEYS:
        artifacts[f"raw-{sport_key}.bin"] = raw_results[sport_key].raw_bytes
        artifacts[f"fetch-receipt-{sport_key}.json"] = _json_bytes(
            raw_results[sport_key].receipt.to_json()
        )
        artifacts[f"evidence-{sport_key}.json"] = _json_bytes(
            evidence_by_sport[sport_key].to_json()
        )
        artifacts[f"target-set-{sport_key}.json"] = _model_bytes(target_by_sport[sport_key])
        for index, supporting_raw in enumerate(
            raw_results[sport_key].supporting_official_raw_bytes,
            start=1,
        ):
            artifacts[f"raw-supporting-{sport_key}-{index:02d}.bin"] = supporting_raw
    lowered = [name.casefold() for name in artifacts]
    if len(lowered) != len(set(lowered)):
        raise PreDnsOrchestrationError("PRE_DNS_BUNDLE_CASEFOLD_COLLISION")
    entries: dict[str, dict[str, object]] = {}
    for name, payload in sorted(artifacts.items()):
        _safe_name(name)
        _write_exclusive(staging / name, payload)
        entries[name] = {"sha256": _sha256(payload), "byte_count": len(payload)}
    selected = selection.selected_candidate()
    workspace_from_bytes = RealCaptureWorkspaceReceiptV1.model_validate_json(
        workspace_receipt_bytes
    )
    recommended_refresh = selected.window_not_before_utc - timedelta(seconds=SAFETY_CUTOFF_SECONDS)
    manifest_without_hash: dict[str, object] = {
        "schema_version": PRE_DNS_BUNDLE_SCHEMA,
        "status": status,
        "published_at_utc": _utc_text(published_at_utc),
        "runtime_main_sha": workspace_from_bytes.authorized_main_sha,
        "workspace_receipt_sha256": selection.workspace_receipt_sha256,
        "mission_manifest_sha256": selection.mission_manifest_sha256,
        "source_plan_sha256": source_plan.canonical_sha256,
        "campaign_selection_sha256": selection.canonical_selection_hash,
        "selected_candidate_id": selected.candidate_id,
        "selected_candidate_sha256": selected.canonical_candidate_hash,
        "selected_sport_key": selected.request.sport_key,
        "selected_window_id": selected.window_id,
        "selected_not_before_utc": _utc_text(selected.window_not_before_utc),
        "selected_usable_expires_at_utc": _utc_text(selected.usable_expires_at_utc),
        "selected_earliest_kickoff_utc": _utc_text(
            min(item.official_kickoff_utc for item in selected.fixture_target_set.targets)
        ),
        "recommended_refresh_utc": _utc_text(recommended_refresh),
        "recommended_refresh_europe_paris": recommended_refresh.astimezone(
            ZoneInfo("Europe/Paris")
        ).isoformat(),
        "artifacts": entries,
        "effects": {
            "provider_dns": 0,
            "provider_tcp": 0,
            "provider_http": 0,
            "secret_reads": 0,  # nosec B105 -- effect counter, not a credential
            "owner_review_pack_builds": 0,
            "owner_authorizations": 0,
            "activations": 0,
            "captures": 0,
            "promotions": 0,
            "bets": 0,
        },
    }
    canonical_manifest_hash = _sha256(_json_bytes(manifest_without_hash))
    manifest = {
        **manifest_without_hash,
        "canonical_bundle_manifest_sha256": canonical_manifest_hash,
    }
    manifest_bytes = _json_bytes(manifest)
    _write_exclusive(staging / "bundle-manifest.json", manifest_bytes)
    try:
        os.rename(staging, target)
    except OSError:
        raise PreDnsOrchestrationError("PRE_DNS_BUNDLE_PUBLICATION_FAILED") from None
    return target, _sha256(manifest_bytes)


def _expected_bundle_artifact_names() -> set[str]:
    names = {
        "source-plan.json",
        "workspace-receipt.json",
        "mission-manifest.json",
        "scientific-corpus-evidence.json",
        "scientific-corpus-snapshot.json",
        "campaign-selection.json",
        "iteration-ledger.json",
        "provider-marker-inspection.json",
        "official-schedule-reconciliation.json",
        "raw-supporting-soccer_spain_la_liga-01.bin",
        *(f"review-{name.casefold()}.json" for name in _REVIEW_NAMES),
    }
    for sport_key in LIVE_ALLOWED_SPORT_KEYS:
        names.update(
            {
                f"raw-{sport_key}.bin",
                f"fetch-receipt-{sport_key}.json",
                f"evidence-{sport_key}.json",
                f"target-set-{sport_key}.json",
            }
        )
    return names


def _load_first_c0_canary_source_plan_v1(
    payload: bytes,
) -> FirstC0CanarySourcePlanAuthorityV1:
    try:
        value = strict_json_object(payload)
    except (TypeError, ValueError):
        raise PreDnsOrchestrationError("FIRST_C0_CANARY_SOURCE_PLAN_INVALID") from None
    required = {"schema_version", "sport_key", "adapter", "url"}
    if set(value) != required or value.get("schema_version") != (
        FIRST_C0_CANARY_SOURCE_PLAN_SCHEMA
    ):
        raise PreDnsOrchestrationError("FIRST_C0_CANARY_SOURCE_PLAN_INVALID")
    sport_key = value.get("sport_key")
    adapter = value.get("adapter")
    url = value.get("url")
    expected_adapters = {
        "soccer_spain_la_liga": LALIGA_PUBLIC_MATCHES_JSON_V1,
        "soccer_germany_bundesliga": DFB_DATACENTER_HTML_V1,
    }
    if (
        not isinstance(sport_key, str)
        or not isinstance(adapter, str)
        or not isinstance(url, str)
        or expected_adapters.get(sport_key) != adapter
    ):
        raise PreDnsOrchestrationError("FIRST_C0_CANARY_SOURCE_PLAN_INVALID")
    parsed = urlparse(url)
    try:
        port = parsed.port
    except ValueError:
        raise PreDnsOrchestrationError("FIRST_C0_CANARY_SOURCE_PLAN_INVALID") from None
    host = (parsed.hostname or "").rstrip(".").casefold()
    if (
        parsed.scheme.casefold() != "https"
        or parsed.username
        or parsed.password
        or port not in {None, 443}
        or parsed.fragment
    ):
        raise PreDnsOrchestrationError("FIRST_C0_CANARY_SOURCE_PLAN_INVALID")
    if sport_key == "soccer_spain_la_liga":
        query = parse_qs(parsed.query, keep_blank_values=True)
        if (
            host != "apim.laliga.com"
            or parsed.path != "/public-service/api/v1/matches"
            or set(query) != {"subscription", "competition", "limit", "offset"}
            or query.get("subscription") != ["laliga-easports-2026"]
            or query.get("competition") != ["primera-division"]
            or query.get("limit") != ["100"]
            or query.get("offset") != ["300"]
        ):
            raise PreDnsOrchestrationError("FIRST_C0_CANARY_SOURCE_PLAN_INVALID")
    elif (
        host != "datencenter.dfb.de"
        or parsed.path != "/competitions/12/seasons/current"
        or parsed.query
    ):
        raise PreDnsOrchestrationError("FIRST_C0_CANARY_SOURCE_PLAN_INVALID")
    canonical = {
        "schema_version": FIRST_C0_CANARY_SOURCE_PLAN_SCHEMA,
        "sport_key": sport_key,
        "adapter": adapter,
        "url": url,
    }
    return FirstC0CanarySourcePlanAuthorityV1(
        source=OfficialSourceSpec(sport_key=sport_key, adapter=adapter, url=url),
        canonical_sha256=_sha256(canonical_json_bytes(canonical)),
    )


def _first_c0_canary_source_plan_from_cycle_record_v1(
    value: Mapping[str, object],
) -> FirstC0CanarySourcePlanAuthorityV1:
    return _load_first_c0_canary_source_plan_v1(
        _json_bytes(
            {
                "schema_version": FIRST_C0_CANARY_SOURCE_PLAN_SCHEMA,
                "sport_key": value.get("sport_key"),
                "adapter": value.get("adapter"),
                "url": value.get("url"),
            }
        )
    )


def _load_first_c0_canary_marker_inspection_v1(
    payload: bytes,
    *,
    workspace: RealCaptureWorkspaceReceiptV1,
    mission: RealExecutionMissionManifestV1,
) -> FirstC0CanaryMarkerInspectionV1 | LegacyFirstC0CanaryMarkerInspectionV1:
    try:
        value = strict_json_object(payload)
    except (TypeError, ValueError):
        raise PreDnsOrchestrationError("FIRST_C0_CANARY_MARKER_INSPECTION_INVALID") from None
    required_v2 = {
        "schema_version",
        "local_marker_path",
        "v2_global_marker_path",
        "legacy_global_marker_path",
        "local_marker_present",
        "v2_global_marker_present",
        "legacy_global_marker_present",
        "inspected_read_only",
    }
    required_v1 = {
        "schema_version",
        "local_marker_path",
        "global_marker_path",
        "local_marker_present",
        "global_marker_present",
        "inspected_read_only",
    }
    local = Path(workspace.control_temp_root) / _CONTROL_MARKER_NAME
    marker_name = f"{mission.mission_id.casefold()}-{mission.canonical_manifest_sha256()}.json"
    try:
        global_marker_paths = global_claims.global_claim_marker_paths_v2(
            workspace,
            marker_name,
        )
    except global_claims.GlobalClaimBoundaryError as error:
        raise PreDnsOrchestrationError(error.code) from None
    schema = value.get("schema_version")
    local_matches = isinstance(value.get("local_marker_path"), str) and (
        os.path.normcase(os.path.abspath(cast(str, value["local_marker_path"])))
        == os.path.normcase(os.path.abspath(local))
    )
    if schema == "robin-first-c0-canary-marker-inspection-v2":
        if (
            set(value) != required_v2
            or value.get("local_marker_present") is not False
            or value.get("v2_global_marker_present") is not False
            or value.get("legacy_global_marker_present") is not False
            or value.get("inspected_read_only") is not True
            or not local_matches
            or not isinstance(value.get("v2_global_marker_path"), str)
            or not isinstance(value.get("legacy_global_marker_path"), str)
            or os.path.normcase(os.path.abspath(cast(str, value["v2_global_marker_path"])))
            != os.path.normcase(os.path.abspath(global_marker_paths.v2))
            or os.path.normcase(os.path.abspath(cast(str, value["legacy_global_marker_path"])))
            != os.path.normcase(os.path.abspath(global_marker_paths.legacy))
        ):
            raise PreDnsOrchestrationError("FIRST_C0_CANARY_MARKER_INSPECTION_INVALID")
        return FirstC0CanaryMarkerInspectionV1(
            local_marker_path=cast(str, value["local_marker_path"]),
            v2_global_marker_path=cast(str, value["v2_global_marker_path"]),
            legacy_global_marker_path=cast(str, value["legacy_global_marker_path"]),
            local_marker_present=False,
            v2_global_marker_present=False,
            legacy_global_marker_present=False,
            inspected_read_only=True,
        )
    if schema == "robin-first-c0-canary-marker-inspection-v1":
        if (
            set(value) != required_v1
            or value.get("local_marker_present") is not False
            or value.get("global_marker_present") is not False
            or value.get("inspected_read_only") is not True
            or not local_matches
            or not isinstance(value.get("global_marker_path"), str)
            or os.path.normcase(os.path.abspath(cast(str, value["global_marker_path"])))
            != os.path.normcase(os.path.abspath(global_marker_paths.legacy))
        ):
            raise PreDnsOrchestrationError("FIRST_C0_CANARY_MARKER_INSPECTION_INVALID")
        return LegacyFirstC0CanaryMarkerInspectionV1(
            local_marker_path=cast(str, value["local_marker_path"]),
            global_marker_path=cast(str, value["global_marker_path"]),
            local_marker_present=False,
            global_marker_present=False,
            inspected_read_only=True,
        )
    raise PreDnsOrchestrationError("FIRST_C0_CANARY_MARKER_INSPECTION_INVALID")


def _first_c0_canary_marker_authority_matches_v1(
    observed: MarkerInspectionV1,
    frozen: (
        MarkerInspectionV1
        | LegacyMarkerInspectionV1
        | FirstC0CanaryMarkerInspectionV1
        | LegacyFirstC0CanaryMarkerInspectionV1
    ),
) -> bool:
    if isinstance(frozen, MarkerInspectionV1):
        return observed.to_json() == frozen.to_json()
    if isinstance(frozen, LegacyMarkerInspectionV1):
        return (
            observed.historical_marker_unchanged == frozen.historical_marker_unchanged
            and observed.current_marker_present == frozen.current_marker_present
            and observed.historical_raw_sha256 == frozen.historical_raw_sha256
            and observed.historical_acl_sha256 == frozen.historical_acl_sha256
            and observed.historical_marker_path == frozen.historical_marker_path
            and observed.historical_authority_manifest_sha256
            == frozen.historical_authority_manifest_sha256
            and observed.current_authority_manifest_sha256
            == frozen.current_authority_manifest_sha256
            and os.path.normcase(os.path.abspath(observed.current_local_marker))
            == os.path.normcase(os.path.abspath(frozen.current_local_marker))
            and os.path.normcase(os.path.abspath(observed.current_legacy_global_marker))
            == os.path.normcase(os.path.abspath(frozen.current_global_marker))
        )
    if isinstance(frozen, LegacyFirstC0CanaryMarkerInspectionV1):
        return (
            observed.historical_marker_unchanged
            and not observed.current_marker_present
            and os.path.normcase(os.path.abspath(observed.current_local_marker))
            == os.path.normcase(os.path.abspath(frozen.local_marker_path))
            and os.path.normcase(os.path.abspath(observed.current_legacy_global_marker))
            == os.path.normcase(os.path.abspath(frozen.global_marker_path))
        )
    return (
        observed.historical_marker_unchanged
        and not observed.current_marker_present
        and os.path.normcase(os.path.abspath(observed.current_local_marker))
        == os.path.normcase(os.path.abspath(frozen.local_marker_path))
        and os.path.normcase(os.path.abspath(observed.current_v2_global_marker))
        == os.path.normcase(os.path.abspath(frozen.v2_global_marker_path))
        and os.path.normcase(os.path.abspath(observed.current_legacy_global_marker))
        == os.path.normcase(os.path.abspath(frozen.legacy_global_marker_path))
    )


def _historical_marker_binding_matches_v1(
    observed: MarkerInspectionV1,
    expected: MarkerInspectionV1,
    *,
    expected_v2_root_identity: tuple[object, ...],
    expected_legacy_root_identity: tuple[object, ...],
) -> bool:
    return (
        expected.historical_marker_unchanged
        and observed.historical_marker_unchanged
        and expected.historical_raw_sha256 is not None
        and observed.historical_raw_sha256 == expected.historical_raw_sha256
        and observed.historical_acl_sha256 == expected.historical_acl_sha256
        and os.path.normcase(os.path.abspath(observed.historical_marker_path))
        == os.path.normcase(os.path.abspath(expected.historical_marker_path))
        and observed.historical_authority_manifest_sha256
        == expected.historical_authority_manifest_sha256
        and observed.current_v2_root_identity == expected_v2_root_identity
        and observed.current_legacy_root_identity == expected_legacy_root_identity
    )


def _load_first_c0_canary_bundle_v1(
    root: Path,
    manifest_bytes: bytes,
    manifest: Mapping[str, object],
    *,
    raw_evidence_verifier: RawEvidenceVerifierV1,
) -> LoadedPreDnsBundleV1:
    prefetched_schema = manifest.get("schema_version") == FIRST_C0_PREFETCHED_WINDOW_BUNDLE_SCHEMA
    required_manifest = {
        "schema_version",
        "status",
        "preparation_cycle",
        "cumulative_official_reads",
        "preparation_cycles_maximum",
        "official_physical_reads_maximum",
        "published_at_utc",
        "source_plan_sha256",
        "sport_key",
        "official_source",
        "workspace_receipt_sha256",
        "mission_manifest_sha256",
        "selection_schema",
        "selection_purpose",
        "selection_sha256",
        "fixture_target_set_sha256",
        "selected_window_id",
        "selected_not_before_utc",
        "selected_usable_expires_at_utc",
        "maximum_http_calls",
        "maximum_credits",
        "markets",
        "region",
        "production_selection_authority",
        "promotion_authority",
        "batch_authority",
        "scientific_edge_claim",
        "artifact_sha256",
        "provider_dns",
        "provider_tcp",
        "provider_http",
        "secret_reads",
        "owner_review_pack_builds",
    }
    if prefetched_schema:
        required_manifest.update(
            {
                "h2_window_duration_seconds",
                "h2_prefetch_lead_seconds",
                "post_open_total_budget_seconds",
                "post_open_safety_reserve_seconds",
                "maximum_open_to_preflight_seconds",
            }
        )
    if (
        set(manifest) != required_manifest
        or manifest.get("schema_version")
        not in {FIRST_C0_CANARY_BUNDLE_SCHEMA, FIRST_C0_PREFETCHED_WINDOW_BUNDLE_SCHEMA}
        or manifest.get("status")
        not in {
            "CANARY_READY_NOW",
            "CANARY_FUTURE_WINDOW",
            "PREFETCHED_FUTURE_WINDOW",
        }
        or prefetched_schema != (manifest.get("status") == "PREFETCHED_FUTURE_WINDOW")
    ):
        raise PreDnsOrchestrationError("FIRST_C0_CANARY_BUNDLE_MANIFEST_INVALID")
    raw_hashes = manifest.get("artifact_sha256")
    if not isinstance(raw_hashes, dict) or not 11 <= len(raw_hashes) <= 18:
        raise PreDnsOrchestrationError("FIRST_C0_CANARY_BUNDLE_MANIFEST_INVALID")
    expected_names = {"bundle-manifest.json", *raw_hashes}
    observed_names = {entry.name for entry in root.iterdir()}
    if expected_names != observed_names or len({name.casefold() for name in expected_names}) != len(
        expected_names
    ):
        raise PreDnsOrchestrationError("FIRST_C0_CANARY_BUNDLE_FILE_SET_INVALID")
    payloads: dict[str, bytes] = {}
    for raw_name, raw_hash in raw_hashes.items():
        if (
            not isinstance(raw_name, str)
            or not isinstance(raw_hash, str)
            or len(raw_hash) != 64
            or raw_hash != raw_hash.casefold()
            or any(character not in "0123456789abcdef" for character in raw_hash)
        ):
            raise PreDnsOrchestrationError("FIRST_C0_CANARY_BUNDLE_MANIFEST_INVALID")
        name = _safe_name(raw_name)
        payload = _read_regular_bounded(
            root / name,
            maximum_bytes=MAXIMUM_BUNDLE_ARTIFACT_BYTES,
        )
        if _sha256(payload) != raw_hash:
            raise PreDnsOrchestrationError("FIRST_C0_CANARY_BUNDLE_ARTIFACT_HASH_MISMATCH")
        payloads[name] = payload
    try:
        workspace = RealCaptureWorkspaceReceiptV1.model_validate_json(
            payloads["workspace-receipt.json"]
        )
        mission = RealExecutionMissionManifestV1.model_validate_json(
            payloads["mission-manifest.json"]
        )
        source_plan = _load_first_c0_canary_source_plan_v1(payloads["source-plan.json"])
        selection_payload = strict_json_loads(payloads["first-c0-canary-selection.json"])
        selection = load_campaign_selection_authority_v1(selection_payload)
        if not isinstance(selection, FirstC0CanarySelectionV1):
            raise ValueError
        target_set = FixtureTargetSetV1.model_validate_json(payloads["fixture-target-set.json"])
        evidence = strict_json_object(payloads["official-schedule-evidence.json"])
        receipt = strict_json_object(payloads["official-fetch-receipt.json"])
        parsed_receipt = _parse_fetch_receipt(payloads["official-fetch-receipt.json"])
        counters = strict_json_object(payloads["preparation-counters.json"])
        marker = _load_first_c0_canary_marker_inspection_v1(
            payloads["marker-inspection.json"],
            workspace=workspace,
            mission=mission,
        )
    except (
        CaptureContractError,
        KeyError,
        PreDnsOrchestrationError,
        TypeError,
        ValueError,
    ) as error:
        if isinstance(error, PreDnsOrchestrationError):
            raise
        raise PreDnsOrchestrationError("FIRST_C0_CANARY_BUNDLE_CONTRACT_INVALID") from None
    counter_fields = {
        "official_reads",
        "cumulative_official_reads",
        "preparation_cycle",
        "preparation_cycles_maximum",
        "official_physical_reads_maximum",
        "supporting_official_reads",
        "target_set_freezes",
        "selector_invocations",
        "provider_dns",
        "provider_tcp",
        "provider_http",
        "secret_reads",
        "owner_review_pack_builds",
    }
    cycle = counters.get("preparation_cycle")
    cumulative_reads = counters.get("cumulative_official_reads")
    supporting_count = counters.get("supporting_official_reads")
    expected_supporting_count = int(source_plan.source.adapter == LALIGA_PUBLIC_MATCHES_JSON_V1)
    official_read_ceiling = 2 if mission.mission_id == "FIRST_C0_VERTICAL_V1" else 12
    expected_cycle_names = (
        {
            *(f"prior-cycle-{index:02d}-read-reservation.json" for index in range(1, cycle)),
            *(f"prior-cycle-{index:02d}-attempt-receipt.json" for index in range(1, cycle)),
        }
        if type(cycle) is int and 1 <= cycle <= 3
        else set()
    )
    fixed_names = {
        "workspace-receipt.json",
        "mission-manifest.json",
        "source-plan.json",
        "official-source-raw.bin",
        "official-fetch-receipt.json",
        "official-schedule-evidence.json",
        "fixture-target-set.json",
        "first-c0-canary-selection.json",
        "marker-inspection.json",
        "preparation-counters.json",
        "current-cycle-read-reservation.json",
        *(
            f"official-supporting-source-raw-{index}.bin"
            for index in range(1, expected_supporting_count + 1)
        ),
        *expected_cycle_names,
    }
    zero_effects = {
        "provider_dns": 0,
        "provider_tcp": 0,
        "provider_http": 0,
        "secret_reads": 0,  # nosec B105
        "owner_review_pack_builds": 0,
    }
    if (
        set(counters) != counter_fields
        or set(payloads) != fixed_names
        or type(cycle) is not int
        or not 1 <= cycle <= 3
        or counters.get("preparation_cycles_maximum") != 3
        or counters.get("official_physical_reads_maximum") != official_read_ceiling
        or counters.get("official_reads") != 1 + expected_supporting_count
        or type(cumulative_reads) is not int
        or not cast(int, counters["official_reads"]) <= cumulative_reads <= official_read_ceiling
        or supporting_count != expected_supporting_count
        or counters.get("target_set_freezes") != 1
        or counters.get("selector_invocations") != 1
        or any(counters.get(name) != value for name, value in zero_effects.items())
        or manifest.get("preparation_cycle") != cycle
        or manifest.get("cumulative_official_reads") != cumulative_reads
        or manifest.get("preparation_cycles_maximum") != 3
        or manifest.get("official_physical_reads_maximum") != official_read_ceiling
        or any(manifest.get(name) != value for name, value in zero_effects.items())
    ):
        raise PreDnsOrchestrationError("FIRST_C0_CANARY_BUNDLE_COUNTERS_INVALID")
    reservation_fields = {
        "schema_version",
        "cycle_index",
        "cycle_role",
        "workspace_receipt_sha256",
        "mission_manifest_sha256",
        "source_plan_sha256",
        "prior_cycle_receipt_sha256",
        "sport_key",
        "adapter",
        "url",
        "status",
        "official_reads_reserved",
        "cumulative_official_reads_reserved",
        "provider_dns",
        "provider_tcp",
        "provider_http",
        "secret_reads",
        "owner_review_pack_builds",
        "recorded_at_utc",
    }
    receipt_fields = {
        "schema_version",
        "cycle_index",
        "cycle_role",
        "workspace_receipt_sha256",
        "mission_manifest_sha256",
        "source_plan_sha256",
        "prior_cycle_receipt_sha256",
        "reservation_sha256",
        "sport_key",
        "adapter",
        "url",
        "status",
        "code",
        "fallback_category",
        "failure_classification",
        "http_status",
        "official_reads",
        "supporting_official_reads",
        "cumulative_official_reads",
        "recommended_refresh_utc",
        "selected_not_before_utc",
        "bundle_manifest_sha256",
        "official_fetch_receipt",
        "provider_dns",
        "provider_tcp",
        "provider_http",
        "secret_reads",
        "owner_review_pack_builds",
        "recorded_at_utc",
    }
    prior_receipt_sha256: str | None = None
    previous_cumulative = 0
    previous_recorded_at: datetime | None = None
    previous_attempt: Mapping[str, object] | None = None
    previous_plan: FirstC0CanarySourcePlanAuthorityV1 | None = None
    for index in range(1, cycle):
        try:
            reservation_bytes = payloads[f"prior-cycle-{index:02d}-read-reservation.json"]
            receipt_bytes = payloads[f"prior-cycle-{index:02d}-attempt-receipt.json"]
            reservation = strict_json_object(reservation_bytes)
            attempt = strict_json_object(receipt_bytes)
            reservation_plan = _first_c0_canary_source_plan_from_cycle_record_v1(reservation)
            attempt_plan = _first_c0_canary_source_plan_from_cycle_record_v1(attempt)
            reserved_at = _parse_exact_utc_text(
                reservation.get("recorded_at_utc"),
                code="FIRST_C0_CANARY_BUNDLE_LINEAGE_INVALID",
            )
            attempted_at = _parse_exact_utc_text(
                attempt.get("recorded_at_utc"),
                code="FIRST_C0_CANARY_BUNDLE_LINEAGE_INVALID",
            )
        except (KeyError, PreDnsOrchestrationError, TypeError, ValueError):
            raise PreDnsOrchestrationError("FIRST_C0_CANARY_BUNDLE_LINEAGE_INVALID") from None
        read_count = reservation.get("official_reads_reserved")
        cumulative = reservation.get("cumulative_official_reads_reserved")
        expected_supporting = int(reservation_plan.source.adapter == LALIGA_PUBLIC_MATCHES_JSON_V1)
        status = attempt.get("status")
        success_semantics_valid = (
            status == "SUCCEEDED"
            and attempt.get("code")
            in {
                "CANARY_READY_NOW",
                "CANARY_FUTURE_WINDOW",
                "PREFETCHED_FUTURE_WINDOW",
            }
            and attempt.get("fallback_category") is None
            and attempt.get("failure_classification") is None
            and attempt.get("http_status") == 200
            and isinstance(attempt.get("recommended_refresh_utc"), str)
            and isinstance(attempt.get("selected_not_before_utc"), str)
            and _is_sha256_text(attempt.get("bundle_manifest_sha256"))
            and isinstance(attempt.get("official_fetch_receipt"), dict)
        )
        failure_semantics_valid = (
            status in {"FAILED_BEFORE_DNS", "FAILED_NO_FALLBACK"}
            and isinstance(attempt.get("code"), str)
            and attempt.get("failure_classification") in {"TRANSIENT", "DETERMINISTIC"}
            and type(attempt.get("http_status")) is int
            and attempt.get("recommended_refresh_utc") is None
            and attempt.get("selected_not_before_utc") is None
            and attempt.get("bundle_manifest_sha256") is None
            and (
                attempt.get("official_fetch_receipt") is None
                or isinstance(attempt.get("official_fetch_receipt"), dict)
            )
        )
        transition_valid = True
        if index == 1:
            transition_valid = (
                reservation_plan.source.sport_key == "soccer_spain_la_liga"
                and reservation.get("cycle_role") == "PRIMARY_INITIAL"
                and prior_receipt_sha256 is None
            )
        elif previous_attempt is None or previous_plan is None:
            transition_valid = False
        elif previous_attempt.get("status") == "SUCCEEDED":
            refresh_at = _parse_exact_utc_text(
                previous_attempt.get("recommended_refresh_utc"),
                code="FIRST_C0_CANARY_BUNDLE_LINEAGE_INVALID",
            )
            transition_valid = (
                previous_attempt.get("code") == "CANARY_FUTURE_WINDOW"
                and reservation_plan == previous_plan
                and reservation.get("cycle_role")
                == (
                    "PRIMARY_REFRESH"
                    if reservation_plan.source.sport_key == "soccer_spain_la_liga"
                    else "FALLBACK_REFRESH"
                )
                and reserved_at >= refresh_at
            )
        elif previous_plan.source.sport_key == "soccer_spain_la_liga":
            transition_valid = (
                previous_attempt.get("status") == "FAILED_BEFORE_DNS"
                and previous_attempt.get("fallback_category")
                in {
                    "SOURCE_UNAVAILABLE",
                    "PARSER_FAIL_CLOSED",
                    "NO_PROSPECTIVE_FIXTURE",
                    "NO_H24_H2_WINDOW",
                }
                and reservation_plan.source.sport_key == "soccer_germany_bundesliga"
                and reservation.get("cycle_role") == "FALLBACK_INITIAL"
            )
        else:
            transition_valid = False
        if (
            set(reservation) != reservation_fields
            or set(attempt) != receipt_fields
            or reservation.get("schema_version")
            != "robin-first-c0-canary-official-read-reservation-v1"
            or attempt.get("schema_version") != "robin-first-c0-canary-attempt-receipt-v1"
            or reservation.get("cycle_index") != index
            or attempt.get("cycle_index") != index
            or reservation.get("cycle_role") != attempt.get("cycle_role")
            or not isinstance(reservation.get("cycle_role"), str)
            or reservation.get("prior_cycle_receipt_sha256") != prior_receipt_sha256
            or attempt.get("prior_cycle_receipt_sha256") != prior_receipt_sha256
            or attempt.get("reservation_sha256") != _sha256(reservation_bytes)
            or reservation_plan != attempt_plan
            or reservation.get("source_plan_sha256") != reservation_plan.canonical_sha256
            or attempt.get("source_plan_sha256") != reservation_plan.canonical_sha256
            or reservation.get("workspace_receipt_sha256") != workspace.canonical_receipt_hash
            or attempt.get("workspace_receipt_sha256") != workspace.canonical_receipt_hash
            or reservation.get("mission_manifest_sha256") != mission.canonical_manifest_sha256()
            or attempt.get("mission_manifest_sha256") != mission.canonical_manifest_sha256()
            or reservation.get("status") != "RESERVED_BEFORE_OFFICIAL_READ"
            or not (success_semantics_valid or failure_semantics_valid)
            or type(read_count) is not int
            or read_count != 1 + expected_supporting
            or type(cumulative) is not int
            or cumulative != previous_cumulative + read_count
            or attempt.get("official_reads") != read_count
            or attempt.get("supporting_official_reads") != expected_supporting
            or attempt.get("cumulative_official_reads") != cumulative
            or cumulative > official_read_ceiling
            or attempted_at < reserved_at
            or (previous_recorded_at is not None and reserved_at < previous_recorded_at)
            or not transition_valid
            or any(reservation.get(name) != value for name, value in zero_effects.items())
            or any(attempt.get(name) != value for name, value in zero_effects.items())
        ):
            raise PreDnsOrchestrationError("FIRST_C0_CANARY_BUNDLE_LINEAGE_INVALID")
        prior_receipt_sha256 = _sha256(receipt_bytes)
        previous_cumulative = cumulative
        previous_recorded_at = attempted_at
        previous_attempt = attempt
        previous_plan = reservation_plan
    try:
        current_reservation = strict_json_object(payloads["current-cycle-read-reservation.json"])
        current_reserved_at = _parse_exact_utc_text(
            current_reservation.get("recorded_at_utc"),
            code="FIRST_C0_CANARY_BUNDLE_LINEAGE_INVALID",
        )
        current_attempt_bytes = _read_regular_bounded(
            Path(workspace.control_temp_root)
            / f"first-c0-canary-cycle-{cycle:02d}-attempt-receipt-v1.json",
            maximum_bytes=MAXIMUM_BUNDLE_ARTIFACT_BYTES,
        )
        current_attempt = strict_json_object(current_attempt_bytes)
        current_attempted_at = _parse_exact_utc_text(
            current_attempt.get("recorded_at_utc"),
            code="FIRST_C0_CANARY_BUNDLE_LINEAGE_INVALID",
        )
    except (KeyError, OSError, PreDnsOrchestrationError, TypeError, ValueError):
        raise PreDnsOrchestrationError("FIRST_C0_CANARY_BUNDLE_LINEAGE_INVALID") from None
    if cycle == 1:
        current_transition_valid = (
            source_plan.source.sport_key == "soccer_spain_la_liga"
            and current_reservation.get("cycle_role") == "PRIMARY_INITIAL"
            and prior_receipt_sha256 is None
        )
    elif previous_attempt is None or previous_plan is None:
        current_transition_valid = False
    elif previous_attempt.get("status") == "SUCCEEDED":
        refresh_at = _parse_exact_utc_text(
            previous_attempt.get("recommended_refresh_utc"),
            code="FIRST_C0_CANARY_BUNDLE_LINEAGE_INVALID",
        )
        current_transition_valid = (
            previous_attempt.get("code") == "CANARY_FUTURE_WINDOW"
            and source_plan == previous_plan
            and current_reservation.get("cycle_role")
            == (
                "PRIMARY_REFRESH"
                if source_plan.source.sport_key == "soccer_spain_la_liga"
                else "FALLBACK_REFRESH"
            )
            and current_reserved_at >= refresh_at
        )
    elif previous_plan.source.sport_key == "soccer_spain_la_liga":
        current_transition_valid = (
            previous_attempt.get("status") == "FAILED_BEFORE_DNS"
            and previous_attempt.get("fallback_category")
            in {
                "SOURCE_UNAVAILABLE",
                "PARSER_FAIL_CLOSED",
                "NO_PROSPECTIVE_FIXTURE",
                "NO_H24_H2_WINDOW",
            }
            and source_plan.source.sport_key == "soccer_germany_bundesliga"
            and current_reservation.get("cycle_role") == "FALLBACK_INITIAL"
        )
    else:
        current_transition_valid = False
    if (
        set(current_reservation) != reservation_fields
        or set(current_attempt) != receipt_fields
        or current_reservation.get("schema_version")
        != "robin-first-c0-canary-official-read-reservation-v1"
        or current_attempt.get("schema_version") != "robin-first-c0-canary-attempt-receipt-v1"
        or current_reservation.get("cycle_index") != cycle
        or current_attempt.get("cycle_index") != cycle
        or current_attempt.get("cycle_role") != current_reservation.get("cycle_role")
        or current_reservation.get("prior_cycle_receipt_sha256") != prior_receipt_sha256
        or current_attempt.get("prior_cycle_receipt_sha256") != prior_receipt_sha256
        or current_attempt.get("reservation_sha256")
        != _sha256(payloads["current-cycle-read-reservation.json"])
        or current_reservation.get("workspace_receipt_sha256") != workspace.canonical_receipt_hash
        or current_attempt.get("workspace_receipt_sha256") != workspace.canonical_receipt_hash
        or current_reservation.get("mission_manifest_sha256") != mission.canonical_manifest_sha256()
        or current_attempt.get("mission_manifest_sha256") != mission.canonical_manifest_sha256()
        or current_reservation.get("source_plan_sha256") != source_plan.canonical_sha256
        or current_attempt.get("source_plan_sha256") != source_plan.canonical_sha256
        or current_reservation.get("sport_key") != source_plan.source.sport_key
        or current_attempt.get("sport_key") != source_plan.source.sport_key
        or current_reservation.get("adapter") != source_plan.source.adapter
        or current_attempt.get("adapter") != source_plan.source.adapter
        or current_reservation.get("url") != source_plan.source.url
        or current_attempt.get("url") != source_plan.source.url
        or current_reservation.get("status") != "RESERVED_BEFORE_OFFICIAL_READ"
        or current_attempt.get("status") != "SUCCEEDED"
        or current_attempt.get("code") != manifest.get("status")
        or current_attempt.get("fallback_category") is not None
        or current_attempt.get("failure_classification") is not None
        or current_attempt.get("http_status") != 200
        or current_reservation.get("official_reads_reserved") != counters["official_reads"]
        or current_attempt.get("official_reads") != counters["official_reads"]
        or current_attempt.get("supporting_official_reads") != expected_supporting_count
        or current_reservation.get("cumulative_official_reads_reserved") != cumulative_reads
        or current_attempt.get("cumulative_official_reads") != cumulative_reads
        or current_attempt.get("selected_not_before_utc") != manifest.get("selected_not_before_utc")
        or not isinstance(current_attempt.get("recommended_refresh_utc"), str)
        or current_attempt.get("bundle_manifest_sha256") != _sha256(manifest_bytes)
        or current_attempt.get("official_fetch_receipt") != receipt
        or current_attempted_at
        < _parse_exact_utc_text(
            manifest.get("published_at_utc"),
            code="FIRST_C0_CANARY_BUNDLE_LINEAGE_INVALID",
        )
        or current_attempted_at < current_reserved_at
        or (previous_recorded_at is not None and current_reserved_at < previous_recorded_at)
        or not current_transition_valid
        or previous_cumulative + cast(int, counters["official_reads"]) != cumulative_reads
        or any(current_reservation.get(name) != value for name, value in zero_effects.items())
        or any(current_attempt.get(name) != value for name, value in zero_effects.items())
    ):
        raise PreDnsOrchestrationError("FIRST_C0_CANARY_BUNDLE_LINEAGE_INVALID")
    selected = selection.selected_candidate()
    expected_refresh = max(
        selection.selected_at_utc,
        selected.window_not_before_utc
        - timedelta(
            seconds=(FIRST_C0_H2_PREFETCH_LEAD_SECONDS if selected.window_id == "H2" else 60)
        ),
    )
    if (
        root.parent != Path(workspace.control_temp_root).absolute()
        or manifest.get("workspace_receipt_sha256") != workspace.canonical_receipt_hash
        or manifest.get("mission_manifest_sha256") != mission.canonical_manifest_sha256()
        or manifest.get("source_plan_sha256") != source_plan.canonical_sha256
        or manifest.get("sport_key") != source_plan.source.sport_key
        or manifest.get("official_source") != source_plan.source.url
        or selection.source_target_sets != (target_set,)
        or selection.workspace_receipt_sha256 != workspace.canonical_receipt_hash
        or selection.workspace_prepared_at_utc != workspace.prepared_at_utc
        or selection.mission_id != mission.mission_id
        or selection.mission_manifest_sha256 != mission.canonical_manifest_sha256()
        or selection.mission_expires_at_utc != mission.expires_at
        or current_attempt.get("recommended_refresh_utc") != _utc_text(expected_refresh)
        or _parse_exact_utc_text(
            manifest.get("published_at_utc"),
            code="FIRST_C0_CANARY_BUNDLE_AUTHORITY_MISMATCH",
        )
        < selection.selected_at_utc
    ):
        raise PreDnsOrchestrationError("FIRST_C0_CANARY_BUNDLE_AUTHORITY_MISMATCH")
    expected_status = (
        "CANARY_READY_NOW"
        if selected.status == "OPEN_SELECTABLE"
        else "PREFETCHED_FUTURE_WINDOW"
        if prefetched_schema
        else "CANARY_FUTURE_WINDOW"
    )
    if (
        manifest.get("status") != expected_status
        or (
            prefetched_schema
            and (
                selected.window_id != "H2"
                or selected.status != "FUTURE_NOT_OPEN"
                or current_reserved_at
                < selected.window_not_before_utc
                - timedelta(seconds=FIRST_C0_H2_PREFETCH_LEAD_SECONDS)
                or current_attempted_at >= selected.window_not_before_utc
                or manifest.get("h2_window_duration_seconds") != FIRST_C0_H2_WINDOW_DURATION_SECONDS
                or manifest.get("h2_prefetch_lead_seconds") != FIRST_C0_H2_PREFETCH_LEAD_SECONDS
                or manifest.get("post_open_total_budget_seconds")
                != FIRST_C0_POST_OPEN_TOTAL_BUDGET_SECONDS
                or manifest.get("post_open_safety_reserve_seconds")
                != FIRST_C0_POST_OPEN_SAFETY_RESERVE_SECONDS
                or manifest.get("maximum_open_to_preflight_seconds")
                != FIRST_C0_MAXIMUM_OPEN_TO_PREFLIGHT_SECONDS
                or int(
                    (
                        selected.window_expires_at_utc - selected.window_not_before_utc
                    ).total_seconds()
                )
                != FIRST_C0_H2_WINDOW_DURATION_SECONDS
                or int(
                    (
                        selected.usable_expires_at_utc - selected.window_not_before_utc
                    ).total_seconds()
                )
                < MINIMUM_READY_MARGIN_SECONDS + FIRST_C0_MAXIMUM_OPEN_TO_PREFLIGHT_SECONDS
            )
        )
        or manifest.get("selection_schema") != selection.schema_version
        or manifest.get("selection_purpose") != selection.purpose
        or manifest.get("selection_sha256") != selection.canonical_selection_hash
        or manifest.get("fixture_target_set_sha256")
        != selected.fixture_target_set.canonical_set_hash
        or manifest.get("selected_window_id") != selected.window_id
        or manifest.get("selected_not_before_utc") != _utc_text(selection.selected_not_before_utc)
        or manifest.get("selected_usable_expires_at_utc")
        != _utc_text(selected.usable_expires_at_utc)
        or manifest.get("maximum_http_calls") != 1
        or manifest.get("maximum_credits") != 1
        or manifest.get("markets") != ["h2h"]
        or manifest.get("region") != "eu"
        or manifest.get("production_selection_authority") is not False
        or manifest.get("promotion_authority") is not False
        or manifest.get("batch_authority") is not False
        or manifest.get("scientific_edge_claim") is not False
    ):
        raise PreDnsOrchestrationError("FIRST_C0_CANARY_BUNDLE_AUTHORITY_MISMATCH")
    raw_payload = payloads["official-source-raw.bin"]
    supporting_payloads = tuple(
        payloads[f"official-supporting-source-raw-{index}.bin"]
        for index in range(1, expected_supporting_count + 1)
    )
    final_url = receipt.get("final_url")
    final_host = (
        (urlparse(final_url).hostname or "").rstrip(".").casefold()
        if isinstance(final_url, str)
        else ""
    )
    raw_fixtures = evidence.get("fixtures")
    normalized_fixtures: list[dict[str, object]] = []
    if isinstance(raw_fixtures, list):
        for raw_fixture in raw_fixtures:
            if not isinstance(raw_fixture, dict):
                break
            home = raw_fixture.get("official_home_team")
            away = raw_fixture.get("official_away_team")
            if not isinstance(home, str) or not isinstance(away, str):
                break
            normalized_fixtures.append(
                {
                    "internal_fixture_target_id": raw_fixture.get("internal_fixture_target_id"),
                    "competition": raw_fixture.get("competition"),
                    "official_home_team": canonical_team_name_v1(home),
                    "official_away_team": canonical_team_name_v1(away),
                    "official_kickoff_utc": raw_fixture.get("official_kickoff_utc"),
                }
            )
    target_material = [
        {
            "internal_fixture_target_id": target.internal_fixture_target_id,
            "competition": target.competition,
            "official_home_team": target.official_home_team,
            "official_away_team": target.official_away_team,
            "official_kickoff_utc": _utc_text(target.official_kickoff_utc),
        }
        for target in target_set.targets
    ]
    if (
        parsed_receipt.sport_key != source_plan.source.sport_key
        or parsed_receipt.adapter_revision != source_plan.source.adapter
        or parsed_receipt.requested_url != source_plan.source.url
        or not parsed_receipt.accepted
        or parsed_receipt.rejection_code is not None
        or parsed_receipt.http_status != 200
        or parsed_receipt.raw_sha256 != _sha256(raw_payload)
        or parsed_receipt.byte_count != len(raw_payload)
        or len(parsed_receipt.supporting_official_reads) != len(supporting_payloads)
        or any(
            item.byte_count != len(raw) or item.raw_sha256 != _sha256(raw)
            for item, raw in zip(
                parsed_receipt.supporting_official_reads,
                supporting_payloads,
                strict=True,
            )
        )
        or not any(
            final_host == domain or final_host.endswith(f".{domain}")
            for domain in source_plan.source.allowed_domains
        )
        or evidence.get("sport_key") != source_plan.source.sport_key
        or evidence.get("adapter_revision") != source_plan.source.adapter
        or evidence.get("target_set_id") != target_set.target_set_id
        or evidence.get("official_source_authority") != final_url
        or evidence.get("official_source_content_sha256") != _sha256(raw_payload)
        or evidence.get("source_observed_at_utc") != receipt.get("observed_at_utc")
        or evidence.get("selection_horizon_not_before_utc")
        != _utc_text(cast(datetime, target_set.official_schedule_horizon_not_before_utc))
        or evidence.get("selection_horizon_expires_at_utc")
        != _utc_text(cast(datetime, target_set.official_schedule_horizon_expires_at_utc))
        or evidence.get("official_schedule_completeness")
        != "OWNER_REVIEWED_COMPLETE_OFFICIAL_HORIZON"
        or evidence.get("official_schedule_fixture_count") != len(target_set.targets)
        or normalized_fixtures != target_material
        or any(
            target.source_evidence_sha256 != _sha256(payloads["official-schedule-evidence.json"])
            or _utc_text(target.source_observed_at_utc) != receipt.get("observed_at_utc")
            or target.official_source_authority != final_url
            for target in target_set.targets
        )
    ):
        raise PreDnsOrchestrationError("FIRST_C0_CANARY_BUNDLE_AUTHORITY_MISMATCH")
    raw_evidence_verifier(
        source_plan.source,
        raw_payload,
        payloads["official-fetch-receipt.json"],
        payloads["official-schedule-evidence.json"],
        target_set,
        supporting_payloads,
    )
    return LoadedPreDnsBundleV1(
        directory=root,
        manifest=manifest,
        manifest_sha256=_sha256(manifest_bytes),
        workspace_receipt=workspace,
        mission_manifest=mission,
        source_plan=source_plan,
        campaign_selection=selection,
        target_sets=(target_set,),
        marker_inspection=marker,
    )


def load_first_c0_prefetch_handoff_v1(
    path: Path,
    loaded: LoadedPreDnsBundleV1,
) -> FirstC0PrefetchedWindowHandoffV1:
    """Load the append-only backlink that closes a prefetched H2 bundle."""

    if (
        loaded.manifest.get("schema_version") != FIRST_C0_PREFETCHED_WINDOW_BUNDLE_SCHEMA
        or loaded.manifest.get("status") != "PREFETCHED_FUTURE_WINDOW"
        or path.name != _PREFETCH_HANDOFF_NAME
        or path.absolute().parent != Path(loaded.workspace_receipt.control_temp_root).absolute()
    ):
        raise PreDnsOrchestrationError("FIRST_C0_PREFETCH_HANDOFF_BOUNDARY_INVALID")
    payload = _read_regular_bounded(path, maximum_bytes=MAXIMUM_BUNDLE_ARTIFACT_BYTES)
    try:
        handoff = FirstC0PrefetchedWindowHandoffV1.model_validate_json(payload)
    except (TypeError, ValueError):
        raise PreDnsOrchestrationError("FIRST_C0_PREFETCH_HANDOFF_INVALID") from None
    if payload != _model_bytes(handoff):
        raise PreDnsOrchestrationError("FIRST_C0_PREFETCH_HANDOFF_BYTES_NONCANONICAL")
    selection = loaded.campaign_selection
    if not isinstance(selection, FirstC0CanarySelectionV1):
        raise PreDnsOrchestrationError("FIRST_C0_PREFETCH_HANDOFF_AUTHORITY_INVALID")
    selected = selection.selected_candidate()
    artifacts = loaded.manifest.get("artifact_sha256")
    source_plan_sha256 = getattr(loaded.source_plan, "canonical_sha256", None)
    source_observed = {target.source_observed_at_utc for target in loaded.target_sets[0].targets}
    try:
        published_at = _parse_exact_utc_text(
            loaded.manifest.get("published_at_utc"),
            code="FIRST_C0_PREFETCH_HANDOFF_AUTHORITY_INVALID",
        )
    except PreDnsOrchestrationError:
        raise PreDnsOrchestrationError("FIRST_C0_PREFETCH_HANDOFF_AUTHORITY_INVALID") from None
    if (
        not isinstance(artifacts, dict)
        or handoff.workspace_receipt_sha256 != loaded.workspace_receipt.canonical_receipt_hash
        or handoff.mission_manifest_sha256 != loaded.mission_manifest.canonical_manifest_sha256()
        or handoff.source_plan_sha256 != source_plan_sha256
        or handoff.official_fetch_receipt_sha256 != artifacts.get("official-fetch-receipt.json")
        or handoff.official_raw_sha256 != artifacts.get("official-source-raw.bin")
        or handoff.official_evidence_sha256 != artifacts.get("official-schedule-evidence.json")
        or handoff.fixture_target_set_sha256 != selected.fixture_target_set.canonical_set_hash
        or handoff.campaign_selection_sha256 != selection.canonical_selection_hash
        or handoff.selected_candidate_sha256 != selected.canonical_candidate_hash
        or handoff.bundle_manifest_sha256 != loaded.manifest_sha256
        or handoff.selected_window_id != selected.window_id
        or handoff.prefetched_at_utc < published_at
        or handoff.prefetched_at_utc >= handoff.window_not_before_utc
        or handoff.window_not_before_utc != selected.window_not_before_utc
        or handoff.window_expires_at_utc != selected.window_expires_at_utc
        or handoff.selected_usable_expires_at_utc != selected.usable_expires_at_utc
        or handoff.preparation_cycle_number != loaded.manifest.get("preparation_cycle")
        or handoff.official_physical_reads_cumulative
        != loaded.manifest.get("cumulative_official_reads")
        or source_observed != {handoff.source_observed_at_utc}
    ):
        raise PreDnsOrchestrationError("FIRST_C0_PREFETCH_HANDOFF_AUTHORITY_INVALID")
    return handoff


def load_first_c0_window_open_revalidation_v1(
    path: Path,
    loaded: LoadedPreDnsBundleV1,
    handoff: FirstC0PrefetchedWindowHandoffV1,
    *,
    handoff_path: Path,
) -> FirstC0WindowOpenRevalidationV1:
    if (
        path.name != _WINDOW_OPEN_RECEIPT_NAME
        or path.absolute().parent != Path(loaded.workspace_receipt.control_temp_root).absolute()
    ):
        raise PreDnsOrchestrationError("FIRST_C0_WINDOW_RECEIPT_BOUNDARY_INVALID")
    payload = _read_regular_bounded(path, maximum_bytes=MAXIMUM_BUNDLE_ARTIFACT_BYTES)
    handoff_payload = _read_regular_bounded(
        handoff_path,
        maximum_bytes=MAXIMUM_BUNDLE_ARTIFACT_BYTES,
    )
    try:
        receipt = FirstC0WindowOpenRevalidationV1.model_validate_json(payload)
    except (TypeError, ValueError):
        raise PreDnsOrchestrationError("FIRST_C0_WINDOW_RECEIPT_INVALID") from None
    selected = loaded.campaign_selection.selected_candidate()
    if (
        payload != _model_bytes(receipt)
        or handoff_payload != _model_bytes(handoff)
        or receipt.prefetch_handoff_sha256 != _sha256(handoff_payload)
        or receipt.workspace_receipt_sha256 != loaded.workspace_receipt.canonical_receipt_hash
        or receipt.mission_manifest_sha256 != loaded.mission_manifest.canonical_manifest_sha256()
        or receipt.bundle_manifest_sha256 != loaded.manifest_sha256
        or receipt.campaign_selection_sha256 != loaded.campaign_selection.canonical_selection_hash
        or receipt.selected_candidate_sha256 != selected.canonical_candidate_hash
        or receipt.source_observed_at_utc != handoff.source_observed_at_utc
        or receipt.mission_expires_at_utc != loaded.mission_manifest.expires_at
        or receipt.selected_usable_expires_at_utc != selected.usable_expires_at_utc
        or receipt.window_not_before_utc != handoff.window_not_before_utc
        or receipt.window_expires_at_utc != handoff.window_expires_at_utc
        or receipt.status != "READY_NOW"
    ):
        raise PreDnsOrchestrationError("FIRST_C0_WINDOW_RECEIPT_AUTHORITY_INVALID")
    return receipt


def _prefetched_bundle_bytes_current_v1(loaded: LoadedPreDnsBundleV1) -> bool:
    try:
        manifest_payload = _read_regular_bounded(
            loaded.directory / "bundle-manifest.json",
            maximum_bytes=MAXIMUM_BUNDLE_ARTIFACT_BYTES,
        )
        if _sha256(manifest_payload) != loaded.manifest_sha256:
            return False
        manifest = strict_json_object(manifest_payload)
        if manifest != dict(loaded.manifest):
            return False
        artifact_hashes = manifest.get("artifact_sha256")
        if not isinstance(artifact_hashes, dict):
            return False
        expected_names = {"bundle-manifest.json", *artifact_hashes}
        if {entry.name for entry in loaded.directory.iterdir()} != expected_names:
            return False
        return all(
            isinstance(name, str)
            and isinstance(expected, str)
            and _sha256(
                _read_regular_bounded(
                    loaded.directory / _safe_name(name),
                    maximum_bytes=MAXIMUM_BUNDLE_ARTIFACT_BYTES,
                )
            )
            == expected
            for name, expected in artifact_hashes.items()
        )
    except (OSError, PreDnsOrchestrationError, TypeError, ValueError):
        return False


def revalidate_prefetched_window_open_v1(
    *,
    loaded: LoadedPreDnsBundleV1,
    handoff: FirstC0PrefetchedWindowHandoffV1,
    handoff_path: Path,
    output_path: Path,
    wait_started_at_utc: datetime,
    wait_started_monotonic: float,
    clock_path_valid: bool = True,
    clock: ClockV1 = lambda: datetime.now(UTC),
    monotonic: MonotonicV1 = time.monotonic,
    workspace_validator: WorkspaceValidatorV1 = _validate_workspace_default,
) -> FirstC0WindowOpenRevalidationV1:
    """Activate one immutable future bundle using only local clocks and bytes."""

    control_root = Path(loaded.workspace_receipt.control_temp_root).absolute()
    if (
        output_path.absolute().parent != control_root
        or output_path.name != _WINDOW_OPEN_RECEIPT_NAME
    ):
        raise PreDnsOrchestrationError("FIRST_C0_WINDOW_RECEIPT_BOUNDARY_INVALID")
    if (
        handoff_path.absolute().parent != control_root
        or handoff_path.name != _PREFETCH_HANDOFF_NAME
    ):
        raise PreDnsOrchestrationError("FIRST_C0_PREFETCH_HANDOFF_BOUNDARY_INVALID")
    workspace_current = True
    try:
        workspace_validator(loaded.workspace_receipt)
    except Exception:
        workspace_current = False
    bundle_current = _prefetched_bundle_bytes_current_v1(loaded)
    try:
        handoff_current = _read_regular_bounded(
            handoff_path,
            maximum_bytes=MAXIMUM_BUNDLE_ARTIFACT_BYTES,
        ) == _model_bytes(handoff)
    except PreDnsOrchestrationError:
        handoff_current = False
    checked = _utc(clock(), code="FIRST_C0_WINDOW_CLOCK_INVALID")
    checked_monotonic = float(monotonic())
    started_monotonic = float(wait_started_monotonic)
    monotonic_elapsed = checked_monotonic - started_monotonic
    started = _utc(wait_started_at_utc, code="FIRST_C0_WINDOW_CLOCK_INVALID")
    wall_elapsed = (checked - started).total_seconds()
    clock_divergence = abs(wall_elapsed - monotonic_elapsed)
    monotonic_values_valid = (
        math.isfinite(started_monotonic)
        and started_monotonic >= 0
        and math.isfinite(checked_monotonic)
        and checked_monotonic >= 0
        and math.isfinite(monotonic_elapsed)
    )
    receipt_started_monotonic = started_monotonic if monotonic_values_valid else 0.0
    receipt_monotonic_elapsed = monotonic_elapsed if monotonic_values_valid else 0.0
    receipt_checked_monotonic = receipt_started_monotonic + receipt_monotonic_elapsed
    receipt_clock_divergence = abs(wall_elapsed - receipt_monotonic_elapsed)
    receipt_clock_path_valid = clock_path_valid and monotonic_values_valid
    selected = loaded.campaign_selection.selected_candidate()
    source_delta = checked - handoff.source_observed_at_utc
    source_age = int(source_delta.total_seconds())
    source_fresh = (
        timedelta(0) <= source_delta <= timedelta(seconds=handoff.maximum_source_age_seconds)
    )
    mission_current = checked < loaded.mission_manifest.expires_at
    usable_ceiling = selected.usable_expires_at_utc
    usable_margin = int((usable_ceiling - checked).total_seconds())
    selection_current = True
    try:
        loaded.campaign_selection.assert_selected_candidate_current(checked)
    except ValueError:
        selection_current = False
    if (
        not receipt_clock_path_valid
        or monotonic_elapsed < 0
        or wall_elapsed < 0
        or clock_divergence > 2.0
    ):
        status: Literal["READY_NOW", "EXPIRED", "CLOCK_INVALID", "STALE", "HARD_STOP"] = (
            "CLOCK_INVALID"
        )
    elif checked >= handoff.window_expires_at_utc or not mission_current:
        status = "EXPIRED"
    elif not source_fresh:
        status = "STALE"
    elif (
        not workspace_current
        or not bundle_current
        or not handoff_current
        or not selection_current
        or checked < handoff.window_not_before_utc
        or checked - handoff.window_not_before_utc
        > timedelta(seconds=FIRST_C0_MAXIMUM_OPEN_TO_PREFLIGHT_SECONDS)
        or usable_margin < MINIMUM_READY_MARGIN_SECONDS
    ):
        status = "HARD_STOP"
    else:
        status = "READY_NOW"
    try:
        receipt = FirstC0WindowOpenRevalidationV1.issue(
            prefetch_handoff_sha256=_sha256(_model_bytes(handoff)),
            workspace_receipt_sha256=loaded.workspace_receipt.canonical_receipt_hash,
            mission_manifest_sha256=loaded.mission_manifest.canonical_manifest_sha256(),
            bundle_manifest_sha256=loaded.manifest_sha256,
            campaign_selection_sha256=loaded.campaign_selection.canonical_selection_hash,
            selected_candidate_sha256=selected.canonical_candidate_hash,
            wait_started_at_utc=started,
            checked_at_utc=checked,
            source_observed_at_utc=handoff.source_observed_at_utc,
            mission_expires_at_utc=loaded.mission_manifest.expires_at,
            selected_usable_expires_at_utc=usable_ceiling,
            wait_started_monotonic=receipt_started_monotonic,
            window_open_monotonic=(
                receipt_started_monotonic
                + (handoff.window_not_before_utc - started).total_seconds()
            ),
            checked_monotonic=receipt_checked_monotonic,
            monotonic_elapsed_seconds=receipt_monotonic_elapsed,
            wall_elapsed_seconds=wall_elapsed,
            clock_divergence_seconds=receipt_clock_divergence,
            window_not_before_utc=handoff.window_not_before_utc,
            window_expires_at_utc=handoff.window_expires_at_utc,
            usable_margin_seconds=usable_margin,
            source_age_seconds=source_age,
            source_fresh=source_fresh,
            mission_current=mission_current,
            workspace_current=workspace_current,
            bundle_current=bundle_current and handoff_current,
            handoff_current=handoff_current,
            selection_current=selection_current,
            clock_path_valid=receipt_clock_path_valid,
            status=status,
        )
    except (TypeError, ValueError):
        raise PreDnsOrchestrationError("FIRST_C0_WINDOW_RECEIPT_BUILD_FAILED") from None
    _write_exclusive(output_path, _model_bytes(receipt))
    return receipt


def load_pre_dns_bundle_v1(
    directory: Path,
    *,
    raw_evidence_verifier: RawEvidenceVerifierV1 = verify_raw_official_evidence_v1,
) -> LoadedPreDnsBundleV1:
    root = _assert_plain_directory(directory)
    manifest_bytes = _read_regular_bounded(
        root / "bundle-manifest.json",
        maximum_bytes=MAXIMUM_BUNDLE_ARTIFACT_BYTES,
    )
    try:
        manifest = strict_json_object(manifest_bytes)
    except (TypeError, ValueError):
        raise PreDnsOrchestrationError("PRE_DNS_BUNDLE_MANIFEST_INVALID") from None
    if manifest.get("schema_version") in {
        FIRST_C0_CANARY_BUNDLE_SCHEMA,
        FIRST_C0_PREFETCHED_WINDOW_BUNDLE_SCHEMA,
    }:
        return _load_first_c0_canary_bundle_v1(
            root,
            manifest_bytes,
            manifest,
            raw_evidence_verifier=raw_evidence_verifier,
        )
    required = {
        "schema_version",
        "status",
        "published_at_utc",
        "runtime_main_sha",
        "workspace_receipt_sha256",
        "mission_manifest_sha256",
        "source_plan_sha256",
        "campaign_selection_sha256",
        "selected_candidate_id",
        "selected_candidate_sha256",
        "selected_sport_key",
        "selected_window_id",
        "selected_not_before_utc",
        "selected_usable_expires_at_utc",
        "selected_earliest_kickoff_utc",
        "recommended_refresh_utc",
        "recommended_refresh_europe_paris",
        "artifacts",
        "effects",
        "canonical_bundle_manifest_sha256",
    }
    if (
        set(manifest) != required
        or manifest.get("schema_version") != PRE_DNS_BUNDLE_SCHEMA
        or manifest.get("status") not in {"PRE_DNS_READY_NOW", "PRE_DNS_FUTURE_WINDOW_PLANNED"}
    ):
        raise PreDnsOrchestrationError("PRE_DNS_BUNDLE_MANIFEST_INVALID")
    canonical_hash = manifest.get("canonical_bundle_manifest_sha256")
    without_hash = {
        key: value for key, value in manifest.items() if key != "canonical_bundle_manifest_sha256"
    }
    if canonical_hash != _sha256(_json_bytes(without_hash)):
        raise PreDnsOrchestrationError("PRE_DNS_BUNDLE_MANIFEST_HASH_MISMATCH")
    raw_entries = manifest.get("artifacts")
    if not isinstance(raw_entries, dict) or set(raw_entries) != _expected_bundle_artifact_names():
        raise PreDnsOrchestrationError("PRE_DNS_BUNDLE_MANIFEST_INVALID")
    expected_names = {"bundle-manifest.json", *raw_entries.keys()}
    observed_names = {entry.name for entry in root.iterdir()}
    if expected_names != observed_names or len({name.casefold() for name in expected_names}) != len(
        expected_names
    ):
        raise PreDnsOrchestrationError("PRE_DNS_BUNDLE_FILE_SET_INVALID")
    payloads: dict[str, bytes] = {}
    for raw_name, raw_facts in raw_entries.items():
        if not isinstance(raw_name, str) or not isinstance(raw_facts, dict):
            raise PreDnsOrchestrationError("PRE_DNS_BUNDLE_MANIFEST_INVALID")
        name = _safe_name(raw_name)
        payload = _read_regular_bounded(
            root / name,
            maximum_bytes=MAXIMUM_BUNDLE_ARTIFACT_BYTES,
        )
        if raw_facts != {"sha256": _sha256(payload), "byte_count": len(payload)}:
            raise PreDnsOrchestrationError("PRE_DNS_BUNDLE_ARTIFACT_HASH_MISMATCH")
        payloads[name] = payload
    try:
        workspace = RealCaptureWorkspaceReceiptV1.model_validate_json(
            payloads["workspace-receipt.json"]
        )
        mission = RealExecutionMissionManifestV1.model_validate_json(
            payloads["mission-manifest.json"]
        )
        source_plan = load_official_source_plan_bytes(payloads["source-plan.json"])
        selection = CampaignWindowSelectionV1.model_validate_json(
            payloads["campaign-selection.json"]
        )
        target_sets = tuple(
            FixtureTargetSetV1.model_validate_json(payloads[f"target-set-{sport_key}.json"])
            for sport_key in LIVE_ALLOWED_SPORT_KEYS
        )
        marker = _marker_from_json(
            strict_json_loads(payloads["provider-marker-inspection.json"]),
            workspace=workspace,
            mission=mission,
        )
        corpus = ScientificCorpusSnapshotV1.model_validate_json(
            payloads["scientific-corpus-snapshot.json"]
        )
        iteration_ledger = strict_json_object(payloads["iteration-ledger.json"])
        if (
            set(iteration_ledger) != {"schema_version", "iterations", "counters"}
            or iteration_ledger.get("schema_version") != PRE_DNS_ITERATION_LEDGER_SCHEMA
        ):
            raise ValueError
        for review_name in _REVIEW_NAMES:
            _validate_review_bytes(
                review_name,
                payloads[f"review-{review_name.casefold()}.json"],
            )
    except (KeyError, TypeError, ValueError, OfficialScheduleSourceError):
        raise PreDnsOrchestrationError("PRE_DNS_BUNDLE_CONTRACT_INVALID") from None
    if (
        root.parent != Path(workspace.control_temp_root).absolute()
        or not root.name.startswith("pre-dns-owner-pack-inputs-")
        or manifest["runtime_main_sha"] != workspace.authorized_main_sha
        or manifest["workspace_receipt_sha256"] != workspace.canonical_receipt_hash
        or manifest["mission_manifest_sha256"] != mission.canonical_manifest_sha256()
        or manifest["source_plan_sha256"] != source_plan.canonical_sha256
        or manifest["campaign_selection_sha256"] != selection.canonical_selection_hash
        or selection.source_target_sets != target_sets
        or corpus != selection.corpus_snapshot
        or corpus.source_evidence_sha256 != _sha256(payloads["scientific-corpus-evidence.json"])
    ):
        raise PreDnsOrchestrationError("PRE_DNS_BUNDLE_AUTHORITY_MISMATCH")
    selected = selection.selected_candidate()
    earliest_kickoff = min(
        target.official_kickoff_utc for target in selected.fixture_target_set.targets
    )
    refresh = selected.window_not_before_utc - timedelta(seconds=SAFETY_CUTOFF_SECONDS)
    expected_effects = {
        "provider_dns": 0,
        "provider_tcp": 0,
        "provider_http": 0,
        "secret_reads": 0,  # nosec B105 -- effect counter, not a credential
        "owner_review_pack_builds": 0,
        "owner_authorizations": 0,
        "activations": 0,
        "captures": 0,
        "promotions": 0,
        "bets": 0,
    }
    expected_status = (
        "PRE_DNS_READY_NOW"
        if selected.status == "OPEN_SELECTABLE"
        else "PRE_DNS_FUTURE_WINDOW_PLANNED"
    )
    if (
        manifest["status"] != expected_status
        or manifest["selected_candidate_id"] != selected.candidate_id
        or manifest["selected_candidate_sha256"] != selected.canonical_candidate_hash
        or manifest["selected_sport_key"] != selected.request.sport_key
        or manifest["selected_window_id"] != selected.window_id
        or manifest["selected_not_before_utc"] != _utc_text(selected.window_not_before_utc)
        or manifest["selected_usable_expires_at_utc"] != _utc_text(selected.usable_expires_at_utc)
        or manifest["selected_earliest_kickoff_utc"] != _utc_text(earliest_kickoff)
        or manifest["recommended_refresh_utc"] != _utc_text(refresh)
        or manifest["recommended_refresh_europe_paris"]
        != refresh.astimezone(ZoneInfo("Europe/Paris")).isoformat()
        or manifest["effects"] != expected_effects
    ):
        raise PreDnsOrchestrationError("PRE_DNS_BUNDLE_AUTHORITY_MISMATCH")
    raw_iterations = iteration_ledger.get("iterations")
    raw_counters = iteration_ledger.get("counters")
    counter_mapping = (
        cast(dict[str, object], raw_counters) if isinstance(raw_counters, dict) else {}
    )
    counter_limits = {
        "iterations": 4,
        "official_reads": 20,
        "supporting_official_reads": 4,
        "corpus_snapshots": 4,
        "corpus_validations": 4,
        "target_set_freezes": 20,
        "selector_invocations": 4,
    }
    counters_valid = (
        isinstance(raw_counters, dict)
        and set(counter_mapping) == set(counter_limits)
        and all(
            not isinstance(counter_mapping.get(name), bool)
            and isinstance(counter_mapping.get(name), int)
            and 0 <= cast(int, counter_mapping.get(name)) <= limit
            for name, limit in counter_limits.items()
        )
    )
    iteration_count = cast(int, counter_mapping.get("iterations")) if counters_valid else 0
    official_count = cast(int, counter_mapping.get("official_reads")) if counters_valid else 0
    supporting_count = (
        cast(int, counter_mapping.get("supporting_official_reads")) if counters_valid else 0
    )
    corpus_count = cast(int, counter_mapping.get("corpus_snapshots")) if counters_valid else 0
    corpus_validation_count = (
        cast(int, counter_mapping.get("corpus_validations")) if counters_valid else 0
    )
    freeze_count = cast(int, counter_mapping.get("target_set_freezes")) if counters_valid else 0
    selector_count = cast(int, counter_mapping.get("selector_invocations")) if counters_valid else 0
    rows_valid = isinstance(raw_iterations, list) and all(
        isinstance(item, dict) for item in raw_iterations
    )
    if rows_valid:
        rows = cast(list[dict[str, object]], raw_iterations)
        allowed_row_keys = {
            "iteration",
            "started_at_utc",
            "result",
            "code",
            "provider_dns",
            "official_reads_after",
            "selection_sha256",
            "usable_margin_seconds",
        }
        rows_valid = all(
            {"iteration", "started_at_utc", "result", "code", "provider_dns"} <= set(row)
            and set(row) <= allowed_row_keys
            and row.get("iteration") == index
            and isinstance(row.get("started_at_utc"), str)
            and isinstance(row.get("code"), str)
            and row.get("provider_dns") == 0
            and (
                row.get("result") == "ITERATION_INVALIDATED"
                if index < len(rows)
                else row.get("result") == expected_status
            )
            for index, row in enumerate(rows, start=1)
        )
        if rows_valid and rows:
            rows_valid = rows[-1].get("selection_sha256") == selection.canonical_selection_hash
    if (
        not isinstance(raw_iterations, list)
        or not raw_iterations
        or not isinstance(raw_iterations[-1], dict)
        or raw_iterations[-1].get("result") != expected_status
        or not counters_valid
        or not rows_valid
        or len(raw_iterations) != iteration_count
        or official_count + supporting_count > 20
        or official_count < 5
        or supporting_count < 1
        or corpus_validation_count > corpus_count
        or corpus_validation_count < 2
        or corpus_count < 2
        or freeze_count < 5
        or selector_count < 1
    ):
        raise PreDnsOrchestrationError("PRE_DNS_BUNDLE_ITERATION_LEDGER_INVALID")
    try:
        if (
            load_scientific_corpus_evidence_v1(
                payloads["scientific-corpus-evidence.json"],
                workspace_receipt=workspace,
                evaluated_at_utc=selection.selected_at_utc,
            )
            != corpus
        ):
            raise PreDnsOrchestrationError("PRE_DNS_BUNDLE_AUTHORITY_MISMATCH")
    except PreDnsOrchestrationError:
        raise PreDnsOrchestrationError("PRE_DNS_BUNDLE_AUTHORITY_MISMATCH") from None
    for sport_key, target_set in zip(LIVE_ALLOWED_SPORT_KEYS, target_sets, strict=True):
        try:
            receipt = strict_json_object(payloads[f"fetch-receipt-{sport_key}.json"])
            evidence = strict_json_object(payloads[f"evidence-{sport_key}.json"])
            parsed_receipt = _parse_fetch_receipt(payloads[f"fetch-receipt-{sport_key}.json"])
        except (TypeError, ValueError):
            raise PreDnsOrchestrationError("PRE_DNS_BUNDLE_CONTRACT_INVALID") from None
        raw_payload = payloads[f"raw-{sport_key}.bin"]
        source = source_plan.source(sport_key)
        supporting_raw_payloads = (
            (payloads["raw-supporting-soccer_spain_la_liga-01.bin"],)
            if source.adapter == LALIGA_PUBLIC_MATCHES_JSON_V1
            else ()
        )
        if len(parsed_receipt.supporting_official_reads) != len(supporting_raw_payloads) or any(
            item.byte_count != len(raw) or item.raw_sha256 != _sha256(raw)
            for item, raw in zip(
                parsed_receipt.supporting_official_reads,
                supporting_raw_payloads,
                strict=True,
            )
        ):
            raise PreDnsOrchestrationError("PRE_DNS_BUNDLE_AUTHORITY_MISMATCH")
        raw_fixtures = evidence.get("fixtures")
        normalized_raw_fixtures: list[dict[str, object]] = []
        if isinstance(raw_fixtures, list):
            for raw_fixture in raw_fixtures:
                if not isinstance(raw_fixture, dict):
                    break
                home = raw_fixture.get("official_home_team")
                away = raw_fixture.get("official_away_team")
                if not isinstance(home, str) or not isinstance(away, str):
                    break
                normalized_raw_fixtures.append(
                    {
                        "internal_fixture_target_id": raw_fixture.get("internal_fixture_target_id"),
                        "competition": raw_fixture.get("competition"),
                        "official_home_team": canonical_team_name_v1(home),
                        "official_away_team": canonical_team_name_v1(away),
                        "official_kickoff_utc": raw_fixture.get("official_kickoff_utc"),
                    }
                )
        target_fixture_material = [
            {
                "internal_fixture_target_id": target.internal_fixture_target_id,
                "competition": target.competition,
                "official_home_team": target.official_home_team,
                "official_away_team": target.official_away_team,
                "official_kickoff_utc": _utc_text(target.official_kickoff_utc),
            }
            for target in target_set.targets
        ]
        final_url = receipt.get("final_url")
        final_host = (
            (urlparse(final_url).hostname or "").rstrip(".").casefold()
            if isinstance(final_url, str)
            else ""
        )
        redirect_chain = receipt.get("redirect_chain")
        redirect_valid = isinstance(redirect_chain, list)
        expected_url = source.url
        if isinstance(redirect_chain, list):
            for raw_hop in redirect_chain:
                if not isinstance(raw_hop, dict):
                    redirect_valid = False
                    break
                location = raw_hop.get("location")
                location_host = (
                    (urlparse(location).hostname or "").rstrip(".").casefold()
                    if isinstance(location, str)
                    else ""
                )
                if (
                    raw_hop.get("requested_url") != expected_url
                    or raw_hop.get("status_code") not in {301, 302, 303, 307, 308}
                    or not any(
                        location_host == domain or location_host.endswith(f".{domain}")
                        for domain in source.allowed_domains
                    )
                ):
                    redirect_valid = False
                    break
                expected_url = cast(str, location)
        if (
            receipt.get("sport_key") != sport_key
            or receipt.get("adapter_revision") != source.adapter
            or receipt.get("requested_url") != source.url
            or receipt.get("accepted") is not True
            or receipt.get("rejection_code") is not None
            or receipt.get("http_status") != 200
            or receipt.get("raw_sha256") != _sha256(raw_payload)
            or receipt.get("byte_count") != len(raw_payload)
            or not isinstance(receipt.get("content_type"), str)
            or not any(
                final_host == domain or final_host.endswith(f".{domain}")
                for domain in source.allowed_domains
            )
            or not redirect_valid
            or final_url != expected_url
            or evidence.get("sport_key") != sport_key
            or evidence.get("adapter_revision") != source.adapter
            or not isinstance(evidence.get("parser_metadata"), dict)
            or evidence.get("target_set_id") != target_set.target_set_id
            or evidence.get("official_source_authority") != final_url
            or evidence.get("official_source_content_sha256") != _sha256(raw_payload)
            or evidence.get("source_observed_at_utc") != receipt.get("observed_at_utc")
            or evidence.get("selection_horizon_not_before_utc")
            != _utc_text(cast(datetime, target_set.official_schedule_horizon_not_before_utc))
            or evidence.get("selection_horizon_expires_at_utc")
            != _utc_text(cast(datetime, target_set.official_schedule_horizon_expires_at_utc))
            or evidence.get("official_schedule_completeness")
            != "OWNER_REVIEWED_COMPLETE_OFFICIAL_HORIZON"
            or evidence.get("official_schedule_fixture_count") != len(target_set.targets)
            or normalized_raw_fixtures != target_fixture_material
            or any(
                target.source_evidence_sha256 != _sha256(payloads[f"evidence-{sport_key}.json"])
                or _utc_text(target.source_observed_at_utc) != receipt.get("observed_at_utc")
                or target.official_source_authority != final_url
                for target in target_set.targets
            )
        ):
            raise PreDnsOrchestrationError("PRE_DNS_BUNDLE_AUTHORITY_MISMATCH")
        raw_evidence_verifier(
            source,
            raw_payload,
            payloads[f"fetch-receipt-{sport_key}.json"],
            payloads[f"evidence-{sport_key}.json"],
            target_set,
            supporting_raw_payloads,
        )
    try:
        reconciliation = strict_json_object(payloads["official-schedule-reconciliation.json"])
        observed_raw = reconciliation.get("observed_at_utc")
        if not isinstance(observed_raw, str):
            raise ValueError
        observed = _utc(
            datetime.fromisoformat(observed_raw.replace("Z", "+00:00")),
            code="OFFICIAL_RECONCILIATION_TIME_INVALID",
        )
        evidence_documents = {
            sport_key: strict_json_object(payloads[f"evidence-{sport_key}.json"])
            for sport_key in LIVE_ALLOWED_SPORT_KEYS
        }
        source_observed_values = []
        horizons = set()
        for evidence in evidence_documents.values():
            source_observed_raw = evidence.get("source_observed_at_utc")
            horizon_starts_raw = evidence.get("selection_horizon_not_before_utc")
            horizon_expires_raw = evidence.get("selection_horizon_expires_at_utc")
            if not all(
                isinstance(value, str)
                for value in (
                    source_observed_raw,
                    horizon_starts_raw,
                    horizon_expires_raw,
                )
            ):
                raise ValueError
            source_observed_values.append(
                _utc(
                    datetime.fromisoformat(cast(str, source_observed_raw).replace("Z", "+00:00")),
                    code="OFFICIAL_RECONCILIATION_SOURCE_INVALID",
                )
            )
            horizons.add((horizon_starts_raw, horizon_expires_raw))
        expected_reconciliation = {
            "schema_version": "robin-official-schedule-reconciliation-v1",
            "observed_at_utc": _utc_text(observed),
            "sport_keys": list(LIVE_ALLOWED_SPORT_KEYS),
            "fixture_counts": {
                sport_key: evidence_documents[sport_key].get("official_schedule_fixture_count")
                for sport_key in LIVE_ALLOWED_SPORT_KEYS
            },
            "source_sha256": {
                sport_key: evidence_documents[sport_key].get("official_source_content_sha256")
                for sport_key in LIVE_ALLOWED_SPORT_KEYS
            },
            "adapter_revisions": {
                sport_key: evidence_documents[sport_key].get("adapter_revision")
                for sport_key in LIVE_ALLOWED_SPORT_KEYS
            },
            "complete_official_horizon": True,
            "provider_dns": 0,
            "provider_tcp": 0,
            "provider_http": 0,
            "secret_reads": 0,  # nosec B105 -- effect counter, not a credential
        }
        if (
            len(horizons) != 1
            or any(
                source_observed > observed or observed - source_observed > MAXIMUM_SOURCE_AGE
                for source_observed in source_observed_values
            )
            or any(
                not isinstance(value, int) or isinstance(value, bool) or value <= 0
                for value in cast(
                    dict[str, object], expected_reconciliation["fixture_counts"]
                ).values()
            )
            or _json_bytes(expected_reconciliation)
            != payloads["official-schedule-reconciliation.json"]
        ):
            raise ValueError
    except (KeyError, TypeError, ValueError, PreDnsOrchestrationError):
        raise PreDnsOrchestrationError("OFFICIAL_RECONCILIATION_INVALID") from None
    return LoadedPreDnsBundleV1(
        directory=root,
        manifest=manifest,
        manifest_sha256=_sha256(manifest_bytes),
        workspace_receipt=workspace,
        mission_manifest=mission,
        source_plan=source_plan,
        campaign_selection=selection,
        target_sets=target_sets,
        marker_inspection=marker,
    )


def _prepare_owner_review_pack_inputs_v1(
    *,
    workspace_receipt: RealCaptureWorkspaceReceiptV1,
    workspace_receipt_bytes: bytes,
    mission_manifest: RealExecutionMissionManifestV1,
    mission_manifest_bytes: bytes,
    source_plan_bytes: bytes,
    corpus_evidence_reader: CorpusEvidenceReaderV1,
    output_parent: Path,
    reviews: Mapping[str, bytes],
    fetcher: OfficialScheduleFetcher,
    marker_inspector: MarkerInspectorV1,
    clock: ClockV1 = lambda: datetime.now(UTC),
    monotonic: MonotonicV1 = time.monotonic,
    workspace_validator: WorkspaceValidatorV1 = _validate_workspace_default,
    evidence_builder: EvidenceBuilderV1 = build_official_schedule_evidence,
    pdf_text_extractor: PdfTextExtractor | None = None,
    limits: PreDnsLimitsV1 = PreDnsLimitsV1(),
) -> PreDnsResultV1:
    """Converge only reversible evidence and publish one immutable PRE-DNS bundle."""

    try:
        if (
            RealCaptureWorkspaceReceiptV1.model_validate_json(workspace_receipt_bytes)
            != workspace_receipt
        ):
            raise PreDnsOrchestrationError("PRE_DNS_WORKSPACE_RECEIPT_MISMATCH")
        if (
            RealExecutionMissionManifestV1.model_validate_json(mission_manifest_bytes)
            != mission_manifest
        ):
            raise PreDnsOrchestrationError("PRE_DNS_MISSION_MANIFEST_MISMATCH")
        source_plan = load_official_source_plan_bytes(source_plan_bytes)
    except (TypeError, ValueError, OfficialScheduleSourceError):
        raise PreDnsOrchestrationError("PRE_DNS_INPUT_AUTHORITY_INVALID") from None
    if (
        set(reviews) != set(_REVIEW_NAMES)
        or any(not reviews[name] for name in _REVIEW_NAMES)
        or not workspace_receipt.authority_eligible_for_real_execution
        or workspace_receipt.provider_http_requests != 0
        or workspace_receipt.provider_tcp_connections != 0
        or workspace_receipt.provider_secret_reads != 0
    ):
        raise PreDnsOrchestrationError("PRE_DNS_INPUT_AUTHORITY_INVALID")
    for review_name in _REVIEW_NAMES:
        _validate_review_bytes(review_name, reviews[review_name])
    try:
        control_parent = _assert_plain_directory(Path(workspace_receipt.control_temp_root))
        requested_parent = _assert_plain_directory(output_parent)
    except PreDnsOrchestrationError:
        raise PreDnsOrchestrationError("PRE_DNS_OUTPUT_PARENT_INVALID") from None
    if requested_parent != control_parent:
        raise PreDnsOrchestrationError("PRE_DNS_OUTPUT_OUTSIDE_CONTROL_TEMP")

    iterations = 0
    official_reads = 0
    supporting_reads = 0
    corpus_snapshots = 0
    corpus_validations = 0
    freezes = 0
    selector_invocations = 0
    iteration_ledger: list[Mapping[str, object]] = []
    iteration_codes: list[str] = []

    def counters() -> PreDnsCountersV1:
        return PreDnsCountersV1(
            iterations=iterations,
            official_reads=official_reads,
            supporting_official_reads=supporting_reads,
            corpus_snapshots=corpus_snapshots,
            corpus_validations=corpus_validations,
            target_set_freezes=freezes,
            selector_invocations=selector_invocations,
        )

    for iteration in range(1, limits.maximum_iterations + 1):
        iterations += 1
        iteration_started = _utc(clock(), code="PRE_DNS_CLOCK_INVALID")
        if iteration_started >= mission_manifest.expires_at:
            raise PreDnsOrchestrationError("BOOTSTRAP_MISSION_EXPIRED")
        try:
            workspace_validator(workspace_receipt)
        except Exception:
            raise PreDnsOrchestrationError("PRE_DNS_WORKSPACE_DRIFT") from None
        marker = marker_inspector(workspace_receipt, mission_manifest)
        if not marker.historical_marker_unchanged:
            raise PreDnsOrchestrationError("HISTORICAL_MARKER_CHANGED")
        if marker.current_marker_present:
            raise PreDnsOrchestrationError("CURRENT_V2_MARKER_PRESENT")
        next_iteration_reads = len(LIVE_ALLOWED_SPORT_KEYS) + sum(
            source.adapter == LALIGA_PUBLIC_MATCHES_JSON_V1 for source in source_plan.sources
        )
        if official_reads + supporting_reads + next_iteration_reads > limits.maximum_official_reads:
            iteration_codes.append("MAXIMUM_OFFICIAL_READS_EXHAUSTED")
            break
        raw_results: dict[str, OfficialFetchResult] = {}
        evidences: list[OfficialScheduleEvidence] = []
        reconciliation: Mapping[str, object] | None = None
        horizon_expires = iteration_started + timedelta(days=OFFICIAL_SCHEDULE_HORIZON_DAYS)
        if horizon_expires <= iteration_started + timedelta(minutes=15):
            iteration_codes.append("PRE_DNS_HORIZON_TOO_SHORT")
            break
        try:
            for source in source_plan.sources:
                anticipated_supporting_reads = int(source.adapter == LALIGA_PUBLIC_MATCHES_JSON_V1)
                anticipated_reads = 1 + anticipated_supporting_reads
                if (
                    official_reads + supporting_reads + anticipated_reads
                    > limits.maximum_official_reads
                ):
                    raise PreDnsOrchestrationError("MAXIMUM_OFFICIAL_READS_EXHAUSTED")
                official_reads += 1
                supporting_reads += anticipated_supporting_reads
                result = fetch_official_schedule_source(
                    source,
                    fetcher=fetcher,
                    observed_at_utc=None,
                    clock=clock,
                )
                if (
                    len(result.receipt.supporting_official_reads) != anticipated_supporting_reads
                    or len(result.supporting_official_raw_bytes) != anticipated_supporting_reads
                ):
                    raise PreDnsOrchestrationError("OFFICIAL_SUPPORTING_READ_BUDGET_INVALID")
                raw_results[source.sport_key] = result
                evidences.append(
                    evidence_builder(
                        source,
                        result,
                        horizon_not_before_utc=iteration_started,
                        horizon_expires_at_utc=horizon_expires,
                        pdf_text_extractor=pdf_text_extractor,
                    )
                )
            reconciliation_at = _utc(clock(), code="PRE_DNS_CLOCK_INVALID")
            reconciliation = reconcile_official_schedule_evidence(
                evidences,
                observed_at_utc=reconciliation_at,
            )
        except (
            OfficialScheduleSourceError,
            PreDnsOrchestrationError,
            TypeError,
            ValueError,
        ) as error:
            code = getattr(error, "code", "OFFICIAL_SOURCE_ITERATION_REJECTED")
            iteration_codes.append(code)
            iteration_ledger.append(
                {
                    "iteration": iteration,
                    "started_at_utc": _utc_text(iteration_started),
                    "result": "ITERATION_INVALIDATED",
                    "code": code,
                    "official_reads_after": official_reads,
                    "provider_dns": 0,
                }
            )
            continue
        if corpus_snapshots + 2 > limits.maximum_corpus_snapshots:
            iteration_codes.append("MAXIMUM_CORPUS_SNAPSHOTS_EXHAUSTED")
            break
        corpus_snapshots += 2
        corpus_at = _utc(clock(), code="PRE_DNS_CLOCK_INVALID")
        try:
            corpus_payload_a = corpus_evidence_reader()
            corpus_a = load_scientific_corpus_evidence_v1(
                corpus_payload_a,
                workspace_receipt=workspace_receipt,
                evaluated_at_utc=corpus_at,
            )
            corpus_validations += 1
            corpus_payload_b = corpus_evidence_reader()
            corpus_b = load_scientific_corpus_evidence_v1(
                corpus_payload_b,
                workspace_receipt=workspace_receipt,
                evaluated_at_utc=corpus_at,
            )
            corpus_validations += 1
            if corpus_payload_a != corpus_payload_b or corpus_a != corpus_b:
                raise PreDnsOrchestrationError("CAMPAIGN_CORPUS_NONDETERMINISTIC")
        except (PreDnsOrchestrationError, TypeError, ValueError) as error:
            code = getattr(error, "code", "CAMPAIGN_CORPUS_ITERATION_REJECTED")
            iteration_codes.append(code)
            iteration_ledger.append(
                {
                    "iteration": iteration,
                    "started_at_utc": _utc_text(iteration_started),
                    "result": "ITERATION_INVALIDATED",
                    "code": code,
                    "provider_dns": 0,
                }
            )
            continue
        cutoff_at = _utc(clock(), code="PRE_DNS_CLOCK_INVALID") + timedelta(
            seconds=SAFETY_CUTOFF_SECONDS
        )
        if any(
            fixture.kickoff_utc < cutoff_at
            for evidence in evidences
            for fixture in evidence.fixtures
        ):
            code = "ANTI_ROLLOVER_SAFETY_CUTOFF"
            iteration_codes.append(code)
            iteration_ledger.append(
                {
                    "iteration": iteration,
                    "started_at_utc": _utc_text(iteration_started),
                    "result": "ITERATION_INVALIDATED",
                    "code": code,
                    "provider_dns": 0,
                }
            )
            continue
        if freezes + len(LIVE_ALLOWED_SPORT_KEYS) > limits.maximum_target_set_freezes:
            iteration_codes.append("MAXIMUM_TARGET_SET_FREEZES_EXHAUSTED")
            break
        try:
            frozen_at = _utc(clock(), code="PRE_DNS_CLOCK_INVALID")
            frozen_sets: list[FixtureTargetSetV1] = []
            for evidence in evidences:
                freezes += 1
                frozen_sets.append(
                    freeze_official_schedule_evidence_v1(
                        evidence,
                        workspace_receipt=workspace_receipt,
                        created_at_utc=frozen_at,
                    )
                )
            target_sets = tuple(frozen_sets)
        except (TypeError, ValueError, PreDnsOrchestrationError) as error:
            code = getattr(error, "code", "OFFICIAL_TARGET_FREEZE_REJECTED")
            iteration_codes.append(code)
            iteration_ledger.append(
                {
                    "iteration": iteration,
                    "started_at_utc": _utc_text(iteration_started),
                    "result": "ITERATION_INVALIDATED",
                    "code": code,
                    "provider_dns": 0,
                }
            )
            continue
        freeze_completed_monotonic = monotonic()
        selector_started_monotonic = monotonic()
        selected_at = _utc(clock(), code="PRE_DNS_CLOCK_INVALID")
        if (
            selector_started_monotonic - freeze_completed_monotonic
            > MAXIMUM_FREEZE_TO_SELECTOR_SECONDS
            or any(
                target.official_kickoff_utc < selected_at + timedelta(seconds=SAFETY_CUTOFF_SECONDS)
                for target_set in target_sets
                for target in target_set.targets
            )
        ):
            code = "ITERATION_INVALIDATED"
            iteration_codes.append(code)
            iteration_ledger.append(
                {
                    "iteration": iteration,
                    "started_at_utc": _utc_text(iteration_started),
                    "result": "ITERATION_INVALIDATED",
                    "code": code,
                    "provider_dns": 0,
                }
            )
            continue
        if selector_invocations + 1 > limits.maximum_selector_invocations:
            iteration_codes.append("MAXIMUM_SELECTOR_INVOCATIONS_EXHAUSTED")
            break
        selector_invocations += 1
        try:
            selection = CampaignWindowSelectionV1.issue(
                selected_at_utc=selected_at,
                workspace_receipt_sha256=workspace_receipt.canonical_receipt_hash,
                workspace_prepared_at_utc=workspace_receipt.prepared_at_utc,
                mission_manifest_sha256=mission_manifest.canonical_manifest_sha256(),
                mission_expires_at_utc=mission_manifest.expires_at,
                source_target_sets=target_sets,
                corpus_snapshot=corpus_a,
            )
        except (TypeError, ValueError) as error:
            code = "CAMPAIGN_SELECTION_ITERATION_REJECTED"
            iteration_codes.append(code)
            iteration_ledger.append(
                {
                    "iteration": iteration,
                    "started_at_utc": _utc_text(iteration_started),
                    "result": "ITERATION_INVALIDATED",
                    "code": f"{code}:{error}",
                    "provider_dns": 0,
                }
            )
            continue
        selected = selection.selected_candidate()
        earliest_kickoff = min(
            target.official_kickoff_utc for target in selected.fixture_target_set.targets
        )
        usable_ceiling = min(
            mission_manifest.expires_at,
            selected.usable_expires_at_utc,
            earliest_kickoff - timedelta(seconds=SAFETY_CUTOFF_SECONDS),
        )
        ready_margin = int((usable_ceiling - selected_at).total_seconds())
        if selected.status == "OPEN_SELECTABLE" and ready_margin < MINIMUM_READY_MARGIN_SECONDS:
            code = "PRE_DNS_OPEN_MARGIN_INSUFFICIENT"
            iteration_codes.append(code)
            iteration_ledger.append(
                {
                    "iteration": iteration,
                    "started_at_utc": _utc_text(iteration_started),
                    "result": "ITERATION_INVALIDATED",
                    "code": code,
                    "usable_margin_seconds": ready_margin,
                    "provider_dns": 0,
                }
            )
            continue
        status: Literal["PRE_DNS_READY_NOW", "PRE_DNS_FUTURE_WINDOW_PLANNED"] = (
            "PRE_DNS_READY_NOW"
            if selected.status == "OPEN_SELECTABLE"
            else "PRE_DNS_FUTURE_WINDOW_PLANNED"
        )
        if selected.status not in {"OPEN_SELECTABLE", "FUTURE_NOT_OPEN"}:
            code = "CAMPAIGN_SELECTION_NOT_ELIGIBLE"
            iteration_codes.append(code)
            iteration_ledger.append(
                {
                    "iteration": iteration,
                    "started_at_utc": _utc_text(iteration_started),
                    "result": "ITERATION_INVALIDATED",
                    "code": code,
                    "provider_dns": 0,
                }
            )
            continue
        if selector_invocations + 1 > limits.maximum_selector_invocations:
            iteration_codes.append("MAXIMUM_SELECTOR_INVOCATIONS_EXHAUSTED")
            break
        published_at = _utc(clock(), code="PRE_DNS_CLOCK_INVALID")
        selector_invocations += 1
        try:
            if published_at < selected_at:
                raise ValueError("PRE_DNS_PUBLICATION_CLOCK_REGRESSED")
            publication_selection = CampaignWindowSelectionV1.issue(
                selected_at_utc=published_at,
                workspace_receipt_sha256=workspace_receipt.canonical_receipt_hash,
                workspace_prepared_at_utc=workspace_receipt.prepared_at_utc,
                mission_manifest_sha256=mission_manifest.canonical_manifest_sha256(),
                mission_expires_at_utc=mission_manifest.expires_at,
                source_target_sets=target_sets,
                corpus_snapshot=corpus_a,
            )
            publication_selected = publication_selection.selected_candidate()
            publication_status: Literal["PRE_DNS_READY_NOW", "PRE_DNS_FUTURE_WINDOW_PLANNED"] = (
                "PRE_DNS_READY_NOW"
                if publication_selected.status == "OPEN_SELECTABLE"
                else "PRE_DNS_FUTURE_WINDOW_PLANNED"
            )
            if (
                publication_selected.status not in {"OPEN_SELECTABLE", "FUTURE_NOT_OPEN"}
                or publication_selected.stable_group_hash != selected.stable_group_hash
                or publication_status != status
            ):
                raise ValueError("PRE_DNS_PUBLICATION_SELECTION_CHANGED")
            publication_earliest_kickoff = min(
                target.official_kickoff_utc
                for target in publication_selected.fixture_target_set.targets
            )
            publication_usable_ceiling = min(
                mission_manifest.expires_at,
                publication_selected.usable_expires_at_utc,
                publication_earliest_kickoff - timedelta(seconds=SAFETY_CUTOFF_SECONDS),
            )
            ready_margin = int((publication_usable_ceiling - published_at).total_seconds())
            refresh = publication_selected.window_not_before_utc - timedelta(
                seconds=SAFETY_CUTOFF_SECONDS
            )
            if publication_status == "PRE_DNS_READY_NOW":
                publication_selection.assert_selected_candidate_current(published_at)
                if ready_margin < MINIMUM_READY_MARGIN_SECONDS:
                    raise ValueError("PRE_DNS_OPEN_MARGIN_INSUFFICIENT")
            elif published_at >= refresh:
                raise ValueError("PRE_DNS_FUTURE_REFRESH_DUE")
        except (TypeError, ValueError) as error:
            code = str(error) or "PRE_DNS_PUBLICATION_REVALIDATION_FAILED"
            iteration_codes.append(code)
            iteration_ledger.append(
                {
                    "iteration": iteration,
                    "started_at_utc": _utc_text(iteration_started),
                    "result": "ITERATION_INVALIDATED",
                    "code": code,
                    "provider_dns": 0,
                }
            )
            continue
        selection = publication_selection
        selected = publication_selected
        status = publication_status
        iteration_ledger.append(
            {
                "iteration": iteration,
                "started_at_utc": _utc_text(iteration_started),
                "result": status,
                "code": status,
                "selection_sha256": selection.canonical_selection_hash,
                "usable_margin_seconds": ready_margin,
                "provider_dns": 0,
            }
        )
        if reconciliation is None:
            raise PreDnsOrchestrationError("OFFICIAL_RECONCILIATION_MISSING")
        bundle_directory, bundle_hash = _publish_pre_dns_bundle_v1(
            output_parent=output_parent,
            status=status,
            published_at_utc=published_at,
            workspace_receipt_bytes=workspace_receipt_bytes,
            mission_manifest_bytes=mission_manifest_bytes,
            source_plan_bytes=source_plan_bytes,
            source_plan=source_plan,
            raw_results=raw_results,
            evidences=tuple(evidences),
            reconciliation=reconciliation,
            target_sets=target_sets,
            corpus_evidence_bytes=corpus_payload_a,
            corpus_snapshot=corpus_a,
            selection=selection,
            iteration_ledger=tuple(iteration_ledger),
            reviews=reviews,
            marker_inspection=marker,
            counters=counters(),
        )
        return PreDnsResultV1(
            status=status,
            selection=selection,
            bundle_directory=bundle_directory,
            bundle_manifest_sha256=bundle_hash,
            recommended_refresh_utc=refresh,
            recommended_refresh_europe_paris=refresh.astimezone(
                ZoneInfo("Europe/Paris")
            ).isoformat(),
            counters=counters(),
            iteration_codes=tuple(iteration_codes),
        )
    return PreDnsResultV1(
        status="PRE_DNS_CONVERGENCE_EXHAUSTED",
        selection=None,
        bundle_directory=None,
        bundle_manifest_sha256=None,
        recommended_refresh_utc=None,
        recommended_refresh_europe_paris=None,
        counters=counters(),
        iteration_codes=tuple(iteration_codes),
    )


def prepare_owner_review_pack_inputs_v1(
    *,
    workspace_receipt: RealCaptureWorkspaceReceiptV1,
    workspace_receipt_bytes: bytes,
    mission_manifest: RealExecutionMissionManifestV1,
    mission_manifest_bytes: bytes,
    source_plan_bytes: bytes,
    corpus_evidence_reader: CorpusEvidenceReaderV1,
    output_parent: Path,
    reviews: Mapping[str, bytes],
    fetcher: OfficialScheduleFetcher,
    marker_inspector: MarkerInspectorV1,
    clock: ClockV1 = lambda: datetime.now(UTC),
    monotonic: MonotonicV1 = time.monotonic,
    workspace_validator: WorkspaceValidatorV1 = _validate_workspace_default,
    evidence_builder: EvidenceBuilderV1 = build_official_schedule_evidence,
    pdf_text_extractor: PdfTextExtractor | None = None,
    limits: PreDnsLimitsV1 = PreDnsLimitsV1(),
) -> PreDnsResultV1:
    """Run the historical five-league convergence outside current First-C0 V5."""

    raise PreDnsOrchestrationError("FIRST_C0_SINGLE_OWNER_ENTRYPOINT_REQUIRED")


def _owner_pack_artifacts(pack: OwnerReviewPackV1) -> dict[str, tuple[BaseModel, str]]:
    return {
        "owner_review_pack": (pack, pack.canonical_pack_hash),
        "owner_authorization_candidate": (
            pack.owner_authorization_candidate,
            pack.owner_authorization_candidate.canonical_authorization_hash,
        ),
        "activation_candidate": (
            pack.activation_candidate,
            pack.activation_candidate.canonical_activation_hash,
        ),
        "plan_candidate": (pack.plan_candidate, pack.plan_candidate.canonical_plan_hash),
        "plan_item_candidate": (
            pack.plan_item_candidate,
            pack.plan_item_candidate.canonical_item_hash,
        ),
        "campaign_selection": (
            pack.campaign_selection,
            pack.campaign_selection.canonical_selection_hash,
        ),
        "fixture_target_set": (
            pack.fixture_target_set,
            pack.fixture_target_set.canonical_set_hash,
        ),
        "provider_network_binding": (
            pack.provider_network_binding,
            pack.provider_network_binding.canonical_binding_hash,
        ),
        "mission_manifest": (pack.mission_manifest, pack.mission_manifest_sha256),
        "workspace_receipt": (
            pack.workspace_receipt,
            pack.workspace_receipt.canonical_receipt_hash,
        ),
        "request": (pack.request, pack.request_fingerprint_sha256),
    }


def verify_owner_review_pack_artifacts_v1(
    directory: Path,
    pack: OwnerReviewPackV1,
    paths: Mapping[str, Path],
) -> None:
    root = _assert_plain_directory(directory)
    artifacts = _owner_pack_artifacts(pack)
    expected_names = {
        f"{label.replace('_', '-')}-{digest}.json" for label, (_, digest) in artifacts.items()
    }
    if set(paths) != set(artifacts) or {entry.name for entry in root.iterdir()} != expected_names:
        raise PreDnsOrchestrationError("OWNER_REVIEW_PACK_ARTIFACT_SET_INVALID")
    for label, (artifact, digest) in artifacts.items():
        expected = root / f"{label.replace('_', '-')}-{digest}.json"
        if paths[label].absolute() != expected:
            raise PreDnsOrchestrationError("OWNER_REVIEW_PACK_ARTIFACT_PATH_INVALID")
        payload = _read_regular_bounded(expected, maximum_bytes=MAXIMUM_BUNDLE_ARTIFACT_BYTES)
        if payload != _model_bytes(artifact):
            raise PreDnsOrchestrationError("OWNER_REVIEW_PACK_ARTIFACT_CANONICAL_MISMATCH")
    generated_text = _utc_text(pack.generated_at_utc)
    nonce_hash = canonical_sha256(
        {
            "workspace": pack.workspace_receipt.canonical_receipt_hash,
            "binding": pack.provider_network_binding.canonical_binding_hash,
            "targets": pack.fixture_target_set.canonical_set_hash,
            "campaign_selection": pack.campaign_selection.canonical_selection_hash,
            "request": canonical_sha256(pack.request.fingerprint_material()),
            "generated_at": generated_text,
        }
    )
    if (
        pack.owner_authorization_candidate.authorization_nonce != f"owner-{nonce_hash[:40]}"
        or pack.activation_candidate.activation_nonce != f"activation-{nonce_hash[24:64]}"
        or pack.expected_owner_authorization_sha256
        != pack.owner_authorization_candidate.expected_promoted_authorization_hash()
    ):
        raise PreDnsOrchestrationError("OWNER_REVIEW_PACK_NONCE_RECOMPUTATION_FAILED")


def preflight_owner_review_pack_once_v1(
    *,
    bundle_directory: Path,
    workspace_receipt: RealCaptureWorkspaceReceiptV1,
    mission_manifest: RealExecutionMissionManifestV1,
    output_binding_path: Path,
    output_pack_directory: Path,
    marker_inspector: MarkerInspectorV1,
    owner_present_for_review: bool,
    execute: bool,
    binding_ttl_seconds: int = 900,
    prefetch_handoff_path: Path | None = None,
    window_open_receipt_path: Path | None = None,
    clock: ClockV1 = lambda: datetime.now(UTC),
    monotonic: MonotonicV1 = time.monotonic,
    workspace_validator: WorkspaceValidatorV1 = _validate_workspace_default,
    raw_evidence_verifier: RawEvidenceVerifierV1 = verify_raw_official_evidence_v1,
) -> tuple[RunnerPreflightV1, LoadedPreDnsBundleV1 | None]:
    checked = _utc(clock(), code="ATOMIC_RUNNER_CLOCK_INVALID")
    errors: list[str] = []
    loaded: LoadedPreDnsBundleV1 | None = None
    observed_marker: MarkerInspectionV1 | None = None
    prefetched_receipt: FirstC0WindowOpenRevalidationV1 | None = None
    try:
        loaded = load_pre_dns_bundle_v1(
            bundle_directory,
            raw_evidence_verifier=raw_evidence_verifier,
        )
    except PreDnsOrchestrationError as error:
        errors.append(error.code)
    if checked >= mission_manifest.expires_at:
        errors.append("BOOTSTRAP_MISSION_EXPIRED")
    try:
        workspace_validator(workspace_receipt)
    except Exception:
        errors.append("WORKSPACE_DRIFT")
    try:
        observed_marker = marker_inspector(workspace_receipt, mission_manifest)
        if not observed_marker.historical_marker_unchanged:
            errors.append("HISTORICAL_MARKER_CHANGED")
        if observed_marker.current_marker_present:
            errors.append("CURRENT_V2_MARKER_PRESENT")
    except Exception:
        errors.append("PROVIDER_MARKER_INSPECTION_FAILED")
    if loaded is not None:
        prefetched = (
            loaded.manifest.get("schema_version") == FIRST_C0_PREFETCHED_WINDOW_BUNDLE_SCHEMA
        )
        if prefetched:
            if prefetch_handoff_path is None or window_open_receipt_path is None:
                errors.append("FIRST_C0_WINDOW_RECEIPT_REQUIRED")
            else:
                try:
                    prefetch_handoff = load_first_c0_prefetch_handoff_v1(
                        prefetch_handoff_path,
                        loaded,
                    )
                    prefetched_receipt = load_first_c0_window_open_revalidation_v1(
                        window_open_receipt_path,
                        loaded,
                        prefetch_handoff,
                        handoff_path=prefetch_handoff_path,
                    )
                    loaded = replace(
                        loaded,
                        prefetch_handoff=prefetch_handoff,
                        prefetch_handoff_path=prefetch_handoff_path,
                        window_open_receipt=prefetched_receipt,
                        window_open_receipt_path=window_open_receipt_path,
                    )
                except PreDnsOrchestrationError as error:
                    errors.append(error.code)
        if observed_marker is None or not _first_c0_canary_marker_authority_matches_v1(
            observed_marker,
            loaded.marker_inspection,
        ):
            errors.append("PROVIDER_MARKER_AUTHORITY_MISMATCH")
        if loaded.workspace_receipt != workspace_receipt:
            errors.append("WORKSPACE_RECEIPT_BUNDLE_MISMATCH")
        if loaded.mission_manifest != mission_manifest:
            errors.append("MISSION_MANIFEST_BUNDLE_MISMATCH")
        selection = loaded.campaign_selection
        if (
            isinstance(selection, FirstC0CanarySelectionV1)
            and selection.selected_ready_at_selection is False
            and not prefetched
        ):
            errors.append("FIRST_C0_WINDOW_RECEIPT_REQUIRED")
        selected = selection.selected_candidate()
        if (
            isinstance(selection, FirstC0CanarySelectionV1)
            and selected.window_id == "H2"
            and not prefetched
        ):
            errors.append("FIRST_C0_WINDOW_RECEIPT_REQUIRED")
            errors.append("FIRST_C0_H2_PREFETCH_REQUIRED_BEFORE_WINDOW_OPEN")
        try:
            selection.assert_selected_candidate_current(checked)
        except ValueError as error:
            code = str(error)
            errors.append(
                "FUTURE_WINDOW_NOT_OPEN" if "NOT_OPEN" in code else "CAMPAIGN_SELECTION_NOT_CURRENT"
            )
        usable_margin = int((selected.usable_expires_at_utc - checked).total_seconds())
        if usable_margin < MINIMUM_READY_MARGIN_SECONDS:
            errors.append("OWNER_REVIEW_USABLE_MARGIN_INSUFFICIENT")
    else:
        usable_margin = 0
    if os.path.lexists(output_binding_path):
        errors.append("PROVIDER_NETWORK_BINDING_OUTPUT_EXISTS")
    if os.path.lexists(output_pack_directory):
        errors.append("OWNER_REVIEW_PACK_OUTPUT_EXISTS")
    try:
        binding_parent = _assert_plain_directory(output_binding_path.absolute().parent)
        pack_parent = _assert_plain_directory(output_pack_directory.absolute().parent)
        control_parent = _assert_plain_directory(Path(workspace_receipt.control_temp_root))
        _safe_name(output_binding_path.name)
        _safe_name(output_pack_directory.name)
        if binding_parent != pack_parent or pack_parent != control_parent:
            errors.append("ATOMIC_RUNNER_OUTPUT_PARENT_MISMATCH")
        success_receipt = _runner_receipt_path(output_pack_directory, hard_stop=False)
        hard_stop_receipt = _runner_receipt_path(output_pack_directory, hard_stop=True)
        resolution_marker = Path(workspace_receipt.control_temp_root) / _CONTROL_MARKER_NAME
        output_identities = {
            os.path.normcase(os.path.abspath(path))
            for path in (
                output_binding_path,
                output_pack_directory,
                hard_stop_receipt,
                resolution_marker,
            )
        }
        staging_prefix = f".{output_pack_directory.name}.staging-".casefold()
        if len(output_identities) != 4 or output_binding_path.name.casefold().startswith(
            staging_prefix
        ):
            errors.append("ATOMIC_RUNNER_OUTPUT_ALIAS")
        if os.path.lexists(success_receipt) or os.path.lexists(hard_stop_receipt):
            errors.append("ATOMIC_RUNNER_RECEIPT_OUTPUT_EXISTS")
        staging_prefixes = (
            staging_prefix,
            f".{output_pack_directory.name}.execution-receipt.staging-".casefold(),
        )
        if any(
            entry.name.casefold().startswith(staging_prefixes) for entry in pack_parent.iterdir()
        ):
            errors.append("OWNER_REVIEW_PACK_STAGING_EXISTS")
    except PreDnsOrchestrationError:
        errors.append("ATOMIC_RUNNER_OUTPUT_BOUNDARY_INVALID")
    if type(execute) is not bool or type(owner_present_for_review) is not bool:
        errors.append("OWNER_EXECUTION_GATE_INVALID")
    if execute is True and owner_present_for_review is not True:
        errors.append("OWNER_PRESENCE_REQUIRED")
    if (
        type(binding_ttl_seconds) is not int
        or not MINIMUM_READY_MARGIN_SECONDS <= binding_ttl_seconds <= 900
    ):
        errors.append("PROVIDER_NETWORK_BINDING_TTL_INSUFFICIENT")
    if prefetched_receipt is not None and loaded is not None:
        checked = _utc(clock(), code="ATOMIC_RUNNER_CLOCK_INVALID")
        checked_monotonic = float(monotonic())
        wall_since_activation = (checked - prefetched_receipt.checked_at_utc).total_seconds()
        monotonic_since_activation = checked_monotonic - prefetched_receipt.checked_monotonic
        if (
            not math.isfinite(checked_monotonic)
            or not math.isfinite(monotonic_since_activation)
            or wall_since_activation < 0
            or monotonic_since_activation < 0
            or abs(wall_since_activation - monotonic_since_activation) > 2.0
        ):
            errors.append("FIRST_C0_PREFLIGHT_CLOCK_INVALID")
        if (
            checked - prefetched_receipt.window_not_before_utc
            > timedelta(seconds=FIRST_C0_MAXIMUM_OPEN_TO_PREFLIGHT_SECONDS)
            or checked_monotonic - prefetched_receipt.window_open_monotonic
            > FIRST_C0_MAXIMUM_OPEN_TO_PREFLIGHT_SECONDS
        ):
            errors.append("FIRST_C0_OPEN_TO_PREFLIGHT_BUDGET_EXCEEDED")
        try:
            loaded.campaign_selection.assert_selected_candidate_current(checked)
        except ValueError:
            errors.append("CAMPAIGN_SELECTION_NOT_CURRENT")
        usable_margin = int(
            (
                loaded.campaign_selection.selected_candidate().usable_expires_at_utc - checked
            ).total_seconds()
        )
        if usable_margin < MINIMUM_READY_MARGIN_SECONDS:
            errors.append("OWNER_REVIEW_USABLE_MARGIN_INSUFFICIENT")
    if loaded is not None:
        selected = loaded.campaign_selection.selected_candidate()
        if (
            isinstance(loaded.campaign_selection, FirstC0CanarySelectionV1)
            and selected.window_id == "H2"
            and prefetched_receipt is None
        ):
            checked = _utc(clock(), code="ATOMIC_RUNNER_CLOCK_INVALID")
            try:
                loaded.campaign_selection.assert_selected_candidate_current(checked)
            except ValueError as error:
                code = str(error)
                errors.append(
                    "FUTURE_WINDOW_NOT_OPEN"
                    if "NOT_OPEN" in code
                    else "CAMPAIGN_SELECTION_NOT_CURRENT"
                )
            usable_margin = int((selected.usable_expires_at_utc - checked).total_seconds())
            if usable_margin < MINIMUM_READY_MARGIN_SECONDS:
                errors.append("OWNER_REVIEW_USABLE_MARGIN_INSUFFICIENT")
        if (
            isinstance(loaded.campaign_selection, FirstC0CanarySelectionV1)
            and selected.window_id == "H2"
            and checked - selected.window_not_before_utc
            > timedelta(seconds=FIRST_C0_MAXIMUM_OPEN_TO_PREFLIGHT_SECONDS)
        ):
            errors.append("FIRST_C0_OPEN_TO_PREFLIGHT_BUDGET_EXCEEDED")
    future = "FUTURE_WINDOW_NOT_OPEN" in errors
    accepted = not errors
    status: RunnerStatusV1 = (
        "PREFLIGHT_ACCEPT"
        if accepted
        else "FUTURE_WINDOW_NOT_OPEN"
        if future
        else "PREFLIGHT_REJECTED"
    )
    return (
        RunnerPreflightV1(
            accepted=accepted,
            status=status,
            errors=tuple(dict.fromkeys(errors)),
            checked_at_utc=checked,
            usable_margin_seconds=usable_margin,
        ),
        loaded,
    )


def _runner_receipt_path(output_pack_directory: Path, *, hard_stop: bool) -> Path:
    if not hard_stop:
        return output_pack_directory / "execution-receipt.json"
    return output_pack_directory.parent / f"{output_pack_directory.name}-hard-stop-receipt.json"


def _final_execute_preflight_v1(
    *,
    loaded: LoadedPreDnsBundleV1,
    workspace_receipt: RealCaptureWorkspaceReceiptV1,
    mission_manifest: RealExecutionMissionManifestV1,
    output_binding_path: Path,
    output_pack_directory: Path,
    marker_inspector: MarkerInspectorV1,
    binding_ttl_seconds: int,
    clock: ClockV1,
    monotonic: MonotonicV1,
    workspace_validator: WorkspaceValidatorV1,
) -> RunnerPreflightV1:
    """Resample every mutable pre-DNS gate immediately before resolver execution."""

    errors: list[str] = []
    observed_marker: MarkerInspectionV1 | None = None
    try:
        workspace_validator(workspace_receipt)
    except Exception:
        errors.append("WORKSPACE_DRIFT")
    try:
        observed_marker = marker_inspector(workspace_receipt, mission_manifest)
        if not observed_marker.historical_marker_unchanged:
            errors.append("HISTORICAL_MARKER_CHANGED")
        if observed_marker.current_marker_present:
            errors.append("CURRENT_V2_MARKER_PRESENT")
    except Exception:
        errors.append("PROVIDER_MARKER_INSPECTION_FAILED")
    if observed_marker is None or not _first_c0_canary_marker_authority_matches_v1(
        observed_marker,
        loaded.marker_inspection,
    ):
        errors.append("PROVIDER_MARKER_AUTHORITY_MISMATCH")
    if os.path.lexists(output_binding_path):
        errors.append("PROVIDER_NETWORK_BINDING_OUTPUT_EXISTS")
    if os.path.lexists(output_pack_directory):
        errors.append("OWNER_REVIEW_PACK_OUTPUT_EXISTS")
    try:
        binding_parent = _assert_plain_directory(output_binding_path.absolute().parent)
        pack_parent = _assert_plain_directory(output_pack_directory.absolute().parent)
        control_parent = _assert_plain_directory(Path(workspace_receipt.control_temp_root))
        _safe_name(output_binding_path.name)
        _safe_name(output_pack_directory.name)
        if binding_parent != pack_parent or pack_parent != control_parent:
            errors.append("ATOMIC_RUNNER_OUTPUT_PARENT_MISMATCH")
        hard_stop_receipt = _runner_receipt_path(output_pack_directory, hard_stop=True)
        resolution_marker = Path(workspace_receipt.control_temp_root) / _CONTROL_MARKER_NAME
        output_identities = {
            os.path.normcase(os.path.abspath(path))
            for path in (
                output_binding_path,
                output_pack_directory,
                hard_stop_receipt,
                resolution_marker,
            )
        }
        staging_prefix = f".{output_pack_directory.name}.staging-".casefold()
        if len(output_identities) != 4 or output_binding_path.name.casefold().startswith(
            staging_prefix
        ):
            errors.append("ATOMIC_RUNNER_OUTPUT_ALIAS")
        if os.path.lexists(hard_stop_receipt):
            errors.append("ATOMIC_RUNNER_RECEIPT_OUTPUT_EXISTS")
        if any(entry.name.casefold().startswith(staging_prefix) for entry in pack_parent.iterdir()):
            errors.append("OWNER_REVIEW_PACK_STAGING_EXISTS")
    except PreDnsOrchestrationError:
        errors.append("ATOMIC_RUNNER_OUTPUT_BOUNDARY_INVALID")
    if (
        type(binding_ttl_seconds) is not int
        or not MINIMUM_READY_MARGIN_SECONDS <= binding_ttl_seconds <= 900
    ):
        errors.append("PROVIDER_NETWORK_BINDING_TTL_INSUFFICIENT")

    checked = _utc(clock(), code="ATOMIC_RUNNER_CLOCK_INVALID")
    if checked >= mission_manifest.expires_at:
        errors.append("BOOTSTRAP_MISSION_EXPIRED")
    selection = loaded.campaign_selection
    try:
        selection.assert_selected_candidate_current(checked)
    except ValueError as error:
        code = str(error)
        errors.append(
            "FUTURE_WINDOW_NOT_OPEN" if "NOT_OPEN" in code else "CAMPAIGN_SELECTION_NOT_CURRENT"
        )
    selected = selection.selected_candidate()
    usable_margin = int((selected.usable_expires_at_utc - checked).total_seconds())
    if usable_margin < MINIMUM_READY_MARGIN_SECONDS:
        errors.append("OWNER_REVIEW_USABLE_MARGIN_INSUFFICIENT")
    if (
        isinstance(selection, FirstC0CanarySelectionV1)
        and selected.window_id == "H2"
        and checked - selected.window_not_before_utc
        > timedelta(seconds=FIRST_C0_MAXIMUM_OPEN_TO_PREFLIGHT_SECONDS)
    ):
        errors.append("FIRST_C0_OPEN_TO_PREFLIGHT_BUDGET_EXCEEDED")
    receipt = loaded.window_open_receipt
    if (
        isinstance(selection, FirstC0CanarySelectionV1)
        and selected.window_id == "H2"
        and receipt is None
    ):
        errors.append("FIRST_C0_H2_PREFETCH_REQUIRED_BEFORE_WINDOW_OPEN")
    if receipt is not None:
        try:
            if (
                loaded.prefetch_handoff is None
                or loaded.prefetch_handoff_path is None
                or loaded.window_open_receipt_path is None
                or _read_regular_bounded(
                    loaded.prefetch_handoff_path,
                    maximum_bytes=MAXIMUM_BUNDLE_ARTIFACT_BYTES,
                )
                != _model_bytes(loaded.prefetch_handoff)
                or _read_regular_bounded(
                    loaded.window_open_receipt_path,
                    maximum_bytes=MAXIMUM_BUNDLE_ARTIFACT_BYTES,
                )
                != _model_bytes(receipt)
                or not _prefetched_bundle_bytes_current_v1(loaded)
            ):
                errors.append("FIRST_C0_PREFETCH_AUTHORITY_DRIFT")
        except PreDnsOrchestrationError:
            errors.append("FIRST_C0_PREFETCH_AUTHORITY_DRIFT")
        current_monotonic = float(monotonic())
        wall_since_activation = (checked - receipt.checked_at_utc).total_seconds()
        monotonic_since_activation = current_monotonic - receipt.checked_monotonic
        if (
            not math.isfinite(current_monotonic)
            or not math.isfinite(monotonic_since_activation)
            or wall_since_activation < 0
            or monotonic_since_activation < 0
            or abs(wall_since_activation - monotonic_since_activation) > 2.0
        ):
            errors.append("FIRST_C0_PREFLIGHT_CLOCK_INVALID")
        if (
            checked - receipt.window_not_before_utc
            > timedelta(seconds=FIRST_C0_MAXIMUM_OPEN_TO_PREFLIGHT_SECONDS)
            or current_monotonic - receipt.window_open_monotonic
            > FIRST_C0_MAXIMUM_OPEN_TO_PREFLIGHT_SECONDS
        ):
            errors.append("FIRST_C0_OPEN_TO_PREFLIGHT_BUDGET_EXCEEDED")
    future = "FUTURE_WINDOW_NOT_OPEN" in errors
    accepted = not errors
    status: RunnerStatusV1 = (
        "PREFLIGHT_ACCEPT"
        if accepted
        else "FUTURE_WINDOW_NOT_OPEN"
        if future
        else "PREFLIGHT_REJECTED"
    )
    return RunnerPreflightV1(
        accepted=accepted,
        status=status,
        errors=tuple(dict.fromkeys(errors)),
        checked_at_utc=checked,
        usable_margin_seconds=usable_margin,
        global_v2_read_identity=(
            observed_marker.current_v2_root_identity if observed_marker is not None else None
        ),
        global_legacy_root_identity=(
            observed_marker.current_legacy_root_identity if observed_marker is not None else None
        ),
        historical_marker_binding=observed_marker,
    )


def _write_runner_receipt(
    path: Path,
    *,
    status: str,
    observed_at_utc: datetime,
    bundle_sha256: str,
    binding_sha256: str | None,
    pack_sha256: str | None,
    resolver_operations: int,
    pack_builds: int,
    code: str | None,
    failure_phase: str | None,
    resolver_completed: bool,
    binding_persisted: bool,
    pack_staged: bool,
    publication_completed: bool,
    expected_output_directory_name: str,
) -> None:
    _write_exclusive(
        path,
        _json_bytes(
            {
                "schema_version": ATOMIC_RUNNER_RECEIPT_SCHEMA,
                "status": status,
                "observed_at_utc": _utc_text(observed_at_utc),
                "pre_dns_bundle_sha256": bundle_sha256,
                "provider_network_binding_sha256": binding_sha256,
                "owner_review_pack_sha256": pack_sha256,
                "resolver_operations": resolver_operations,
                "resolver_retries": 0,
                "pack_builds": pack_builds,
                "failure_phase": failure_phase,
                "resolver_completed": resolver_completed,
                "binding_persisted": binding_persisted,
                "pack_staged": pack_staged,
                "publication_completed": publication_completed,
                "publication_authority": "EFFECTIVE_ONLY_AFTER_PARENT_DIRECTORY_RENAME",
                "expected_output_directory_name": expected_output_directory_name,
                "provider_tcp": 0,
                "provider_http": 0,
                "secret_reads": 0,  # nosec B105 -- effect counter, not a credential
                "owner_authorized_artifacts": 0,
                "activations": 0,
                "captures": 0,
                "promotions": 0,
                "bets": 0,
                "hard_stop_code": code,
            }
        ),
    )


def _run_owner_review_pack_once_v1(
    *,
    bundle_directory: Path,
    workspace_receipt: RealCaptureWorkspaceReceiptV1,
    mission_manifest: RealExecutionMissionManifestV1,
    output_binding_path: Path,
    output_pack_directory: Path,
    resolver: ResolverV1,
    marker_inspector: MarkerInspectorV1,
    execute: bool = False,
    owner_present_for_review: bool = False,
    binding_ttl_seconds: int = 900,
    prefetch_handoff_path: Path | None = None,
    window_open_receipt_path: Path | None = None,
    clock: ClockV1 = lambda: datetime.now(UTC),
    monotonic: MonotonicV1 = time.monotonic,
    duration_monotonic: MonotonicV1 | None = None,
    clock_path_anchor_wall_utc: datetime | None = None,
    clock_path_anchor_monotonic: float | None = None,
    workspace_validator: WorkspaceValidatorV1 = _validate_workspace_default,
    binding_preparer: BindingPreparerV1 = _prepare_provider_network_binding_after_atomic_preflight_v1,
    pack_builder: PackBuilderV1 = _build_first_c0_owner_review_pack_after_atomic_binding_v1,
    pack_writer: PackWriterV1 = _write_first_c0_owner_review_pack_after_atomic_binding_v1,
    raw_evidence_verifier: RawEvidenceVerifierV1 = verify_raw_official_evidence_v1,
    v5_single_owner_entrypoint: bool,
) -> AtomicRunnerResultV1:
    """Default to read-only preflight; execute one non-retryable DNS-to-pack transaction."""

    raw_monotonic = monotonic
    budget_monotonic = monotonic if duration_monotonic is None else duration_monotonic
    guarded_clock_path = _GuardedClockPathV1(
        clock=clock,
        monotonic=raw_monotonic,
        anchor_wall_utc=clock_path_anchor_wall_utc,
        anchor_monotonic=clock_path_anchor_monotonic,
    )
    guarded_clock = guarded_clock_path.clock
    paired_monotonic = guarded_clock_path.paired_monotonic

    def sample_budget_monotonic() -> float:
        sampled = float(budget_monotonic())
        if not math.isfinite(sampled):
            raise PreDnsOrchestrationError("DNS_TO_PACK_MONOTONIC_INVALID")
        return sampled

    try:
        preflight, loaded = preflight_owner_review_pack_once_v1(
            bundle_directory=bundle_directory,
            workspace_receipt=workspace_receipt,
            mission_manifest=mission_manifest,
            output_binding_path=output_binding_path,
            output_pack_directory=output_pack_directory,
            marker_inspector=marker_inspector,
            owner_present_for_review=owner_present_for_review,
            execute=execute,
            binding_ttl_seconds=binding_ttl_seconds,
            prefetch_handoff_path=prefetch_handoff_path,
            window_open_receipt_path=window_open_receipt_path,
            clock=guarded_clock,
            monotonic=paired_monotonic,
            workspace_validator=workspace_validator,
            raw_evidence_verifier=raw_evidence_verifier,
        )
    except PreDnsOrchestrationError as error:
        if error.code != "FIRST_C0_PREFLIGHT_CLOCK_INVALID":
            raise
        preflight = RunnerPreflightV1(
            accepted=False,
            status="PREFLIGHT_REJECTED",
            errors=(error.code,),
            checked_at_utc=(
                guarded_clock_path.last_observed_wall_utc or mission_manifest.expires_at
            ),
            usable_margin_seconds=0,
        )
        loaded = None
    if execute is True and loaded is not None and v5_single_owner_entrypoint is not True:
        preflight = RunnerPreflightV1(
            accepted=False,
            status="PREFLIGHT_REJECTED",
            errors=tuple(
                dict.fromkeys((*preflight.errors, "FIRST_C0_SINGLE_OWNER_ENTRYPOINT_REQUIRED"))
            ),
            checked_at_utc=preflight.checked_at_utc,
            usable_margin_seconds=preflight.usable_margin_seconds,
        )
    if not execute or not preflight.accepted or loaded is None:
        return AtomicRunnerResultV1(
            status=preflight.status,
            preflight=preflight,
            resolver_operations=0,
            pack_builds=0,
            binding_sha256=None,
            pack_sha256=None,
            receipt_path=None,
            hard_stop_code=None,
        )
    try:
        preflight = _final_execute_preflight_v1(
            loaded=loaded,
            workspace_receipt=workspace_receipt,
            mission_manifest=mission_manifest,
            output_binding_path=output_binding_path,
            output_pack_directory=output_pack_directory,
            marker_inspector=marker_inspector,
            binding_ttl_seconds=binding_ttl_seconds,
            clock=guarded_clock,
            monotonic=paired_monotonic,
            workspace_validator=workspace_validator,
        )
    except PreDnsOrchestrationError as error:
        if error.code != "FIRST_C0_PREFLIGHT_CLOCK_INVALID":
            raise
        preflight = RunnerPreflightV1(
            accepted=False,
            status="PREFLIGHT_REJECTED",
            errors=(error.code,),
            checked_at_utc=(
                guarded_clock_path.last_observed_wall_utc or mission_manifest.expires_at
            ),
            usable_margin_seconds=0,
        )
    if not preflight.accepted:
        return AtomicRunnerResultV1(
            status=preflight.status,
            preflight=preflight,
            resolver_operations=0,
            pack_builds=0,
            binding_sha256=None,
            pack_sha256=None,
            receipt_path=None,
            hard_stop_code=None,
        )
    expected_v2_root_identity = preflight.global_v2_read_identity
    expected_legacy_root_identity = preflight.global_legacy_root_identity
    expected_historical_marker = preflight.historical_marker_binding
    if (
        expected_v2_root_identity is None
        or expected_legacy_root_identity is None
        or expected_historical_marker is None
        or expected_historical_marker.historical_raw_sha256 is None
    ):
        rejected = RunnerPreflightV1(
            accepted=False,
            status="PREFLIGHT_REJECTED",
            errors=("GLOBAL_CLAIM_PREFLIGHT_IDENTITY_UNAVAILABLE",),
            checked_at_utc=preflight.checked_at_utc,
            usable_margin_seconds=0,
        )
        return AtomicRunnerResultV1(
            status=rejected.status,
            preflight=rejected,
            resolver_operations=0,
            pack_builds=0,
            binding_sha256=None,
            pack_sha256=None,
            receipt_path=None,
            hard_stop_code=None,
        )
    selection = loaded.campaign_selection
    selected = selection.selected_candidate()
    earliest_kickoff = min(
        target.official_kickoff_utc for target in selected.fixture_target_set.targets
    )

    def binding_clock() -> datetime:
        current = _utc(guarded_clock(), code="ATOMIC_RUNNER_CLOCK_INVALID")
        usable_ceiling = min(
            mission_manifest.expires_at,
            selected.usable_expires_at_utc,
            earliest_kickoff - timedelta(seconds=SAFETY_CUTOFF_SECONDS),
        )
        if int((usable_ceiling - current).total_seconds()) < MINIMUM_READY_MARGIN_SECONDS:
            raise PreDnsOrchestrationError("OWNER_REVIEW_USABLE_MARGIN_INSUFFICIENT")
        try:
            selection.assert_selected_candidate_current(current)
        except ValueError:
            raise PreDnsOrchestrationError("CAMPAIGN_SELECTION_NOT_CURRENT") from None
        if (
            isinstance(selection, FirstC0CanarySelectionV1)
            and selected.window_id == "H2"
            and current - selected.window_not_before_utc
            > timedelta(seconds=FIRST_C0_MAXIMUM_OPEN_TO_PREFLIGHT_SECONDS)
        ):
            raise PreDnsOrchestrationError("FIRST_C0_OPEN_TO_PREFLIGHT_BUDGET_EXCEEDED")
        receipt = loaded.window_open_receipt
        if receipt is not None:
            current_monotonic = float(paired_monotonic())
            wall_since_activation = (current - receipt.checked_at_utc).total_seconds()
            monotonic_since_activation = current_monotonic - receipt.checked_monotonic
            if (
                not math.isfinite(current_monotonic)
                or not math.isfinite(monotonic_since_activation)
                or wall_since_activation < 0
                or monotonic_since_activation < 0
                or abs(wall_since_activation - monotonic_since_activation) > 2.0
            ):
                raise PreDnsOrchestrationError("FIRST_C0_PREFLIGHT_CLOCK_INVALID")
            if (
                current - receipt.window_not_before_utc
                > timedelta(seconds=FIRST_C0_MAXIMUM_OPEN_TO_PREFLIGHT_SECONDS)
                or current_monotonic - receipt.window_open_monotonic
                > FIRST_C0_MAXIMUM_OPEN_TO_PREFLIGHT_SECONDS
            ):
                raise PreDnsOrchestrationError("FIRST_C0_OPEN_TO_PREFLIGHT_BUDGET_EXCEEDED")
        return current

    try:
        binding_clock()
    except PreDnsOrchestrationError as error:
        rejected = RunnerPreflightV1(
            accepted=False,
            status="PREFLIGHT_REJECTED",
            errors=(error.code,),
            checked_at_utc=preflight.checked_at_utc,
            usable_margin_seconds=0,
        )
        return AtomicRunnerResultV1(
            status=rejected.status,
            preflight=rejected,
            resolver_operations=0,
            pack_builds=0,
            binding_sha256=None,
            pack_sha256=None,
            receipt_path=None,
            hard_stop_code=None,
        )
    resolver_operations = 0
    pack_builds = 0
    resolver_completed_monotonic: float | None = None
    failure_phase: str | None = "BINDING_PREPARATION"
    resolver_completed = False
    binding_persisted = False
    pack_staged = False
    publication_completed = False

    def counted_resolver(
        host: str,
        port: int,
        family: int,
        socket_type: int,
        protocol: int,
    ) -> Iterable[tuple[object, ...]]:
        nonlocal failure_phase, resolver_completed, resolver_completed_monotonic
        nonlocal resolver_operations
        # The provider path samples this clock before its final composite
        # authority barrier.  Sampling again here would reopen a mutation
        # window between that barrier and the real resolver operation.
        resolver_operations += 1
        if resolver_operations != 1:
            raise PreDnsOrchestrationError("RESOLVER_OPERATION_LIMIT_EXCEEDED")
        failure_phase = "RESOLVER"
        result = tuple(
            cast(
                Iterable[tuple[object, ...]],
                resolver(host, port, family, socket_type, protocol),
            )
        )
        resolver_completed = True
        resolver_completed_monotonic = sample_budget_monotonic()
        failure_phase = "BINDING_VALIDATION"
        return result

    def assert_final_pre_effect_authority() -> None:
        try:
            observed = marker_inspector(workspace_receipt, mission_manifest)
        except Exception:
            raise PreDnsOrchestrationError("PROVIDER_MARKER_INSPECTION_FAILED") from None
        if not _historical_marker_binding_matches_v1(
            observed,
            expected_historical_marker,
            expected_v2_root_identity=expected_v2_root_identity,
            expected_legacy_root_identity=expected_legacy_root_identity,
        ):
            raise PreDnsOrchestrationError("HISTORICAL_MARKER_CHANGED")

    binding: ProviderNetworkBindingV1 | None = None
    pack: OwnerReviewPackV1 | None = None
    staging: Path | None = None
    try:
        binding = binding_preparer(
            workspace_receipt=workspace_receipt,
            mission_manifest=mission_manifest,
            campaign_selection=loaded.campaign_selection,
            output_path=output_binding_path,
            resolver=counted_resolver,
            clock=binding_clock,
            binding_ttl_seconds=binding_ttl_seconds,
            expected_global_v2_read_identity=expected_v2_root_identity,
            expected_global_legacy_root_identity=expected_legacy_root_identity,
            final_pre_effect_assertion=assert_final_pre_effect_authority,
        )
        if (
            resolver_operations != 1
            or resolver_completed_monotonic is None
            or binding.resolution_operations != 1
        ):
            raise PreDnsOrchestrationError("RESOLVER_OPERATION_COUNT_INVALID")
        persisted_binding = ProviderNetworkBindingV1.model_validate_json(
            _read_regular_bounded(
                output_binding_path,
                maximum_bytes=MAXIMUM_BUNDLE_ARTIFACT_BYTES,
            )
        )
        if persisted_binding != binding or _read_regular_bounded(
            output_binding_path,
            maximum_bytes=MAXIMUM_BUNDLE_ARTIFACT_BYTES,
        ) != _model_bytes(binding):
            raise PreDnsOrchestrationError("PROVIDER_NETWORK_BINDING_PERSISTENCE_INVALID")
        binding_persisted = True
        failure_phase = "PACK_BUILD"
        generated = _utc(guarded_clock(), code="ATOMIC_RUNNER_CLOCK_INVALID")
        nonce_hash = canonical_sha256(
            {
                "workspace": workspace_receipt.canonical_receipt_hash,
                "binding": binding.canonical_binding_hash,
                "targets": selected.fixture_target_set.canonical_set_hash,
                "campaign_selection": loaded.campaign_selection.canonical_selection_hash,
                "request": canonical_sha256(selected.request.fingerprint_material()),
                "generated_at": _utc_text(generated),
            }
        )
        pack_started = sample_budget_monotonic()
        pack_start_elapsed = pack_started - resolver_completed_monotonic
        if pack_start_elapsed < 0:
            raise PreDnsOrchestrationError("DNS_TO_PACK_MONOTONIC_INVALID")
        if pack_start_elapsed > MAXIMUM_DNS_TO_PACK_START_SECONDS:
            raise PreDnsOrchestrationError("DNS_TO_PACK_START_BUDGET_EXCEEDED")
        pack_builds += 1
        pack = pack_builder(
            workspace_receipt=workspace_receipt,
            mission_manifest=mission_manifest,
            provider_network_binding=binding,
            campaign_selection=loaded.campaign_selection,
            generated_at_utc=generated,
            authorization_nonce=f"owner-{nonce_hash[:40]}",
            activation_nonce=f"activation-{nonce_hash[24:64]}",
        )
        failure_phase = "PACK_STAGING"
        staging = output_pack_directory.parent / (
            f".{output_pack_directory.name}.staging-{binding.canonical_binding_hash[:16]}"
        )
        if os.path.lexists(staging):
            raise PreDnsOrchestrationError("OWNER_REVIEW_PACK_STAGING_EXISTS")
        os.mkdir(staging, 0o700)
        paths = pack_writer(staging, pack)
        verify_owner_review_pack_artifacts_v1(staging, pack, paths)
        pack_staged = True
        workspace_validator(workspace_receipt)
        completed = _utc(guarded_clock(), code="ATOMIC_RUNNER_CLOCK_INVALID")
        assert_owner_review_pack_completion_current_v1(pack, completed)
        completion_elapsed = sample_budget_monotonic() - resolver_completed_monotonic
        if completion_elapsed < 0:
            raise PreDnsOrchestrationError("DNS_TO_PACK_MONOTONIC_INVALID")
        if completion_elapsed > MAXIMUM_DNS_TO_PACK_COMPLETION_SECONDS:
            raise PreDnsOrchestrationError("DNS_TO_PACK_COMPLETION_BUDGET_EXCEEDED")
        if os.path.lexists(output_pack_directory):
            raise PreDnsOrchestrationError("OWNER_REVIEW_PACK_OUTPUT_EXISTS")
        failure_phase = "PACK_PUBLICATION"
        receipt = _runner_receipt_path(output_pack_directory, hard_stop=False)
        publication_elapsed = sample_budget_monotonic() - resolver_completed_monotonic
        if publication_elapsed < 0:
            raise PreDnsOrchestrationError("DNS_TO_PACK_MONOTONIC_INVALID")
        if publication_elapsed > MAXIMUM_DNS_TO_PACK_COMPLETION_SECONDS:
            raise PreDnsOrchestrationError("DNS_TO_PACK_COMPLETION_BUDGET_EXCEEDED")
        os.rename(staging, output_pack_directory)
        publication_completed = True
        failure_phase = "RECEIPT_FINALIZATION"
        _write_runner_receipt(
            receipt,
            status="OWNER_REVIEW_PACK_CREATED",
            observed_at_utc=completed,
            bundle_sha256=loaded.manifest_sha256,
            binding_sha256=binding.canonical_binding_hash,
            pack_sha256=pack.canonical_pack_hash,
            resolver_operations=resolver_operations,
            pack_builds=pack_builds,
            code=None,
            failure_phase=None,
            resolver_completed=True,
            binding_persisted=True,
            pack_staged=True,
            publication_completed=True,
            expected_output_directory_name=output_pack_directory.name,
        )
        failure_phase = None
        return AtomicRunnerResultV1(
            status="OWNER_REVIEW_PACK_CREATED",
            preflight=preflight,
            resolver_operations=resolver_operations,
            pack_builds=pack_builds,
            binding_sha256=binding.canonical_binding_hash,
            pack_sha256=pack.canonical_pack_hash,
            receipt_path=receipt,
            hard_stop_code=None,
        )
    except Exception as error:
        code = getattr(error, "code", "POST_DNS_PACK_FAILURE")
        receipt = _runner_receipt_path(output_pack_directory, hard_stop=True)
        try:
            _write_runner_receipt(
                receipt,
                status="POST_DNS_HARD_STOP",
                observed_at_utc=(
                    guarded_clock_path.last_trusted_wall_utc or preflight.checked_at_utc
                ),
                bundle_sha256=loaded.manifest_sha256,
                binding_sha256=(binding.canonical_binding_hash if binding is not None else None),
                pack_sha256=(pack.canonical_pack_hash if pack is not None else None),
                resolver_operations=resolver_operations,
                pack_builds=pack_builds,
                code=code,
                failure_phase=failure_phase,
                resolver_completed=resolver_completed,
                binding_persisted=binding_persisted,
                pack_staged=pack_staged,
                publication_completed=publication_completed,
                expected_output_directory_name=output_pack_directory.name,
            )
        except PreDnsOrchestrationError:
            raise PreDnsOrchestrationError("POST_DNS_HARD_STOP_RECEIPT_WRITE_FAILED") from None
        return AtomicRunnerResultV1(
            status="POST_DNS_HARD_STOP",
            preflight=preflight,
            resolver_operations=resolver_operations,
            pack_builds=pack_builds,
            binding_sha256=(binding.canonical_binding_hash if binding is not None else None),
            pack_sha256=(pack.canonical_pack_hash if pack is not None else None),
            receipt_path=receipt,
            hard_stop_code=code,
        )


def run_owner_review_pack_once_v1(
    *,
    bundle_directory: Path,
    workspace_receipt: RealCaptureWorkspaceReceiptV1,
    mission_manifest: RealExecutionMissionManifestV1,
    output_binding_path: Path,
    output_pack_directory: Path,
    resolver: ResolverV1,
    marker_inspector: MarkerInspectorV1,
    execute: bool = False,
    owner_present_for_review: bool = False,
    binding_ttl_seconds: int = 900,
    prefetch_handoff_path: Path | None = None,
    window_open_receipt_path: Path | None = None,
    clock: ClockV1 = lambda: datetime.now(UTC),
    monotonic: MonotonicV1 = time.monotonic,
    duration_monotonic: MonotonicV1 | None = None,
    clock_path_anchor_wall_utc: datetime | None = None,
    clock_path_anchor_monotonic: float | None = None,
    workspace_validator: WorkspaceValidatorV1 = _validate_workspace_default,
    binding_preparer: BindingPreparerV1 = _prepare_provider_network_binding_after_atomic_preflight_v1,
    pack_builder: PackBuilderV1 = _build_first_c0_owner_review_pack_after_atomic_binding_v1,
    pack_writer: PackWriterV1 = _write_first_c0_owner_review_pack_after_atomic_binding_v1,
    raw_evidence_verifier: RawEvidenceVerifierV1 = verify_raw_official_evidence_v1,
) -> AtomicRunnerResultV1:
    """Keep V5 execute effects behind the single owner-facing entrypoint."""

    return _run_owner_review_pack_once_v1(
        bundle_directory=bundle_directory,
        workspace_receipt=workspace_receipt,
        mission_manifest=mission_manifest,
        output_binding_path=output_binding_path,
        output_pack_directory=output_pack_directory,
        resolver=resolver,
        marker_inspector=marker_inspector,
        execute=execute,
        owner_present_for_review=owner_present_for_review,
        binding_ttl_seconds=binding_ttl_seconds,
        prefetch_handoff_path=prefetch_handoff_path,
        window_open_receipt_path=window_open_receipt_path,
        clock=clock,
        monotonic=monotonic,
        duration_monotonic=duration_monotonic,
        clock_path_anchor_wall_utc=clock_path_anchor_wall_utc,
        clock_path_anchor_monotonic=clock_path_anchor_monotonic,
        workspace_validator=workspace_validator,
        binding_preparer=binding_preparer,
        pack_builder=pack_builder,
        pack_writer=pack_writer,
        raw_evidence_verifier=raw_evidence_verifier,
        v5_single_owner_entrypoint=False,
    )


def _run_first_c0_owner_review_pack_once_after_owner_gate_v1(
    *,
    bundle_directory: Path,
    workspace_receipt: RealCaptureWorkspaceReceiptV1,
    mission_manifest: RealExecutionMissionManifestV1,
    output_binding_path: Path,
    output_pack_directory: Path,
    resolver: ResolverV1,
    marker_inspector: MarkerInspectorV1,
    execute: bool = False,
    owner_present_for_review: bool = False,
    binding_ttl_seconds: int = 900,
    prefetch_handoff_path: Path | None = None,
    window_open_receipt_path: Path | None = None,
    clock: ClockV1 = lambda: datetime.now(UTC),
    monotonic: MonotonicV1 = time.monotonic,
    duration_monotonic: MonotonicV1 | None = None,
    clock_path_anchor_wall_utc: datetime | None = None,
    clock_path_anchor_monotonic: float | None = None,
    workspace_validator: WorkspaceValidatorV1 = _validate_workspace_default,
    binding_preparer: BindingPreparerV1 = _prepare_provider_network_binding_after_atomic_preflight_v1,
    pack_builder: PackBuilderV1 = _build_first_c0_owner_review_pack_after_atomic_binding_v1,
    pack_writer: PackWriterV1 = _write_first_c0_owner_review_pack_after_atomic_binding_v1,
    raw_evidence_verifier: RawEvidenceVerifierV1 = verify_raw_official_evidence_v1,
) -> AtomicRunnerResultV1:
    return _run_owner_review_pack_once_v1(
        bundle_directory=bundle_directory,
        workspace_receipt=workspace_receipt,
        mission_manifest=mission_manifest,
        output_binding_path=output_binding_path,
        output_pack_directory=output_pack_directory,
        resolver=resolver,
        marker_inspector=marker_inspector,
        execute=execute,
        owner_present_for_review=owner_present_for_review,
        binding_ttl_seconds=binding_ttl_seconds,
        prefetch_handoff_path=prefetch_handoff_path,
        window_open_receipt_path=window_open_receipt_path,
        clock=clock,
        monotonic=monotonic,
        duration_monotonic=duration_monotonic,
        clock_path_anchor_wall_utc=clock_path_anchor_wall_utc,
        clock_path_anchor_monotonic=clock_path_anchor_monotonic,
        workspace_validator=workspace_validator,
        binding_preparer=binding_preparer,
        pack_builder=pack_builder,
        pack_writer=pack_writer,
        raw_evidence_verifier=raw_evidence_verifier,
        v5_single_owner_entrypoint=True,
    )


__all__ = [
    "AtomicRunnerResultV1",
    "HistoricalMarkerExpectationV1",
    "LoadedPreDnsBundleV1",
    "MarkerInspectionV1",
    "PreDnsCountersV1",
    "PreDnsLimitsV1",
    "PreDnsOrchestrationError",
    "PreDnsResultV1",
    "RunnerPreflightV1",
    "freeze_official_schedule_evidence_v1",
    "inspect_provider_markers_read_only_v1",
    "load_pre_dns_bundle_v1",
    "load_scientific_corpus_evidence_v1",
    "preflight_owner_review_pack_once_v1",
    "prepare_owner_review_pack_inputs_v1",
    "run_owner_review_pack_once_v1",
    "verify_owner_review_pack_artifacts_v1",
]
