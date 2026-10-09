"""Recurring, idempotent real-data collection for the personal Robin lab."""

from __future__ import annotations

import base64
import hashlib
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal, Protocol, cast

from robin.capture.contracts import (
    CaptureContractError,
    ProviderRequestSpec,
    canonical_json_bytes,
    ensure_utc,
    strict_json_loads,
)
from robin.capture.live_transport import (
    LiveTransport,
    LiveTransportError,
    LiveTransportResponse,
    PublicProviderRequestV1,
    SecretReader,
    validate_provider_secret,
)
from robin.capture.real_data_result import (
    MARKETS,
    MAX_RESPONSE_BYTES,
    REGION,
    SPORT_KEYS,
    _normalize_payload,
    _observed_credit_cost,
    _Quota,
    _quota,
)
from robin.capture.reprise_collecte import NetworkResolution
from robin.prospective_observatory.chronos_control_plane import (
    ConditionalPutOutcome,
    ConditionalPutResult,
    ObservedObject,
)
from robin.prospective_observatory.chronos_r2 import LatestProjection

MISSION_ID = "ROBIN_AUTONOMOUS_LAB_20261004"
MANDATE_SHA256 = "c611e5cfdb2fb6bc2b1a6238e7bc8ec94191d4841c9cad177abcf6bb8662a813"
RECURRING_CLAIM_IDS = (
    "DATA.ROBIN.AUTONOMOUS_LAB.RECURRING_CAPTURES.V1.001",
    "DATA.ROBIN.AUTONOMOUS_LAB.RECURRING_VIEW.V1.001",
    "GOV.ROBIN.AUTONOMOUS_LAB.RECURRING_CONSUMPTION.V1.001",
)
SEED_CLAIM_IDS = (
    "DATA.ROBIN.AUTONOMOUS_LAB.SEED_CAPTURES.V1.001",
    "DATA.ROBIN.AUTONOMOUS_LAB.SEED_VIEW.V1.001",
    "GOV.ROBIN.AUTONOMOUS_LAB.SEED_CONSUMPTION.V1.001",
)
_ALLOWED_REPORT_CLAIM_IDS = {RECURRING_CLAIM_IDS, SEED_CLAIM_IDS}
OBJECT_PREFIX = f"robin/autonomous-lab/{MISSION_ID}"
ACCOUNTING_HEAD_KEY = f"{OBJECT_PREFIX}/accounting/head.json"
ACCOUNTING_INITIALIZED_KEY = f"{OBJECT_PREFIX}/accounting/initialized.json"
LATEST_REPORT_KEY = f"{OBJECT_PREFIX}/latest.json"
HISTORICAL_SEED_AT = datetime(2026, 10, 3, 20, 58, 16, tzinfo=UTC)
HISTORICAL_SEED_SLOT = datetime(2026, 10, 3, 20, 0, tzinfo=UTC)
HISTORICAL_REQUESTS = 16
HISTORICAL_CREDITS = 34
HISTORICAL_PROVIDER_REMAINING = 19_969
HISTORICAL_RECEIPT_SHA256 = "72b0ba67363658f7503968e43c831e5485d2c6ea9f1f1a2a8b73a0cb5ac38e37"
HISTORICAL_PRIVATE_REPORT_KEY = (
    "robin/real-data-result/ROBIN_REAL_DATA_RESULT_20261003/runs/37153158456/private-report.json"
)
HISTORICAL_PRIVATE_REPORT_SHA256 = (
    "b0f0151d92d5ce4a90980b3521bb8acf49a34f00c58b85d558fec7eea610762e"
)
HISTORICAL_ADAPTER_KEY = f"{OBJECT_PREFIX}/imports/run-37153158456/private-report.json"
HISTORICAL_MISSION_ID = "ROBIN_REAL_DATA_RESULT_20261003"
HISTORICAL_RUN_ID = "37153158456"
HISTORICAL_REPOSITORY_SHA = "0be96131d1c9c6d7337629f906ead3b282304293"
SLOT_REQUESTS = len(SPORT_KEYS)
SLOT_CREDITS = SLOT_REQUESTS * 2
ROLLING_24H_REQUEST_MAX = 140
ROLLING_24H_CREDIT_MAX = 280
ROLLING_30D_REQUEST_MAX = 4_000
ROLLING_30D_CREDIT_MAX = 8_000
MAX_CAS_ATTEMPTS = 3
MAX_ACCOUNTING_CHAIN_NODES = 2_048
PROVIDER_KEY = "THE_ODDS_API_V4"
# The provider route identifies h2h/totals, but its V4 odds response does not
# attest a soccer settlement period. Preserve that limitation explicitly.
SETTLEMENT_PERIOD_KEY = "PROVIDER_DEFAULT_UNSPECIFIED"

_MANIFEST_FIELDS = {
    "mission_id",
    "authorized_stages",
    "maximum_stage",
    "external_effects",
    "compute_budget",
    "time_budget",
    "source_hash",
    "expires_at",
}
_REQUIRED_EFFECTS = {
    "github_actions_schedule_every_2_hours_minute_17",
    "provider_https_get_per_slot_max_5",
    "provider_http_rolling_24h_max_140",
    "provider_credit_rolling_24h_max_280",
    "provider_http_rolling_30d_max_4000",
    "provider_credit_rolling_30d_max_8000",
    "r2_atomic_accounting_head_compare_and_swap",
    "r2_immutable_raw_capture_and_exact_readback",
}
_SAFETY_LOCKS = {
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


class RecurringError(RuntimeError):
    """Stable fail-closed code without provider material."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class TransportFactory(Protocol):
    def __call__(self, clock: Callable[[], datetime]) -> LiveTransport: ...


class RecurringStore(Protocol):
    def put_if_absent(
        self,
        key: str,
        data: bytes,
        *,
        metadata: Mapping[str, str],
        on_dispatch: Callable[[], None],
    ) -> ConditionalPutResult: ...

    def get_object(self, key: str) -> ObservedObject | None: ...

    def get_latest_projection(self, key: str) -> LatestProjection | None: ...

    def put_latest_projection(
        self,
        key: str,
        data: bytes,
        *,
        metadata: Mapping[str, str],
        expected_etag: str | None,
        on_dispatch: Callable[[], None],
    ) -> ConditionalPutResult: ...


@dataclass(frozen=True, slots=True)
class RecurringConfig:
    manifest_path: Path
    output_directory: Path
    repository_sha: str
    github_run_id: str
    github_run_attempt: int
    relay_generation: str
    relay_chain_id: str
    relay_parent_run_id: str
    relay_sequence: int
    safety_environment: Mapping[str, str]


@dataclass(frozen=True, slots=True)
class _Manifest:
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class _Admission:
    node_key: str
    node_sha256: str
    node: Mapping[str, object]
    resumed: bool = False


@dataclass(frozen=True, slots=True)
class _BranchOutcome:
    branch: dict[str, object]
    rows: tuple[dict[str, object], ...]
    provider_attempts: int
    circuit_code: str | None = None
    observed_remaining: int | None = None
    credit_bound_valid: bool = True


def _iso_z(value: datetime) -> str:
    return ensure_utc(value, field="recurring_time").isoformat().replace("+00:00", "Z")


def _parse_time(value: object, code: str) -> datetime:
    if not isinstance(value, str):
        raise RecurringError(code)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return ensure_utc(parsed, field="recurring_time")
    except (CaptureContractError, ValueError):
        raise RecurringError(code) from None


def slot_start_utc(now: datetime) -> datetime:
    """Map scheduler jitter to one deterministic two-hour UTC slot."""

    current = ensure_utc(now, field="recurring_slot_now")
    return current.replace(
        hour=current.hour - (current.hour % 2), minute=0, second=0, microsecond=0
    )


def _slot_id(slot: datetime) -> str:
    return ensure_utc(slot, field="recurring_slot").strftime("%Y%m%dT%H%M%SZ")


def classify_market_limitation(
    code: str,
) -> Literal["MISSING", "DUPLICATED", "LEGACY_UNKNOWN", "OTHER"]:
    if code == "RESULT_MARKET_MISSING":
        return "MISSING"
    if code == "RESULT_MARKET_DUPLICATED":
        return "DUPLICATED"
    if code == "RESULT_MARKET_MISSING_OR_DUPLICATED":
        return "LEGACY_UNKNOWN"
    return "OTHER"


def _mapping(data: bytes, code: str) -> Mapping[str, object]:
    try:
        value = strict_json_loads(data)
    except CaptureContractError:
        raise RecurringError(code) from None
    if not isinstance(value, dict):
        raise RecurringError(code)
    return cast(Mapping[str, object], value)


def _report_claim_ids(report: Mapping[str, object]) -> list[str]:
    raw = report.get("claim_ids")
    if not isinstance(raw, list) or tuple(raw) not in _ALLOWED_REPORT_CLAIM_IDS:
        raise RecurringError("RECURRING_REPORT_CLAIMS_INVALID")
    return [cast(str, item) for item in raw]


def _validate_config(config: RecurringConfig) -> None:
    if (
        re.fullmatch(r"[0-9a-f]{40}", config.repository_sha) is None
        or re.fullmatch(r"[1-9][0-9]{0,19}", config.github_run_id) is None
        or config.github_run_attempt != 1
        or re.fullmatch(r"[0-9a-f]{64}", config.relay_generation) is None
        or re.fullmatch(r"[1-9][0-9]{0,19}", config.relay_chain_id) is None
        or re.fullmatch(r"[1-9][0-9]{0,19}", config.relay_parent_run_id) is None
        or config.relay_parent_run_id == config.github_run_id
        or not isinstance(config.relay_sequence, int)
        or isinstance(config.relay_sequence, bool)
        or not 1 <= config.relay_sequence <= 9_999_999_999
        or not config.output_directory.is_absolute()
    ):
        raise RecurringError("RECURRING_CONFIG_INVALID")
    if dict(config.safety_environment) != _SAFETY_LOCKS:
        raise RecurringError("RECURRING_SAFETY_LOCK_INVALID")


def _load_manifest(path: Path, now: datetime) -> _Manifest:
    try:
        data = path.read_bytes().replace(b"\r\n", b"\n")
        manifest = _mapping(data, "RECURRING_MANIFEST_INVALID")
    except OSError:
        raise RecurringError("RECURRING_MANIFEST_INVALID") from None
    if (
        set(manifest) != _MANIFEST_FIELDS
        or manifest.get("mission_id") != MISSION_ID
        or manifest.get("authorized_stages") != ["E1", "E2", "E3A", "E3B"]
        or manifest.get("maximum_stage") != "E3B"
        or manifest.get("source_hash") != MANDATE_SHA256
        or not isinstance(manifest.get("external_effects"), list)
        or not _REQUIRED_EFFECTS <= set(cast(list[object], manifest["external_effects"]))
    ):
        raise RecurringError("RECURRING_MANIFEST_INVALID")
    expires_at = _parse_time(manifest.get("expires_at"), "RECURRING_MANIFEST_INVALID")
    if now >= expires_at:
        raise RecurringError("RECURRING_AUTHORITY_EXPIRED")
    return _Manifest(expires_at=expires_at)


def _diagnostic(
    *,
    stage: str,
    code: str,
    exception_class: str,
    errno: int | None = None,
    http_status: int | None = None,
) -> dict[str, object]:
    result: dict[str, object] = {
        "stage": stage,
        "code": code,
        "exception_class": exception_class,
    }
    if errno is not None:
        result["errno"] = errno
    if http_status is not None:
        result["http_status"] = http_status
    return result


def _transport_diagnostic(error: LiveTransportError) -> dict[str, object]:
    observed = error.diagnostic
    if observed is None:
        return _diagnostic(
            stage="PROVIDER_DISPATCH",
            code=error.code,
            exception_class="LiveTransportError",
        )
    return _diagnostic(
        stage=observed.stage,
        code=observed.code,
        exception_class=observed.exception_class,
        errno=observed.errno,
        http_status=observed.http_status,
    )


def _put_exact(
    store: RecurringStore,
    *,
    key: str,
    data: bytes,
    kind: str,
    allow_preexisting: bool = False,
) -> Literal["CREATED", "PREEXISTING", "AMBIGUOUS"]:
    result = store.put_if_absent(
        key,
        data,
        metadata={
            "mission_id": MISSION_ID,
            "kind": kind,
            "sha256": hashlib.sha256(data).hexdigest(),
        },
        on_dispatch=lambda: None,
    )
    if result.outcome is ConditionalPutOutcome.AMBIGUOUS:
        return "AMBIGUOUS"
    if result.outcome in {
        ConditionalPutOutcome.PRECONDITION_FAILED,
        ConditionalPutOutcome.CONFLICT,
    }:
        if not allow_preexisting:
            raise RecurringError("RECURRING_IMMUTABLE_WRITE_CONFLICT")
        observed = store.get_object(key)
        if observed is None or observed.data != data:
            raise RecurringError("RECURRING_IMMUTABLE_INTEGRITY_CONFLICT")
        return "PREEXISTING"
    if result.outcome is not ConditionalPutOutcome.CREATED:
        raise RecurringError("RECURRING_IMMUTABLE_WRITE_FAILED")
    observed = store.get_object(key)
    if observed is None or observed.data != data:
        raise RecurringError("RECURRING_R2_READBACK_MISMATCH")
    return "CREATED"


def _entry(*, slot: datetime, requests: int, credits: int, kind: str) -> dict[str, object]:
    return {
        "slot_start_utc": _iso_z(slot),
        "requests": requests,
        "credits": credits,
        "kind": kind,
    }


def _validated_entries(node: Mapping[str, object]) -> list[dict[str, object]]:
    raw = node.get("entries")
    if not isinstance(raw, list) or len(raw) > 400:
        raise RecurringError("RECURRING_ACCOUNTING_NODE_INVALID")
    entries: list[dict[str, object]] = []
    for item in raw:
        if not isinstance(item, dict):
            raise RecurringError("RECURRING_ACCOUNTING_NODE_INVALID")
        stamp = _parse_time(item.get("slot_start_utc"), "RECURRING_ACCOUNTING_NODE_INVALID")
        requests = item.get("requests")
        credits = item.get("credits")
        kind = item.get("kind")
        if (
            isinstance(requests, bool)
            or not isinstance(requests, int)
            or requests < 0
            or isinstance(credits, bool)
            or not isinstance(credits, int)
            or credits < 0
            or not isinstance(kind, str)
            or not kind
        ):
            raise RecurringError("RECURRING_ACCOUNTING_NODE_INVALID")
        entries.append(_entry(slot=stamp, requests=requests, credits=credits, kind=kind))
    return entries


def _validated_accounting_node(node: Mapping[str, object]) -> list[dict[str, object]]:
    entries = _validated_entries(node)
    slot = _parse_time(node.get("slot_start_utc"), "RECURRING_ACCOUNTING_NODE_INVALID")
    lifetime_requests = node.get("lifetime_requests")
    lifetime_credits = node.get("lifetime_credits")
    rolling_24h_requests = node.get("rolling_24h_requests")
    rolling_24h_credits = node.get("rolling_24h_credits")
    rolling_30d_requests = node.get("rolling_30d_requests")
    rolling_30d_credits = node.get("rolling_30d_credits")
    floor = node.get("provider_remaining_floor")
    bound = node.get("credit_bound_valid")
    previous_key = node.get("previous_node_key")
    previous_sha = node.get("previous_node_sha256")
    node_kind = node.get("node_kind")
    slot_state = node.get("slot_state")
    integer_fields = (
        lifetime_requests,
        lifetime_credits,
        rolling_24h_requests,
        rolling_24h_credits,
        rolling_30d_requests,
        rolling_30d_credits,
        floor,
    )
    if (
        node.get("schema_version") != "robin-autonomous-accounting-node-v1"
        or node.get("mission_id") != MISSION_ID
        or not isinstance(node_kind, str)
        or node_kind
        not in {
            "ACCOUNTING_BASELINE",
            "SLOT_RESERVATION",
            "QUOTA_RECONCILIATION",
            "SLOT_CLOSURE",
        }
        or slot_state not in {"OPEN", "CLOSED"}
        or not isinstance(bound, bool)
        or any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in integer_fields
        )
        or cast(int, lifetime_requests) < sum(cast(int, item["requests"]) for item in entries)
        or cast(int, lifetime_credits) < sum(cast(int, item["credits"]) for item in entries)
        or ((previous_key is None) != (previous_sha is None))
        or (
            previous_key is not None
            and (
                not isinstance(previous_key, str)
                or not isinstance(previous_sha, str)
                or re.fullmatch(r"[0-9a-f]{64}", previous_sha) is None
            )
        )
        or not isinstance(node.get("github_run_id"), str)
        or not isinstance(node.get("repository_sha"), str)
    ):
        raise RecurringError("RECURRING_ACCOUNTING_NODE_INVALID")
    expected_24h = _window_totals(entries, slot, timedelta(hours=24))
    expected_30d = _window_totals(entries, slot, timedelta(days=30))
    if expected_24h != (rolling_24h_requests, rolling_24h_credits) or expected_30d != (
        rolling_30d_requests,
        rolling_30d_credits,
    ):
        raise RecurringError("RECURRING_ACCOUNTING_NODE_INVALID")
    return entries


def _validate_accounting_transition(
    previous: Mapping[str, object], current: Mapping[str, object]
) -> None:
    previous_entries = _validated_accounting_node(previous)
    current_entries = _validated_accounting_node(current)
    previous_slot = _parse_time(previous.get("slot_start_utc"), "RECURRING_ACCOUNTING_NODE_INVALID")
    current_slot = _parse_time(current.get("slot_start_utc"), "RECURRING_ACCOUNTING_NODE_INVALID")
    kind = current.get("node_kind")
    if kind == "SLOT_RESERVATION":
        retained = [
            item
            for item in previous_entries
            if _parse_time(item["slot_start_utc"], "RECURRING_ACCOUNTING_NODE_INVALID")
            > current_slot - timedelta(days=30)
        ]
        expected_entries = retained + [
            _entry(
                slot=current_slot,
                requests=SLOT_REQUESTS,
                credits=SLOT_CREDITS,
                kind="SCHEDULED_SLOT_RESERVATION",
            )
        ]
        valid = (
            current_slot > previous_slot
            and previous.get("slot_state") == "CLOSED"
            and previous.get("credit_bound_valid") is True
            and current.get("slot_state") == "OPEN"
            and current.get("credit_bound_valid") is True
            and current_entries == expected_entries
            and current.get("lifetime_requests")
            == cast(int, previous["lifetime_requests"]) + SLOT_REQUESTS
            and current.get("lifetime_credits")
            == cast(int, previous["lifetime_credits"]) + SLOT_CREDITS
            and current.get("provider_remaining_floor")
            == cast(int, previous["provider_remaining_floor"]) - SLOT_CREDITS
        )
    elif kind == "QUOTA_RECONCILIATION":
        observed = current.get("provider_observed_remaining_floor")
        expected_floor = (
            min(cast(int, previous["provider_remaining_floor"]), observed)
            if isinstance(observed, int) and not isinstance(observed, bool)
            else previous["provider_remaining_floor"]
        )
        valid = (
            current_slot == previous_slot
            and previous.get("slot_state") == "OPEN"
            and current.get("slot_state") == "OPEN"
            and current_entries == previous_entries
            and current.get("lifetime_requests") == previous.get("lifetime_requests")
            and current.get("lifetime_credits") == previous.get("lifetime_credits")
            and current.get("rolling_24h_requests") == previous.get("rolling_24h_requests")
            and current.get("rolling_24h_credits") == previous.get("rolling_24h_credits")
            and current.get("rolling_30d_requests") == previous.get("rolling_30d_requests")
            and current.get("rolling_30d_credits") == previous.get("rolling_30d_credits")
            and current.get("provider_remaining_floor") == expected_floor
            and not (
                previous.get("credit_bound_valid") is False
                and current.get("credit_bound_valid") is True
            )
        )
    elif kind == "SLOT_CLOSURE":
        valid = (
            current_slot == previous_slot
            and previous.get("slot_state") == "OPEN"
            and current.get("slot_state") == "CLOSED"
            and current_entries == previous_entries
            and all(
                current.get(field) == previous.get(field)
                for field in (
                    "lifetime_requests",
                    "lifetime_credits",
                    "rolling_24h_requests",
                    "rolling_24h_credits",
                    "rolling_30d_requests",
                    "rolling_30d_credits",
                    "provider_remaining_floor",
                    "credit_bound_valid",
                )
            )
            and isinstance(current.get("report_key"), str)
            and isinstance(current.get("report_sha256"), str)
            and re.fullmatch(r"[0-9a-f]{64}", cast(str, current["report_sha256"])) is not None
        )
    else:
        valid = False
    if not valid:
        raise RecurringError("RECURRING_ACCOUNTING_TRANSITION_INVALID")


def _initialization_marker(*, root_node_key: str, root_node_sha256: str) -> bytes:
    return canonical_json_bytes(
        {
            "schema_version": "robin-autonomous-accounting-initialized-v1",
            "mission_id": MISSION_ID,
            "root_node_key": root_node_key,
            "root_node_sha256": root_node_sha256,
        }
    )


def _is_initial_reservation(node: Mapping[str, object]) -> bool:
    slot = _parse_time(node.get("slot_start_utc"), "RECURRING_ACCOUNTING_NODE_INVALID")
    entries = [
        _entry(
            slot=HISTORICAL_SEED_AT,
            requests=HISTORICAL_REQUESTS,
            credits=HISTORICAL_CREDITS,
            kind="HISTORICAL_RUN_37153158456_AND_PRIOR_RESERVE",
        )
    ]
    entries = [
        item
        for item in entries
        if _parse_time(item["slot_start_utc"], "RECURRING_ACCOUNTING_NODE_INVALID")
        > slot - timedelta(days=30)
    ]
    entries.append(
        _entry(
            slot=slot,
            requests=SLOT_REQUESTS,
            credits=SLOT_CREDITS,
            kind="SCHEDULED_SLOT_RESERVATION",
        )
    )
    return (
        node.get("node_kind") == "SLOT_RESERVATION"
        and node.get("slot_state") == "OPEN"
        and node.get("previous_node_key") is None
        and node.get("previous_node_sha256") is None
        and _validated_entries(node) == entries
        and node.get("lifetime_requests") == HISTORICAL_REQUESTS + SLOT_REQUESTS
        and node.get("lifetime_credits") == HISTORICAL_CREDITS + SLOT_CREDITS
        and node.get("provider_remaining_floor") == HISTORICAL_PROVIDER_REMAINING - SLOT_CREDITS
        and node.get("credit_bound_valid") is True
    )


def _ensure_initialization_marker(
    store: RecurringStore,
    *,
    root_node_key: str,
    root_node_sha256: str,
    root_node: Mapping[str, object],
) -> None:
    observed_marker = store.get_object(ACCOUNTING_INITIALIZED_KEY)
    if observed_marker is None:
        if not _is_initial_reservation(root_node):
            raise RecurringError("RECURRING_ACCOUNTING_INITIALIZATION_MARKER_MISSING")
        marker_bytes = _initialization_marker(
            root_node_key=root_node_key, root_node_sha256=root_node_sha256
        )
        outcome = _put_exact(
            store,
            key=ACCOUNTING_INITIALIZED_KEY,
            data=marker_bytes,
            kind="accounting-initialization-marker",
            allow_preexisting=True,
        )
        if outcome == "AMBIGUOUS":
            raise RecurringError("RECURRING_ACCOUNTING_INITIALIZATION_AMBIGUOUS")
        observed_marker = store.get_object(ACCOUNTING_INITIALIZED_KEY)
    if observed_marker is None:
        raise RecurringError("RECURRING_ACCOUNTING_INITIALIZATION_MARKER_MISSING")
    marker_data = _mapping(
        observed_marker.data, "RECURRING_ACCOUNTING_INITIALIZATION_MARKER_INVALID"
    )
    marker_key = marker_data.get("root_node_key")
    marker_sha = marker_data.get("root_node_sha256")
    if (
        marker_data.get("schema_version") != "robin-autonomous-accounting-initialized-v1"
        or marker_data.get("mission_id") != MISSION_ID
        or not isinstance(marker_key, str)
        or not isinstance(marker_sha, str)
        or re.fullmatch(r"[0-9a-f]{64}", marker_sha) is None
    ):
        raise RecurringError("RECURRING_ACCOUNTING_INITIALIZATION_MARKER_INVALID")
    if root_node.get("previous_node_key") is None and (
        marker_key != root_node_key or marker_sha != root_node_sha256
    ):
        raise RecurringError("RECURRING_ACCOUNTING_ROOT_MISMATCH")
    root = store.get_object(marker_key)
    if root is None:
        raise RecurringError("RECURRING_ACCOUNTING_ROOT_MISSING")
    if hashlib.sha256(root.data).hexdigest() != marker_sha:
        raise RecurringError("RECURRING_ACCOUNTING_ROOT_MISMATCH")
    decoded_root = _mapping(root.data, "RECURRING_ACCOUNTING_NODE_INVALID")
    _validated_accounting_node(decoded_root)
    if (
        decoded_root.get("previous_node_key") is not None
        or decoded_root.get("previous_node_sha256") is not None
    ):
        raise RecurringError("RECURRING_ACCOUNTING_ROOT_INVALID")


def _load_accounting(
    store: RecurringStore,
) -> tuple[LatestProjection | None, Mapping[str, object] | None]:
    head = store.get_latest_projection(ACCOUNTING_HEAD_KEY)
    if head is None:
        if store.get_object(ACCOUNTING_INITIALIZED_KEY) is not None:
            raise RecurringError("RECURRING_ACCOUNTING_HEAD_MISSING_AFTER_INITIALIZATION")
        return None, None
    decoded_head = _mapping(head.data, "RECURRING_ACCOUNTING_HEAD_INVALID")
    node_key = decoded_head.get("node_key")
    node_sha = decoded_head.get("node_sha256")
    if (
        decoded_head.get("schema_version") != "robin-autonomous-accounting-head-v1"
        or decoded_head.get("mission_id") != MISSION_ID
        or not isinstance(node_key, str)
        or not isinstance(node_sha, str)
        or re.fullmatch(r"[0-9a-f]{64}", node_sha) is None
    ):
        raise RecurringError("RECURRING_ACCOUNTING_HEAD_INVALID")
    observed = store.get_object(node_key)
    if observed is None:
        raise RecurringError("RECURRING_ACCOUNTING_PREDECESSOR_MISSING")
    if hashlib.sha256(observed.data).hexdigest() != node_sha:
        raise RecurringError("RECURRING_ACCOUNTING_PREDECESSOR_MISMATCH")
    node = _mapping(observed.data, "RECURRING_ACCOUNTING_NODE_INVALID")
    _validated_accounting_node(node)
    lifetime_requests = node.get("lifetime_requests")
    lifetime_credits = node.get("lifetime_credits")
    floor = node.get("provider_remaining_floor")
    credit_bound_valid = node.get("credit_bound_valid")
    slot_state = node.get("slot_state")
    if (
        decoded_head.get("slot_start_utc") != node.get("slot_start_utc")
        or decoded_head.get("lifetime_requests") != lifetime_requests
        or decoded_head.get("lifetime_credits") != lifetime_credits
        or decoded_head.get("provider_remaining_floor") != floor
        or decoded_head.get("credit_bound_valid") != credit_bound_valid
        or decoded_head.get("slot_state") != slot_state
    ):
        raise RecurringError("RECURRING_ACCOUNTING_NODE_INVALID")
    root_key = node_key
    root_sha = node_sha
    root_node = node
    visited = {node_key}
    while isinstance(root_node.get("previous_node_key"), str):
        if len(visited) >= MAX_ACCOUNTING_CHAIN_NODES:
            raise RecurringError("RECURRING_ACCOUNTING_CHAIN_LIMIT")
        previous_key = cast(str, root_node["previous_node_key"])
        previous_sha = root_node.get("previous_node_sha256")
        if (
            previous_key in visited
            or not isinstance(previous_sha, str)
            or re.fullmatch(r"[0-9a-f]{64}", previous_sha) is None
        ):
            raise RecurringError("RECURRING_ACCOUNTING_PREDECESSOR_INVALID")
        predecessor = store.get_object(previous_key)
        if predecessor is None:
            raise RecurringError("RECURRING_ACCOUNTING_PREDECESSOR_MISSING")
        if hashlib.sha256(predecessor.data).hexdigest() != previous_sha:
            raise RecurringError("RECURRING_ACCOUNTING_PREDECESSOR_MISMATCH")
        previous_node = _mapping(predecessor.data, "RECURRING_ACCOUNTING_PREDECESSOR_INVALID")
        _validate_accounting_transition(previous_node, root_node)
        visited.add(previous_key)
        root_key = previous_key
        root_sha = previous_sha
        root_node = previous_node
    _ensure_initialization_marker(
        store,
        root_node_key=root_key,
        root_node_sha256=root_sha,
        root_node=root_node,
    )
    if node.get("node_kind") == "SLOT_CLOSURE":
        report_key = node.get("report_key")
        report_sha = node.get("report_sha256")
        if not isinstance(report_key, str) or not isinstance(report_sha, str):
            raise RecurringError("RECURRING_ACCOUNTING_CLOSURE_INVALID")
        report = store.get_object(report_key)
        if report is None or hashlib.sha256(report.data).hexdigest() != report_sha:
            raise RecurringError("RECURRING_ACCOUNTING_CLOSURE_REPORT_INVALID")
    return head, node


def _window_totals(
    entries: list[dict[str, object]], now: datetime, window: timedelta
) -> tuple[int, int]:
    threshold = now - window
    active = [
        item
        for item in entries
        if threshold
        < _parse_time(item["slot_start_utc"], "RECURRING_ACCOUNTING_NODE_INVALID")
        <= now
    ]
    return (
        sum(cast(int, item["requests"]) for item in active),
        sum(cast(int, item["credits"]) for item in active),
    )


def _reserve_accounting_slot(
    config: RecurringConfig,
    *,
    store: RecurringStore,
    slot: datetime,
) -> _Admission:
    for attempt in range(1, MAX_CAS_ATTEMPTS + 1):
        head, previous = _load_accounting(store)
        if previous is None:
            entries = [
                _entry(
                    slot=HISTORICAL_SEED_AT,
                    requests=HISTORICAL_REQUESTS,
                    credits=HISTORICAL_CREDITS,
                    kind="HISTORICAL_RUN_37153158456_AND_PRIOR_RESERVE",
                )
            ]
            lifetime_requests = HISTORICAL_REQUESTS
            lifetime_credits = HISTORICAL_CREDITS
            provider_floor = HISTORICAL_PROVIDER_REMAINING
            previous_key = None
            previous_sha = None
        else:
            entries = _validated_entries(previous)
            lifetime_requests = cast(int, previous["lifetime_requests"])
            lifetime_credits = cast(int, previous["lifetime_credits"])
            provider_floor = cast(int, previous["provider_remaining_floor"])
            decoded_head = _mapping(
                cast(LatestProjection, head).data,
                "RECURRING_ACCOUNTING_HEAD_INVALID",
            )
            previous_key = cast(str, decoded_head["node_key"])
            previous_sha = cast(str, decoded_head["node_sha256"])

        slot_stamp = _iso_z(slot)
        if previous is not None:
            previous_slot = _parse_time(
                previous.get("slot_start_utc"), "RECURRING_ACCOUNTING_NODE_INVALID"
            )
            if previous_slot > slot:
                raise RecurringError("RECURRING_ACCOUNTING_SLOT_REGRESSION")
            if previous_slot == slot:
                reservations = [
                    item
                    for item in entries
                    if item["slot_start_utc"] == slot_stamp
                    and item["kind"] == "SCHEDULED_SLOT_RESERVATION"
                    and item["requests"] == SLOT_REQUESTS
                    and item["credits"] == SLOT_CREDITS
                ]
                if len(reservations) != 1:
                    raise RecurringError("RECURRING_ACCOUNTING_RESUME_INVALID")
                return _Admission(
                    node_key=cast(str, previous_key),
                    node_sha256=cast(str, previous_sha),
                    node=previous,
                    resumed=True,
                )
            if previous.get("slot_state") != "CLOSED":
                raise RecurringError("RECURRING_ACCOUNTING_PREVIOUS_SLOT_OPEN")
            if previous.get("credit_bound_valid") is not True:
                raise RecurringError("RECURRING_CREDIT_BOUND_UNVERIFIED")
        if any(item["slot_start_utc"] == slot_stamp for item in entries):
            raise RecurringError("RECURRING_ACCOUNTING_SLOT_CONFLICT")
        entries = [
            item
            for item in entries
            if _parse_time(item["slot_start_utc"], "RECURRING_ACCOUNTING_NODE_INVALID")
            > slot - timedelta(days=30)
        ]
        candidate_entries = entries + [
            _entry(
                slot=slot,
                requests=SLOT_REQUESTS,
                credits=SLOT_CREDITS,
                kind="SCHEDULED_SLOT_RESERVATION",
            )
        ]
        requests_24h, credits_24h = _window_totals(candidate_entries, slot, timedelta(hours=24))
        requests_30d, credits_30d = _window_totals(candidate_entries, slot, timedelta(days=30))
        if requests_24h > ROLLING_24H_REQUEST_MAX or credits_24h > ROLLING_24H_CREDIT_MAX:
            raise RecurringError("RECURRING_ROLLING_24H_LIMIT")
        if requests_30d > ROLLING_30D_REQUEST_MAX or credits_30d > ROLLING_30D_CREDIT_MAX:
            raise RecurringError("RECURRING_ROLLING_30D_LIMIT")
        if provider_floor < SLOT_CREDITS:
            raise RecurringError("RECURRING_PROVIDER_BALANCE_INSUFFICIENT")

        node_key = (
            f"{OBJECT_PREFIX}/accounting/nodes/{_slot_id(slot)}/"
            f"{config.github_run_id}-cas-{attempt}.json"
        )
        node: dict[str, object] = {
            "schema_version": "robin-autonomous-accounting-node-v1",
            "mission_id": MISSION_ID,
            "node_kind": "SLOT_RESERVATION",
            "slot_state": "OPEN",
            "slot_start_utc": slot_stamp,
            "github_run_id": config.github_run_id,
            "repository_sha": config.repository_sha,
            "previous_node_key": previous_key,
            "previous_node_sha256": previous_sha,
            "previous_head_etag": head.etag if head is not None else None,
            "entries": candidate_entries,
            "lifetime_requests": lifetime_requests + SLOT_REQUESTS,
            "lifetime_credits": lifetime_credits + SLOT_CREDITS,
            "rolling_24h_requests": requests_24h,
            "rolling_24h_credits": credits_24h,
            "rolling_30d_requests": requests_30d,
            "rolling_30d_credits": credits_30d,
            "provider_remaining_floor": provider_floor - SLOT_CREDITS,
            "credit_bound_valid": True,
        }
        node_bytes = canonical_json_bytes(node)
        node_sha = hashlib.sha256(node_bytes).hexdigest()
        outcome = _put_exact(
            store,
            key=node_key,
            data=node_bytes,
            kind="accounting-node",
            allow_preexisting=True,
        )
        if outcome == "AMBIGUOUS":
            raise RecurringError("RECURRING_ACCOUNTING_NODE_AMBIGUOUS")
        head_bytes = canonical_json_bytes(
            {
                "schema_version": "robin-autonomous-accounting-head-v1",
                "mission_id": MISSION_ID,
                "node_key": node_key,
                "node_sha256": node_sha,
                "slot_start_utc": slot_stamp,
                "lifetime_requests": node["lifetime_requests"],
                "lifetime_credits": node["lifetime_credits"],
                "provider_remaining_floor": node["provider_remaining_floor"],
                "credit_bound_valid": node["credit_bound_valid"],
                "slot_state": node["slot_state"],
            }
        )
        result = store.put_latest_projection(
            ACCOUNTING_HEAD_KEY,
            head_bytes,
            metadata={"mission_id": MISSION_ID, "kind": "accounting-head"},
            expected_etag=head.etag if head is not None else None,
            on_dispatch=lambda: None,
        )
        if result.outcome is ConditionalPutOutcome.CREATED:
            _, verified = _load_accounting(store)
            if verified is None:
                raise RecurringError("RECURRING_ACCOUNTING_HEAD_INVALID")
            return _Admission(node_key=node_key, node_sha256=node_sha, node=verified)
        if result.outcome not in {
            ConditionalPutOutcome.CONFLICT,
            ConditionalPutOutcome.PRECONDITION_FAILED,
        }:
            raise RecurringError("RECURRING_ACCOUNTING_HEAD_AMBIGUOUS")
    raise RecurringError("RECURRING_ACCOUNTING_CAS_EXHAUSTED")


def _reconcile_accounting(
    config: RecurringConfig,
    *,
    store: RecurringStore,
    slot: datetime,
    observed_remaining: int | None,
    credit_bound_valid: bool,
) -> _Admission:
    """Lower the durable provider floor or close future admission after ambiguity."""

    for attempt in range(1, MAX_CAS_ATTEMPTS + 1):
        head, previous = _load_accounting(store)
        if head is None or previous is None:
            raise RecurringError("RECURRING_ACCOUNTING_RECONCILIATION_INVALID")
        head_slot = _parse_time(previous.get("slot_start_utc"), "RECURRING_ACCOUNTING_NODE_INVALID")
        if head_slot != slot:
            raise RecurringError("RECURRING_ACCOUNTING_RECONCILIATION_RACE")
        if previous.get("slot_state") != "OPEN":
            raise RecurringError("RECURRING_ACCOUNTING_RECONCILIATION_CLOSED")
        current_floor = cast(int, previous["provider_remaining_floor"])
        target_floor = (
            min(current_floor, observed_remaining)
            if observed_remaining is not None
            else current_floor
        )
        target_bound = cast(bool, previous["credit_bound_valid"]) and credit_bound_valid
        decoded_head = _mapping(head.data, "RECURRING_ACCOUNTING_HEAD_INVALID")
        previous_key = cast(str, decoded_head["node_key"])
        previous_sha = cast(str, decoded_head["node_sha256"])
        if target_floor == current_floor and target_bound == bool(
            previous.get("credit_bound_valid", True)
        ):
            return _Admission(
                node_key=previous_key,
                node_sha256=previous_sha,
                node=previous,
                resumed=True,
            )
        node: dict[str, object] = {
            "schema_version": "robin-autonomous-accounting-node-v1",
            "mission_id": MISSION_ID,
            "node_kind": "QUOTA_RECONCILIATION",
            "slot_state": "OPEN",
            "slot_start_utc": previous["slot_start_utc"],
            "github_run_id": config.github_run_id,
            "repository_sha": config.repository_sha,
            "previous_node_key": previous_key,
            "previous_node_sha256": previous_sha,
            "previous_head_etag": head.etag,
            "reservation_node_key": (previous.get("reservation_node_key") or previous_key),
            "entries": _validated_entries(previous),
            "lifetime_requests": previous["lifetime_requests"],
            "lifetime_credits": previous["lifetime_credits"],
            "rolling_24h_requests": previous["rolling_24h_requests"],
            "rolling_24h_credits": previous["rolling_24h_credits"],
            "rolling_30d_requests": previous["rolling_30d_requests"],
            "rolling_30d_credits": previous["rolling_30d_credits"],
            "provider_remaining_floor": target_floor,
            "provider_observed_remaining_floor": observed_remaining,
            "provider_remaining_floor_source": (
                "PROVIDER_HEADER_MINIMUM" if observed_remaining is not None else "SLOT_RESERVATION"
            ),
            "credit_bound_valid": target_bound,
        }
        node_bytes = canonical_json_bytes(node)
        node_sha = hashlib.sha256(node_bytes).hexdigest()
        node_key = (
            f"{OBJECT_PREFIX}/accounting/reconciliations/{_slot_id(slot)}/"
            f"{config.github_run_id}-{target_floor}-{int(target_bound)}-cas-{attempt}.json"
        )
        outcome = _put_exact(
            store,
            key=node_key,
            data=node_bytes,
            kind="accounting-reconciliation",
            allow_preexisting=True,
        )
        if outcome == "AMBIGUOUS":
            raise RecurringError("RECURRING_ACCOUNTING_RECONCILIATION_AMBIGUOUS")
        head_bytes = canonical_json_bytes(
            {
                "schema_version": "robin-autonomous-accounting-head-v1",
                "mission_id": MISSION_ID,
                "node_key": node_key,
                "node_sha256": node_sha,
                "slot_start_utc": previous["slot_start_utc"],
                "lifetime_requests": node["lifetime_requests"],
                "lifetime_credits": node["lifetime_credits"],
                "provider_remaining_floor": target_floor,
                "credit_bound_valid": target_bound,
                "slot_state": "OPEN",
            }
        )
        result = store.put_latest_projection(
            ACCOUNTING_HEAD_KEY,
            head_bytes,
            metadata={"mission_id": MISSION_ID, "kind": "accounting-head"},
            expected_etag=head.etag,
            on_dispatch=lambda: None,
        )
        if result.outcome is ConditionalPutOutcome.CREATED:
            _, verified = _load_accounting(store)
            if verified is None:
                raise RecurringError("RECURRING_ACCOUNTING_RECONCILIATION_INVALID")
            return _Admission(node_key=node_key, node_sha256=node_sha, node=verified)
        if result.outcome not in {
            ConditionalPutOutcome.AMBIGUOUS,
            ConditionalPutOutcome.CONFLICT,
            ConditionalPutOutcome.PRECONDITION_FAILED,
        }:
            raise RecurringError("RECURRING_ACCOUNTING_RECONCILIATION_AMBIGUOUS")
    raise RecurringError("RECURRING_ACCOUNTING_RECONCILIATION_CAS_EXHAUSTED")


def _close_accounting_slot(
    config: RecurringConfig,
    *,
    store: RecurringStore,
    slot: datetime,
    report_key: str,
    report_sha256: str,
) -> _Admission:
    """Close one admitted slot only after its immutable report is verified."""

    report = store.get_object(report_key)
    if (
        report is None
        or re.fullmatch(r"[0-9a-f]{64}", report_sha256) is None
        or hashlib.sha256(report.data).hexdigest() != report_sha256
    ):
        raise RecurringError("RECURRING_ACCOUNTING_CLOSURE_REPORT_INVALID")
    for attempt in range(1, MAX_CAS_ATTEMPTS + 1):
        head, previous = _load_accounting(store)
        if head is None or previous is None:
            raise RecurringError("RECURRING_ACCOUNTING_CLOSURE_INVALID")
        head_slot = _parse_time(previous.get("slot_start_utc"), "RECURRING_ACCOUNTING_NODE_INVALID")
        if head_slot != slot:
            raise RecurringError("RECURRING_ACCOUNTING_CLOSURE_RACE")
        decoded_head = _mapping(head.data, "RECURRING_ACCOUNTING_HEAD_INVALID")
        previous_key = cast(str, decoded_head["node_key"])
        previous_sha = cast(str, decoded_head["node_sha256"])
        if previous.get("slot_state") == "CLOSED":
            if (
                previous.get("node_kind") != "SLOT_CLOSURE"
                or previous.get("report_key") != report_key
                or previous.get("report_sha256") != report_sha256
            ):
                raise RecurringError("RECURRING_ACCOUNTING_CLOSURE_CONFLICT")
            return _Admission(
                node_key=previous_key,
                node_sha256=previous_sha,
                node=previous,
                resumed=True,
            )
        if previous.get("slot_state") != "OPEN":
            raise RecurringError("RECURRING_ACCOUNTING_CLOSURE_INVALID")
        node: dict[str, object] = {
            "schema_version": "robin-autonomous-accounting-node-v1",
            "mission_id": MISSION_ID,
            "node_kind": "SLOT_CLOSURE",
            "slot_state": "CLOSED",
            "slot_start_utc": previous["slot_start_utc"],
            "github_run_id": config.github_run_id,
            "repository_sha": config.repository_sha,
            "previous_node_key": previous_key,
            "previous_node_sha256": previous_sha,
            "previous_head_etag": head.etag,
            "reservation_node_key": previous.get("reservation_node_key") or previous_key,
            "entries": _validated_entries(previous),
            "lifetime_requests": previous["lifetime_requests"],
            "lifetime_credits": previous["lifetime_credits"],
            "rolling_24h_requests": previous["rolling_24h_requests"],
            "rolling_24h_credits": previous["rolling_24h_credits"],
            "rolling_30d_requests": previous["rolling_30d_requests"],
            "rolling_30d_credits": previous["rolling_30d_credits"],
            "provider_remaining_floor": previous["provider_remaining_floor"],
            "credit_bound_valid": previous["credit_bound_valid"],
            "report_key": report_key,
            "report_sha256": report_sha256,
        }
        node_bytes = canonical_json_bytes(node)
        node_sha = hashlib.sha256(node_bytes).hexdigest()
        node_key = (
            f"{OBJECT_PREFIX}/accounting/closures/{_slot_id(slot)}/"
            f"{config.github_run_id}-cas-{attempt}.json"
        )
        outcome = _put_exact(
            store,
            key=node_key,
            data=node_bytes,
            kind="accounting-slot-closure",
            allow_preexisting=True,
        )
        if outcome == "AMBIGUOUS":
            raise RecurringError("RECURRING_ACCOUNTING_CLOSURE_AMBIGUOUS")
        head_bytes = canonical_json_bytes(
            {
                "schema_version": "robin-autonomous-accounting-head-v1",
                "mission_id": MISSION_ID,
                "node_key": node_key,
                "node_sha256": node_sha,
                "slot_start_utc": previous["slot_start_utc"],
                "lifetime_requests": previous["lifetime_requests"],
                "lifetime_credits": previous["lifetime_credits"],
                "provider_remaining_floor": previous["provider_remaining_floor"],
                "credit_bound_valid": previous["credit_bound_valid"],
                "slot_state": "CLOSED",
            }
        )
        result = store.put_latest_projection(
            ACCOUNTING_HEAD_KEY,
            head_bytes,
            metadata={"mission_id": MISSION_ID, "kind": "accounting-head"},
            expected_etag=head.etag,
            on_dispatch=lambda: None,
        )
        if result.outcome is ConditionalPutOutcome.CREATED:
            _, verified = _load_accounting(store)
            if verified is None:
                raise RecurringError("RECURRING_ACCOUNTING_CLOSURE_INVALID")
            return _Admission(node_key=node_key, node_sha256=node_sha, node=verified)
        if result.outcome not in {
            ConditionalPutOutcome.AMBIGUOUS,
            ConditionalPutOutcome.CONFLICT,
            ConditionalPutOutcome.PRECONDITION_FAILED,
        }:
            raise RecurringError("RECURRING_ACCOUNTING_CLOSURE_AMBIGUOUS")
    raise RecurringError("RECURRING_ACCOUNTING_CLOSURE_CAS_EXHAUSTED")


def _branch_stub(
    sport_key: str,
    *,
    source: str,
    diagnostic: Mapping[str, object],
) -> dict[str, object]:
    return {
        "sport_key": sport_key,
        "markets_requested": list(MARKETS),
        "status": "INCOMPLETE",
        "source": source,
        "provider_key": PROVIDER_KEY,
        "settlement_period_key": SETTLEMENT_PERIOD_KEY,
        "acquisition_started_at_utc": None,
        "acquisition_finished_at_utc": None,
        "provider_request_attempted": False,
        "capture_time_utc": None,
        "quota": None,
        "raw_object_key": None,
        "raw_object_sha256": None,
        "readback_verified": False,
        "data_availability": "UNAVAILABLE",
        "row_count": 0,
        "match_count": 0,
        "market_branch_coverage": {"h2h": 0, "totals": 0},
        "limitations": [],
        "diagnostic": dict(diagnostic),
    }


def _raw_envelope(
    config: RecurringConfig,
    *,
    slot: datetime,
    sport_key: str,
    response: LiveTransportResponse,
    quota: Mapping[str, object] | None,
    quota_code: str | None,
    observed_cost: int | None,
    observed_remaining: int | None,
    acquisition_started_at: datetime,
    acquisition_finished_at: datetime,
) -> bytes:
    started = ensure_utc(acquisition_started_at, field="recurring_acquisition_started")
    finished = ensure_utc(acquisition_finished_at, field="recurring_acquisition_finished")
    captured = ensure_utc(response.first_observed_at_utc, field="recurring_capture_time")
    if finished < started or not started <= captured <= finished:
        raise RecurringError("RECURRING_ACQUISITION_TIME_INVALID")
    return canonical_json_bytes(
        {
            "schema_version": "robin-autonomous-raw-envelope-v2",
            "mission_id": MISSION_ID,
            "slot_start_utc": _iso_z(slot),
            "sport_key": sport_key,
            "markets": list(MARKETS),
            "repository_sha": config.repository_sha,
            "github_run_id": config.github_run_id,
            "provider_key": PROVIDER_KEY,
            "settlement_period_key": SETTLEMENT_PERIOD_KEY,
            "acquisition_started_at_utc": _iso_z(started),
            "acquisition_finished_at_utc": _iso_z(finished),
            "capture_time_utc": _iso_z(captured),
            "http_status": response.http_status,
            "quota": dict(quota) if quota is not None else None,
            "quota_diagnostic_code": quota_code,
            "observed_credit_cost": observed_cost,
            "observed_remaining_floor": observed_remaining,
            "transport_accounting": {
                "network_calls": response.network_calls,
                "provider_calls": response.provider_calls,
                "retries": response.retries,
                "redirects": response.redirects,
            },
            "raw_payload_base64": base64.b64encode(response.payload).decode("ascii"),
            "raw_payload_sha256": hashlib.sha256(response.payload).hexdigest(),
            "raw_payload_bytes": len(response.payload),
        }
    )


def _payload_from_readback(
    data: bytes, *, slot: datetime, sport_key: str
) -> tuple[
    bytes,
    datetime,
    int,
    _Quota | None,
    str | None,
    int | None,
    int | None,
    str | None,
    str | None,
    datetime | None,
    datetime | None,
]:
    envelope = _mapping(data, "RECURRING_RAW_ENVELOPE_INVALID")
    schema_version = envelope.get("schema_version")
    if (
        schema_version
        not in {"robin-autonomous-raw-envelope-v1", "robin-autonomous-raw-envelope-v2"}
        or envelope.get("mission_id") != MISSION_ID
        or envelope.get("slot_start_utc") != _iso_z(slot)
        or envelope.get("sport_key") != sport_key
        or envelope.get("markets") != list(MARKETS)
    ):
        raise RecurringError("RECURRING_RAW_ENVELOPE_INVALID")
    encoded = envelope.get("raw_payload_base64")
    expected_sha = envelope.get("raw_payload_sha256")
    expected_size = envelope.get("raw_payload_bytes")
    if (
        not isinstance(encoded, str)
        or not isinstance(expected_sha, str)
        or isinstance(expected_size, bool)
        or not isinstance(expected_size, int)
    ):
        raise RecurringError("RECURRING_RAW_ENVELOPE_INVALID")
    try:
        payload = base64.b64decode(encoded, validate=True)
    except ValueError:
        raise RecurringError("RECURRING_RAW_ENVELOPE_INVALID") from None
    if len(payload) != expected_size or hashlib.sha256(payload).hexdigest() != expected_sha:
        raise RecurringError("RECURRING_RAW_ENVELOPE_INTEGRITY_FAILED")
    capture_time = _parse_time(envelope.get("capture_time_utc"), "RECURRING_RAW_ENVELOPE_INVALID")
    status = envelope.get("http_status")
    quota = envelope.get("quota")
    quota_code = envelope.get("quota_diagnostic_code")
    observed_cost = envelope.get("observed_credit_cost")
    observed_remaining = envelope.get("observed_remaining_floor")
    acquisition_started: datetime | None = None
    acquisition_finished: datetime | None = None
    provider_key: str | None = None
    settlement_period_key: str | None = None
    if schema_version == "robin-autonomous-raw-envelope-v2":
        if (
            envelope.get("provider_key") != PROVIDER_KEY
            or envelope.get("settlement_period_key") != SETTLEMENT_PERIOD_KEY
        ):
            raise RecurringError("RECURRING_RAW_ENVELOPE_INVALID")
        acquisition_started = _parse_time(
            envelope.get("acquisition_started_at_utc"), "RECURRING_RAW_ENVELOPE_INVALID"
        )
        acquisition_finished = _parse_time(
            envelope.get("acquisition_finished_at_utc"), "RECURRING_RAW_ENVELOPE_INVALID"
        )
        if (
            acquisition_finished < acquisition_started
            or not acquisition_started <= capture_time <= acquisition_finished
        ):
            raise RecurringError("RECURRING_RAW_ENVELOPE_INVALID")
        provider_key = PROVIDER_KEY
        settlement_period_key = SETTLEMENT_PERIOD_KEY
    if (
        isinstance(status, bool)
        or not isinstance(status, int)
        or (quota is not None and not isinstance(quota, dict))
        or (quota_code is not None and not isinstance(quota_code, str))
        or (
            observed_cost is not None
            and (isinstance(observed_cost, bool) or not isinstance(observed_cost, int))
        )
        or (
            observed_remaining is not None
            and (
                isinstance(observed_remaining, bool)
                or not isinstance(observed_remaining, int)
                or observed_remaining < 0
            )
        )
    ):
        raise RecurringError("RECURRING_RAW_ENVELOPE_INVALID")
    parsed_quota: _Quota | None = None
    if isinstance(quota, dict):
        remaining = quota.get("requests_remaining")
        used = quota.get("requests_used")
        last = quota.get("requests_last")
        if any(
            isinstance(value, bool) or not isinstance(value, int)
            for value in (remaining, used, last)
        ):
            raise RecurringError("RECURRING_RAW_ENVELOPE_INVALID")
        parsed_quota = _Quota(
            remaining=cast(int, remaining),
            used=cast(int, used),
            last=cast(int, last),
            observed_at_utc=_parse_time(
                quota.get("observed_at_utc"), "RECURRING_RAW_ENVELOPE_INVALID"
            ),
        )
    return (
        payload,
        capture_time,
        status,
        parsed_quota,
        quota_code,
        observed_cost,
        observed_remaining,
        provider_key,
        settlement_period_key,
        acquisition_started,
        acquisition_finished,
    )


def _observed_remaining(headers: Mapping[str, str]) -> int | None:
    normalized = {name.casefold(): value for name, value in headers.items()}
    if len(normalized) != len(headers):
        return None
    value = normalized.get("x-requests-remaining")
    if not isinstance(value, str) or not value.isascii() or not value.isdecimal():
        return None
    observed = int(value)
    return observed if observed <= 2**63 - 1 else None


def _attempt_reservation_bytes(config: RecurringConfig, *, slot: datetime, sport_key: str) -> bytes:
    return canonical_json_bytes(
        {
            "schema_version": "robin-autonomous-attempt-reservation-v1",
            "mission_id": MISSION_ID,
            "slot_start_utc": _iso_z(slot),
            "sport_key": sport_key,
            "markets": list(MARKETS),
            "provider_requests_reserved": 1,
            "provider_credits_reserved": 2,
            "github_run_id": config.github_run_id,
            "repository_sha": config.repository_sha,
        }
    )


def _validate_attempt_reservation(
    observed: ObservedObject, *, slot: datetime, sport_key: str
) -> None:
    digest = hashlib.sha256(observed.data).hexdigest()
    reservation = _mapping(observed.data, "RECURRING_ATTEMPT_RESERVATION_INVALID")
    if (
        observed.metadata.get("sha256") != digest
        or reservation.get("schema_version") != "robin-autonomous-attempt-reservation-v1"
        or reservation.get("mission_id") != MISSION_ID
        or reservation.get("slot_start_utc") != _iso_z(slot)
        or reservation.get("sport_key") != sport_key
        or reservation.get("markets") != list(MARKETS)
        or reservation.get("provider_requests_reserved") != 1
        or reservation.get("provider_credits_reserved") != 2
        or not isinstance(reservation.get("github_run_id"), str)
        or re.fullmatch(r"[1-9][0-9]{0,19}", cast(str, reservation["github_run_id"])) is None
        or not isinstance(reservation.get("repository_sha"), str)
        or re.fullmatch(r"[0-9a-f]{40}", cast(str, reservation["repository_sha"])) is None
    ):
        raise RecurringError("RECURRING_ATTEMPT_RESERVATION_INVALID")


def _reserve_attempt(
    config: RecurringConfig,
    *,
    store: RecurringStore,
    key: str,
    slot: datetime,
    sport_key: str,
) -> Literal["CREATED", "PREEXISTING", "AMBIGUOUS"]:
    data = _attempt_reservation_bytes(config, slot=slot, sport_key=sport_key)
    result = store.put_if_absent(
        key,
        data,
        metadata={
            "mission_id": MISSION_ID,
            "kind": "provider-attempt-reservation",
            "sha256": hashlib.sha256(data).hexdigest(),
        },
        on_dispatch=lambda: None,
    )
    if result.outcome is ConditionalPutOutcome.AMBIGUOUS:
        return "AMBIGUOUS"
    if result.outcome in {
        ConditionalPutOutcome.PRECONDITION_FAILED,
        ConditionalPutOutcome.CONFLICT,
    }:
        observed = store.get_object(key)
        if observed is None:
            raise RecurringError("RECURRING_ATTEMPT_RESERVATION_MISSING")
        _validate_attempt_reservation(observed, slot=slot, sport_key=sport_key)
        return "PREEXISTING"
    if result.outcome is not ConditionalPutOutcome.CREATED:
        raise RecurringError("RECURRING_ATTEMPT_RESERVATION_FAILED")
    observed = store.get_object(key)
    if observed is None or observed.data != data:
        raise RecurringError("RECURRING_ATTEMPT_RESERVATION_READBACK_MISMATCH")
    _validate_attempt_reservation(observed, slot=slot, sport_key=sport_key)
    return "CREATED"


def _normalize_raw_branch(
    observed: ObservedObject,
    *,
    slot: datetime,
    sport_key: str,
    raw_key: str,
    source: str,
    provider_request_attempted: bool,
    provider_attempts_new: int,
) -> _BranchOutcome:
    if observed.metadata.get("sha256") != hashlib.sha256(observed.data).hexdigest():
        raise RecurringError("RECURRING_RAW_ENVELOPE_INTEGRITY_FAILED")
    (
        payload,
        capture_time,
        status,
        quota,
        quota_code,
        observed_cost,
        envelope_remaining,
        provider_key,
        settlement_period_key,
        acquisition_started,
        acquisition_finished,
    ) = _payload_from_readback(observed.data, slot=slot, sport_key=sport_key)
    observed_remaining = quota.remaining if quota is not None else envelope_remaining
    credit_bound_valid = quota_code is None and quota is not None and observed_cost == 2
    circuit_code: str | None = None
    if quota_code is not None:
        circuit_code = quota_code
    elif quota is None:
        circuit_code = "RECURRING_QUOTA_INVALID"
    elif observed_cost != 2:
        circuit_code = "RECURRING_CREDIT_COST_INVALID"
    elif quota.remaining < 2:
        circuit_code = "RECURRING_PROVIDER_BALANCE_INSUFFICIENT"
    branch_base: dict[str, object] = {
        "sport_key": sport_key,
        "markets_requested": list(MARKETS),
        "source": source,
        "provider_key": provider_key,
        "settlement_period_key": settlement_period_key,
        "acquisition_started_at_utc": (
            _iso_z(acquisition_started) if acquisition_started is not None else None
        ),
        "acquisition_finished_at_utc": (
            _iso_z(acquisition_finished) if acquisition_finished is not None else None
        ),
        "provider_request_attempted": provider_request_attempted,
        "capture_time_utc": _iso_z(capture_time),
        "quota": quota.as_dict() if quota is not None else None,
        "raw_object_key": raw_key,
        "raw_object_sha256": hashlib.sha256(observed.data).hexdigest(),
        "readback_verified": True,
        "data_availability": "UNAVAILABLE",
    }
    if quota_code is not None or quota is None or observed_cost != 2 or status != 200:
        code = quota_code or "RECURRING_PROVIDER_HTTP_STATUS"
        branch_base.update(
            {
                "status": "INCOMPLETE",
                "row_count": 0,
                "match_count": 0,
                "market_branch_coverage": {"h2h": 0, "totals": 0},
                "limitations": [],
                "diagnostic": _diagnostic(
                    stage="RESPONSE_VALIDATE",
                    code=code,
                    exception_class="RecurringError",
                    http_status=status,
                ),
            }
        )
        return _BranchOutcome(
            branch=branch_base,
            rows=(),
            provider_attempts=provider_attempts_new,
            circuit_code=circuit_code,
            observed_remaining=observed_remaining,
            credit_bound_valid=credit_bound_valid,
        )
    if quota is None:
        raise RecurringError("RECURRING_QUOTA_INVALID")
    try:
        normalized_rows, limitations = _normalize_payload(
            payload,
            cycle_index=1,
            sport_key=sport_key,
            capture_time=capture_time,
            quota=quota,
        )
    except Exception as error:
        code = getattr(error, "code", "RECURRING_NORMALIZATION_FAILED")
        branch_base.update(
            {
                "status": "INCOMPLETE",
                "row_count": 0,
                "match_count": 0,
                "market_branch_coverage": {"h2h": 0, "totals": 0},
                "limitations": [],
                "diagnostic": _diagnostic(
                    stage="OFFLINE_REPLAY",
                    code=code if isinstance(code, str) else "RECURRING_NORMALIZATION_FAILED",
                    exception_class="ResultError",
                    http_status=status,
                ),
            }
        )
        return _BranchOutcome(
            branch=branch_base,
            rows=(),
            provider_attempts=provider_attempts_new,
            circuit_code=circuit_code,
            observed_remaining=observed_remaining,
            credit_bound_valid=credit_bound_valid,
        )
    rows = tuple(
        dict(row)
        | {
            "slot_start_utc": _iso_z(slot),
            "provider_key": provider_key,
            "settlement_period_key": settlement_period_key,
            "acquisition_started_at_utc": (
                _iso_z(acquisition_started) if acquisition_started is not None else None
            ),
            "acquisition_finished_at_utc": (
                _iso_z(acquisition_finished) if acquisition_finished is not None else None
            ),
        }
        for row in normalized_rows
    )
    branch_base.update(
        {
            "status": "COMPLETE" if not limitations else "PARTIAL",
            "data_availability": ("VERIFIED_WITH_ROWS" if rows else "VERIFIED_EMPTY"),
            "row_count": len(rows),
            "match_count": len({row["event_id"] for row in rows}),
            "market_branch_coverage": {
                market: int(any(row["market_key"] == market for row in rows)) for market in MARKETS
            },
            "limitations": list(limitations),
            "diagnostic": None,
        }
    )
    return _BranchOutcome(
        branch=branch_base,
        rows=rows,
        provider_attempts=provider_attempts_new,
        circuit_code=circuit_code,
        observed_remaining=observed_remaining,
        credit_bound_valid=credit_bound_valid,
    )


def _run_branch(
    config: RecurringConfig,
    *,
    slot: datetime,
    sport_key: str,
    store: RecurringStore,
    transport_factory: TransportFactory,
    clock: Callable[[], datetime],
    provider_resolution: Callable[[], NetworkResolution],
    provider_secret: Callable[[], str],
    circuit_code: str | None,
    allow_provider_dispatch: bool,
) -> _BranchOutcome:
    prefix = f"{OBJECT_PREFIX}/slots/{_slot_id(slot)}/{sport_key}"
    reservation_key = f"{prefix}/attempt-reservation.json"
    raw_key = f"{prefix}/raw-envelope.json"
    prior_reservation = store.get_object(reservation_key)
    prior_raw = store.get_object(raw_key)
    if prior_raw is not None and prior_reservation is None:
        raise RecurringError("RECURRING_RAW_WITHOUT_RESERVATION")
    if prior_reservation is not None:
        _validate_attempt_reservation(prior_reservation, slot=slot, sport_key=sport_key)
        if prior_raw is not None:
            return _normalize_raw_branch(
                prior_raw,
                slot=slot,
                sport_key=sport_key,
                raw_key=raw_key,
                source="RECOVERED_R2_CAPTURE",
                provider_request_attempted=True,
                provider_attempts_new=0,
            )
        return _BranchOutcome(
            branch=_branch_stub(
                sport_key,
                source="PRIOR_ATTEMPT_NOT_RETRIED",
                diagnostic=_diagnostic(
                    stage="ATTEMPT_RECOVERY",
                    code="RECURRING_PRIOR_ATTEMPT_NOT_RETRIED",
                    exception_class="RecurringError",
                ),
            ),
            rows=(),
            provider_attempts=0,
            circuit_code="RECURRING_PRIOR_ATTEMPT_ACCOUNTING_UNVERIFIED",
            credit_bound_valid=False,
        )
    if circuit_code is not None:
        return _BranchOutcome(
            branch=_branch_stub(
                sport_key,
                source="PROVIDER_CIRCUIT_OPEN",
                diagnostic=_diagnostic(
                    stage="PROVIDER_CIRCUIT",
                    code=circuit_code,
                    exception_class="RecurringError",
                ),
            ),
            rows=(),
            provider_attempts=0,
            circuit_code=circuit_code,
        )
    if not allow_provider_dispatch:
        return _BranchOutcome(
            branch=_branch_stub(
                sport_key,
                source="MISSED_OPEN_SLOT_NOT_BACKFILLED",
                diagnostic=_diagnostic(
                    stage="ATTEMPT_RECOVERY",
                    code="RECURRING_MISSED_OPEN_SLOT_NOT_BACKFILLED",
                    exception_class="RecurringError",
                ),
            ),
            rows=(),
            provider_attempts=0,
        )
    reservation_outcome = _reserve_attempt(
        config,
        store=store,
        key=reservation_key,
        slot=slot,
        sport_key=sport_key,
    )
    if reservation_outcome == "AMBIGUOUS":
        return _BranchOutcome(
            branch=_branch_stub(
                sport_key,
                source="ATTEMPT_RESERVATION_AMBIGUOUS",
                diagnostic=_diagnostic(
                    stage="ATTEMPT_RESERVATION",
                    code="RECURRING_ATTEMPT_RESERVATION_AMBIGUOUS",
                    exception_class="RecurringError",
                ),
            ),
            rows=(),
            provider_attempts=0,
        )
    if reservation_outcome == "PREEXISTING":
        observed = store.get_object(raw_key)
        if observed is not None:
            return _normalize_raw_branch(
                observed,
                slot=slot,
                sport_key=sport_key,
                raw_key=raw_key,
                source="RECOVERED_R2_CAPTURE",
                provider_request_attempted=True,
                provider_attempts_new=0,
            )
        return _BranchOutcome(
            branch=_branch_stub(
                sport_key,
                source="PRIOR_ATTEMPT_NOT_RETRIED",
                diagnostic=_diagnostic(
                    stage="ATTEMPT_RECOVERY",
                    code="RECURRING_PRIOR_ATTEMPT_NOT_RETRIED",
                    exception_class="RecurringError",
                ),
            ),
            rows=(),
            provider_attempts=0,
            circuit_code="RECURRING_PRIOR_ATTEMPT_ACCOUNTING_UNVERIFIED",
            credit_bound_valid=False,
        )
    try:
        resolution = provider_resolution()
    except RecurringError as error:
        return _BranchOutcome(
            branch=_branch_stub(
                sport_key,
                source="PROVIDER_ACCESS_FAILURE",
                diagnostic=_diagnostic(
                    stage="DNS_RESOLUTION",
                    code=error.code,
                    exception_class="RecurringError",
                ),
            ),
            rows=(),
            provider_attempts=0,
        )
    request = PublicProviderRequestV1.from_spec(
        ProviderRequestSpec(
            endpoint=f"/v4/sports/{sport_key}/odds",
            sport_key=sport_key,
            region=REGION,
            markets=MARKETS,
            timeout_seconds=20,
        ),
        maximum_response_bytes=MAX_RESPONSE_BYTES,
        approved_provider_ip_address=resolution.selected_ip_address,
    )
    transport = transport_factory(clock)
    try:
        transport.preflight(request)
    except LiveTransportError as error:
        return _BranchOutcome(
            branch=_branch_stub(
                sport_key,
                source="LOCAL_PREFLIGHT_FAILURE",
                diagnostic=_diagnostic(
                    stage="TRANSPORT_PREFLIGHT",
                    code=error.code,
                    exception_class="LiveTransportError",
                ),
            ),
            rows=(),
            provider_attempts=0,
        )
    acquisition_started_at: datetime | None = None
    try:
        api_key = provider_secret()
        acquisition_started_at = ensure_utc(clock(), field="recurring_acquisition_started")
        response = transport.dispatch(request, api_key=api_key)
    except RecurringError as error:
        return _BranchOutcome(
            branch=_branch_stub(
                sport_key,
                source="PROVIDER_ACCESS_FAILURE",
                diagnostic=_diagnostic(
                    stage="PROVIDER_SECRET",
                    code=error.code,
                    exception_class="RecurringError",
                ),
            ),
            rows=(),
            provider_attempts=0,
        )
    except LiveTransportError as error:
        acquisition_finished_at = ensure_utc(clock(), field="recurring_acquisition_finished")
        branch = _branch_stub(
            sport_key,
            source="LIVE_PROVIDER_FAILURE",
            diagnostic=_transport_diagnostic(error),
        )
        branch.update(
            {
                "provider_request_attempted": True,
                "acquisition_started_at_utc": (
                    _iso_z(acquisition_started_at) if acquisition_started_at is not None else None
                ),
                "acquisition_finished_at_utc": _iso_z(acquisition_finished_at),
            }
        )
        return _BranchOutcome(branch=branch, rows=(), provider_attempts=1)
    except Exception:
        acquisition_finished_at = ensure_utc(clock(), field="recurring_acquisition_finished")
        branch = _branch_stub(
            sport_key,
            source="LIVE_PROVIDER_FAILURE",
            diagnostic=_diagnostic(
                stage="PROVIDER_DISPATCH",
                code="RECURRING_PROVIDER_DISPATCH_FAILED",
                exception_class="Exception",
            ),
        )
        branch.update(
            {
                "provider_request_attempted": True,
                "acquisition_started_at_utc": (
                    _iso_z(acquisition_started_at) if acquisition_started_at is not None else None
                ),
                "acquisition_finished_at_utc": _iso_z(acquisition_finished_at),
            }
        )
        return _BranchOutcome(branch=branch, rows=(), provider_attempts=1)

    acquisition_finished_at = ensure_utc(clock(), field="recurring_acquisition_finished")
    if acquisition_started_at is None or acquisition_finished_at < acquisition_started_at:
        raise RecurringError("RECURRING_ACQUISITION_TIME_INVALID")

    quota_code: str | None = None
    observed_quota = None
    observed_cost = _observed_credit_cost(response.headers)
    observed_remaining = _observed_remaining(response.headers)
    if (
        response.network_calls != 1
        or response.provider_calls != 1
        or response.retries != 0
        or response.redirects != 0
    ):
        quota_code = "RECURRING_TRANSPORT_ACCOUNTING_INVALID"
    else:
        try:
            observed_quota = _quota(response.headers, response.first_observed_at_utc)
        except Exception:
            quota_code = "RECURRING_QUOTA_INVALID"
    if observed_cost != 2:
        quota_code = "RECURRING_CREDIT_COST_INVALID"
    credit_bound_valid = quota_code is None and observed_quota is not None and observed_cost == 2
    circuit_after_response: str | None = None
    if quota_code is not None:
        circuit_after_response = quota_code
    elif observed_quota is None:
        circuit_after_response = "RECURRING_QUOTA_INVALID"
    elif observed_cost != 2:
        circuit_after_response = "RECURRING_CREDIT_COST_INVALID"
    elif observed_quota.remaining < 2:
        circuit_after_response = "RECURRING_PROVIDER_BALANCE_INSUFFICIENT"
    quota_dict = observed_quota.as_dict() if observed_quota is not None else None
    envelope = _raw_envelope(
        config,
        slot=slot,
        sport_key=sport_key,
        response=response,
        quota=quota_dict,
        quota_code=quota_code,
        observed_cost=observed_cost,
        observed_remaining=observed_remaining,
        acquisition_started_at=acquisition_started_at,
        acquisition_finished_at=acquisition_finished_at,
    )
    try:
        raw_outcome = _put_exact(
            store,
            key=raw_key,
            data=envelope,
            kind="raw-provider-response",
        )
        if raw_outcome != "CREATED":
            raise RecurringError("RECURRING_RAW_WRITE_AMBIGUOUS")
        observed = store.get_object(raw_key)
        if observed is None:
            raise RecurringError("RECURRING_RAW_READBACK_MISSING")
    except Exception as error:
        code = error.code if isinstance(error, RecurringError) else "RECURRING_RAW_STORAGE_FAILURE"
        branch = _branch_stub(
            sport_key,
            source="LIVE_STORAGE_FAILURE",
            diagnostic=_diagnostic(
                stage="R2_RAW_PERSISTENCE",
                code=code,
                exception_class=type(error).__name__,
                http_status=response.http_status,
            ),
        )
        branch.update(
            {
                "provider_request_attempted": True,
                "capture_time_utc": _iso_z(response.first_observed_at_utc),
                "acquisition_started_at_utc": _iso_z(acquisition_started_at),
                "acquisition_finished_at_utc": _iso_z(acquisition_finished_at),
            }
        )
        return _BranchOutcome(
            branch=branch,
            rows=(),
            provider_attempts=1,
            circuit_code=circuit_after_response,
            observed_remaining=observed_remaining,
            credit_bound_valid=credit_bound_valid,
        )
    return _normalize_raw_branch(
        observed,
        slot=slot,
        sport_key=sport_key,
        raw_key=raw_key,
        source="LIVE_R2_CAPTURE",
        provider_request_attempted=True,
        provider_attempts_new=1,
    )


def _public_receipt(
    report: Mapping[str, object],
    *,
    report_key: str,
    report_sha256: str,
    replayed: bool,
) -> dict[str, object]:
    accounting = cast(Mapping[str, object], report["accounting"])
    receipt: dict[str, object] = {
        "schema_version": "robin-autonomous-lab-public-receipt-v1",
        "mission_id": MISSION_ID,
        "claim_ids": _report_claim_ids(report),
        "status": report["status"],
        "repository_sha": report["repository_sha"],
        "github_run_id": report["github_run_id"],
        "slot_start_utc": report["slot_start_utc"],
        "capture_times_utc": report["capture_times_utc"],
        "source_timestamp_min_utc": report["source_timestamp_min_utc"],
        "source_timestamp_max_utc": report["source_timestamp_max_utc"],
        "validated_capture_count": report["validated_capture_count"],
        "incomplete_branch_count": report["incomplete_branch_count"],
        "row_count": report["row_count"],
        "match_count": report["match_count"],
        "bookmaker_count": report["bookmaker_count"],
        "market_branch_coverage": report["market_branch_coverage"],
        "market_outcome_row_counts": report["market_outcome_row_counts"],
        "provider_requests_new": 0 if replayed else report["provider_requests_new"],
        "provider_requests_reserved": SLOT_REQUESTS,
        "provider_credits_reserved": SLOT_CREDITS,
        "rolling_24h_requests": accounting["rolling_24h_requests"],
        "rolling_24h_credits": accounting["rolling_24h_credits"],
        "rolling_30d_requests": accounting["rolling_30d_requests"],
        "rolling_30d_credits": accounting["rolling_30d_credits"],
        "lifetime_requests": accounting["lifetime_requests"],
        "lifetime_credits": accounting["lifetime_credits"],
        "credit_bound_valid": accounting.get("credit_bound_valid", True),
        "private_report_r2_key": report_key,
        "private_report_r2_sha256": report_sha256,
        "private_report_r2_status": "VERIFIED",
        "replayed_existing_slot": replayed,
        "resumed_existing_admission": report.get("resumed_existing_admission", False),
        "automatic_retries": 0,
        "purchases": 0,
        "real_bets": 0,
        "backfills": 0,
        "promotions": 0,
    }
    lineage = report.get("relay_lineage")
    if lineage is not None:
        if not isinstance(lineage, Mapping):
            raise RecurringError("RECURRING_REPORT_INVALID")
        receipt["relay_lineage"] = dict(lineage)
    return receipt


def _read_existing_report(store: RecurringStore, *, slot: datetime) -> dict[str, object] | None:
    key = f"{OBJECT_PREFIX}/slots/{_slot_id(slot)}/private-report.json"
    observed = store.get_object(key)
    if observed is None:
        return None
    report_sha = hashlib.sha256(observed.data).hexdigest()
    report = _mapping(observed.data, "RECURRING_REPORT_INVALID")
    if (
        observed.metadata.get("sha256") != report_sha
        or re.fullmatch(r"[0-9a-f]{64}", report_sha) is None
        or report.get("schema_version") != "robin-autonomous-lab-private-report-v1"
        or report.get("mission_id") != MISSION_ID
        or report.get("slot_start_utc") != _iso_z(slot)
    ):
        raise RecurringError("RECURRING_REPORT_INVALID")
    return _public_receipt(
        report,
        report_key=key,
        report_sha256=report_sha,
        replayed=True,
    )


def _advance_latest_report(
    store: RecurringStore,
    *,
    slot: datetime,
    report_key: str,
    report_sha: str,
    status: str,
    run_id: str,
) -> None:
    current_object = store.get_object(report_key)
    if current_object is None or hashlib.sha256(current_object.data).hexdigest() != report_sha:
        raise RecurringError("RECURRING_LATEST_REPORT_INTEGRITY_INVALID")
    current_report = _mapping(current_object.data, "RECURRING_LATEST_REPORT_INTEGRITY_INVALID")
    if (
        current_report.get("schema_version") != "robin-autonomous-lab-private-report-v1"
        or current_report.get("mission_id") != MISSION_ID
        or current_report.get("slot_start_utc") != _iso_z(slot)
        or current_report.get("status") != status
    ):
        raise RecurringError("RECURRING_LATEST_REPORT_INTEGRITY_INVALID")

    def usable_reference(
        *, key: object, sha: object, expected_slot: object, expected_status: object
    ) -> dict[str, object] | None:
        if not isinstance(key, str) or not isinstance(sha, str):
            raise RecurringError("RECURRING_LATEST_LAST_USABLE_INVALID")
        observed = store.get_object(key)
        if observed is None or hashlib.sha256(observed.data).hexdigest() != sha:
            raise RecurringError("RECURRING_LATEST_LAST_USABLE_INVALID")
        report = _mapping(observed.data, "RECURRING_LATEST_LAST_USABLE_INVALID")
        if (
            report.get("schema_version") != "robin-autonomous-lab-private-report-v1"
            or report.get("mission_id") != MISSION_ID
            or report.get("slot_start_utc") != expected_slot
            or report.get("status") != expected_status
        ):
            raise RecurringError("RECURRING_LATEST_LAST_USABLE_INVALID")
        row_count = report.get("row_count")
        validated = report.get("validated_capture_count")
        if (
            expected_status not in {"REAL_DATA_COMPLETE", "REAL_DATA_PARTIAL"}
            or isinstance(row_count, bool)
            or not isinstance(row_count, int)
            or row_count <= 0
            or isinstance(validated, bool)
            or not isinstance(validated, int)
            or validated <= 0
        ):
            return None
        captures = report.get("capture_times_utc")
        latest_capture = (
            max(value for value in captures if isinstance(value, str))
            if isinstance(captures, list) and any(isinstance(value, str) for value in captures)
            else None
        )
        return {
            "slot_start_utc": expected_slot,
            "github_run_id": report.get("github_run_id"),
            "status": expected_status,
            "report_key": key,
            "report_sha256": sha,
            "latest_capture_time_utc": latest_capture,
        }

    current_reference = usable_reference(
        key=report_key,
        sha=report_sha,
        expected_slot=_iso_z(slot),
        expected_status=status,
    )
    for _attempt in range(MAX_CAS_ATTEMPTS):
        previous = store.get_latest_projection(LATEST_REPORT_KEY)
        previous_data: Mapping[str, object] | None = None
        if previous is not None:
            previous_data = _mapping(previous.data, "RECURRING_LATEST_INVALID")
            previous_slot = _parse_time(
                previous_data.get("slot_start_utc"), "RECURRING_LATEST_INVALID"
            )
            if previous_slot > slot:
                return
            if previous_slot == slot:
                if previous_data.get("report_sha256") == report_sha:
                    return
                raise RecurringError("RECURRING_LATEST_SLOT_CONFLICT")
        last_usable = current_reference
        if last_usable is None and previous_data is not None:
            prior_reference = previous_data.get("last_usable")
            if prior_reference is None and previous_data.get("status") in {
                "REAL_DATA_COMPLETE",
                "REAL_DATA_PARTIAL",
            }:
                prior_reference = {
                    "slot_start_utc": previous_data.get("slot_start_utc"),
                    "status": previous_data.get("status"),
                    "report_key": previous_data.get("report_key"),
                    "report_sha256": previous_data.get("report_sha256"),
                }
            if prior_reference is not None:
                if not isinstance(prior_reference, dict):
                    raise RecurringError("RECURRING_LATEST_LAST_USABLE_INVALID")
                last_usable = usable_reference(
                    key=prior_reference.get("report_key"),
                    sha=prior_reference.get("report_sha256"),
                    expected_slot=prior_reference.get("slot_start_utc"),
                    expected_status=prior_reference.get("status"),
                )
        pointer = canonical_json_bytes(
            {
                "schema_version": "robin-autonomous-lab-latest-v2",
                "mission_id": MISSION_ID,
                "slot_start_utc": _iso_z(slot),
                "github_run_id": run_id,
                "status": status,
                "report_key": report_key,
                "report_sha256": report_sha,
                "last_usable": last_usable,
            }
        )
        result = store.put_latest_projection(
            LATEST_REPORT_KEY,
            pointer,
            metadata={"mission_id": MISSION_ID, "kind": "latest-report"},
            expected_etag=previous.etag if previous is not None else None,
            on_dispatch=lambda: None,
        )
        if result.outcome is ConditionalPutOutcome.CREATED:
            return
        if result.outcome not in {
            ConditionalPutOutcome.CONFLICT,
            ConditionalPutOutcome.PRECONDITION_FAILED,
        }:
            raise RecurringError("RECURRING_LATEST_WRITE_AMBIGUOUS")
    raise RecurringError("RECURRING_LATEST_CAS_EXHAUSTED")


def _recover_latest_from_closed_accounting(
    store: RecurringStore, accounting: Mapping[str, object]
) -> None:
    """Repair a missing/stale latest pointer from a verified closed head."""

    if accounting.get("node_kind") != "SLOT_CLOSURE" or accounting.get("slot_state") != "CLOSED":
        return
    report_key = accounting.get("report_key")
    report_sha = accounting.get("report_sha256")
    if not isinstance(report_key, str) or not isinstance(report_sha, str):
        raise RecurringError("RECURRING_ACCOUNTING_CLOSURE_INVALID")
    observed = store.get_object(report_key)
    if observed is None or hashlib.sha256(observed.data).hexdigest() != report_sha:
        raise RecurringError("RECURRING_ACCOUNTING_CLOSURE_REPORT_INVALID")
    report = _mapping(observed.data, "RECURRING_ACCOUNTING_CLOSURE_REPORT_INVALID")
    slot = _parse_time(accounting.get("slot_start_utc"), "RECURRING_ACCOUNTING_CLOSURE_INVALID")
    status = report.get("status")
    run_id = report.get("github_run_id")
    if (
        report.get("slot_start_utc") != _iso_z(slot)
        or status not in {"REAL_DATA_COMPLETE", "REAL_DATA_PARTIAL", "REAL_DATA_FAILED"}
        or not isinstance(run_id, str)
    ):
        raise RecurringError("RECURRING_ACCOUNTING_CLOSURE_REPORT_INVALID")
    _advance_latest_report(
        store,
        slot=slot,
        report_key=report_key,
        report_sha=report_sha,
        status=status,
        run_id=run_id,
    )


def _historical_seed_adapter(
    receipt: Mapping[str, object], report: Mapping[str, object]
) -> dict[str, object]:
    cross_fields = (
        "status",
        "row_count",
        "validated_capture_count",
        "incomplete_branch_count",
        "capture_times_utc",
        "source_timestamp_min_utc",
        "source_timestamp_max_utc",
        "match_count",
        "bookmaker_count",
    )
    if (
        report.get("schema_version") != "robin-real-data-result-report-v1"
        or report.get("mission_id") != HISTORICAL_MISSION_ID
        or report.get("repository_sha") != HISTORICAL_REPOSITORY_SHA
        or report.get("github_run_id") != HISTORICAL_RUN_ID
        or report.get("status") != "REAL_DATA_PARTIAL"
        or any(report.get(field) != receipt.get(field) for field in cross_fields)
    ):
        raise RecurringError("RECURRING_HISTORICAL_SEED_REPORT_INVALID")
    raw_rows = report.get("rows")
    raw_branches = report.get("branches")
    captures = report.get("capture_times_utc")
    row_count = report.get("row_count")
    validated = report.get("validated_capture_count")
    if (
        not isinstance(raw_rows, list)
        or not isinstance(raw_branches, list)
        or not isinstance(captures, list)
        or isinstance(row_count, bool)
        or not isinstance(row_count, int)
        or row_count <= 0
        or len(raw_rows) != row_count
        or isinstance(validated, bool)
        or not isinstance(validated, int)
        or validated <= 0
        or len(captures) != validated
        or len(raw_branches) != validated
        or any(not isinstance(value, str) for value in captures)
    ):
        raise RecurringError("RECURRING_HISTORICAL_SEED_REPORT_INVALID")
    for value in captures:
        _parse_time(value, "RECURRING_HISTORICAL_SEED_REPORT_INVALID")

    rows: list[dict[str, object]] = []
    for item in raw_rows:
        if not isinstance(item, dict):
            raise RecurringError("RECURRING_HISTORICAL_SEED_REPORT_INVALID")
        row = cast(dict[str, object], item)
        if (
            row.get("sport_key") not in SPORT_KEYS
            or row.get("market_key") not in MARKETS
            or row.get("capture_time_utc") not in captures
            or "slot_start_utc" in row
            or any(
                isinstance(key, str) and (key.startswith("raw_") or "api_key" in key.lower())
                for key in row
            )
        ):
            raise RecurringError("RECURRING_HISTORICAL_SEED_REPORT_INVALID")
        rows.append(dict(row) | {"slot_start_utc": _iso_z(HISTORICAL_SEED_SLOT)})

    branches: list[dict[str, object]] = []
    for item in raw_branches:
        if not isinstance(item, dict):
            raise RecurringError("RECURRING_HISTORICAL_SEED_REPORT_INVALID")
        branch = cast(dict[str, object], item)
        limitations = branch.get("limitations")
        diagnostic = branch.get("diagnostic")
        if (
            branch.get("sport_key") not in SPORT_KEYS
            or not isinstance(branch.get("status"), str)
            or not isinstance(branch.get("row_count"), int)
            or isinstance(branch.get("row_count"), bool)
            or not isinstance(branch.get("capture_time_utc"), str)
            or not isinstance(limitations, list)
            or (diagnostic is not None and not isinstance(diagnostic, dict))
        ):
            raise RecurringError("RECURRING_HISTORICAL_SEED_REPORT_INVALID")
        branches.append(
            {
                "sport_key": branch["sport_key"],
                "status": branch["status"],
                "data_availability": "VERIFIED_WITH_ROWS",
                "row_count": branch["row_count"],
                "capture_time_utc": branch["capture_time_utc"],
                "limitations": limitations,
                "diagnostic": diagnostic,
                "source": "VERIFIED_HISTORICAL_IMPORT",
            }
        )

    return {
        "schema_version": "robin-autonomous-lab-private-report-v1",
        "mission_id": MISSION_ID,
        "claim_ids": list(SEED_CLAIM_IDS),
        "repository_sha": HISTORICAL_REPOSITORY_SHA,
        "github_run_id": HISTORICAL_RUN_ID,
        "slot_start_utc": _iso_z(HISTORICAL_SEED_SLOT),
        "generated_at_utc": _iso_z(HISTORICAL_SEED_AT),
        "status": "REAL_DATA_PARTIAL",
        "branches": branches,
        "rows": rows,
        "row_count": row_count,
        "validated_capture_count": validated,
        "incomplete_branch_count": report.get("incomplete_branch_count"),
        "capture_times_utc": captures,
        "source_timestamp_min_utc": report.get("source_timestamp_min_utc"),
        "source_timestamp_max_utc": report.get("source_timestamp_max_utc"),
        "match_count": report.get("match_count"),
        "bookmaker_count": report.get("bookmaker_count"),
        "accounting": {
            "rolling_24h_requests": HISTORICAL_REQUESTS,
            "rolling_24h_credits": HISTORICAL_CREDITS,
            "rolling_30d_requests": HISTORICAL_REQUESTS,
            "rolling_30d_credits": HISTORICAL_CREDITS,
            "lifetime_requests": HISTORICAL_REQUESTS,
            "lifetime_credits": HISTORICAL_CREDITS,
            "provider_remaining_floor": HISTORICAL_PROVIDER_REMAINING,
        },
        "provider_requests_new": 0,
        "seed_import_provider_requests_new": 0,
        "seed_provenance": {
            "receipt_sha256": HISTORICAL_RECEIPT_SHA256,
            "private_report_key": HISTORICAL_PRIVATE_REPORT_KEY,
            "private_report_sha256": HISTORICAL_PRIVATE_REPORT_SHA256,
        },
    }


def _ensure_historical_seed_latest(store: RecurringStore, *, receipt_path: Path) -> None:
    if store.get_latest_projection(LATEST_REPORT_KEY) is not None:
        return
    if not receipt_path.is_absolute() or receipt_path.is_symlink():
        raise RecurringError("RECURRING_HISTORICAL_SEED_RECEIPT_INVALID")
    try:
        receipt_bytes = receipt_path.read_bytes().replace(b"\r\n", b"\n")
    except OSError:
        raise RecurringError("RECURRING_HISTORICAL_SEED_RECEIPT_INVALID") from None
    receipt = _mapping(receipt_bytes, "RECURRING_HISTORICAL_SEED_RECEIPT_INVALID")
    if hashlib.sha256(canonical_json_bytes(receipt)).hexdigest() != HISTORICAL_RECEIPT_SHA256:
        raise RecurringError("RECURRING_HISTORICAL_SEED_RECEIPT_INVALID")
    if (
        receipt.get("schema_version") != "robin-real-data-result-public-receipt-v1"
        or receipt.get("mission_id") != HISTORICAL_MISSION_ID
        or receipt.get("repository_sha") != HISTORICAL_REPOSITORY_SHA
        or receipt.get("github_run_id") != HISTORICAL_RUN_ID
        or receipt.get("status") != "REAL_DATA_PARTIAL"
        or receipt.get("private_report_r2_key") != HISTORICAL_PRIVATE_REPORT_KEY
        or receipt.get("private_report_r2_sha256") != HISTORICAL_PRIVATE_REPORT_SHA256
        or receipt.get("private_report_r2_status") != "VERIFIED"
        or receipt.get("provider_requests_cumulative") != HISTORICAL_REQUESTS
        or receipt.get("provider_credits_cumulative_upper_bound") != HISTORICAL_CREDITS
    ):
        raise RecurringError("RECURRING_HISTORICAL_SEED_RECEIPT_INVALID")
    observed = store.get_object(HISTORICAL_PRIVATE_REPORT_KEY)
    if observed is None:
        raise RecurringError("RECURRING_HISTORICAL_SEED_REPORT_MISSING")
    if (
        hashlib.sha256(observed.data).hexdigest() != HISTORICAL_PRIVATE_REPORT_SHA256
        or observed.metadata.get("sha256") != HISTORICAL_PRIVATE_REPORT_SHA256
        or observed.metadata.get("mission") != HISTORICAL_MISSION_ID.lower()
        or observed.metadata.get("kind") != "private-normalized-report"
    ):
        raise RecurringError("RECURRING_HISTORICAL_SEED_REPORT_INVALID")
    report = _mapping(observed.data, "RECURRING_HISTORICAL_SEED_REPORT_INVALID")
    adapter = _historical_seed_adapter(receipt, report)
    adapter_bytes = canonical_json_bytes(adapter)
    outcome = _put_exact(
        store,
        key=HISTORICAL_ADAPTER_KEY,
        data=adapter_bytes,
        kind="verified-historical-normalized-report",
        allow_preexisting=True,
    )
    if outcome == "AMBIGUOUS":
        raise RecurringError("RECURRING_HISTORICAL_SEED_WRITE_AMBIGUOUS")
    adapter_sha = hashlib.sha256(adapter_bytes).hexdigest()
    _advance_latest_report(
        store,
        slot=HISTORICAL_SEED_SLOT,
        report_key=HISTORICAL_ADAPTER_KEY,
        report_sha=adapter_sha,
        status="REAL_DATA_PARTIAL",
        run_id=HISTORICAL_RUN_ID,
    )


def recover_latest_report(
    config: RecurringConfig,
    *,
    store: RecurringStore,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    historical_receipt_path: Path | None = None,
) -> Mapping[str, object] | None:
    """Authorize and repair latest before a consumer reads the previous report."""

    _validate_config(config)
    started = ensure_utc(clock(), field="recurring_started_at")
    _load_manifest(config.manifest_path, started)
    _, active_accounting = _load_accounting(store)
    if historical_receipt_path is not None:
        _ensure_historical_seed_latest(store, receipt_path=historical_receipt_path)
    if active_accounting is not None:
        _recover_latest_from_closed_accounting(store, active_accounting)
    return active_accounting


def run_recurring_real_data(
    config: RecurringConfig,
    *,
    store: RecurringStore,
    transport_factory: TransportFactory,
    secret_reader: SecretReader,
    resolver: Callable[[], NetworkResolution],
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> dict[str, object]:
    """Collect one deterministic slot after durable atomic admission."""

    _validate_config(config)
    started = ensure_utc(clock(), field="recurring_started_at")
    _load_manifest(config.manifest_path, started)
    requested_slot = slot_start_utc(started)
    _, active_accounting = _load_accounting(store)
    if active_accounting is not None:
        _recover_latest_from_closed_accounting(store, active_accounting)
    slot = requested_slot
    offline_recovery = False
    if active_accounting is not None and active_accounting.get("slot_state") == "OPEN":
        active_slot = _parse_time(
            active_accounting.get("slot_start_utc"),
            "RECURRING_ACCOUNTING_NODE_INVALID",
        )
        if active_slot > requested_slot:
            raise RecurringError("RECURRING_ACCOUNTING_SLOT_REGRESSION")
        slot = active_slot
        offline_recovery = active_slot < requested_slot
    existing = _read_existing_report(store, slot=slot)
    if existing is not None:
        _close_accounting_slot(
            config,
            store=store,
            slot=slot,
            report_key=cast(str, existing["private_report_r2_key"]),
            report_sha256=cast(str, existing["private_report_r2_sha256"]),
        )
        _advance_latest_report(
            store,
            slot=slot,
            report_key=cast(str, existing["private_report_r2_key"]),
            report_sha=cast(str, existing["private_report_r2_sha256"]),
            status=cast(str, existing["status"]),
            run_id=cast(str, existing["github_run_id"]),
        )
        return existing
    admission = _reserve_accounting_slot(config, store=store, slot=slot)
    resumed_admission = admission.resumed

    resolution: NetworkResolution | None = None
    resolution_attempted = False
    resolution_error: str | None = None
    api_key: str | None = None
    secret_attempted = False
    provider_access_error_code: str | None = None

    def provider_resolution() -> NetworkResolution:
        nonlocal resolution, resolution_attempted, resolution_error
        if resolution_error is not None:
            raise RecurringError(resolution_error)
        if not resolution_attempted:
            resolution_attempted = True
            try:
                resolution = resolver()
            except Exception:
                resolution_error = "RECURRING_DNS_RESOLUTION_FAILED"
                raise RecurringError(resolution_error) from None
            if resolution is None:
                resolution_error = "RECURRING_DNS_RESOLUTION_INVALID"
                raise RecurringError(resolution_error)
            if resolution.resolution_operations != 1:
                resolution_error = "RECURRING_DNS_RESOLUTION_INVALID"
                raise RecurringError(resolution_error)
        if resolution is None:
            resolution_error = "RECURRING_DNS_RESOLUTION_INVALID"
            raise RecurringError(resolution_error)
        try:
            now = ensure_utc(clock(), field="recurring_provider_access")
            resolution.assert_current(now)
        except Exception:
            resolution_error = "RECURRING_DNS_RESOLUTION_EXPIRED"
            raise RecurringError(resolution_error) from None
        return resolution

    def provider_secret() -> str:
        nonlocal api_key, secret_attempted, provider_access_error_code
        if provider_access_error_code is not None:
            raise RecurringError(provider_access_error_code)
        if not secret_attempted:
            secret_attempted = True
            try:
                api_key = validate_provider_secret(secret_reader.read())
            except Exception:
                provider_access_error_code = "RECURRING_PROVIDER_SECRET_INVALID"
                raise RecurringError(provider_access_error_code) from None
        if api_key is None:
            provider_access_error_code = "RECURRING_PROVIDER_SECRET_INVALID"
            raise RecurringError(provider_access_error_code)
        return api_key

    branches: list[dict[str, object]] = []
    rows: list[dict[str, object]] = []
    provider_requests = 0
    circuit_code: str | None = None
    for sport_key in SPORT_KEYS:
        try:
            outcome = _run_branch(
                config,
                slot=slot,
                sport_key=sport_key,
                store=store,
                transport_factory=transport_factory,
                clock=clock,
                provider_resolution=provider_resolution,
                provider_secret=provider_secret,
                circuit_code=circuit_code,
                allow_provider_dispatch=not offline_recovery,
            )
        except RecurringError as error:
            outcome = _BranchOutcome(
                branch=_branch_stub(
                    sport_key,
                    source="BRANCH_RUNTIME_FAILURE",
                    diagnostic=_diagnostic(
                        stage="BRANCH_RUNTIME",
                        code=error.code,
                        exception_class="RecurringError",
                    ),
                ),
                rows=(),
                provider_attempts=0,
            )
        except Exception as error:
            outcome = _BranchOutcome(
                branch=_branch_stub(
                    sport_key,
                    source="BRANCH_RUNTIME_FAILURE",
                    diagnostic=_diagnostic(
                        stage="BRANCH_RUNTIME",
                        code="RECURRING_BRANCH_RUNTIME_FAILURE",
                        exception_class=type(error).__name__,
                    ),
                ),
                rows=(),
                provider_attempts=0,
            )
        if outcome.observed_remaining is not None or not outcome.credit_bound_valid:
            current_floor = cast(int, admission.node["provider_remaining_floor"])
            if not outcome.credit_bound_valid or (
                outcome.observed_remaining is not None
                and outcome.observed_remaining < current_floor
            ):
                try:
                    admission = _reconcile_accounting(
                        config,
                        store=store,
                        slot=slot,
                        observed_remaining=outcome.observed_remaining,
                        credit_bound_valid=outcome.credit_bound_valid,
                    )
                except RecurringError:
                    raise RecurringError("RECURRING_ACCOUNTING_RECONCILIATION_FAILED") from None
        if circuit_code is None and outcome.circuit_code is not None:
            circuit_code = outcome.circuit_code
        branches.append(outcome.branch)
        rows.extend(outcome.rows)
        provider_requests += outcome.provider_attempts

    rows.sort(
        key=lambda row: (
            cast(str, row["sport_key"]),
            cast(str, row["kickoff_utc"]),
            cast(str, row["event_id"]),
            cast(str, row["bookmaker_key"]),
            cast(str, row["market_key"]),
            cast(float | None, row["point"]) or -1.0,
            cast(str, row["outcome"]),
        )
    )
    validated = sum(1 for branch in branches if branch["status"] in {"COMPLETE", "PARTIAL"})
    incomplete = sum(1 for branch in branches if branch["status"] == "INCOMPLETE")
    status = (
        "REAL_DATA_COMPLETE"
        if all(branch["status"] == "COMPLETE" for branch in branches)
        else "REAL_DATA_PARTIAL"
        if validated
        else "REAL_DATA_FAILED"
    )
    captures = sorted(
        cast(str, branch["capture_time_utc"])
        for branch in branches
        if isinstance(branch.get("capture_time_utc"), str)
    )
    source_times = sorted(cast(str, row["source_timestamp_utc"]) for row in rows)
    accounting = {
        key: admission.node[key]
        for key in (
            "lifetime_requests",
            "lifetime_credits",
            "rolling_24h_requests",
            "rolling_24h_credits",
            "rolling_30d_requests",
            "rolling_30d_credits",
            "provider_remaining_floor",
            "credit_bound_valid",
        )
    } | {
        "node_key": admission.node_key,
        "node_sha256": admission.node_sha256,
        "entries": admission.node["entries"],
    }
    report: dict[str, object] = {
        "schema_version": "robin-autonomous-lab-private-report-v1",
        "mission_id": MISSION_ID,
        "claim_ids": list(RECURRING_CLAIM_IDS),
        "repository_sha": config.repository_sha,
        "github_run_id": config.github_run_id,
        "relay_lineage": {
            "generation": config.relay_generation,
            "chain_id": config.relay_chain_id,
            "parent_run_id": config.relay_parent_run_id,
            "sequence": config.relay_sequence,
        },
        "slot_start_utc": _iso_z(slot),
        "generated_at_utc": _iso_z(clock()),
        "status": status,
        "branches": branches,
        "rows": rows,
        "row_count": len(rows),
        "validated_capture_count": validated,
        "incomplete_branch_count": incomplete,
        "capture_times_utc": captures,
        "source_timestamp_min_utc": source_times[0] if source_times else None,
        "source_timestamp_max_utc": source_times[-1] if source_times else None,
        "match_count": len({row["event_id"] for row in rows}),
        "bookmaker_count": len({row["bookmaker_key"] for row in rows}),
        "market_branch_coverage": {
            market: sum(
                cast(Mapping[str, int], branch["market_branch_coverage"])[market]
                for branch in branches
            )
            for market in MARKETS
        },
        "market_outcome_row_counts": {
            market: sum(1 for row in rows if row["market_key"] == market) for market in MARKETS
        },
        "market_limitation_counts": {
            code: sum(
                1
                for branch in branches
                for limitation in cast(list[Mapping[str, object]], branch["limitations"])
                if limitation.get("code") == code
            )
            for code in (
                "RESULT_MARKET_MISSING",
                "RESULT_MARKET_DUPLICATED",
                "RESULT_MARKET_MISSING_OR_DUPLICATED",
            )
        },
        "provider_requests_new": provider_requests,
        "provider_requests_reserved": SLOT_REQUESTS,
        "provider_credits_reserved": SLOT_CREDITS,
        "resumed_existing_admission": resumed_admission,
        "accounting": accounting,
        "effect_accounting": {
            "automatic_retries": 0,
            "purchases": 0,
            "real_bets": 0,
            "backfills": 0,
            "promotions": 0,
        },
        "scientific_status": "DESCRIPTIVE_ONLY_NO_EDGE_VALIDATED",
    }
    report_bytes = canonical_json_bytes(report)
    report_key = f"{OBJECT_PREFIX}/slots/{_slot_id(slot)}/private-report.json"
    report_outcome = _put_exact(
        store,
        key=report_key,
        data=report_bytes,
        kind="private-normalized-report",
        allow_preexisting=True,
    )
    if report_outcome == "AMBIGUOUS":
        raise RecurringError("RECURRING_REPORT_WRITE_AMBIGUOUS")
    report_sha = hashlib.sha256(report_bytes).hexdigest()
    _close_accounting_slot(
        config,
        store=store,
        slot=slot,
        report_key=report_key,
        report_sha256=report_sha,
    )
    _advance_latest_report(
        store,
        slot=slot,
        report_key=report_key,
        report_sha=report_sha,
        status=status,
        run_id=config.github_run_id,
    )
    return _public_receipt(
        report,
        report_key=report_key,
        report_sha256=report_sha,
        replayed=False,
    )


__all__ = [
    "ACCOUNTING_HEAD_KEY",
    "ACCOUNTING_INITIALIZED_KEY",
    "HISTORICAL_PRIVATE_REPORT_KEY",
    "LATEST_REPORT_KEY",
    "MISSION_ID",
    "RECURRING_CLAIM_IDS",
    "SEED_CLAIM_IDS",
    "RecurringConfig",
    "RecurringError",
    "classify_market_limitation",
    "recover_latest_report",
    "run_recurring_real_data",
    "slot_start_utc",
]
