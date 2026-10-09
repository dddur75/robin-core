"""Bounded two-capture pilot for ROBIN_REPRISE_COLLECTE_20261002.

The module owns mission-wide ordering and accounting.  Network and object-store
adapters remain injected so their existing strict implementations can be reused
without giving either adapter authority to retry or to enlarge the mission.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import html
import io
import ipaddress
import math
import re
import socket
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal, Protocol, cast

from robin.capture.contracts import (
    CaptureContractError,
    ProviderRequestSpec,
    canonical_json_bytes,
    ensure_utc,
    strict_json_loads,
)
from robin.capture.live_contracts import validate_provider_ip_address
from robin.capture.live_transport import (
    LiveTransport,
    LiveTransportError,
    LiveTransportResponse,
    PublicProviderRequestV1,
    SecretReader,
    validate_provider_secret,
)
from robin.capture.provider_network import system_resolver_identity_v1
from robin.prospective_observatory.chronos_control_plane import (
    ConditionalObjectStore,
    ConditionalPutOutcome,
)

MISSION_ID = "ROBIN_REPRISE_COLLECTE_20261002"
MANDATE_SHA256 = "0a48756520b7f77f6c2d66d27e3b423d5f62d0468bd8b8607aa1cebf5f391d22"
SPORT_KEY = "soccer_epl"
REGION: Literal["eu"] = "eu"
MARKET: Literal["h2h"] = "h2h"
MAX_PROVIDER_REQUESTS = 2
MAX_PROVIDER_CREDITS = 4
MAX_CREDITS_PER_REQUEST = 2
MAX_R2_PUTS = 5
MAX_R2_GETS = 3
MAX_RESPONSE_BYTES = 5_242_880
MAX_SOURCE_AGE = timedelta(minutes=15)
OBJECT_PREFIX = f"robin/reprise-collecte/{MISSION_ID}"
CLAIM_IDS = (
    "DATA.REPRISE.COLLECTE.CAPTURES.V1.001",
    "DATA.REPRISE.COLLECTE.VIEW.V1.001",
    "GOV.REPRISE.COLLECTE.CONSUMPTION.V1.001",
)

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
_EXPECTED_EFFECTS = [
    "git_remote_write_non_force",
    "github_pull_request_write",
    "github_merge_commit",
    "github_actions_observe",
    "github_actions_workflow_dispatch_exactly_once_after_merge",
    "github_actions_artifact_upload_encrypted",
    "provider_public_dns_resolution_exactly_once",
    "provider_secret_read_exactly_once",
    "provider_tcp_tls_connection_max_2",
    "provider_https_get_max_2",
    "provider_credit_consume_max_4",
    "r2_conditional_put_max_5",
    "r2_exact_key_get_max_3",
    "local_private_delivery_artifact_writes",
    "offline_replay_from_captured_bytes",
]
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
_OUTPUT_FILENAMES = (
    "public-receipt.json",
    "reprise-collecte-private.json",
    "reprise-collecte.csv",
    "reprise-collecte.html",
)


class PilotError(RuntimeError):
    """Stable fail-closed code that never contains provider or secret material."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class TransportFactory(Protocol):
    def __call__(self, clock: Callable[[], datetime]) -> LiveTransport: ...


@dataclass(frozen=True, slots=True)
class NetworkResolution:
    selected_ip_address: str
    resolved_ip_addresses: tuple[str, ...]
    observed_at_utc: datetime
    expires_at_utc: datetime
    resolver_identity: str
    resolution_operations: int = 1

    def __post_init__(self) -> None:
        try:
            observed = ensure_utc(self.observed_at_utc, field="reprise_resolution_observed_at")
            expires = ensure_utc(self.expires_at_utc, field="reprise_resolution_expires_at")
            canonical = _canonical_addresses(self.resolved_ip_addresses)
            validate_provider_ip_address(self.selected_ip_address)
        except (CaptureContractError, TypeError, ValueError):
            raise PilotError("REPRISE_DNS_RESOLUTION_INVALID") from None
        if (
            not self.resolver_identity
            or self.resolution_operations != 1
            or canonical != self.resolved_ip_addresses
            or not canonical
            or self.selected_ip_address != canonical[0]
            or observed >= expires
            or expires - observed > timedelta(minutes=15)
        ):
            raise PilotError("REPRISE_DNS_RESOLUTION_INVALID")

    def assert_current(self, now: datetime) -> None:
        current = ensure_utc(now, field="reprise_resolution_current_at")
        if not self.observed_at_utc <= current < self.expires_at_utc:
            raise PilotError("REPRISE_DNS_RESOLUTION_EXPIRED")


@dataclass(frozen=True, slots=True)
class PilotConfig:
    manifest_path: Path
    output_directory: Path
    repository_sha: str
    github_run_id: str
    github_run_attempt: int
    interval_seconds: int
    safety_environment: Mapping[str, str]


@dataclass(frozen=True, slots=True)
class _Manifest:
    expires_at: datetime
    time_budget: int


@dataclass(frozen=True, slots=True)
class _QuotaAudit:
    remaining: int
    used: int
    last: int
    observed_at_utc: datetime

    def as_dict(self) -> dict[str, object]:
        return {
            "requests_remaining": self.remaining,
            "requests_used": self.used,
            "requests_last": self.last,
            "observed_at_utc": _iso_z(self.observed_at_utc),
        }


@dataclass(frozen=True, slots=True)
class _CaptureAudit:
    capture_index: int
    capture_time_utc: datetime
    quota: _QuotaAudit
    rows: tuple[dict[str, object], ...]
    raw_payload_sha256: str
    raw_object_sha256: str
    raw_object_key: str
    normalized_rows_sha256: str


@dataclass(frozen=True, slots=True)
class _FailedCaptureEvidence:
    capture_index: int
    capture_time_utc: datetime
    quota: _QuotaAudit | None
    raw_payload_sha256: str
    raw_object_sha256: str
    raw_object_key: str
    validation_error_code: str
    readback_verified: bool

    def as_dict(self) -> dict[str, object]:
        return {
            "capture_index": self.capture_index,
            "capture_time_utc": _iso_z(self.capture_time_utc),
            "quota": self.quota.as_dict() if self.quota is not None else None,
            "raw_payload_sha256": self.raw_payload_sha256,
            "raw_object_sha256": self.raw_object_sha256,
            "raw_object_key": self.raw_object_key,
            "validation_error_code": self.validation_error_code,
            "readback_verified": self.readback_verified,
        }


class _CaptureFailure(PilotError):
    def __init__(self, code: str, evidence: _FailedCaptureEvidence) -> None:
        self.evidence = evidence
        super().__init__(code)


@dataclass(slots=True)
class _Effects:
    r2_puts: int = 0
    r2_gets: int = 0
    provider_requests: int = 0
    dns_resolutions: int = 0
    secret_reads: int = 0
    confirmed_credit_minimum: int = 0


def _iso_z(value: datetime) -> str:
    return (
        ensure_utc(value, field="reprise_timestamp")
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def _parse_time(value: object, *, code: str) -> datetime:
    if not isinstance(value, str) or not value or len(value) > 64:
        raise PilotError(code)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return ensure_utc(parsed, field="reprise_parsed_timestamp")
    except (TypeError, ValueError):
        raise PilotError(code) from None


def _canonical_addresses(addresses: Iterable[str]) -> tuple[str, ...]:
    parsed: dict[tuple[int, bytes], str] = {}
    for value in addresses:
        if not isinstance(value, str):
            raise ValueError("address must be text")
        validate_provider_ip_address(value)
        address = ipaddress.ip_address(value)
        parsed[(address.version, address.packed)] = str(address)
    return tuple(parsed[key] for key in sorted(parsed))


def resolve_provider_once(
    *,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    getaddrinfo: Callable[[str, int, int, int, int], Iterable[tuple[Any, ...]]] = (
        socket.getaddrinfo
    ),
) -> NetworkResolution:
    """Perform exactly one OS resolver operation and select one canonical address."""

    observed = ensure_utc(clock(), field="reprise_dns_observed_at")
    try:
        answers = tuple(
            getaddrinfo(
                "api.the-odds-api.com",
                443,
                socket.AF_UNSPEC,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
            )
        )
    except (OSError, TypeError, ValueError):
        raise PilotError("REPRISE_DNS_RESOLUTION_FAILED") from None
    addresses: list[str] = []
    for answer in answers:
        if not isinstance(answer, tuple) or len(answer) < 5:
            raise PilotError("REPRISE_DNS_RESOLUTION_INVALID")
        socket_address = answer[4]
        if not isinstance(socket_address, tuple) or not socket_address:
            raise PilotError("REPRISE_DNS_RESOLUTION_INVALID")
        value = socket_address[0]
        if not isinstance(value, str):
            raise PilotError("REPRISE_DNS_RESOLUTION_INVALID")
        addresses.append(value)
    try:
        canonical = _canonical_addresses(addresses)
    except (TypeError, ValueError):
        raise PilotError("REPRISE_DNS_RESOLUTION_INVALID") from None
    if not canonical:
        raise PilotError("REPRISE_DNS_RESOLUTION_INVALID")
    return NetworkResolution(
        selected_ip_address=canonical[0],
        resolved_ip_addresses=canonical,
        observed_at_utc=observed,
        expires_at_utc=observed + timedelta(minutes=15),
        resolver_identity=system_resolver_identity_v1(),
    )


def _validate_config(config: PilotConfig) -> None:
    if config.github_run_attempt != 1:
        raise PilotError("REPRISE_WORKFLOW_RERUN_FORBIDDEN")
    if re.fullmatch(r"[0-9a-f]{40}", config.repository_sha) is None:
        raise PilotError("REPRISE_REPOSITORY_SHA_INVALID")
    if re.fullmatch(r"[1-9][0-9]{0,19}", config.github_run_id) is None:
        raise PilotError("REPRISE_GITHUB_RUN_ID_INVALID")
    if not 60 <= config.interval_seconds <= 600:
        raise PilotError("REPRISE_CAPTURE_INTERVAL_INVALID")
    if not config.manifest_path.is_file():
        raise PilotError("REPRISE_MANIFEST_MISSING")
    if not config.output_directory.is_dir() or config.output_directory.is_symlink():
        raise PilotError("REPRISE_OUTPUT_DIRECTORY_INVALID")
    if any((config.output_directory / name).exists() for name in _OUTPUT_FILENAMES):
        raise PilotError("REPRISE_OUTPUT_ALREADY_EXISTS")
    for variable, expected in _SAFETY_LOCKS.items():
        if config.safety_environment.get(variable) != expected:
            raise PilotError("REPRISE_SAFETY_LOCK_INVALID")


def _load_manifest(path: Path, now: datetime) -> _Manifest:
    try:
        decoded = strict_json_loads(path.read_bytes())
    except (CaptureContractError, OSError):
        raise PilotError("REPRISE_MANIFEST_INVALID") from None
    if not isinstance(decoded, dict):
        raise PilotError("REPRISE_MANIFEST_INVALID")
    manifest = cast(dict[str, object], decoded)
    if set(manifest) != _MANIFEST_FIELDS:
        raise PilotError("REPRISE_MANIFEST_INVALID")
    expected = {
        "mission_id": MISSION_ID,
        "authorized_stages": ["E1"],
        "maximum_stage": "E1",
        "external_effects": _EXPECTED_EFFECTS,
        "compute_budget": 4000,
        "time_budget": 7200,
        "source_hash": MANDATE_SHA256,
    }
    if any(manifest.get(key) != value for key, value in expected.items()):
        raise PilotError("REPRISE_MANIFEST_INVALID")
    expires = _parse_time(manifest.get("expires_at"), code="REPRISE_MANIFEST_INVALID")
    if ensure_utc(now, field="reprise_manifest_now") >= expires:
        raise PilotError("REPRISE_MISSION_EXPIRED")
    return _Manifest(expires_at=expires, time_budget=7200)


def _assert_time_budget(
    *,
    manifest: _Manifest,
    clock: Callable[[], datetime],
    monotonic: Callable[[], float],
    started_monotonic: float,
) -> datetime:
    now = ensure_utc(clock(), field="reprise_effect_time")
    elapsed = monotonic() - started_monotonic
    if elapsed < 0 or elapsed > manifest.time_budget:
        raise PilotError("REPRISE_TIME_BUDGET_EXCEEDED")
    if now >= manifest.expires_at:
        raise PilotError("REPRISE_MISSION_EXPIRED")
    return now


def _put_once(
    store: ConditionalObjectStore,
    *,
    key: str,
    data: bytes,
    kind: str,
    effects: _Effects,
    failure_code: str,
) -> str:
    payload_sha256 = hashlib.sha256(data).hexdigest()
    callbacks = 0

    def on_dispatch() -> None:
        nonlocal callbacks
        if effects.r2_puts >= MAX_R2_PUTS:
            raise PilotError("REPRISE_R2_PUT_BUDGET_EXCEEDED")
        callbacks += 1
        effects.r2_puts += 1

    try:
        result = store.put_if_absent(
            key,
            data,
            metadata={
                "mission": MISSION_ID.lower(),
                "kind": kind,
                "sha256": payload_sha256,
            },
            on_dispatch=on_dispatch,
        )
    except PilotError:
        raise
    except Exception:
        raise PilotError(failure_code) from None
    if (
        callbacks != 1
        or result.outcome is not ConditionalPutOutcome.CREATED
        or result.transport_attempts != 1
        or result.automatic_retry_possible
    ):
        raise PilotError(failure_code)
    return payload_sha256


def _get_verified(
    store: ConditionalObjectStore,
    *,
    key: str,
    expected: bytes,
    effects: _Effects,
) -> bytes:
    if effects.r2_gets >= MAX_R2_GETS:
        raise PilotError("REPRISE_R2_GET_BUDGET_EXCEEDED")
    effects.r2_gets += 1
    try:
        observed = store.get_object(key)
    except Exception:
        raise PilotError("REPRISE_R2_READBACK_FAILED") from None
    if observed is None or observed.data != expected:
        raise PilotError("REPRISE_R2_READBACK_MISMATCH")
    expected_sha = hashlib.sha256(expected).hexdigest()
    if observed.metadata.get("sha256") != expected_sha:
        raise PilotError("REPRISE_R2_READBACK_METADATA_MISMATCH")
    return observed.data


def _reservation_bytes(
    *,
    config: PilotConfig,
    capture_index: int,
    recorded_at: datetime,
    first_capture_sha256: str | None,
) -> bytes:
    return canonical_json_bytes(
        {
            "schema_version": "robin-reprise-collecte-attempt-reservation-v1",
            "mission_id": MISSION_ID,
            "repository_sha": config.repository_sha,
            "github_run_id": config.github_run_id,
            "github_run_attempt": config.github_run_attempt,
            "capture_index": capture_index,
            "recorded_at_utc": _iso_z(recorded_at),
            "sport_key": SPORT_KEY,
            "region": REGION,
            "market": MARKET,
            "provider_requests_reserved": 1,
            "credits_reserved_maximum": MAX_CREDITS_PER_REQUEST,
            "mission_provider_requests_maximum": MAX_PROVIDER_REQUESTS,
            "mission_credits_maximum": MAX_PROVIDER_CREDITS,
            "automatic_retries": 0,
            "first_capture_sha256": first_capture_sha256,
        }
    )


def _text(value: object, *, code: str, maximum: int = 200) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.strip() != value
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise PilotError(code)
    return value


def _mapping(value: object, *, code: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise PilotError(code)
    return cast(Mapping[str, object], value)


def _sequence(value: object, *, code: str, maximum: int) -> list[object]:
    if not isinstance(value, list) or not value or len(value) > maximum:
        raise PilotError(code)
    return cast(list[object], value)


def _price(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise PilotError("REPRISE_ODDS_PRICE_INVALID")
    parsed = float(value)
    if not math.isfinite(parsed) or not 1.0 < parsed <= 10_000.0:
        raise PilotError("REPRISE_ODDS_PRICE_INVALID")
    return parsed


def _normalize_payload(
    payload: bytes,
    *,
    capture_index: int,
    capture_time: datetime,
    quota: _QuotaAudit,
    credits_total: int,
) -> tuple[dict[str, object], ...]:
    try:
        decoded = strict_json_loads(payload)
    except CaptureContractError:
        raise PilotError("REPRISE_PROVIDER_JSON_INVALID") from None
    if not isinstance(decoded, list):
        raise PilotError("REPRISE_PROVIDER_PAYLOAD_SHAPE_INVALID")
    if not decoded:
        raise PilotError("REPRISE_NO_UPCOMING_ODDS")
    if len(decoded) > 500:
        raise PilotError("REPRISE_PROVIDER_PAYLOAD_TOO_MANY_EVENTS")
    rows: list[dict[str, object]] = []
    identities: set[tuple[str, str]] = set()
    for raw_event in decoded:
        event = _mapping(raw_event, code="REPRISE_EVENT_INVALID")
        event_id = _text(event.get("id"), code="REPRISE_EVENT_INVALID", maximum=160)
        if event.get("sport_key") != SPORT_KEY:
            raise PilotError("REPRISE_EVENT_SPORT_MISMATCH")
        home = _text(event.get("home_team"), code="REPRISE_TEAM_INVALID")
        away = _text(event.get("away_team"), code="REPRISE_TEAM_INVALID")
        if home == away:
            raise PilotError("REPRISE_TEAM_INVALID")
        kickoff = _parse_time(event.get("commence_time"), code="REPRISE_KICKOFF_INVALID")
        if kickoff <= capture_time:
            raise PilotError("REPRISE_NO_UPCOMING_ODDS")
        raw_bookmakers = event.get("bookmakers")
        if not isinstance(raw_bookmakers, list) or len(raw_bookmakers) > 100:
            raise PilotError("REPRISE_BOOKMAKERS_INVALID")
        bookmakers = cast(list[object], raw_bookmakers)
        for raw_bookmaker in bookmakers:
            bookmaker = _mapping(raw_bookmaker, code="REPRISE_BOOKMAKER_INVALID")
            bookmaker_key = _text(
                bookmaker.get("key"), code="REPRISE_BOOKMAKER_INVALID", maximum=100
            )
            bookmaker_title = _text(
                bookmaker.get("title"), code="REPRISE_BOOKMAKER_INVALID", maximum=160
            )
            source_time = _parse_time(
                bookmaker.get("last_update"), code="REPRISE_SOURCE_TIMESTAMP_INVALID"
            )
            if source_time > capture_time + timedelta(minutes=5) or source_time >= kickoff:
                raise PilotError("REPRISE_SOURCE_TIMESTAMP_INVALID")
            if capture_time - source_time > MAX_SOURCE_AGE:
                raise PilotError("REPRISE_SOURCE_TIMESTAMP_STALE")
            markets = _sequence(
                bookmaker.get("markets"), code="REPRISE_MARKETS_INVALID", maximum=10
            )
            h2h = [
                _mapping(market, code="REPRISE_MARKET_INVALID")
                for market in markets
                if isinstance(market, dict) and market.get("key") == MARKET
            ]
            if len(h2h) != 1:
                raise PilotError("REPRISE_H2H_MARKET_INVALID")
            outcomes = _sequence(
                h2h[0].get("outcomes"), code="REPRISE_OUTCOMES_INVALID", maximum=10
            )
            prices: dict[str, float] = {}
            for raw_outcome in outcomes:
                outcome = _mapping(raw_outcome, code="REPRISE_OUTCOME_INVALID")
                name = _text(outcome.get("name"), code="REPRISE_OUTCOME_INVALID")
                if name in prices:
                    raise PilotError("REPRISE_OUTCOME_DUPLICATED")
                prices[name] = _price(outcome.get("price"))
            if set(prices) != {home, "Draw", away}:
                raise PilotError("REPRISE_1N2_INCOMPLETE")
            identity = (event_id, bookmaker_key)
            if identity in identities:
                raise PilotError("REPRISE_ROW_DUPLICATED")
            identities.add(identity)
            rows.append(
                {
                    "capture_index": capture_index,
                    "capture_time_utc": _iso_z(capture_time),
                    "source_timestamp_utc": _iso_z(source_time),
                    "event_id": event_id,
                    "match": f"{home} — {away}",
                    "home_team": home,
                    "away_team": away,
                    "kickoff_utc": _iso_z(kickoff),
                    "bookmaker_key": bookmaker_key,
                    "bookmaker": bookmaker_title,
                    "odds_1": prices[home],
                    "odds_n": prices["Draw"],
                    "odds_2": prices[away],
                    "capture_credits": quota.last,
                    "credits_total_after_capture": credits_total,
                }
            )
    if not rows:
        raise PilotError("REPRISE_NO_UPCOMING_ODDS")
    rows.sort(
        key=lambda row: (
            cast(str, row["kickoff_utc"]),
            cast(str, row["event_id"]),
            cast(str, row["bookmaker_key"]),
        )
    )
    return tuple(rows)


def _quota(headers: Mapping[str, str], observed_at: datetime) -> _QuotaAudit:
    normalized: dict[str, str] = {}
    for name, value in headers.items():
        lowered = name.casefold()
        if lowered in normalized:
            raise PilotError("REPRISE_QUOTA_HEADERS_INVALID")
        normalized[lowered] = value
    names = ("x-requests-remaining", "x-requests-used", "x-requests-last")
    if any(name not in normalized for name in names):
        raise PilotError("REPRISE_QUOTA_HEADERS_MISSING")
    parsed: list[int] = []
    for name in names:
        value = normalized[name]
        if not isinstance(value, str) or not value.isascii() or not value.isdecimal():
            raise PilotError("REPRISE_QUOTA_HEADERS_INVALID")
        number = int(value)
        if number < 0 or number > 2**63 - 1:
            raise PilotError("REPRISE_QUOTA_HEADERS_INVALID")
        parsed.append(number)
    remaining, used, last = parsed
    if not 1 <= last <= MAX_CREDITS_PER_REQUEST:
        raise PilotError("REPRISE_CREDIT_COST_UNEXPECTED")
    if used < last:
        raise PilotError("REPRISE_QUOTA_HEADERS_INVALID")
    return _QuotaAudit(
        remaining=remaining,
        used=used,
        last=last,
        observed_at_utc=observed_at,
    )


def _prepared_capture(
    response: LiveTransportResponse,
    *,
    capture_index: int,
    credits_before: int,
    previous_capture_time: datetime | None,
) -> tuple[
    _QuotaAudit | None,
    tuple[dict[str, object], ...] | None,
    str | None,
    str | None,
]:
    quota: _QuotaAudit | None = None
    rows: tuple[dict[str, object], ...] | None = None
    rows_sha256: str | None = None
    error_code: str | None = None
    try:
        if (
            response.network_calls != 1
            or response.provider_calls != 1
            or response.retries != 0
            or response.redirects != 0
        ):
            raise PilotError("REPRISE_TRANSPORT_ACCOUNTING_INVALID")
        if response.http_status != 200:
            raise PilotError("REPRISE_PROVIDER_HTTP_STATUS_INVALID")
        observed = ensure_utc(
            response.first_observed_at_utc, field="reprise_capture_first_observed_at"
        )
        if previous_capture_time is not None and observed <= previous_capture_time:
            raise PilotError("REPRISE_CAPTURE_TIME_NOT_INCREASING")
        quota = _quota(response.headers, observed)
        credits_total = credits_before + quota.last
        if credits_total > MAX_PROVIDER_CREDITS:
            raise PilotError("REPRISE_CREDIT_BUDGET_EXCEEDED")
        rows = _normalize_payload(
            response.payload,
            capture_index=capture_index,
            capture_time=observed,
            quota=quota,
            credits_total=credits_total,
        )
        rows_sha256 = hashlib.sha256(canonical_json_bytes(list(rows))).hexdigest()
        immediate_replay = _normalize_payload(
            bytes(response.payload),
            capture_index=capture_index,
            capture_time=observed,
            quota=quota,
            credits_total=credits_total,
        )
        replay_sha256 = hashlib.sha256(canonical_json_bytes(list(immediate_replay))).hexdigest()
        if replay_sha256 != rows_sha256:
            raise PilotError("REPRISE_OFFLINE_REPLAY_MISMATCH")
    except PilotError as error:
        error_code = error.code
    return quota, rows, rows_sha256, error_code


def _capture_once(
    *,
    capture_index: int,
    credits_before: int,
    previous_capture_time: datetime | None,
    request: PublicProviderRequestV1,
    api_key: str,
    config: PilotConfig,
    store: ConditionalObjectStore,
    transport_factory: TransportFactory,
    clock: Callable[[], datetime],
    effects: _Effects,
) -> _CaptureAudit:
    transport = transport_factory(clock)
    try:
        transport.preflight(request)
        if effects.provider_requests >= MAX_PROVIDER_REQUESTS:
            raise PilotError("REPRISE_PROVIDER_REQUEST_BUDGET_EXCEEDED")
        effects.provider_requests += 1
        response = transport.dispatch(request, api_key=api_key)
    except PilotError:
        raise
    except LiveTransportError:
        raise PilotError("REPRISE_PROVIDER_DISPATCH_FAILED") from None
    except Exception:
        raise PilotError("REPRISE_PROVIDER_DISPATCH_FAILED") from None

    payload_sha256 = hashlib.sha256(response.payload).hexdigest()
    quota, rows, rows_sha256, audit_error = _prepared_capture(
        response,
        capture_index=capture_index,
        credits_before=credits_before,
        previous_capture_time=previous_capture_time,
    )
    if quota is not None:
        effects.confirmed_credit_minimum += quota.last
    envelope = {
        "schema_version": "robin-reprise-collecte-raw-envelope-v1",
        "mission_id": MISSION_ID,
        "repository_sha": config.repository_sha,
        "github_run_id": config.github_run_id,
        "capture_index": capture_index,
        "capture_time_utc": _iso_z(response.first_observed_at_utc),
        "http_status": response.http_status,
        "headers": dict(
            sorted((name.casefold(), value) for name, value in response.headers.items())
        ),
        "transport_accounting": {
            "network_calls": response.network_calls,
            "provider_calls": response.provider_calls,
            "retries": response.retries,
            "redirects": response.redirects,
        },
        "raw_payload_base64": base64.b64encode(response.payload).decode("ascii"),
        "raw_payload_sha256": payload_sha256,
        "raw_payload_bytes": len(response.payload),
        "quota": quota.as_dict() if quota is not None else None,
        "normalized_rows_sha256": rows_sha256,
        "pre_storage_validation_status": "PASS" if audit_error is None else "FAIL",
        "pre_storage_validation_error_code": audit_error,
    }
    envelope_bytes = canonical_json_bytes(envelope)
    key = f"{OBJECT_PREFIX}/{payload_sha256}/capture-{capture_index}.json"
    envelope_sha256 = _put_once(
        store,
        key=key,
        data=envelope_bytes,
        kind=f"capture-{capture_index}",
        effects=effects,
        failure_code="REPRISE_R2_CAPTURE_NOT_CREATED",
    )
    try:
        readback = _get_verified(store, key=key, expected=envelope_bytes, effects=effects)
    except PilotError as error:
        raise _CaptureFailure(
            error.code,
            _FailedCaptureEvidence(
                capture_index=capture_index,
                capture_time_utc=response.first_observed_at_utc,
                quota=quota,
                raw_payload_sha256=payload_sha256,
                raw_object_sha256=envelope_sha256,
                raw_object_key=key,
                validation_error_code=error.code,
                readback_verified=False,
            ),
        ) from None
    if audit_error is not None:
        raise _CaptureFailure(
            audit_error,
            _FailedCaptureEvidence(
                capture_index=capture_index,
                capture_time_utc=response.first_observed_at_utc,
                quota=quota,
                raw_payload_sha256=payload_sha256,
                raw_object_sha256=envelope_sha256,
                raw_object_key=key,
                validation_error_code=audit_error,
                readback_verified=True,
            ),
        )
    if quota is None or rows is None or rows_sha256 is None:
        raise PilotError("REPRISE_CAPTURE_AUDIT_STATE_INVALID")
    try:
        replay_envelope = strict_json_loads(readback)
        if not isinstance(replay_envelope, dict):
            raise ValueError
        encoded = replay_envelope.get("raw_payload_base64")
        if not isinstance(encoded, str):
            raise ValueError
        replay_payload = base64.b64decode(encoded, validate=True)
    except (CaptureContractError, ValueError):
        raise PilotError("REPRISE_OFFLINE_REPLAY_INVALID") from None
    if replay_payload != response.payload:
        raise PilotError("REPRISE_OFFLINE_REPLAY_MISMATCH")
    replay_rows = _normalize_payload(
        replay_payload,
        capture_index=capture_index,
        capture_time=response.first_observed_at_utc,
        quota=quota,
        credits_total=credits_before + quota.last,
    )
    replay_sha256 = hashlib.sha256(canonical_json_bytes(list(replay_rows))).hexdigest()
    if replay_sha256 != rows_sha256:
        raise PilotError("REPRISE_OFFLINE_REPLAY_MISMATCH")
    return _CaptureAudit(
        capture_index=capture_index,
        capture_time_utc=response.first_observed_at_utc,
        quota=quota,
        rows=rows,
        raw_payload_sha256=payload_sha256,
        raw_object_sha256=envelope_sha256,
        raw_object_key=key,
        normalized_rows_sha256=rows_sha256,
    )


_CSV_FIELDS = (
    "capture_index",
    "capture_time_utc",
    "source_timestamp_utc",
    "event_id",
    "match",
    "home_team",
    "away_team",
    "kickoff_utc",
    "bookmaker_key",
    "bookmaker",
    "odds_1",
    "odds_n",
    "odds_2",
    "capture_credits",
    "credits_total_after_capture",
)


def _csv_value(value: object) -> object:
    if isinstance(value, str) and value.startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def _render_csv(rows: tuple[dict[str, object], ...]) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=list(_CSV_FIELDS), lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow({field: _csv_value(row[field]) for field in _CSV_FIELDS})
    return stream.getvalue().encode("utf-8")


def _render_html(
    rows: tuple[dict[str, object], ...],
    *,
    status: str,
    credits_exact: int | None,
    credits_confirmed_minimum: int,
    partial_reason_code: str | None,
) -> bytes:
    labels = {
        "capture_index": "Capture",
        "capture_time_utc": "Heure de capture (UTC)",
        "source_timestamp_utc": "Heure source (UTC)",
        "match": "Match",
        "kickoff_utc": "Coup d’envoi (UTC)",
        "bookmaker": "Bookmaker",
        "odds_1": "1",
        "odds_n": "N",
        "odds_2": "2",
        "capture_credits": "Crédits capture",
        "credits_total_after_capture": "Crédits cumulés",
    }
    visible = tuple(labels)
    headers = "".join(f"<th>{html.escape(labels[field])}</th>" for field in visible)
    body = "".join(
        "<tr>" + "".join(f"<td>{html.escape(str(row[field]))}</td>" for field in visible) + "</tr>"
        for row in rows
    )
    if credits_exact is None:
        consumption = (
            f"au moins {credits_confirmed_minimum} crédit(s) confirmé(s), "
            f"plafond autorisé {MAX_PROVIDER_CREDITS}"
        )
    else:
        consumption = f"{credits_exact} crédit(s) consommé(s)"
    status_line = status
    if partial_reason_code is not None:
        status_line += f" · arrêt expurgé {partial_reason_code}"
    document = (
        '<!doctype html><html lang="fr"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        "<title>Robin — reprise collecte</title>"
        "<style>body{font-family:system-ui,sans-serif;margin:2rem;color:#172033}"
        "table{border-collapse:collapse;width:100%}th,td{border:1px solid #c9d1df;"
        "padding:.55rem;text-align:left}th{background:#eef3fa}caption{text-align:left;"
        "font-weight:700;margin-bottom:.7rem}.meta{margin:0 0 1rem}</style></head><body>"
        f'<h1>Reprise collecte — {html.escape(status_line)}</h1><p class="meta">'
        f"{len(rows)} lignes vérifiées · {html.escape(consumption)} · aucun pari</p>"
        f"<table><caption>Matchs, cotes, heures et consommation</caption><thead><tr>{headers}"
        f"</tr></thead><tbody>{body}</tbody></table></body></html>"
    )
    return document.encode("utf-8")


def _write_exclusive(path: Path, data: bytes) -> None:
    try:
        with path.open("xb") as stream:
            stream.write(data)
            stream.flush()
    except OSError:
        raise PilotError("REPRISE_LOCAL_DELIVERY_WRITE_FAILED") from None


def _private_report(
    *,
    config: PilotConfig,
    captures: tuple[_CaptureAudit, ...],
    rows: tuple[dict[str, object], ...],
    effects: _Effects,
    status: str,
    failure_stage: str | None,
    failure_code: str | None,
    credits_exact: int | None,
    credits_confirmed_minimum: int,
    credit_accounting_status: str,
    r2_put_requests: int,
    r2_get_requests: int,
    failed_capture: _FailedCaptureEvidence | None,
) -> dict[str, object]:
    return {
        "schema_version": "robin-reprise-collecte-private-report-v1",
        "mission_id": MISSION_ID,
        "status": status,
        "repository_sha": config.repository_sha,
        "github_run_id": config.github_run_id,
        "claim_ids": list(CLAIM_IDS),
        "validated_capture_count": len(captures),
        "provider_dispatch_attempts": effects.provider_requests,
        "credits_consumed_exact": credits_exact,
        "credits_consumed_confirmed_minimum": credits_confirmed_minimum,
        "credits_consumed_authorized_upper_bound": MAX_PROVIDER_CREDITS,
        "credit_accounting_status": credit_accounting_status,
        "failure_stage": failure_stage,
        "failure_code": failure_code,
        "effect_accounting": {
            "r2_put_requests": r2_put_requests,
            "r2_get_requests": r2_get_requests,
            "dns_resolutions": effects.dns_resolutions,
            "secret_reads": effects.secret_reads,
        },
        "captures": [
            {
                "capture_index": capture.capture_index,
                "capture_time_utc": _iso_z(capture.capture_time_utc),
                "quota": capture.quota.as_dict(),
                "raw_payload_sha256": capture.raw_payload_sha256,
                "raw_object_sha256": capture.raw_object_sha256,
                "raw_object_key": capture.raw_object_key,
                "normalized_rows_sha256": capture.normalized_rows_sha256,
                "row_count": len(capture.rows),
            }
            for capture in captures
        ],
        "failed_capture": failed_capture.as_dict() if failed_capture is not None else None,
        "rows": list(rows),
        "retention": {
            "raw_payloads": "R2_IMMUTABLE_PRIVATE_ONLY",
            "public_plaintext_odds": False,
            "offline_replay_verified": bool(captures) and failed_capture is None,
        },
        "conclusions": {
            "recurrence": "COLLECTE_RECURRENTE_NON_ENCORE_DEMONTREE",
            "edge": "AUCUN_EDGE_VALIDE_PAR_CE_PILOTE",
        },
    }


def _failure_stage(code: str, *, capture_index: int) -> str:
    prefix = f"CAPTURE_{capture_index}"
    if code == "REPRISE_PROVIDER_DISPATCH_FAILED":
        return f"{prefix}_DISPATCH"
    if "REPLAY" in code or "READBACK" in code:
        return f"{prefix}_REPLAY"
    if code.startswith("REPRISE_R2_"):
        return f"{prefix}_PERSISTENCE"
    if code in {
        "REPRISE_SECOND_CAPTURE_QUOTA_INSUFFICIENT",
        "REPRISE_TIME_BUDGET_EXCEEDED",
        "REPRISE_MISSION_EXPIRED",
        "REPRISE_DNS_RESOLUTION_EXPIRED",
    }:
        return f"{prefix}_AUTHORIZATION"
    return f"{prefix}_AUDIT"


def _credit_accounting(
    captures: tuple[_CaptureAudit, ...], effects: _Effects
) -> tuple[int | None, int, str]:
    confirmed = effects.confirmed_credit_minimum
    if effects.provider_requests == len(captures):
        return confirmed, confirmed, "EXACT"
    return None, confirmed, "BOUNDED_UNKNOWN"


def _local_delivery(
    *,
    config: PilotConfig,
    captures: tuple[_CaptureAudit, ...],
    rows: tuple[dict[str, object], ...],
    effects: _Effects,
    status: str,
    failure_stage: str | None,
    failure_code: str | None,
    private_report_r2_status: str,
    private_report_r2_sha256: str | None,
    failed_capture: _FailedCaptureEvidence | None = None,
) -> dict[str, object]:
    credits_exact, credits_minimum, accounting_status = _credit_accounting(captures, effects)
    report = _private_report(
        config=config,
        captures=captures,
        rows=rows,
        effects=effects,
        status=status,
        failure_stage=failure_stage,
        failure_code=failure_code,
        credits_exact=credits_exact,
        credits_confirmed_minimum=credits_minimum,
        credit_accounting_status=accounting_status,
        r2_put_requests=effects.r2_puts,
        r2_get_requests=effects.r2_gets,
        failed_capture=failed_capture,
    )
    private_bytes = canonical_json_bytes(report)
    csv_bytes = _render_csv(rows)
    html_bytes = _render_html(
        rows,
        status=status,
        credits_exact=credits_exact,
        credits_confirmed_minimum=credits_minimum,
        partial_reason_code=failure_code,
    )
    event_ids = {cast(str, row["event_id"]) for row in rows}
    bookmaker_ids = {cast(str, row["bookmaker_key"]) for row in rows}
    source_timestamps = [cast(str, row["source_timestamp_utc"]) for row in rows]
    public_receipt: dict[str, object] = {
        "schema_version": "robin-reprise-collecte-public-receipt-v1",
        "mission_id": MISSION_ID,
        "status": status,
        "repository_sha": config.repository_sha,
        "github_run_id": config.github_run_id,
        "claim_ids": list(CLAIM_IDS),
        "capture_count": len(captures),
        "validated_capture_count": len(captures),
        "provider_requests": effects.provider_requests,
        "provider_dispatch_attempts": effects.provider_requests,
        "credits_consumed": credits_exact,
        "credits_consumed_confirmed_minimum": credits_minimum,
        "credits_consumed_authorized_upper_bound": MAX_PROVIDER_CREDITS,
        "credit_accounting_status": accounting_status,
        "partial_reason_code": failure_code,
        "failure_stage": failure_stage,
        "row_count": len(rows),
        "match_count": len(event_ids),
        "bookmaker_count": len(bookmaker_ids),
        "capture_times_utc": [_iso_z(capture.capture_time_utc) for capture in captures],
        "source_timestamp_min_utc": min(source_timestamps) if source_timestamps else None,
        "source_timestamp_max_utc": max(source_timestamps) if source_timestamps else None,
        "r2_put_requests": effects.r2_puts,
        "r2_get_requests": effects.r2_gets,
        "dns_resolutions": effects.dns_resolutions,
        "secret_reads": effects.secret_reads,
        "automatic_retries": 0,
        "purchases": 0,
        "real_bets": 0,
        "raw_capture_object_sha256": [
            *[capture.raw_object_sha256 for capture in captures],
            *([failed_capture.raw_object_sha256] if failed_capture is not None else []),
        ],
        "private_report_r2_status": private_report_r2_status,
        "private_report_r2_sha256": private_report_r2_sha256,
        "private_json_sha256": hashlib.sha256(private_bytes).hexdigest(),
        "csv_sha256": hashlib.sha256(csv_bytes).hexdigest(),
        "html_sha256": hashlib.sha256(html_bytes).hexdigest(),
        "recurrence_status": "COLLECTE_RECURRENTE_NON_ENCORE_DEMONTREE",
        "edge_status": "AUCUN_EDGE_VALIDE_PAR_CE_PILOTE",
    }
    _write_exclusive(config.output_directory / "reprise-collecte-private.json", private_bytes)
    _write_exclusive(config.output_directory / "reprise-collecte.csv", csv_bytes)
    _write_exclusive(config.output_directory / "reprise-collecte.html", html_bytes)
    _write_exclusive(
        config.output_directory / "public-receipt.json",
        canonical_json_bytes(public_receipt),
    )
    return public_receipt


def run_reprise_collecte(
    config: PilotConfig,
    *,
    store: ConditionalObjectStore,
    transport_factory: TransportFactory,
    secret_reader: SecretReader,
    resolver: Callable[[], NetworkResolution],
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    monotonic: Callable[[], float] = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep,
) -> dict[str, object]:
    """Run the single authorized pilot; every uncertainty terminates without retry."""

    _validate_config(config)
    started_at = ensure_utc(clock(), field="reprise_started_at")
    manifest = _load_manifest(config.manifest_path, started_at)
    started_monotonic = monotonic()
    effects = _Effects()
    api_key = ""

    first_reservation = _reservation_bytes(
        config=config,
        capture_index=1,
        recorded_at=started_at,
        first_capture_sha256=None,
    )
    _put_once(
        store,
        key=f"{OBJECT_PREFIX}/attempt-1-reservation.json",
        data=first_reservation,
        kind="attempt-1-reservation",
        effects=effects,
        failure_code="REPRISE_R2_RESERVATION_NOT_CREATED",
    )
    _assert_time_budget(
        manifest=manifest,
        clock=clock,
        monotonic=monotonic,
        started_monotonic=started_monotonic,
    )
    try:
        effects.dns_resolutions += 1
        if effects.dns_resolutions > 1:
            raise PilotError("REPRISE_DNS_BUDGET_EXCEEDED")
        resolution = resolver()
        if resolution.resolution_operations != 1:
            raise PilotError("REPRISE_DNS_RESOLUTION_INVALID")
        resolution.assert_current(clock())
        effects.secret_reads += 1
        if effects.secret_reads > 1:
            raise PilotError("REPRISE_SECRET_READ_BUDGET_EXCEEDED")
        try:
            api_key = validate_provider_secret(secret_reader.read())
        except LiveTransportError:
            raise PilotError("REPRISE_PROVIDER_SECRET_INVALID") from None
        request = PublicProviderRequestV1.from_spec(
            ProviderRequestSpec(
                endpoint=f"/v4/sports/{SPORT_KEY}/odds",
                sport_key=SPORT_KEY,
                region=REGION,
                markets=(MARKET,),
                timeout_seconds=20,
            ),
            maximum_response_bytes=MAX_RESPONSE_BYTES,
            approved_provider_ip_address=resolution.selected_ip_address,
        )
        try:
            first = _capture_once(
                capture_index=1,
                credits_before=0,
                previous_capture_time=None,
                request=request,
                api_key=api_key,
                config=config,
                store=store,
                transport_factory=transport_factory,
                clock=clock,
                effects=effects,
            )
        except PilotError as error:
            if effects.provider_requests == 0:
                raise
            return _local_delivery(
                config=config,
                captures=(),
                rows=(),
                effects=effects,
                status="PARTIEL",
                failure_stage=_failure_stage(error.code, capture_index=1),
                failure_code=error.code,
                private_report_r2_status="NOT_ATTEMPTED_PARTIAL",
                private_report_r2_sha256=None,
                failed_capture=(error.evidence if isinstance(error, _CaptureFailure) else None),
            )
        try:
            credits = first.quota.last
            if (
                first.quota.remaining < MAX_CREDITS_PER_REQUEST
                or credits + MAX_CREDITS_PER_REQUEST > MAX_PROVIDER_CREDITS
            ):
                raise PilotError("REPRISE_SECOND_CAPTURE_QUOTA_INSUFFICIENT")
            _assert_time_budget(
                manifest=manifest,
                clock=clock,
                monotonic=monotonic,
                started_monotonic=started_monotonic,
            )
            sleeper(float(config.interval_seconds))
            second_reservation_time = _assert_time_budget(
                manifest=manifest,
                clock=clock,
                monotonic=monotonic,
                started_monotonic=started_monotonic,
            )
            resolution.assert_current(second_reservation_time)
            second_reservation = _reservation_bytes(
                config=config,
                capture_index=2,
                recorded_at=second_reservation_time,
                first_capture_sha256=first.raw_object_sha256,
            )
            _put_once(
                store,
                key=f"{OBJECT_PREFIX}/attempt-2-reservation.json",
                data=second_reservation,
                kind="attempt-2-reservation",
                effects=effects,
                failure_code="REPRISE_R2_RESERVATION_NOT_CREATED",
            )
            resolution.assert_current(clock())
            second = _capture_once(
                capture_index=2,
                credits_before=credits,
                previous_capture_time=first.capture_time_utc,
                request=request,
                api_key=api_key,
                config=config,
                store=store,
                transport_factory=transport_factory,
                clock=clock,
                effects=effects,
            )
            credits += second.quota.last
            if (
                second.quota.used != first.quota.used + second.quota.last
                or second.quota.remaining != first.quota.remaining - second.quota.last
                or credits > MAX_PROVIDER_CREDITS
            ):
                raise PilotError("REPRISE_QUOTA_SEQUENCE_INVALID")
        except PilotError as error:
            return _local_delivery(
                config=config,
                captures=(first,),
                rows=first.rows,
                effects=effects,
                status="PARTIEL",
                failure_stage=_failure_stage(error.code, capture_index=2),
                failure_code=error.code,
                private_report_r2_status="NOT_ATTEMPTED_PARTIAL",
                private_report_r2_sha256=None,
                failed_capture=(error.evidence if isinstance(error, _CaptureFailure) else None),
            )
        captures = (first, second)
        rows = tuple(
            sorted(
                (*first.rows, *second.rows),
                key=lambda row: (
                    cast(int, row["capture_index"]),
                    cast(str, row["kickoff_utc"]),
                    cast(str, row["event_id"]),
                    cast(str, row["bookmaker_key"]),
                ),
            )
        )
        report = _private_report(
            config=config,
            captures=captures,
            rows=rows,
            effects=effects,
            status="COLLECTE_REELLE_VERIFIEE",
            failure_stage=None,
            failure_code=None,
            credits_exact=credits,
            credits_confirmed_minimum=credits,
            credit_accounting_status="EXACT",
            r2_put_requests=effects.r2_puts + 1,
            r2_get_requests=effects.r2_gets + 1,
            failed_capture=None,
        )
        private_bytes = canonical_json_bytes(report)
        report_key = f"{OBJECT_PREFIX}/private-report.json"
        try:
            report_sha256 = _put_once(
                store,
                key=report_key,
                data=private_bytes,
                kind="private-report",
                effects=effects,
                failure_code="REPRISE_R2_REPORT_NOT_CREATED",
            )
            _get_verified(store, key=report_key, expected=private_bytes, effects=effects)
        except PilotError as error:
            return _local_delivery(
                config=config,
                captures=captures,
                rows=rows,
                effects=effects,
                status="PARTIEL",
                failure_stage="PRIVATE_REPORT_PERSISTENCE",
                failure_code=error.code,
                private_report_r2_status="UNVERIFIED",
                private_report_r2_sha256=None,
            )
        return _local_delivery(
            config=config,
            captures=captures,
            rows=rows,
            effects=effects,
            status="COLLECTE_REELLE_VERIFIEE",
            failure_stage=None,
            failure_code=None,
            private_report_r2_status="VERIFIED",
            private_report_r2_sha256=report_sha256,
        )
    finally:
        api_key = ""


__all__ = [
    "CLAIM_IDS",
    "MANDATE_SHA256",
    "MISSION_ID",
    "NetworkResolution",
    "PilotConfig",
    "PilotError",
    "resolve_provider_once",
    "run_reprise_collecte",
]
