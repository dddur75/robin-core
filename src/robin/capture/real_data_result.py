"""Bounded real-data result mission for five football leagues and two markets.

The module composes the existing strict HTTPS transport and immutable R2
adapter.  Every provider slot is reserved durably before dispatch, so another
workflow run can inspect or resume the fixed slot without silently retrying it.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import html
import io
import math
import re
import time
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
from robin.capture.reprise_collecte import NetworkResolution
from robin.prospective_observatory.chronos_control_plane import (
    ConditionalObjectStore,
    ConditionalPutOutcome,
)

MISSION_ID = "ROBIN_REAL_DATA_RESULT_20261003"
MANDATE_SHA256 = "f01be9dddc7d7a098caec9fc3bf623ab2b53803ce03b6202f5b3fcdcad0ad25b"
SPORT_KEYS = (
    "soccer_epl",
    "soccer_france_ligue_one",
    "soccer_spain_la_liga",
    "soccer_germany_bundesliga",
    "soccer_italy_serie_a",
)
MARKETS: tuple[Literal["h2h", "totals"], ...] = ("h2h", "totals")
REGION: Literal["eu"] = "eu"
CYCLE_COUNT = 3
SUCCESSOR_PROVIDER_SLOTS = CYCLE_COUNT * len(SPORT_KEYS)
PRIOR_PROVIDER_REQUESTS = 1
PRIOR_CREDITS_RESERVED = 4
MISSION_PROVIDER_REQUESTS_MAX = 40
MISSION_PROVIDER_CREDITS_MAX = 60
MAX_CREDITS_PER_REQUEST = 2
MAX_RESPONSE_BYTES = 5_242_880
MAX_SOURCE_AGE = timedelta(minutes=15)
MAX_R2_PUTS_PER_RUN = 34
MAX_R2_GETS_PER_RUN = 34
OBJECT_PREFIX = f"robin/real-data-result/{MISSION_ID}"
CLAIM_IDS = (
    "DATA.ROBIN.REAL.RESULT.CAPTURES.V1.001",
    "DATA.ROBIN.REAL.RESULT.VIEW.V1.001",
    "GOV.ROBIN.REAL.RESULT.CONSUMPTION.V1.001",
)
_QUOTA_STOP_CODES = frozenset(
    {
        "RESULT_QUOTA_HEADERS_MISSING",
        "RESULT_QUOTA_HEADERS_INVALID",
        "RESULT_CREDIT_COST_UNEXPECTED",
        "RESULT_TRANSPORT_ACCOUNTING_INVALID",
    }
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
    "github_actions_workflow_dispatch_max_3_after_merge",
    "github_actions_artifact_upload_normalized_public_repository",
    "provider_public_dns_resolution_per_dispatch_max_1",
    "provider_secret_read_per_dispatch_max_1",
    "provider_https_get_successor_slot_max_15",
    "provider_credit_reservation_successor_max_30",
    "provider_http_cumulative_max_40_with_prior_baseline_1",
    "provider_credit_cumulative_max_60_with_prior_reserve_4",
    "r2_immutable_attempt_reservation_before_each_provider_request",
    "r2_immutable_raw_capture_and_exact_readback",
    "r2_immutable_cycle_receipt_and_final_report",
    "offline_replay_from_r2_readback",
    "normalized_csv_html_consultable_delivery",
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
    "robin-real-data.json",
    "robin-real-data.csv",
    "robin-real-data.html",
)


class ResultError(RuntimeError):
    """Stable failure code; exception text never includes provider material."""

    def __init__(
        self,
        code: str,
        *,
        diagnostic: dict[str, object] | None = None,
    ) -> None:
        self.code = code
        self.diagnostic = diagnostic
        super().__init__(code)


class TransportFactory(Protocol):
    def __call__(self, clock: Callable[[], datetime]) -> LiveTransport: ...


@dataclass(frozen=True, slots=True)
class ResultConfig:
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
class _Quota:
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


@dataclass(slots=True)
class _Effects:
    r2_puts: int = 0
    r2_gets: int = 0
    reserved_slots: int = 0
    provider_requests: int = 0
    quota_observed_attempts: int = 0
    credit_cost_observed_attempts: int = 0
    credits_confirmed: int = 0
    credits_observed_excess: int = 0
    credit_bound_valid: bool = True
    dns_resolutions: int = 0
    secret_reads: int = 0

    @property
    def credits_new_upper_bound(self) -> int | None:
        if not self.credit_bound_valid:
            return None
        return self.reserved_slots * MAX_CREDITS_PER_REQUEST + self.credits_observed_excess


_BranchResult = tuple[dict[str, object], tuple[dict[str, object], ...], _Quota | None]


def _iso_z(value: datetime) -> str:
    return (
        ensure_utc(value, field="real_result_timestamp")
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def _parse_time(value: object, *, code: str) -> datetime:
    if not isinstance(value, str) or not value or len(value) > 64:
        raise ResultError(code)
    try:
        return ensure_utc(
            datetime.fromisoformat(value.replace("Z", "+00:00")),
            field="real_result_parsed_timestamp",
        )
    except (TypeError, ValueError):
        raise ResultError(code) from None


def _text(value: object, *, code: str, maximum: int = 200) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.strip() != value
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ResultError(code)
    return value


def _mapping(value: object, *, code: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise ResultError(code)
    return cast(Mapping[str, object], value)


def _list(value: object, *, code: str, maximum: int) -> list[object]:
    if not isinstance(value, list) or len(value) > maximum:
        raise ResultError(code)
    return cast(list[object], value)


def _price(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ResultError("RESULT_ODDS_PRICE_INVALID")
    parsed = float(value)
    if not math.isfinite(parsed) or not 1.0 < parsed <= 10_000.0:
        raise ResultError("RESULT_ODDS_PRICE_INVALID")
    return parsed


def _point(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ResultError("RESULT_TOTALS_POINT_INVALID")
    parsed = float(value)
    if not math.isfinite(parsed) or not 0.0 < parsed <= 100.0:
        raise ResultError("RESULT_TOTALS_POINT_INVALID")
    return parsed


def _validate_config(config: ResultConfig) -> None:
    if config.github_run_attempt != 1:
        raise ResultError("RESULT_WORKFLOW_RERUN_FORBIDDEN")
    if re.fullmatch(r"[0-9a-f]{40}", config.repository_sha) is None:
        raise ResultError("RESULT_REPOSITORY_SHA_INVALID")
    if re.fullmatch(r"[1-9][0-9]{0,19}", config.github_run_id) is None:
        raise ResultError("RESULT_GITHUB_RUN_ID_INVALID")
    if not 60 <= config.interval_seconds <= 300:
        raise ResultError("RESULT_CYCLE_INTERVAL_INVALID")
    if not config.manifest_path.is_file():
        raise ResultError("RESULT_MANIFEST_MISSING")
    if not config.output_directory.is_dir() or config.output_directory.is_symlink():
        raise ResultError("RESULT_OUTPUT_DIRECTORY_INVALID")
    if any((config.output_directory / name).exists() for name in _OUTPUT_FILENAMES):
        raise ResultError("RESULT_OUTPUT_ALREADY_EXISTS")
    for variable, expected in _SAFETY_LOCKS.items():
        if config.safety_environment.get(variable) != expected:
            raise ResultError("RESULT_SAFETY_LOCK_INVALID")


def _load_manifest(path: Path, now: datetime) -> _Manifest:
    try:
        decoded = strict_json_loads(path.read_bytes())
    except (CaptureContractError, OSError):
        raise ResultError("RESULT_MANIFEST_INVALID") from None
    if not isinstance(decoded, dict):
        raise ResultError("RESULT_MANIFEST_INVALID")
    manifest = cast(dict[str, object], decoded)
    expected = {
        "mission_id": MISSION_ID,
        "authorized_stages": ["E1", "E2", "E3A", "E3B"],
        "maximum_stage": "E3B",
        "external_effects": _EXPECTED_EFFECTS,
        "compute_budget": 16_000,
        "time_budget": 28_800,
        "source_hash": MANDATE_SHA256,
    }
    if set(manifest) != _MANIFEST_FIELDS or any(
        manifest.get(key) != value for key, value in expected.items()
    ):
        raise ResultError("RESULT_MANIFEST_INVALID")
    expires_at = _parse_time(manifest.get("expires_at"), code="RESULT_MANIFEST_INVALID")
    if ensure_utc(now, field="real_result_manifest_now") >= expires_at:
        raise ResultError("RESULT_MISSION_EXPIRED")
    return _Manifest(expires_at=expires_at, time_budget=28_800)


def _assert_authority(
    manifest: _Manifest,
    *,
    clock: Callable[[], datetime],
    monotonic: Callable[[], float],
    started_monotonic: float,
) -> datetime:
    now = ensure_utc(clock(), field="real_result_effect_time")
    elapsed = monotonic() - started_monotonic
    if elapsed < 0 or elapsed > manifest.time_budget:
        raise ResultError("RESULT_ACTIVE_TIME_BUDGET_EXCEEDED")
    if now >= manifest.expires_at:
        raise ResultError("RESULT_MISSION_EXPIRED")
    return now


def _quota(headers: Mapping[str, str], observed_at: datetime) -> _Quota:
    normalized = {name.casefold(): value for name, value in headers.items()}
    names = ("x-requests-remaining", "x-requests-used", "x-requests-last")
    if len(normalized) != len(headers) or any(name not in normalized for name in names):
        raise ResultError("RESULT_QUOTA_HEADERS_MISSING")
    values: list[int] = []
    for name in names:
        value = normalized[name]
        if not isinstance(value, str) or not value.isascii() or not value.isdecimal():
            raise ResultError("RESULT_QUOTA_HEADERS_INVALID")
        number = int(value)
        if number < 0 or number > 2**63 - 1:
            raise ResultError("RESULT_QUOTA_HEADERS_INVALID")
        values.append(number)
    remaining, used, last = values
    if not 1 <= last <= MAX_CREDITS_PER_REQUEST or used < last:
        raise ResultError("RESULT_CREDIT_COST_UNEXPECTED")
    return _Quota(remaining=remaining, used=used, last=last, observed_at_utc=observed_at)


def _observed_credit_cost(headers: Mapping[str, str]) -> int | None:
    normalized = {name.casefold(): value for name, value in headers.items()}
    if len(normalized) != len(headers):
        return None
    value = normalized.get("x-requests-last")
    if not isinstance(value, str) or not value.isascii() or not value.isdecimal():
        return None
    observed = int(value)
    if observed < 0 or observed > 2**63 - 1:
        return None
    return observed


def _limitation(
    code: str,
    *,
    event_id: str | None = None,
    bookmaker_key: str | None = None,
    market_key: str | None = None,
) -> dict[str, object]:
    return {
        "code": code,
        "event_id": event_id,
        "bookmaker_key": bookmaker_key,
        "market_key": market_key,
    }


def _normalize_payload(
    payload: bytes,
    *,
    cycle_index: int,
    sport_key: str,
    capture_time: datetime,
    quota: _Quota,
) -> tuple[tuple[dict[str, object], ...], tuple[dict[str, object], ...]]:
    try:
        decoded = strict_json_loads(payload)
    except CaptureContractError:
        raise ResultError("RESULT_PROVIDER_JSON_INVALID") from None
    if not isinstance(decoded, list) or len(decoded) > 500:
        raise ResultError("RESULT_PROVIDER_PAYLOAD_SHAPE_INVALID")
    if not decoded:
        return (), ()
    rows: list[dict[str, object]] = []
    limitations: list[dict[str, object]] = []
    identities: set[tuple[str, str, str, float | None, str]] = set()
    for raw_event in decoded:
        event = _mapping(raw_event, code="RESULT_EVENT_INVALID")
        event_id = _text(event.get("id"), code="RESULT_EVENT_INVALID", maximum=160)
        if event.get("sport_key") != sport_key:
            raise ResultError("RESULT_EVENT_SPORT_MISMATCH")
        sport_title_value = event.get("sport_title", sport_key)
        sport_title = _text(sport_title_value, code="RESULT_EVENT_INVALID", maximum=160)
        home = _text(event.get("home_team"), code="RESULT_TEAM_INVALID")
        away = _text(event.get("away_team"), code="RESULT_TEAM_INVALID")
        if home == away:
            raise ResultError("RESULT_TEAM_INVALID")
        kickoff = _parse_time(event.get("commence_time"), code="RESULT_KICKOFF_INVALID")
        if kickoff <= capture_time:
            limitations.append(_limitation("RESULT_EVENT_NOT_UPCOMING", event_id=event_id))
            continue
        bookmakers = _list(event.get("bookmakers"), code="RESULT_BOOKMAKERS_INVALID", maximum=100)
        if not bookmakers:
            limitations.append(_limitation("RESULT_BOOKMAKERS_EMPTY", event_id=event_id))
            continue
        for raw_bookmaker in bookmakers:
            try:
                bookmaker = _mapping(raw_bookmaker, code="RESULT_BOOKMAKER_INVALID")
                bookmaker_key = _text(
                    bookmaker.get("key"), code="RESULT_BOOKMAKER_INVALID", maximum=100
                )
                bookmaker_title = _text(
                    bookmaker.get("title"), code="RESULT_BOOKMAKER_INVALID", maximum=160
                )
                bookmaker_source_time = _parse_time(
                    bookmaker.get("last_update"), code="RESULT_SOURCE_TIMESTAMP_INVALID"
                )
            except ResultError as error:
                limitations.append(_limitation(error.code, event_id=event_id))
                continue
            if (
                bookmaker_source_time > capture_time + timedelta(minutes=5)
                or bookmaker_source_time >= kickoff
                or capture_time - bookmaker_source_time > MAX_SOURCE_AGE
            ):
                limitations.append(
                    _limitation(
                        "RESULT_SOURCE_TIMESTAMP_STALE_OR_INVALID",
                        event_id=event_id,
                        bookmaker_key=bookmaker_key,
                    )
                )
                continue
            try:
                markets = _list(bookmaker.get("markets"), code="RESULT_MARKETS_INVALID", maximum=20)
            except ResultError as error:
                limitations.append(
                    _limitation(error.code, event_id=event_id, bookmaker_key=bookmaker_key)
                )
                continue
            by_key: dict[str, list[Mapping[str, object]]] = {"h2h": [], "totals": []}
            for raw_market in markets:
                if not isinstance(raw_market, dict):
                    continue
                market = cast(Mapping[str, object], raw_market)
                key = market.get("key")
                if isinstance(key, str) and key in by_key:
                    by_key[key].append(market)
            for market_key in MARKETS:
                selected = by_key[market_key]
                if not selected:
                    limitations.append(
                        _limitation(
                            "RESULT_MARKET_MISSING",
                            event_id=event_id,
                            bookmaker_key=bookmaker_key,
                            market_key=market_key,
                        )
                    )
                    continue
                if len(selected) > 1:
                    limitations.append(
                        _limitation(
                            "RESULT_MARKET_DUPLICATED",
                            event_id=event_id,
                            bookmaker_key=bookmaker_key,
                            market_key=market_key,
                        )
                    )
                    continue
                try:
                    raw_market_source_time = selected[0].get("last_update")
                    if raw_market_source_time is None:
                        market_source_time = bookmaker_source_time
                        source_timestamp_origin = "BOOKMAKER_LAST_UPDATE_FALLBACK"
                    else:
                        market_source_time = _parse_time(
                            raw_market_source_time,
                            code="RESULT_SOURCE_TIMESTAMP_INVALID",
                        )
                        source_timestamp_origin = "MARKET_LAST_UPDATE"
                    if (
                        market_source_time > capture_time + timedelta(minutes=5)
                        or market_source_time >= kickoff
                        or capture_time - market_source_time > MAX_SOURCE_AGE
                    ):
                        raise ResultError("RESULT_SOURCE_TIMESTAMP_STALE_OR_INVALID")
                    outcomes = _list(
                        selected[0].get("outcomes"),
                        code="RESULT_OUTCOMES_INVALID",
                        maximum=40,
                    )
                    prepared: list[tuple[str, float, float | None]] = []
                    for raw_outcome in outcomes:
                        outcome = _mapping(raw_outcome, code="RESULT_OUTCOME_INVALID")
                        name = _text(outcome.get("name"), code="RESULT_OUTCOME_INVALID")
                        price = _price(outcome.get("price"))
                        point = _point(outcome.get("point")) if market_key == "totals" else None
                        prepared.append((name, price, point))
                    if market_key == "h2h":
                        if len(prepared) != 3 or {
                            name for name, _price_value, _point_value in prepared
                        } != {home, "Draw", away}:
                            raise ResultError("RESULT_H2H_INCOMPLETE")
                    else:
                        totals: dict[float, set[str]] = {}
                        for name, _price_value, point in prepared:
                            if point is None:
                                raise ResultError("RESULT_TOTALS_POINT_INVALID")
                            totals.setdefault(point, set()).add(name)
                        if (
                            len(prepared) != 2
                            or len(totals) != 1
                            or any(names != {"Over", "Under"} for names in totals.values())
                        ):
                            raise ResultError("RESULT_TOTALS_INCOMPLETE")
                except ResultError as error:
                    limitations.append(
                        _limitation(
                            error.code,
                            event_id=event_id,
                            bookmaker_key=bookmaker_key,
                            market_key=market_key,
                        )
                    )
                    continue
                for outcome_name, price, point in prepared:
                    identity = (event_id, bookmaker_key, market_key, point, outcome_name)
                    if identity in identities:
                        raise ResultError("RESULT_ROW_DUPLICATED")
                    identities.add(identity)
                    rows.append(
                        {
                            "cycle_index": cycle_index,
                            "sport_key": sport_key,
                            "sport_title": sport_title,
                            "capture_time_utc": _iso_z(capture_time),
                            "source_timestamp_utc": _iso_z(market_source_time),
                            "source_timestamp_origin": source_timestamp_origin,
                            "event_id": event_id,
                            "match": f"{home} — {away}",
                            "home_team": home,
                            "away_team": away,
                            "kickoff_utc": _iso_z(kickoff),
                            "bookmaker_key": bookmaker_key,
                            "bookmaker": bookmaker_title,
                            "market_key": market_key,
                            "outcome": outcome_name,
                            "point": point,
                            "price": price,
                            "quota_remaining": quota.remaining,
                        }
                    )
    if not rows:
        raise ResultError("RESULT_NO_VALID_ODDS")
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
    return tuple(rows), tuple(limitations)


def _put_immutable(
    store: ConditionalObjectStore,
    *,
    key: str,
    data: bytes,
    kind: str,
    effects: _Effects,
    allow_preexisting: bool = False,
) -> tuple[str, str]:
    payload_sha256 = hashlib.sha256(data).hexdigest()
    callbacks = 0

    def on_dispatch() -> None:
        nonlocal callbacks
        if effects.r2_puts >= MAX_R2_PUTS_PER_RUN:
            raise ResultError("RESULT_R2_PUT_BUDGET_EXCEEDED")
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
    except ResultError:
        raise
    except Exception as error:
        raise ResultError(
            "RESULT_R2_PUT_FAILED",
            diagnostic=_exception_diagnostic(
                stage="R2_WRITE",
                code="RESULT_R2_PUT_FAILED",
                error=error,
            ),
        ) from None
    if callbacks != 1 or result.transport_attempts != 1 or result.automatic_retry_possible:
        raise ResultError("RESULT_R2_PUT_ACCOUNTING_INVALID")
    if result.outcome is ConditionalPutOutcome.CREATED:
        return "CREATED", payload_sha256
    if allow_preexisting and result.outcome is ConditionalPutOutcome.PRECONDITION_FAILED:
        return "PREEXISTING", payload_sha256
    raise ResultError("RESULT_R2_IMMUTABLE_WRITE_REJECTED")


def _get_observed(
    store: ConditionalObjectStore,
    *,
    key: str,
    effects: _Effects,
    missing_code: str,
) -> bytes:
    if effects.r2_gets >= MAX_R2_GETS_PER_RUN:
        raise ResultError("RESULT_R2_GET_BUDGET_EXCEEDED")
    effects.r2_gets += 1
    try:
        observed = store.get_object(key)
    except Exception as error:
        raise ResultError(
            "RESULT_R2_READBACK_FAILED",
            diagnostic=_exception_diagnostic(
                stage="R2_READBACK",
                code="RESULT_R2_READBACK_FAILED",
                error=error,
            ),
        ) from None
    if observed is None:
        raise ResultError(missing_code)
    digest = hashlib.sha256(observed.data).hexdigest()
    if observed.metadata.get("sha256") != digest:
        raise ResultError("RESULT_R2_READBACK_METADATA_MISMATCH")
    return observed.data


def _get_optional(
    store: ConditionalObjectStore,
    *,
    key: str,
    effects: _Effects,
) -> bytes | None:
    if effects.r2_gets >= MAX_R2_GETS_PER_RUN:
        raise ResultError("RESULT_R2_GET_BUDGET_EXCEEDED")
    effects.r2_gets += 1
    try:
        observed = store.get_object(key)
    except Exception as error:
        raise ResultError(
            "RESULT_R2_READBACK_FAILED",
            diagnostic=_exception_diagnostic(
                stage="R2_READBACK",
                code="RESULT_R2_READBACK_FAILED",
                error=error,
            ),
        ) from None
    if observed is None:
        return None
    digest = hashlib.sha256(observed.data).hexdigest()
    if observed.metadata.get("sha256") != digest:
        raise ResultError("RESULT_R2_READBACK_METADATA_MISMATCH")
    return observed.data


def _get_exact(
    store: ConditionalObjectStore,
    *,
    key: str,
    expected: bytes,
    effects: _Effects,
) -> bytes:
    observed = _get_observed(
        store,
        key=key,
        effects=effects,
        missing_code="RESULT_R2_READBACK_MISSING",
    )
    if observed != expected:
        raise ResultError("RESULT_R2_READBACK_MISMATCH")
    return observed


def _slot_prefix(cycle_index: int, sport_key: str) -> str:
    if cycle_index not in range(1, CYCLE_COUNT + 1) or sport_key not in SPORT_KEYS:
        raise ResultError("RESULT_SLOT_INVALID")
    return f"{OBJECT_PREFIX}/cycle-{cycle_index:02d}/{sport_key}"


def _reservation_bytes(
    config: ResultConfig,
    *,
    cycle_index: int,
    sport_key: str,
    recorded_at: datetime,
) -> bytes:
    return canonical_json_bytes(
        {
            "schema_version": "robin-real-data-attempt-reservation-v1",
            "mission_id": MISSION_ID,
            "repository_sha": config.repository_sha,
            "github_run_id": config.github_run_id,
            "github_run_attempt": config.github_run_attempt,
            "cycle_index": cycle_index,
            "sport_key": sport_key,
            "markets": list(MARKETS),
            "recorded_at_utc": _iso_z(recorded_at),
            "provider_requests_reserved": 1,
            "credits_reserved_maximum": MAX_CREDITS_PER_REQUEST,
            "prior_provider_requests": PRIOR_PROVIDER_REQUESTS,
            "prior_credits_reserved": PRIOR_CREDITS_RESERVED,
            "cumulative_provider_requests_maximum": MISSION_PROVIDER_REQUESTS_MAX,
            "cumulative_provider_credits_maximum": MISSION_PROVIDER_CREDITS_MAX,
            "automatic_retries": 0,
        }
    )


def _diagnostic(
    *,
    stage: str,
    code: str,
    exception_class: str,
    errno: int | None = None,
    http_status: int | None = None,
) -> dict[str, object]:
    safe_class = (
        exception_class
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", exception_class)
        else "BaseException"
    )
    safe_status = http_status if http_status is not None and 100 <= http_status <= 599 else None
    safe_errno = errno if isinstance(errno, int) and not isinstance(errno, bool) else None
    return {
        "stage": stage,
        "code": code,
        "exception_class": safe_class,
        "errno": safe_errno,
        "http_status": safe_status,
    }


def _exception_diagnostic(
    *,
    stage: str,
    code: str,
    error: BaseException,
) -> dict[str, object]:
    error_number = getattr(error, "errno", None)
    response = getattr(error, "response", None)
    http_status: int | None = None
    if isinstance(response, Mapping):
        metadata = response.get("ResponseMetadata")
        if isinstance(metadata, Mapping):
            candidate_status = metadata.get("HTTPStatusCode")
            if isinstance(candidate_status, int) and not isinstance(candidate_status, bool):
                http_status = candidate_status
    return _diagnostic(
        stage=stage,
        code=code,
        exception_class=type(error).__name__,
        errno=(
            error_number
            if isinstance(error_number, int) and not isinstance(error_number, bool)
            else None
        ),
        http_status=http_status,
    )


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


def _raw_envelope(
    *,
    config: ResultConfig,
    cycle_index: int,
    sport_key: str,
    response: LiveTransportResponse,
    quota: _Quota | None,
    observed_credit_cost: int | None,
    quota_diagnostic_code: str | None,
) -> bytes:
    payload_sha256 = hashlib.sha256(response.payload).hexdigest()
    return canonical_json_bytes(
        {
            "schema_version": "robin-real-data-raw-envelope-v1",
            "mission_id": MISSION_ID,
            "repository_sha": config.repository_sha,
            "github_run_id": config.github_run_id,
            "cycle_index": cycle_index,
            "sport_key": sport_key,
            "markets": list(MARKETS),
            "capture_time_utc": _iso_z(response.first_observed_at_utc),
            "http_status": response.http_status,
            "quota": quota.as_dict() if quota is not None else None,
            "observed_credit_cost": observed_credit_cost,
            "quota_diagnostic_code": quota_diagnostic_code,
            "transport_accounting": {
                "network_calls": response.network_calls,
                "provider_calls": response.provider_calls,
                "retries": response.retries,
                "redirects": response.redirects,
            },
            "raw_payload_base64": base64.b64encode(response.payload).decode("ascii"),
            "raw_payload_sha256": payload_sha256,
            "raw_payload_bytes": len(response.payload),
        }
    )


def _decoded_envelope(
    data: bytes,
    *,
    cycle_index: int,
    sport_key: str,
) -> tuple[bytes, datetime, int, _Quota | None, str, str, str, int | None, str | None]:
    try:
        decoded = strict_json_loads(data)
        envelope = _mapping(decoded, code="RESULT_R2_ENVELOPE_INVALID")
        if (
            envelope.get("schema_version") != "robin-real-data-raw-envelope-v1"
            or envelope.get("mission_id") != MISSION_ID
            or envelope.get("cycle_index") != cycle_index
            or envelope.get("sport_key") != sport_key
            or envelope.get("markets") != list(MARKETS)
        ):
            raise ResultError("RESULT_R2_ENVELOPE_INVALID")
        encoded = envelope.get("raw_payload_base64")
        expected_sha256 = envelope.get("raw_payload_sha256")
        raw_bytes = envelope.get("raw_payload_bytes")
        status = envelope.get("http_status")
        capture_repository_sha = envelope.get("repository_sha")
        capture_github_run_id = envelope.get("github_run_id")
        observed_credit_cost = envelope.get("observed_credit_cost")
        quota_diagnostic_code = envelope.get("quota_diagnostic_code")
        if (
            not isinstance(encoded, str)
            or not isinstance(expected_sha256, str)
            or not isinstance(raw_bytes, int)
            or isinstance(raw_bytes, bool)
            or not isinstance(status, int)
            or isinstance(status, bool)
            or not isinstance(capture_repository_sha, str)
            or re.fullmatch(r"[0-9a-f]{40}", capture_repository_sha) is None
            or not isinstance(capture_github_run_id, str)
            or re.fullmatch(r"[1-9][0-9]{0,19}", capture_github_run_id) is None
            or (
                observed_credit_cost is not None
                and (
                    isinstance(observed_credit_cost, bool)
                    or not isinstance(observed_credit_cost, int)
                    or observed_credit_cost < 0
                    or observed_credit_cost > 2**63 - 1
                )
            )
            or (
                quota_diagnostic_code is not None and quota_diagnostic_code not in _QUOTA_STOP_CODES
            )
        ):
            raise ResultError("RESULT_R2_ENVELOPE_INVALID")
        payload = base64.b64decode(encoded, validate=True)
        if len(payload) != raw_bytes or hashlib.sha256(payload).hexdigest() != expected_sha256:
            raise ResultError("RESULT_R2_ENVELOPE_INTEGRITY_FAILED")
        capture_time = _parse_time(
            envelope.get("capture_time_utc"), code="RESULT_R2_ENVELOPE_INVALID"
        )
        raw_quota = envelope.get("quota")
        quota: _Quota | None = None
        if raw_quota is not None:
            quota_mapping = _mapping(raw_quota, code="RESULT_R2_ENVELOPE_INVALID")
            remaining = quota_mapping.get("requests_remaining")
            used = quota_mapping.get("requests_used")
            last = quota_mapping.get("requests_last")
            if any(
                isinstance(value, bool) or not isinstance(value, int)
                for value in (remaining, used, last)
            ):
                raise ResultError("RESULT_R2_ENVELOPE_INVALID")
            quota = _Quota(
                remaining=cast(int, remaining),
                used=cast(int, used),
                last=cast(int, last),
                observed_at_utc=_parse_time(
                    quota_mapping.get("observed_at_utc"), code="RESULT_R2_ENVELOPE_INVALID"
                ),
            )
            if observed_credit_cost != quota.last or quota_diagnostic_code is not None:
                raise ResultError("RESULT_R2_ENVELOPE_INVALID")
        elif quota_diagnostic_code is None:
            raise ResultError("RESULT_R2_ENVELOPE_INVALID")
    except (CaptureContractError, ValueError):
        raise ResultError("RESULT_R2_ENVELOPE_INVALID") from None
    return (
        payload,
        capture_time,
        status,
        quota,
        expected_sha256,
        capture_repository_sha,
        capture_github_run_id,
        observed_credit_cost,
        quota_diagnostic_code,
    )


def _replay_envelope(
    data: bytes,
    *,
    cycle_index: int,
    sport_key: str,
) -> tuple[
    tuple[dict[str, object], ...],
    tuple[dict[str, object], ...],
    _Quota,
    datetime,
    str,
    str,
    str,
]:
    (
        payload,
        capture_time,
        status,
        quota,
        payload_sha256,
        capture_repository_sha,
        capture_github_run_id,
        _observed_credit_cost_value,
        quota_diagnostic_code,
    ) = _decoded_envelope(
        data,
        cycle_index=cycle_index,
        sport_key=sport_key,
    )
    if status != 200:
        raise ResultError("RESULT_PROVIDER_HTTP_STATUS_INVALID")
    if quota is None:
        raise ResultError(quota_diagnostic_code or "RESULT_QUOTA_HEADERS_MISSING")
    rows, limitations = _normalize_payload(
        payload,
        cycle_index=cycle_index,
        sport_key=sport_key,
        capture_time=capture_time,
        quota=quota,
    )
    replay_rows, replay_limitations = _normalize_payload(
        bytes(payload),
        cycle_index=cycle_index,
        sport_key=sport_key,
        capture_time=capture_time,
        quota=quota,
    )
    if canonical_json_bytes([*rows]) != canonical_json_bytes([*replay_rows]) or (
        canonical_json_bytes([*limitations]) != canonical_json_bytes([*replay_limitations])
    ):
        raise ResultError("RESULT_OFFLINE_REPLAY_MISMATCH")
    return (
        rows,
        limitations,
        quota,
        capture_time,
        payload_sha256,
        capture_repository_sha,
        capture_github_run_id,
    )


def _branch_stub(
    *,
    cycle_index: int,
    sport_key: str,
    status: str,
    source: str,
    diagnostic: dict[str, object] | None,
) -> dict[str, object]:
    return {
        "cycle_index": cycle_index,
        "sport_key": sport_key,
        "markets_requested": list(MARKETS),
        "status": status,
        "source": source,
        "provider_request_attempted": False,
        "capture_time_utc": None,
        "capture_repository_sha": None,
        "capture_github_run_id": None,
        "quota": None,
        "row_count": 0,
        "match_count": 0,
        "market_branch_coverage": {"h2h": 0, "totals": 0},
        "limitations": [],
        "raw_payload_sha256": None,
        "raw_object_key": None,
        "raw_object_sha256": None,
        "readback_verified": False,
        "replay_verified": False,
        "diagnostic": diagnostic,
    }


def _complete_branch(
    *,
    cycle_index: int,
    sport_key: str,
    source: str,
    provider_request_attempted: bool,
    raw_key: str,
    raw_bytes: bytes,
    rows: tuple[dict[str, object], ...],
    limitations: tuple[dict[str, object], ...],
    quota: _Quota,
    capture_time: datetime,
    payload_sha256: str,
    capture_repository_sha: str,
    capture_github_run_id: str,
) -> dict[str, object]:
    market_branch_coverage = {
        market: int(any(row["market_key"] == market for row in rows)) for market in MARKETS
    }
    return {
        "cycle_index": cycle_index,
        "sport_key": sport_key,
        "markets_requested": list(MARKETS),
        "status": "PARTIAL" if limitations else "COMPLETE",
        "source": source,
        "provider_request_attempted": provider_request_attempted,
        "capture_time_utc": _iso_z(capture_time),
        "capture_repository_sha": capture_repository_sha,
        "capture_github_run_id": capture_github_run_id,
        "quota": quota.as_dict(),
        "row_count": len(rows),
        "match_count": len({cast(str, row["event_id"]) for row in rows}),
        "market_branch_coverage": market_branch_coverage,
        "limitations": [*limitations],
        "raw_payload_sha256": payload_sha256,
        "raw_object_key": raw_key,
        "raw_object_sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "readback_verified": True,
        "replay_verified": True,
        "diagnostic": None,
    }


def _assert_provider_budget(effects: _Effects) -> None:
    next_requests = effects.provider_requests + 1
    current_credits_upper = effects.credits_new_upper_bound
    if current_credits_upper is None:
        raise ResultError("RESULT_PROVIDER_CREDIT_BOUND_UNVERIFIED")
    next_credits_upper = current_credits_upper + MAX_CREDITS_PER_REQUEST
    if (
        next_requests > SUCCESSOR_PROVIDER_SLOTS
        or PRIOR_PROVIDER_REQUESTS + next_requests > MISSION_PROVIDER_REQUESTS_MAX
    ):
        raise ResultError("RESULT_PROVIDER_REQUEST_BUDGET_EXCEEDED")
    if PRIOR_CREDITS_RESERVED + next_credits_upper > MISSION_PROVIDER_CREDITS_MAX:
        raise ResultError("RESULT_PROVIDER_CREDIT_BUDGET_EXCEEDED")


def _replay_prior_capture(
    *,
    cycle_index: int,
    sport_key: str,
    raw_key: str,
    existing_raw: bytes,
    effects: _Effects,
) -> tuple[dict[str, object], tuple[dict[str, object], ...], _Quota | None]:
    verified_quota: _Quota | None = None
    try:
        decoded = _decoded_envelope(
            existing_raw,
            cycle_index=cycle_index,
            sport_key=sport_key,
        )
        prior_observed_cost = decoded[7]
        prior_quota_diagnostic = decoded[8]
        verified_quota = decoded[3]
        if prior_observed_cost is None:
            effects.credit_bound_valid = False
        else:
            effects.credits_observed_excess += max(0, prior_observed_cost - MAX_CREDITS_PER_REQUEST)
        if prior_quota_diagnostic is not None:
            raise ResultError(prior_quota_diagnostic)
        (
            rows,
            limitations,
            quota,
            capture_time,
            payload_sha256,
            capture_repository_sha,
            capture_github_run_id,
        ) = _replay_envelope(
            existing_raw,
            cycle_index=cycle_index,
            sport_key=sport_key,
        )
    except ResultError as error:
        return (
            _branch_stub(
                cycle_index=cycle_index,
                sport_key=sport_key,
                status="INCOMPLETE",
                source="PRIOR_CAPTURE_REPLAY_FAILED",
                diagnostic=_diagnostic(
                    stage="OFFLINE_REPLAY",
                    code=error.code,
                    exception_class="ResultError",
                ),
            ),
            (),
            verified_quota,
        )
    return (
        _complete_branch(
            cycle_index=cycle_index,
            sport_key=sport_key,
            source="REUSED_R2_CAPTURE",
            provider_request_attempted=False,
            raw_key=raw_key,
            raw_bytes=existing_raw,
            rows=rows,
            limitations=limitations,
            quota=quota,
            capture_time=capture_time,
            payload_sha256=payload_sha256,
            capture_repository_sha=capture_repository_sha,
            capture_github_run_id=capture_github_run_id,
        ),
        rows,
        quota,
    )


def _recover_prior_slot(
    *,
    cycle_index: int,
    sport_key: str,
    reservation_key: str,
    raw_key: str,
    store: ConditionalObjectStore,
    effects: _Effects,
) -> tuple[dict[str, object], tuple[dict[str, object], ...], _Quota | None] | None:
    existing_reservation = _get_optional(store, key=reservation_key, effects=effects)
    if existing_reservation is None:
        return None
    effects.reserved_slots += 1
    existing_raw = _get_optional(store, key=raw_key, effects=effects)
    if existing_raw is None:
        return (
            _branch_stub(
                cycle_index=cycle_index,
                sport_key=sport_key,
                status="INCOMPLETE",
                source="PRIOR_ATTEMPT_AMBIGUOUS",
                diagnostic=_diagnostic(
                    stage="ATTEMPT_RECOVERY",
                    code="RESULT_PRIOR_ATTEMPT_AMBIGUOUS",
                    exception_class="ResultError",
                ),
            ),
            (),
            None,
        )
    return _replay_prior_capture(
        cycle_index=cycle_index,
        sport_key=sport_key,
        raw_key=raw_key,
        existing_raw=existing_raw,
        effects=effects,
    )


def _run_branch(
    *,
    config: ResultConfig,
    cycle_index: int,
    sport_key: str,
    recorded_at: datetime,
    approved_ip_address: str,
    api_key: str,
    store: ConditionalObjectStore,
    transport_factory: TransportFactory,
    clock: Callable[[], datetime],
    effects: _Effects,
) -> tuple[dict[str, object], tuple[dict[str, object], ...], _Quota | None]:
    prefix = _slot_prefix(cycle_index, sport_key)
    reservation_key = f"{prefix}/attempt-reservation.json"
    raw_key = f"{prefix}/raw-envelope.json"
    _assert_provider_budget(effects)
    request = PublicProviderRequestV1.from_spec(
        ProviderRequestSpec(
            endpoint=f"/v4/sports/{sport_key}/odds",
            sport_key=sport_key,
            region=REGION,
            markets=MARKETS,
            timeout_seconds=20,
        ),
        maximum_response_bytes=MAX_RESPONSE_BYTES,
        approved_provider_ip_address=approved_ip_address,
    )
    transport = transport_factory(clock)
    try:
        transport.preflight(request)
    except LiveTransportError as error:
        recovered = _recover_prior_slot(
            cycle_index=cycle_index,
            sport_key=sport_key,
            reservation_key=reservation_key,
            raw_key=raw_key,
            store=store,
            effects=effects,
        )
        if recovered is not None:
            return recovered
        return (
            _branch_stub(
                cycle_index=cycle_index,
                sport_key=sport_key,
                status="INCOMPLETE",
                source="LOCAL_PREFLIGHT_FAILURE",
                diagnostic=_diagnostic(
                    stage="TRANSPORT_PREFLIGHT",
                    code=error.code,
                    exception_class="LiveTransportError",
                ),
            ),
            (),
            None,
        )
    except Exception:
        recovered = _recover_prior_slot(
            cycle_index=cycle_index,
            sport_key=sport_key,
            reservation_key=reservation_key,
            raw_key=raw_key,
            store=store,
            effects=effects,
        )
        if recovered is not None:
            return recovered
        return (
            _branch_stub(
                cycle_index=cycle_index,
                sport_key=sport_key,
                status="INCOMPLETE",
                source="LOCAL_PREFLIGHT_FAILURE",
                diagnostic=_diagnostic(
                    stage="TRANSPORT_PREFLIGHT",
                    code="RESULT_TRANSPORT_PREFLIGHT_FAILED",
                    exception_class="Exception",
                ),
            ),
            (),
            None,
        )
    reservation = _reservation_bytes(
        config,
        cycle_index=cycle_index,
        sport_key=sport_key,
        recorded_at=recorded_at,
    )
    reservation_status, _reservation_sha = _put_immutable(
        store,
        key=reservation_key,
        data=reservation,
        kind="provider-attempt-reservation",
        effects=effects,
        allow_preexisting=True,
    )
    effects.reserved_slots += 1
    if reservation_status == "PREEXISTING":
        existing_raw = _get_optional(store, key=raw_key, effects=effects)
        if existing_raw is None:
            return (
                _branch_stub(
                    cycle_index=cycle_index,
                    sport_key=sport_key,
                    status="INCOMPLETE",
                    source="PRIOR_ATTEMPT_AMBIGUOUS",
                    diagnostic=_diagnostic(
                        stage="ATTEMPT_RECOVERY",
                        code="RESULT_PRIOR_ATTEMPT_AMBIGUOUS",
                        exception_class="ResultError",
                    ),
                ),
                (),
                None,
            )
        return _replay_prior_capture(
            cycle_index=cycle_index,
            sport_key=sport_key,
            raw_key=raw_key,
            existing_raw=existing_raw,
            effects=effects,
        )

    try:
        effects.provider_requests += 1
        response = transport.dispatch(request, api_key=api_key)
    except LiveTransportError as error:
        return (
            _branch_stub(
                cycle_index=cycle_index,
                sport_key=sport_key,
                status="INCOMPLETE",
                source="LIVE_PROVIDER_FAILURE",
                diagnostic=_transport_diagnostic(error),
            )
            | {"provider_request_attempted": True},
            (),
            None,
        )
    except Exception:
        return (
            _branch_stub(
                cycle_index=cycle_index,
                sport_key=sport_key,
                status="INCOMPLETE",
                source="LIVE_PROVIDER_FAILURE",
                diagnostic=_diagnostic(
                    stage="PROVIDER_DISPATCH",
                    code="RESULT_PROVIDER_DISPATCH_FAILED",
                    exception_class="Exception",
                ),
            )
            | {"provider_request_attempted": True},
            (),
            None,
        )

    observed_cost = _observed_credit_cost(response.headers)
    if observed_cost is None:
        effects.credit_bound_valid = False
    else:
        effects.credit_cost_observed_attempts += 1
        effects.credits_confirmed += observed_cost
        effects.credits_observed_excess += max(0, observed_cost - MAX_CREDITS_PER_REQUEST)

    quota_error_code: str | None = None
    if (
        response.network_calls != 1
        or response.provider_calls != 1
        or response.retries != 0
        or response.redirects != 0
    ):
        observed_quota: _Quota | None = None
        quota_error_code = "RESULT_TRANSPORT_ACCOUNTING_INVALID"
    else:
        try:
            observed_quota = _quota(response.headers, response.first_observed_at_utc)
        except ResultError as error:
            observed_quota = None
            quota_error_code = error.code
    if observed_quota is not None:
        effects.quota_observed_attempts += 1
    envelope = _raw_envelope(
        config=config,
        cycle_index=cycle_index,
        sport_key=sport_key,
        response=response,
        quota=observed_quota,
        observed_credit_cost=observed_cost,
        quota_diagnostic_code=quota_error_code,
    )
    _raw_status, _raw_sha = _put_immutable(
        store,
        key=raw_key,
        data=envelope,
        kind="raw-provider-response",
        effects=effects,
    )
    readback = _get_exact(store, key=raw_key, expected=envelope, effects=effects)
    if quota_error_code is not None:
        branch = _branch_stub(
            cycle_index=cycle_index,
            sport_key=sport_key,
            status="INCOMPLETE",
            source="LIVE_R2_CAPTURE",
            diagnostic=_diagnostic(
                stage="RESPONSE_VALIDATE",
                code=quota_error_code,
                exception_class="ResultError",
                http_status=response.http_status,
            ),
        )
        branch.update(
            {
                "provider_request_attempted": True,
                "capture_time_utc": _iso_z(response.first_observed_at_utc),
                "capture_repository_sha": config.repository_sha,
                "capture_github_run_id": config.github_run_id,
                "raw_payload_sha256": hashlib.sha256(response.payload).hexdigest(),
                "raw_object_key": raw_key,
                "raw_object_sha256": hashlib.sha256(envelope).hexdigest(),
                "readback_verified": True,
            }
        )
        return branch, (), None
    try:
        (
            rows,
            limitations,
            replay_quota,
            capture_time,
            payload_sha256,
            capture_repository_sha,
            capture_github_run_id,
        ) = _replay_envelope(readback, cycle_index=cycle_index, sport_key=sport_key)
    except ResultError as error:
        branch = _branch_stub(
            cycle_index=cycle_index,
            sport_key=sport_key,
            status="INCOMPLETE",
            source="LIVE_R2_CAPTURE",
            diagnostic=_diagnostic(
                stage="RESPONSE_VALIDATE" if response.http_status != 200 else "OFFLINE_REPLAY",
                code=error.code,
                exception_class="ResultError",
                http_status=response.http_status,
            ),
        )
        branch.update(
            {
                "provider_request_attempted": True,
                "capture_time_utc": _iso_z(response.first_observed_at_utc),
                "capture_repository_sha": config.repository_sha,
                "capture_github_run_id": config.github_run_id,
                "quota": observed_quota.as_dict() if observed_quota is not None else None,
                "raw_payload_sha256": hashlib.sha256(response.payload).hexdigest(),
                "raw_object_key": raw_key,
                "raw_object_sha256": hashlib.sha256(envelope).hexdigest(),
                "readback_verified": True,
            }
        )
        return branch, (), observed_quota
    return (
        _complete_branch(
            cycle_index=cycle_index,
            sport_key=sport_key,
            source="LIVE_R2_CAPTURE",
            provider_request_attempted=True,
            raw_key=raw_key,
            raw_bytes=envelope,
            rows=rows,
            limitations=limitations,
            quota=replay_quota,
            capture_time=capture_time,
            payload_sha256=payload_sha256,
            capture_repository_sha=capture_repository_sha,
            capture_github_run_id=capture_github_run_id,
        ),
        rows,
        replay_quota,
    )


_CSV_FIELDS = (
    "cycle_index",
    "sport_key",
    "sport_title",
    "capture_time_utc",
    "source_timestamp_utc",
    "source_timestamp_origin",
    "event_id",
    "match",
    "home_team",
    "away_team",
    "kickoff_utc",
    "bookmaker_key",
    "bookmaker",
    "market_key",
    "outcome",
    "point",
    "price",
    "quota_remaining",
)


def _render_csv(rows: tuple[dict[str, object], ...]) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=_CSV_FIELDS, lineterminator="\n")
    writer.writeheader()
    writer.writerows(
        {
            field: (
                f"'{value}"
                if isinstance(value := row[field], str) and value and value[0] in "=+-@\t\r"
                else value
            )
            for field in _CSV_FIELDS
        }
        for row in rows
    )
    return stream.getvalue().encode("utf-8")


def _render_html(
    rows: tuple[dict[str, object], ...],
    *,
    status: str,
    terminal_safety_status: str,
    global_stop_code: str | None,
    cycle_count: int,
    completed_branches: int,
    incomplete_branches: int,
    provider_requests: int,
    credits_upper: int | None,
    market_branch_coverage: Mapping[str, int],
    market_row_counts: Mapping[str, int],
    branches: tuple[dict[str, object], ...],
) -> bytes:
    headings = "".join(f"<th>{html.escape(field)}</th>" for field in _CSV_FIELDS)
    body_rows: list[str] = []
    for row in rows:
        cells = "".join(
            f"<td>{html.escape('' if row[field] is None else str(row[field]))}</td>"
            for field in _CSV_FIELDS
        )
        body_rows.append(f"<tr>{cells}</tr>")
    limitation_rows: list[str] = []
    for branch in branches:
        codes: list[str] = []
        diagnostic = branch.get("diagnostic")
        if isinstance(diagnostic, dict) and isinstance(diagnostic.get("code"), str):
            codes.append(cast(str, diagnostic["code"]))
        limitations = branch.get("limitations")
        if isinstance(limitations, list):
            for limitation in limitations:
                if isinstance(limitation, dict) and isinstance(limitation.get("code"), str):
                    codes.append(cast(str, limitation["code"]))
        for code in codes:
            limitation_rows.append(
                "<tr>"
                f"<td>{html.escape(str(branch['cycle_index']))}</td>"
                f"<td>{html.escape(str(branch['sport_key']))}</td>"
                f"<td>{html.escape(str(branch['status']))}</td>"
                f"<td>{html.escape(code)}</td>"
                "</tr>"
            )
    limitation_table = (
        '<div class="scroll"><table><thead><tr><th>cycle</th><th>ligue</th>'
        "<th>statut</th><th>limite</th></tr></thead><tbody>"
        + "".join(limitation_rows)
        + "</tbody></table></div>"
        if limitation_rows
        else "<p>Aucune limite détectée sur les branches reçues.</p>"
    )
    coverage_denominator = len(branches)
    credits_text = "INCONNU — arrêt fail-closed" if credits_upper is None else str(credits_upper)
    page = f"""<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Robin — données réelles</title>
<style>
body{{font:14px system-ui,sans-serif;margin:24px;color:#18202a}}
.summary{{display:flex;gap:16px;flex-wrap:wrap;margin:16px 0}}
.metric{{padding:10px 12px;border:1px solid #ccd4dd;border-radius:8px}}
.scroll{{overflow:auto;max-height:70vh;border:1px solid #ccd4dd}}
table{{border-collapse:collapse;width:max-content;min-width:100%}}
th,td{{padding:6px 8px;border-bottom:1px solid #e2e7ec;text-align:left;white-space:nowrap}}
th{{position:sticky;top:0;background:#f4f7fa}}
</style>
</head>
<body>
<h1>Robin — données réelles reçues</h1>
<p>Statut : <strong>{html.escape(status)}</strong>. Horaires en UTC.</p>
<p>Sécurité terminale : <strong>{html.escape(terminal_safety_status)}</strong>.
Code d’arrêt global : <strong>{html.escape(global_stop_code or "AUCUN")}</strong>.</p>
<div class="summary">
<div class="metric">Cycles programmés : {cycle_count}</div>
<div class="metric">Branches complètes : {completed_branches}</div>
<div class="metric">Branches incomplètes : {incomplete_branches}</div>
<div class="metric">Requêtes nouvelles : {provider_requests}</div>
<div class="metric">Crédits cumulés, borne haute : {credits_text}</div>
<div class="metric">Lignes : {len(rows)}</div>
<div class="metric">Branches avec H2H : {market_branch_coverage["h2h"]}/{coverage_denominator}</div>
<div class="metric">Branches avec totals : {market_branch_coverage["totals"]}/{coverage_denominator}</div>
<div class="metric">Issues H2H : {market_row_counts["h2h"]}</div>
<div class="metric">Issues totals : {market_row_counts["totals"]}</div>
</div>
<h2>Limites et branches incomplètes</h2>
{limitation_table}
<h2>Cotes reçues</h2>
<div class="scroll"><table><thead><tr>{headings}</tr></thead>
<tbody>{"".join(body_rows)}</tbody></table></div>
</body>
</html>
"""
    return page.encode("utf-8")


def _write_exclusive(path: Path, data: bytes) -> None:
    try:
        with path.open("xb") as stream:
            stream.write(data)
            stream.flush()
    except OSError:
        raise ResultError("RESULT_LOCAL_DELIVERY_WRITE_FAILED") from None


def _branch_market_coverage(branches: tuple[dict[str, object], ...]) -> dict[str, int]:
    result: dict[str, int] = {market: 0 for market in MARKETS}
    for branch in branches:
        coverage = branch.get("market_branch_coverage")
        if not isinstance(coverage, dict):
            continue
        for market in MARKETS:
            count = coverage.get(market)
            if isinstance(count, int) and not isinstance(count, bool):
                result[market] += count
    return result


def _market_row_counts(rows: tuple[dict[str, object], ...]) -> dict[str, int]:
    return {market: sum(1 for row in rows if row.get("market_key") == market) for market in MARKETS}


def _sport_coverage(branches: tuple[dict[str, object], ...]) -> dict[str, int]:
    result = {sport: 0 for sport in SPORT_KEYS}
    for branch in branches:
        sport = branch.get("sport_key")
        if sport in result and branch.get("replay_verified") is True:
            result[sport] += 1
    return result


def _consumption(effects: _Effects) -> dict[str, object]:
    credits_exact = (
        effects.credits_confirmed
        if effects.credit_cost_observed_attempts == effects.provider_requests
        else None
    )
    successor_upper = effects.credits_new_upper_bound
    cumulative_upper = (
        PRIOR_CREDITS_RESERVED + successor_upper if successor_upper is not None else None
    )
    return {
        "prior_provider_requests": PRIOR_PROVIDER_REQUESTS,
        "prior_credits_reserved": PRIOR_CREDITS_RESERVED,
        "provider_slots_reserved_successor": effects.reserved_slots,
        "provider_requests_new": effects.provider_requests,
        "provider_requests_cumulative": PRIOR_PROVIDER_REQUESTS + effects.reserved_slots,
        "provider_requests_cumulative_maximum": MISSION_PROVIDER_REQUESTS_MAX,
        "provider_credits_new_exact": credits_exact,
        "provider_credits_new_confirmed": effects.credits_confirmed,
        "provider_credits_successor_upper_bound": successor_upper,
        "provider_credits_cumulative_upper_bound": cumulative_upper,
        "provider_credits_cumulative_maximum": MISSION_PROVIDER_CREDITS_MAX,
        "quota_observed_attempts": effects.quota_observed_attempts,
        "credit_cost_observed_attempts": effects.credit_cost_observed_attempts,
        "accounting_status": (
            "EXACT_NEW_ATTEMPTS_WITH_PRIOR_RESERVE"
            if credits_exact is not None
            else "BOUNDED_UNKNOWN_NEW_ATTEMPTS_WITH_PRIOR_RESERVE"
            if successor_upper is not None
            else "UNBOUNDED_COST_HEADER_MISSING_STOPPED_WITH_PRIOR_RESERVE"
        ),
    }


def _report(
    *,
    config: ResultConfig,
    cycles: tuple[dict[str, object], ...],
    branches: tuple[dict[str, object], ...],
    rows: tuple[dict[str, object], ...],
    effects: _Effects,
    report_r2_puts: int,
    report_r2_gets: int,
    global_stop_code: str | None,
) -> dict[str, object]:
    completed = sum(1 for branch in branches if branch["status"] == "COMPLETE")
    incomplete = len(branches) - completed
    verified = [branch for branch in branches if branch["replay_verified"] is True]
    status = (
        "REAL_DATA_COMPLETE"
        if (
            global_stop_code is None
            and len(cycles) == CYCLE_COUNT
            and completed == SUCCESSOR_PROVIDER_SLOTS
        )
        else "REAL_DATA_PARTIAL"
        if verified
        else "NO_REAL_CAPTURE"
    )
    captures = [cast(str, branch["capture_time_utc"]) for branch in verified]
    source_times = [cast(str, row["source_timestamp_utc"]) for row in rows]
    consumption = _consumption(effects)
    first_quota = next(
        (
            branch["quota"]
            for branch in branches
            if branch.get("provider_request_attempted") is True and branch.get("quota") is not None
        ),
        None,
    )
    return {
        "schema_version": "robin-real-data-result-report-v1",
        "mission_id": MISSION_ID,
        "status": status,
        "terminal_safety_status": "PASS" if global_stop_code is None else "FAIL_CLOSED",
        "global_stop_code": global_stop_code,
        "repository_sha": config.repository_sha,
        "github_run_id": config.github_run_id,
        "claim_ids": list(CLAIM_IDS),
        "cycle_count": len(cycles),
        "completed_cycle_count": len(cycles),
        "completed_branch_count": completed,
        "incomplete_branch_count": incomplete,
        "validated_capture_count": len(verified),
        "first_verified_capture_time_utc": captures[0] if captures else None,
        "capture_times_utc": captures,
        "source_timestamp_min_utc": min(source_times) if source_times else None,
        "source_timestamp_max_utc": max(source_times) if source_times else None,
        "row_count": len(rows),
        "match_count": len(
            {(cast(str, row["sport_key"]), cast(str, row["event_id"])) for row in rows}
        ),
        "bookmaker_count": len({cast(str, row["bookmaker_key"]) for row in rows}),
        "market_branch_coverage": _branch_market_coverage(branches),
        "market_outcome_row_counts": _market_row_counts(rows),
        "sport_coverage": _sport_coverage(branches),
        "current_quota_first_observed": first_quota,
        "consumption": consumption,
        "provider_requests_new": consumption["provider_requests_new"],
        "provider_requests_cumulative": consumption["provider_requests_cumulative"],
        "provider_credits_new_exact": consumption["provider_credits_new_exact"],
        "provider_credits_cumulative_upper_bound": consumption[
            "provider_credits_cumulative_upper_bound"
        ],
        "effect_accounting": {
            "r2_put_requests": report_r2_puts,
            "r2_get_requests": report_r2_gets,
            "dns_resolutions": effects.dns_resolutions,
            "secret_reads": effects.secret_reads,
            "automatic_retries": 0,
            "purchases": 0,
            "real_bets": 0,
            "backfills": 0,
            "promotions": 0,
        },
        "cycles": [*cycles],
        "branches": [*branches],
        "rows": [*rows],
        "retention": {
            "raw_payloads": "R2_IMMUTABLE_PRIVATE_ONLY",
            "normalization_source": "R2_EXACT_READBACK_ONLY",
            "offline_replay_verified_capture_count": len(verified),
            "git_contains_raw_payload": False,
        },
    }


def _cycle_receipt(
    *,
    config: ResultConfig,
    cycle_index: int,
    started_at: datetime,
    finished_at: datetime,
    branches: tuple[dict[str, object], ...],
) -> bytes:
    return canonical_json_bytes(
        {
            "schema_version": "robin-real-data-cycle-receipt-v1",
            "mission_id": MISSION_ID,
            "repository_sha": config.repository_sha,
            "github_run_id": config.github_run_id,
            "cycle_index": cycle_index,
            "cycle_started_at_utc": _iso_z(started_at),
            "finished_at_utc": _iso_z(finished_at),
            "sport_keys": list(SPORT_KEYS),
            "markets": list(MARKETS),
            "branches": [
                {
                    "sport_key": branch["sport_key"],
                    "status": branch["status"],
                    "source": branch["source"],
                    "row_count": branch["row_count"],
                    "diagnostic": branch["diagnostic"],
                }
                for branch in branches
            ],
        }
    )


def _assert_resolution_current(resolution: NetworkResolution, now: datetime) -> None:
    try:
        resolution.assert_current(now)
    except Exception:
        raise ResultError("RESULT_DNS_RESOLUTION_EXPIRED") from None


def run_real_data_result(
    config: ResultConfig,
    *,
    store: ConditionalObjectStore,
    transport_factory: TransportFactory,
    secret_reader: SecretReader,
    resolver: Callable[[], NetworkResolution],
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    monotonic: Callable[[], float] = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep,
) -> dict[str, object]:
    """Execute three fixed cycles; branch failures remain explicit and isolated."""

    _validate_config(config)
    started_at = ensure_utc(clock(), field="real_result_started_at")
    manifest = _load_manifest(config.manifest_path, started_at)
    started_monotonic = monotonic()
    effects = _Effects()
    resolution: NetworkResolution | None = None
    api_key: str | None = None

    def provider_access() -> tuple[NetworkResolution, str]:
        nonlocal resolution, api_key
        if resolution is None:
            effects.dns_resolutions += 1
            try:
                resolution = resolver()
            except Exception:
                raise ResultError("RESULT_DNS_RESOLUTION_FAILED") from None
            if resolution.resolution_operations != 1:
                raise ResultError("RESULT_DNS_RESOLUTION_INVALID")
        resolution_check_time = _assert_authority(
            manifest,
            clock=clock,
            monotonic=monotonic,
            started_monotonic=started_monotonic,
        )
        _assert_resolution_current(resolution, resolution_check_time)
        if api_key is None:
            effects.secret_reads += 1
            try:
                api_key = validate_provider_secret(secret_reader.read())
            except LiveTransportError:
                raise ResultError("RESULT_PROVIDER_SECRET_INVALID") from None
        return resolution, api_key

    cycles: list[dict[str, object]] = []
    all_branches: list[dict[str, object]] = []
    all_rows: list[dict[str, object]] = []
    previous_cycle_started: datetime | None = None
    minimum_known_remaining: int | None = None
    last_dispatch_quota: _Quota | None = None
    branch_attempt_failure_counts: dict[tuple[str, str], int] = {}
    stopped_sports: set[str] = set()
    global_stop_code: str | None = None
    try:
        inventory: dict[tuple[int, str], _BranchResult | None] = {}
        for inventory_cycle in range(1, CYCLE_COUNT + 1):
            for inventory_sport in SPORT_KEYS:
                _assert_authority(
                    manifest,
                    clock=clock,
                    monotonic=monotonic,
                    started_monotonic=started_monotonic,
                )
                inventory_prefix = _slot_prefix(inventory_cycle, inventory_sport)
                recovered = _recover_prior_slot(
                    cycle_index=inventory_cycle,
                    sport_key=inventory_sport,
                    reservation_key=f"{inventory_prefix}/attempt-reservation.json",
                    raw_key=f"{inventory_prefix}/raw-envelope.json",
                    store=store,
                    effects=effects,
                )
                inventory[(inventory_cycle, inventory_sport)] = recovered
                if recovered is None:
                    continue
                inventory_branch, _inventory_rows, inventory_quota = recovered
                if inventory_quota is not None:
                    minimum_known_remaining = (
                        inventory_quota.remaining
                        if minimum_known_remaining is None
                        else min(minimum_known_remaining, inventory_quota.remaining)
                    )
                if inventory_branch["source"] == "PRIOR_CAPTURE_REPLAY_FAILED":
                    prior_diagnostic = inventory_branch.get("diagnostic")
                    if (
                        isinstance(prior_diagnostic, dict)
                        and prior_diagnostic.get("code") in _QUOTA_STOP_CODES
                    ):
                        global_stop_code = "RESULT_PROVIDER_QUOTA_UNVERIFIED"
                    if (
                        inventory_branch.get("status") == "INCOMPLETE"
                        and isinstance(prior_diagnostic, dict)
                        and isinstance(prior_diagnostic.get("code"), str)
                    ):
                        failure_key = (
                            inventory_sport,
                            cast(str, prior_diagnostic["code"]),
                        )
                        branch_attempt_failure_counts[failure_key] = (
                            branch_attempt_failure_counts.get(failure_key, 0) + 1
                        )
                        if branch_attempt_failure_counts[failure_key] >= 2:
                            stopped_sports.add(inventory_sport)

        for cycle_index in range(1, CYCLE_COUNT + 1):
            if cycle_index > 1:
                sleeper(float(config.interval_seconds))
            cycle_started = _assert_authority(
                manifest,
                clock=clock,
                monotonic=monotonic,
                started_monotonic=started_monotonic,
            )
            if previous_cycle_started is not None and cycle_started <= previous_cycle_started:
                raise ResultError("RESULT_CYCLE_TIME_NOT_INCREASING")
            previous_cycle_started = cycle_started
            if resolution is not None:
                _assert_resolution_current(resolution, cycle_started)
            cycle_branches: list[dict[str, object]] = []
            for sport_key in SPORT_KEYS:
                effect_time = _assert_authority(
                    manifest,
                    clock=clock,
                    monotonic=monotonic,
                    started_monotonic=started_monotonic,
                )
                if resolution is not None:
                    _assert_resolution_current(resolution, effect_time)
                recovered = inventory[(cycle_index, sport_key)]
                if recovered is not None:
                    branch, rows, observed_quota = recovered
                elif global_stop_code is not None:
                    branch = _branch_stub(
                        cycle_index=cycle_index,
                        sport_key=sport_key,
                        status="INCOMPLETE",
                        source="NOT_ATTEMPTED_GLOBAL_STOP",
                        diagnostic=_diagnostic(
                            stage="MISSION_BUDGET",
                            code=global_stop_code,
                            exception_class="ResultError",
                        ),
                    )
                    rows = ()
                    observed_quota = None
                elif sport_key in stopped_sports:
                    branch = _branch_stub(
                        cycle_index=cycle_index,
                        sport_key=sport_key,
                        status="INCOMPLETE",
                        source="NOT_ATTEMPTED_BRANCH_STOP",
                        diagnostic=_diagnostic(
                            stage="BRANCH_POLICY",
                            code="RESULT_REPEATED_BRANCH_ATTEMPT_STOP",
                            exception_class="ResultError",
                        ),
                    )
                    rows = ()
                    observed_quota = None
                elif (
                    minimum_known_remaining is not None
                    and minimum_known_remaining < MAX_CREDITS_PER_REQUEST
                ):
                    global_stop_code = "RESULT_PROVIDER_QUOTA_INSUFFICIENT"
                    branch = _branch_stub(
                        cycle_index=cycle_index,
                        sport_key=sport_key,
                        status="INCOMPLETE",
                        source="NOT_ATTEMPTED_QUOTA_STOP",
                        diagnostic=_diagnostic(
                            stage="MISSION_BUDGET",
                            code=global_stop_code,
                            exception_class="ResultError",
                        ),
                    )
                    rows = ()
                    observed_quota = None
                else:
                    active_resolution, active_api_key = provider_access()
                    branch, rows, observed_quota = _run_branch(
                        config=config,
                        cycle_index=cycle_index,
                        sport_key=sport_key,
                        recorded_at=effect_time,
                        approved_ip_address=active_resolution.selected_ip_address,
                        api_key=active_api_key,
                        store=store,
                        transport_factory=transport_factory,
                        clock=clock,
                        effects=effects,
                    )
                cycle_branches.append(branch)
                all_branches.append(branch)
                all_rows.extend(rows)
                is_current_dispatch_quota = (
                    branch.get("provider_request_attempted") is True
                    and branch.get("source") == "LIVE_R2_CAPTURE"
                )
                if observed_quota is not None:
                    if is_current_dispatch_quota:
                        if last_dispatch_quota is not None and (
                            observed_quota.used < last_dispatch_quota.used
                            or observed_quota.remaining > last_dispatch_quota.remaining
                        ):
                            global_stop_code = "RESULT_QUOTA_SEQUENCE_INVALID"
                        last_dispatch_quota = observed_quota
                    minimum_known_remaining = (
                        observed_quota.remaining
                        if minimum_known_remaining is None
                        else min(minimum_known_remaining, observed_quota.remaining)
                    )
                elif is_current_dispatch_quota:
                    global_stop_code = "RESULT_PROVIDER_QUOTA_UNVERIFIED"
                elif branch["source"] == "PRIOR_CAPTURE_REPLAY_FAILED":
                    prior_diagnostic = branch.get("diagnostic")
                    if (
                        isinstance(prior_diagnostic, dict)
                        and prior_diagnostic.get("code") in _QUOTA_STOP_CODES
                    ):
                        global_stop_code = "RESULT_PROVIDER_QUOTA_UNVERIFIED"
                branch_diagnostic = branch.get("diagnostic")
                source = branch.get("source")
                if (
                    branch.get("status") == "INCOMPLETE"
                    and branch.get("provider_request_attempted") is True
                    and isinstance(source, str)
                    and not source.startswith("NOT_ATTEMPTED_")
                    and isinstance(branch_diagnostic, dict)
                    and isinstance(branch_diagnostic.get("code"), str)
                ):
                    failure_key = (sport_key, cast(str, branch_diagnostic["code"]))
                    branch_attempt_failure_counts[failure_key] = (
                        branch_attempt_failure_counts.get(failure_key, 0) + 1
                    )
                    if branch_attempt_failure_counts[failure_key] >= 2:
                        stopped_sports.add(sport_key)

            finished_at = _assert_authority(
                manifest,
                clock=clock,
                monotonic=monotonic,
                started_monotonic=started_monotonic,
            )
            cycle_tuple = tuple(cycle_branches)
            receipt_bytes = _cycle_receipt(
                config=config,
                cycle_index=cycle_index,
                started_at=cycle_started,
                finished_at=finished_at,
                branches=cycle_tuple,
            )
            cycle_key = f"{OBJECT_PREFIX}/runs/{config.github_run_id}/cycle-{cycle_index:02d}.json"
            _put_immutable(
                store,
                key=cycle_key,
                data=receipt_bytes,
                kind="cycle-receipt",
                effects=effects,
            )
            _get_exact(store, key=cycle_key, expected=receipt_bytes, effects=effects)
            cycles.append(
                {
                    "cycle_index": cycle_index,
                    "cycle_started_at_utc": _iso_z(cycle_started),
                    "finished_at_utc": _iso_z(finished_at),
                    "status": (
                        "COMPLETE"
                        if all(branch["status"] == "COMPLETE" for branch in cycle_tuple)
                        else "PARTIAL"
                    ),
                    "cycle_receipt_r2_key": cycle_key,
                    "cycle_receipt_sha256": hashlib.sha256(receipt_bytes).hexdigest(),
                }
            )

        branches_tuple = tuple(all_branches)
        rows_tuple = tuple(
            sorted(
                all_rows,
                key=lambda row: (
                    cast(int, row["cycle_index"]),
                    cast(str, row["sport_key"]),
                    cast(str, row["kickoff_utc"]),
                    cast(str, row["event_id"]),
                    cast(str, row["bookmaker_key"]),
                    cast(str, row["market_key"]),
                    cast(float | None, row["point"]) or -1.0,
                    cast(str, row["outcome"]),
                ),
            )
        )
        report = _report(
            config=config,
            cycles=tuple(cycles),
            branches=branches_tuple,
            rows=rows_tuple,
            effects=effects,
            report_r2_puts=effects.r2_puts + 1,
            report_r2_gets=effects.r2_gets + 1,
            global_stop_code=global_stop_code,
        )
        report_bytes = canonical_json_bytes(report)
        report_key = f"{OBJECT_PREFIX}/runs/{config.github_run_id}/private-report.json"
        _put_immutable(
            store,
            key=report_key,
            data=report_bytes,
            kind="private-normalized-report",
            effects=effects,
        )
        _get_exact(store, key=report_key, expected=report_bytes, effects=effects)
        report_sha256 = hashlib.sha256(report_bytes).hexdigest()
        consumption = cast(dict[str, object], report["consumption"])
        completed = cast(int, report["completed_branch_count"])
        incomplete = cast(int, report["incomplete_branch_count"])
        csv_bytes = _render_csv(rows_tuple)
        html_bytes = _render_html(
            rows_tuple,
            status=cast(str, report["status"]),
            terminal_safety_status=cast(str, report["terminal_safety_status"]),
            global_stop_code=cast(str | None, report["global_stop_code"]),
            cycle_count=len(cycles),
            completed_branches=completed,
            incomplete_branches=incomplete,
            provider_requests=effects.provider_requests,
            credits_upper=cast(int | None, consumption["provider_credits_cumulative_upper_bound"]),
            market_branch_coverage=cast(dict[str, int], report["market_branch_coverage"]),
            market_row_counts=cast(dict[str, int], report["market_outcome_row_counts"]),
            branches=branches_tuple,
        )
        public_receipt: dict[str, object] = {
            "schema_version": "robin-real-data-result-public-receipt-v1",
            "mission_id": MISSION_ID,
            "status": report["status"],
            "terminal_safety_status": report["terminal_safety_status"],
            "global_stop_code": report["global_stop_code"],
            "repository_sha": config.repository_sha,
            "github_run_id": config.github_run_id,
            "claim_ids": list(CLAIM_IDS),
            "cycle_count": report["cycle_count"],
            "completed_cycle_count": report["completed_cycle_count"],
            "completed_branch_count": completed,
            "incomplete_branch_count": incomplete,
            "validated_capture_count": report["validated_capture_count"],
            "first_verified_capture_time_utc": report["first_verified_capture_time_utc"],
            "capture_times_utc": report["capture_times_utc"],
            "source_timestamp_min_utc": report["source_timestamp_min_utc"],
            "source_timestamp_max_utc": report["source_timestamp_max_utc"],
            "row_count": len(rows_tuple),
            "match_count": report["match_count"],
            "bookmaker_count": report["bookmaker_count"],
            "market_branch_coverage": report["market_branch_coverage"],
            "market_outcome_row_counts": report["market_outcome_row_counts"],
            "sport_coverage": report["sport_coverage"],
            "provider_requests_new": consumption["provider_requests_new"],
            "provider_requests_cumulative": consumption["provider_requests_cumulative"],
            "provider_credits_new_exact": consumption["provider_credits_new_exact"],
            "provider_credits_cumulative_upper_bound": consumption[
                "provider_credits_cumulative_upper_bound"
            ],
            "consumption": consumption,
            "effect_accounting": report["effect_accounting"],
            "private_report_r2_status": "VERIFIED",
            "private_report_r2_key": report_key,
            "private_report_r2_sha256": report_sha256,
            "private_json_sha256": report_sha256,
            "csv_sha256": hashlib.sha256(csv_bytes).hexdigest(),
            "html_sha256": hashlib.sha256(html_bytes).hexdigest(),
            "automatic_retries": 0,
            "purchases": 0,
            "real_bets": 0,
            "backfills": 0,
            "promotions": 0,
        }
        _write_exclusive(config.output_directory / "robin-real-data.json", report_bytes)
        _write_exclusive(config.output_directory / "robin-real-data.csv", csv_bytes)
        _write_exclusive(config.output_directory / "robin-real-data.html", html_bytes)
        _write_exclusive(
            config.output_directory / "public-receipt.json",
            canonical_json_bytes(public_receipt),
        )
        return public_receipt
    finally:
        api_key = ""


__all__ = [
    "CLAIM_IDS",
    "MANDATE_SHA256",
    "MARKETS",
    "MISSION_ID",
    "NetworkResolution",
    "ResultConfig",
    "ResultError",
    "SPORT_KEYS",
    "run_real_data_result",
]
