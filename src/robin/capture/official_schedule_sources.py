"""Fail-closed official schedule acquisition and five-league parsing boundary."""

from __future__ import annotations

import hashlib
import html
import http.client
import importlib
import io
import json
import re
import ssl
import time
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol, cast
from urllib.parse import parse_qs, urljoin, urlparse
from zoneinfo import ZoneInfo

from robin.capture.live_contracts import LIVE_ALLOWED_SPORT_KEYS

SOURCE_PLAN_SCHEMA = "robin-official-schedule-source-plan-v1"
EVIDENCE_SCHEMA = "robin-owner-observed-official-schedule-v1"
RECONCILIATION_SCHEMA = "robin-official-schedule-reconciliation-v1"
MAXIMUM_SOURCE_BYTES = 16_777_216
MAXIMUM_REDIRECTS = 5
MAXIMUM_SOURCE_AGE = timedelta(minutes=30)
DEFAULT_TIMEOUT_SECONDS = 45.0
LALIGA_BOOTSTRAP_URL = "https://www.laliga.com/en-GB/laliga-easports/results"
LIGUE1_CALENDAR_URL = "https://ma-api.ligue1.fr/championship-calendar/1?season=2026"
LIGUE1_GAMEWEEK_URL_TEMPLATE = (
    "https://ma-api.ligue1.fr/championship-matches/championship/1/game-week/{gameweek}?season=2026"
)
LIGUE1_MAXIMUM_GAMEWEEK_READS = 5

PREMIER_LEAGUE_FULL_SEASON_HTML_V1 = "PREMIER_LEAGUE_FULL_SEASON_HTML_V1"
LALIGA_PUBLIC_MATCHES_JSON_V1 = "LALIGA_PUBLIC_MATCHES_JSON_V1"
DFB_DATACENTER_HTML_V1 = "DFB_DATACENTER_HTML_V1"
LEGA_SERIE_A_CALENDAR_PDF_V1 = "LEGA_SERIE_A_CALENDAR_PDF_V1"
LIGUE1_CALENDAR_JSON_V1 = "LIGUE1_CALENDAR_JSON_V1"

_ADAPTER_BY_SPORT = {
    "soccer_epl": PREMIER_LEAGUE_FULL_SEASON_HTML_V1,
    "soccer_spain_la_liga": LALIGA_PUBLIC_MATCHES_JSON_V1,
    "soccer_germany_bundesliga": DFB_DATACENTER_HTML_V1,
    "soccer_italy_serie_a": LEGA_SERIE_A_CALENDAR_PDF_V1,
    "soccer_france_ligue_one": LIGUE1_CALENDAR_JSON_V1,
}
_OFFICIAL_DOMAINS_BY_ADAPTER = {
    PREMIER_LEAGUE_FULL_SEASON_HTML_V1: ("premierleague.com",),
    LALIGA_PUBLIC_MATCHES_JSON_V1: ("laliga.com",),
    DFB_DATACENTER_HTML_V1: ("dfb.de",),
    LEGA_SERIE_A_CALENDAR_PDF_V1: ("legaseriea.it",),
    LIGUE1_CALENDAR_JSON_V1: ("ma-api.ligue1.fr",),
}
_CONTENT_TYPES_BY_ADAPTER = {
    PREMIER_LEAGUE_FULL_SEASON_HTML_V1: ("text/html", "application/xhtml+xml"),
    LALIGA_PUBLIC_MATCHES_JSON_V1: ("application/json",),
    DFB_DATACENTER_HTML_V1: ("text/html", "application/xhtml+xml"),
    LEGA_SERIE_A_CALENDAR_PDF_V1: ("application/pdf",),
    LIGUE1_CALENDAR_JSON_V1: ("application/json",),
}
_COMPETITION_BY_SPORT = {
    "soccer_epl": "Premier League",
    "soccer_spain_la_liga": "LALIGA EA SPORTS",
    "soccer_germany_bundesliga": "Bundesliga",
    "soccer_italy_serie_a": "Serie A Enilive",
    "soccer_france_ligue_one": "Ligue 1 McDonald's",
}
_DENIED_PROVIDER_HOSTS = frozenset({"api.the-odds-api.com"})


class OfficialScheduleSourceError(RuntimeError):
    """Stable fail-closed error with an optional rejected fetch receipt."""

    def __init__(
        self,
        code: str,
        *,
        receipt: OfficialFetchReceipt | None = None,
    ) -> None:
        self.code = code
        self.receipt = receipt
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class OfficialSourceSpec:
    sport_key: str
    adapter: str
    url: str

    @property
    def allowed_domains(self) -> tuple[str, ...]:
        return _OFFICIAL_DOMAINS_BY_ADAPTER[self.adapter]


@dataclass(frozen=True, slots=True)
class OfficialSourcePlan:
    season: str
    sources: tuple[OfficialSourceSpec, ...]
    canonical_sha256: str

    def source(self, sport_key: str) -> OfficialSourceSpec:
        matches = tuple(item for item in self.sources if item.sport_key == sport_key)
        if len(matches) != 1:
            raise OfficialScheduleSourceError("OFFICIAL_SOURCE_PLAN_SPORT_MISSING")
        return matches[0]

    def to_json(self) -> dict[str, object]:
        return {
            "schema_version": SOURCE_PLAN_SCHEMA,
            "season": self.season,
            "sources": {
                item.sport_key: {"adapter": item.adapter, "url": item.url} for item in self.sources
            },
        }


@dataclass(frozen=True, slots=True)
class RedirectHop:
    requested_url: str
    status_code: int
    location: str

    def to_json(self) -> dict[str, object]:
        return {
            "requested_url": self.requested_url,
            "status_code": self.status_code,
            "location": self.location,
        }


@dataclass(frozen=True, slots=True)
class OfficialHttpResponse:
    status_code: int
    final_url: str
    content_type: str
    body: bytes
    redirect_chain: tuple[RedirectHop, ...] = ()
    supporting_official_reads: tuple[SupportingOfficialRead, ...] = ()
    supporting_official_raw_bytes: tuple[bytes, ...] = ()


@dataclass(frozen=True, slots=True)
class OfficialPhysicalResponse:
    """Exact bytes and timing for each physical official HTTP response."""

    requested_url: str
    status_code: int
    content_type: str
    response_headers: Mapping[str, str]
    body: bytes
    observed_at_utc: datetime


@dataclass(frozen=True, slots=True)
class SupportingOfficialRead:
    requested_url: str
    final_url: str
    official_domain: str
    status_code: int
    content_type: str
    byte_count: int
    raw_sha256: str
    redirect_chain: tuple[RedirectHop, ...]

    def to_json(self) -> dict[str, object]:
        return {
            "requested_url": self.requested_url,
            "final_url": self.final_url,
            "official_domain": self.official_domain,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "byte_count": self.byte_count,
            "raw_sha256": self.raw_sha256,
            "redirect_chain": [item.to_json() for item in self.redirect_chain],
        }


class OfficialScheduleFetcher(Protocol):
    def fetch(self, source: OfficialSourceSpec) -> OfficialHttpResponse: ...


@dataclass(frozen=True, slots=True)
class OfficialFetchReceipt:
    sport_key: str
    adapter_revision: str
    requested_url: str
    final_url: str
    official_domain: str
    observed_at_utc: datetime
    http_status: int
    content_type: str
    byte_count: int
    raw_sha256: str
    redirect_chain: tuple[RedirectHop, ...]
    accepted: bool
    rejection_code: str | None
    supporting_official_reads: tuple[SupportingOfficialRead, ...] = ()

    def to_json(self) -> dict[str, object]:
        return {
            "schema_version": "robin-official-schedule-fetch-receipt-v1",
            "sport_key": self.sport_key,
            "adapter_revision": self.adapter_revision,
            "requested_url": self.requested_url,
            "final_url": self.final_url,
            "official_domain": self.official_domain,
            "observed_at_utc": _utc_text(self.observed_at_utc),
            "http_status": self.http_status,
            "content_type": self.content_type,
            "byte_count": self.byte_count,
            "raw_sha256": self.raw_sha256,
            "redirect_chain": [item.to_json() for item in self.redirect_chain],
            "accepted": self.accepted,
            "rejection_code": self.rejection_code,
            "supporting_official_reads": [
                item.to_json() for item in self.supporting_official_reads
            ],
        }


@dataclass(frozen=True, slots=True)
class OfficialFetchResult:
    raw_bytes: bytes
    receipt: OfficialFetchReceipt
    supporting_official_raw_bytes: tuple[bytes, ...] = ()


@dataclass(frozen=True, slots=True)
class OfficialFixture:
    home: str
    away: str
    kickoff_utc: datetime
    official_id: str
    kickoff_confirmed: bool = True
    round_number: int | None = None
    source_authority: str | None = None
    source_content_sha256: str | None = None
    source_pointer: str | None = None
    source_record_ordinal: int | None = None
    home_official_id: str | None = None
    away_official_id: str | None = None


@dataclass(frozen=True, slots=True)
class OfficialScheduleEvidence:
    sport_key: str
    source_authority: str
    source_content_sha256: str
    source_observed_at_utc: datetime
    horizon_not_before_utc: datetime
    horizon_expires_at_utc: datetime
    fixtures: tuple[OfficialFixture, ...]
    adapter_revision: str
    parser_metadata: Mapping[str, object]

    def to_json(self) -> dict[str, object]:
        fixtures: list[dict[str, object]] = []
        for item in self.fixtures:
            identity = "|".join(
                (
                    self.sport_key,
                    _utc_text(item.kickoff_utc),
                    item.home,
                    item.away,
                    item.official_id,
                )
            )
            fixtures.append(
                {
                    "internal_fixture_target_id": (
                        f"official-{self.sport_key}-{hashlib.sha256(identity.encode()).hexdigest()[:24]}"
                    ),
                    "competition": _COMPETITION_BY_SPORT[self.sport_key],
                    "official_home_team": item.home,
                    "official_away_team": item.away,
                    "official_kickoff_utc": _utc_text(item.kickoff_utc),
                    "source_authority": item.source_authority or self.source_authority,
                    "source_content_sha256": (
                        item.source_content_sha256 or self.source_content_sha256
                    ),
                    "source_pointer": (
                        item.source_pointer or f"adapter_projection.fixtures[{len(fixtures)}]"
                    ),
                    "source_record_ordinal": (
                        item.source_record_ordinal
                        if item.source_record_ordinal is not None
                        else len(fixtures)
                    ),
                }
            )
        return {
            "schema_version": EVIDENCE_SCHEMA,
            "target_set_id": f"official-horizon-{self.sport_key}-{hashlib.sha256(_canonical_bytes({'source_sha256': self.source_content_sha256, 'horizon_not_before_utc': _utc_text(self.horizon_not_before_utc), 'horizon_expires_at_utc': _utc_text(self.horizon_expires_at_utc), 'fixtures': fixtures})).hexdigest()[:24]}",
            "sport_key": self.sport_key,
            "official_source_authority": self.source_authority,
            "official_source_content_sha256": self.source_content_sha256,
            "source_observed_at_utc": _utc_text(self.source_observed_at_utc),
            "selection_horizon_not_before_utc": _utc_text(self.horizon_not_before_utc),
            "selection_horizon_expires_at_utc": _utc_text(self.horizon_expires_at_utc),
            "official_schedule_fixture_count": len(fixtures),
            "official_schedule_completeness": "OWNER_REVIEWED_COMPLETE_OFFICIAL_HORIZON",
            "adapter_revision": self.adapter_revision,
            "parser_metadata": dict(self.parser_metadata),
            "fixtures": fixtures,
        }


class _PdfPage(Protocol):
    def extract_text(self) -> str | None: ...


class _PdfReader(Protocol):
    pages: Sequence[_PdfPage]


PdfTextExtractor = Callable[[bytes], str]


def _utc(value: datetime, *, code: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise OfficialScheduleSourceError(code)
    return value.astimezone(UTC)


def _utc_text(value: datetime) -> str:
    return _utc(value, code="OFFICIAL_SCHEDULE_DATETIME_INVALID").isoformat().replace("+00:00", "Z")


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _clean(value: str) -> str:
    return " ".join(html.unescape(re.sub(r"<[^>]+>", "", value)).split())


def _host_allowed(host: str, domains: tuple[str, ...]) -> bool:
    normalized = host.rstrip(".").casefold()
    return any(normalized == item or normalized.endswith(f".{item}") for item in domains)


def _validate_official_url(url: str, source: OfficialSourceSpec) -> str:
    parsed = urlparse(url)
    host = (parsed.hostname or "").rstrip(".").casefold()
    try:
        port = parsed.port
    except ValueError:
        raise OfficialScheduleSourceError("OFFICIAL_SOURCE_URL_INVALID") from None
    if (
        parsed.scheme.casefold() != "https"
        or not host
        or parsed.username
        or parsed.password
        or parsed.fragment
        or port not in {None, 443}
    ):
        raise OfficialScheduleSourceError("OFFICIAL_SOURCE_URL_INVALID")
    if host in _DENIED_PROVIDER_HOSTS:
        raise OfficialScheduleSourceError("OFFICIAL_SOURCE_PROVIDER_HOST_FORBIDDEN")
    if not _host_allowed(host, source.allowed_domains):
        raise OfficialScheduleSourceError("OFFICIAL_SOURCE_HOST_FORBIDDEN")
    return host


def _extract_laliga_public_subscription(payload: bytes) -> str:
    try:
        source = payload.decode("utf-8")
    except UnicodeDecodeError:
        raise OfficialScheduleSourceError("LALIGA_BOOTSTRAP_AUTHORITY_INVALID") from None
    match = re.search(
        r'<script[^>]+id=["\']__NEXT_DATA__["\'][^>]*>(.*?)</script>',
        source,
        flags=re.DOTALL | re.IGNORECASE,
    )
    if match is None:
        raise OfficialScheduleSourceError("LALIGA_BOOTSTRAP_AUTHORITY_INVALID")
    try:
        document = json.loads(match.group(1))
    except json.JSONDecodeError:
        raise OfficialScheduleSourceError("LALIGA_BOOTSTRAP_AUTHORITY_INVALID") from None
    if not isinstance(document, dict):
        raise OfficialScheduleSourceError("LALIGA_BOOTSTRAP_AUTHORITY_INVALID")
    candidates: tuple[object, ...] = (
        document.get("runtimeConfig"),
        document.get("props"),
    )
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        runtime = candidate.get("runtimeConfig", candidate)
        if not isinstance(runtime, dict):
            continue
        subscription = runtime.get("backendSubscription")
        if isinstance(subscription, str) and subscription.strip():
            return subscription.strip()
    raise OfficialScheduleSourceError("LALIGA_BOOTSTRAP_AUTHORITY_INVALID")


def load_official_source_plan_bytes(payload: bytes) -> OfficialSourcePlan:
    if len(payload) > 1_048_576:
        raise OfficialScheduleSourceError("OFFICIAL_SOURCE_PLAN_TOO_LARGE")
    try:
        raw = json.loads(payload, object_pairs_hook=_reject_duplicate_json_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise OfficialScheduleSourceError("OFFICIAL_SOURCE_PLAN_INVALID") from None
    if not isinstance(raw, dict) or set(raw) != {"schema_version", "season", "sources"}:
        raise OfficialScheduleSourceError("OFFICIAL_SOURCE_PLAN_INVALID")
    season = raw.get("season")
    sources = raw.get("sources")
    if (
        raw.get("schema_version") != SOURCE_PLAN_SCHEMA
        or season != "2026-2027"
        or not isinstance(sources, dict)
        or set(sources) != set(LIVE_ALLOWED_SPORT_KEYS)
    ):
        raise OfficialScheduleSourceError("OFFICIAL_SOURCE_PLAN_INVALID")
    parsed_sources: list[OfficialSourceSpec] = []
    for sport_key in LIVE_ALLOWED_SPORT_KEYS:
        entry = sources.get(sport_key)
        if not isinstance(entry, dict) or set(entry) != {"adapter", "url"}:
            raise OfficialScheduleSourceError("OFFICIAL_SOURCE_PLAN_ENTRY_INVALID")
        adapter = entry.get("adapter")
        url = entry.get("url")
        if adapter != _ADAPTER_BY_SPORT[sport_key] or not isinstance(url, str):
            raise OfficialScheduleSourceError("OFFICIAL_SOURCE_PLAN_ADAPTER_INVALID")
        source = OfficialSourceSpec(sport_key=sport_key, adapter=adapter, url=url)
        _validate_official_url(url, source)
        if adapter == LALIGA_PUBLIC_MATCHES_JSON_V1:
            parsed_url = urlparse(url)
            query = parse_qs(parsed_url.query, keep_blank_values=True)
            if (
                (parsed_url.hostname or "").casefold() != "apim.laliga.com"
                or query.get("limit") != ["100"]
                or query.get("offset") != ["300"]
            ):
                raise OfficialScheduleSourceError("LALIGA_PAGINATION_AUTHORITY_INVALID")
        if adapter == LIGUE1_CALENDAR_JSON_V1:
            parsed_url = urlparse(url)
            query = parse_qs(parsed_url.query, keep_blank_values=True)
            if (
                (parsed_url.hostname or "").casefold() != "ma-api.ligue1.fr"
                or parsed_url.path != "/championship-calendar/1"
                or set(query) != {"season"}
                or query.get("season") != ["2026"]
                or url != LIGUE1_CALENDAR_URL
            ):
                raise OfficialScheduleSourceError("LIGUE1_CALENDAR_AUTHORITY_INVALID")
        parsed_sources.append(source)
    canonical = {
        "schema_version": SOURCE_PLAN_SCHEMA,
        "season": season,
        "sources": {
            item.sport_key: {"adapter": item.adapter, "url": item.url} for item in parsed_sources
        },
    }
    return OfficialSourcePlan(
        season=season,
        sources=tuple(parsed_sources),
        canonical_sha256=hashlib.sha256(_canonical_bytes(canonical)).hexdigest(),
    )


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("OFFICIAL_SOURCE_PLAN_DUPLICATE_KEY")
        result[key] = value
    return result


class BuiltinHttpsOfficialScheduleFetcher:
    """Direct HTTPS client: no proxy, netrc, persistent cookie, auth or ambient session."""

    def __init__(
        self,
        *,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        maximum_bytes: int = MAXIMUM_SOURCE_BYTES,
        maximum_redirects: int = MAXIMUM_REDIRECTS,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        monotonic: Callable[[], float] = time.monotonic,
        on_dispatch: Callable[[str], None] | None = None,
        on_response: Callable[[OfficialPhysicalResponse], None] | None = None,
        on_partial_response: Callable[[OfficialPhysicalResponse], None] | None = None,
        horizon_not_before_utc: datetime | None = None,
        horizon_expires_at_utc: datetime | None = None,
    ) -> None:
        if (
            timeout_seconds <= 0
            or maximum_bytes <= 0
            or not isinstance(maximum_redirects, int)
            or isinstance(maximum_redirects, bool)
            or not 0 <= maximum_redirects <= MAXIMUM_REDIRECTS
        ):
            raise ValueError("OFFICIAL_FETCH_LIMIT_INVALID")
        self._timeout_seconds = timeout_seconds
        self._maximum_bytes = maximum_bytes
        self._maximum_redirects = maximum_redirects
        self._clock = clock
        self._monotonic = monotonic
        self._on_dispatch = on_dispatch
        self._on_response = on_response
        self._on_partial_response = on_partial_response
        self._horizon_not_before_utc = horizon_not_before_utc
        self._horizon_expires_at_utc = horizon_expires_at_utc

    def _request(
        self,
        source: OfficialSourceSpec,
        requested_url: str,
        *,
        extra_headers: Mapping[str, str] | None = None,
        maximum_redirects: int | None = None,
    ) -> OfficialHttpResponse:
        current_url = requested_url
        redirects: list[RedirectHop] = []
        redirect_limit = self._maximum_redirects if maximum_redirects is None else maximum_redirects
        if not 0 <= redirect_limit <= self._maximum_redirects:
            raise OfficialScheduleSourceError("OFFICIAL_SOURCE_REDIRECT_LIMIT_INVALID")
        for _ in range(redirect_limit + 1):
            host = _validate_official_url(current_url, source)
            parsed = urlparse(current_url)
            target = parsed.path or "/"
            if parsed.query:
                target = f"{target}?{parsed.query}"
            connection = http.client.HTTPSConnection(
                host,
                port=parsed.port or 443,
                timeout=self._timeout_seconds,
                context=ssl.create_default_context(),
            )
            try:
                headers = {
                    "Accept": ", ".join(_CONTENT_TYPES_BY_ADAPTER[source.adapter]),
                    "Accept-Encoding": "identity",
                    "Connection": "close",
                    "User-Agent": "RobinOfficialScheduleBoundary/1",
                }
                headers.update(extra_headers or {})
                dispatch_started = self._monotonic()
                if self._on_dispatch is not None:
                    self._on_dispatch(current_url)
                connection.request(
                    "GET",
                    target,
                    headers=headers,
                )
                response = connection.getresponse()
                status = response.status
                content_type = response.getheader("Content-Type", "")
                location = response.getheader("Location")
                length_header = response.getheader("Content-Length")
                raw_headers = response.getheaders()
                safe_headers = {
                    name.casefold(): value.strip()
                    for name, value in raw_headers
                    if name.casefold()
                    in {
                        "content-type",
                        "content-length",
                        "etag",
                        "last-modified",
                        "date",
                    }
                    and value.isascii()
                    and len(value) <= 512
                    and not any(character in value for character in "\r\n\x00")
                }

                def physical_response(payload: bytes) -> OfficialPhysicalResponse:
                    return OfficialPhysicalResponse(
                        requested_url=current_url,
                        status_code=status,
                        content_type=content_type,
                        response_headers=safe_headers,
                        body=payload,
                        observed_at_utc=_utc(
                            self._clock(),
                            code="OFFICIAL_FETCH_TIME_INVALID",
                        ),
                    )

                chunks: list[bytes] = []
                total = 0

                def tighten_body_deadline() -> None:
                    remaining = self._timeout_seconds - (self._monotonic() - dispatch_started)
                    if remaining <= 0:
                        raise TimeoutError("OFFICIAL_SOURCE_TOTAL_DEADLINE_EXCEEDED")
                    network_socket = getattr(connection, "sock", None)
                    setter = getattr(network_socket, "settimeout", None)
                    if callable(setter):
                        setter(remaining)

                try:
                    read1 = getattr(response, "read1", None)
                    if callable(read1):
                        while total <= self._maximum_bytes:
                            tighten_body_deadline()
                            chunk = read1(min(65_536, self._maximum_bytes + 1 - total))
                            if not isinstance(chunk, bytes):
                                raise http.client.HTTPException("OFFICIAL_SOURCE_BODY_INVALID")
                            if chunk:
                                chunks.append(chunk)
                                total += len(chunk)
                            # A socket timeout bounds an individual operation;
                            # the monotonic check after it bounds the full read,
                            # including a slow final chunk or slow EOF.
                            tighten_body_deadline()
                            if not chunk:
                                break
                    else:
                        tighten_body_deadline()
                        chunk = response.read(self._maximum_bytes + 1)
                        if not isinstance(chunk, bytes):
                            raise http.client.HTTPException("OFFICIAL_SOURCE_BODY_INVALID")
                        chunks.append(chunk)
                        tighten_body_deadline()
                except http.client.IncompleteRead as error:
                    partial_body = (b"".join(chunks) + bytes(error.partial))[
                        : self._maximum_bytes + 1
                    ]
                    if self._on_partial_response is not None:
                        self._on_partial_response(physical_response(partial_body))
                    raise OfficialScheduleSourceError("OFFICIAL_SOURCE_NETWORK_FAILED") from error
                except (OSError, ssl.SSLError, http.client.HTTPException) as error:
                    partial_body = b"".join(chunks)[: self._maximum_bytes + 1]
                    if self._on_partial_response is not None:
                        self._on_partial_response(physical_response(partial_body))
                    raise OfficialScheduleSourceError("OFFICIAL_SOURCE_NETWORK_FAILED") from error
                body = b"".join(chunks)
                physical = physical_response(body)
                declared_length: int | None = None
                length_invalid = False
                if length_header is not None:
                    if not length_header.isascii() or not length_header.isdigit():
                        length_invalid = True
                    else:
                        declared_length = int(length_header)
                length_mismatch = declared_length is not None and len(body) != declared_length
                body_complete = (
                    len(body) <= self._maximum_bytes and not length_invalid and not length_mismatch
                )
                if body_complete and self._on_response is not None:
                    self._on_response(physical)
                elif not body_complete and self._on_partial_response is not None:
                    self._on_partial_response(physical)
                content_encoding = (response.getheader("Content-Encoding") or "").strip().casefold()
                if content_encoding not in {"", "identity"}:
                    raise OfficialScheduleSourceError("OFFICIAL_SOURCE_CONTENT_ENCODING_INVALID")
                if length_invalid:
                    raise OfficialScheduleSourceError("OFFICIAL_SOURCE_CONTENT_LENGTH_INVALID")
                if declared_length is not None and declared_length > self._maximum_bytes:
                    raise OfficialScheduleSourceError("OFFICIAL_SOURCE_RESPONSE_TOO_LARGE")
                if length_mismatch:
                    raise OfficialScheduleSourceError("OFFICIAL_SOURCE_CONTENT_LENGTH_MISMATCH")
                if len(body) > self._maximum_bytes:
                    raise OfficialScheduleSourceError("OFFICIAL_SOURCE_RESPONSE_TOO_LARGE")
                if status in {301, 302, 303, 307, 308}:
                    if not location:
                        raise OfficialScheduleSourceError("OFFICIAL_SOURCE_REDIRECT_INVALID")
                    next_url = urljoin(current_url, location)
                    _validate_official_url(next_url, source)
                    redirects.append(
                        RedirectHop(
                            requested_url=current_url,
                            status_code=status,
                            location=next_url,
                        )
                    )
                    current_url = next_url
                    continue
                return OfficialHttpResponse(
                    status_code=status,
                    final_url=current_url,
                    content_type=content_type,
                    body=body,
                    redirect_chain=tuple(redirects),
                )
            except (OSError, ssl.SSLError, http.client.HTTPException) as error:
                raise OfficialScheduleSourceError("OFFICIAL_SOURCE_NETWORK_FAILED") from error
            finally:
                connection.close()
        raise OfficialScheduleSourceError("OFFICIAL_SOURCE_REDIRECT_LIMIT_EXCEEDED")

    def fetch(self, source: OfficialSourceSpec) -> OfficialHttpResponse:
        if source.adapter == LIGUE1_CALENDAR_JSON_V1:
            if self._horizon_not_before_utc is None or self._horizon_expires_at_utc is None:
                raise OfficialScheduleSourceError("LIGUE1_HORIZON_REQUIRED")
            calendar = self._request(source, source.url, maximum_redirects=0)
            calendar_type = calendar.content_type.split(";", 1)[0].strip().casefold()
            if (
                calendar.status_code != 200
                or calendar_type != "application/json"
                or not calendar.body
            ):
                raise OfficialScheduleSourceError("LIGUE1_CALENDAR_AUTHORITY_INVALID")
            references = _parse_ligue1_calendar_refs(
                calendar.body,
                horizon_starts=self._horizon_not_before_utc,
                horizon_expires=self._horizon_expires_at_utc,
            )
            supporting_reads: list[SupportingOfficialRead] = []
            supporting_raw: list[bytes] = []
            for reference in references:
                requested_url = LIGUE1_GAMEWEEK_URL_TEMPLATE.format(gameweek=reference.number)
                response = self._request(source, requested_url, maximum_redirects=0)
                normalized_type = response.content_type.split(";", 1)[0].strip().casefold()
                if (
                    response.status_code != 200
                    or normalized_type != "application/json"
                    or not response.body
                    or response.redirect_chain
                    or response.final_url != requested_url
                ):
                    raise OfficialScheduleSourceError("LIGUE1_GAMEWEEK_AUTHORITY_INVALID")
                supporting_reads.append(
                    SupportingOfficialRead(
                        requested_url=requested_url,
                        final_url=response.final_url,
                        official_domain=(urlparse(response.final_url).hostname or "").casefold(),
                        status_code=response.status_code,
                        content_type=response.content_type,
                        byte_count=len(response.body),
                        raw_sha256=hashlib.sha256(response.body).hexdigest(),
                        redirect_chain=response.redirect_chain,
                    )
                )
                supporting_raw.append(response.body)
            return OfficialHttpResponse(
                status_code=calendar.status_code,
                final_url=calendar.final_url,
                content_type=calendar.content_type,
                body=calendar.body,
                redirect_chain=calendar.redirect_chain,
                supporting_official_reads=tuple(supporting_reads),
                supporting_official_raw_bytes=tuple(supporting_raw),
            )
        if source.adapter != LALIGA_PUBLIC_MATCHES_JSON_V1:
            return self._request(source, source.url)
        if (urlparse(source.url).hostname or "").casefold() != "apim.laliga.com":
            raise OfficialScheduleSourceError("LALIGA_PAGINATION_AUTHORITY_INVALID")
        bootstrap = self._request(source, LALIGA_BOOTSTRAP_URL)
        bootstrap_type = bootstrap.content_type.split(";", 1)[0].strip().casefold()
        if bootstrap.status_code != 200 or bootstrap_type not in {
            "text/html",
            "application/xhtml+xml",
        }:
            raise OfficialScheduleSourceError("LALIGA_BOOTSTRAP_AUTHORITY_INVALID")
        subscription = _extract_laliga_public_subscription(bootstrap.body)
        result = self._request(
            source,
            source.url,
            extra_headers={"Ocp-Apim-Subscription-Key": subscription},
        )
        if subscription.encode("utf-8") in result.body:
            raise OfficialScheduleSourceError("LALIGA_BOOTSTRAP_SECRET_LEAK")
        subscription = ""
        supporting = SupportingOfficialRead(
            requested_url=LALIGA_BOOTSTRAP_URL,
            final_url=bootstrap.final_url,
            official_domain=(urlparse(bootstrap.final_url).hostname or "").casefold(),
            status_code=bootstrap.status_code,
            content_type=bootstrap.content_type,
            byte_count=len(bootstrap.body),
            raw_sha256=hashlib.sha256(bootstrap.body).hexdigest(),
            redirect_chain=bootstrap.redirect_chain,
        )
        return OfficialHttpResponse(
            status_code=result.status_code,
            final_url=result.final_url,
            content_type=result.content_type,
            body=result.body,
            redirect_chain=result.redirect_chain,
            supporting_official_reads=(supporting,),
            supporting_official_raw_bytes=(bootstrap.body,),
        )


def _receipt(
    source: OfficialSourceSpec,
    *,
    observed_at_utc: datetime,
    response: OfficialHttpResponse | None,
    accepted: bool,
    rejection_code: str | None,
) -> OfficialFetchReceipt:
    final_url = response.final_url if response is not None else source.url
    host = (urlparse(final_url).hostname or "").casefold()
    body = response.body if response is not None else b""
    return OfficialFetchReceipt(
        sport_key=source.sport_key,
        adapter_revision=source.adapter,
        requested_url=source.url,
        final_url=final_url,
        official_domain=host,
        observed_at_utc=_utc(observed_at_utc, code="OFFICIAL_FETCH_TIME_INVALID"),
        http_status=response.status_code if response is not None else 0,
        content_type=response.content_type if response is not None else "",
        byte_count=len(body),
        raw_sha256=hashlib.sha256(body).hexdigest(),
        redirect_chain=response.redirect_chain if response is not None else (),
        accepted=accepted,
        rejection_code=rejection_code,
        supporting_official_reads=(
            response.supporting_official_reads if response is not None else ()
        ),
    )


def fetch_official_schedule_source(
    source: OfficialSourceSpec,
    *,
    fetcher: OfficialScheduleFetcher,
    observed_at_utc: datetime | None = None,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> OfficialFetchResult:
    response: OfficialHttpResponse | None = None
    try:
        if _ADAPTER_BY_SPORT.get(source.sport_key) != source.adapter:
            raise OfficialScheduleSourceError("OFFICIAL_SOURCE_SPORT_ADAPTER_MISMATCH")
        _validate_official_url(source.url, source)
        response = fetcher.fetch(source)
        _validate_official_url(response.final_url, source)
        if len(response.redirect_chain) > MAXIMUM_REDIRECTS:
            raise OfficialScheduleSourceError("OFFICIAL_SOURCE_REDIRECT_LIMIT_EXCEEDED")
        expected_url = source.url
        for hop in response.redirect_chain:
            if hop.requested_url != expected_url or hop.status_code not in {
                301,
                302,
                303,
                307,
                308,
            }:
                raise OfficialScheduleSourceError("OFFICIAL_SOURCE_REDIRECT_CHAIN_INVALID")
            _validate_official_url(hop.requested_url, source)
            _validate_official_url(hop.location, source)
            expected_url = hop.location
        if response.final_url != expected_url:
            raise OfficialScheduleSourceError("OFFICIAL_SOURCE_REDIRECT_CHAIN_INVALID")
        if len(response.supporting_official_reads) != len(
            response.supporting_official_raw_bytes
        ) or any(
            item.status_code != 200
            or item.byte_count != len(raw)
            or item.raw_sha256 != hashlib.sha256(raw).hexdigest()
            or not _host_allowed(item.official_domain, source.allowed_domains)
            or not _redirect_chain_valid(
                item.requested_url,
                item.final_url,
                item.redirect_chain,
                source,
            )
            for item, raw in zip(
                response.supporting_official_reads,
                response.supporting_official_raw_bytes,
                strict=True,
            )
        ):
            raise OfficialScheduleSourceError("OFFICIAL_SUPPORTING_READ_INVALID")
        if response.status_code != 200:
            raise OfficialScheduleSourceError("OFFICIAL_SOURCE_HTTP_STATUS_INVALID")
        normalized_type = response.content_type.split(";", 1)[0].strip().casefold()
        if normalized_type not in _CONTENT_TYPES_BY_ADAPTER[source.adapter]:
            raise OfficialScheduleSourceError("OFFICIAL_SOURCE_CONTENT_TYPE_INVALID")
        if not response.body:
            raise OfficialScheduleSourceError("OFFICIAL_SOURCE_RESPONSE_EMPTY")
        if len(response.body) > MAXIMUM_SOURCE_BYTES:
            raise OfficialScheduleSourceError("OFFICIAL_SOURCE_RESPONSE_TOO_LARGE")
    except OfficialScheduleSourceError as error:
        observed = clock() if observed_at_utc is None else observed_at_utc
        rejected = _receipt(
            source,
            observed_at_utc=observed,
            response=response,
            accepted=False,
            rejection_code=error.code,
        )
        raise OfficialScheduleSourceError(error.code, receipt=rejected) from None
    observed = clock() if observed_at_utc is None else observed_at_utc
    accepted = _receipt(
        source,
        observed_at_utc=observed,
        response=response,
        accepted=True,
        rejection_code=None,
    )
    if response is None:
        raise OfficialScheduleSourceError("OFFICIAL_SOURCE_RESPONSE_MISSING")
    return OfficialFetchResult(
        raw_bytes=response.body,
        receipt=accepted,
        supporting_official_raw_bytes=response.supporting_official_raw_bytes,
    )


def _redirect_chain_valid(
    requested_url: str,
    final_url: str,
    chain: tuple[RedirectHop, ...],
    source: OfficialSourceSpec,
) -> bool:
    expected = requested_url
    try:
        _validate_official_url(expected, source)
        for hop in chain:
            if hop.requested_url != expected or hop.status_code not in {
                301,
                302,
                303,
                307,
                308,
            }:
                return False
            _validate_official_url(hop.location, source)
            expected = hop.location
        _validate_official_url(final_url, source)
    except OfficialScheduleSourceError:
        return False
    return expected == final_url


def _parse_iso_aware(value: str, *, code: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise OfficialScheduleSourceError(code) from None
    return _utc(parsed, code=code)


def _parse_epl(
    payload: bytes,
    *,
    horizon_starts: datetime,
    horizon_expires: datetime,
) -> tuple[tuple[OfficialFixture, ...], Mapping[str, object]]:
    try:
        source = payload.decode("utf-8")
    except UnicodeDecodeError:
        raise OfficialScheduleSourceError("EPL_SOURCE_ENCODING_INVALID") from None
    if "all 380 matches are below" not in source or "15:00 UK time" not in source:
        raise OfficialScheduleSourceError("EPL_FULL_SEASON_AUTHORITY_INVALID")
    months = {
        name: index
        for index, name in enumerate(
            (
                "January",
                "February",
                "March",
                "April",
                "May",
                "June",
                "July",
                "August",
                "September",
                "October",
                "November",
                "December",
            ),
            start=1,
        )
    }
    date_pattern = re.compile(
        r"^(Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday)\s+"
        r"(\d{1,2})\s+(" + "|".join(months) + r")(?:\s+(\d{4}))?$"
    )
    fixture_pattern = re.compile(
        r"^(?:(\d{1,2}:\d{2})(?:\s+(?:GMT|BST))?\s+)?(.+?)\s+v\s+(.+?)"
        r"(?:\s+\([^)]*\))?\**$"
    )
    london = ZoneInfo("Europe/London")
    current_date: datetime | None = None
    current_year = 2026
    fixtures: list[OfficialFixture] = []
    unconfirmed_kickoffs = 0
    paragraphs = re.findall(r"<p(?:\s[^>]*)?>(.*?)</p>", source, flags=re.DOTALL | re.IGNORECASE)
    for paragraph in paragraphs:
        paragraph = re.sub(
            r"<em(?:\s[^>]*)?>.*?</em>",
            "",
            paragraph,
            flags=re.DOTALL | re.IGNORECASE,
        )
        paragraph = re.sub(r"<br\s*/?>", "\n", paragraph, flags=re.IGNORECASE)
        for raw_line in paragraph.splitlines():
            line = _clean(raw_line)
            if not line:
                continue
            date_match = date_pattern.fullmatch(line)
            if date_match:
                weekday, day, month, explicit_year = date_match.groups()
                current_year = int(explicit_year or current_year)
                current_date = datetime(
                    current_year,
                    months[month],
                    int(day),
                    tzinfo=london,
                )
                if current_date.strftime("%A") != weekday:
                    raise OfficialScheduleSourceError("EPL_WEEKDAY_MISMATCH")
                continue
            if re.match(
                r"^(?:Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday)\b",
                line,
            ):
                current_date = None
                raise OfficialScheduleSourceError("EPL_DATE_HEADING_INVALID")
            if current_date is None or " v " not in line:
                continue
            fixture_match = fixture_pattern.fullmatch(line)
            if fixture_match is None:
                raise OfficialScheduleSourceError("EPL_FIXTURE_ROW_INVALID")
            display_time, home, away = fixture_match.groups()
            kickoff_confirmed = display_time is not None
            if not kickoff_confirmed:
                day_start = current_date.astimezone(UTC)
                day_end = (current_date + timedelta(days=1)).astimezone(UTC)
                if day_start < horizon_expires and day_end > horizon_starts:
                    raise OfficialScheduleSourceError("EPL_HORIZON_KICKOFF_UNCONFIRMED")
                unconfirmed_kickoffs += 1
            hour, minute = (int(value) for value in (display_time or "15:00").split(":"))
            kickoff = current_date.replace(hour=hour, minute=minute).astimezone(UTC)
            fixtures.append(
                OfficialFixture(
                    home=_clean(home),
                    away=_clean(away),
                    kickoff_utc=kickoff,
                    official_id=f"epl-{len(fixtures) + 1:03d}",
                    kickoff_confirmed=kickoff_confirmed,
                )
            )
    aliases = {"Newcastle": "Newcastle United"}

    def audit_name(value: str) -> str:
        return aliases.get(value, value)

    clubs = {audit_name(item.home) for item in fixtures} | {
        audit_name(item.away) for item in fixtures
    }
    pairs = Counter((audit_name(item.home), audit_name(item.away)) for item in fixtures)
    expected_pairs = {(home, away) for home in clubs for away in clubs if home != away}
    kickoff_counts = Counter(item.kickoff_utc for item in fixtures)
    team_kickoff_counts = Counter(
        (team, item.kickoff_utc)
        for item in fixtures
        for team in (audit_name(item.home), audit_name(item.away))
    )
    if (
        len(fixtures) != 380
        or len({(item.home, item.away, item.kickoff_utc) for item in fixtures}) != 380
        or len(clubs) != 20
        or set(pairs) != expected_pairs
        or any(count != 1 for count in pairs.values())
        or any(item.home == item.away for item in fixtures)
        or any(count > 10 for count in kickoff_counts.values())
        or any(count != 1 for count in team_kickoff_counts.values())
    ):
        raise OfficialScheduleSourceError("EPL_FULL_SEASON_COMPLETENESS_INVALID")
    return tuple(fixtures), {
        "full_source_fixture_count": 380,
        "club_count": 20,
        "directed_pair_count": 380,
        "unconfirmed_kickoff_count_outside_horizon": unconfirmed_kickoffs,
        "timezone": "Europe/London",
    }


def _team_name(value: object) -> str:
    if isinstance(value, str) and value.strip():
        return " ".join(value.split())
    if isinstance(value, dict):
        for key in ("nickname", "boundname", "official_name", "name", "shortname", "short_name"):
            candidate = value.get(key)
            if isinstance(candidate, str) and candidate.strip():
                return " ".join(candidate.split())
    raise OfficialScheduleSourceError("LALIGA_TEAM_NAME_MISSING")


def _parse_laliga(
    payload: bytes,
    *,
    horizon_starts: datetime,
    horizon_expires: datetime,
) -> tuple[tuple[OfficialFixture, ...], Mapping[str, object]]:
    try:
        raw = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise OfficialScheduleSourceError("LALIGA_JSON_INVALID") from None
    if not isinstance(raw, dict):
        raise OfficialScheduleSourceError("LALIGA_JSON_INVALID")
    matches: object = raw.get("matches")
    data = raw.get("data")
    if not isinstance(matches, list) and isinstance(data, list):
        matches = data
    elif not isinstance(matches, list) and isinstance(data, dict):
        matches = data.get("matches")
    if not isinstance(matches, list):
        raise OfficialScheduleSourceError("LALIGA_MATCH_ENVELOPE_INVALID")
    total_candidates: list[object] = [raw.get("total")]
    for container in (raw.get("pagination"), data):
        if isinstance(container, dict):
            total_candidates.append(container.get("total"))
            pagination = container.get("pagination")
            if isinstance(pagination, dict):
                total_candidates.append(pagination.get("total"))
    totals = {
        value
        for value in total_candidates
        if isinstance(value, int) and not isinstance(value, bool)
    }
    if totals != {380}:
        raise OfficialScheduleSourceError("LALIGA_PAGINATION_AUTHORITY_INVALID")
    fixtures: list[OfficialFixture] = []
    ids: list[str] = []
    weeks: Counter[int] = Counter()
    for item in matches:
        if not isinstance(item, dict):
            raise OfficialScheduleSourceError("LALIGA_MATCH_INVALID")
        competition = item.get("competition")
        slug = competition.get("slug") if isinstance(competition, dict) else competition
        if slug != "primera-division":
            raise OfficialScheduleSourceError("LALIGA_COMPETITION_INVALID")
        date_value = item.get("date")
        if not isinstance(date_value, str):
            raise OfficialScheduleSourceError("OFFICIAL_SCHEDULE_KICKOFF_MISSING")
        kickoff = _parse_iso_aware(date_value, code="OFFICIAL_SCHEDULE_KICKOFF_TIMEZONE_INVALID")
        if (
            horizon_starts <= kickoff < horizon_expires
            and kickoff.hour == kickoff.minute == kickoff.second == 0
        ):
            raise OfficialScheduleSourceError("OFFICIAL_SCHEDULE_KICKOFF_PLACEHOLDER")
        raw_id = item.get("id", item.get("opta_id"))
        if raw_id is None or not str(raw_id).strip():
            raise OfficialScheduleSourceError("LALIGA_MATCH_ID_MISSING")
        gameweek = item.get("gameweek")
        raw_week = gameweek.get("week") if isinstance(gameweek, dict) else gameweek
        if isinstance(raw_week, str) and raw_week.isdigit():
            raw_week = int(raw_week)
        if isinstance(raw_week, bool) or not isinstance(raw_week, int) or not 1 <= raw_week <= 38:
            raise OfficialScheduleSourceError("LALIGA_GAMEWEEK_INVALID")
        official_id = str(raw_id)
        fixtures.append(
            OfficialFixture(
                home=_team_name(item.get("home_team")),
                away=_team_name(item.get("away_team")),
                kickoff_utc=kickoff,
                official_id=official_id,
                round_number=raw_week,
            )
        )
        ids.append(official_id)
        weeks[raw_week] += 1
    round_appearances = {
        week: Counter(
            team
            for item in fixtures
            if item.round_number == week
            for team in (item.home, item.away)
        )
        for week in range(1, 9)
    }
    club_appearances = Counter(team for item in fixtures for team in (item.home, item.away))
    season_starts = datetime(2026, 7, 1, tzinfo=UTC)
    season_expires = datetime(2027, 7, 1, tzinfo=UTC)
    if (
        len(fixtures) != 80
        or any(weeks[week] != 10 for week in range(1, 9))
        or len(ids) != len(set(ids))
        or len({(item.home, item.away, item.kickoff_utc) for item in fixtures}) != len(fixtures)
        or any(left.kickoff_utc < right.kickoff_utc for left, right in zip(fixtures, fixtures[1:]))
        or any(item.home == item.away for item in fixtures)
        or len(club_appearances) != 20
        or any(count != 8 for count in club_appearances.values())
        or any(
            len(appearances) != 20 or any(count != 1 for count in appearances.values())
            for appearances in round_appearances.values()
        )
        or any(not season_starts <= item.kickoff_utc < season_expires for item in fixtures)
    ):
        raise OfficialScheduleSourceError("LALIGA_PAGINATION_AUTHORITY_INVALID")
    return tuple(fixtures), {
        "response_total": 380,
        "response_fixture_count": 80,
        "request_limit": 100,
        "request_offset": 300,
        "gameweek_fixture_counts": dict(sorted(weeks.items())),
        "club_count": len(club_appearances),
        "club_appearances": dict(sorted(club_appearances.items())),
    }


def _parse_bundesliga(
    payload: bytes,
    *,
    horizon_starts: datetime,
    horizon_expires: datetime,
) -> tuple[tuple[OfficialFixture, ...], Mapping[str, object]]:
    try:
        source = payload.decode("utf-8")
    except UnicodeDecodeError:
        raise OfficialScheduleSourceError("BUNDESLIGA_SOURCE_ENCODING_INVALID") from None
    if "Bundesliga 2026/27" not in source or "der Spielplan" not in source:
        raise OfficialScheduleSourceError("BUNDESLIGA_SEASON_AUTHORITY_INVALID")
    matchdays = {int(value) for value in re.findall(r"(\d{1,2})\. Spieltag", source)}
    if matchdays != set(range(1, 35)):
        raise OfficialScheduleSourceError("BUNDESLIGA_MATCHDAY_TABLE_INCOMPLETE")
    sections = re.split(r"(\d{1,2})\. Spieltag", source)
    dated_counts = {
        int(sections[index]): len(
            re.findall(
                r"\d{2}\.\d{2}\.\d{4}\s+\d{2}:\d{2}\s+Uhr",
                sections[index + 1],
            )
        )
        for index in range(1, len(sections), 2)
    }
    if (
        any(count not in {0, 9} for count in dated_counts.values())
        or sum(count for count in dated_counts.values()) != 45
    ):
        raise OfficialScheduleSourceError("BUNDESLIGA_EXACT_DATED_TABLE_INVALID")
    berlin = ZoneInfo("Europe/Berlin")
    fixtures: list[OfficialFixture] = []
    dated_round_clubs: dict[int, frozenset[str]] = {}
    for index in range(1, len(sections), 2):
        round_number = int(sections[index])
        if dated_counts[round_number] == 0:
            continue
        round_fixtures: list[OfficialFixture] = []
        blocks = re.split(
            r'<div\s+class="c-MatchTable-row"\s*>',
            sections[index + 1],
        )[1:]
        for block in blocks:
            date_match = re.search(
                r"(?:Montag|Dienstag|Mittwoch|Donnerstag|Freitag|Samstag|Sonntag),\s*"
                r"(\d{2}\.\d{2}\.\d{4})\s+(\d{2}:\d{2})\s+Uhr",
                block,
            )
            if date_match is None:
                continue
            local = datetime.strptime(
                " ".join(date_match.groups()),
                "%d.%m.%Y %H:%M",
            ).replace(tzinfo=berlin)
            kickoff = local.astimezone(UTC)
            id_match = re.search(r'id="match_(\d+)"', block)
            home_match = re.search(
                r"c-MatchTable-team--home[^>]*>.*?<a\s+[^>]*>(.*?)</a>",
                block,
                flags=re.DOTALL,
            )
            away_match = re.search(
                r"c-MatchTable-team--away[^>]*>.*?<a\s+[^>]*>(.*?)</a>",
                block,
                flags=re.DOTALL,
            )
            if id_match is None or home_match is None or away_match is None:
                raise OfficialScheduleSourceError("BUNDESLIGA_HORIZON_PARTIAL")
            round_fixtures.append(
                OfficialFixture(
                    home=_clean(home_match.group(1)),
                    away=_clean(away_match.group(1)),
                    kickoff_utc=kickoff,
                    official_id=id_match.group(1),
                    round_number=round_number,
                )
            )
        appearances = Counter(team for item in round_fixtures for team in (item.home, item.away))
        if (
            len(round_fixtures) != 9
            or len(appearances) != 18
            or any(count != 1 for count in appearances.values())
            or any(item.home == item.away for item in round_fixtures)
        ):
            raise OfficialScheduleSourceError("BUNDESLIGA_EXACT_DATED_TABLE_INVALID")
        dated_round_clubs[round_number] = frozenset(appearances)
        fixtures.extend(round_fixtures)
    ids = tuple(item.official_id for item in fixtures)
    club_sets = set(dated_round_clubs.values())
    if (
        len(fixtures) != 45
        or len(ids) != len(set(ids))
        or len({(item.home, item.away, item.kickoff_utc) for item in fixtures}) != len(fixtures)
        or len(dated_round_clubs) != 5
        or len(club_sets) != 1
        or len(next(iter(club_sets), ())) != 18
    ):
        raise OfficialScheduleSourceError("BUNDESLIGA_EXACT_DATED_TABLE_INVALID")
    return tuple(fixtures), {
        "exact_dated_source_fixture_count": len(fixtures),
        "full_matchday_heading_count": 34,
        "exact_dated_matchdays": sorted(dated_round_clubs),
        "club_count": 18,
        "unique_official_match_ids": len(ids),
        "timezone": "Europe/Berlin",
    }


def default_pdf_text_extractor(payload: bytes) -> str:
    """Use an already-installed PDF tool lazily; importing this module stays dependency-free."""

    try:
        pdfplumber = importlib.import_module("pdfplumber")
    except ModuleNotFoundError:
        pdfplumber = None
    if pdfplumber is not None:
        open_pdf = cast(Callable[[io.BytesIO], object], getattr(pdfplumber, "open"))
        document = open_pdf(io.BytesIO(payload))
        try:
            pages = cast(Sequence[object], getattr(document, "pages"))
            texts = [cast(str | None, getattr(page, "extract_text")()) or "" for page in pages]
            return "\n".join(texts)
        finally:
            close = cast(Callable[[], object], getattr(document, "close"))
            close()
    try:
        pypdf = importlib.import_module("pypdf")
    except ModuleNotFoundError:
        raise OfficialScheduleSourceError("SERIE_A_PDF_TOOL_UNAVAILABLE") from None
    reader_class = cast(Callable[[io.BytesIO], _PdfReader], getattr(pypdf, "PdfReader"))
    reader = reader_class(io.BytesIO(payload))
    return "\n".join(page.extract_text() or "" for page in reader.pages)


def _parse_serie_a(
    payload: bytes,
    *,
    horizon_starts: datetime,
    horizon_expires: datetime,
    pdf_text_extractor: PdfTextExtractor,
) -> tuple[tuple[OfficialFixture, ...], Mapping[str, object]]:
    try:
        source = pdf_text_extractor(payload)
    except OfficialScheduleSourceError:
        raise
    except Exception as error:
        raise OfficialScheduleSourceError("SERIE_A_PDF_PARSE_FAILED") from error
    if (
        not all(
            marker in source for marker in ("SERIE A ENILIVE 2026/2027", "n. 208", "24 giugno 2026")
        )
        or source.count("GIORNATA") < 5
    ):
        raise OfficialScheduleSourceError("SERIE_A_PDF_AUTHORITY_INVALID")
    rome = ZoneInfo("Europe/Rome")
    fixtures: list[OfficialFixture] = []
    raw_rows = 0
    ambiguous_rows = 0
    row = re.compile(r"^(\d{2}/\d{2}/\d{4})\s+\S+\s+(\d{2}\.\d{2})\s+(.+?)\s+DAZN(?:/SKY)?$")
    for raw_line in source.splitlines():
        line = " ".join(raw_line.split())
        match = row.fullmatch(line)
        if match is None:
            continue
        raw_rows += 1
        date_value, time_value, game = match.groups()
        local = datetime.strptime(f"{date_value} {time_value}", "%d/%m/%Y %H.%M").replace(
            tzinfo=rome
        )
        kickoff = local.astimezone(UTC)
        if "/" in game or game.count("-") != 1:
            ambiguous_rows += 1
            if horizon_starts <= kickoff < horizon_expires:
                raise OfficialScheduleSourceError("SERIE_A_AMBIGUOUS_TABLE")
            continue
        home, away = (value.strip().rstrip("*") for value in game.split("-", 1))
        fixtures.append(
            OfficialFixture(
                home=home,
                away=away,
                kickoff_utc=kickoff,
                official_id=f"serie-a-{len(fixtures) + 1:03d}",
            )
        )
    unique = {(item.home, item.away, item.kickoff_utc) for item in fixtures}
    opening_cutoff = datetime(2026, 9, 1, tzinfo=rome).astimezone(UTC)
    opening = tuple(item for item in fixtures if item.kickoff_utc < opening_cutoff)
    clubs = {team for item in opening for team in (item.home, item.away)}
    appearances = Counter(team for item in opening for team in (item.home, item.away))
    if (
        raw_rows != 50
        or len(fixtures) + ambiguous_rows != raw_rows
        or len(unique) != len(fixtures)
        or len(opening) != 20
        or len(clubs) != 20
        or any(count != 2 for count in appearances.values())
    ):
        raise OfficialScheduleSourceError("SERIE_A_TABLE_COMPLETENESS_INVALID")
    return tuple(fixtures), {
        "communicated_source_fixture_rows": raw_rows,
        "parsed_unambiguous_source_fixture_count": len(fixtures),
        "ambiguous_outside_horizon_fixture_rows": ambiguous_rows,
        "opening_two_matchdays_fixture_count": 20,
        "opening_two_matchdays_club_count": 20,
        "communicated_matchdays": 5,
        "timezone": "Europe/Rome",
    }


@dataclass(frozen=True, slots=True)
class _Ligue1GameWeekRef:
    number: int
    match_ids: tuple[str, ...]
    starts_at_utc: datetime
    ends_at_utc: datetime


def _parse_ligue1_json(payload: bytes, *, code: str) -> dict[str, object]:
    def reject_constant(_value: str) -> None:
        raise ValueError(code)

    try:
        document = json.loads(
            payload,
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise OfficialScheduleSourceError(code) from None
    if not isinstance(document, dict):
        raise OfficialScheduleSourceError(code)
    return cast(dict[str, object], document)


def _ligue1_identifier(value: object, *, code: str) -> str:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise OfficialScheduleSourceError(code)
    normalized = str(value).strip()
    if not normalized or len(normalized) > 128 or "\x00" in normalized:
        raise OfficialScheduleSourceError(code)
    return normalized


def _parse_ligue1_calendar_refs(
    payload: bytes,
    *,
    horizon_starts: datetime,
    horizon_expires: datetime,
) -> tuple[_Ligue1GameWeekRef, ...]:
    starts = _utc(horizon_starts, code="LIGUE1_HORIZON_INVALID")
    expires = _utc(horizon_expires, code="LIGUE1_HORIZON_INVALID")
    if starts >= expires:
        raise OfficialScheduleSourceError("LIGUE1_HORIZON_INVALID")
    document = _parse_ligue1_json(payload, code="LIGUE1_CALENDAR_JSON_INVALID")
    raw_gameweeks = document.get("gameWeeks")
    if not isinstance(raw_gameweeks, list) or not raw_gameweeks:
        raise OfficialScheduleSourceError("LIGUE1_CALENDAR_AUTHORITY_INVALID")
    references: list[_Ligue1GameWeekRef] = []
    seen_numbers: set[int] = set()
    seen_match_ids: set[str] = set()
    for raw_gameweek in raw_gameweeks:
        if not isinstance(raw_gameweek, dict):
            raise OfficialScheduleSourceError("LIGUE1_CALENDAR_AUTHORITY_INVALID")
        number = raw_gameweek.get("gameWeekNumber")
        raw_match_ids = raw_gameweek.get("matchesIds")
        if (
            isinstance(number, bool)
            or not isinstance(number, int)
            or not 1 <= number <= 34
            or number in seen_numbers
            or not isinstance(raw_match_ids, list)
            or len(raw_match_ids) != 9
        ):
            raise OfficialScheduleSourceError("LIGUE1_CALENDAR_AUTHORITY_INVALID")
        match_ids = tuple(
            _ligue1_identifier(value, code="LIGUE1_CALENDAR_AUTHORITY_INVALID")
            for value in raw_match_ids
        )
        if len(set(match_ids)) != 9 or seen_match_ids.intersection(match_ids):
            raise OfficialScheduleSourceError("LIGUE1_CALENDAR_AUTHORITY_INVALID")
        boundaries: list[datetime] = []
        for field in ("endDate", "displayEndDate", "lastRegularMatchDate"):
            value = raw_gameweek.get(field)
            if not isinstance(value, str):
                raise OfficialScheduleSourceError("LIGUE1_CALENDAR_AUTHORITY_INVALID")
            boundaries.append(_parse_iso_aware(value, code="LIGUE1_CALENDAR_AUTHORITY_INVALID"))
        start_value = raw_gameweek.get("startDate")
        if not isinstance(start_value, str):
            raise OfficialScheduleSourceError("LIGUE1_CALENDAR_AUTHORITY_INVALID")
        reference = _Ligue1GameWeekRef(
            number=number,
            match_ids=match_ids,
            starts_at_utc=_parse_iso_aware(
                start_value,
                code="LIGUE1_CALENDAR_AUTHORITY_INVALID",
            ),
            ends_at_utc=max(boundaries),
        )
        if reference.starts_at_utc > reference.ends_at_utc:
            raise OfficialScheduleSourceError("LIGUE1_CALENDAR_AUTHORITY_INVALID")
        references.append(reference)
        seen_numbers.add(number)
        seen_match_ids.update(match_ids)
    if len(references) != 34 or seen_numbers != set(range(1, 35)) or len(seen_match_ids) != 306:
        raise OfficialScheduleSourceError("LIGUE1_CALENDAR_COMPLETENESS_INVALID")
    selected = tuple(
        sorted(
            (
                item
                for item in references
                if item.starts_at_utc < expires and item.ends_at_utc >= starts
            ),
            key=lambda item: item.number,
        )
    )
    if not selected:
        raise OfficialScheduleSourceError("LIGUE1_CALENDAR_HORIZON_EMPTY")
    if len(selected) > LIGUE1_MAXIMUM_GAMEWEEK_READS:
        raise OfficialScheduleSourceError("LIGUE1_GAMEWEEK_READ_LIMIT_EXCEEDED")
    return selected


def _ligue1_club(
    value: object,
    *,
    code: str,
) -> tuple[str, str]:
    if not isinstance(value, dict):
        raise OfficialScheduleSourceError(code)
    club_id = _ligue1_identifier(value.get("clubId"), code=code)
    identity = value.get("clubIdentity")
    if not isinstance(identity, dict):
        raise OfficialScheduleSourceError(code)
    if _ligue1_identifier(identity.get("id"), code=code) != club_id:
        raise OfficialScheduleSourceError(code)
    name = identity.get("name")
    if not isinstance(name, str):
        raise OfficialScheduleSourceError(code)
    normalized_name = " ".join(name.split())
    if not normalized_name or normalized_name != name.strip() or len(normalized_name) > 128:
        raise OfficialScheduleSourceError(code)
    return club_id, normalized_name


def _parse_ligue1_gameweek(
    payload: bytes,
    *,
    reference: _Ligue1GameWeekRef,
    source_read: SupportingOfficialRead,
) -> tuple[OfficialFixture, ...]:
    code = "LIGUE1_GAMEWEEK_AUTHORITY_INVALID"
    document = _parse_ligue1_json(payload, code="LIGUE1_GAMEWEEK_JSON_INVALID")
    raw_matches = document.get("matches")
    expected_url = LIGUE1_GAMEWEEK_URL_TEMPLATE.format(gameweek=reference.number)
    if (
        not isinstance(raw_matches, list)
        or len(raw_matches) != 9
        or source_read.requested_url != expected_url
        or source_read.final_url != expected_url
        or source_read.redirect_chain
        or source_read.status_code != 200
        or source_read.content_type.split(";", 1)[0].strip().casefold() != "application/json"
        or source_read.byte_count != len(payload)
        or source_read.raw_sha256 != hashlib.sha256(payload).hexdigest()
    ):
        raise OfficialScheduleSourceError(code)
    fixtures: list[OfficialFixture] = []
    match_ids: list[str] = []
    club_ids: list[str] = []
    identities: set[tuple[str, str, datetime]] = set()
    for match_index, raw_match in enumerate(raw_matches):
        if not isinstance(raw_match, dict):
            raise OfficialScheduleSourceError(code)
        match_id = _ligue1_identifier(raw_match.get("matchId"), code=code)
        gameweek = raw_match.get("gameWeekNumber")
        championship = raw_match.get("championshipId")
        date_value = raw_match.get("date")
        if (
            raw_match.get("unknownMatch") is not False
            or isinstance(gameweek, bool)
            or gameweek != reference.number
            or isinstance(championship, bool)
            or championship != 1
            or not isinstance(date_value, str)
        ):
            raise OfficialScheduleSourceError(code)
        kickoff = _parse_iso_aware(date_value, code=code)
        if not reference.starts_at_utc <= kickoff <= reference.ends_at_utc:
            raise OfficialScheduleSourceError(code)
        home_id, home = _ligue1_club(raw_match.get("home"), code=code)
        away_id, away = _ligue1_club(raw_match.get("away"), code=code)
        identity = (home_id, away_id, kickoff)
        if home_id == away_id or home == away or identity in identities:
            raise OfficialScheduleSourceError(code)
        identities.add(identity)
        match_ids.append(match_id)
        club_ids.extend((home_id, away_id))
        fixtures.append(
            OfficialFixture(
                home=home,
                away=away,
                kickoff_utc=kickoff,
                official_id=match_id,
                round_number=reference.number,
                source_authority=source_read.final_url,
                source_content_sha256=source_read.raw_sha256,
                source_pointer=f"/matches/{match_index}",
                source_record_ordinal=match_index,
                home_official_id=home_id,
                away_official_id=away_id,
            )
        )
    if (
        set(match_ids) != set(reference.match_ids)
        or len(match_ids) != len(set(match_ids))
        or len(club_ids) != 18
        or len(set(club_ids)) != 18
    ):
        raise OfficialScheduleSourceError(code)
    return tuple(fixtures)


def _parse_ligue1_calendar_bundle(
    fetch_result: OfficialFetchResult,
    *,
    horizon_starts: datetime,
    horizon_expires: datetime,
) -> tuple[tuple[OfficialFixture, ...], Mapping[str, object]]:
    references = _parse_ligue1_calendar_refs(
        fetch_result.raw_bytes,
        horizon_starts=horizon_starts,
        horizon_expires=horizon_expires,
    )
    reads = fetch_result.receipt.supporting_official_reads
    payloads = fetch_result.supporting_official_raw_bytes
    if len(reads) != len(references) or len(payloads) != len(references):
        raise OfficialScheduleSourceError("LIGUE1_GAMEWEEK_BUNDLE_INCOMPLETE")
    fixtures: list[OfficialFixture] = []
    expected_ids = 0
    club_names_by_id: dict[str, str] = {}
    club_ids_by_name: dict[str, str] = {}
    for reference, source_read, payload in zip(references, reads, payloads, strict=True):
        expected_url = LIGUE1_GAMEWEEK_URL_TEMPLATE.format(gameweek=reference.number)
        if source_read.requested_url != expected_url:
            raise OfficialScheduleSourceError("LIGUE1_GAMEWEEK_BUNDLE_INCOMPLETE")
        expected_ids += len(reference.match_ids)
        gameweek_fixtures = _parse_ligue1_gameweek(
            payload,
            reference=reference,
            source_read=source_read,
        )
        for fixture in gameweek_fixtures:
            for club_id, club_name in (
                (fixture.home_official_id, fixture.home),
                (fixture.away_official_id, fixture.away),
            ):
                if club_id is None:
                    raise OfficialScheduleSourceError("LIGUE1_CLUB_IDENTITY_INCONSISTENT")
                if club_names_by_id.get(club_id, club_name) != club_name:
                    raise OfficialScheduleSourceError("LIGUE1_CLUB_IDENTITY_INCONSISTENT")
                if club_ids_by_name.get(club_name, club_id) != club_id:
                    raise OfficialScheduleSourceError("LIGUE1_CLUB_IDENTITY_INCONSISTENT")
                club_names_by_id[club_id] = club_name
                club_ids_by_name[club_name] = club_id
        fixtures.extend(gameweek_fixtures)
    accounted_ids = len({item.official_id for item in fixtures})
    complete = expected_ids == accounted_ids == len(fixtures)
    if not complete or len(club_names_by_id) != 18:
        raise OfficialScheduleSourceError("LIGUE1_GAMEWEEK_BUNDLE_INCOMPLETE")
    club_identity_material = dict(sorted(club_names_by_id.items()))
    return tuple(fixtures), {
        "covered_not_before": _utc_text(horizon_starts),
        "covered_expires": _utc_text(horizon_expires),
        "gameweeks_fetched": [item.number for item in references],
        "calendar_ids_expected": expected_ids,
        "calendar_ids_accounted": accounted_ids,
        "calendar_gameweeks_total": 34,
        "calendar_match_ids_total": 306,
        "calendar_club_identities_total": len(club_identity_material),
        "calendar_club_identities_sha256": hashlib.sha256(
            _canonical_bytes(club_identity_material)
        ).hexdigest(),
        "calendar_match_ids_by_gameweek": {
            str(item.number): list(item.match_ids) for item in references
        },
        "complete_official_horizon": complete,
        "timezone": "UTC",
    }


def build_official_schedule_evidence(
    source: OfficialSourceSpec,
    fetch_result: OfficialFetchResult,
    *,
    horizon_not_before_utc: datetime,
    horizon_expires_at_utc: datetime,
    pdf_text_extractor: PdfTextExtractor | None = None,
) -> OfficialScheduleEvidence:
    horizon_starts = _utc(
        horizon_not_before_utc,
        code="OFFICIAL_SCHEDULE_HORIZON_INVALID",
    )
    horizon_expires = _utc(
        horizon_expires_at_utc,
        code="OFFICIAL_SCHEDULE_HORIZON_INVALID",
    )
    if horizon_starts >= horizon_expires:
        raise OfficialScheduleSourceError("OFFICIAL_SCHEDULE_HORIZON_INVALID")
    normalized_type = fetch_result.receipt.content_type.split(";", 1)[0].strip().casefold()
    try:
        final_host = _validate_official_url(fetch_result.receipt.final_url, source)
    except OfficialScheduleSourceError:
        raise OfficialScheduleSourceError("OFFICIAL_FETCH_RECEIPT_INVALID") from None
    if (
        _ADAPTER_BY_SPORT.get(source.sport_key) != source.adapter
        or not fetch_result.receipt.accepted
        or fetch_result.receipt.sport_key != source.sport_key
        or fetch_result.receipt.adapter_revision != source.adapter
        or fetch_result.receipt.requested_url != source.url
        or fetch_result.receipt.official_domain != final_host
        or fetch_result.receipt.http_status != 200
        or normalized_type not in _CONTENT_TYPES_BY_ADAPTER[source.adapter]
        or fetch_result.receipt.byte_count != len(fetch_result.raw_bytes)
        or fetch_result.receipt.rejection_code is not None
        or fetch_result.receipt.raw_sha256 != hashlib.sha256(fetch_result.raw_bytes).hexdigest()
        or len(fetch_result.receipt.supporting_official_reads)
        != len(fetch_result.supporting_official_raw_bytes)
        or not _redirect_chain_valid(
            fetch_result.receipt.requested_url,
            fetch_result.receipt.final_url,
            fetch_result.receipt.redirect_chain,
            source,
        )
        or (
            source.adapter == LIGUE1_CALENDAR_JSON_V1
            and (
                fetch_result.receipt.redirect_chain
                or any(
                    item.redirect_chain for item in fetch_result.receipt.supporting_official_reads
                )
            )
        )
        or any(
            item.status_code != 200
            or item.byte_count <= 0
            or item.byte_count != len(raw)
            or item.raw_sha256 != item.raw_sha256.casefold()
            or len(item.raw_sha256) != 64
            or item.raw_sha256 != hashlib.sha256(raw).hexdigest()
            or not _host_allowed(item.official_domain, source.allowed_domains)
            or not _redirect_chain_valid(
                item.requested_url,
                item.final_url,
                item.redirect_chain,
                source,
            )
            for item, raw in zip(
                fetch_result.receipt.supporting_official_reads,
                fetch_result.supporting_official_raw_bytes,
                strict=True,
            )
        )
    ):
        raise OfficialScheduleSourceError("OFFICIAL_FETCH_RECEIPT_INVALID")
    if source.adapter == PREMIER_LEAGUE_FULL_SEASON_HTML_V1:
        fixtures, metadata = _parse_epl(
            fetch_result.raw_bytes,
            horizon_starts=horizon_starts,
            horizon_expires=horizon_expires,
        )
    elif source.adapter == LALIGA_PUBLIC_MATCHES_JSON_V1:
        fixtures, metadata = _parse_laliga(
            fetch_result.raw_bytes,
            horizon_starts=horizon_starts,
            horizon_expires=horizon_expires,
        )
    elif source.adapter == DFB_DATACENTER_HTML_V1:
        fixtures, metadata = _parse_bundesliga(
            fetch_result.raw_bytes,
            horizon_starts=horizon_starts,
            horizon_expires=horizon_expires,
        )
    elif source.adapter == LEGA_SERIE_A_CALENDAR_PDF_V1:
        fixtures, metadata = _parse_serie_a(
            fetch_result.raw_bytes,
            horizon_starts=horizon_starts,
            horizon_expires=horizon_expires,
            pdf_text_extractor=pdf_text_extractor or default_pdf_text_extractor,
        )
    elif source.adapter == LIGUE1_CALENDAR_JSON_V1:
        fixtures, metadata = _parse_ligue1_calendar_bundle(
            fetch_result,
            horizon_starts=horizon_starts,
            horizon_expires=horizon_expires,
        )
    else:
        raise OfficialScheduleSourceError("OFFICIAL_SOURCE_ADAPTER_INVALID")
    selected = tuple(
        sorted(
            (item for item in fixtures if horizon_starts <= item.kickoff_utc < horizon_expires),
            key=lambda item: (item.kickoff_utc, item.home, item.away, item.official_id),
        )
    )
    if not selected:
        raise OfficialScheduleSourceError("OFFICIAL_SCHEDULE_HORIZON_EMPTY")
    if any(not item.kickoff_confirmed for item in selected):
        raise OfficialScheduleSourceError("OFFICIAL_SCHEDULE_HORIZON_KICKOFF_UNCONFIRMED")
    identities = tuple((item.home, item.away, item.kickoff_utc) for item in selected)
    ids = tuple(item.official_id for item in selected)
    if (
        len(identities) != len(set(identities))
        or len(ids) != len(set(ids))
        or any(item.home == item.away for item in selected)
        or any(item.kickoff_utc.tzinfo is None for item in selected)
    ):
        raise OfficialScheduleSourceError("OFFICIAL_SCHEDULE_FIXTURE_INVALID")
    if any(
        any(
            value is not None
            for value in (
                item.source_authority,
                item.source_content_sha256,
                item.source_pointer,
                item.source_record_ordinal,
            )
        )
        and any(
            value is None
            for value in (
                item.source_authority,
                item.source_content_sha256,
                item.source_pointer,
                item.source_record_ordinal,
            )
        )
        for item in selected
    ):
        raise OfficialScheduleSourceError("OFFICIAL_SCHEDULE_FIXTURE_PROVENANCE_INVALID")
    if source.adapter == LIGUE1_CALENDAR_JSON_V1 and any(
        item.source_authority is None for item in selected
    ):
        raise OfficialScheduleSourceError("LIGUE1_FIXTURE_PROVENANCE_INVALID")
    metadata_document = dict(metadata)
    metadata_document.setdefault("covered_not_before", _utc_text(horizon_starts))
    metadata_document.setdefault("covered_expires", _utc_text(horizon_expires))
    metadata_document.setdefault("complete_official_horizon", True)
    return OfficialScheduleEvidence(
        sport_key=source.sport_key,
        source_authority=fetch_result.receipt.final_url,
        source_content_sha256=fetch_result.receipt.raw_sha256,
        source_observed_at_utc=fetch_result.receipt.observed_at_utc,
        horizon_not_before_utc=horizon_starts,
        horizon_expires_at_utc=horizon_expires,
        fixtures=selected,
        adapter_revision=source.adapter,
        parser_metadata=metadata_document,
    )


def reconcile_official_schedule_evidence(
    evidences: Sequence[OfficialScheduleEvidence],
    *,
    observed_at_utc: datetime,
) -> dict[str, object]:
    observed = _utc(observed_at_utc, code="OFFICIAL_RECONCILIATION_TIME_INVALID")
    if tuple(item.sport_key for item in evidences) != LIVE_ALLOWED_SPORT_KEYS:
        raise OfficialScheduleSourceError("OFFICIAL_RECONCILIATION_FIVE_LEAGUE_INVALID")
    if any(
        item.source_observed_at_utc > observed
        or observed - item.source_observed_at_utc > MAXIMUM_SOURCE_AGE
        or not item.fixtures
        or item.adapter_revision != _ADAPTER_BY_SPORT[item.sport_key]
        for item in evidences
    ):
        raise OfficialScheduleSourceError("OFFICIAL_RECONCILIATION_SOURCE_INVALID")
    for item in evidences:
        metadata = item.parser_metadata
        if item.adapter_revision != LIGUE1_CALENDAR_JSON_V1:
            # Legacy evidence builders predate explicit horizon-coverage metadata.
            # Their adapter contracts remain bounded by the parsed fixture set; only
            # the rolling Ligue 1 adapter needs the calendar/page closure proof below.
            if metadata.get("complete_official_horizon") is False:
                raise OfficialScheduleSourceError("OFFICIAL_RECONCILIATION_COMPLETENESS_INVALID")
            continue
        covered_not_before = metadata.get("covered_not_before")
        covered_expires = metadata.get("covered_expires")
        if (
            metadata.get("complete_official_horizon") is not True
            or not isinstance(covered_not_before, str)
            or not isinstance(covered_expires, str)
            or _parse_iso_aware(
                covered_not_before,
                code="OFFICIAL_RECONCILIATION_COMPLETENESS_INVALID",
            )
            > item.horizon_not_before_utc
            or _parse_iso_aware(
                covered_expires,
                code="OFFICIAL_RECONCILIATION_COMPLETENESS_INVALID",
            )
            < item.horizon_expires_at_utc
            or metadata.get("calendar_gameweeks_total") != 34
            or metadata.get("calendar_match_ids_total") != 306
            or metadata.get("calendar_club_identities_total") != 18
            or not isinstance(metadata.get("calendar_club_identities_sha256"), str)
            or re.fullmatch(
                r"[0-9a-f]{64}",
                cast(str, metadata.get("calendar_club_identities_sha256")),
            )
            is None
            or metadata.get("calendar_ids_expected") != metadata.get("calendar_ids_accounted")
            or not metadata.get("gameweeks_fetched")
        ):
            raise OfficialScheduleSourceError("OFFICIAL_RECONCILIATION_COMPLETENESS_INVALID")
    horizons = {(item.horizon_not_before_utc, item.horizon_expires_at_utc) for item in evidences}
    if len(horizons) != 1:
        raise OfficialScheduleSourceError("OFFICIAL_RECONCILIATION_HORIZON_MISMATCH")
    return {
        "schema_version": RECONCILIATION_SCHEMA,
        "observed_at_utc": _utc_text(observed),
        "sport_keys": list(LIVE_ALLOWED_SPORT_KEYS),
        "fixture_counts": {item.sport_key: len(item.fixtures) for item in evidences},
        "source_sha256": {item.sport_key: item.source_content_sha256 for item in evidences},
        "adapter_revisions": {item.sport_key: item.adapter_revision for item in evidences},
        "complete_official_horizon": True,
        "provider_dns": 0,
        "provider_tcp": 0,
        "provider_http": 0,
        "secret_reads": 0,  # nosec B105 -- effect counter, not a credential
    }


__all__ = [
    "DEFAULT_TIMEOUT_SECONDS",
    "DFB_DATACENTER_HTML_V1",
    "EVIDENCE_SCHEMA",
    "LEGA_SERIE_A_CALENDAR_PDF_V1",
    "LALIGA_PUBLIC_MATCHES_JSON_V1",
    "LIGUE1_CALENDAR_JSON_V1",
    "LIGUE1_CALENDAR_URL",
    "LIGUE1_GAMEWEEK_URL_TEMPLATE",
    "LIGUE1_MAXIMUM_GAMEWEEK_READS",
    "MAXIMUM_SOURCE_AGE",
    "MAXIMUM_SOURCE_BYTES",
    "PREMIER_LEAGUE_FULL_SEASON_HTML_V1",
    "BuiltinHttpsOfficialScheduleFetcher",
    "OfficialFetchReceipt",
    "OfficialFetchResult",
    "OfficialFixture",
    "OfficialHttpResponse",
    "OfficialPhysicalResponse",
    "OfficialScheduleEvidence",
    "OfficialScheduleFetcher",
    "OfficialScheduleSourceError",
    "OfficialSourcePlan",
    "OfficialSourceSpec",
    "PdfTextExtractor",
    "RedirectHop",
    "SupportingOfficialRead",
    "build_official_schedule_evidence",
    "default_pdf_text_extractor",
    "fetch_official_schedule_source",
    "load_official_source_plan_bytes",
    "reconcile_official_schedule_evidence",
]
