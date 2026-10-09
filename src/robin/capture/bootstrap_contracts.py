"""Additive contracts closing the first-real-capture bootstrap boundary.

The V1 live contracts remain historical replay contracts.  This module contains
only successor authority and preparation evidence whose inputs are legitimately
available before the first provider request.
"""

from __future__ import annotations

import ipaddress
import os
import unicodedata
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Final, Literal, Self, TypeAlias, cast
from urllib.parse import urlparse

from pydantic import Field, model_validator

from robin.capture.contracts import (
    CaptureContractError,
    FrozenContract,
    JsonValue,
    ProviderRequestSpec,
    canonical_sha256,
    ensure_utc,
)
from robin.capture.live_contracts import (
    LIVE_ALLOWED_MARKET_SETS,
    LIVE_ALLOWED_MARKETS,
    LIVE_ALLOWED_SPORT_KEYS,
    MAX_ACTIVATION_TTL,
    LiveAdmissionPermitV1,
    LiveResponseIntakeClaimV1,
    MarketSet,
)

BOOTSTRAP_CAPABILITY_VERSION: Final[Literal["robin-real-execution-bootstrap-closure-v1"]] = (
    "robin-real-execution-bootstrap-closure-v1"
)
BOOTSTRAP_MISSION_ID: Final[Literal["REAL_EXECUTION_BOOTSTRAP_CLOSURE_V1"]] = (
    "REAL_EXECUTION_BOOTSTRAP_CLOSURE_V1"
)
FIRST_C0_VERTICAL_MISSION_ID: Final[Literal["FIRST_C0_VERTICAL_V1"]] = "FIRST_C0_VERTICAL_V1"
MissionIdV1: TypeAlias = Literal[
    "REAL_EXECUTION_BOOTSTRAP_CLOSURE_V1",
    "FIRST_C0_VERTICAL_V1",
]
PROVIDER_CANONICAL_HOSTNAME: Final[Literal["api.the-odds-api.com"]] = "api.the-odds-api.com"
MAX_NETWORK_BINDING_TTL = timedelta(minutes=15)
MIN_OWNER_REVIEW_WINDOW = timedelta(minutes=2)
PRE_KICKOFF_SAFETY_MARGIN = timedelta(minutes=5)
MAX_CAMPAIGN_SOURCE_AGE = timedelta(minutes=30)
CAMPAIGN_SELECTION_WINDOWS: Final[tuple[str, ...]] = ("H24", "H2", "H1")
CAMPAIGN_SELECTION_REVISION: Final[Literal["complete-five-league-interval-clique-ranking-v2"]] = (
    "complete-five-league-interval-clique-ranking-v2"
)
CAMPAIGN_RANKING_POLICY: Final[
    Literal[
        "coverage-desc;protocol-role-desc;positive-margin-required;"
        "cross-league-desc;earliest-readiness-asc;stable-group-hash-asc"
    ]
] = (
    "coverage-desc;protocol-role-desc;positive-margin-required;"
    "cross-league-desc;earliest-readiness-asc;stable-group-hash-asc"
)
FIRST_C0_CANARY_SELECTION_REVISION: Final[Literal["single-league-first-real-c0-canary-v1"]] = (
    "single-league-first-real-c0-canary-v1"
)
FIRST_C0_CANARY_RANKING_POLICY: Final[
    Literal[
        "coverage-desc;protocol-role-desc;positive-margin-required;"
        "earliest-readiness-asc;stable-group-hash-asc"
    ]
] = (
    "coverage-desc;protocol-role-desc;positive-margin-required;"
    "earliest-readiness-asc;stable-group-hash-asc"
)
FIRST_C0_CANARY_SPORT_KEYS: Final[tuple[str, ...]] = (
    "soccer_spain_la_liga",
    "soccer_germany_bundesliga",
)
FIRST_C0_CANARY_MINIMUM_READY_MARGIN_SECONDS: Final[int] = 840
FIRST_C0_H2_WINDOW_DURATION_SECONDS: Final[int] = 900
FIRST_C0_H2_PREFETCH_LEAD_SECONDS: Final[int] = 300
FIRST_C0_POST_OPEN_TOTAL_BUDGET_SECONDS: Final[int] = 60
FIRST_C0_POST_OPEN_SAFETY_RESERVE_SECONDS: Final[int] = 15
FIRST_C0_MAXIMUM_OPEN_TO_PREFLIGHT_SECONDS: Final[int] = 45
FIRST_C0_MAXIMUM_LOCAL_WAIT_SECONDS: Final[int] = 900
FIRST_C0_CANARY_OFFICIAL_DOMAINS: Final[dict[str, str]] = {
    "soccer_spain_la_liga": "laliga.com",
    "soccer_germany_bundesliga": "dfb.de",
}
FIRST_C0_CANARY_COMPETITIONS: Final[dict[str, str]] = {
    "soccer_spain_la_liga": "LALIGA EA SPORTS",
    "soccer_germany_bundesliga": "Bundesliga",
}
MISSION_MANIFEST_SOURCE_HASH: Final[
    Literal["204e4323d0b99fdfa8c655cdc3a08a8d2b3c82ac0a784f9a97982c90ab3a7312"]
] = "204e4323d0b99fdfa8c655cdc3a08a8d2b3c82ac0a784f9a97982c90ab3a7312"
REAL_EXECUTION_BOOTSTRAP_MANIFEST_SHA256: Final[
    Literal["d3d570be434b61c0875212061d92419d074b0d8357ba60e55c9f10cd79458e14"]
] = "d3d570be434b61c0875212061d92419d074b0d8357ba60e55c9f10cd79458e14"
MISSION_EXTERNAL_EFFECTS: Final[tuple[str, ...]] = (
    "local_standalone_runtime_create_after_merge",
    "github_public_full_clone_after_merge",
    "provider_public_dns_resolution_exactly_once_after_merge",
    "official_schedule_public_read_after_merge",
    "git_remote_write_non_force",
    "github_pull_request_write",
    "github_merge_commit",
    "github_actions_observe",
)
FIRST_C0_VERTICAL_MANIFEST_SOURCE_HASH: Final[
    Literal["9015d1cd535893614917d1697d0ad5ce059bf1aed42b99140134781351744ff6"]
] = "9015d1cd535893614917d1697d0ad5ce059bf1aed42b99140134781351744ff6"
FIRST_C0_VERTICAL_MANIFEST_SHA256: Final[
    Literal["0a2fa273481921a6207a30b27f50a1e293bfbf6d3e19f78596b1308628072ce4"]
] = "0a2fa273481921a6207a30b27f50a1e293bfbf6d3e19f78596b1308628072ce4"
FIRST_C0_VERTICAL_MANIFEST_EXPIRES_AT: Final = datetime(2026, 9, 4, 8, 8, 40, tzinfo=UTC)
FIRST_C0_VERTICAL_EXTERNAL_EFFECTS: Final[tuple[str, ...]] = (
    "git_remote_write_non_force",
    "github_pull_request_write",
    "github_merge_commit",
    "github_actions_observe",
    "local_standalone_runtime_create_after_merge",
    "github_public_full_clone_after_merge",
    "official_schedule_public_read_max_2_after_merge",
    "provider_public_dns_resolution_exactly_once_after_merge",
    "owner_review_pack_create_exactly_once_after_dns_binding",
    "owner_authorization_promote_exactly_once_after_explicit_pack_specific_owner_decision",
    "provider_secret_read_exactly_once_after_pack_specific_owner_authorization",
    "provider_tcp_tls_connection_exactly_once_after_pack_specific_owner_authorization",
    "provider_https_get_exactly_once_after_pack_specific_owner_authorization",
    "provider_credit_consume_exactly_once_after_pack_specific_owner_authorization",
    "local_immutable_live_capture_artifact_writes",
    "offline_replay_from_captured_bytes",
)
TEAM_NORMALIZATION_REVISION: Final[
    Literal["unicode-nfkc-casefold-collapse-unicode-whitespace-v1"]
] = "unicode-nfkc-casefold-collapse-unicode-whitespace-v1"
FIXTURE_MAPPING_REVISION: Final[Literal["exact-sport-kickoff-home-away-v1"]] = (
    "exact-sport-kickoff-home-away-v1"
)

Sha256 = str

_FORBIDDEN_SPECIAL_USE_NETWORKS: Final = (
    # Complete IANA IPv4 Special-Purpose Address Registry, 2025-10-09.
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.31.196.0/24"),
    ipaddress.ip_network("192.52.193.0/24"),
    ipaddress.ip_network("192.88.99.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("192.175.48.0/24"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("240.0.0.0/4"),
    # Complete IANA IPv6 Special-Purpose Address Registry, 2025-10-09,
    # plus the deprecated site-local block retained as an explicit deny.
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("::ffff:0:0/96"),
    ipaddress.ip_network("64:ff9b::/96"),
    ipaddress.ip_network("64:ff9b:1::/48"),
    ipaddress.ip_network("100::/64"),
    ipaddress.ip_network("100:0:0:1::/64"),
    ipaddress.ip_network("2001::/23"),
    ipaddress.ip_network("2001:db8::/32"),
    ipaddress.ip_network("2002::/16"),
    ipaddress.ip_network("2620:4f:8000::/48"),
    ipaddress.ip_network("3fff::/20"),
    ipaddress.ip_network("5f00::/16"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fec0::/10"),
)


def _normalized_utc_data(data: dict[str, Any], *fields: str) -> dict[str, Any]:
    normalized = dict(data)
    for field in fields:
        if field in normalized and normalized[field] is not None:
            normalized[field] = ensure_utc(cast(datetime, normalized[field]), field=field)
    return normalized


def _canonical_market_set(markets: MarketSet) -> bool:
    expected = tuple(market for market in LIVE_ALLOWED_MARKETS if market in markets)
    return bool(markets) and len(set(markets)) == len(markets) and markets == expected


def _ordered_sport_subset(sports: tuple[str, ...]) -> bool:
    return sports == tuple(sport for sport in LIVE_ALLOWED_SPORT_KEYS if sport in sports)


def canonical_team_name_v1(value: str) -> str:
    """Apply the reviewed exact normalization rule; aliases and fuzzy edits are forbidden."""

    if not isinstance(value, str):
        raise ValueError("FIXTURE_TEAM_NAME_INVALID")
    normalized = unicodedata.normalize("NFKC", value)
    if any(unicodedata.category(character).startswith("C") for character in normalized):
        raise ValueError("FIXTURE_TEAM_NAME_INVALID")
    collapsed = " ".join(normalized.strip().split())
    if not collapsed or len(collapsed) > 160:
        raise ValueError("FIXTURE_TEAM_NAME_INVALID")
    return collapsed.casefold()


def _first_c0_official_source_authority_valid(sport_key: str, value: str) -> bool:
    try:
        parsed = urlparse(value)
        port = parsed.port
    except ValueError:
        return False
    host = (parsed.hostname or "").rstrip(".").casefold()
    expected_domain = FIRST_C0_CANARY_OFFICIAL_DOMAINS.get(sport_key)
    return bool(
        expected_domain
        and parsed.scheme.casefold() == "https"
        and host
        and (host == expected_domain or host.endswith(f".{expected_domain}"))
        and parsed.username is None
        and parsed.password is None
        and port in {None, 443}
        and not parsed.fragment
    )


def validate_global_unicast_ip(value: str) -> str:
    """Return a canonical globally routable address or fail closed."""

    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise ValueError("PROVIDER_NETWORK_ADDRESS_INVALID") from None
    if (
        str(address) != value
        or not address.is_global
        or address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
        or address.is_reserved
        or getattr(address, "is_site_local", False)
        or getattr(address, "ipv4_mapped", None) is not None
        or getattr(address, "scope_id", None) is not None
        or any(address in network for network in _FORBIDDEN_SPECIAL_USE_NETWORKS)
    ):
        raise ValueError("PROVIDER_NETWORK_ADDRESS_NOT_GLOBAL_UNICAST")
    return value


def canonical_provider_ip_set(addresses: tuple[str, ...]) -> tuple[str, ...]:
    """Canonicalize, deduplicate and order IPv4 before IPv6 by packed bytes."""

    parsed: dict[tuple[int, bytes], str] = {}
    for raw in addresses:
        validate_global_unicast_ip(raw)
        address = ipaddress.ip_address(raw)
        key = (0 if address.version == 4 else 1, address.packed)
        parsed[key] = str(address)
    if not parsed:
        raise ValueError("PROVIDER_NETWORK_ADDRESS_SET_EMPTY")
    return tuple(parsed[key] for key in sorted(parsed))


class RealExecutionMissionManifestV1(FrozenContract):
    """Semantic, hashable view of the tracked mission authority manifest."""

    mission_id: MissionIdV1 = BOOTSTRAP_MISSION_ID
    authorized_stages: tuple[Literal["E1"], ...]
    maximum_stage: Literal["E1"]
    external_effects: tuple[str, ...]
    compute_budget: Literal[8000, 4000]
    time_budget: Literal[345600, 259200]
    source_hash: Literal[
        "204e4323d0b99fdfa8c655cdc3a08a8d2b3c82ac0a784f9a97982c90ab3a7312",
        "9015d1cd535893614917d1697d0ad5ce059bf1aed42b99140134781351744ff6",
    ] = MISSION_MANIFEST_SOURCE_HASH
    expires_at: datetime

    @classmethod
    def issue(cls, **data: Any) -> Self:
        return cls.model_validate(data)

    @model_validator(mode="after")
    def validate_manifest(self) -> Self:
        expires_at = ensure_utc(self.expires_at, field="mission_manifest_expires_at")
        if self.authorized_stages != ("E1",):
            raise ValueError("BOOTSTRAP_MISSION_MANIFEST_SCOPE_INVALID")
        if self.mission_id == BOOTSTRAP_MISSION_ID:
            if (
                self.external_effects != MISSION_EXTERNAL_EFFECTS
                or self.compute_budget != 8000
                or self.time_budget != 345600
                or self.source_hash != MISSION_MANIFEST_SOURCE_HASH
            ):
                raise ValueError("BOOTSTRAP_MISSION_MANIFEST_SCOPE_INVALID")
        elif (
            self.external_effects != FIRST_C0_VERTICAL_EXTERNAL_EFFECTS
            or self.compute_budget != 4000
            or self.time_budget != 259200
            or self.source_hash != FIRST_C0_VERTICAL_MANIFEST_SOURCE_HASH
            or expires_at != FIRST_C0_VERTICAL_MANIFEST_EXPIRES_AT
        ):
            raise ValueError("FIRST_C0_VERTICAL_MISSION_MANIFEST_SCOPE_INVALID")
        return self

    def assert_first_c0_live_effect_ceiling(self) -> None:
        """Reject historical, substituted, expanded, or reordered live authority."""

        if (
            self.mission_id != FIRST_C0_VERTICAL_MISSION_ID
            or self.external_effects != FIRST_C0_VERTICAL_EXTERNAL_EFFECTS
            or self.compute_budget != 4000
            or self.time_budget != 259200
            or self.source_hash != FIRST_C0_VERTICAL_MANIFEST_SOURCE_HASH
            or self.expires_at != FIRST_C0_VERTICAL_MANIFEST_EXPIRES_AT
            or self.canonical_manifest_sha256() != FIRST_C0_VERTICAL_MANIFEST_SHA256
        ):
            raise ValueError("FIRST_C0_VERTICAL_LIVE_EFFECT_CEILING_INVALID")

    def canonical_manifest_sha256(self) -> Sha256:
        return canonical_sha256(cast(dict[str, JsonValue], self.model_dump(mode="json")))


class ProviderNetworkResolutionClaimV1(FrozenContract):
    """Durable pre-resolution reservation; its existence permanently consumes the attempt."""

    schema_version: Literal["robin-provider-network-resolution-claim-v1"] = (
        "robin-provider-network-resolution-claim-v1"
    )
    mission_id: MissionIdV1 = BOOTSTRAP_MISSION_ID
    mission_manifest_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    workspace_receipt_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    campaign_selection_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    fixture_target_set_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    claimed_at_utc: datetime
    mission_expires_at_utc: datetime
    canonical_hostname: Literal["api.the-odds-api.com"] = PROVIDER_CANONICAL_HOSTNAME
    resolution_method: Literal["SYSTEM_GETADDRINFO_AF_UNSPEC_SINGLE_CALL"] = (
        "SYSTEM_GETADDRINFO_AF_UNSPEC_SINGLE_CALL"
    )
    resolution_operations_reserved: Literal[1] = 1
    retries_permitted: Literal[0] = 0
    provider_http_requests: Literal[0] = 0
    provider_tcp_connections: Literal[0] = 0
    provider_secret_reads: Literal[0] = 0
    canonical_claim_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")

    def identity_material(self) -> dict[str, JsonValue]:
        return cast(
            dict[str, JsonValue],
            self.model_dump(mode="json", exclude={"canonical_claim_hash"}),
        )

    @classmethod
    def issue(cls, **data: Any) -> Self:
        normalized = _normalized_utc_data(
            data,
            "claimed_at_utc",
            "mission_expires_at_utc",
        )
        provisional = cls.model_construct(canonical_claim_hash="0" * 64, **normalized)
        return cls(
            canonical_claim_hash=canonical_sha256(provisional.identity_material()),
            **normalized,
        )

    @model_validator(mode="after")
    def validate_claim(self) -> Self:
        claimed = ensure_utc(self.claimed_at_utc, field="network_resolution_claimed_at")
        mission_expires = ensure_utc(
            self.mission_expires_at_utc,
            field="network_resolution_mission_expires_at",
        )
        if claimed >= mission_expires:
            raise ValueError("PROVIDER_NETWORK_RESOLUTION_CLAIM_EXPIRED")
        if self.canonical_claim_hash != canonical_sha256(self.identity_material()):
            raise ValueError("PROVIDER_NETWORK_RESOLUTION_CLAIM_HASH_MISMATCH")
        return self


class ProviderNetworkBindingV1(FrozenContract):
    schema_version: Literal["robin-provider-network-binding-v1"] = (
        "robin-provider-network-binding-v1"
    )
    canonical_hostname: Literal["api.the-odds-api.com"] = PROVIDER_CANONICAL_HOSTNAME
    resolution_method: Literal["SYSTEM_GETADDRINFO_AF_UNSPEC_SINGLE_CALL"] = (
        "SYSTEM_GETADDRINFO_AF_UNSPEC_SINGLE_CALL"
    )
    resolver_identity: str = Field(min_length=1, max_length=240)
    resolver_provenance: Literal["OPERATING_SYSTEM_STUB_RESOLVER_NO_PROVIDER_TRANSPORT"] = (
        "OPERATING_SYSTEM_STUB_RESOLVER_NO_PROVIDER_TRANSPORT"
    )
    resolution_claim: ProviderNetworkResolutionClaimV1
    observed_at_utc: datetime
    expires_at_utc: datetime
    binding_ttl_seconds: int = Field(gt=0, le=900)
    resolved_ip_addresses: tuple[str, ...]
    selection_policy: Literal["IPV4_THEN_IPV6_PACKED_BYTES_FIRST_V1"] = (
        "IPV4_THEN_IPV6_PACKED_BYTES_FIRST_V1"
    )
    selected_ip_address: str
    address_family: Literal["IPv4", "IPv6"]
    resolution_operations: Literal[1] = 1
    provider_http_requests: Literal[0] = 0
    provider_tcp_connections: Literal[0] = 0
    provider_secret_reads: Literal[0] = 0
    canonical_binding_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")

    def identity_material(self) -> dict[str, JsonValue]:
        return cast(
            dict[str, JsonValue],
            self.model_dump(mode="json", exclude={"canonical_binding_hash"}),
        )

    @classmethod
    def issue(cls, **data: Any) -> Self:
        normalized_times = _normalized_utc_data(data, "observed_at_utc", "expires_at_utc")
        raw_addresses = tuple(normalized_times.get("resolved_ip_addresses", ()))
        canonical_addresses = canonical_provider_ip_set(raw_addresses)
        normalized = {**normalized_times, "resolved_ip_addresses": canonical_addresses}
        normalized.setdefault("selected_ip_address", canonical_addresses[0])
        selected = ipaddress.ip_address(cast(str, normalized["selected_ip_address"]))
        normalized.setdefault("address_family", "IPv4" if selected.version == 4 else "IPv6")
        provisional = cls.model_construct(canonical_binding_hash="0" * 64, **normalized)
        return cls(
            canonical_binding_hash=canonical_sha256(provisional.identity_material()),
            **normalized,
        )

    @model_validator(mode="after")
    def validate_binding(self) -> Self:
        observed = ensure_utc(self.observed_at_utc, field="network_binding_observed_at")
        expires = ensure_utc(self.expires_at_utc, field="network_binding_expires_at")
        if (
            observed >= expires
            or self.resolution_claim.claimed_at_utc > observed
            or observed - self.resolution_claim.claimed_at_utc > timedelta(minutes=1)
            or observed >= self.resolution_claim.mission_expires_at_utc
            or expires > self.resolution_claim.mission_expires_at_utc
            or expires - observed > MAX_NETWORK_BINDING_TTL
            or expires - observed != timedelta(seconds=self.binding_ttl_seconds)
        ):
            raise ValueError("PROVIDER_NETWORK_BINDING_INTERVAL_INVALID")
        canonical = canonical_provider_ip_set(self.resolved_ip_addresses)
        if canonical != self.resolved_ip_addresses:
            raise ValueError("PROVIDER_NETWORK_ADDRESS_SET_NOT_CANONICAL")
        if self.selected_ip_address not in canonical or self.selected_ip_address != canonical[0]:
            raise ValueError("PROVIDER_NETWORK_SELECTION_INVALID")
        selected = ipaddress.ip_address(self.selected_ip_address)
        expected_family = "IPv4" if selected.version == 4 else "IPv6"
        if self.address_family != expected_family:
            raise ValueError("PROVIDER_NETWORK_ADDRESS_FAMILY_MISMATCH")
        if self.canonical_binding_hash != canonical_sha256(self.identity_material()):
            raise ValueError("PROVIDER_NETWORK_BINDING_HASH_MISMATCH")
        return self

    def assert_current(self, now: datetime) -> None:
        current = ensure_utc(now, field="network_binding_validation_at")
        if not self.observed_at_utc <= current < self.expires_at_utc:
            raise ValueError("NETWORK_BINDING_EXPIRED")


class OfficialFixtureTargetV1(FrozenContract):
    schema_version: Literal["robin-official-fixture-target-v1"] = "robin-official-fixture-target-v1"
    internal_fixture_target_id: str = Field(min_length=1, max_length=160)
    competition: str = Field(min_length=1, max_length=120)
    sport_key: str = Field(min_length=1, max_length=120)
    official_home_team: str = Field(min_length=1, max_length=160)
    official_away_team: str = Field(min_length=1, max_length=160)
    official_kickoff_utc: datetime
    official_source_authority: str = Field(min_length=1, max_length=400)
    source_observed_at_utc: datetime
    source_evidence_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    team_normalization_revision: Literal["unicode-nfkc-casefold-collapse-unicode-whitespace-v1"] = (
        TEAM_NORMALIZATION_REVISION
    )
    canonical_target_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")

    def identity_material(self) -> dict[str, JsonValue]:
        return cast(
            dict[str, JsonValue],
            self.model_dump(mode="json", exclude={"canonical_target_hash"}),
        )

    @classmethod
    def issue(cls, **data: Any) -> Self:
        normalized = _normalized_utc_data(
            data,
            "official_kickoff_utc",
            "source_observed_at_utc",
        )
        if "official_home_team" in normalized:
            normalized["official_home_team"] = canonical_team_name_v1(
                cast(str, normalized["official_home_team"])
            )
        if "official_away_team" in normalized:
            normalized["official_away_team"] = canonical_team_name_v1(
                cast(str, normalized["official_away_team"])
            )
        provisional = cls.model_construct(canonical_target_hash="0" * 64, **normalized)
        return cls(
            canonical_target_hash=canonical_sha256(provisional.identity_material()),
            **normalized,
        )

    @model_validator(mode="after")
    def validate_target(self) -> Self:
        if self.sport_key not in LIVE_ALLOWED_SPORT_KEYS:
            raise ValueError("FIXTURE_TARGET_SPORT_FORBIDDEN")
        kickoff = ensure_utc(self.official_kickoff_utc, field="fixture_target_kickoff")
        observed = ensure_utc(self.source_observed_at_utc, field="fixture_source_observed_at")
        if observed >= kickoff:
            raise ValueError("FIXTURE_TARGET_SOURCE_NOT_PREMATCH")
        home = canonical_team_name_v1(self.official_home_team)
        away = canonical_team_name_v1(self.official_away_team)
        if home == away:
            raise ValueError("FIXTURE_TARGET_TEAMS_IDENTICAL")
        if self.official_home_team != home or self.official_away_team != away:
            raise ValueError("FIXTURE_TARGET_TEAM_NOT_CANONICAL")
        if self.canonical_target_hash != canonical_sha256(self.identity_material()):
            raise ValueError("FIXTURE_TARGET_HASH_MISMATCH")
        return self

    def exact_identity_key(self) -> tuple[str, datetime, str, str]:
        return (
            self.sport_key,
            self.official_kickoff_utc,
            canonical_team_name_v1(self.official_home_team),
            canonical_team_name_v1(self.official_away_team),
        )


class FixtureTargetSetV1(FrozenContract):
    schema_version: Literal["robin-fixture-target-set-v1"] = "robin-fixture-target-set-v1"
    target_set_id: str = Field(min_length=1, max_length=160)
    sport_key: str = Field(min_length=1, max_length=120)
    workspace_receipt_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    created_at_utc: datetime
    official_schedule_horizon_not_before_utc: datetime | None = None
    official_schedule_horizon_expires_at_utc: datetime | None = None
    official_schedule_fixture_count: int | None = Field(default=None, gt=0)
    official_schedule_completeness: Literal["OWNER_REVIEWED_COMPLETE_OFFICIAL_HORIZON"] | None = (
        None
    )
    targets: tuple[OfficialFixtureTargetV1, ...]
    canonical_set_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")

    def identity_material(self) -> dict[str, JsonValue]:
        return cast(
            dict[str, JsonValue],
            self.model_dump(mode="json", exclude={"canonical_set_hash"}),
        )

    @classmethod
    def issue(cls, **data: Any) -> Self:
        normalized_times = _normalized_utc_data(
            data,
            "created_at_utc",
            "official_schedule_horizon_not_before_utc",
            "official_schedule_horizon_expires_at_utc",
        )
        targets = tuple(
            sorted(
                tuple(normalized_times.get("targets", ())),
                key=lambda target: (
                    target.official_kickoff_utc,
                    canonical_team_name_v1(target.official_home_team),
                    canonical_team_name_v1(target.official_away_team),
                    target.internal_fixture_target_id,
                ),
            )
        )
        normalized = {**normalized_times, "targets": targets}
        provisional = cls.model_construct(canonical_set_hash="0" * 64, **normalized)
        return cls(
            canonical_set_hash=canonical_sha256(provisional.identity_material()),
            **normalized,
        )

    @model_validator(mode="after")
    def validate_target_set(self) -> Self:
        created = ensure_utc(self.created_at_utc, field="fixture_target_set_created_at")
        if self.sport_key not in LIVE_ALLOWED_SPORT_KEYS or not self.targets:
            raise ValueError("FIXTURE_TARGET_SET_SCOPE_INVALID")
        expected = tuple(
            sorted(
                self.targets,
                key=lambda target: (
                    target.official_kickoff_utc,
                    canonical_team_name_v1(target.official_home_team),
                    canonical_team_name_v1(target.official_away_team),
                    target.internal_fixture_target_id,
                ),
            )
        )
        if self.targets != expected or any(
            target.sport_key != self.sport_key for target in self.targets
        ):
            raise ValueError("FIXTURE_TARGET_SET_NOT_CANONICAL")
        if any(
            target.source_observed_at_utc > created or created >= target.official_kickoff_utc
            for target in self.targets
        ):
            raise ValueError("FIXTURE_TARGET_SET_TEMPORAL_INVALID")
        schedule_fields = (
            self.official_schedule_horizon_not_before_utc,
            self.official_schedule_horizon_expires_at_utc,
            self.official_schedule_fixture_count,
            self.official_schedule_completeness,
        )
        if any(field is not None for field in schedule_fields):
            if any(field is None for field in schedule_fields):
                raise ValueError("FIXTURE_TARGET_SET_OFFICIAL_HORIZON_INCOMPLETE")
            horizon_starts = ensure_utc(
                cast(datetime, self.official_schedule_horizon_not_before_utc),
                field="official_schedule_horizon_not_before",
            )
            horizon_expires = ensure_utc(
                cast(datetime, self.official_schedule_horizon_expires_at_utc),
                field="official_schedule_horizon_expires_at",
            )
            if (
                horizon_starts >= horizon_expires
                or self.official_schedule_fixture_count != len(self.targets)
                or any(
                    not horizon_starts <= target.official_kickoff_utc < horizon_expires
                    for target in self.targets
                )
            ):
                raise ValueError("FIXTURE_TARGET_SET_OFFICIAL_HORIZON_INVALID")
        ids = tuple(target.internal_fixture_target_id for target in self.targets)
        hashes = tuple(target.canonical_target_hash for target in self.targets)
        identities = tuple(target.exact_identity_key() for target in self.targets)
        if (
            len(ids) != len(set(ids))
            or len(hashes) != len(set(hashes))
            or len(identities) != len(set(identities))
        ):
            raise ValueError("FIXTURE_TARGET_SET_DUPLICATED")
        if self.canonical_set_hash != canonical_sha256(self.identity_material()):
            raise ValueError("FIXTURE_TARGET_SET_HASH_MISMATCH")
        return self


class CampaignWindowDefinitionV1(FrozenContract):
    """Exact successor authority for the three executable campaign windows."""

    schema_version: Literal["robin-campaign-window-definition-v1"] = (
        "robin-campaign-window-definition-v1"
    )
    window_id: Literal["H24", "H2", "H1"]
    temporal_role: str = Field(min_length=1, max_length=120)
    temporal_role_class: str = Field(min_length=1, max_length=120)
    authority: str = Field(min_length=1, max_length=160)
    authority_caveat: str | None = Field(default=None, max_length=400)
    scientific_selection_eligible: bool
    earliest_minutes_before_kickoff: int = Field(gt=0)
    latest_minutes_before_kickoff: int = Field(gt=0)
    ideal_minutes_before_kickoff: int = Field(gt=0)
    predictor_protocol_ids: tuple[str, ...]
    target_protocol_ids: tuple[str, ...]
    protocol_role_value: int = Field(gt=0)

    @model_validator(mode="after")
    def validate_definition(self) -> Self:
        expected = _campaign_window_material_v1()[self.window_id]
        observed = self.model_dump(mode="python", exclude={"schema_version"})
        if observed != expected:
            raise ValueError("CAMPAIGN_WINDOW_DEFINITION_MUTATED")
        return self


def _campaign_window_material_v1() -> dict[str, dict[str, Any]]:
    h2_predictors = tuple(f"RDS-EXP-V1-{index:03d}" for index in range(1, 26) if index != 6)
    return {
        "H24": {
            "window_id": "H24",
            "temporal_role": "PREDICTOR",
            "temporal_role_class": "PREDICTOR_CAPTURE",
            "authority": "FROZEN_PR57",
            "authority_caveat": None,
            "scientific_selection_eligible": True,
            "earliest_minutes_before_kickoff": 1560,
            "latest_minutes_before_kickoff": 1440,
            "ideal_minutes_before_kickoff": 1440,
            "predictor_protocol_ids": (
                "RDS-EXP-V1-006",
                "RDS-EXP-V1-008",
                "RDS-EXP-V1-009",
                "RDS-EXP-V1-010",
            ),
            "target_protocol_ids": (),
            "protocol_role_value": 4,
        },
        "H2": {
            "window_id": "H2",
            "temporal_role": "MIXED_BY_PROTOCOL_WITH_DISTINCT_BINDINGS",
            "temporal_role_class": "PREDICTOR_CAPTURE_WITH_EXP006_TARGET_BINDING",
            "authority": "FROZEN_PR57",
            "authority_caveat": None,
            "scientific_selection_eligible": True,
            "earliest_minutes_before_kickoff": 135,
            "latest_minutes_before_kickoff": 120,
            "ideal_minutes_before_kickoff": 120,
            "predictor_protocol_ids": h2_predictors,
            "target_protocol_ids": ("RDS-EXP-V1-006",),
            "protocol_role_value": 25,
        },
        "H1": {
            "window_id": "H1",
            "temporal_role": "TARGET",
            "temporal_role_class": "TARGET_CAPTURE",
            "authority": "STRICT_CONVERGENCE_GUARD_PROPOSED_FROM_FROZEN_5_MIN_TOLERANCE",
            "authority_caveat": (
                "PR57 does not freeze the lower H1 bound or latest/nearest selection rule."
            ),
            "scientific_selection_eligible": False,
            "earliest_minutes_before_kickoff": 65,
            "latest_minutes_before_kickoff": 55,
            "ideal_minutes_before_kickoff": 60,
            "predictor_protocol_ids": (),
            "target_protocol_ids": ("RDS-EXP-V1-005", "RDS-EXP-V1-023"),
            "protocol_role_value": 2,
        },
    }


def campaign_window_definitions_v1() -> tuple[CampaignWindowDefinitionV1, ...]:
    material = _campaign_window_material_v1()
    return tuple(
        CampaignWindowDefinitionV1(**material[window]) for window in CAMPAIGN_SELECTION_WINDOWS
    )


def first_c0_canary_window_definitions_v1() -> tuple[CampaignWindowDefinitionV1, ...]:
    """Reuse the frozen H24/H2 definitions while excluding non-admitting H1."""

    return tuple(
        definition
        for definition in campaign_window_definitions_v1()
        if definition.window_id in {"H24", "H2"}
    )


class CampaignLeagueCorpusCountV1(FrozenContract):
    sport_key: str = Field(min_length=1, max_length=120)
    admitted_fixture_count: int = Field(ge=0)


class ScientificCorpusSnapshotV1(FrozenContract):
    """Owner-observed coverage used only as the final cross-league value factor."""

    schema_version: Literal["robin-scientific-corpus-snapshot-v1"] = (
        "robin-scientific-corpus-snapshot-v1"
    )
    observed_at_utc: datetime
    source_evidence_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    league_counts: tuple[CampaignLeagueCorpusCountV1, ...]
    canonical_corpus_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")

    def identity_material(self) -> dict[str, JsonValue]:
        return cast(
            dict[str, JsonValue],
            self.model_dump(mode="json", exclude={"canonical_corpus_hash"}),
        )

    @classmethod
    def issue(cls, **data: Any) -> Self:
        normalized = _normalized_utc_data(data, "observed_at_utc")
        counts = tuple(
            sorted(
                tuple(normalized.get("league_counts", ())),
                key=lambda item: LIVE_ALLOWED_SPORT_KEYS.index(item.sport_key),
            )
        )
        normalized["league_counts"] = counts
        provisional = cls.model_construct(canonical_corpus_hash="0" * 64, **normalized)
        return cls(
            canonical_corpus_hash=canonical_sha256(provisional.identity_material()),
            **normalized,
        )

    @model_validator(mode="after")
    def validate_corpus(self) -> Self:
        ensure_utc(self.observed_at_utc, field="campaign_corpus_observed_at")
        if tuple(item.sport_key for item in self.league_counts) != LIVE_ALLOWED_SPORT_KEYS:
            raise ValueError("CAMPAIGN_CORPUS_LEAGUES_INCOMPLETE")
        if self.canonical_corpus_hash != canonical_sha256(self.identity_material()):
            raise ValueError("CAMPAIGN_CORPUS_HASH_MISMATCH")
        return self

    def admitted_count(self, sport_key: str) -> int:
        return next(
            item.admitted_fixture_count
            for item in self.league_counts
            if item.sport_key == sport_key
        )


def _campaign_group_hash_v1(
    *,
    source_target_set_sha256: str,
    sport_key: str,
    window_id: str,
    target_hashes: tuple[str, ...],
    window_not_before_utc: datetime,
    window_expires_at_utc: datetime,
) -> str:
    return canonical_sha256(
        cast(
            dict[str, JsonValue],
            {
                "source_target_set_sha256": source_target_set_sha256,
                "sport_key": sport_key,
                "window_id": window_id,
                "target_hashes": list(target_hashes),
                "window_not_before_utc": window_not_before_utc.isoformat(),
                "window_expires_at_utc": window_expires_at_utc.isoformat(),
            },
        )
    )


class CampaignWindowCandidateV1(FrozenContract):
    schema_version: Literal["robin-campaign-window-candidate-v1"] = (
        "robin-campaign-window-candidate-v1"
    )
    candidate_id: str = Field(min_length=1, max_length=160)
    evaluated_at_utc: datetime
    source_target_set_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    fixture_target_set: FixtureTargetSetV1
    request: ProviderRequestSpec
    window_id: Literal["H24", "H2", "H1"]
    temporal_role: str = Field(min_length=1, max_length=120)
    temporal_role_class: str = Field(min_length=1, max_length=120)
    window_authority: str = Field(min_length=1, max_length=160)
    window_authority_caveat: str | None = Field(default=None, max_length=400)
    scientific_selection_eligible: bool
    predictor_protocol_ids: tuple[str, ...]
    target_protocol_ids: tuple[str, ...]
    competitions: tuple[str, ...]
    target_ids: tuple[str, ...]
    target_hashes: tuple[Sha256, ...]
    window_not_before_utc: datetime
    window_expires_at_utc: datetime
    scheduled_capture_at_utc: datetime
    usable_expires_at_utc: datetime
    fixture_coverage: int = Field(gt=0)
    protocol_role_value: int = Field(gt=0)
    timing_margin_seconds: int = Field(ge=0)
    prior_admitted_fixture_count: int = Field(ge=0)
    cross_league_corpus_value: int = Field(ge=0)
    one_call_http_ceiling: Literal[1] = 1
    one_call_credit_ceiling: Literal[1] = 1
    status: Literal[
        "MISSED_NOT_BACKDATED",
        "NON_ADMITTING_SCIENTIFIC_AUTHORITY",
        "FUTURE_INSUFFICIENT_MARGIN",
        "FUTURE_NOT_OPEN",
        "OPEN_INSUFFICIENT_MARGIN",
        "OPEN_SELECTABLE",
    ]
    stable_group_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    canonical_candidate_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")

    def identity_material(self) -> dict[str, JsonValue]:
        return cast(
            dict[str, JsonValue],
            self.model_dump(mode="json", exclude={"canonical_candidate_hash"}),
        )

    @classmethod
    def issue(cls, **data: Any) -> Self:
        normalized = _normalized_utc_data(
            data,
            "evaluated_at_utc",
            "window_not_before_utc",
            "window_expires_at_utc",
            "scheduled_capture_at_utc",
            "usable_expires_at_utc",
        )
        provisional = cls.model_construct(canonical_candidate_hash="0" * 64, **normalized)
        return cls(
            canonical_candidate_hash=canonical_sha256(provisional.identity_material()),
            **normalized,
        )

    @model_validator(mode="after")
    def validate_candidate(self) -> Self:
        evaluated = ensure_utc(self.evaluated_at_utc, field="campaign_candidate_evaluated_at")
        starts = ensure_utc(self.window_not_before_utc, field="campaign_window_not_before")
        closes = ensure_utc(self.window_expires_at_utc, field="campaign_window_expires_at")
        scheduled = ensure_utc(self.scheduled_capture_at_utc, field="campaign_scheduled_at")
        usable = ensure_utc(self.usable_expires_at_utc, field="campaign_usable_expires_at")
        target_ids = tuple(
            target.internal_fixture_target_id for target in self.fixture_target_set.targets
        )
        target_hashes = tuple(
            target.canonical_target_hash for target in self.fixture_target_set.targets
        )
        competitions = tuple(
            sorted({target.competition for target in self.fixture_target_set.targets})
        )
        definition = next(
            item for item in campaign_window_definitions_v1() if item.window_id == self.window_id
        )
        readiness = max(evaluated, starts)
        margin = max(0, int((usable - readiness).total_seconds()))
        expected_group_hash = _campaign_group_hash_v1(
            source_target_set_sha256=self.source_target_set_sha256,
            sport_key=self.request.sport_key,
            window_id=self.window_id,
            target_hashes=target_hashes,
            window_not_before_utc=starts,
            window_expires_at_utc=closes,
        )
        if evaluated >= usable or evaluated >= closes:
            expected_status = "MISSED_NOT_BACKDATED"
        elif not definition.scientific_selection_eligible:
            expected_status = "NON_ADMITTING_SCIENTIFIC_AUTHORITY"
        elif evaluated < starts:
            expected_status = (
                "FUTURE_NOT_OPEN"
                if usable - starts >= MIN_OWNER_REVIEW_WINDOW
                else "FUTURE_INSUFFICIENT_MARGIN"
            )
        elif usable - evaluated < MIN_OWNER_REVIEW_WINDOW:
            expected_status = "OPEN_INSUFFICIENT_MARGIN"
        else:
            expected_status = "OPEN_SELECTABLE"
        if (
            not starts <= scheduled <= closes
            or usable > closes
            or self.fixture_target_set.created_at_utc > evaluated
            or self.fixture_coverage != len(target_ids)
            or self.target_ids != target_ids
            or self.target_hashes != target_hashes
            or self.competitions != competitions
            or self.stable_group_hash != expected_group_hash
            or self.timing_margin_seconds != margin
            or self.status != expected_status
            or self.temporal_role != definition.temporal_role
            or self.temporal_role_class != definition.temporal_role_class
            or self.window_authority != definition.authority
            or self.window_authority_caveat != definition.authority_caveat
            or self.scientific_selection_eligible != definition.scientific_selection_eligible
            or self.predictor_protocol_ids != definition.predictor_protocol_ids
            or self.target_protocol_ids != definition.target_protocol_ids
            or self.protocol_role_value != definition.protocol_role_value
            or self.request.sport_key != self.fixture_target_set.sport_key
            or self.request.endpoint != f"/v4/sports/{self.request.sport_key}/odds"
            or self.request.markets != ("h2h",)
            or self.request.timeout_seconds != 5
            or self.canonical_candidate_hash != canonical_sha256(self.identity_material())
        ):
            raise ValueError("CAMPAIGN_CANDIDATE_INVALID")
        return self


def _candidate_rank_v1(
    candidate: CampaignWindowCandidateV1,
) -> tuple[int, int, int, int, datetime, str]:
    positive_margin = int(
        candidate.timing_margin_seconds >= int(MIN_OWNER_REVIEW_WINDOW.total_seconds())
    )
    return (
        -candidate.fixture_coverage,
        -candidate.protocol_role_value,
        -positive_margin,
        -candidate.cross_league_corpus_value,
        candidate.window_not_before_utc,
        candidate.stable_group_hash,
    )


def _first_c0_canary_candidate_rank_v1(
    candidate: CampaignWindowCandidateV1,
) -> tuple[int, int, int, datetime, str]:
    positive_margin = int(
        candidate.timing_margin_seconds >= FIRST_C0_CANARY_MINIMUM_READY_MARGIN_SECONDS
    )
    return (
        -candidate.fixture_coverage,
        -candidate.protocol_role_value,
        -positive_margin,
        max(candidate.evaluated_at_utc, candidate.window_not_before_utc),
        candidate.stable_group_hash,
    )


def _first_c0_canary_candidate_selectable_v1(
    candidate: CampaignWindowCandidateV1,
) -> bool:
    return (
        candidate.status in {"OPEN_SELECTABLE", "FUTURE_NOT_OPEN"}
        and candidate.timing_margin_seconds >= FIRST_C0_CANARY_MINIMUM_READY_MARGIN_SECONDS
    )


def _interval_candidate_groups_v1(
    intervals: tuple[tuple[OfficialFixtureTargetV1, datetime, datetime], ...],
) -> tuple[tuple[tuple[OfficialFixtureTargetV1, ...], datetime, datetime], ...]:
    """Enumerate every distinct active interval clique without greedy removal."""

    endpoints = tuple(
        sorted({point for _, starts, closes in intervals for point in (starts, closes)})
    )
    groups: dict[
        tuple[str, ...],
        tuple[tuple[OfficialFixtureTargetV1, ...], datetime, datetime],
    ] = {}
    for point in endpoints:
        covered = tuple(item for item in intervals if item[1] <= point <= item[2])
        if not covered:
            continue
        key = tuple(item[0].canonical_target_hash for item in covered)
        groups[key] = (
            tuple(item[0] for item in covered),
            max(item[1] for item in covered),
            min(item[2] for item in covered),
        )
    return tuple(
        groups[key]
        for key in sorted(
            groups,
            key=lambda item: (-len(item), item),
        )
    )


def _derive_window_candidates_v1(
    *,
    source_target_sets: tuple[FixtureTargetSetV1, ...],
    window_definitions: tuple[CampaignWindowDefinitionV1, ...],
    prior_admitted_counts: dict[str, int],
    cross_league_corpus_values: dict[str, int],
    evaluated_at_utc: datetime,
    mission_expires_at_utc: datetime,
) -> tuple[CampaignWindowCandidateV1, ...]:
    candidates: list[CampaignWindowCandidateV1] = []
    for source_set in source_target_sets:
        prior_count = prior_admitted_counts[source_set.sport_key]
        cross_league_value = cross_league_corpus_values[source_set.sport_key]
        for definition in window_definitions:
            intervals = tuple(
                (
                    target,
                    target.official_kickoff_utc
                    - timedelta(minutes=definition.earliest_minutes_before_kickoff),
                    target.official_kickoff_utc
                    - timedelta(minutes=definition.latest_minutes_before_kickoff),
                )
                for target in source_set.targets
            )
            for targets, opens, closes in _interval_candidate_groups_v1(intervals):
                scheduled = closes
                earliest_kickoff = min(target.official_kickoff_utc for target in targets)
                usable = min(
                    closes,
                    mission_expires_at_utc,
                    earliest_kickoff - PRE_KICKOFF_SAFETY_MARGIN,
                )
                group_hash = _campaign_group_hash_v1(
                    source_target_set_sha256=source_set.canonical_set_hash,
                    sport_key=source_set.sport_key,
                    window_id=definition.window_id,
                    target_hashes=tuple(target.canonical_target_hash for target in targets),
                    window_not_before_utc=opens,
                    window_expires_at_utc=closes,
                )
                candidate_id = (
                    f"campaign-{definition.window_id.lower()}-"
                    f"{source_set.sport_key}-{group_hash[:20]}"
                )
                candidate_set = FixtureTargetSetV1.issue(
                    target_set_id=f"campaign-targets-{group_hash[:32]}",
                    sport_key=source_set.sport_key,
                    workspace_receipt_sha256=source_set.workspace_receipt_sha256,
                    created_at_utc=source_set.created_at_utc,
                    targets=targets,
                )
                if evaluated_at_utc >= usable or evaluated_at_utc >= closes:
                    status = "MISSED_NOT_BACKDATED"
                elif not definition.scientific_selection_eligible:
                    status = "NON_ADMITTING_SCIENTIFIC_AUTHORITY"
                elif evaluated_at_utc < opens:
                    status = (
                        "FUTURE_NOT_OPEN"
                        if usable - opens >= MIN_OWNER_REVIEW_WINDOW
                        else "FUTURE_INSUFFICIENT_MARGIN"
                    )
                elif usable - evaluated_at_utc < MIN_OWNER_REVIEW_WINDOW:
                    status = "OPEN_INSUFFICIENT_MARGIN"
                else:
                    status = "OPEN_SELECTABLE"
                candidates.append(
                    CampaignWindowCandidateV1.issue(
                        candidate_id=candidate_id,
                        evaluated_at_utc=evaluated_at_utc,
                        source_target_set_sha256=source_set.canonical_set_hash,
                        fixture_target_set=candidate_set,
                        request=ProviderRequestSpec(
                            endpoint=f"/v4/sports/{source_set.sport_key}/odds",
                            sport_key=source_set.sport_key,
                            region="eu",
                            markets=("h2h",),
                            timeout_seconds=5,
                        ),
                        window_id=definition.window_id,
                        temporal_role=definition.temporal_role,
                        temporal_role_class=definition.temporal_role_class,
                        window_authority=definition.authority,
                        window_authority_caveat=definition.authority_caveat,
                        scientific_selection_eligible=(definition.scientific_selection_eligible),
                        predictor_protocol_ids=definition.predictor_protocol_ids,
                        target_protocol_ids=definition.target_protocol_ids,
                        competitions=tuple(sorted({target.competition for target in targets})),
                        target_ids=tuple(
                            target.internal_fixture_target_id for target in candidate_set.targets
                        ),
                        target_hashes=tuple(
                            target.canonical_target_hash for target in candidate_set.targets
                        ),
                        window_not_before_utc=opens,
                        window_expires_at_utc=closes,
                        scheduled_capture_at_utc=scheduled,
                        usable_expires_at_utc=usable,
                        fixture_coverage=len(targets),
                        protocol_role_value=definition.protocol_role_value,
                        timing_margin_seconds=max(
                            0,
                            int((usable - max(evaluated_at_utc, opens)).total_seconds()),
                        ),
                        prior_admitted_fixture_count=prior_count,
                        cross_league_corpus_value=cross_league_value,
                        status=status,
                        stable_group_hash=group_hash,
                    )
                )
    return tuple(
        sorted(
            candidates,
            key=lambda candidate: (
                candidate.window_not_before_utc,
                LIVE_ALLOWED_SPORT_KEYS.index(candidate.request.sport_key),
                CAMPAIGN_SELECTION_WINDOWS.index(candidate.window_id),
                candidate.canonical_candidate_hash,
            ),
        )
    )


def _derive_campaign_candidates_v1(
    *,
    source_target_sets: tuple[FixtureTargetSetV1, ...],
    window_definitions: tuple[CampaignWindowDefinitionV1, ...],
    corpus_snapshot: ScientificCorpusSnapshotV1,
    evaluated_at_utc: datetime,
    mission_expires_at_utc: datetime,
) -> tuple[CampaignWindowCandidateV1, ...]:
    maximum_corpus_count = max(
        item.admitted_fixture_count for item in corpus_snapshot.league_counts
    )
    prior_counts = {
        target_set.sport_key: corpus_snapshot.admitted_count(target_set.sport_key)
        for target_set in source_target_sets
    }
    return _derive_window_candidates_v1(
        source_target_sets=source_target_sets,
        window_definitions=window_definitions,
        prior_admitted_counts=prior_counts,
        cross_league_corpus_values={
            sport_key: maximum_corpus_count - prior_count
            for sport_key, prior_count in prior_counts.items()
        },
        evaluated_at_utc=evaluated_at_utc,
        mission_expires_at_utc=mission_expires_at_utc,
    )


def _derive_first_c0_canary_candidates_v1(
    *,
    source_target_sets: tuple[FixtureTargetSetV1, ...],
    window_definitions: tuple[CampaignWindowDefinitionV1, ...],
    evaluated_at_utc: datetime,
    mission_expires_at_utc: datetime,
) -> tuple[CampaignWindowCandidateV1, ...]:
    sport_keys = {target_set.sport_key for target_set in source_target_sets}
    return _derive_window_candidates_v1(
        source_target_sets=source_target_sets,
        window_definitions=window_definitions,
        prior_admitted_counts={sport_key: 0 for sport_key in sport_keys},
        cross_league_corpus_values={sport_key: 0 for sport_key in sport_keys},
        evaluated_at_utc=evaluated_at_utc,
        mission_expires_at_utc=mission_expires_at_utc,
    )


class CampaignWindowSelectionV1(FrozenContract):
    """Complete frozen five-league universe and its unique best remaining winner."""

    schema_version: Literal["robin-campaign-window-selection-v1"] = (
        "robin-campaign-window-selection-v1"
    )
    selection_revision: Literal["complete-five-league-interval-clique-ranking-v2"] = (
        CAMPAIGN_SELECTION_REVISION
    )
    ranking_policy: Literal[
        "coverage-desc;protocol-role-desc;positive-margin-required;"
        "cross-league-desc;earliest-readiness-asc;stable-group-hash-asc"
    ] = CAMPAIGN_RANKING_POLICY
    selected_at_utc: datetime
    workspace_receipt_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    workspace_prepared_at_utc: datetime
    mission_manifest_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    mission_expires_at_utc: datetime
    source_target_sets: tuple[FixtureTargetSetV1, ...]
    corpus_snapshot: ScientificCorpusSnapshotV1
    window_definitions: tuple[CampaignWindowDefinitionV1, ...]
    candidates: tuple[CampaignWindowCandidateV1, ...]
    selected_candidate_id: str = Field(min_length=1, max_length=160)
    selected_candidate_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    selected_fixture_target_set_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    selected_not_before_utc: datetime
    selected_ready_at_selection: bool
    canonical_selection_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")

    def identity_material(self) -> dict[str, JsonValue]:
        return cast(
            dict[str, JsonValue],
            self.model_dump(mode="json", exclude={"canonical_selection_hash"}),
        )

    @classmethod
    def issue(cls, **data: Any) -> Self:
        normalized = _normalized_utc_data(
            data,
            "selected_at_utc",
            "workspace_prepared_at_utc",
            "mission_expires_at_utc",
            "selected_not_before_utc",
        )
        source_sets = tuple(
            sorted(
                tuple(normalized.get("source_target_sets", ())),
                key=lambda target_set: LIVE_ALLOWED_SPORT_KEYS.index(target_set.sport_key),
            )
        )
        definitions = tuple(normalized.get("window_definitions", campaign_window_definitions_v1()))
        candidates = _derive_campaign_candidates_v1(
            source_target_sets=source_sets,
            window_definitions=definitions,
            corpus_snapshot=cast(ScientificCorpusSnapshotV1, normalized["corpus_snapshot"]),
            evaluated_at_utc=cast(datetime, normalized["selected_at_utc"]),
            mission_expires_at_utc=cast(datetime, normalized["mission_expires_at_utc"]),
        )
        selectable = tuple(
            candidate
            for candidate in candidates
            if candidate.status in {"OPEN_SELECTABLE", "FUTURE_NOT_OPEN"}
        )
        if not selectable:
            raise ValueError("CAMPAIGN_NO_REMAINING_SELECTABLE_CANDIDATE")
        selected = min(selectable, key=_candidate_rank_v1)
        normalized.update(
            source_target_sets=source_sets,
            window_definitions=definitions,
            candidates=candidates,
            selected_candidate_id=selected.candidate_id,
            selected_candidate_sha256=selected.canonical_candidate_hash,
            selected_fixture_target_set_sha256=(selected.fixture_target_set.canonical_set_hash),
            selected_not_before_utc=max(
                cast(datetime, normalized["selected_at_utc"]),
                selected.window_not_before_utc,
            ),
            selected_ready_at_selection=(selected.status == "OPEN_SELECTABLE"),
        )
        provisional = cls.model_construct(canonical_selection_hash="0" * 64, **normalized)
        return cls(
            canonical_selection_hash=canonical_sha256(provisional.identity_material()),
            **normalized,
        )

    @model_validator(mode="after")
    def validate_selection(self) -> Self:
        selected_at = ensure_utc(self.selected_at_utc, field="campaign_selected_at")
        prepared_at = ensure_utc(
            self.workspace_prepared_at_utc,
            field="campaign_workspace_prepared_at",
        )
        mission_expires = ensure_utc(
            self.mission_expires_at_utc,
            field="campaign_mission_expires_at",
        )
        selected_not_before = ensure_utc(
            self.selected_not_before_utc,
            field="campaign_selected_not_before",
        )
        if (
            selected_at < prepared_at
            or selected_at >= mission_expires
            or self.ranking_policy != CAMPAIGN_RANKING_POLICY
            or self.window_definitions != campaign_window_definitions_v1()
            or tuple(item.sport_key for item in self.source_target_sets) != LIVE_ALLOWED_SPORT_KEYS
            or self.corpus_snapshot.observed_at_utc < prepared_at
            or self.corpus_snapshot.observed_at_utc > selected_at
            or selected_at - self.corpus_snapshot.observed_at_utc > MAX_CAMPAIGN_SOURCE_AGE
        ):
            raise ValueError("CAMPAIGN_SELECTION_SCOPE_INVALID")
        for target_set in self.source_target_sets:
            if (
                target_set.workspace_receipt_sha256 != self.workspace_receipt_sha256
                or target_set.created_at_utc < prepared_at
                or target_set.created_at_utc > selected_at
                or selected_at - target_set.created_at_utc > MAX_CAMPAIGN_SOURCE_AGE
                or target_set.official_schedule_completeness
                != "OWNER_REVIEWED_COMPLETE_OFFICIAL_HORIZON"
                or target_set.official_schedule_fixture_count != len(target_set.targets)
                or target_set.official_schedule_horizon_not_before_utc is None
                or target_set.official_schedule_horizon_expires_at_utc is None
                or not target_set.official_schedule_horizon_not_before_utc
                <= selected_at
                < target_set.official_schedule_horizon_expires_at_utc
                or any(
                    target.source_observed_at_utc < prepared_at
                    or target.source_observed_at_utc > target_set.created_at_utc
                    or selected_at - target.source_observed_at_utc > MAX_CAMPAIGN_SOURCE_AGE
                    for target in target_set.targets
                )
            ):
                raise ValueError("CAMPAIGN_OFFICIAL_SCHEDULE_NOT_POST_BOOTSTRAP")
        expected_candidates = _derive_campaign_candidates_v1(
            source_target_sets=self.source_target_sets,
            window_definitions=self.window_definitions,
            corpus_snapshot=self.corpus_snapshot,
            evaluated_at_utc=selected_at,
            mission_expires_at_utc=mission_expires,
        )
        selectable = tuple(
            candidate
            for candidate in expected_candidates
            if candidate.status in {"OPEN_SELECTABLE", "FUTURE_NOT_OPEN"}
        )
        if not selectable:
            raise ValueError("CAMPAIGN_NO_REMAINING_SELECTABLE_CANDIDATE")
        selected = min(selectable, key=_candidate_rank_v1)
        if (
            self.candidates != expected_candidates
            or self.selected_candidate_id != selected.candidate_id
            or self.selected_candidate_sha256 != selected.canonical_candidate_hash
            or self.selected_fixture_target_set_sha256
            != selected.fixture_target_set.canonical_set_hash
            or selected_not_before != max(selected_at, selected.window_not_before_utc)
            or self.selected_ready_at_selection != (selected.status == "OPEN_SELECTABLE")
            or self.canonical_selection_hash != canonical_sha256(self.identity_material())
        ):
            raise ValueError("CAMPAIGN_SELECTION_DERIVATION_MISMATCH")
        return self

    def selected_candidate(self) -> CampaignWindowCandidateV1:
        matches = tuple(
            candidate
            for candidate in self.candidates
            if candidate.canonical_candidate_hash == self.selected_candidate_sha256
            and candidate.candidate_id == self.selected_candidate_id
        )
        if len(matches) != 1:
            raise ValueError("CAMPAIGN_SELECTED_CANDIDATE_MISSING")
        return matches[0]

    def assert_selected_candidate_current(self, now: datetime) -> None:
        current = ensure_utc(now, field="campaign_current_at")
        if current < self.selected_at_utc or current >= self.mission_expires_at_utc:
            raise ValueError("CAMPAIGN_SELECTION_NOT_CURRENT")
        if current - self.corpus_snapshot.observed_at_utc > MAX_CAMPAIGN_SOURCE_AGE or any(
            current - target_set.created_at_utc > MAX_CAMPAIGN_SOURCE_AGE
            or any(
                current - target.source_observed_at_utc > MAX_CAMPAIGN_SOURCE_AGE
                for target in target_set.targets
            )
            for target_set in self.source_target_sets
        ):
            raise ValueError("CAMPAIGN_SELECTION_SOURCE_STALE")
        current_candidates = _derive_campaign_candidates_v1(
            source_target_sets=self.source_target_sets,
            window_definitions=self.window_definitions,
            corpus_snapshot=self.corpus_snapshot,
            evaluated_at_utc=current,
            mission_expires_at_utc=self.mission_expires_at_utc,
        )
        selectable = tuple(
            candidate
            for candidate in current_candidates
            if candidate.status in {"OPEN_SELECTABLE", "FUTURE_NOT_OPEN"}
        )
        if not selectable:
            raise ValueError("CAMPAIGN_NO_REMAINING_SELECTABLE_CANDIDATE")
        selected = min(selectable, key=_candidate_rank_v1)
        originally_selected = self.selected_candidate()
        if selected.stable_group_hash != originally_selected.stable_group_hash:
            raise ValueError("CAMPAIGN_SELECTED_CANDIDATE_NO_LONGER_BEST")
        if selected.status != "OPEN_SELECTABLE":
            raise ValueError("CAMPAIGN_SELECTED_CANDIDATE_NOT_OPEN")


class FirstC0CanarySelectionV1(FrozenContract):
    """Additive single-league authority for only the first real C0 canary."""

    schema_version: Literal["robin-first-c0-canary-selection-v1"] = (
        "robin-first-c0-canary-selection-v1"
    )
    selection_revision: Literal["single-league-first-real-c0-canary-v1"] = (
        FIRST_C0_CANARY_SELECTION_REVISION
    )
    purpose: Literal["FIRST_REAL_CAPTURE_CANARY_ONLY"] = "FIRST_REAL_CAPTURE_CANARY_ONLY"
    mission_id: MissionIdV1
    ranking_policy: Literal[
        "coverage-desc;protocol-role-desc;positive-margin-required;"
        "earliest-readiness-asc;stable-group-hash-asc"
    ] = FIRST_C0_CANARY_RANKING_POLICY
    selected_at_utc: datetime
    workspace_receipt_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    workspace_prepared_at_utc: datetime
    mission_manifest_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    mission_expires_at_utc: datetime
    source_target_set_count: Literal[1] = 1
    sport_key_count: Literal[1] = 1
    sport_key: Literal["soccer_spain_la_liga", "soccer_germany_bundesliga"]
    source_target_sets: tuple[FixtureTargetSetV1, ...]
    window_definitions: tuple[CampaignWindowDefinitionV1, ...]
    candidates: tuple[CampaignWindowCandidateV1, ...]
    selected_candidate_id: str = Field(min_length=1, max_length=160)
    selected_candidate_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    selected_fixture_target_set_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    selected_not_before_utc: datetime
    selected_ready_at_selection: bool
    maximum_http_calls: Literal[1] = 1
    maximum_credits: Literal[1] = 1
    markets: tuple[Literal["h2h"], ...] = ("h2h",)
    region: Literal["eu"] = "eu"
    production_selection_authority: Literal[False] = False
    promotion_authority: Literal[False] = False
    batch_authority: Literal[False] = False
    scientific_edge_claim: Literal[False] = False
    canonical_selection_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")

    def identity_material(self) -> dict[str, JsonValue]:
        return cast(
            dict[str, JsonValue],
            self.model_dump(mode="json", exclude={"canonical_selection_hash"}),
        )

    @classmethod
    def issue(cls, **data: Any) -> Self:
        normalized = _normalized_utc_data(
            data,
            "selected_at_utc",
            "workspace_prepared_at_utc",
            "mission_expires_at_utc",
            "selected_not_before_utc",
        )
        source_sets = tuple(normalized.get("source_target_sets", ()))
        if len(source_sets) != 1 or not isinstance(source_sets[0], FixtureTargetSetV1):
            raise ValueError("FIRST_C0_CANARY_SOURCE_TARGET_SET_COUNT_INVALID")
        definitions = tuple(
            normalized.get("window_definitions", first_c0_canary_window_definitions_v1())
        )
        candidates = _derive_first_c0_canary_candidates_v1(
            source_target_sets=source_sets,
            window_definitions=definitions,
            evaluated_at_utc=cast(datetime, normalized["selected_at_utc"]),
            mission_expires_at_utc=cast(datetime, normalized["mission_expires_at_utc"]),
        )
        selectable = tuple(
            candidate
            for candidate in candidates
            if _first_c0_canary_candidate_selectable_v1(candidate)
        )
        if not selectable:
            raise ValueError("FIRST_C0_CANARY_NO_REMAINING_SELECTABLE_CANDIDATE")
        selected = min(selectable, key=_first_c0_canary_candidate_rank_v1)
        normalized.update(
            sport_key=source_sets[0].sport_key,
            source_target_sets=source_sets,
            window_definitions=definitions,
            candidates=candidates,
            selected_candidate_id=selected.candidate_id,
            selected_candidate_sha256=selected.canonical_candidate_hash,
            selected_fixture_target_set_sha256=selected.fixture_target_set.canonical_set_hash,
            selected_not_before_utc=max(
                cast(datetime, normalized["selected_at_utc"]),
                selected.window_not_before_utc,
            ),
            selected_ready_at_selection=(selected.status == "OPEN_SELECTABLE"),
        )
        provisional = cls.model_construct(canonical_selection_hash="0" * 64, **normalized)
        return cls(
            canonical_selection_hash=canonical_sha256(provisional.identity_material()),
            **normalized,
        )

    @model_validator(mode="after")
    def validate_selection(self) -> Self:
        selected_at = ensure_utc(self.selected_at_utc, field="first_c0_canary_selected_at")
        prepared_at = ensure_utc(
            self.workspace_prepared_at_utc,
            field="first_c0_canary_workspace_prepared_at",
        )
        mission_expires = ensure_utc(
            self.mission_expires_at_utc,
            field="first_c0_canary_mission_expires_at",
        )
        selected_not_before = ensure_utc(
            self.selected_not_before_utc,
            field="first_c0_canary_selected_not_before",
        )
        if (
            selected_at < prepared_at
            or selected_at >= mission_expires
            or self.ranking_policy != FIRST_C0_CANARY_RANKING_POLICY
            or self.window_definitions != first_c0_canary_window_definitions_v1()
            or self.source_target_set_count != 1
            or self.sport_key_count != 1
            or len(self.source_target_sets) != 1
            or self.sport_key not in FIRST_C0_CANARY_SPORT_KEYS
            or self.source_target_sets[0].sport_key != self.sport_key
            or self.maximum_http_calls != 1
            or self.maximum_credits != 1
            or self.markets != ("h2h",)
            or self.region != "eu"
            or self.production_selection_authority
            or self.promotion_authority
            or self.batch_authority
            or self.scientific_edge_claim
        ):
            raise ValueError("FIRST_C0_CANARY_SELECTION_SCOPE_INVALID")
        target_set = self.source_target_sets[0]
        if (
            target_set.workspace_receipt_sha256 != self.workspace_receipt_sha256
            or target_set.created_at_utc < prepared_at
            or target_set.created_at_utc > selected_at
            or selected_at - target_set.created_at_utc > MAX_CAMPAIGN_SOURCE_AGE
            or target_set.official_schedule_completeness
            != "OWNER_REVIEWED_COMPLETE_OFFICIAL_HORIZON"
            or target_set.official_schedule_fixture_count != len(target_set.targets)
            or target_set.official_schedule_horizon_not_before_utc is None
            or target_set.official_schedule_horizon_expires_at_utc is None
            or not target_set.official_schedule_horizon_not_before_utc
            <= selected_at
            < target_set.official_schedule_horizon_expires_at_utc
            or len({target.official_source_authority for target in target_set.targets}) != 1
            or len({target.source_evidence_sha256 for target in target_set.targets}) != 1
            or any(
                target.sport_key != self.sport_key
                or target.competition != FIRST_C0_CANARY_COMPETITIONS[self.sport_key]
                or not _first_c0_official_source_authority_valid(
                    self.sport_key,
                    target.official_source_authority,
                )
                or target.source_observed_at_utc < prepared_at
                or target.source_observed_at_utc > target_set.created_at_utc
                or selected_at - target.source_observed_at_utc > MAX_CAMPAIGN_SOURCE_AGE
                or target.official_kickoff_utc <= selected_at
                for target in target_set.targets
            )
        ):
            raise ValueError("FIRST_C0_CANARY_OFFICIAL_SOURCE_INVALID")
        expected_candidates = _derive_first_c0_canary_candidates_v1(
            source_target_sets=self.source_target_sets,
            window_definitions=self.window_definitions,
            evaluated_at_utc=selected_at,
            mission_expires_at_utc=mission_expires,
        )
        if any(
            candidate.window_id not in {"H24", "H2"}
            or candidate.prior_admitted_fixture_count != 0
            or candidate.cross_league_corpus_value != 0
            for candidate in expected_candidates
        ):
            raise ValueError("FIRST_C0_CANARY_CANDIDATE_SCOPE_INVALID")
        selectable = tuple(
            candidate
            for candidate in expected_candidates
            if _first_c0_canary_candidate_selectable_v1(candidate)
        )
        if not selectable:
            raise ValueError("FIRST_C0_CANARY_NO_REMAINING_SELECTABLE_CANDIDATE")
        selected = min(selectable, key=_first_c0_canary_candidate_rank_v1)
        if (
            self.candidates != expected_candidates
            or self.selected_candidate_id != selected.candidate_id
            or self.selected_candidate_sha256 != selected.canonical_candidate_hash
            or self.selected_fixture_target_set_sha256
            != selected.fixture_target_set.canonical_set_hash
            or selected_not_before != max(selected_at, selected.window_not_before_utc)
            or self.selected_ready_at_selection != (selected.status == "OPEN_SELECTABLE")
            or self.canonical_selection_hash != canonical_sha256(self.identity_material())
        ):
            raise ValueError("FIRST_C0_CANARY_SELECTION_DERIVATION_MISMATCH")
        return self

    def selected_candidate(self) -> CampaignWindowCandidateV1:
        matches = tuple(
            candidate
            for candidate in self.candidates
            if candidate.canonical_candidate_hash == self.selected_candidate_sha256
            and candidate.candidate_id == self.selected_candidate_id
        )
        if len(matches) != 1:
            raise ValueError("FIRST_C0_CANARY_SELECTED_CANDIDATE_MISSING")
        return matches[0]

    def assert_selected_candidate_current(self, now: datetime) -> None:
        current = ensure_utc(now, field="first_c0_canary_current_at")
        target_set = self.source_target_sets[0]
        if current < self.selected_at_utc or current >= self.mission_expires_at_utc:
            raise ValueError("FIRST_C0_CANARY_SELECTION_NOT_CURRENT")
        if (
            current - target_set.created_at_utc > MAX_CAMPAIGN_SOURCE_AGE
            or target_set.official_schedule_horizon_not_before_utc is None
            or target_set.official_schedule_horizon_expires_at_utc is None
            or not target_set.official_schedule_horizon_not_before_utc
            <= current
            < target_set.official_schedule_horizon_expires_at_utc
            or any(
                current - target.source_observed_at_utc > MAX_CAMPAIGN_SOURCE_AGE
                for target in target_set.targets
            )
        ):
            raise ValueError("FIRST_C0_CANARY_SELECTION_SOURCE_STALE")
        current_candidates = _derive_first_c0_canary_candidates_v1(
            source_target_sets=self.source_target_sets,
            window_definitions=self.window_definitions,
            evaluated_at_utc=current,
            mission_expires_at_utc=self.mission_expires_at_utc,
        )
        selectable = tuple(
            candidate
            for candidate in current_candidates
            if _first_c0_canary_candidate_selectable_v1(candidate)
        )
        if not selectable:
            raise ValueError("FIRST_C0_CANARY_NO_REMAINING_SELECTABLE_CANDIDATE")
        selected = min(selectable, key=_first_c0_canary_candidate_rank_v1)
        if selected.stable_group_hash != self.selected_candidate().stable_group_hash:
            raise ValueError("FIRST_C0_CANARY_SELECTED_CANDIDATE_NO_LONGER_BEST")
        if selected.status != "OPEN_SELECTABLE":
            raise ValueError("FIRST_C0_CANARY_SELECTED_CANDIDATE_NOT_OPEN")


class FirstC0PrefetchedWindowHandoffV1(FrozenContract):
    """Immutable authority for local, clock-only opening of one prefetched H2 bundle."""

    schema_version: Literal["robin-first-c0-prefetched-window-handoff-v1"] = (
        "robin-first-c0-prefetched-window-handoff-v1"
    )
    workspace_receipt_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    mission_manifest_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    source_plan_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    official_fetch_receipt_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    official_raw_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    official_evidence_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    fixture_target_set_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    campaign_selection_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    selected_candidate_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    bundle_manifest_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    selected_window_id: Literal["H2"] = "H2"
    source_observed_at_utc: datetime
    prefetched_at_utc: datetime
    window_not_before_utc: datetime
    window_expires_at_utc: datetime
    selected_usable_expires_at_utc: datetime
    recommended_owner_sequence_start_utc: datetime
    source_age_at_window_open_seconds: int = Field(ge=0)
    maximum_source_age_seconds: Literal[1800] = 1800
    preparation_cycle_number: int = Field(ge=1, le=3)
    official_physical_reads_cumulative: int = Field(ge=1, le=12)
    local_activation_authorized: Literal[True] = True
    additional_official_reads_authorized: Literal[0] = 0
    additional_preparation_cycles_authorized: Literal[0] = 0
    additional_selector_invocations_authorized: Literal[0] = 0
    additional_target_set_freezes_authorized: Literal[0] = 0
    canonical_receipt_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")

    def identity_material(self) -> dict[str, JsonValue]:
        return cast(
            dict[str, JsonValue],
            self.model_dump(mode="json", exclude={"canonical_receipt_sha256"}),
        )

    @classmethod
    def issue(cls, **data: Any) -> Self:
        normalized = _normalized_utc_data(
            data,
            "source_observed_at_utc",
            "prefetched_at_utc",
            "window_not_before_utc",
            "window_expires_at_utc",
            "selected_usable_expires_at_utc",
            "recommended_owner_sequence_start_utc",
        )
        source_observed = cast(datetime, normalized["source_observed_at_utc"])
        window_open = cast(datetime, normalized["window_not_before_utc"])
        normalized["source_age_at_window_open_seconds"] = int(
            (window_open - source_observed).total_seconds()
        )
        provisional = cls.model_construct(canonical_receipt_sha256="0" * 64, **normalized)
        return cls(
            canonical_receipt_sha256=canonical_sha256(provisional.identity_material()),
            **normalized,
        )

    @model_validator(mode="after")
    def validate_handoff(self) -> Self:
        observed = ensure_utc(
            self.source_observed_at_utc,
            field="first_c0_prefetch_source_observed_at",
        )
        prefetched = ensure_utc(
            self.prefetched_at_utc,
            field="first_c0_prefetched_at",
        )
        window_open = ensure_utc(
            self.window_not_before_utc,
            field="first_c0_prefetch_window_not_before",
        )
        window_expires = ensure_utc(
            self.window_expires_at_utc,
            field="first_c0_prefetch_window_expires",
        )
        owner_start = ensure_utc(
            self.recommended_owner_sequence_start_utc,
            field="first_c0_owner_sequence_start",
        )
        usable_expires = ensure_utc(
            self.selected_usable_expires_at_utc,
            field="first_c0_prefetch_usable_expires_at",
        )
        if (
            observed > prefetched
            or prefetched >= window_open
            or window_expires - window_open
            != timedelta(seconds=FIRST_C0_H2_WINDOW_DURATION_SECONDS)
            or usable_expires
            < window_open
            + timedelta(
                seconds=(
                    FIRST_C0_CANARY_MINIMUM_READY_MARGIN_SECONDS
                    + FIRST_C0_MAXIMUM_OPEN_TO_PREFLIGHT_SECONDS
                )
            )
            or usable_expires > window_expires
            or owner_start != window_open - timedelta(seconds=FIRST_C0_H2_PREFETCH_LEAD_SECONDS)
            or self.source_age_at_window_open_seconds
            != int((window_open - observed).total_seconds())
            or window_open - observed > timedelta(seconds=self.maximum_source_age_seconds)
            or self.source_age_at_window_open_seconds > self.maximum_source_age_seconds
            or self.additional_official_reads_authorized != 0
            or self.additional_preparation_cycles_authorized != 0
            or self.additional_selector_invocations_authorized != 0
            or self.additional_target_set_freezes_authorized != 0
            or not self.local_activation_authorized
            or self.canonical_receipt_sha256 != canonical_sha256(self.identity_material())
        ):
            raise ValueError("FIRST_C0_PREFETCH_HANDOFF_INVALID")
        return self


class FirstC0WindowOpenRevalidationV1(FrozenContract):
    """Append-only local receipt proving the prefetched candidate opened without effects."""

    schema_version: Literal["robin-first-c0-window-open-revalidation-v1"] = (
        "robin-first-c0-window-open-revalidation-v1"
    )
    prefetch_handoff_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    workspace_receipt_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    mission_manifest_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    bundle_manifest_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    campaign_selection_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    selected_candidate_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    wait_started_at_utc: datetime
    checked_at_utc: datetime
    source_observed_at_utc: datetime
    mission_expires_at_utc: datetime
    selected_usable_expires_at_utc: datetime
    wait_started_monotonic: float = Field(ge=0.0)
    window_open_monotonic: float = Field(ge=0.0)
    checked_monotonic: float = Field(ge=0.0)
    monotonic_elapsed_seconds: float = Field(ge=-86400.0, le=86400.0)
    wall_elapsed_seconds: float = Field(ge=-86400.0, le=86400.0)
    clock_divergence_seconds: float = Field(ge=0.0, le=86400.0)
    window_not_before_utc: datetime
    window_expires_at_utc: datetime
    usable_margin_seconds: int
    source_age_seconds: int
    source_fresh: bool
    mission_current: bool
    workspace_current: bool
    bundle_current: bool
    handoff_current: bool
    selection_current: bool
    clock_path_valid: bool
    official_reads_delta: Literal[0] = 0
    preparation_cycles_delta: Literal[0] = 0
    selector_invocations_delta: Literal[0] = 0
    target_set_freezes_delta: Literal[0] = 0
    provider_effects: Literal[0] = 0
    status: Literal["READY_NOW", "EXPIRED", "CLOCK_INVALID", "STALE", "HARD_STOP"]
    canonical_receipt_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")

    def identity_material(self) -> dict[str, JsonValue]:
        return cast(
            dict[str, JsonValue],
            self.model_dump(mode="json", exclude={"canonical_receipt_sha256"}),
        )

    @classmethod
    def issue(cls, **data: Any) -> Self:
        normalized = _normalized_utc_data(
            data,
            "wait_started_at_utc",
            "checked_at_utc",
            "source_observed_at_utc",
            "mission_expires_at_utc",
            "selected_usable_expires_at_utc",
            "window_not_before_utc",
            "window_expires_at_utc",
        )
        provisional = cls.model_construct(canonical_receipt_sha256="0" * 64, **normalized)
        return cls(
            canonical_receipt_sha256=canonical_sha256(provisional.identity_material()),
            **normalized,
        )

    @model_validator(mode="after")
    def validate_revalidation(self) -> Self:
        started = ensure_utc(
            self.wait_started_at_utc,
            field="first_c0_window_wait_started_at",
        )
        checked = ensure_utc(
            self.checked_at_utc,
            field="first_c0_window_checked_at",
        )
        window_open = ensure_utc(
            self.window_not_before_utc,
            field="first_c0_window_not_before",
        )
        window_expires = ensure_utc(
            self.window_expires_at_utc,
            field="first_c0_window_expires",
        )
        observed = ensure_utc(
            self.source_observed_at_utc,
            field="first_c0_window_source_observed_at",
        )
        mission_expires = ensure_utc(
            self.mission_expires_at_utc,
            field="first_c0_window_mission_expires_at",
        )
        usable_expires = ensure_utc(
            self.selected_usable_expires_at_utc,
            field="first_c0_window_usable_expires_at",
        )
        expected_wall = (checked - started).total_seconds()
        expected_margin = int((usable_expires - checked).total_seconds())
        expected_source_age = int((checked - observed).total_seconds())
        expected_source_fresh = timedelta(0) <= checked - observed <= MAX_CAMPAIGN_SOURCE_AGE
        clock_invalid = (
            not self.clock_path_valid
            or self.monotonic_elapsed_seconds < 0
            or self.wall_elapsed_seconds < 0
            or self.clock_divergence_seconds > 2.0
        )
        expected_mission_current = checked < mission_expires
        expired = checked >= window_expires or not self.mission_current
        stale = not self.source_fresh
        hard_stop = (
            not self.workspace_current
            or not self.bundle_current
            or not self.handoff_current
            or not self.selection_current
            or checked < window_open
            or checked - window_open > timedelta(seconds=FIRST_C0_MAXIMUM_OPEN_TO_PREFLIGHT_SECONDS)
            or self.usable_margin_seconds < FIRST_C0_CANARY_MINIMUM_READY_MARGIN_SECONDS
        )
        expected_status = (
            "CLOCK_INVALID"
            if clock_invalid
            else "EXPIRED"
            if expired
            else "STALE"
            if stale
            else "HARD_STOP"
            if hard_stop
            else "READY_NOW"
        )
        if (
            window_expires - window_open != timedelta(seconds=FIRST_C0_H2_WINDOW_DURATION_SECONDS)
            or usable_expires > window_expires
            or abs(self.wall_elapsed_seconds - expected_wall) > 0.001
            or abs(
                self.monotonic_elapsed_seconds
                - (self.checked_monotonic - self.wait_started_monotonic)
            )
            > 0.001
            or abs(
                self.window_open_monotonic
                - (self.wait_started_monotonic + (window_open - started).total_seconds())
            )
            > 0.001
            or abs(
                self.clock_divergence_seconds
                - abs(self.wall_elapsed_seconds - self.monotonic_elapsed_seconds)
            )
            > 0.001
            or self.usable_margin_seconds != expected_margin
            or self.source_age_seconds != expected_source_age
            or self.source_fresh != expected_source_fresh
            or self.mission_current != expected_mission_current
            or self.status != expected_status
            or self.canonical_receipt_sha256 != canonical_sha256(self.identity_material())
        ):
            raise ValueError("FIRST_C0_WINDOW_REVALIDATION_INVALID")
        if self.status == "READY_NOW" and (
            not window_open <= checked < window_expires
            or checked - window_open > timedelta(seconds=FIRST_C0_MAXIMUM_OPEN_TO_PREFLIGHT_SECONDS)
            or self.usable_margin_seconds < FIRST_C0_CANARY_MINIMUM_READY_MARGIN_SECONDS
            or not all(
                (
                    self.source_fresh,
                    self.mission_current,
                    self.workspace_current,
                    self.bundle_current,
                    self.handoff_current,
                    self.selection_current,
                )
            )
            or self.clock_divergence_seconds > 2.0
            or self.official_reads_delta != 0
            or self.preparation_cycles_delta != 0
            or self.selector_invocations_delta != 0
            or self.target_set_freezes_delta != 0
            or self.provider_effects != 0
        ):
            raise ValueError("FIRST_C0_WINDOW_READY_INVARIANT_INVALID")
        return self


CampaignSelectionAuthorityV1: TypeAlias = CampaignWindowSelectionV1 | FirstC0CanarySelectionV1


def load_campaign_selection_authority_v1(payload: object) -> CampaignSelectionAuthorityV1:
    """Load only the two explicitly admitted selection schemas."""

    if not isinstance(payload, dict):
        raise CaptureContractError("CAMPAIGN_SELECTION_AUTHORITY_PAYLOAD_INVALID")
    schema_version = payload.get("schema_version")
    if schema_version == "robin-campaign-window-selection-v1":
        try:
            return CampaignWindowSelectionV1.model_validate(payload)
        except (TypeError, ValueError):
            raise CaptureContractError("CAMPAIGN_WINDOW_SELECTION_AUTHORITY_INVALID") from None
    if schema_version == "robin-first-c0-canary-selection-v1":
        try:
            return FirstC0CanarySelectionV1.model_validate(payload)
        except (TypeError, ValueError):
            raise CaptureContractError("FIRST_C0_CANARY_SELECTION_AUTHORITY_INVALID") from None
    raise CaptureContractError("CAMPAIGN_SELECTION_AUTHORITY_SCHEMA_UNSUPPORTED")


class OwnerAuthorizationV2(FrozenContract):
    schema_version: Literal["robin-owner-authorization-v2"] = "robin-owner-authorization-v2"
    authorization_id: str = Field(min_length=1, max_length=120)
    authorization_status: Literal["OWNER_REVIEW_CANDIDATE", "OWNER_AUTHORIZED"] = (
        "OWNER_REVIEW_CANDIDATE"
    )
    review_candidate_sha256: Sha256 | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    mission_id: MissionIdV1 = BOOTSTRAP_MISSION_ID
    capability_version: Literal["robin-real-execution-bootstrap-closure-v1"] = (
        BOOTSTRAP_CAPABILITY_VERSION
    )
    repository_identity: Literal["dddur75/robin-stades-ng"] = "dddur75/robin-stades-ng"
    owner_identity: Literal["dddur75"] = "dddur75"
    provenance: Literal["EXTERNAL_IMMUTABLE_OWNER_ARTIFACT"] = "EXTERNAL_IMMUTABLE_OWNER_ARTIFACT"
    authenticity_boundary: Literal["EXTERNALLY_VERIFIED_NOT_CRYPTOGRAPHICALLY_PROVEN"] = (
        "EXTERNALLY_VERIFIED_NOT_CRYPTOGRAPHICALLY_PROVEN"
    )
    authorized_main_sha: Sha256 = Field(pattern=r"^[0-9a-f]{40}$")
    mission_manifest_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    mission_expires_at_utc: datetime
    workspace_receipt_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    issued_at_utc: datetime
    not_before_utc: datetime
    expires_at_utc: datetime
    allowed_sport_keys: tuple[str, ...]
    allowed_region: Literal["eu"] = "eu"
    allowed_market_sets: tuple[MarketSet, ...]
    maximum_http_calls: int = Field(gt=0)
    maximum_credits: int = Field(gt=0)
    maximum_plan_items: int = Field(gt=0)
    approved_capture_root_fingerprint: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    approved_repository_root_fingerprint: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    approved_control_temp_root_fingerprint: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    approved_git_executable_path: str = Field(min_length=1, max_length=1024)
    approved_git_executable_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    provider_network_binding_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    approved_provider_ip_address: str
    campaign_selection_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    fixture_target_set_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    local_execution_boundary: Literal["OWNER_ATTESTED_EXCLUSIVE_OS_ACL_NO_CONCURRENT_MUTATOR"] = (
        "OWNER_ATTESTED_EXCLUSIVE_OS_ACL_NO_CONCURRENT_MUTATOR"
    )
    authorization_nonce: str = Field(min_length=16, max_length=160)
    canonical_authorization_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")

    def identity_material(self) -> dict[str, JsonValue]:
        return cast(
            dict[str, JsonValue],
            self.model_dump(mode="json", exclude={"canonical_authorization_hash"}),
        )

    def expected_promoted_authorization_hash(self) -> str:
        """Project the exact owner-authorized hash without issuing authority."""

        if (
            self.authorization_status != "OWNER_REVIEW_CANDIDATE"
            or self.review_candidate_sha256 is not None
        ):
            raise ValueError("OWNER_AUTHORIZATION_PROMOTION_PROJECTION_REQUIRES_CANDIDATE")
        promoted_material = cast(
            dict[str, JsonValue],
            {
                **self.identity_material(),
                "authorization_status": "OWNER_AUTHORIZED",
                "review_candidate_sha256": self.canonical_authorization_hash,
            },
        )
        return canonical_sha256(promoted_material)

    @classmethod
    def issue(cls, **data: Any) -> Self:
        normalized = _normalized_utc_data(
            data,
            "mission_expires_at_utc",
            "issued_at_utc",
            "not_before_utc",
            "expires_at_utc",
        )
        if "approved_git_executable_path" in normalized:
            normalized["approved_git_executable_path"] = os.path.normcase(
                os.path.abspath(cast(str, normalized["approved_git_executable_path"]))
            )
        provisional = cls.model_construct(canonical_authorization_hash="0" * 64, **normalized)
        return cls(
            canonical_authorization_hash=canonical_sha256(provisional.identity_material()),
            **normalized,
        )

    @model_validator(mode="after")
    def validate_authorization(self) -> Self:
        issued = ensure_utc(self.issued_at_utc, field="authorization_issued_at")
        starts = ensure_utc(self.not_before_utc, field="authorization_not_before")
        expires = ensure_utc(self.expires_at_utc, field="authorization_expires_at")
        mission_expires = ensure_utc(
            self.mission_expires_at_utc,
            field="authorization_mission_expires_at",
        )
        if (
            issued > starts
            or starts >= expires
            or expires - starts > MAX_ACTIVATION_TTL
            or expires > mission_expires
        ):
            raise ValueError("OWNER_AUTHORIZATION_INTERVAL_INVALID")
        if not self.allowed_sport_keys or not _ordered_sport_subset(self.allowed_sport_keys):
            raise ValueError("OWNER_AUTHORIZATION_SPORTS_INVALID")
        expected_sets = tuple(
            cast(MarketSet, market_set)
            for market_set in LIVE_ALLOWED_MARKET_SETS
            if market_set in self.allowed_market_sets
        )
        if not self.allowed_market_sets or self.allowed_market_sets != expected_sets:
            raise ValueError("OWNER_AUTHORIZATION_MARKET_SETS_INVALID")
        if any(not _canonical_market_set(market_set) for market_set in self.allowed_market_sets):
            raise ValueError("OWNER_AUTHORIZATION_MARKET_SETS_INVALID")
        if self.maximum_plan_items > self.maximum_http_calls:
            raise ValueError("OWNER_AUTHORIZATION_PLAN_ITEMS_EXCEED_CALLS")
        if self.authorization_status == "OWNER_REVIEW_CANDIDATE":
            if self.review_candidate_sha256 is not None:
                raise ValueError("OWNER_AUTHORIZATION_CANDIDATE_PARENT_FORBIDDEN")
        else:
            candidate_material = cast(
                dict[str, JsonValue],
                {
                    **self.identity_material(),
                    "authorization_status": "OWNER_REVIEW_CANDIDATE",
                    "review_candidate_sha256": None,
                },
            )
            if self.review_candidate_sha256 != canonical_sha256(candidate_material):
                raise ValueError("OWNER_AUTHORIZATION_REVIEW_CANDIDATE_MISMATCH")
        validate_global_unicast_ip(self.approved_provider_ip_address)
        canonical_git = os.path.normcase(os.path.abspath(self.approved_git_executable_path))
        if canonical_git != self.approved_git_executable_path:
            raise ValueError("OWNER_AUTHORIZATION_GIT_PATH_NOT_CANONICAL")
        if self.canonical_authorization_hash != canonical_sha256(self.identity_material()):
            raise ValueError("OWNER_AUTHORIZATION_HASH_MISMATCH")
        return self


class ActivationEnvelopeV2(FrozenContract):
    schema_version: Literal["robin-live-activation-envelope-v2"] = (
        "robin-live-activation-envelope-v2"
    )
    activation_id: str = Field(min_length=1, max_length=120)
    mission_id: MissionIdV1
    mission_manifest_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    mission_expires_at_utc: datetime
    authorization_id: str = Field(min_length=1, max_length=120)
    authorization_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    repository_sha: Sha256 = Field(pattern=r"^[0-9a-f]{40}$")
    provider_network_binding_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    fixture_target_set_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    sport_key: str = Field(min_length=1, max_length=120)
    region: Literal["eu"] = "eu"
    markets: MarketSet
    not_before_utc: datetime
    expires_at_utc: datetime
    maximum_http_calls: int = Field(gt=0)
    maximum_credits: int = Field(gt=0)
    plan_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    activation_nonce: str = Field(min_length=16, max_length=160)
    activation_scope_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    canonical_activation_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")

    def scope_material(self) -> dict[str, JsonValue]:
        return cast(
            dict[str, JsonValue],
            self.model_dump(
                mode="json",
                exclude={"plan_sha256", "activation_scope_sha256", "canonical_activation_hash"},
            ),
        )

    def identity_material(self) -> dict[str, JsonValue]:
        return cast(
            dict[str, JsonValue],
            self.model_dump(mode="json", exclude={"canonical_activation_hash"}),
        )

    @classmethod
    def issue(cls, **data: Any) -> Self:
        normalized = _normalized_utc_data(
            data,
            "mission_expires_at_utc",
            "not_before_utc",
            "expires_at_utc",
        )
        provisional = cls.model_construct(
            activation_scope_sha256="0" * 64,
            canonical_activation_hash="0" * 64,
            **normalized,
        )
        scope_hash = canonical_sha256(provisional.scope_material())
        scoped = cls.model_construct(
            activation_scope_sha256=scope_hash,
            canonical_activation_hash="0" * 64,
            **normalized,
        )
        return cls(
            activation_scope_sha256=scope_hash,
            canonical_activation_hash=canonical_sha256(scoped.identity_material()),
            **normalized,
        )

    @model_validator(mode="after")
    def validate_activation(self) -> Self:
        starts = ensure_utc(self.not_before_utc, field="activation_not_before")
        expires = ensure_utc(self.expires_at_utc, field="activation_expires_at")
        mission_expires = ensure_utc(
            self.mission_expires_at_utc,
            field="activation_mission_expires_at",
        )
        if starts >= expires or expires - starts > MAX_ACTIVATION_TTL or expires > mission_expires:
            raise ValueError("LIVE_ACTIVATION_INTERVAL_INVALID")
        if self.sport_key not in LIVE_ALLOWED_SPORT_KEYS or not _canonical_market_set(self.markets):
            raise ValueError("LIVE_ACTIVATION_SCOPE_INVALID")
        if self.activation_scope_sha256 != canonical_sha256(self.scope_material()):
            raise ValueError("LIVE_ACTIVATION_SCOPE_HASH_MISMATCH")
        if self.canonical_activation_hash != canonical_sha256(self.identity_material()):
            raise ValueError("LIVE_ACTIVATION_HASH_MISMATCH")
        return self


class LivePlanItemV2(FrozenContract):
    schema_version: Literal["robin-live-plan-item-v2"] = "robin-live-plan-item-v2"
    item_id: str = Field(min_length=1, max_length=120)
    mission_id: MissionIdV1
    mission_manifest_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    mission_expires_at_utc: datetime
    plan_id: str = Field(min_length=1, max_length=120)
    sequence: int = Field(gt=0)
    sport_key: str = Field(min_length=1, max_length=120)
    region: Literal["eu"] = "eu"
    markets: MarketSet
    provider_request_fingerprint: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    fixture_target_set_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    provider_network_binding_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    not_before_utc: datetime
    expires_at_utc: datetime
    maximum_http_calls: Literal[1] = 1
    maximum_credits: int = Field(gt=0)
    purpose: str = Field(min_length=1, max_length=200)
    window_label: str = Field(min_length=1, max_length=120)
    canonical_item_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")

    def identity_material(self) -> dict[str, JsonValue]:
        return cast(
            dict[str, JsonValue],
            self.model_dump(mode="json", exclude={"canonical_item_hash"}),
        )

    @classmethod
    def issue(cls, **data: Any) -> Self:
        normalized = _normalized_utc_data(
            data,
            "mission_expires_at_utc",
            "not_before_utc",
            "expires_at_utc",
        )
        provisional = cls.model_construct(canonical_item_hash="0" * 64, **normalized)
        return cls(
            canonical_item_hash=canonical_sha256(provisional.identity_material()),
            **normalized,
        )

    @model_validator(mode="after")
    def validate_item(self) -> Self:
        starts = ensure_utc(self.not_before_utc, field="item_not_before")
        expires = ensure_utc(self.expires_at_utc, field="item_expires_at")
        mission_expires = ensure_utc(
            self.mission_expires_at_utc,
            field="item_mission_expires_at",
        )
        if starts >= expires or expires > mission_expires:
            raise ValueError("LIVE_PLAN_ITEM_INTERVAL_INVALID")
        if self.sport_key not in LIVE_ALLOWED_SPORT_KEYS or not _canonical_market_set(self.markets):
            raise ValueError("LIVE_PLAN_ITEM_SCOPE_INVALID")
        if self.maximum_credits != len(self.markets):
            raise ValueError("LIVE_PLAN_ITEM_CREDIT_LIMIT_INVALID")
        if self.canonical_item_hash != canonical_sha256(self.identity_material()):
            raise ValueError("LIVE_PLAN_ITEM_HASH_MISMATCH")
        return self


class LivePlanV2(FrozenContract):
    schema_version: Literal["robin-live-plan-v2"] = "robin-live-plan-v2"
    plan_id: str = Field(min_length=1, max_length=120)
    mission_id: MissionIdV1
    mission_manifest_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    mission_expires_at_utc: datetime
    activation_id: str = Field(min_length=1, max_length=120)
    activation_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    repository_sha: Sha256 = Field(pattern=r"^[0-9a-f]{40}$")
    provider_network_binding_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    fixture_target_set_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    created_at_utc: datetime
    expires_at_utc: datetime
    items: tuple[LivePlanItemV2, ...]
    maximum_http_calls: int = Field(gt=0)
    maximum_credits: int = Field(gt=0)
    canonical_plan_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")

    def identity_material(self) -> dict[str, JsonValue]:
        return cast(
            dict[str, JsonValue],
            self.model_dump(mode="json", exclude={"canonical_plan_hash"}),
        )

    @classmethod
    def issue(cls, **data: Any) -> Self:
        normalized = _normalized_utc_data(
            data,
            "mission_expires_at_utc",
            "created_at_utc",
            "expires_at_utc",
        )
        provisional = cls.model_construct(canonical_plan_hash="0" * 64, **normalized)
        return cls(
            canonical_plan_hash=canonical_sha256(provisional.identity_material()),
            **normalized,
        )

    @model_validator(mode="after")
    def validate_plan(self) -> Self:
        created = ensure_utc(self.created_at_utc, field="plan_created_at")
        expires = ensure_utc(self.expires_at_utc, field="plan_expires_at")
        mission_expires = ensure_utc(
            self.mission_expires_at_utc,
            field="plan_mission_expires_at",
        )
        if created >= expires or expires > mission_expires or not self.items:
            raise ValueError("LIVE_PLAN_INTERVAL_OR_ITEMS_INVALID")
        if len(self.items) > self.maximum_http_calls:
            raise ValueError("LIVE_PLAN_CALL_LIMIT_EXCEEDED")
        if sum(item.maximum_credits for item in self.items) > self.maximum_credits:
            raise ValueError("LIVE_PLAN_CREDIT_LIMIT_EXCEEDED")
        if tuple(item.sequence for item in self.items) != tuple(range(1, len(self.items) + 1)):
            raise ValueError("LIVE_PLAN_SEQUENCE_INVALID")
        if len({item.item_id for item in self.items}) != len(self.items):
            raise ValueError("LIVE_PLAN_ITEM_ID_DUPLICATED")
        if any(
            item.plan_id != self.plan_id
            or item.mission_id != self.mission_id
            or item.mission_manifest_sha256 != self.mission_manifest_sha256
            or item.mission_expires_at_utc != self.mission_expires_at_utc
            or item.fixture_target_set_sha256 != self.fixture_target_set_sha256
            or item.provider_network_binding_sha256 != self.provider_network_binding_sha256
            or item.not_before_utc < created
            or item.expires_at_utc > expires
            for item in self.items
        ):
            raise ValueError("LIVE_PLAN_ITEM_BINDING_MISMATCH")
        if self.canonical_plan_hash != canonical_sha256(self.identity_material()):
            raise ValueError("LIVE_PLAN_HASH_MISMATCH")
        return self


class LiveCaptureLineageV2(FrozenContract):
    schema_version: Literal["robin-live-capture-lineage-v2"] = "robin-live-capture-lineage-v2"
    manifest_id: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    manifest_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    request: ProviderRequestSpec
    request_fingerprint_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    expected_sport_key: str
    expected_region: Literal["eu"] = "eu"
    expected_markets: MarketSet
    fixture_target_set_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    provider_network_binding_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    post_capture_mapping_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    scientific_admission: Literal["FULL", "PARTIAL", "NONE"]
    mapped_target_count: int = Field(ge=0)
    non_admitted_target_count: int = Field(ge=0)
    mapped_provider_event_count: int = Field(ge=0)
    non_admitted_provider_event_count: int = Field(ge=0)
    admission_permit: LiveAdmissionPermitV1
    response_intake_claim: LiveResponseIntakeClaimV1
    canonical_lineage_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")

    def identity_material(self) -> dict[str, JsonValue]:
        return cast(
            dict[str, JsonValue],
            self.model_dump(mode="json", exclude={"canonical_lineage_sha256"}),
        )

    @classmethod
    def issue(cls, **data: Any) -> Self:
        provisional = cls.model_construct(canonical_lineage_sha256="0" * 64, **data)
        return cls(
            canonical_lineage_sha256=canonical_sha256(provisional.identity_material()),
            **data,
        )

    @model_validator(mode="after")
    def validate_lineage(self) -> Self:
        if (
            self.expected_sport_key not in LIVE_ALLOWED_SPORT_KEYS
            or not _canonical_market_set(self.expected_markets)
            or self.request.sport_key != self.expected_sport_key
            or self.request.region != self.expected_region
            or self.request.markets != self.expected_markets
            or self.request.endpoint != f"/v4/sports/{self.expected_sport_key}/odds"
            or canonical_sha256(self.request.fingerprint_material())
            != self.request_fingerprint_sha256
            or self.admission_permit.request_fingerprint_sha256 != self.request_fingerprint_sha256
            or self.response_intake_claim.canonical_permit_sha256
            != self.admission_permit.canonical_permit_sha256
            or self.response_intake_claim.item_hash != self.admission_permit.item_hash
        ):
            raise ValueError("LIVE_CAPTURE_LINEAGE_SCOPE_MISMATCH")
        total = self.mapped_target_count + self.non_admitted_target_count
        expected_admission = (
            "NONE"
            if self.mapped_target_count == 0
            else "FULL"
            if self.non_admitted_target_count == 0
            else "PARTIAL"
        )
        if total <= 0 or self.scientific_admission != expected_admission:
            raise ValueError("LIVE_CAPTURE_SCIENTIFIC_ADMISSION_INVALID")
        if self.canonical_lineage_sha256 != canonical_sha256(self.identity_material()):
            raise ValueError("LIVE_CAPTURE_LINEAGE_HASH_MISMATCH")
        return self


class RealCaptureWorkspaceReceiptV1(FrozenContract):
    schema_version: Literal["robin-real-capture-workspace-receipt-v1"] = (
        "robin-real-capture-workspace-receipt-v1"
    )
    repository_identity: Literal["dddur75/robin-stades-ng"] = "dddur75/robin-stades-ng"
    authorized_main_sha: Sha256 = Field(pattern=r"^[0-9a-f]{40}$")
    bootstrap_mode: Literal["CREATE", "VERIFY", "INSPECT"]
    bootstrap_tool_source_repository_root: str = Field(min_length=1, max_length=1024)
    bootstrap_tool_loaded_from_runtime_repository: bool
    bootstrap_package_source_repository_root: str = Field(min_length=1, max_length=1024)
    bootstrap_package_loaded_from_runtime_repository: bool
    authority_eligible_for_real_execution: bool
    prepared_at_utc: datetime
    runtime_repository_root: str = Field(min_length=1, max_length=1024)
    repository_root_fingerprint: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    repository_security_descriptor_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    control_temp_root: str = Field(min_length=1, max_length=1024)
    control_temp_fingerprint: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    control_temp_security_descriptor_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    capture_root: str = Field(min_length=1, max_length=1024)
    capture_root_fingerprint: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    capture_security_descriptor_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    git_executable_path: str = Field(min_length=1, max_length=1024)
    git_executable_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    exact_detached_checkout: Literal[True]
    worktree_pristine: Literal[True]
    index_pristine: Literal[True]
    expected_remote_verified: Literal[True]
    submodules_absent: Literal[True]
    alternates_absent: Literal[True]
    unsafe_config_includes_absent: Literal[True]
    synchronized_roots_absent: Literal[True]
    cloud_placeholders_absent: Literal[True]
    reparse_escapes_absent: Literal[True]
    roots_non_overlapping: Literal[True]
    local_fixed_filesystem_verified: Literal[True]
    acl_exclusivity_verified: Literal[True]
    provider_http_requests: Literal[0] = 0
    provider_tcp_connections: Literal[0] = 0
    provider_secret_reads: Literal[0] = 0
    canonical_receipt_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")

    def identity_material(self) -> dict[str, JsonValue]:
        return cast(
            dict[str, JsonValue],
            self.model_dump(mode="json", exclude={"canonical_receipt_hash"}),
        )

    @classmethod
    def issue(cls, **data: Any) -> Self:
        normalized = _normalized_utc_data(data, "prepared_at_utc")
        for field in (
            "runtime_repository_root",
            "bootstrap_tool_source_repository_root",
            "bootstrap_package_source_repository_root",
            "control_temp_root",
            "capture_root",
            "git_executable_path",
        ):
            if field in normalized:
                normalized[field] = os.path.normcase(os.path.abspath(cast(str, normalized[field])))
        provisional = cls.model_construct(canonical_receipt_hash="0" * 64, **normalized)
        return cls(
            canonical_receipt_hash=canonical_sha256(provisional.identity_material()),
            **normalized,
        )

    @model_validator(mode="after")
    def validate_receipt(self) -> Self:
        ensure_utc(self.prepared_at_utc, field="workspace_prepared_at")
        paths = (
            self.runtime_repository_root,
            self.bootstrap_tool_source_repository_root,
            self.bootstrap_package_source_repository_root,
            self.control_temp_root,
            self.capture_root,
            self.git_executable_path,
        )
        if any(os.path.abspath(path) != path for path in paths):
            raise ValueError("REAL_WORKSPACE_PATH_NOT_ABSOLUTE")
        expected_tool_loaded = os.path.normcase(
            self.bootstrap_tool_source_repository_root
        ) == os.path.normcase(self.runtime_repository_root)
        expected_package_loaded = os.path.normcase(
            self.bootstrap_package_source_repository_root
        ) == os.path.normcase(self.runtime_repository_root)
        expected_authority = (
            self.bootstrap_mode == "VERIFY" and expected_tool_loaded and expected_package_loaded
        )
        if (
            self.bootstrap_tool_loaded_from_runtime_repository != expected_tool_loaded
            or self.bootstrap_package_loaded_from_runtime_repository != expected_package_loaded
            or self.authority_eligible_for_real_execution != expected_authority
        ):
            raise ValueError("REAL_WORKSPACE_BOOTSTRAP_SOURCE_INVALID")
        if self.canonical_receipt_hash != canonical_sha256(self.identity_material()):
            raise ValueError("REAL_WORKSPACE_RECEIPT_HASH_MISMATCH")
        return self


class OwnerReviewPackV1(FrozenContract):
    """Unexecuted, externally reviewable successor authority bundle."""

    schema_version: Literal["robin-owner-review-pack-v1"] = "robin-owner-review-pack-v1"
    generated_at_utc: datetime
    mission_manifest: RealExecutionMissionManifestV1
    mission_manifest_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    workspace_receipt: RealCaptureWorkspaceReceiptV1
    workspace_receipt_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    campaign_selection: Annotated[
        CampaignSelectionAuthorityV1,
        Field(discriminator="schema_version"),
    ]
    campaign_selection_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    selected_campaign_candidate_id: str = Field(min_length=1, max_length=160)
    selected_campaign_candidate_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    selected_campaign_window_id: Literal["H24", "H2", "H1"]
    selected_campaign_temporal_role: str = Field(min_length=1, max_length=120)
    selected_campaign_predictor_protocol_ids: tuple[str, ...]
    selected_campaign_target_protocol_ids: tuple[str, ...]
    selected_fixture_target_ids: tuple[str, ...]
    selected_fixture_target_hashes: tuple[Sha256, ...]
    earliest_target_kickoff_utc: datetime
    pre_kickoff_safety_margin_seconds: Literal[300] = 300
    target_window_not_before_utc: datetime
    target_window_expires_at_utc: datetime
    request: ProviderRequestSpec
    request_fingerprint_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    fixture_target_set: FixtureTargetSetV1
    provider_network_binding: ProviderNetworkBindingV1
    owner_authorization_candidate: OwnerAuthorizationV2
    expected_owner_authorization_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    activation_candidate: ActivationEnvelopeV2
    plan_candidate: LivePlanV2
    plan_item_candidate: LivePlanItemV2
    owner_authorization_ready: Literal[True] = True
    provider_dns_resolutions_used: Literal[1] = 1
    provider_http_calls: Literal[0] = 0
    real_secret_reads: Literal[0] = 0
    real_capture_calls: Literal[0] = 0
    real_batch_status: Literal["NOT_EXECUTED"] = "NOT_EXECUTED"
    real_snapshot_status: Literal["NOT_CREATED"] = "NOT_CREATED"
    purchases: Literal[0] = 0
    promotions: Literal[0] = 0
    bets: Literal[0] = 0
    canonical_pack_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")

    def identity_material(self) -> dict[str, JsonValue]:
        return cast(
            dict[str, JsonValue],
            self.model_dump(mode="json", exclude={"canonical_pack_hash"}),
        )

    @classmethod
    def issue(cls, **data: Any) -> Self:
        normalized = _normalized_utc_data(
            data,
            "generated_at_utc",
            "earliest_target_kickoff_utc",
            "target_window_not_before_utc",
            "target_window_expires_at_utc",
        )
        provisional = cls.model_construct(canonical_pack_hash="0" * 64, **normalized)
        return cls(
            canonical_pack_hash=canonical_sha256(provisional.identity_material()),
            **normalized,
        )

    @model_validator(mode="after")
    def validate_pack(self) -> Self:
        generated = ensure_utc(self.generated_at_utc, field="owner_pack_generated_at")
        earliest_kickoff = ensure_utc(
            self.earliest_target_kickoff_utc,
            field="owner_pack_earliest_target_kickoff",
        )
        starts = ensure_utc(
            self.target_window_not_before_utc,
            field="owner_pack_window_not_before",
        )
        expires = ensure_utc(
            self.target_window_expires_at_utc,
            field="owner_pack_window_expires_at",
        )
        authorization = self.owner_authorization_candidate
        activation = self.activation_candidate
        plan = self.plan_candidate
        item = self.plan_item_candidate
        selected_campaign = self.campaign_selection.selected_candidate()
        fingerprint = canonical_sha256(self.request.fingerprint_material())
        target_ids = tuple(
            target.internal_fixture_target_id for target in self.fixture_target_set.targets
        )
        target_hashes = tuple(
            target.canonical_target_hash for target in self.fixture_target_set.targets
        )
        request_key = fingerprint[:20]
        expected_authorization_id = f"owner-review-{request_key}"
        expected_activation_id = f"activation-review-{request_key}"
        expected_plan_id = f"plan-review-{request_key}"
        expected_item_id = f"item-review-{request_key}"
        expected_window_label = (
            f"campaign:{selected_campaign.window_id}:"
            f"{selected_campaign.canonical_candidate_hash[:32]}"
        )
        expected_expires = min(
            self.provider_network_binding.expires_at_utc,
            self.mission_manifest.expires_at,
            selected_campaign.usable_expires_at_utc,
            earliest_kickoff - PRE_KICKOFF_SAFETY_MARGIN,
        )
        if (
            generated != starts
            or not starts < expires
            or expires - starts < MIN_OWNER_REVIEW_WINDOW
            or expires != expected_expires
            or earliest_kickoff
            != min(target.official_kickoff_utc for target in self.fixture_target_set.targets)
            or earliest_kickoff - expires < PRE_KICKOFF_SAFETY_MARGIN
            or self.selected_fixture_target_ids != target_ids
            or self.selected_fixture_target_hashes != target_hashes
            or not target_ids
            or len(target_ids) != len(set(target_ids))
            or self.mission_manifest_sha256 != self.mission_manifest.canonical_manifest_sha256()
            or self.workspace_receipt_sha256 != self.workspace_receipt.canonical_receipt_hash
            or not self.workspace_receipt.authority_eligible_for_real_execution
            or self.campaign_selection_sha256 != self.campaign_selection.canonical_selection_hash
            or self.campaign_selection.workspace_receipt_sha256 != self.workspace_receipt_sha256
            or self.campaign_selection.workspace_prepared_at_utc
            != self.workspace_receipt.prepared_at_utc
            or self.campaign_selection.mission_manifest_sha256 != self.mission_manifest_sha256
            or (
                isinstance(self.campaign_selection, FirstC0CanarySelectionV1)
                and self.campaign_selection.mission_id != self.mission_manifest.mission_id
            )
            or self.campaign_selection.mission_expires_at_utc != self.mission_manifest.expires_at
            or self.selected_campaign_candidate_id != selected_campaign.candidate_id
            or self.selected_campaign_candidate_sha256 != selected_campaign.canonical_candidate_hash
            or self.selected_campaign_window_id != selected_campaign.window_id
            or self.selected_campaign_temporal_role != selected_campaign.temporal_role
            or self.selected_campaign_predictor_protocol_ids
            != selected_campaign.predictor_protocol_ids
            or self.selected_campaign_target_protocol_ids != selected_campaign.target_protocol_ids
            or self.fixture_target_set != selected_campaign.fixture_target_set
            or self.request != selected_campaign.request
            or self.request_fingerprint_sha256 != fingerprint
            or authorization.authorization_status != "OWNER_REVIEW_CANDIDATE"
            or authorization.mission_id != self.mission_manifest.mission_id
            or authorization.review_candidate_sha256 is not None
            or authorization.authorization_id != expected_authorization_id
            or authorization.authorized_main_sha != self.workspace_receipt.authorized_main_sha
            or authorization.issued_at_utc != generated
            or authorization.not_before_utc != starts
            or authorization.expires_at_utc != expires
            or authorization.allowed_sport_keys != (self.request.sport_key,)
            or authorization.allowed_region != self.request.region
            or authorization.allowed_market_sets != (self.request.markets,)
            or authorization.maximum_http_calls != 1
            or authorization.maximum_credits != len(self.request.markets)
            or authorization.maximum_plan_items != 1
            or authorization.approved_capture_root_fingerprint
            != self.workspace_receipt.capture_root_fingerprint
            or authorization.approved_repository_root_fingerprint
            != self.workspace_receipt.repository_root_fingerprint
            or authorization.approved_control_temp_root_fingerprint
            != self.workspace_receipt.control_temp_fingerprint
            or authorization.approved_git_executable_path
            != self.workspace_receipt.git_executable_path
            or authorization.approved_git_executable_sha256
            != self.workspace_receipt.git_executable_sha256
            or authorization.mission_manifest_sha256 != self.mission_manifest_sha256
            or authorization.mission_expires_at_utc != self.mission_manifest.expires_at
            or authorization.workspace_receipt_sha256 != self.workspace_receipt_sha256
            or authorization.provider_network_binding_sha256
            != self.provider_network_binding.canonical_binding_hash
            or authorization.approved_provider_ip_address
            != self.provider_network_binding.selected_ip_address
            or authorization.campaign_selection_sha256 != self.campaign_selection_sha256
            or authorization.fixture_target_set_sha256 != self.fixture_target_set.canonical_set_hash
            or self.expected_owner_authorization_sha256
            != authorization.expected_promoted_authorization_hash()
            or activation.activation_id != expected_activation_id
            or activation.mission_id != self.mission_manifest.mission_id
            or activation.mission_manifest_sha256 != self.mission_manifest_sha256
            or activation.mission_expires_at_utc != self.mission_manifest.expires_at
            or activation.authorization_id != authorization.authorization_id
            or activation.authorization_hash != self.expected_owner_authorization_sha256
            or activation.repository_sha != self.workspace_receipt.authorized_main_sha
            or activation.provider_network_binding_sha256
            != self.provider_network_binding.canonical_binding_hash
            or activation.fixture_target_set_sha256 != self.fixture_target_set.canonical_set_hash
            or activation.sport_key != self.request.sport_key
            or activation.region != self.request.region
            or activation.markets != self.request.markets
            or activation.not_before_utc != starts
            or activation.expires_at_utc != expires
            or activation.maximum_http_calls != 1
            or activation.maximum_credits != len(self.request.markets)
            or plan.canonical_plan_hash != activation.plan_sha256
            or plan.mission_id != self.mission_manifest.mission_id
            or plan.mission_manifest_sha256 != self.mission_manifest_sha256
            or plan.mission_expires_at_utc != self.mission_manifest.expires_at
            or plan.plan_id != expected_plan_id
            or plan.activation_id != activation.activation_id
            or plan.activation_hash != activation.activation_scope_sha256
            or plan.repository_sha != self.workspace_receipt.authorized_main_sha
            or plan.provider_network_binding_sha256
            != self.provider_network_binding.canonical_binding_hash
            or plan.fixture_target_set_sha256 != self.fixture_target_set.canonical_set_hash
            or plan.created_at_utc != generated
            or plan.expires_at_utc != expires
            or plan.maximum_http_calls != 1
            or plan.maximum_credits != len(self.request.markets)
            or plan.items != (item,)
            or item.item_id != expected_item_id
            or item.mission_id != self.mission_manifest.mission_id
            or item.mission_manifest_sha256 != self.mission_manifest_sha256
            or item.mission_expires_at_utc != self.mission_manifest.expires_at
            or item.plan_id != plan.plan_id
            or item.sequence != 1
            or item.sport_key != self.request.sport_key
            or item.region != self.request.region
            or item.markets != self.request.markets
            or item.provider_request_fingerprint != fingerprint
            or item.provider_network_binding_sha256
            != self.provider_network_binding.canonical_binding_hash
            or item.fixture_target_set_sha256 != self.fixture_target_set.canonical_set_hash
            or item.not_before_utc != starts
            or item.expires_at_utc != expires
            or item.maximum_http_calls != 1
            or item.maximum_credits != len(self.request.markets)
            or item.purpose != "first real receipt-backed capture after explicit owner approval"
            or item.window_label != expected_window_label
            or self.fixture_target_set.sport_key != self.request.sport_key
            or self.fixture_target_set.workspace_receipt_sha256 != self.workspace_receipt_sha256
            or self.provider_network_binding.resolution_claim.workspace_receipt_sha256
            != self.workspace_receipt_sha256
            or self.provider_network_binding.resolution_claim.mission_manifest_sha256
            != self.mission_manifest_sha256
            or self.provider_network_binding.resolution_claim.mission_id
            != self.mission_manifest.mission_id
            or self.provider_network_binding.resolution_claim.mission_expires_at_utc
            != self.mission_manifest.expires_at
            or self.provider_network_binding.resolution_claim.campaign_selection_sha256
            != self.campaign_selection_sha256
            or self.provider_network_binding.resolution_claim.fixture_target_set_sha256
            != self.fixture_target_set.canonical_set_hash
            or self.workspace_receipt.prepared_at_utc > self.fixture_target_set.created_at_utc
            or self.fixture_target_set.created_at_utc > self.campaign_selection.selected_at_utc
            or self.fixture_target_set.created_at_utc
            > self.provider_network_binding.resolution_claim.claimed_at_utc
            or self.provider_network_binding.resolution_claim.claimed_at_utc
            > self.provider_network_binding.observed_at_utc
            or self.provider_network_binding.observed_at_utc > generated
            or generated < self.fixture_target_set.created_at_utc
            or generated - self.fixture_target_set.created_at_utc > timedelta(hours=24)
            or any(
                generated < target.source_observed_at_utc
                or generated - target.source_observed_at_utc > timedelta(hours=24)
                for target in self.fixture_target_set.targets
            )
        ):
            raise ValueError("OWNER_REVIEW_PACK_BINDING_INVALID")
        try:
            self.provider_network_binding.assert_current(generated)
            self.campaign_selection.assert_selected_candidate_current(generated)
        except ValueError:
            raise ValueError("OWNER_REVIEW_PACK_AUTHORITY_EXPIRED") from None
        if expires > self.provider_network_binding.expires_at_utc:
            raise ValueError("OWNER_REVIEW_PACK_EXCEEDS_NETWORK_BINDING")
        if self.canonical_pack_hash != canonical_sha256(self.identity_material()):
            raise ValueError("OWNER_REVIEW_PACK_HASH_MISMATCH")
        return self
