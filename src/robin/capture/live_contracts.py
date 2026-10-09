"""Immutable contracts for one-shot, externally authorized live canaries."""

from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any, Literal, Self, cast

from pydantic import Field, model_validator

from robin.capture.contracts import (
    FrozenContract,
    JsonValue,
    ProviderRequestSpec,
    QuotaObservation,
    canonical_sha256,
    ensure_utc,
)

LIVE_CAPABILITY_VERSION = "robin-bounded-multi-league-live-canary-v1"
LIVE_MISSION_ID = "BOUNDED_MULTI_LEAGUE_LIVE_CANARY_CAPABILITY_V1"
LIVE_REPOSITORY_IDENTITY = "dddur75/robin-stades-ng"
LIVE_ALLOWED_SPORT_KEYS = (
    "soccer_spain_la_liga",
    "soccer_france_ligue_one",
    "soccer_epl",
    "soccer_italy_serie_a",
    "soccer_germany_bundesliga",
)
LIVE_ALLOWED_REGION = "eu"
LIVE_ALLOWED_MARKETS = ("h2h", "totals")
LIVE_ALLOWED_MARKET_SETS = (("h2h",), ("totals",), ("h2h", "totals"))
MAX_ACTIVATION_TTL = timedelta(minutes=15)

Sha256 = str
Market = Literal["h2h", "totals"]
MarketSet = tuple[Market, ...]


def _validate_market_set(markets: MarketSet) -> None:
    expected = tuple(market for market in LIVE_ALLOWED_MARKETS if market in markets)
    if not markets or len(set(markets)) != len(markets) or markets != expected:
        raise ValueError("LIVE_MARKET_SET_INVALID")


def _ordered_sport_subset(sports: tuple[str, ...]) -> bool:
    return sports == tuple(sport for sport in LIVE_ALLOWED_SPORT_KEYS if sport in sports)


def validate_provider_ip_address(value: str) -> str:
    try:
        provider_address = ipaddress.ip_address(value)
    except ValueError:
        raise ValueError("LIVE_PROVIDER_IP_INVALID") from None
    if (
        str(provider_address) != value
        or not provider_address.is_global
        or provider_address.is_multicast
        or getattr(provider_address, "ipv4_mapped", None) is not None
        or getattr(provider_address, "scope_id", None) is not None
    ):
        raise ValueError("LIVE_PROVIDER_IP_INVALID")
    return value


class LiveTerminalDisposition(StrEnum):
    SUCCESS = "SUCCESS"
    PRE_DISPATCH_REJECTED = "PRE_DISPATCH_REJECTED"
    HTTP_REJECTED = "HTTP_REJECTED"
    PAYLOAD_REJECTED = "PAYLOAD_REJECTED"
    QUOTA_RECONCILIATION_FAILED = "QUOTA_RECONCILIATION_FAILED"
    DISPATCH_OUTCOME_UNKNOWN = "DISPATCH_OUTCOME_UNKNOWN"
    OFFLINE_REPLAY_FAILED = "OFFLINE_REPLAY_FAILED"


class OwnerAuthorizationV1(FrozenContract):
    schema_version: Literal["robin-owner-authorization-v1"] = "robin-owner-authorization-v1"
    authorization_id: str = Field(min_length=1, max_length=120)
    mission_id: Literal["BOUNDED_MULTI_LEAGUE_LIVE_CANARY_CAPABILITY_V1"] = (
        "BOUNDED_MULTI_LEAGUE_LIVE_CANARY_CAPABILITY_V1"
    )
    capability_version: Literal["robin-bounded-multi-league-live-canary-v1"] = (
        "robin-bounded-multi-league-live-canary-v1"
    )
    repository_identity: Literal["dddur75/robin-stades-ng"] = "dddur75/robin-stades-ng"
    owner_identity: Literal["dddur75"] = "dddur75"
    provenance: Literal["EXTERNAL_IMMUTABLE_OWNER_ARTIFACT"] = "EXTERNAL_IMMUTABLE_OWNER_ARTIFACT"
    authenticity_boundary: Literal["EXTERNALLY_VERIFIED_NOT_CRYPTOGRAPHICALLY_PROVEN"] = (
        "EXTERNALLY_VERIFIED_NOT_CRYPTOGRAPHICALLY_PROVEN"
    )
    authorized_main_sha: Sha256 = Field(pattern=r"^[0-9a-f]{40}$")
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
    approved_git_executable_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    approved_provider_ip_address: str
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

    @classmethod
    def issue(cls, **data: Any) -> Self:
        provisional = cls.model_construct(canonical_authorization_hash="0" * 64, **data)
        return cls(
            canonical_authorization_hash=canonical_sha256(provisional.identity_material()),
            **data,
        )

    @model_validator(mode="after")
    def validate_authorization(self) -> Self:
        issued = ensure_utc(self.issued_at_utc, field="authorization_issued_at")
        starts = ensure_utc(self.not_before_utc, field="authorization_not_before")
        expires = ensure_utc(self.expires_at_utc, field="authorization_expires_at")
        if issued > starts or starts >= expires:
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
        for market_set in self.allowed_market_sets:
            _validate_market_set(market_set)
        if self.maximum_plan_items > self.maximum_http_calls:
            raise ValueError("OWNER_AUTHORIZATION_PLAN_ITEMS_EXCEED_CALLS")
        try:
            validate_provider_ip_address(self.approved_provider_ip_address)
        except ValueError:
            raise ValueError("OWNER_AUTHORIZATION_PROVIDER_IP_INVALID") from None
        if self.canonical_authorization_hash != canonical_sha256(self.identity_material()):
            raise ValueError("OWNER_AUTHORIZATION_HASH_MISMATCH")
        return self


class ActivationEnvelopeV1(FrozenContract):
    schema_version: Literal["robin-live-activation-envelope-v1"] = (
        "robin-live-activation-envelope-v1"
    )
    activation_id: str = Field(min_length=1, max_length=120)
    authorization_id: str = Field(min_length=1, max_length=120)
    authorization_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    repository_sha: Sha256 = Field(pattern=r"^[0-9a-f]{40}$")
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
                exclude={
                    "plan_sha256",
                    "activation_scope_sha256",
                    "canonical_activation_hash",
                },
            ),
        )

    def identity_material(self) -> dict[str, JsonValue]:
        return cast(
            dict[str, JsonValue],
            self.model_dump(mode="json", exclude={"canonical_activation_hash"}),
        )

    @classmethod
    def issue(cls, **data: Any) -> Self:
        provisional = cls.model_construct(
            activation_scope_sha256="0" * 64,
            canonical_activation_hash="0" * 64,
            **data,
        )
        scope_hash = canonical_sha256(provisional.scope_material())
        scoped = cls.model_construct(
            activation_scope_sha256=scope_hash,
            canonical_activation_hash="0" * 64,
            **data,
        )
        return cls(
            activation_scope_sha256=scope_hash,
            canonical_activation_hash=canonical_sha256(scoped.identity_material()),
            **data,
        )

    @model_validator(mode="after")
    def validate_activation(self) -> Self:
        starts = ensure_utc(self.not_before_utc, field="activation_not_before")
        expires = ensure_utc(self.expires_at_utc, field="activation_expires_at")
        if starts >= expires or expires - starts > MAX_ACTIVATION_TTL:
            raise ValueError("LIVE_ACTIVATION_INTERVAL_INVALID")
        if self.sport_key not in LIVE_ALLOWED_SPORT_KEYS:
            raise ValueError("LIVE_ACTIVATION_SPORT_FORBIDDEN")
        _validate_market_set(self.markets)
        if self.activation_scope_sha256 != canonical_sha256(self.scope_material()):
            raise ValueError("LIVE_ACTIVATION_SCOPE_HASH_MISMATCH")
        if self.canonical_activation_hash != canonical_sha256(self.identity_material()):
            raise ValueError("LIVE_ACTIVATION_HASH_MISMATCH")
        return self


class LivePlanItemV1(FrozenContract):
    schema_version: Literal["robin-live-plan-item-v1"] = "robin-live-plan-item-v1"
    item_id: str = Field(min_length=1, max_length=120)
    plan_id: str = Field(min_length=1, max_length=120)
    sequence: int = Field(gt=0)
    sport_key: str = Field(min_length=1, max_length=120)
    region: Literal["eu"] = "eu"
    markets: MarketSet
    provider_request_fingerprint: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    fixture_mappings_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
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
        provisional = cls.model_construct(canonical_item_hash="0" * 64, **data)
        return cls(
            canonical_item_hash=canonical_sha256(provisional.identity_material()),
            **data,
        )

    @model_validator(mode="after")
    def validate_item(self) -> Self:
        starts = ensure_utc(self.not_before_utc, field="item_not_before")
        expires = ensure_utc(self.expires_at_utc, field="item_expires_at")
        if starts >= expires:
            raise ValueError("LIVE_PLAN_ITEM_INTERVAL_INVALID")
        if self.sport_key not in LIVE_ALLOWED_SPORT_KEYS:
            raise ValueError("LIVE_PLAN_ITEM_SPORT_FORBIDDEN")
        _validate_market_set(self.markets)
        if self.maximum_credits != len(self.markets):
            raise ValueError("LIVE_PLAN_ITEM_CREDIT_LIMIT_INVALID")
        if self.canonical_item_hash != canonical_sha256(self.identity_material()):
            raise ValueError("LIVE_PLAN_ITEM_HASH_MISMATCH")
        return self


class LivePlanV1(FrozenContract):
    schema_version: Literal["robin-live-plan-v1"] = "robin-live-plan-v1"
    plan_id: str = Field(min_length=1, max_length=120)
    activation_id: str = Field(min_length=1, max_length=120)
    activation_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    repository_sha: Sha256 = Field(pattern=r"^[0-9a-f]{40}$")
    created_at_utc: datetime
    expires_at_utc: datetime
    items: tuple[LivePlanItemV1, ...]
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
        provisional = cls.model_construct(canonical_plan_hash="0" * 64, **data)
        return cls(
            canonical_plan_hash=canonical_sha256(provisional.identity_material()),
            **data,
        )

    @model_validator(mode="after")
    def validate_plan(self) -> Self:
        created = ensure_utc(self.created_at_utc, field="plan_created_at")
        expires = ensure_utc(self.expires_at_utc, field="plan_expires_at")
        if created >= expires or not self.items:
            raise ValueError("LIVE_PLAN_INTERVAL_OR_ITEMS_INVALID")
        if len(self.items) > self.maximum_http_calls:
            raise ValueError("LIVE_PLAN_CALL_LIMIT_EXCEEDED")
        if sum(item.maximum_credits for item in self.items) > self.maximum_credits:
            raise ValueError("LIVE_PLAN_CREDIT_LIMIT_EXCEEDED")
        if tuple(item.sequence for item in self.items) != tuple(range(1, len(self.items) + 1)):
            raise ValueError("LIVE_PLAN_SEQUENCE_INVALID")
        if len({item.item_id for item in self.items}) != len(self.items):
            raise ValueError("LIVE_PLAN_ITEM_ID_DUPLICATED")
        if any(item.plan_id != self.plan_id for item in self.items):
            raise ValueError("LIVE_PLAN_ITEM_PLAN_MISMATCH")
        if any(
            item.not_before_utc < created or item.expires_at_utc > expires for item in self.items
        ):
            raise ValueError("LIVE_PLAN_ITEM_OUTSIDE_PLAN_INTERVAL")
        if self.canonical_plan_hash != canonical_sha256(self.identity_material()):
            raise ValueError("LIVE_PLAN_HASH_MISMATCH")
        return self


class LiveAdmissionPermitV1(FrozenContract):
    schema_version: Literal["robin-live-admission-permit-v1"] = "robin-live-admission-permit-v1"
    capture_root_fingerprint: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    authorization_id: str
    authorization_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    activation_id: str
    activation_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    repository_sha: Sha256 = Field(pattern=r"^[0-9a-f]{40}$")
    plan_id: str
    plan_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    item_id: str
    item_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    request_fingerprint_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    lease_id: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    authorization_binding_key_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    authorization_binding_payload_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    activation_binding_key_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    activation_binding_payload_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    reserved_credits: int = Field(gt=0)
    dispatch_armed_marker_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    budget_dispatch_entry_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    canonical_permit_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")

    def identity_material(self) -> dict[str, JsonValue]:
        return cast(
            dict[str, JsonValue],
            self.model_dump(mode="json", exclude={"canonical_permit_sha256"}),
        )

    @classmethod
    def issue(cls, **data: Any) -> Self:
        provisional = cls.model_construct(canonical_permit_sha256="0" * 64, **data)
        return cls(
            canonical_permit_sha256=canonical_sha256(provisional.identity_material()),
            **data,
        )

    @model_validator(mode="after")
    def validate_permit(self) -> Self:
        if self.canonical_permit_sha256 != canonical_sha256(self.identity_material()):
            raise ValueError("LIVE_ADMISSION_PERMIT_HASH_MISMATCH")
        return self


class LiveResponseIntakeClaimV1(FrozenContract):
    schema_version: Literal["robin-live-response-intake-claim-v1"] = (
        "robin-live-response-intake-claim-v1"
    )
    canonical_intake_claim_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    canonical_permit_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    dispatch_started_marker_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    item_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    payload_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    payload_byte_length: int = Field(ge=0)
    first_observed_at_utc: datetime
    ingested_at_utc: datetime

    def identity_material(self) -> dict[str, JsonValue]:
        return cast(
            dict[str, JsonValue],
            self.model_dump(mode="json", exclude={"canonical_intake_claim_sha256"}),
        )

    @classmethod
    def issue(cls, **data: Any) -> Self:
        provisional = cls.model_construct(canonical_intake_claim_sha256="0" * 64, **data)
        return cls(
            canonical_intake_claim_sha256=canonical_sha256(provisional.identity_material()),
            **data,
        )

    @model_validator(mode="after")
    def validate_claim(self) -> Self:
        observed = ensure_utc(
            self.first_observed_at_utc,
            field="live_intake_first_observed_at",
        )
        ingested = ensure_utc(
            self.ingested_at_utc,
            field="live_intake_ingested_at",
        )
        if ingested < observed:
            raise ValueError("LIVE_RESPONSE_INTAKE_TIMESTAMPS_INVALID")
        if self.canonical_intake_claim_sha256 != canonical_sha256(self.identity_material()):
            raise ValueError("LIVE_RESPONSE_INTAKE_CLAIM_HASH_MISMATCH")
        return self


class LiveCaptureLineageV1(FrozenContract):
    schema_version: Literal["robin-live-capture-lineage-v1"] = "robin-live-capture-lineage-v1"
    manifest_id: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    manifest_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    request: ProviderRequestSpec
    request_fingerprint_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    expected_sport_key: str
    expected_region: Literal["eu"] = "eu"
    expected_markets: MarketSet
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
        _validate_market_set(self.expected_markets)
        if (
            self.expected_sport_key not in LIVE_ALLOWED_SPORT_KEYS
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
        if self.canonical_lineage_sha256 != canonical_sha256(self.identity_material()):
            raise ValueError("LIVE_CAPTURE_LINEAGE_HASH_MISMATCH")
        return self


class LiveLeaseV1(FrozenContract):
    schema_version: Literal["robin-live-lease-v1"] = "robin-live-lease-v1"
    lease_id: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    authorization_id: str
    authorization_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    activation_id: str
    activation_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    repository_sha: Sha256 = Field(pattern=r"^[0-9a-f]{40}$")
    plan_id: str
    plan_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    item_id: str
    item_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    request_fingerprint_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    authorization_binding_key_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    authorization_binding_payload_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    activation_binding_key_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    activation_binding_payload_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    acquired_at_utc: datetime
    expires_at_utc: datetime
    state: Literal["LEASED"] = "LEASED"

    @model_validator(mode="after")
    def validate_lease(self) -> Self:
        acquired = ensure_utc(self.acquired_at_utc, field="lease_acquired_at")
        expires = ensure_utc(self.expires_at_utc, field="lease_expires_at")
        material = cast(dict[str, JsonValue], self.model_dump(mode="json", exclude={"lease_id"}))
        if acquired >= expires or self.lease_id != canonical_sha256(material):
            raise ValueError("LIVE_LEASE_INVALID")
        return self

    @classmethod
    def issue(cls, **data: Any) -> Self:
        provisional = cls.model_construct(lease_id="0" * 64, **data)
        material = cast(
            dict[str, JsonValue],
            provisional.model_dump(mode="json", exclude={"lease_id"}),
        )
        return cls(lease_id=canonical_sha256(material), **data)


class LiveExecutionAttemptReceiptV1(FrozenContract):
    schema_version: Literal["robin-live-execution-attempt-receipt-v1"] = (
        "robin-live-execution-attempt-receipt-v1"
    )
    execution_attempt_id: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    authorization_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    activation_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    plan_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    item_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    lease_id: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    request_fingerprint_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    response_intake_claim_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    dispatch_started_at_utc: datetime
    first_observed_at_utc: datetime
    ingested_at_utc: datetime
    prepared_at_utc: datetime
    http_status: int = Field(ge=100, le=599)
    network_calls: Literal[1] = 1
    provider_calls: Literal[1] = 1
    retries: Literal[0] = 0
    redirects: Literal[0] = 0
    secret_reads_count: Literal[1] = 1
    payload_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    payload_byte_length: int = Field(ge=0)
    capture_receipt_id: Sha256 | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    manifest_id: Sha256 | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    manifest_hash: Sha256 | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    canonical_attempt_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")

    def identity_material(self) -> dict[str, JsonValue]:
        return cast(
            dict[str, JsonValue],
            self.model_dump(
                mode="json", exclude={"execution_attempt_id", "canonical_attempt_sha256"}
            ),
        )

    @classmethod
    def issue(cls, **data: Any) -> Self:
        provisional = cls.model_construct(
            execution_attempt_id="0" * 64,
            canonical_attempt_sha256="0" * 64,
            **data,
        )
        digest = canonical_sha256(provisional.identity_material())
        return cls(execution_attempt_id=digest, canonical_attempt_sha256=digest, **data)

    @model_validator(mode="after")
    def validate_attempt(self) -> Self:
        timestamps = [
            ensure_utc(self.dispatch_started_at_utc, field="attempt_dispatch_started_at"),
            ensure_utc(self.first_observed_at_utc, field="attempt_first_observed_at"),
            ensure_utc(self.ingested_at_utc, field="attempt_ingested_at"),
            ensure_utc(self.prepared_at_utc, field="attempt_prepared_at"),
        ]
        digest = canonical_sha256(self.identity_material())
        if timestamps != sorted(timestamps):
            raise ValueError("LIVE_EXECUTION_ATTEMPT_TIMESTAMPS_INVALID")
        if (self.manifest_id is None) != (self.manifest_hash is None):
            raise ValueError("LIVE_EXECUTION_ATTEMPT_MANIFEST_INCOMPLETE")
        if self.execution_attempt_id != digest or self.canonical_attempt_sha256 != digest:
            raise ValueError("LIVE_EXECUTION_ATTEMPT_HASH_MISMATCH")
        return self


class LiveExecutionReceiptV1(FrozenContract):
    schema_version: Literal["robin-live-execution-receipt-v1"] = "robin-live-execution-receipt-v1"
    execution_receipt_id: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    authorization_id: str
    authorization_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    activation_id: str
    activation_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    repository_sha: Sha256 = Field(pattern=r"^[0-9a-f]{40}$")
    plan_id: str
    plan_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    item_id: str
    item_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    lease_id: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    lease_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    request_fingerprint_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    response_intake_claim_sha256: Sha256 | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    execution_attempt_id: Sha256 | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    dispatch_started_at_utc: datetime | None = None
    first_observed_at_utc: datetime | None = None
    ingested_at_utc: datetime | None = None
    terminal_at_utc: datetime
    http_status: int | Literal["UNKNOWN"]
    network_calls: int = Field(ge=0, le=1)
    provider_calls: int = Field(ge=0, le=1)
    retries: Literal[0] = 0
    redirects: Literal[0] = 0
    reserved_requests: int = Field(ge=0, le=1)
    reserved_credits: int = Field(ge=0)
    observed_quota: QuotaObservation | None = None
    payload_sha256: Sha256 | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    payload_byte_length: int | None = Field(default=None, ge=0)
    intake_receipt_id: Sha256 | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    final_receipt_id: Sha256 | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    manifest_id: Sha256 | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    manifest_hash: Sha256 | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    offline_replay_verdict: Literal["ROBIN_OFFLINE_CAPTURE_REPLAY_PROVEN", "NOT_POSSIBLE", "FAILED"]
    secret_reads_count: int = Field(ge=0, le=1)
    secret_retained: Literal[False] = False
    terminal_disposition: LiveTerminalDisposition

    def identity_material(self) -> dict[str, JsonValue]:
        return cast(
            dict[str, JsonValue],
            self.model_dump(mode="json", exclude={"execution_receipt_id"}),
        )

    @classmethod
    def issue(cls, **data: Any) -> Self:
        provisional = cls.model_construct(execution_receipt_id="0" * 64, **data)
        return cls(
            execution_receipt_id=canonical_sha256(provisional.identity_material()),
            **data,
        )

    @model_validator(mode="after")
    def validate_receipt(self) -> Self:
        terminal = ensure_utc(self.terminal_at_utc, field="live_terminal_at")
        timestamps = (
            self.dispatch_started_at_utc,
            self.first_observed_at_utc,
            self.ingested_at_utc,
        )
        prior = [ensure_utc(value, field="live_timestamp") for value in timestamps if value]
        if prior != sorted(prior) or any(value > terminal for value in prior):
            raise ValueError("LIVE_EXECUTION_TIMESTAMPS_INVALID")
        if self.network_calls != self.provider_calls:
            raise ValueError("LIVE_EXECUTION_CALL_COUNTER_MISMATCH")
        if self.lease_hash != self.lease_id:
            raise ValueError("LIVE_EXECUTION_LEASE_HASH_MISMATCH")
        if (self.payload_sha256 is None) != (self.payload_byte_length is None):
            raise ValueError("LIVE_EXECUTION_PAYLOAD_EVIDENCE_INCOMPLETE")
        if (self.manifest_id is None) != (self.manifest_hash is None):
            raise ValueError("LIVE_EXECUTION_MANIFEST_EVIDENCE_INCOMPLETE")
        if self.terminal_disposition is LiveTerminalDisposition.SUCCESS:
            if not (
                self.http_status == 200
                and self.network_calls == 1
                and self.secret_reads_count == 1
                and self.reserved_requests == 1
                and self.reserved_credits > 0
                and self.dispatch_started_at_utc is not None
                and self.first_observed_at_utc is not None
                and self.ingested_at_utc is not None
                and self.payload_sha256
                and self.payload_byte_length is not None
                and self.execution_attempt_id
                and self.response_intake_claim_sha256
                and self.intake_receipt_id
                and self.final_receipt_id
                and self.manifest_id
                and self.observed_quota is not None
                and self.offline_replay_verdict == "ROBIN_OFFLINE_CAPTURE_REPLAY_PROVEN"
            ):
                raise ValueError("LIVE_EXECUTION_SUCCESS_EVIDENCE_INCOMPLETE")
        if self.terminal_disposition is LiveTerminalDisposition.PRE_DISPATCH_REJECTED:
            if not (
                self.network_calls == 0
                and self.http_status == "UNKNOWN"
                and self.dispatch_started_at_utc is None
                and self.first_observed_at_utc is None
                and self.ingested_at_utc is None
                and self.execution_attempt_id is None
                and self.response_intake_claim_sha256 is None
                and self.payload_sha256 is None
                and self.intake_receipt_id is None
                and self.final_receipt_id is None
                and self.manifest_id is None
                and self.observed_quota is None
                and self.offline_replay_verdict == "NOT_POSSIBLE"
            ):
                raise ValueError("LIVE_PRE_DISPATCH_COUNTER_INVALID")
        if self.terminal_disposition is LiveTerminalDisposition.DISPATCH_OUTCOME_UNKNOWN:
            if not (
                self.network_calls == 1
                and self.http_status == "UNKNOWN"
                and self.dispatch_started_at_utc is not None
                and self.first_observed_at_utc is None
                and self.ingested_at_utc is None
                and self.secret_reads_count == 1
                and self.reserved_requests == 1
                and self.reserved_credits > 0
                and self.execution_attempt_id is None
                and self.response_intake_claim_sha256 is None
                and self.payload_sha256 is None
                and self.intake_receipt_id is None
                and self.final_receipt_id is None
                and self.manifest_id is None
                and self.observed_quota is None
                and self.offline_replay_verdict == "NOT_POSSIBLE"
            ):
                raise ValueError("LIVE_UNKNOWN_DISPATCH_EVIDENCE_INVALID")
        response_dispositions = {
            LiveTerminalDisposition.HTTP_REJECTED,
            LiveTerminalDisposition.PAYLOAD_REJECTED,
            LiveTerminalDisposition.QUOTA_RECONCILIATION_FAILED,
            LiveTerminalDisposition.OFFLINE_REPLAY_FAILED,
        }
        if self.terminal_disposition in response_dispositions and not (
            self.http_status != "UNKNOWN"
            and self.network_calls == 1
            and self.secret_reads_count == 1
            and self.reserved_requests == 1
            and self.reserved_credits > 0
            and self.dispatch_started_at_utc is not None
            and self.first_observed_at_utc is not None
            and self.ingested_at_utc is not None
            and self.execution_attempt_id
            and self.response_intake_claim_sha256
            and self.payload_sha256
            and self.payload_byte_length is not None
        ):
            raise ValueError("LIVE_RESPONSE_REJECTION_EVIDENCE_INCOMPLETE")
        if self.final_receipt_id is None and (
            self.intake_receipt_id is not None or self.observed_quota is not None
        ):
            raise ValueError("LIVE_FINAL_RECEIPT_DEPENDENCIES_INVALID")
        if self.manifest_id is not None and (
            self.final_receipt_id is None or self.intake_receipt_id is None
        ):
            raise ValueError("LIVE_MANIFEST_RECEIPT_EVIDENCE_MISSING")
        if self.terminal_disposition is LiveTerminalDisposition.OFFLINE_REPLAY_FAILED and (
            self.manifest_id is None or self.offline_replay_verdict != "FAILED"
        ):
            raise ValueError("LIVE_OFFLINE_REPLAY_FAILURE_EVIDENCE_INVALID")
        if self.terminal_disposition in {
            LiveTerminalDisposition.HTTP_REJECTED,
            LiveTerminalDisposition.PAYLOAD_REJECTED,
        } and (self.manifest_id is not None or self.offline_replay_verdict != "NOT_POSSIBLE"):
            raise ValueError("LIVE_RESPONSE_REJECTION_REPLAY_EVIDENCE_INVALID")
        if self.terminal_disposition is LiveTerminalDisposition.QUOTA_RECONCILIATION_FAILED:
            expected_replay = (
                "ROBIN_OFFLINE_CAPTURE_REPLAY_PROVEN"
                if self.manifest_id is not None
                else "NOT_POSSIBLE"
            )
            if self.offline_replay_verdict != expected_replay:
                raise ValueError("LIVE_QUOTA_REJECTION_REPLAY_EVIDENCE_INVALID")
        if self.execution_receipt_id != canonical_sha256(self.identity_material()):
            raise ValueError("LIVE_EXECUTION_RECEIPT_HASH_MISMATCH")
        return self
