"""Immutable contracts for the receipt-backed capture harness."""

from __future__ import annotations

import hashlib
import json
import math
import types
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Any, Literal, Self, Union, cast, get_args, get_origin
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

CAPTURE_SCHEMA_VERSION = "robin-receipt-capture-harness-v1"
RETENTION_POLICY_ID = "INTERNAL_MARKET_DATA_RETENTION_POLICY_V1"
SECRET_ENV_NAME = "THE_ODDS_" + "API_KEY"
ALLOWED_PROVIDER_HOST = "api.the-odds-api.com"
ALLOWED_MARKETS = ("h2h", "totals")
ALLOWED_REGIONS = ("eu",)
MAX_SIGNED_64 = 2**63 - 1

JsonValue = None | bool | int | float | str | list["JsonValue"] | dict[str, "JsonValue"]


class CaptureMode(StrEnum):
    VALIDATE_OFFLINE = "VALIDATE_OFFLINE"
    DRY_RUN = "DRY_RUN"
    LIVE_CANARY = "LIVE_CANARY"


class AdmissionStatus(StrEnum):
    INTAKE_PENDING = "INTAKE_PENDING"
    ADMITTED = "ADMITTED"
    QUARANTINED = "QUARANTINED"


class MappingStatus(StrEnum):
    MAPPED = "MAPPED"
    AMBIGUOUS = "AMBIGUOUS"
    UNMAPPED = "UNMAPPED"


def ensure_utc(value: datetime, *, field: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field.upper()}_UTC_REQUIRED")
    return value.astimezone(UTC)


def canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


class CaptureContractError(ValueError):
    """Stable validation failure that never embeds rejected request input."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def strict_json_loads(payload: str | bytes) -> Any:
    """Decode control-plane JSON without duplicate keys or non-finite numbers."""

    def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise CaptureContractError("CAPTURE_CONTROL_JSON_DUPLICATE_KEY")
            result[key] = value
        return result

    def reject_constant(_value: str) -> None:
        raise CaptureContractError("CAPTURE_CONTROL_JSON_NON_FINITE")

    def parse_float(value: str) -> float:
        parsed = float(value)
        if not math.isfinite(parsed):
            raise CaptureContractError("CAPTURE_CONTROL_JSON_NON_FINITE")
        return parsed

    def parse_int(value: str) -> int:
        if len(value.removeprefix("-")) > 19:
            raise CaptureContractError("CAPTURE_CONTROL_JSON_INTEGER_OUT_OF_RANGE")
        parsed = int(value)
        if not -(2**63) <= parsed < 2**63:
            raise CaptureContractError("CAPTURE_CONTROL_JSON_INTEGER_OUT_OF_RANGE")
        return parsed

    try:
        return json.loads(
            payload,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_constant,
            parse_float=parse_float,
            parse_int=parse_int,
        )
    except CaptureContractError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, TypeError, ValueError):
        raise CaptureContractError("CAPTURE_CONTROL_JSON_INVALID") from None


def strict_json_object(payload: str | bytes) -> dict[str, Any]:
    value = strict_json_loads(payload)
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise CaptureContractError("CAPTURE_CONTROL_JSON_OBJECT_REQUIRED")
    stack: list[object] = [value]
    nodes = 0
    while stack:
        current = stack.pop()
        nodes += 1
        if nodes > 100_000:
            raise CaptureContractError("CAPTURE_CONTROL_JSON_TOO_COMPLEX")
        if isinstance(current, dict):
            stack.extend(current.values())
        elif isinstance(current, list):
            stack.extend(current)
        elif isinstance(current, str) and any(
            0xD800 <= ord(character) <= 0xDFFF for character in current
        ):
            raise CaptureContractError("CAPTURE_CONTROL_JSON_SURROGATE_FORBIDDEN")
    return value


class FrozenContract(BaseModel):
    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        validate_default=True,
        hide_input_in_errors=True,
    )

    @model_validator(mode="before")
    @classmethod
    def reject_coerced_integers(cls, value: Any) -> Any:
        """Keep all persisted counters/ceilings integer-exact at every boundary."""

        if not isinstance(value, dict):
            return value

        def integer_shape(annotation: Any) -> tuple[bool, set[object]]:
            if annotation is int:
                return True, set()
            origin = get_origin(annotation)
            if origin is Literal:
                literals = set(get_args(annotation))
                return any(type(item) is int for item in literals), {
                    item for item in literals if type(item) is not int
                }
            if origin in {types.UnionType, Union}:
                contains_integer = False
                permitted: set[object] = set()
                for member in get_args(annotation):
                    if member is type(None):
                        permitted.add(None)
                        continue
                    member_contains_integer, member_permitted = integer_shape(member)
                    contains_integer = contains_integer or member_contains_integer
                    permitted.update(member_permitted)
                return contains_integer, permitted
            return False, set()

        for name, field in cls.model_fields.items():
            if name not in value:
                continue
            contains_integer, permitted = integer_shape(field.annotation)
            observed = value[name]
            is_permitted_literal = any(
                type(observed) is type(item) and observed == item for item in permitted
            )
            if (
                contains_integer
                and not is_permitted_literal
                and (not isinstance(observed, int) or isinstance(observed, bool))
            ):
                raise CaptureContractError("CAPTURE_CONTRACT_INTEGER_TYPE_INVALID")
        return value

    def __init__(self, **data: Any) -> None:
        try:
            super().__init__(**data)
        except ValidationError:
            raise CaptureContractError("CAPTURE_CONTRACT_INVALID") from None

    @classmethod
    def model_validate(cls, obj: Any, **kwargs: Any) -> Self:
        try:
            return super().model_validate(obj, **kwargs)
        except ValidationError:
            raise CaptureContractError("CAPTURE_CONTRACT_INVALID") from None

    @classmethod
    def model_validate_json(
        cls,
        json_data: str | bytes | bytearray,
        **kwargs: Any,
    ) -> Self:
        try:
            if isinstance(json_data, bytearray):
                json_data = bytes(json_data)
            return cls.model_validate(strict_json_object(json_data), **kwargs)
        except (CaptureContractError, ValidationError):
            raise CaptureContractError("CAPTURE_CONTRACT_INVALID") from None

    @classmethod
    def model_validate_strings(cls, obj: Any, **kwargs: Any) -> Self:
        try:
            return super().model_validate_strings(obj, **kwargs)
        except ValidationError:
            raise CaptureContractError("CAPTURE_CONTRACT_INVALID") from None


class ProviderRequestSpec(FrozenContract):
    provider: Literal["the-odds-api-v4"] = "the-odds-api-v4"
    scheme: Literal["https"] = "https"
    host: Literal["api.the-odds-api.com"] = "api.the-odds-api.com"
    endpoint: str = Field(min_length=1, max_length=240)
    sport_key: str = Field(min_length=1, max_length=120, pattern=r"^[a-z0-9_]+$")
    region: Literal["eu"] = "eu"
    markets: tuple[Literal["h2h", "totals"], ...]
    odds_format: Literal["decimal"] = "decimal"
    date_format: Literal["iso"] = "iso"
    allow_redirects: Literal[False] = False
    retries: Literal[0] = 0
    timeout_seconds: int = Field(default=10, ge=1, le=30)

    @model_validator(mode="after")
    def validate_request(self) -> Self:
        parsed = urlsplit(self.endpoint)
        if (
            parsed.scheme
            or parsed.netloc
            or parsed.query
            or parsed.fragment
            or not parsed.path.startswith("/v4/sports/")
            or ".." in PurePosixPath(parsed.path).parts
        ):
            raise ValueError("CAPTURE_ENDPOINT_INVALID")
        lowered = self.endpoint.casefold()
        if any(
            fragment in lowered
            for fragment in ("api_key", "apikey", "authorization", "secret", "token")
        ):
            raise ValueError("CAPTURE_ENDPOINT_SECRET_EXPOSABLE")
        if not self.markets or len(set(self.markets)) != len(self.markets):
            raise ValueError("CAPTURE_MARKETS_INVALID")
        expected = tuple(market for market in ALLOWED_MARKETS if market in self.markets)
        if self.markets != expected:
            raise ValueError("CAPTURE_MARKETS_NOT_CANONICAL")
        return self

    def fingerprint_material(self) -> dict[str, JsonValue]:
        return cast(dict[str, JsonValue], self.model_dump(mode="json"))


class RequestFingerprint(FrozenContract):
    algorithm: Literal["sha256"] = "sha256"
    request_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    request: ProviderRequestSpec

    @model_validator(mode="after")
    def validate_digest(self) -> Self:
        if self.request_sha256 != canonical_sha256(self.request.fingerprint_material()):
            raise ValueError("REQUEST_FINGERPRINT_MISMATCH")
        return self

    @classmethod
    def create(cls, request: ProviderRequestSpec) -> RequestFingerprint:
        return cls(
            request_sha256=canonical_sha256(request.fingerprint_material()),
            request=request,
        )


class CaptureBudget(FrozenContract):
    maximum_requests: int = Field(gt=0)
    used_requests: int = Field(default=0, ge=0)
    maximum_credits: int = Field(gt=0)
    used_credits: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def validate_bounds(self) -> Self:
        if self.used_requests > self.maximum_requests:
            raise ValueError("CAPTURE_REQUEST_BUDGET_EXCEEDED")
        if self.used_credits > self.maximum_credits:
            raise ValueError("CAPTURE_CREDIT_BUDGET_EXCEEDED")
        return self

    def reserve(self, *, requests: int, credits: int) -> CaptureBudget:
        if (
            isinstance(requests, bool)
            or not isinstance(requests, int)
            or isinstance(credits, bool)
            or not isinstance(credits, int)
            or requests <= 0
            or credits < 0
        ):
            raise ValueError("CAPTURE_BUDGET_RESERVATION_INVALID")
        if self.used_requests + requests > self.maximum_requests:
            raise ValueError("CAPTURE_REQUEST_BUDGET_EXCEEDED")
        if self.used_credits + credits > self.maximum_credits:
            raise ValueError("CAPTURE_CREDIT_BUDGET_EXCEEDED")
        return CaptureBudget(
            maximum_requests=self.maximum_requests,
            used_requests=self.used_requests + requests,
            maximum_credits=self.maximum_credits,
            used_credits=self.used_credits + credits,
        )


class QuotaObservation(FrozenContract):
    requests_remaining: int | None = Field(default=None, ge=0, le=MAX_SIGNED_64)
    requests_used: int | None = Field(default=None, ge=0, le=MAX_SIGNED_64)
    requests_last: int | None = Field(default=None, ge=0, le=MAX_SIGNED_64)
    observed_at: datetime

    @model_validator(mode="after")
    def validate_observed_at(self) -> Self:
        ensure_utc(self.observed_at, field="quota_observed_at")
        return self


class InternalRetentionPolicy(FrozenContract):
    policy_id: Literal["INTERNAL_MARKET_DATA_RETENTION_POLICY_V1"] = (
        "INTERNAL_MARKET_DATA_RETENTION_POLICY_V1"
    )
    purpose: Literal["internal analytics only"] = "internal analytics only"
    resale_allowed: Literal[False] = False
    redistribution_allowed: Literal[False] = False
    public_raw_endpoint_allowed: Literal[False] = False
    raw_storage: Literal["local non-synchronised"] = "local non-synchronised"
    raw_ttl_days: Literal[30] = 30
    normalized_observations_retained: Literal[True] = True
    raw_sha256_retained: Literal[True] = True
    derived_data_retained: Literal[True] = True
    automated_deletion_required: Literal[True] = True
    legal_risk: Literal["NON_ZERO_BOUNDED_INTERNAL_DECISION"] = "NON_ZERO_BOUNDED_INTERNAL_DECISION"
    authorized_scope: Literal["bounded research pilot"] = "bounded research pilot"
    full_season_permanent_raw_archive_allowed: Literal[False] = False
    explicit_provider_retention_authorization_claimed: Literal[False] = False


class SchemaFingerprint(FrozenContract):
    algorithm: Literal["sha256"] = "sha256"
    schema_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    paths_and_types: tuple[str, ...]

    @model_validator(mode="after")
    def validate_fingerprint(self) -> Self:
        if not self.paths_and_types:
            raise ValueError("SCHEMA_FINGERPRINT_EMPTY")
        if self.schema_sha256 != canonical_sha256(list(self.paths_and_types)):
            raise ValueError("SCHEMA_FINGERPRINT_MISMATCH")
        return self


class FixtureMapping(FrozenContract):
    provider_event_id: str = Field(min_length=1, max_length=160)
    fixture_id: str | None = Field(default=None, max_length=160)
    status: MappingStatus
    candidate_fixture_ids: tuple[str, ...]
    mapping_revision: str = Field(min_length=1, max_length=80)

    @model_validator(mode="after")
    def validate_mapping(self) -> Self:
        if len(set(self.candidate_fixture_ids)) != len(self.candidate_fixture_ids):
            raise ValueError("FIXTURE_MAPPING_CANDIDATES_DUPLICATED")
        if self.status is MappingStatus.MAPPED:
            if self.fixture_id is None or self.candidate_fixture_ids != (self.fixture_id,):
                raise ValueError("FIXTURE_MAPPING_NOT_ONE_TO_ONE")
        elif self.fixture_id is not None:
            raise ValueError("FIXTURE_MAPPING_NON_MAPPED_FIXTURE_FORBIDDEN")
        if self.status is MappingStatus.AMBIGUOUS and len(self.candidate_fixture_ids) < 2:
            raise ValueError("FIXTURE_MAPPING_AMBIGUITY_UNPROVEN")
        if self.status is MappingStatus.UNMAPPED and self.candidate_fixture_ids:
            raise ValueError("FIXTURE_MAPPING_UNMAPPED_HAS_CANDIDATES")
        return self


class RawPayloadReceipt(FrozenContract):
    receipt_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    intake_receipt_id: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    request_fingerprint_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    payload_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    payload_byte_length: int = Field(ge=0)
    http_status: int = Field(ge=100, le=599)
    quota: QuotaObservation | None = None
    robin_first_observed_at: datetime
    robin_ingested_at: datetime
    available_at: datetime
    raw_expires_at: datetime
    raw_storage_key: str | None = None
    schema_fingerprint_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    admission_status: AdmissionStatus
    rejection_code: str | None = Field(default=None, max_length=100)

    def identity_material(self) -> dict[str, JsonValue]:
        return {
            "schema_version": "robin-raw-payload-receipt-v1",
            **cast(
                dict[str, JsonValue],
                self.model_dump(mode="json", exclude={"receipt_id"}),
            ),
        }

    @classmethod
    def issue(cls, **data: Any) -> Self:
        provisional = cls.model_construct(receipt_id="0" * 64, **data)
        return cls(
            receipt_id=canonical_sha256(provisional.identity_material()),
            **data,
        )

    @model_validator(mode="after")
    def validate_receipt(self) -> Self:
        first = ensure_utc(self.robin_first_observed_at, field="robin_first_observed_at")
        ingested = ensure_utc(self.robin_ingested_at, field="robin_ingested_at")
        available = ensure_utc(self.available_at, field="available_at")
        expires = ensure_utc(self.raw_expires_at, field="raw_expires_at")
        if ingested < first:
            raise ValueError("RECEIPT_INGESTED_BEFORE_OBSERVED")
        if available < first:
            raise ValueError("RECEIPT_AVAILABLE_AT_BACKDATED")
        if expires != first + timedelta(days=30):
            raise ValueError("RECEIPT_RAW_TTL_NOT_30_DAYS")
        expected_key = f"raw/sha256/{self.payload_sha256[:2]}/{self.payload_sha256}.bin"
        if self.raw_storage_key is not None and self.raw_storage_key != expected_key:
            raise ValueError("RECEIPT_RAW_STORAGE_KEY_INVALID")
        if self.admission_status is AdmissionStatus.ADMITTED and self.rejection_code is not None:
            raise ValueError("ADMITTED_RECEIPT_HAS_REJECTION")
        if self.admission_status is AdmissionStatus.QUARANTINED and not self.rejection_code:
            raise ValueError("REJECTED_RECEIPT_REASON_REQUIRED")
        if self.admission_status is AdmissionStatus.INTAKE_PENDING and (
            self.intake_receipt_id is not None
            or self.rejection_code is not None
            or self.quota is not None
            or self.schema_fingerprint_sha256 is not None
        ):
            raise ValueError("INTAKE_RECEIPT_NOT_PROVISIONAL")
        if (
            self.admission_status is not AdmissionStatus.INTAKE_PENDING
            and self.raw_storage_key is not None
            and self.intake_receipt_id is None
        ):
            raise ValueError("FINAL_RECEIPT_INTAKE_LINK_REQUIRED")
        if self.raw_storage_key is None and self.intake_receipt_id is not None:
            raise ValueError("RECEIPT_INTAKE_LINK_WITHOUT_RAW_FORBIDDEN")
        if self.receipt_id != canonical_sha256(self.identity_material()):
            raise ValueError("RECEIPT_IDENTITY_MISMATCH")
        return self


class NormalizedMarketObservation(FrozenContract):
    snapshot_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    fixture_id: str = Field(min_length=1, max_length=160)
    provider_event_id: str = Field(min_length=1, max_length=160)
    receipt_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    payload_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    bookmaker_key: str = Field(min_length=1, max_length=120)
    market_key: Literal["h2h", "totals"]
    market_last_update: datetime | None = None
    outcome_name: str = Field(min_length=1, max_length=160)
    price: Decimal = Field(gt=0)
    point: Decimal | None = None
    available_at: datetime

    @model_validator(mode="after")
    def validate_observation(self) -> Self:
        available = ensure_utc(self.available_at, field="observation_available_at")
        if self.market_last_update is not None:
            updated = ensure_utc(self.market_last_update, field="market_last_update")
            if available < updated:
                raise ValueError("OBSERVATION_AVAILABLE_BEFORE_MARKET_UPDATE")
        if self.market_key == "h2h" and self.point is not None:
            raise ValueError("H2H_POINT_FORBIDDEN")
        if self.market_key == "totals" and self.point is None:
            raise ValueError("TOTALS_POINT_REQUIRED")
        return self


class CaptureManifest(FrozenContract):
    schema_version: Literal["robin-receipt-capture-harness-v1"] = "robin-receipt-capture-harness-v1"
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    snapshot_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    receipt_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    request_fingerprint_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    raw_payload_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    schema_fingerprint: SchemaFingerprint
    fixture_mappings: tuple[FixtureMapping, ...]
    observation_count: int = Field(ge=0)
    normalized_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    normalized_storage_key: str
    captured_at: datetime
    mode: Literal["VALIDATE_OFFLINE", "LIVE_CANARY"] = "VALIDATE_OFFLINE"
    network_calls: Literal[0, 1] = 0
    provider_calls: Literal[0, 1] = 0
    live_canary_authorized: bool = False
    promoted: Literal[False] = False
    bet_calculated: Literal[False] = False

    def identity_material(self) -> dict[str, JsonValue]:
        return cast(
            dict[str, JsonValue],
            self.model_dump(mode="json", exclude={"manifest_sha256"}),
        )

    @classmethod
    def issue(cls, **data: Any) -> Self:
        provisional = cls.model_construct(manifest_sha256="0" * 64, **data)
        return cls(
            manifest_sha256=canonical_sha256(provisional.identity_material()),
            **data,
        )

    @model_validator(mode="after")
    def validate_manifest(self) -> Self:
        ensure_utc(self.captured_at, field="captured_at")
        if self.mode == "VALIDATE_OFFLINE" and (
            self.network_calls != 0 or self.provider_calls != 0 or self.live_canary_authorized
        ):
            raise ValueError("OFFLINE_MANIFEST_EFFECTS_INVALID")
        if self.mode == "LIVE_CANARY" and (
            self.network_calls != 1 or self.provider_calls != 1 or not self.live_canary_authorized
        ):
            raise ValueError("LIVE_MANIFEST_EFFECTS_INVALID")
        expected_key = f"normalized/{self.snapshot_id}.jsonl"
        if self.normalized_storage_key != expected_key:
            raise ValueError("NORMALIZED_STORAGE_KEY_INVALID")
        if self.manifest_sha256 != canonical_sha256(self.identity_material()):
            raise ValueError("CAPTURE_MANIFEST_IDENTITY_MISMATCH")
        return self


class OfflineReplayResult(FrozenContract):
    snapshot_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    receipt_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    raw_payload_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    normalized_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    observation_count: int = Field(ge=0)
    byte_identical: Literal[True]
    deterministic: Literal[True]
    raw_hash_verified_before_parse: Literal[True] = True
    network_calls: Literal[0] = 0
    provider_calls: Literal[0] = 0
    secret_reads_count: Literal[0] = 0
    verdict: Literal["ROBIN_OFFLINE_CAPTURE_REPLAY_PROVEN"] = "ROBIN_OFFLINE_CAPTURE_REPLAY_PROVEN"
