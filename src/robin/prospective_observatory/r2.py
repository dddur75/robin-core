"""Append-only R2-first storage for prospective raw payloads."""

from __future__ import annotations

import base64
import binascii
import gzip
import hashlib
import json
import re
import uuid
import zlib
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol, cast, runtime_checkable
from urllib.parse import quote

from robin.market_math import DevigInputError, DevigResult, devig_probabilities
from robin.prospective_observatory.contracts import (
    R2_SCHEMA_VERSION,
    CaptureContext,
    CaptureFamily,
    CaptureReceipt,
    canonical_json_bytes,
    canonical_sha256,
    ensure_utc,
    receipt_scope_sha256,
)

R2_NAMESPACE = "prospective-deep-data"
R2_RECOVERY_NAMESPACE = "prospective-deep-data-recovery"
R2_RECOVERY_SCHEMA_VERSION = "prospective-receipt-recovery-intent-v1"
R2_BUDGET_NAMESPACE = "prospective-deep-budget"
R2_BUDGET_SCHEMA_VERSION = "prospective-provider-budget-v1"


def complete_positive_overround_market(
    provider_market: str,
    outcomes: list[object],
) -> tuple[tuple[Mapping[str, object], ...], DevigResult] | None:
    expected_count = {"h2h": 3, "totals": 2}.get(provider_market)
    if expected_count is None:
        return None
    eligible: list[Mapping[str, object]] = []
    for outcome in outcomes:
        if not isinstance(outcome, Mapping):
            return None
        if provider_market == "totals":
            try:
                point = float(outcome.get("point", 0.0))
            except (TypeError, ValueError):
                return None
            if point != 2.5:
                continue
        eligible.append(outcome)
    if len(eligible) != expected_count:
        return None
    labels = tuple(str(outcome.get("name", "")).strip() for outcome in eligible)
    prices = tuple(
        cast(float | None, outcome.get("price")) for outcome in eligible
    )
    try:
        devig = devig_probabilities(
            prices,
            method="PROPORTIONAL",
            outcome_labels=labels,
        )
    except DevigInputError:
        return None
    if devig.overround <= 0.0:
        return None
    return tuple(eligible), devig


def _normalized_capture_payload(payload: object) -> object:
    if not isinstance(payload, Mapping):
        return payload
    contract_keys = {
        "raw_payload_kind",
        "raw_provider_payload",
        "normalized_family_records",
    }
    present = contract_keys & set(payload)
    if not present:
        return payload
    if present != contract_keys:
        raise ValueError("R2_CAPTURE_CONTRACT_INCOMPLETE")
    if payload["raw_payload_kind"] not in {
        "PROVIDER_RESPONSE_ENVELOPE",
        "CANONICAL_PROVIDER_RECORDS",
    }:
        raise ValueError("R2_CAPTURE_RAW_KIND_INVALID")
    return payload["normalized_family_records"]


def _raw_provider_records(raw_payload: object) -> list[dict[str, object]]:
    if isinstance(raw_payload, list):
        return [
            dict(record)
            for record in raw_payload
            if isinstance(record, Mapping)
        ]
    if not isinstance(raw_payload, Mapping):
        return []
    response = raw_payload.get("response")
    if isinstance(response, list):
        return [
            dict(record) for record in response if isinstance(record, Mapping)
        ]
    if set(raw_payload) == {"home", "away"}:
        return [
            record
            for side in ("home", "away")
            for record in _raw_provider_records(raw_payload[side])
        ]
    return [dict(raw_payload)]


def operational_odds_replay_projection(
    receipt: CaptureReceipt,
    payload: object,
) -> Mapping[str, object]:
    if receipt.family is not CaptureFamily.ODDS:
        raise ValueError("R2_ODDS_RECEIPT_REQUIRED")
    normalized = _normalized_capture_payload(payload)
    if isinstance(payload, Mapping) and "raw_payload_kind" in payload:
        raw = payload["raw_provider_payload"]
        raw_kind = payload["raw_payload_kind"]
        if raw_kind == "CANONICAL_PROVIDER_RECORDS":
            candidates = (
                [dict(raw)]
                if isinstance(raw, Mapping) and isinstance(normalized, list)
                else raw
            )
            if canonical_sha256(candidates) != canonical_sha256(normalized):
                raise ValueError("R2_RAW_NORMALIZATION_MISMATCH")
            normalized = candidates
        else:
            records = _raw_provider_records(raw)
            normalized_records = (
                normalized if isinstance(normalized, list) else []
            )
            matching = [
                record
                for record in records
                if any(
                    canonical_sha256(record) == canonical_sha256(candidate)
                    for candidate in normalized_records
                )
            ]
            if len(normalized_records) != 1 or len(matching) != 1:
                raise ValueError("R2_RAW_NORMALIZATION_MISMATCH")
            normalized = matching
    return {
        "fixture_id": receipt.fixture_id,
        "family": receipt.family.value,
        "observed_at": receipt.observed_at.isoformat(),
        "payload_sha256": receipt.payload_sha256,
        "data": normalized,
    }


def _projection_records(
    projection: Mapping[str, object],
) -> tuple[Mapping[str, object], ...]:
    data = projection.get("data")
    if isinstance(data, Mapping) and isinstance(data.get("value"), list):
        data = data["value"]
    if isinstance(data, list):
        return tuple(item for item in data if isinstance(item, Mapping))
    if isinstance(data, Mapping):
        return (data,)
    return ()


def project_odds_rows(
    receipt: CaptureReceipt,
    projection: Mapping[str, object],
) -> tuple[dict[str, object], ...]:
    rows: list[dict[str, object]] = []
    receipt_id = str(
        uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"robin:j12:receipt:{receipt.receipt_hash}",
        )
    )
    for event in _projection_records(projection):
        bookmakers = event.get("bookmakers")
        if not isinstance(bookmakers, list):
            continue
        for bookmaker_value in bookmakers:
            if not isinstance(bookmaker_value, Mapping):
                continue
            bookmaker = str(bookmaker_value.get("key", "")).strip()
            markets = bookmaker_value.get("markets")
            if not bookmaker or not isinstance(markets, list):
                continue
            for market_value in markets:
                if not isinstance(market_value, Mapping):
                    continue
                provider_market = str(market_value.get("key", ""))
                market = {
                    "h2h": "1X2",
                    "totals": "OVER_UNDER_2_5",
                }.get(provider_market)
                outcomes = market_value.get("outcomes")
                if market is None or not isinstance(outcomes, list):
                    continue
                validated = complete_positive_overround_market(
                    provider_market,
                    outcomes,
                )
                if validated is None:
                    continue
                eligible_outcomes, devig = validated
                for outcome, odds in zip(
                    eligible_outcomes,
                    devig.input_odds,
                    strict=True,
                ):
                    selection = str(outcome.get("name", "")).strip()
                    if not selection:
                        continue
                    key = (
                        f"{receipt.receipt_hash}:{bookmaker}:"
                        f"{market}:{selection}"
                    )
                    row_id = str(
                        uuid.uuid5(
                            uuid.NAMESPACE_URL,
                            f"robin:j12:odds:{key}",
                        )
                    )
                    snapshot_hash = canonical_sha256(
                        {
                            "bookmaker": bookmaker,
                            "market": market,
                            "selection": selection,
                            "odds": odds,
                            "margin": devig.overround,
                            "observed_at": receipt.observed_at.isoformat(),
                        }
                    )
                    rows.append(
                        {
                            "id": row_id,
                            "receipt_id": receipt_id,
                            "fixture_id": receipt.fixture_id,
                            "bookmaker": bookmaker,
                            "market": market,
                            "selection": selection,
                            "odds": odds,
                            "margin": devig.overround,
                            "observed_at": receipt.observed_at,
                            "cutoff_at": receipt.cutoff_at,
                            "fixture_match_status": "MATCHED_EXACT",
                            "snapshot_hash": snapshot_hash,
                            "code_revision": receipt.code_revision,
                            "append_only": True,
                        }
                    )
    return tuple(
        sorted(
            rows,
            key=lambda value: (
                str(value["bookmaker"]),
                str(value["market"]),
                str(value["selection"]),
            ),
        )
    )


class AppendOnlyViolation(RuntimeError):
    """Raised when an existing R2 object differs from the requested bytes."""


class PayloadIntegrityError(RuntimeError):
    """Raised when a stored payload no longer matches its immutable receipt."""


class ReceiptRecoveryIntegrityError(PayloadIntegrityError):
    """Raised when an append-only receipt recovery intent is not trustworthy."""


@dataclass(frozen=True, slots=True)
class R2NamespaceInventory:
    """Exhaustive, content-verified inventory of the prospective namespace."""

    namespace_prefix: str
    physical_unique_objects: int
    physical_unique_bytes: int
    physical_payload_objects: int
    physical_payload_bytes: int
    physical_receipt_objects: int
    physical_receipt_bytes: int
    physical_recovery_objects: int
    physical_recovery_bytes: int
    logical_references: int
    logical_payload_bytes_read: int
    logical_receipt_bytes_read: int
    payload_keys: tuple[str, ...]
    receipt_keys: tuple[str, ...]
    recovery_keys: tuple[str, ...]
    orphan_payload_keys: tuple[str, ...]
    orphan_receipt_keys: tuple[str, ...]
    unexpected_keys: tuple[str, ...]
    unreadable_keys: tuple[str, ...]
    integrity_error_keys: tuple[str, ...]
    integrity_errors: tuple[str, ...]

    @property
    def logical_bytes_read(self) -> int:
        """Bytes read when each receipt resolves its logical payload reference."""

        return self.logical_payload_bytes_read + self.logical_receipt_bytes_read

    @property
    def verified(self) -> bool:
        return not (
            self.orphan_payload_keys
            or self.orphan_receipt_keys
            or self.unexpected_keys
            or self.unreadable_keys
            or self.integrity_error_keys
        )


class R2NamespaceIntegrityError(PayloadIntegrityError):
    """Raised before replay when the complete R2 namespace is not coherent."""

    def __init__(self, inventory: R2NamespaceInventory) -> None:
        self.inventory = inventory
        counts = (
            f"orphan_payloads={len(inventory.orphan_payload_keys)},"
            f"orphan_receipts={len(inventory.orphan_receipt_keys)},"
            f"unexpected={len(inventory.unexpected_keys)},"
            f"unreadable={len(inventory.unreadable_keys)},"
            f"integrity={len(inventory.integrity_error_keys)}"
        )
        super().__init__(f"R2_NAMESPACE_INTEGRITY_FAILED:{counts}")


@runtime_checkable
class ObjectStore(Protocol):
    """Minimal object-store surface; deletion is deliberately not part of it."""

    def get_object(self, key: str) -> bytes | None: ...

    def put_if_absent(self, key: str, data: bytes) -> bool:
        """Atomically create *key*, returning False when it already exists."""

    def iter_keys(self, prefix: str) -> Iterable[str]: ...


class InMemoryObjectStore:
    """Strict test double with the same no-overwrite contract required from R2."""

    def __init__(self) -> None:
        self._objects: dict[str, bytes] = {}

    def get_object(self, key: str) -> bytes | None:
        return self._objects.get(key)

    def put_if_absent(self, key: str, data: bytes) -> bool:
        if key in self._objects:
            return False
        self._objects[key] = bytes(data)
        return True

    def iter_keys(self, prefix: str) -> Iterable[str]:
        return tuple(sorted(key for key in self._objects if key.startswith(prefix)))

    @property
    def object_count(self) -> int:
        return len(self._objects)


@dataclass(frozen=True, slots=True)
class StoredCapture:
    receipt: CaptureReceipt
    payload: object
    payload_created: bool
    receipt_created: bool


@dataclass(frozen=True, slots=True)
class DurableProviderBudget:
    """Append-only billable-unit reservation stored independently from SQL."""

    idempotency_key: str
    provider: str
    units: int
    provider_remaining: int
    provider_reserve: int
    recorded_at: datetime
    reason: str
    code_revision: str

    def __post_init__(self) -> None:
        if (
            not self.idempotency_key
            or self.provider not in {"API_FOOTBALL", "ODDS_API"}
            or self.units < 0
            or self.provider_remaining < 0
            or self.provider_reserve < 0
            or not self.reason
            or not self.code_revision
        ):
            raise ValueError("R2_PROVIDER_BUDGET_RECORD_INVALID")
        object.__setattr__(
            self,
            "recorded_at",
            ensure_utc(self.recorded_at, field="recorded_at"),
        )

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": R2_BUDGET_SCHEMA_VERSION,
            "idempotency_key": self.idempotency_key,
            "provider": self.provider,
            "units": self.units,
            "provider_remaining": self.provider_remaining,
            "provider_reserve": self.provider_reserve,
            "recorded_at": self.recorded_at.isoformat(),
            "reason": self.reason,
            "code_revision": self.code_revision,
        }

    @property
    def record_hash(self) -> str:
        return canonical_sha256(self.as_dict())


@dataclass(frozen=True, slots=True)
class _PayloadInspection:
    stored_bytes: int
    payload_bytes: int | None
    payload_sha256: str | None
    valid: bool


_SAFE_KEY_SEGMENT = r"(?:[A-Za-z0-9._~-]|%[0-9A-F]{2})+"
_FAMILY_PATTERN = "|".join(
    re.escape(family.value) for family in CaptureFamily
)
_OBJECT_KEY_PATTERN = re.compile(
    rf"^{re.escape(R2_NAMESPACE)}/{re.escape(R2_SCHEMA_VERSION)}/"
    rf"competition={_SAFE_KEY_SEGMENT}/"
    rf"season={_SAFE_KEY_SEGMENT}/"
    rf"fixture={_SAFE_KEY_SEGMENT}/"
    rf"source={_SAFE_KEY_SEGMENT}/"
    rf"family=(?:{_FAMILY_PATTERN})/"
    r"observed_at=\d{8}T\d{6}\.\d{6}Z/"
    r"(?:"
    r"payload-(?P<payload_hash>[0-9a-f]{64})\.json\.gz"
    r"|"
    r"receipt-(?P<receipt_scope>[0-9a-f]{64})-"
    r"(?P<receipt_payload_hash>[0-9a-f]{64})\.json"
    r")$"
)
_RECOVERY_INTENT_KEY_PATTERN = re.compile(
    rf"^{re.escape(R2_RECOVERY_NAMESPACE)}/{re.escape(R2_SCHEMA_VERSION)}/"
    r"intent-(?P<receipt_hash>[0-9a-f]{64})\.json$"
)
_BUDGET_KEY_PATTERN = re.compile(
    rf"^{re.escape(R2_BUDGET_NAMESPACE)}/"
    rf"{re.escape(R2_BUDGET_SCHEMA_VERSION)}/"
    r"entry-(?P<idempotency_hash>[0-9a-f]{64})\.json$"
)


def _has_deterministic_gzip_header(data: bytes) -> bool:
    # RFC 1952 stores MTIME in bytes 4..7. The OS byte may legitimately vary
    # across Python/zlib platforms, so it is deliberately not compared.
    return (
        len(data) >= 10
        and data[:3] == b"\x1f\x8b\x08"
        and data[3] == 0
        and data[4:8] == b"\x00\x00\x00\x00"
    )


def _safe_segment(value: str) -> str:
    if not value or value in {".", ".."}:
        raise ValueError("R2_KEY_SEGMENT_INVALID")
    return quote(value, safe="-_.~")


def deterministic_r2_prefix(context: CaptureContext) -> str:
    observed = context.observed_at.astimezone(UTC).strftime("%Y%m%dT%H%M%S.%fZ")
    return (
        f"{R2_NAMESPACE}/{R2_SCHEMA_VERSION}/"
        f"competition={_safe_segment(context.competition)}/"
        f"season={_safe_segment(context.season)}/"
        f"fixture={_safe_segment(context.fixture_id)}/"
        f"source={_safe_segment(context.provider)}/"
        f"family={context.family.value}/"
        f"observed_at={observed}"
    )


def deterministic_r2_keys(
    context: CaptureContext,
    payload_sha256: str,
) -> tuple[str, str]:
    if len(payload_sha256) != 64 or any(
        character not in "0123456789abcdef" for character in payload_sha256
    ):
        raise ValueError("PAYLOAD_SHA256_INVALID")
    prefix = deterministic_r2_prefix(context)
    receipt_scope = receipt_scope_sha256(
        window_id=context.window_id,
        window_label=context.window_label,
    )
    return (
        f"{prefix}/payload-{payload_sha256}.json.gz",
        f"{prefix}/receipt-{receipt_scope}-{payload_sha256}.json",
    )


def _context_from_receipt(receipt: CaptureReceipt) -> CaptureContext:
    return CaptureContext(
        window_id=receipt.window_id,
        window_label=receipt.window_label,
        fixture_id=receipt.fixture_id,
        competition=receipt.competition,
        season=receipt.season,
        provider=receipt.provider,
        family=receipt.family,
        requested_at=receipt.requested_at,
        response_received_at=receipt.response_received_at,
        observed_at=receipt.observed_at,
        kickoff_at=receipt.kickoff_at,
        cutoff_at=receipt.cutoff_at,
        http_status=receipt.http_status,
        source_endpoint=receipt.source_endpoint,
        complete=receipt.complete,
        quality_status=receipt.quality_status,
        provider_calls=receipt.provider_calls,
        code_revision=receipt.code_revision,
        event_time=receipt.event_time,
        provider_updated_at=receipt.provider_updated_at,
        materialized_at=receipt.materialized_at,
    )


def _recovery_intent_key(receipt: CaptureReceipt) -> str:
    return (
        f"{R2_RECOVERY_NAMESPACE}/{R2_SCHEMA_VERSION}/"
        f"intent-{receipt.receipt_hash}.json"
    )


def _recovery_intent_bytes(
    receipt: CaptureReceipt,
    compressed_payload: bytes,
) -> bytes:
    return canonical_json_bytes(
        {
            "schema_version": R2_RECOVERY_SCHEMA_VERSION,
            "receipt": receipt.model_dump(mode="json"),
            "compressed_payload_base64": base64.b64encode(
                compressed_payload
            ).decode("ascii"),
            "compressed_payload_sha256": hashlib.sha256(
                compressed_payload
            ).hexdigest(),
        }
    )


class ProspectiveR2Repository:
    """Owns raw prospective bytes; Git and PostgreSQL only retain references."""

    def __init__(
        self,
        store: ObjectStore,
        *,
        namespace: str = R2_NAMESPACE,
    ) -> None:
        if namespace != R2_NAMESPACE:
            raise ValueError("PROSPECTIVE_R2_NAMESPACE_MUST_BE_VERSIONED_CANONICAL")
        self.store = store
        self.namespace = namespace

    @staticmethod
    def _put_immutable(store: ObjectStore, key: str, data: bytes) -> bool:
        created = store.put_if_absent(key, data)
        if created:
            return True
        existing = store.get_object(key)
        if existing is None:
            raise AppendOnlyViolation("R2_CONDITIONAL_WRITE_INCONSISTENT")
        if existing != data:
            raise AppendOnlyViolation(f"R2_APPEND_ONLY_OBJECT_MISMATCH:{key}")
        return False

    def capture(
        self,
        *,
        payload: object,
        context: CaptureContext,
    ) -> StoredCapture:
        canonical_payload = canonical_json_bytes(payload)

        payload_sha256 = hashlib.sha256(canonical_payload).hexdigest()
        compressed = gzip.compress(canonical_payload, compresslevel=9, mtime=0)
        payload_key, receipt_key = deterministic_r2_keys(context, payload_sha256)
        materialized_at = context.materialized_at
        receipt = CaptureReceipt(
            window_id=context.window_id,
            window_label=context.window_label,
            fixture_id=context.fixture_id,
            competition=context.competition,
            season=context.season,
            provider=context.provider,
            family=context.family,
            requested_at=context.requested_at,
            response_received_at=context.response_received_at,
            observed_at=context.observed_at,
            kickoff_at=context.kickoff_at,
            cutoff_at=context.cutoff_at,
            seconds_before_kickoff=int(
                (context.kickoff_at - context.response_received_at).total_seconds()
            ),
            http_status=context.http_status,
            payload_sha256=payload_sha256,
            payload_bytes=len(canonical_payload),
            stored_bytes=len(compressed),
            r2_key=payload_key,
            receipt_r2_key=receipt_key,
            source_endpoint=context.source_endpoint,
            complete=context.complete,
            quality_status=context.quality_status,
            provider_calls=context.provider_calls,
            code_revision=context.code_revision,
            event_time=context.event_time,
            provider_updated_at=context.provider_updated_at,
            materialized_at=materialized_at,
        )
        receipt_bytes = canonical_json_bytes(receipt.model_dump(mode="json"))

        # Write-ahead recovery is itself immutable and contains the exact
        # compressed payload plus its canonical receipt. Therefore a crash
        # before either final object can be repaired provider-free.
        self._put_immutable(
            self.store,
            _recovery_intent_key(receipt),
            _recovery_intent_bytes(receipt, compressed),
        )
        payload_created = self._put_immutable(self.store, payload_key, compressed)
        receipt_created = self._put_immutable(
            self.store,
            receipt_key,
            receipt_bytes,
        )
        return StoredCapture(
            receipt=receipt,
            payload=payload,
            payload_created=payload_created,
            receipt_created=receipt_created,
        )

    @staticmethod
    def _budget_key(idempotency_key: str) -> str:
        if not idempotency_key:
            raise ValueError("R2_PROVIDER_BUDGET_IDEMPOTENCY_KEY_REQUIRED")
        return (
            f"{R2_BUDGET_NAMESPACE}/{R2_BUDGET_SCHEMA_VERSION}/"
            f"entry-{canonical_sha256(idempotency_key)}.json"
        )

    def record_provider_budget(
        self,
        record: DurableProviderBudget,
    ) -> bool:
        """Persist charged units before the corresponding provider transport."""

        return self._put_immutable(
            self.store,
            self._budget_key(record.idempotency_key),
            canonical_json_bytes(record.as_dict()),
        )

    def provider_budgets(self) -> tuple[DurableProviderBudget, ...]:
        """Read and validate the complete durable provider budget journal."""

        prefix = f"{R2_BUDGET_NAMESPACE}/{R2_BUDGET_SCHEMA_VERSION}/"
        records: list[DurableProviderBudget] = []
        for key in sorted(set(self.store.iter_keys(prefix))):
            match = _BUDGET_KEY_PATTERN.fullmatch(key)
            body = self.store.get_object(key)
            if match is None or body is None:
                raise PayloadIntegrityError("R2_PROVIDER_BUDGET_OBJECT_INVALID")
            try:
                value = json.loads(body)
                if (
                    not isinstance(value, dict)
                    or set(value)
                    != {
                        "schema_version",
                        "idempotency_key",
                        "provider",
                        "units",
                        "provider_remaining",
                        "provider_reserve",
                        "recorded_at",
                        "reason",
                        "code_revision",
                    }
                    or value.get("schema_version") != R2_BUDGET_SCHEMA_VERSION
                    or canonical_json_bytes(value) != body
                ):
                    raise ValueError("R2_PROVIDER_BUDGET_CONTRACT_INVALID")
                record = DurableProviderBudget(
                    idempotency_key=str(value["idempotency_key"]),
                    provider=str(value["provider"]),
                    units=int(value["units"]),
                    provider_remaining=int(value["provider_remaining"]),
                    provider_reserve=int(value["provider_reserve"]),
                    recorded_at=datetime.fromisoformat(str(value["recorded_at"])),
                    reason=str(value["reason"]),
                    code_revision=str(value["code_revision"]),
                )
            except (
                KeyError,
                TypeError,
                ValueError,
                UnicodeDecodeError,
                json.JSONDecodeError,
            ) as error:
                raise PayloadIntegrityError(
                    "R2_PROVIDER_BUDGET_OBJECT_INVALID"
                ) from error
            if (
                match.group("idempotency_hash")
                != canonical_sha256(record.idempotency_key)
                or key != self._budget_key(record.idempotency_key)
            ):
                raise PayloadIntegrityError("R2_PROVIDER_BUDGET_KEY_MISMATCH")
            records.append(record)
        return tuple(
            sorted(
                records,
                key=lambda item: (
                    item.recorded_at,
                    item.idempotency_key,
                ),
            )
        )

    @staticmethod
    def _payload_from_compressed(
        receipt: CaptureReceipt,
        compressed: bytes,
    ) -> object:
        try:
            canonical_payload = gzip.decompress(compressed)
            payload = json.loads(canonical_payload)
        except (
            gzip.BadGzipFile,
            EOFError,
            zlib.error,
            UnicodeDecodeError,
            json.JSONDecodeError,
        ) as error:
            raise PayloadIntegrityError("R2_PAYLOAD_INVALID") from error

        if (
            hashlib.sha256(canonical_payload).hexdigest()
            != receipt.payload_sha256
            or len(canonical_payload) != receipt.payload_bytes
            or len(compressed) != receipt.stored_bytes
            or canonical_json_bytes(payload) != canonical_payload
            or not _has_deterministic_gzip_header(compressed)
        ):
            raise PayloadIntegrityError("R2_PAYLOAD_HASH_OR_SIZE_MISMATCH")
        return payload

    def _payload_for_receipt(self, receipt: CaptureReceipt) -> object:
        compressed = self.store.get_object(receipt.r2_key)
        if compressed is None:
            raise PayloadIntegrityError("R2_PAYLOAD_MISSING")
        return self._payload_from_compressed(receipt, compressed)

    def reconcile_pending_receipts(self) -> int:
        """Materialize receipts proven by an immutable recovery intent.

        Recovery is deliberately narrow: the canonical intent contains the
        exact compressed payload and receipt, its key must match the receipt
        hash, every deterministic R2 key must match, and the payload must pass
        the complete hash/size validation. Payload objects without such an
        attributable intent remain namespace-integrity failures.
        """

        prefix = f"{R2_RECOVERY_NAMESPACE}/{R2_SCHEMA_VERSION}/"
        recovered = 0
        for key in sorted(set(self.store.iter_keys(prefix))):
            match = _RECOVERY_INTENT_KEY_PATTERN.fullmatch(key)
            body = self.store.get_object(key)
            if match is None or body is None:
                raise ReceiptRecoveryIntegrityError(
                    "R2_RECEIPT_RECOVERY_INTENT_INVALID"
                )
            try:
                intent_data = json.loads(body)
                if (
                    not isinstance(intent_data, dict)
                    or set(intent_data)
                    != {
                        "schema_version",
                        "receipt",
                        "compressed_payload_base64",
                        "compressed_payload_sha256",
                    }
                    or intent_data.get("schema_version")
                    != R2_RECOVERY_SCHEMA_VERSION
                    or canonical_json_bytes(intent_data) != body
                    or not isinstance(
                        intent_data.get("compressed_payload_base64"),
                        str,
                    )
                    or not isinstance(
                        intent_data.get("compressed_payload_sha256"),
                        str,
                    )
                ):
                    raise ValueError("RECOVERY_INTENT_CONTRACT_INVALID")
                receipt = CaptureReceipt.model_validate(
                    intent_data.get("receipt")
                )
                canonical_receipt = canonical_json_bytes(
                    receipt.model_dump(mode="json")
                )
                compressed_payload = base64.b64decode(
                    intent_data["compressed_payload_base64"],
                    validate=True,
                )
            except (
                binascii.Error,
                UnicodeDecodeError,
                json.JSONDecodeError,
                TypeError,
                ValueError,
            ) as error:
                raise ReceiptRecoveryIntegrityError(
                    "R2_RECEIPT_RECOVERY_INTENT_INVALID"
                ) from error
            expected_payload_key, expected_receipt_key = deterministic_r2_keys(
                _context_from_receipt(receipt),
                receipt.payload_sha256,
            )
            if (
                match.group("receipt_hash") != receipt.receipt_hash
                or receipt.r2_key != expected_payload_key
                or receipt.receipt_r2_key != expected_receipt_key
                or key != _recovery_intent_key(receipt)
                or intent_data["compressed_payload_sha256"]
                != hashlib.sha256(compressed_payload).hexdigest()
            ):
                raise ReceiptRecoveryIntegrityError(
                    "R2_RECEIPT_RECOVERY_INTENT_MISMATCH"
                )
            try:
                self._payload_from_compressed(receipt, compressed_payload)
                payload_created = self._put_immutable(
                    self.store,
                    receipt.r2_key,
                    compressed_payload,
                )
                receipt_created = self._put_immutable(
                    self.store,
                    receipt.receipt_r2_key,
                    canonical_receipt,
                )
            except AppendOnlyViolation as error:
                raise ReceiptRecoveryIntegrityError(
                    "R2_RECEIPT_RECOVERY_CONFLICT"
                ) from error
            except PayloadIntegrityError as error:
                raise ReceiptRecoveryIntegrityError(
                    "R2_RECEIPT_RECOVERY_PAYLOAD_INVALID"
                ) from error
            recovered += int(payload_created) + int(receipt_created)
        return recovered

    def inventory_namespace(self) -> R2NamespaceInventory:
        """Recover attributed writes, then validate every raw namespace object."""

        self.reconcile_pending_receipts()
        namespace_prefix = f"{self.namespace}/"
        recovery_prefix = (
            f"{R2_RECOVERY_NAMESPACE}/{R2_SCHEMA_VERSION}/"
        )
        recovery_keys = tuple(
            sorted(set(self.store.iter_keys(recovery_prefix)))
        )
        physical_recovery_bytes = 0
        for key in recovery_keys:
            if _RECOVERY_INTENT_KEY_PATTERN.fullmatch(key) is None:
                raise ReceiptRecoveryIntegrityError(
                    "R2_RECEIPT_RECOVERY_INTENT_INVALID"
                )
            body = self.store.get_object(key)
            if body is None:
                raise ReceiptRecoveryIntegrityError(
                    "R2_RECEIPT_RECOVERY_INTENT_INVALID"
                )
            physical_recovery_bytes += len(body)
        keys = tuple(sorted(set(self.store.iter_keys(namespace_prefix))))
        payload_keys: set[str] = set()
        receipt_object_keys: set[str] = set()
        unexpected_keys: set[str] = set()
        unreadable_keys: set[str] = set()
        integrity_error_keys: set[str] = set()
        integrity_errors: set[str] = set()
        payload_inspections: dict[str, _PayloadInspection] = {}
        receipts: dict[str, tuple[CaptureReceipt, int]] = {}
        physical_unique_bytes = 0
        physical_payload_bytes = 0
        physical_receipt_bytes = 0

        def flag_integrity(key: str, code: str) -> None:
            integrity_error_keys.add(key)
            integrity_errors.add(f"{code}:{key}")

        for key in keys:
            match = _OBJECT_KEY_PATTERN.fullmatch(key)
            body = self.store.get_object(key)
            if body is None:
                unreadable_keys.add(key)
            else:
                physical_unique_bytes += len(body)

            if match is None:
                unexpected_keys.add(key)
                continue

            payload_hash = match.group("payload_hash")
            if payload_hash is not None:
                payload_keys.add(key)
                if body is None:
                    continue
                physical_payload_bytes += len(body)
                try:
                    canonical_payload = gzip.decompress(body)
                    payload = json.loads(canonical_payload)
                    recanonicalized = canonical_json_bytes(payload)
                except (
                    gzip.BadGzipFile,
                    EOFError,
                    zlib.error,
                    UnicodeDecodeError,
                    json.JSONDecodeError,
                    TypeError,
                    ValueError,
                ):
                    flag_integrity(key, "R2_PAYLOAD_INVALID")
                    payload_inspections[key] = _PayloadInspection(
                        stored_bytes=len(body),
                        payload_bytes=None,
                        payload_sha256=None,
                        valid=False,
                    )
                    continue

                actual_hash = hashlib.sha256(canonical_payload).hexdigest()
                valid = True
                if recanonicalized != canonical_payload:
                    flag_integrity(key, "R2_PAYLOAD_NOT_CANONICAL")
                    valid = False
                if actual_hash != payload_hash:
                    flag_integrity(key, "R2_PAYLOAD_KEY_HASH_MISMATCH")
                    valid = False
                if not _has_deterministic_gzip_header(body):
                    flag_integrity(key, "R2_PAYLOAD_GZIP_HEADER_INVALID")
                    valid = False
                payload_inspections[key] = _PayloadInspection(
                    stored_bytes=len(body),
                    payload_bytes=len(canonical_payload),
                    payload_sha256=actual_hash,
                    valid=valid,
                )
                continue

            receipt_object_keys.add(key)
            if body is None:
                continue
            physical_receipt_bytes += len(body)
            try:
                receipt_data = json.loads(body)
                receipt = CaptureReceipt.model_validate(receipt_data)
                canonical_receipt = canonical_json_bytes(
                    receipt.model_dump(mode="json")
                )
            except (
                UnicodeDecodeError,
                json.JSONDecodeError,
                TypeError,
                ValueError,
            ):
                flag_integrity(key, "R2_RECEIPT_INVALID")
                continue

            valid_receipt = True
            if canonical_receipt != body:
                flag_integrity(key, "R2_RECEIPT_NOT_CANONICAL")
                valid_receipt = False
            expected_payload_key, expected_receipt_key = deterministic_r2_keys(
                _context_from_receipt(receipt),
                receipt.payload_sha256,
            )
            if (
                receipt.r2_key != expected_payload_key
                or receipt.receipt_r2_key != expected_receipt_key
                or key != expected_receipt_key
            ):
                flag_integrity(key, "R2_RECEIPT_KEY_MISMATCH")
                valid_receipt = False
            if valid_receipt:
                receipts[key] = (receipt, len(body))

        referenced_payload_keys: set[str] = set()
        orphan_receipt_keys: set[str] = set()
        logical_payload_bytes_read = 0
        logical_receipt_bytes_read = 0
        for receipt_key, (receipt, receipt_bytes) in receipts.items():
            logical_receipt_bytes_read += receipt_bytes
            referenced_payload_keys.add(receipt.r2_key)
            payload_inspection = payload_inspections.get(receipt.r2_key)
            if payload_inspection is None:
                orphan_receipt_keys.add(receipt_key)
                continue

            logical_payload_bytes_read += payload_inspection.stored_bytes
            if not payload_inspection.valid:
                continue
            if (
                payload_inspection.payload_sha256 != receipt.payload_sha256
                or payload_inspection.payload_bytes != receipt.payload_bytes
                or payload_inspection.stored_bytes != receipt.stored_bytes
            ):
                flag_integrity(receipt_key, "R2_RECEIPT_PAYLOAD_MISMATCH")

        orphan_payload_keys = payload_keys - referenced_payload_keys
        return R2NamespaceInventory(
            namespace_prefix=namespace_prefix,
            physical_unique_objects=len(keys) + len(recovery_keys),
            physical_unique_bytes=(
                physical_unique_bytes + physical_recovery_bytes
            ),
            physical_payload_objects=len(payload_keys),
            physical_payload_bytes=physical_payload_bytes,
            physical_receipt_objects=len(receipt_object_keys),
            physical_receipt_bytes=physical_receipt_bytes,
            physical_recovery_objects=len(recovery_keys),
            physical_recovery_bytes=physical_recovery_bytes,
            logical_references=len(receipts),
            logical_payload_bytes_read=logical_payload_bytes_read,
            logical_receipt_bytes_read=logical_receipt_bytes_read,
            payload_keys=tuple(sorted(payload_keys)),
            receipt_keys=tuple(sorted(receipts)),
            recovery_keys=recovery_keys,
            orphan_payload_keys=tuple(sorted(orphan_payload_keys)),
            orphan_receipt_keys=tuple(sorted(orphan_receipt_keys)),
            unexpected_keys=tuple(sorted(unexpected_keys)),
            unreadable_keys=tuple(sorted(unreadable_keys)),
            integrity_error_keys=tuple(sorted(integrity_error_keys)),
            integrity_errors=tuple(sorted(integrity_errors)),
        )

    def read_capture(self, receipt_key: str) -> StoredCapture:
        receipt_bytes = self.store.get_object(receipt_key)
        if receipt_bytes is None:
            raise FileNotFoundError(receipt_key)
        try:
            receipt_data = json.loads(receipt_bytes)
            receipt = CaptureReceipt.model_validate(receipt_data)
            canonical_receipt = canonical_json_bytes(
                receipt.model_dump(mode="json")
            )
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            TypeError,
            ValueError,
        ) as error:
            raise PayloadIntegrityError("R2_RECEIPT_INVALID") from error
        expected_keys = deterministic_r2_keys(
            _context_from_receipt(receipt),
            receipt.payload_sha256,
        )
        if (
            canonical_receipt != receipt_bytes
            or receipt.r2_key != expected_keys[0]
            or receipt.receipt_r2_key != expected_keys[1]
            or receipt_key != expected_keys[1]
        ):
            raise PayloadIntegrityError("R2_RECEIPT_KEY_OR_BODY_MISMATCH")
        payload = self._payload_for_receipt(receipt)
        return StoredCapture(
            receipt=receipt,
            payload=payload,
            payload_created=False,
            receipt_created=False,
        )

    def iter_captures(self) -> Iterator[StoredCapture]:
        inventory = self.inventory_namespace()
        if not inventory.verified:
            raise R2NamespaceIntegrityError(inventory)
        for receipt_key in inventory.receipt_keys:
            yield self.read_capture(receipt_key)
