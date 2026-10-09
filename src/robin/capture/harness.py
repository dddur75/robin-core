"""Fail-closed orchestration for offline validation and future canary captures."""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from threading import Lock
from typing import Literal

from pydantic import Field

from robin.capture.bootstrap_contracts import FixtureTargetSetV1, LiveCaptureLineageV2
from robin.capture.contracts import (
    MAX_SIGNED_64,
    SECRET_ENV_NAME,
    AdmissionStatus,
    CaptureBudget,
    CaptureContractError,
    CaptureManifest,
    CaptureMode,
    FixtureMapping,
    FrozenContract,
    JsonValue,
    NormalizedMarketObservation,
    ProviderRequestSpec,
    QuotaObservation,
    RawPayloadReceipt,
    RequestFingerprint,
    SchemaFingerprint,
    canonical_json_bytes,
    ensure_utc,
)
from robin.capture.fixture_mapping import (
    PostCaptureFixtureMappingV1,
    PostCaptureMappingError,
    derive_post_capture_fixture_mappings_v1,
)
from robin.capture.live_contracts import (
    LiveAdmissionPermitV1,
    LiveCaptureLineageV1,
    LiveResponseIntakeClaimV1,
)
from robin.capture.normalization import (
    CaptureValidationError,
    decode_json_payload,
    normalize_payload,
    normalize_payload_v2,
    normalized_jsonl_bytes,
    schema_fingerprint,
    snapshot_id_for_observation_rows,
)
from robin.capture.storage import CaptureStorageError, CaptureStore

LIVE_CANARY_AUTHORIZED = False
DEFAULT_CAPTURE_MODE = CaptureMode.VALIDATE_OFFLINE


class CaptureGuardError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class CaptureRejected(RuntimeError):
    def __init__(self, code: str, *, receipt_id: str, payload_sha256: str) -> None:
        self.code = code
        self.receipt_id = receipt_id
        self.payload_sha256 = payload_sha256
        super().__init__(code)


class SecretCapability(FrozenContract):
    """Proof that a secret exists without retaining its value."""

    source_environment_variable: Literal["THE_ODDS_API_KEY"] = "THE_ODDS_API_KEY"
    present: Literal[True] = True
    exposure_checked: Literal[True] = True
    secret_value_retained: Literal[False] = False

    @classmethod
    def from_environment(
        cls,
        environment: Mapping[str, str],
        *,
        public_material: bytes,
    ) -> SecretCapability:
        if not public_material:
            raise CaptureGuardError("CAPTURE_PUBLIC_MATERIAL_REQUIRED")
        secret = environment.get(SECRET_ENV_NAME)
        if secret is None or not secret.strip():
            raise CaptureGuardError("CAPTURE_SECRET_MISSING")
        encoded = secret.encode("utf-8")
        if encoded in public_material:
            raise CaptureGuardError("CAPTURE_SECRET_EXPOSABLE")
        return cls()


class CapturePreparation(FrozenContract):
    mode: Literal["VALIDATE_OFFLINE", "DRY_RUN"]
    fingerprint: RequestFingerprint
    reserved_budget: CaptureBudget
    estimated_requests: int = Field(gt=0)
    estimated_credits: int = Field(ge=0)
    network_calls: Literal[0] = 0
    provider_calls: Literal[0] = 0
    secret_reads: Literal[0] = 0


@dataclass(frozen=True, slots=True)
class _ReceiptMaterial:
    intake_receipt_id: str | None
    request_fingerprint_sha256: str
    payload_sha256: str
    payload_byte_length: int
    http_status: int
    robin_first_observed_at: datetime
    robin_ingested_at: datetime
    raw_storage_key: str | None
    schema_fingerprint_sha256: str | None
    admission_status: AdmissionStatus
    rejection_code: str | None


def _safe_integer_header(headers: Mapping[str, str], name: str) -> int | None:
    normalized = {key.casefold(): value for key, value in headers.items()}
    value = normalized.get(name)
    if value is None:
        return None
    if not value.isascii() or not value.isdigit():
        raise CaptureValidationError("CAPTURE_QUOTA_HEADERS_INVALID")
    parsed = int(value)
    if parsed < 0 or parsed > MAX_SIGNED_64:
        raise CaptureValidationError("CAPTURE_QUOTA_HEADERS_INVALID")
    return parsed


def _quota_observation(
    headers: Mapping[str, str],
    *,
    observed_at: datetime,
    estimated_credits: int,
) -> QuotaObservation:
    quota = QuotaObservation(
        requests_remaining=_safe_integer_header(headers, "x-requests-remaining"),
        requests_used=_safe_integer_header(headers, "x-requests-used"),
        requests_last=_safe_integer_header(headers, "x-requests-last"),
        observed_at=observed_at,
    )
    if None in (
        quota.requests_remaining,
        quota.requests_used,
        quota.requests_last,
    ):
        raise CaptureValidationError("CAPTURE_QUOTA_HEADERS_MISSING")
    if quota.requests_last is not None and quota.requests_last != estimated_credits:
        raise CaptureValidationError("CAPTURE_QUOTA_RECONCILIATION_FAILED")
    if (
        quota.requests_used is not None
        and quota.requests_last is not None
        and quota.requests_used < quota.requests_last
    ):
        raise CaptureValidationError("CAPTURE_QUOTA_RECONCILIATION_FAILED")
    return quota


def _build_receipt(
    material: _ReceiptMaterial,
    *,
    quota: QuotaObservation | None,
) -> RawPayloadReceipt:
    return RawPayloadReceipt.issue(
        intake_receipt_id=material.intake_receipt_id,
        request_fingerprint_sha256=material.request_fingerprint_sha256,
        payload_sha256=material.payload_sha256,
        payload_byte_length=material.payload_byte_length,
        http_status=material.http_status,
        quota=quota,
        robin_first_observed_at=material.robin_first_observed_at,
        robin_ingested_at=material.robin_ingested_at,
        available_at=material.robin_first_observed_at,
        raw_expires_at=material.robin_first_observed_at + timedelta(days=30),
        raw_storage_key=material.raw_storage_key,
        schema_fingerprint_sha256=material.schema_fingerprint_sha256,
        admission_status=material.admission_status,
        rejection_code=material.rejection_code,
    )


class CaptureHarness:
    """Offline capture recorder; it intentionally contains no network transport."""

    def __init__(
        self,
        store: CaptureStore,
        budget: CaptureBudget | None,
        *,
        maximum_payload_bytes: int = 1_048_576,
    ) -> None:
        if budget is None:
            raise CaptureGuardError("CAPTURE_BUDGET_REQUIRED")
        if maximum_payload_bytes <= 0:
            raise CaptureGuardError("CAPTURE_PAYLOAD_LIMIT_INVALID")
        self.store = store
        self._budget = budget
        self._budget_lock = Lock()
        self.maximum_payload_bytes = maximum_payload_bytes

    @property
    def current_budget(self) -> CaptureBudget:
        return self._budget

    def prepare(
        self,
        request: ProviderRequestSpec,
        *,
        mode: CaptureMode | str = DEFAULT_CAPTURE_MODE,
    ) -> CapturePreparation:
        return self._prepare(request, mode=mode, consume_budget=False)

    def _prepare(
        self,
        request: ProviderRequestSpec,
        *,
        mode: CaptureMode | str,
        consume_budget: bool,
    ) -> CapturePreparation:
        try:
            validated_mode = CaptureMode(mode)
        except ValueError:
            raise CaptureGuardError("CAPTURE_MODE_INVALID") from None
        if validated_mode is CaptureMode.LIVE_CANARY:
            # This gate deliberately runs before any environment or secret read.
            raise CaptureGuardError("ROBIN_LIVE_CANARY_DISABLED_NOT_AUTHORIZED")
        estimated_requests = 1
        credits = len(request.markets)
        with self._budget_lock:
            try:
                reserved = self.store.reserve_budget(
                    self._budget,
                    requests=estimated_requests,
                    credits=credits,
                    consume=consume_budget,
                )
            except ValueError as exc:
                raise CaptureGuardError(str(exc)) from None
            if consume_budget:
                self._budget = reserved
        prepared_mode: Literal["VALIDATE_OFFLINE", "DRY_RUN"] = (
            "DRY_RUN" if validated_mode is CaptureMode.DRY_RUN else "VALIDATE_OFFLINE"
        )
        return CapturePreparation(
            mode=prepared_mode,
            fingerprint=RequestFingerprint.create(request),
            reserved_budget=reserved,
            estimated_requests=estimated_requests,
            estimated_credits=credits,
        )

    def record_offline_response(
        self,
        request: ProviderRequestSpec,
        *,
        payload: bytes,
        http_status: int,
        response_headers: Mapping[str, str],
        mappings: tuple[FixtureMapping, ...],
        first_observed_at: datetime,
        ingested_at: datetime,
    ) -> CaptureManifest:
        with self.store.capture_transaction():
            return self._record_offline_response_locked(
                request,
                payload=payload,
                http_status=http_status,
                response_headers=response_headers,
                mappings=mappings,
                first_observed_at=first_observed_at,
                ingested_at=ingested_at,
            )

    def _record_offline_response_locked(
        self,
        request: ProviderRequestSpec,
        *,
        payload: bytes,
        http_status: int,
        response_headers: Mapping[str, str],
        mappings: tuple[FixtureMapping, ...],
        first_observed_at: datetime,
        ingested_at: datetime,
    ) -> CaptureManifest:
        preparation = self._prepare(
            request,
            mode=CaptureMode.VALIDATE_OFFLINE,
            consume_budget=True,
        )
        return self._record_response_locked(
            request,
            fingerprint=preparation.fingerprint,
            estimated_credits=preparation.estimated_credits,
            payload=payload,
            http_status=http_status,
            response_headers=response_headers,
            mappings=mappings,
            first_observed_at=first_observed_at,
            ingested_at=ingested_at,
            manifest_mode="VALIDATE_OFFLINE",
            network_calls=0,
            provider_calls=0,
            live_canary_authorized=False,
        )

    def record_live_response(
        self,
        request: ProviderRequestSpec,
        *,
        expected_request_fingerprint_sha256: str,
        payload: bytes,
        http_status: int,
        response_headers: Mapping[str, str],
        mappings: tuple[FixtureMapping, ...],
        admission_permit: LiveAdmissionPermitV1,
        first_observed_at: datetime,
        ingested_at: datetime,
        stage_observer: Callable[[str], None] | None = None,
    ) -> CaptureManifest:
        """Admit an already budgeted, single-dispatch live response."""

        fingerprint = RequestFingerprint.create(request)
        permit = LiveAdmissionPermitV1.model_validate(admission_permit.model_dump(mode="json"))
        from robin.capture.live_storage import LiveStateStore

        live_state = LiveStateStore(self.store)
        permit = live_state.verify_admission_permit(
            permit,
            consume=False,
        )
        if fingerprint.request_sha256 != expected_request_fingerprint_sha256:
            raise CaptureGuardError("LIVE_REQUEST_FINGERPRINT_MISMATCH")
        if (
            permit.capture_root_fingerprint != self.store.capture_root_fingerprint()
            or permit.request_fingerprint_sha256 != fingerprint.request_sha256
            or permit.reserved_credits != len(request.markets)
        ):
            raise CaptureGuardError("LIVE_ADMISSION_PERMIT_MISMATCH")
        response_intake_claim = live_state.claim_live_response_intake(
            permit,
            payload_sha256=hashlib.sha256(payload).hexdigest(),
            payload_byte_length=len(payload),
            first_observed_at=first_observed_at,
            ingested_at=ingested_at,
        )
        with self.store.capture_transaction():
            return self._record_response_locked(
                request,
                fingerprint=fingerprint,
                estimated_credits=len(request.markets),
                payload=payload,
                http_status=http_status,
                response_headers=response_headers,
                mappings=mappings,
                first_observed_at=first_observed_at,
                ingested_at=ingested_at,
                manifest_mode="LIVE_CANARY",
                network_calls=1,
                provider_calls=1,
                live_canary_authorized=True,
                exact_response_markets=request.markets,
                expected_response_sport_key=request.sport_key,
                live_admission_permit=permit,
                live_response_intake_claim=response_intake_claim,
                stage_observer=stage_observer,
            )

    def record_live_response_v2(
        self,
        request: ProviderRequestSpec,
        *,
        expected_request_fingerprint_sha256: str,
        payload: bytes,
        http_status: int,
        response_headers: Mapping[str, str],
        fixture_target_set: FixtureTargetSetV1,
        provider_network_binding_sha256: str,
        admission_permit: LiveAdmissionPermitV1,
        first_observed_at: datetime,
        ingested_at: datetime,
        stage_observer: Callable[[str], None] | None = None,
    ) -> CaptureManifest:
        """Admit V2 bytes and learn provider IDs only after durable raw evidence."""

        fingerprint = RequestFingerprint.create(request)
        permit = LiveAdmissionPermitV1.model_validate(admission_permit.model_dump(mode="json"))
        targets = FixtureTargetSetV1.model_validate(fixture_target_set.model_dump(mode="json"))
        from robin.capture.live_storage import LiveStateStore

        live_state = LiveStateStore(self.store)
        permit = live_state.verify_admission_permit(permit, consume=False)
        try:
            stored_targets = self.store.load_fixture_target_set(targets.canonical_set_hash)
        except CaptureStorageError:
            raise CaptureGuardError("LIVE_FIXTURE_TARGET_SET_NOT_DURABLE") from None
        if fingerprint.request_sha256 != expected_request_fingerprint_sha256:
            raise CaptureGuardError("LIVE_REQUEST_FINGERPRINT_MISMATCH")
        if (
            permit.capture_root_fingerprint != self.store.capture_root_fingerprint()
            or permit.request_fingerprint_sha256 != fingerprint.request_sha256
            or permit.reserved_credits != len(request.markets)
            or targets.sport_key != request.sport_key
            or stored_targets != targets
        ):
            raise CaptureGuardError("LIVE_ADMISSION_PERMIT_MISMATCH")
        response_intake_claim = live_state.claim_live_response_intake(
            permit,
            payload_sha256=hashlib.sha256(payload).hexdigest(),
            payload_byte_length=len(payload),
            first_observed_at=first_observed_at,
            ingested_at=ingested_at,
        )
        with self.store.capture_transaction():
            return self._record_response_locked(
                request,
                fingerprint=fingerprint,
                estimated_credits=len(request.markets),
                payload=payload,
                http_status=http_status,
                response_headers=response_headers,
                mappings=(),
                fixture_target_set=targets,
                provider_network_binding_sha256=provider_network_binding_sha256,
                first_observed_at=first_observed_at,
                ingested_at=ingested_at,
                manifest_mode="LIVE_CANARY",
                network_calls=1,
                provider_calls=1,
                live_canary_authorized=True,
                exact_response_markets=request.markets,
                expected_response_sport_key=request.sport_key,
                live_admission_permit=permit,
                live_response_intake_claim=response_intake_claim,
                stage_observer=stage_observer,
            )

    def _record_response_locked(
        self,
        request: ProviderRequestSpec,
        *,
        fingerprint: RequestFingerprint,
        estimated_credits: int,
        payload: bytes,
        http_status: int,
        response_headers: Mapping[str, str],
        mappings: tuple[FixtureMapping, ...],
        fixture_target_set: FixtureTargetSetV1 | None = None,
        provider_network_binding_sha256: str | None = None,
        first_observed_at: datetime,
        ingested_at: datetime,
        manifest_mode: Literal["VALIDATE_OFFLINE", "LIVE_CANARY"],
        network_calls: Literal[0, 1],
        provider_calls: Literal[0, 1],
        live_canary_authorized: bool,
        exact_response_markets: tuple[str, ...] | None = None,
        expected_response_sport_key: str | None = None,
        live_admission_permit: LiveAdmissionPermitV1 | None = None,
        live_response_intake_claim: LiveResponseIntakeClaimV1 | None = None,
        stage_observer: Callable[[str], None] | None = None,
    ) -> CaptureManifest:
        def observe(stage: str) -> None:
            if stage_observer is not None:
                stage_observer(stage)

        if fixture_target_set is None:
            if provider_network_binding_sha256 is not None:
                raise CaptureGuardError("CAPTURE_V2_BINDING_INCOMPLETE")
        elif mappings or provider_network_binding_sha256 is None:
            raise CaptureGuardError("CAPTURE_V2_BINDING_INCOMPLETE")

        observed = ensure_utc(first_observed_at, field="first_observed_at")
        ingested = ensure_utc(ingested_at, field="ingested_at")
        if ingested < observed:
            raise CaptureGuardError("CAPTURE_INGESTED_BEFORE_OBSERVED")
        if not 100 <= http_status <= 599:
            raise CaptureGuardError("CAPTURE_HTTP_STATUS_INVALID")

        # A provisional TTL-governed receipt is durable before raw bytes are written.
        # The raw SHA-256 and content-addressed write still precede all parsing.
        payload_sha256 = hashlib.sha256(payload).hexdigest()
        observe("RAW_SHA256_COMPUTED")
        if len(payload) > self.maximum_payload_bytes:
            oversized_material = _ReceiptMaterial(
                intake_receipt_id=None,
                request_fingerprint_sha256=fingerprint.request_sha256,
                payload_sha256=payload_sha256,
                payload_byte_length=len(payload),
                http_status=http_status,
                robin_first_observed_at=observed,
                robin_ingested_at=ingested,
                raw_storage_key=None,
                schema_fingerprint_sha256=None,
                admission_status=AdmissionStatus.QUARANTINED,
                rejection_code="CAPTURE_PAYLOAD_TOO_LARGE",
            )
            oversized_receipt = _build_receipt(oversized_material, quota=None)
            self.store.store_receipt(oversized_receipt)
            observe("FINAL_RECEIPT_DURABLE")
            self.store.store_quarantine(oversized_receipt)
            raise CaptureRejected(
                "CAPTURE_PAYLOAD_TOO_LARGE",
                receipt_id=oversized_receipt.receipt_id,
                payload_sha256=payload_sha256,
            )
        expected_raw_key = f"raw/sha256/{payload_sha256[:2]}/{payload_sha256}.bin"
        intake_material = _ReceiptMaterial(
            intake_receipt_id=None,
            request_fingerprint_sha256=fingerprint.request_sha256,
            payload_sha256=payload_sha256,
            payload_byte_length=len(payload),
            http_status=http_status,
            robin_first_observed_at=observed,
            robin_ingested_at=ingested,
            raw_storage_key=expected_raw_key,
            schema_fingerprint_sha256=None,
            admission_status=AdmissionStatus.INTAKE_PENDING,
            rejection_code=None,
        )
        intake_receipt = _build_receipt(intake_material, quota=None)
        self.store.store_receipt(intake_receipt)
        observe("INTAKE_RECEIPT_DURABLE")
        stored_sha256, raw_storage_key = self.store.store_raw(payload)
        observe("RAW_CONTENT_ADDRESSED_DURABLE")
        if stored_sha256 != payload_sha256 or raw_storage_key != expected_raw_key:
            raise CaptureGuardError("CAPTURE_RAW_HASH_MISMATCH")

        rejection_code: str | None = None
        decoded: JsonValue | None = None
        schema: SchemaFingerprint | None = None
        quota: QuotaObservation | None = None
        normalized: tuple[NormalizedMarketObservation, ...] = ()
        mapping_evidence: PostCaptureFixtureMappingV1 | None = None
        v2_snapshot_id: str | None = None
        lowered_headers = {key.casefold(): value for key, value in response_headers.items()}

        if 300 <= http_status <= 399 or "location" in lowered_headers:
            rejection_code = "CAPTURE_REDIRECT_FORBIDDEN"
        elif http_status != 200:
            rejection_code = "CAPTURE_HTTP_STATUS_REJECTED"
        else:
            try:
                quota = _quota_observation(
                    response_headers,
                    observed_at=ingested,
                    estimated_credits=estimated_credits,
                )
                observe("PARSE_STARTED")
                decoded = decode_json_payload(payload)
                schema = schema_fingerprint(decoded)
                observe("SCHEMA_FINGERPRINT_COMPUTED")
                if fixture_target_set is not None:
                    durable_intake = self.store.load_receipt(intake_receipt.receipt_id)
                    durable_raw = self.store.load_raw(durable_intake)
                    if durable_raw != payload:
                        raise PostCaptureMappingError("POST_CAPTURE_RAW_HASH_MISMATCH")
                    observe("IDENTITY_ENVELOPE_PARSE_STARTED")
                    mapping_evidence = derive_post_capture_fixture_mappings_v1(
                        durable_raw,
                        target_set=fixture_target_set,
                        intake_receipt=durable_intake,
                        raw_storage_key=raw_storage_key,
                    )
                    observe("POST_CAPTURE_MAPPING_DERIVED")
                    self.store.store_post_capture_fixture_mapping(mapping_evidence)
                    mappings = mapping_evidence.mappings
                    observe("POST_CAPTURE_MAPPING_EVIDENCE_DURABLE")
            except (
                CaptureValidationError,
                CaptureContractError,
                PostCaptureMappingError,
            ) as exc:
                rejection_code = exc.code

        admitted_material = _ReceiptMaterial(
            intake_receipt_id=intake_receipt.receipt_id,
            request_fingerprint_sha256=fingerprint.request_sha256,
            payload_sha256=payload_sha256,
            payload_byte_length=len(payload),
            http_status=http_status,
            robin_first_observed_at=observed,
            robin_ingested_at=ingested,
            raw_storage_key=raw_storage_key,
            schema_fingerprint_sha256=(schema.schema_sha256 if schema is not None else None),
            admission_status=AdmissionStatus.ADMITTED,
            rejection_code=None,
        )
        admitted_receipt = _build_receipt(admitted_material, quota=quota)

        if rejection_code is None and decoded is not None:
            try:
                if mapping_evidence is None:
                    schema, normalized = normalize_payload(
                        decoded,
                        receipt=admitted_receipt,
                        mappings=mappings,
                        allowed_markets=exact_response_markets,
                        expected_sport_key=expected_response_sport_key,
                    )
                else:
                    schema, normalized, v2_snapshot_id = normalize_payload_v2(
                        decoded,
                        receipt=admitted_receipt,
                        mapping_evidence=mapping_evidence,
                        allowed_markets=exact_response_markets,
                        expected_sport_key=expected_response_sport_key,
                    )
                observe("NORMALIZATION_COMPLETED")
            except (CaptureValidationError, CaptureContractError) as exc:
                rejection_code = exc.code

        if rejection_code is not None:
            rejected_material = _ReceiptMaterial(
                intake_receipt_id=intake_receipt.receipt_id,
                request_fingerprint_sha256=fingerprint.request_sha256,
                payload_sha256=payload_sha256,
                payload_byte_length=len(payload),
                http_status=http_status,
                robin_first_observed_at=observed,
                robin_ingested_at=ingested,
                raw_storage_key=raw_storage_key,
                schema_fingerprint_sha256=(schema.schema_sha256 if schema is not None else None),
                admission_status=AdmissionStatus.QUARANTINED,
                rejection_code=rejection_code,
            )
            rejected_receipt = _build_receipt(rejected_material, quota=quota)
            self.store.store_receipt(rejected_receipt)
            observe("FINAL_RECEIPT_DURABLE")
            self.store.store_quarantine(rejected_receipt)
            raise CaptureRejected(
                rejection_code,
                receipt_id=rejected_receipt.receipt_id,
                payload_sha256=payload_sha256,
            )

        if schema is None:
            raise CaptureGuardError("CAPTURE_SCHEMA_FINGERPRINT_MISSING")
        normalized_bytes = normalized_jsonl_bytes(normalized)
        normalized_sha256 = hashlib.sha256(normalized_bytes).hexdigest()
        snapshot_id = (
            normalized[0].snapshot_id
            if normalized
            else v2_snapshot_id
            if v2_snapshot_id is not None
            else snapshot_id_for_observation_rows(
                receipt_id=admitted_receipt.receipt_id,
                schema_fingerprint_sha256=schema.schema_sha256,
                mappings=mappings,
                observations=(),
            )
        )
        normalized_key = self.store.store_normalized(
            snapshot_id=snapshot_id,
            payload=normalized_bytes,
        )
        manifest = CaptureManifest.issue(
            snapshot_id=snapshot_id,
            receipt_id=admitted_receipt.receipt_id,
            request_fingerprint_sha256=fingerprint.request_sha256,
            raw_payload_sha256=payload_sha256,
            schema_fingerprint=schema,
            fixture_mappings=mappings,
            observation_count=len(normalized),
            normalized_sha256=normalized_sha256,
            normalized_storage_key=normalized_key,
            captured_at=ingested,
            mode=manifest_mode,
            network_calls=network_calls,
            provider_calls=provider_calls,
            live_canary_authorized=live_canary_authorized,
        )
        self.store.store_receipt(admitted_receipt)
        observe("FINAL_RECEIPT_DURABLE")
        if live_admission_permit is not None:
            if live_response_intake_claim is None:
                raise CaptureGuardError("LIVE_RESPONSE_INTAKE_CLAIM_MISSING")
            lineage: LiveCaptureLineageV1 | LiveCaptureLineageV2
            if mapping_evidence is None:
                lineage = LiveCaptureLineageV1.issue(
                    manifest_id=manifest.snapshot_id,
                    manifest_hash=manifest.manifest_sha256,
                    request=request,
                    request_fingerprint_sha256=fingerprint.request_sha256,
                    expected_sport_key=request.sport_key,
                    expected_region=request.region,
                    expected_markets=request.markets,
                    admission_permit=live_admission_permit,
                    response_intake_claim=live_response_intake_claim,
                )
            else:
                if fixture_target_set is None or provider_network_binding_sha256 is None:
                    raise CaptureGuardError("CAPTURE_V2_BINDING_INCOMPLETE")
                mapped_targets = len(mapping_evidence.mapped_target_ids)
                non_admitted_targets = len(mapping_evidence.unmatched_target_ids)
                lineage = LiveCaptureLineageV2.issue(
                    manifest_id=manifest.snapshot_id,
                    manifest_hash=manifest.manifest_sha256,
                    request=request,
                    request_fingerprint_sha256=fingerprint.request_sha256,
                    expected_sport_key=request.sport_key,
                    expected_region=request.region,
                    expected_markets=request.markets,
                    fixture_target_set_sha256=fixture_target_set.canonical_set_hash,
                    provider_network_binding_sha256=provider_network_binding_sha256,
                    post_capture_mapping_sha256=mapping_evidence.canonical_mapping_hash,
                    scientific_admission=(
                        "NONE"
                        if mapped_targets == 0
                        else "FULL"
                        if non_admitted_targets == 0
                        else "PARTIAL"
                    ),
                    mapped_target_count=mapped_targets,
                    non_admitted_target_count=non_admitted_targets,
                    mapped_provider_event_count=mapping_evidence.mapped_provider_event_count,
                    non_admitted_provider_event_count=(
                        mapping_evidence.non_admitted_provider_event_count
                    ),
                    admission_permit=live_admission_permit,
                    response_intake_claim=live_response_intake_claim,
                )
            self.store.store_live_capture_lineage(lineage)
            observe("LIVE_CAPTURE_LINEAGE_DURABLE")
        self.store.store_manifest(manifest)
        observe("MANIFEST_DURABLE")
        return manifest

    @staticmethod
    def public_preparation_bytes(preparation: CapturePreparation) -> bytes:
        return canonical_json_bytes(preparation.model_dump(mode="json"))
