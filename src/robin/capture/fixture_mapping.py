"""Deterministic post-capture mapping from provider events to official targets."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any, Literal, Self, cast

from pydantic import Field, model_validator

from robin.capture.bootstrap_contracts import (
    FIXTURE_MAPPING_REVISION,
    FixtureTargetSetV1,
    canonical_team_name_v1,
)
from robin.capture.contracts import (
    AdmissionStatus,
    FixtureMapping,
    FrozenContract,
    JsonValue,
    MappingStatus,
    RawPayloadReceipt,
    canonical_sha256,
)


class PostCaptureMappingError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class ProviderEventMappingOutcomeV1(FrozenContract):
    provider_event_id: str = Field(min_length=1, max_length=160)
    status: Literal["MAPPED", "AMBIGUOUS", "UNMAPPED"]
    candidate_fixture_target_ids: tuple[str, ...]
    admitted_fixture_target_id: str | None = None

    @model_validator(mode="after")
    def validate_outcome(self) -> Self:
        if (
            tuple(sorted(set(self.candidate_fixture_target_ids)))
            != self.candidate_fixture_target_ids
        ):
            raise ValueError("PROVIDER_EVENT_MAPPING_CANDIDATES_NOT_CANONICAL")
        if self.status == "MAPPED":
            if self.admitted_fixture_target_id is None or self.candidate_fixture_target_ids != (
                self.admitted_fixture_target_id,
            ):
                raise ValueError("PROVIDER_EVENT_MAPPING_NOT_ONE_TO_ONE")
        elif self.admitted_fixture_target_id is not None:
            raise ValueError("PROVIDER_EVENT_MAPPING_NON_ADMITTED_TARGET_FORBIDDEN")
        if self.status == "AMBIGUOUS" and not self.candidate_fixture_target_ids:
            raise ValueError("PROVIDER_EVENT_MAPPING_AMBIGUITY_UNPROVEN")
        if self.status == "UNMAPPED" and self.candidate_fixture_target_ids:
            raise ValueError("PROVIDER_EVENT_MAPPING_UNMAPPED_HAS_CANDIDATES")
        return self


class FixtureTargetMappingOutcomeV1(FrozenContract):
    fixture_target_id: str = Field(min_length=1, max_length=160)
    status: Literal["MAPPED", "AMBIGUOUS", "UNMAPPED"]
    candidate_provider_event_ids: tuple[str, ...]
    admitted_provider_event_id: str | None = None

    @model_validator(mode="after")
    def validate_outcome(self) -> Self:
        if (
            tuple(sorted(set(self.candidate_provider_event_ids)))
            != self.candidate_provider_event_ids
        ):
            raise ValueError("FIXTURE_TARGET_MAPPING_CANDIDATES_NOT_CANONICAL")
        if self.status == "MAPPED":
            if self.admitted_provider_event_id is None or self.candidate_provider_event_ids != (
                self.admitted_provider_event_id,
            ):
                raise ValueError("FIXTURE_TARGET_MAPPING_NOT_ONE_TO_ONE")
        elif self.admitted_provider_event_id is not None:
            raise ValueError("FIXTURE_TARGET_MAPPING_NON_ADMITTED_EVENT_FORBIDDEN")
        if self.status == "UNMAPPED" and self.candidate_provider_event_ids:
            raise ValueError("FIXTURE_TARGET_MAPPING_UNMAPPED_HAS_CANDIDATES")
        if self.status == "AMBIGUOUS" and not self.candidate_provider_event_ids:
            raise ValueError("FIXTURE_TARGET_MAPPING_CONFLICT_UNPROVEN")
        return self


class PostCaptureFixtureMappingV1(FrozenContract):
    schema_version: Literal["robin-post-capture-fixture-mapping-v1"] = (
        "robin-post-capture-fixture-mapping-v1"
    )
    mapping_revision: Literal["exact-sport-kickoff-home-away-v1"] = FIXTURE_MAPPING_REVISION
    fixture_target_set_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    intake_receipt_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    raw_payload_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    raw_storage_key: str
    causal_prerequisites: tuple[
        Literal[
            "RAW_SHA256_COMPUTED",
            "INTAKE_RECEIPT_DURABLE",
            "RAW_CONTENT_ADDRESSED_DURABLE",
        ],
        ...,
    ] = (
        "RAW_SHA256_COMPUTED",
        "INTAKE_RECEIPT_DURABLE",
        "RAW_CONTENT_ADDRESSED_DURABLE",
    )
    mappings: tuple[FixtureMapping, ...]
    provider_event_outcomes: tuple[ProviderEventMappingOutcomeV1, ...]
    fixture_target_outcomes: tuple[FixtureTargetMappingOutcomeV1, ...]
    mapped_target_ids: tuple[str, ...]
    unmatched_target_ids: tuple[str, ...]
    one_to_one_conflict_event_ids: tuple[str, ...]
    mapped_provider_event_count: int = Field(ge=0)
    non_admitted_provider_event_count: int = Field(ge=0)
    canonical_mapping_hash: str = Field(pattern=r"^[0-9a-f]{64}$")

    def identity_material(self) -> dict[str, JsonValue]:
        return cast(
            dict[str, JsonValue],
            self.model_dump(mode="json", exclude={"canonical_mapping_hash"}),
        )

    @classmethod
    def issue(cls, **data: Any) -> Self:
        provisional = cls.model_construct(canonical_mapping_hash="0" * 64, **data)
        return cls(canonical_mapping_hash=canonical_sha256(provisional.identity_material()), **data)

    @model_validator(mode="after")
    def validate_mapping_evidence(self) -> Self:
        expected_key = f"raw/sha256/{self.raw_payload_sha256[:2]}/{self.raw_payload_sha256}.bin"
        if self.raw_storage_key != expected_key:
            raise ValueError("POST_CAPTURE_MAPPING_RAW_KEY_INVALID")
        if tuple(sorted(self.mappings, key=lambda item: item.provider_event_id)) != self.mappings:
            raise ValueError("POST_CAPTURE_MAPPINGS_NOT_CANONICAL")
        provider_ids = tuple(mapping.provider_event_id for mapping in self.mappings)
        if len(provider_ids) != len(set(provider_ids)):
            raise ValueError("POST_CAPTURE_PROVIDER_EVENT_DUPLICATED")
        if (
            tuple(
                sorted(
                    self.provider_event_outcomes,
                    key=lambda item: item.provider_event_id,
                )
            )
            != self.provider_event_outcomes
            or tuple(
                sorted(
                    self.fixture_target_outcomes,
                    key=lambda item: item.fixture_target_id,
                )
            )
            != self.fixture_target_outcomes
            or tuple(item.provider_event_id for item in self.provider_event_outcomes)
            != provider_ids
        ):
            raise ValueError("POST_CAPTURE_SYMMETRIC_OUTCOMES_NOT_CANONICAL")
        mapped = tuple(
            sorted(
                cast(str, mapping.fixture_id)
                for mapping in self.mappings
                if mapping.status is MappingStatus.MAPPED
            )
        )
        if mapped != self.mapped_target_ids or len(mapped) != len(set(mapped)):
            raise ValueError("POST_CAPTURE_MAPPING_NOT_ONE_TO_ONE")
        non_admitted = sum(mapping.status is not MappingStatus.MAPPED for mapping in self.mappings)
        if (
            self.mapped_provider_event_count != len(mapped)
            or self.non_admitted_provider_event_count != non_admitted
            or self.mapped_target_ids
            != tuple(
                item.fixture_target_id
                for item in self.fixture_target_outcomes
                if item.status == "MAPPED"
            )
            or self.unmatched_target_ids
            != tuple(
                item.fixture_target_id
                for item in self.fixture_target_outcomes
                if item.status != "MAPPED"
            )
            or tuple(sorted(self.unmatched_target_ids)) != self.unmatched_target_ids
            or tuple(sorted(self.one_to_one_conflict_event_ids))
            != self.one_to_one_conflict_event_ids
        ):
            raise ValueError("POST_CAPTURE_MAPPING_SUMMARY_INVALID")
        if self.canonical_mapping_hash != canonical_sha256(self.identity_material()):
            raise ValueError("POST_CAPTURE_MAPPING_HASH_MISMATCH")
        return self


def _provider_timestamp(value: object) -> datetime:
    if not isinstance(value, str) or len(value) > 80:
        raise PostCaptureMappingError("POST_CAPTURE_KICKOFF_INVALID")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise PostCaptureMappingError("POST_CAPTURE_KICKOFF_INVALID") from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise PostCaptureMappingError("POST_CAPTURE_KICKOFF_INVALID")
    return parsed.astimezone(UTC)


def _provider_string(value: object, *, code: str, maximum: int = 160) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise PostCaptureMappingError(code)
    return value


def derive_post_capture_fixture_mappings_v1(
    raw_payload: bytes,
    *,
    target_set: FixtureTargetSetV1,
    intake_receipt: RawPayloadReceipt,
    raw_storage_key: str,
) -> PostCaptureFixtureMappingV1:
    """Map only after the intake receipt and content-addressed raw key exist.

    Matching is exact after the single documented Unicode/whitespace/case rule.
    No alias table, edit distance, token similarity, or home/away reversal exists.
    """

    if not isinstance(raw_payload, bytes) or hashlib.sha256(raw_payload).hexdigest() != (
        intake_receipt.payload_sha256
    ):
        raise PostCaptureMappingError("POST_CAPTURE_RAW_HASH_MISMATCH")
    if (
        intake_receipt.admission_status is not AdmissionStatus.INTAKE_PENDING
        or intake_receipt.intake_receipt_id is not None
        or intake_receipt.raw_storage_key != raw_storage_key
    ):
        raise PostCaptureMappingError("POST_CAPTURE_CAUSAL_PREREQUISITE_MISSING")
    expected_key = (
        f"raw/sha256/{intake_receipt.payload_sha256[:2]}/{intake_receipt.payload_sha256}.bin"
    )
    if raw_storage_key != expected_key:
        raise PostCaptureMappingError("POST_CAPTURE_RAW_STORAGE_KEY_MISMATCH")
    from robin.capture.normalization import decode_json_payload

    decoded_payload = decode_json_payload(raw_payload)
    if not isinstance(decoded_payload, list):
        raise PostCaptureMappingError("POST_CAPTURE_PAYLOAD_ROOT_NOT_ARRAY")

    targets_by_identity: dict[tuple[str, datetime, str, str], list[str]] = {}
    all_target_ids: set[str] = set()
    for target in target_set.targets:
        targets_by_identity.setdefault(target.exact_identity_key(), []).append(
            target.internal_fixture_target_id
        )
        all_target_ids.add(target.internal_fixture_target_id)
    for values in targets_by_identity.values():
        values.sort()

    candidates_by_event: dict[str, tuple[str, ...]] = {}
    for raw_event in decoded_payload:
        if not isinstance(raw_event, dict):
            raise PostCaptureMappingError("POST_CAPTURE_EVENT_INVALID")
        event = cast(dict[str, object], raw_event)
        event_id = _provider_string(
            event.get("id"),
            code="POST_CAPTURE_PROVIDER_EVENT_ID_INVALID",
        )
        if event_id in candidates_by_event:
            raise PostCaptureMappingError("POST_CAPTURE_PROVIDER_EVENT_DUPLICATED")
        sport_key = _provider_string(
            event.get("sport_key"),
            code="POST_CAPTURE_SPORT_KEY_INVALID",
            maximum=120,
        )
        if sport_key != target_set.sport_key:
            candidates_by_event[event_id] = ()
            continue
        home = canonical_team_name_v1(
            _provider_string(event.get("home_team"), code="POST_CAPTURE_HOME_TEAM_INVALID")
        )
        away = canonical_team_name_v1(
            _provider_string(event.get("away_team"), code="POST_CAPTURE_AWAY_TEAM_INVALID")
        )
        kickoff = _provider_timestamp(event.get("commence_time"))
        candidates_by_event[event_id] = tuple(
            targets_by_identity.get((sport_key, kickoff, home, away), ())
        )

    events_by_target: dict[str, list[str]] = {target_id: [] for target_id in all_target_ids}
    for event_id, candidates in candidates_by_event.items():
        for target_id in candidates:
            events_by_target[target_id].append(event_id)
    for event_ids in events_by_target.values():
        event_ids.sort()
    conflicts = {
        event_id
        for event_ids in events_by_target.values()
        if len(event_ids) > 1
        for event_id in event_ids
    }

    mappings: list[FixtureMapping] = []
    provider_outcomes: list[ProviderEventMappingOutcomeV1] = []
    for event_id, candidates in sorted(candidates_by_event.items()):
        if event_id in conflicts:
            provider_outcomes.append(
                ProviderEventMappingOutcomeV1(
                    provider_event_id=event_id,
                    status="AMBIGUOUS",
                    candidate_fixture_target_ids=candidates,
                )
            )
            mappings.append(
                FixtureMapping(
                    provider_event_id=event_id,
                    fixture_id=None,
                    status=MappingStatus.UNMAPPED,
                    candidate_fixture_ids=(),
                    mapping_revision=FIXTURE_MAPPING_REVISION,
                )
            )
        elif not candidates:
            provider_outcomes.append(
                ProviderEventMappingOutcomeV1(
                    provider_event_id=event_id,
                    status="UNMAPPED",
                    candidate_fixture_target_ids=(),
                )
            )
            mappings.append(
                FixtureMapping(
                    provider_event_id=event_id,
                    fixture_id=None,
                    status=MappingStatus.UNMAPPED,
                    candidate_fixture_ids=(),
                    mapping_revision=FIXTURE_MAPPING_REVISION,
                )
            )
        elif len(candidates) == 1:
            provider_outcomes.append(
                ProviderEventMappingOutcomeV1(
                    provider_event_id=event_id,
                    status="MAPPED",
                    candidate_fixture_target_ids=candidates,
                    admitted_fixture_target_id=candidates[0],
                )
            )
            mappings.append(
                FixtureMapping(
                    provider_event_id=event_id,
                    fixture_id=candidates[0],
                    status=MappingStatus.MAPPED,
                    candidate_fixture_ids=candidates,
                    mapping_revision=FIXTURE_MAPPING_REVISION,
                )
            )
        else:
            provider_outcomes.append(
                ProviderEventMappingOutcomeV1(
                    provider_event_id=event_id,
                    status="AMBIGUOUS",
                    candidate_fixture_target_ids=candidates,
                )
            )
            mappings.append(
                FixtureMapping(
                    provider_event_id=event_id,
                    fixture_id=None,
                    status=MappingStatus.AMBIGUOUS,
                    candidate_fixture_ids=candidates,
                    mapping_revision=FIXTURE_MAPPING_REVISION,
                )
            )

    canonical_mappings = tuple(mappings)
    provider_outcome_by_event = {
        outcome.provider_event_id: outcome for outcome in provider_outcomes
    }
    target_outcomes: list[FixtureTargetMappingOutcomeV1] = []
    for target_id, candidate_events in sorted(events_by_target.items()):
        canonical_events = tuple(candidate_events)
        if not canonical_events:
            status = "UNMAPPED"
            admitted_event = None
        elif len(canonical_events) > 1:
            status = "AMBIGUOUS"
            admitted_event = None
        else:
            event_outcome = provider_outcome_by_event[canonical_events[0]]
            if event_outcome.status == "MAPPED":
                status = "MAPPED"
                admitted_event = canonical_events[0]
            else:
                status = "AMBIGUOUS"
                admitted_event = None
        target_outcomes.append(
            FixtureTargetMappingOutcomeV1(
                fixture_target_id=target_id,
                status=cast(Any, status),
                candidate_provider_event_ids=canonical_events,
                admitted_provider_event_id=admitted_event,
            )
        )
    mapped_target_ids = tuple(
        outcome.fixture_target_id for outcome in target_outcomes if outcome.status == "MAPPED"
    )
    return PostCaptureFixtureMappingV1.issue(
        fixture_target_set_sha256=target_set.canonical_set_hash,
        intake_receipt_id=intake_receipt.receipt_id,
        raw_payload_sha256=intake_receipt.payload_sha256,
        raw_storage_key=raw_storage_key,
        mappings=canonical_mappings,
        provider_event_outcomes=tuple(provider_outcomes),
        fixture_target_outcomes=tuple(target_outcomes),
        mapped_target_ids=mapped_target_ids,
        unmatched_target_ids=tuple(
            outcome.fixture_target_id for outcome in target_outcomes if outcome.status != "MAPPED"
        ),
        one_to_one_conflict_event_ids=tuple(sorted(conflicts)),
        mapped_provider_event_count=len(mapped_target_ids),
        non_admitted_provider_event_count=sum(
            mapping.status is not MappingStatus.MAPPED for mapping in canonical_mappings
        ),
    )
