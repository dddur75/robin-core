from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from robin.capture import (
    CaptureContractError,
    CaptureStore,
    FixtureTargetSetV1,
    InternalRetentionPolicy,
    OfficialFixtureTargetV1,
    RawPayloadReceipt,
)
from robin.capture.contracts import (
    AdmissionStatus,
    FixtureMapping,
    MappingStatus,
    canonical_json_bytes,
)
from robin.capture.fixture_mapping import (
    FixtureTargetMappingOutcomeV1,
    PostCaptureFixtureMappingV1,
    PostCaptureMappingError,
    ProviderEventMappingOutcomeV1,
    derive_post_capture_fixture_mappings_v1,
)
from robin.capture.normalization import normalize_payload_v2
from robin.capture.storage import CaptureStorageError

OBSERVED = datetime(2026, 8, 22, 8, 0, tzinfo=UTC)
KICKOFF = datetime(2026, 8, 23, 14, 0, tzinfo=UTC)
SPORT = "soccer_epl"


def target(
    target_id: str,
    *,
    home: str = "Olympique Étoile",
    away: str = "North City",
    kickoff: datetime = KICKOFF,
) -> OfficialFixtureTargetV1:
    return OfficialFixtureTargetV1.issue(
        internal_fixture_target_id=target_id,
        competition="Premier League",
        sport_key=SPORT,
        official_home_team=home,
        official_away_team=away,
        official_kickoff_utc=kickoff,
        official_source_authority="https://example.test/official-schedule",
        source_observed_at_utc=OBSERVED,
        source_evidence_sha256=hashlib.sha256(target_id.encode()).hexdigest(),
    )


def target_set(*targets: OfficialFixtureTargetV1) -> FixtureTargetSetV1:
    return FixtureTargetSetV1.issue(
        target_set_id="official-targets-001",
        sport_key=SPORT,
        workspace_receipt_sha256="9" * 64,
        created_at_utc=OBSERVED + timedelta(minutes=1),
        targets=targets,
    )


def event(
    event_id: str,
    *,
    home: str = "OLYMPIQUE E\u0301TOILE",
    away: str = "North   City",
    kickoff: datetime = KICKOFF,
    sport: str = SPORT,
) -> dict[str, Any]:
    return {
        "id": event_id,
        "sport_key": sport,
        "commence_time": kickoff.isoformat().replace("+00:00", "Z"),
        "home_team": home,
        "away_team": away,
        "bookmakers": [
            {
                "key": "synthetic-book",
                "markets": [
                    {
                        "key": "h2h",
                        "last_update": "2026-08-22T08:00:00Z",
                        "outcomes": [
                            {"name": home, "price": 2.1},
                            {"name": "Draw", "price": 3.2},
                            {"name": away, "price": 3.4},
                        ],
                    }
                ],
            }
        ],
    }


def payload_bytes(*events: dict[str, Any]) -> bytes:
    return json.dumps(events, ensure_ascii=False, sort_keys=True).encode("utf-8")


def intake_receipt(payload: bytes) -> RawPayloadReceipt:
    digest = hashlib.sha256(payload).hexdigest()
    return RawPayloadReceipt.issue(
        intake_receipt_id=None,
        request_fingerprint_sha256="1" * 64,
        payload_sha256=digest,
        payload_byte_length=len(payload),
        http_status=200,
        quota=None,
        robin_first_observed_at=OBSERVED + timedelta(minutes=2),
        robin_ingested_at=OBSERVED + timedelta(minutes=2),
        available_at=OBSERVED + timedelta(minutes=2),
        raw_expires_at=OBSERVED + timedelta(minutes=2, days=30),
        raw_storage_key=f"raw/sha256/{digest[:2]}/{digest}.bin",
        schema_fingerprint_sha256=None,
        admission_status=AdmissionStatus.INTAKE_PENDING,
        rejection_code=None,
    )


def derive(
    raw: bytes,
    targets: FixtureTargetSetV1,
):
    receipt = intake_receipt(raw)
    return derive_post_capture_fixture_mappings_v1(
        raw,
        target_set=targets,
        intake_receipt=receipt,
        raw_storage_key=receipt.raw_storage_key or "",
    )


def test_target_hash_normalizes_unicode_whitespace_utc_and_set_order() -> None:
    offset = timezone(timedelta(hours=2))
    first = target("fixture-a")
    equivalent = target(
        "fixture-a",
        home="  OLYMPIQUE\u00a0E\u0301TOILE  ",
        away="NORTH CITY",
        kickoff=KICKOFF.astimezone(offset),
    )
    assert first.canonical_target_hash == equivalent.canonical_target_hash
    second = target("fixture-b", home="West Town", away="South United", kickoff=KICKOFF)
    assert (
        target_set(first, second).canonical_set_hash
        == target_set(second, equivalent).canonical_set_hash
    )


def test_duplicate_official_fixture_identity_is_rejected() -> None:
    with pytest.raises(CaptureContractError):
        target_set(target("fixture-a"), target("fixture-b"))


def test_exact_mapping_is_one_to_one_and_unrelated_provider_events_do_not_reduce_full() -> None:
    targets = target_set(target("fixture-a"))
    raw = payload_bytes(
        event("provider-1"),
        event(
            "provider-unrelated",
            home="Other Home",
            away="Other Away",
            kickoff=KICKOFF + timedelta(hours=2),
        ),
    )
    evidence = derive(raw, targets)
    assert evidence.mapped_target_ids == ("fixture-a",)
    assert evidence.unmatched_target_ids == ()
    assert evidence.mapped_provider_event_count == 1
    assert evidence.non_admitted_provider_event_count == 1
    assert evidence.mappings[0].status is MappingStatus.MAPPED
    assert evidence.mappings[1].status is MappingStatus.UNMAPPED


@pytest.mark.parametrize(
    "changed_event",
    (
        event("provider-1", kickoff=KICKOFF + timedelta(minutes=1)),
        event("provider-1", home="North City", away="Olympique Étoile"),
        event("provider-1", sport="soccer_france_ligue_one"),
    ),
)
def test_kickoff_home_away_and_sport_mismatches_are_unmapped(
    changed_event: dict[str, Any],
) -> None:
    evidence = derive(payload_bytes(changed_event), target_set(target("fixture-a")))
    assert evidence.mapped_target_ids == ()
    assert evidence.unmatched_target_ids == ("fixture-a",)
    assert evidence.mappings[0].status is MappingStatus.UNMAPPED


def test_many_provider_events_to_one_target_are_explicitly_ambiguous() -> None:
    evidence = derive(
        payload_bytes(event("provider-1"), event("provider-2")),
        target_set(target("fixture-a")),
    )
    assert evidence.mapped_target_ids == ()
    assert evidence.one_to_one_conflict_event_ids == ("provider-1", "provider-2")
    assert {outcome.status for outcome in evidence.provider_event_outcomes} == {"AMBIGUOUS"}
    assert evidence.fixture_target_outcomes[0].status == "AMBIGUOUS"
    assert all(mapping.status is MappingStatus.UNMAPPED for mapping in evidence.mappings)


def test_duplicate_provider_id_and_raw_hash_substitution_are_rejected() -> None:
    duplicate = payload_bytes(event("provider-1"), event("provider-1"))
    targets = target_set(target("fixture-a"))
    with pytest.raises(PostCaptureMappingError, match="POST_CAPTURE_PROVIDER_EVENT_DUPLICATED"):
        derive(duplicate, targets)

    original = payload_bytes(event("provider-1"))
    receipt = intake_receipt(original)
    replacement = payload_bytes(event("provider-2"))
    with pytest.raises(PostCaptureMappingError, match="POST_CAPTURE_RAW_HASH_MISMATCH"):
        derive_post_capture_fixture_mappings_v1(
            replacement,
            target_set=targets,
            intake_receipt=receipt,
            raw_storage_key=receipt.raw_storage_key or "",
        )


def test_partial_projection_excludes_unmapped_target_and_snapshot_binds_complete_target_set() -> (
    None
):
    mapped_target = target("fixture-a")
    absent_target = target(
        "fixture-b",
        home="West Town",
        away="South United",
        kickoff=KICKOFF + timedelta(hours=1),
    )
    raw = payload_bytes(event("provider-1"))
    receipt = intake_receipt(raw)
    full_targets = target_set(mapped_target)
    partial_targets = target_set(mapped_target, absent_target)
    full_evidence = derive(raw, full_targets)
    partial_evidence = derive(raw, partial_targets)
    _, full_rows, full_snapshot = normalize_payload_v2(
        json.loads(raw),
        receipt=receipt,
        mapping_evidence=full_evidence,
        allowed_markets=("h2h",),
        expected_sport_key=SPORT,
    )
    _, partial_rows, partial_snapshot = normalize_payload_v2(
        json.loads(raw),
        receipt=receipt,
        mapping_evidence=partial_evidence,
        allowed_markets=("h2h",),
        expected_sport_key=SPORT,
    )
    assert {row.fixture_id for row in partial_rows} == {"fixture-a"}
    assert len(full_rows) == len(partial_rows) == 3
    assert full_snapshot != partial_snapshot
    assert partial_evidence.unmatched_target_ids == ("fixture-b",)


def test_store_and_load_rederive_mapping_semantics_from_durable_raw(tmp_path: Path) -> None:
    targets = target_set(target("fixture-a"))
    raw = payload_bytes(event("provider-1", home="Wrong Home", away="Wrong Away"))
    receipt = intake_receipt(raw)
    store = CaptureStore(
        tmp_path / "capture",
        InternalRetentionPolicy(),
        approved_local_root=tmp_path / "capture",
    )
    store.store_fixture_target_set(targets)
    store.store_receipt(receipt)
    _raw_sha256, raw_key = store.store_raw(raw)
    forged = PostCaptureFixtureMappingV1.issue(
        fixture_target_set_sha256=targets.canonical_set_hash,
        intake_receipt_id=receipt.receipt_id,
        raw_payload_sha256=receipt.payload_sha256,
        raw_storage_key=raw_key,
        mappings=(
            FixtureMapping(
                provider_event_id="provider-1",
                fixture_id="fixture-a",
                status=MappingStatus.MAPPED,
                candidate_fixture_ids=("fixture-a",),
                mapping_revision="exact-sport-kickoff-home-away-v1",
            ),
        ),
        provider_event_outcomes=(
            ProviderEventMappingOutcomeV1(
                provider_event_id="provider-1",
                status="MAPPED",
                candidate_fixture_target_ids=("fixture-a",),
                admitted_fixture_target_id="fixture-a",
            ),
        ),
        fixture_target_outcomes=(
            FixtureTargetMappingOutcomeV1(
                fixture_target_id="fixture-a",
                status="MAPPED",
                candidate_provider_event_ids=("provider-1",),
                admitted_provider_event_id="provider-1",
            ),
        ),
        mapped_target_ids=("fixture-a",),
        unmatched_target_ids=(),
        one_to_one_conflict_event_ids=(),
        mapped_provider_event_count=1,
        non_admitted_provider_event_count=0,
    )
    with pytest.raises(CaptureStorageError, match="POST_CAPTURE_MAPPING_SEMANTIC_MISMATCH"):
        store.store_post_capture_fixture_mapping(forged)

    store._write_immutable(
        f"live/post-capture-mappings/{forged.canonical_mapping_hash}.json",
        canonical_json_bytes(forged.model_dump(mode="json")) + b"\n",
    )
    with pytest.raises(CaptureStorageError, match="POST_CAPTURE_MAPPING_SEMANTIC_MISMATCH"):
        store.load_post_capture_fixture_mapping(forged.canonical_mapping_hash)
