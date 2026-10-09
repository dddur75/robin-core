from __future__ import annotations

import copy
import hashlib
import json
import traceback
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event, Thread
from typing import Any

import pytest

from robin.capture import (
    LIVE_CANARY_AUTHORIZED,
    CaptureBudget,
    CaptureContractError,
    CaptureGuardError,
    CaptureHarness,
    CaptureMode,
    CaptureRejected,
    CaptureStore,
    FixtureMapping,
    InternalRetentionPolicy,
    ProviderRequestSpec,
    RequestFingerprint,
    SecretCapability,
)
from robin.capture.contracts import MappingStatus, strict_json_object
from robin.capture.normalization import CaptureValidationError
from robin.capture.storage import CaptureStorageError

OBSERVED = datetime(2026, 8, 15, 10, 5, tzinfo=UTC)
INGESTED = datetime(2026, 8, 15, 10, 5, 1, tzinfo=UTC)


def request(*, markets: tuple[str, ...] = ("h2h", "totals")) -> ProviderRequestSpec:
    return ProviderRequestSpec(
        endpoint="/v4/sports/soccer_fictional_alpha/odds",
        sport_key="soccer_fictional_alpha",
        markets=markets,
    )


def budget() -> CaptureBudget:
    return CaptureBudget(maximum_requests=2, maximum_credits=4)


def mapping(event_id: str = "synthetic-event-001") -> FixtureMapping:
    return FixtureMapping(
        provider_event_id=event_id,
        fixture_id="synthetic-fixture-001",
        status=MappingStatus.MAPPED,
        candidate_fixture_ids=("synthetic-fixture-001",),
        mapping_revision="synthetic-mapping-v1",
    )


def encoded(synthetic_pack: dict[str, Any], name: str) -> bytes:
    return json.dumps(
        synthetic_pack["responses"][name],
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def harness(
    tmp_path: Path,
    *,
    maximum_payload_bytes: int = 1_048_576,
    capture_budget: CaptureBudget | None = None,
) -> CaptureHarness:
    capture_root = tmp_path / "capture"
    store = CaptureStore(
        capture_root,
        InternalRetentionPolicy(),
        approved_local_root=capture_root,
    )
    return CaptureHarness(
        store,
        capture_budget or CaptureBudget(maximum_requests=100, maximum_credits=200),
        maximum_payload_bytes=maximum_payload_bytes,
    )


def record(
    instance: CaptureHarness,
    payload: bytes,
    *,
    spec: ProviderRequestSpec | None = None,
    mappings: tuple[FixtureMapping, ...] | None = None,
    status: int = 200,
    headers: dict[str, str] | None = None,
):
    effective_spec = spec or request()
    effective_headers = headers or {
        "x-requests-remaining": "498",
        "x-requests-used": "2",
        "x-requests-last": str(len(effective_spec.markets)),
    }
    return instance.record_offline_response(
        effective_spec,
        payload=payload,
        http_status=status,
        response_headers=effective_headers,
        mappings=mappings or (mapping(),),
        first_observed_at=OBSERVED,
        ingested_at=INGESTED,
    )


def test_default_and_dry_run_are_zero_network(tmp_path: Path) -> None:
    instance = harness(tmp_path)
    default = instance.prepare(request())
    dry = instance.prepare(request(), mode=CaptureMode.DRY_RUN)

    assert default.mode == "VALIDATE_OFFLINE"
    assert dry.mode == "DRY_RUN"
    assert default.network_calls == dry.network_calls == 0
    assert default.provider_calls == dry.provider_calls == 0
    assert default.secret_reads == dry.secret_reads == 0
    assert list((instance.store.root / "raw" / "sha256").rglob("*.bin")) == []


def test_live_canary_is_disabled_before_secret_read(tmp_path: Path) -> None:
    class ExplodingEnvironment(dict[str, str]):
        def get(self, key: str, default: str | None = None) -> str | None:
            del key, default
            raise AssertionError("environment must not be read")

    instance = harness(tmp_path)
    environment = ExplodingEnvironment()
    assert LIVE_CANARY_AUTHORIZED is False
    with pytest.raises(CaptureGuardError, match="ROBIN_LIVE_CANARY_DISABLED_NOT_AUTHORIZED"):
        instance.prepare(request(), mode=CaptureMode.LIVE_CANARY)
    with pytest.raises(CaptureGuardError, match="ROBIN_LIVE_CANARY_DISABLED_NOT_AUTHORIZED"):
        instance.prepare(request(), mode="LIVE_CANARY")
    with pytest.raises(CaptureGuardError, match="CAPTURE_MODE_INVALID"):
        instance.prepare(request(), mode="LIVE")
    assert environment == {}


@pytest.mark.parametrize(
    ("override", "code"),
    [
        ({"scheme": "http"}, "literal_error"),
        ({"host": "invalid.example"}, "literal_error"),
        ({"allow_redirects": True}, "literal_error"),
        ({"retries": 1}, "literal_error"),
        ({"region": "us"}, "literal_error"),
        ({"markets": ("spreads",)}, "literal_error"),
        ({"endpoint": "/v4/sports/x/odds?apiKey=exposable"}, "CAPTURE_ENDPOINT_INVALID"),
    ],
)
def test_request_guards_fail_closed(override: dict[str, object], code: str) -> None:
    values: dict[str, object] = {
        "endpoint": "/v4/sports/soccer_fictional_alpha/odds",
        "sport_key": "soccer_fictional_alpha",
        "markets": ("h2h",),
    }
    values.update(override)
    del code
    with pytest.raises(CaptureContractError, match="CAPTURE_CONTRACT_INVALID"):
        ProviderRequestSpec.model_validate(values)


@pytest.mark.parametrize(
    "payload",
    (
        b'{"maximum_requests":1,"maximum_requests":2}',
        b'{"value":1e999}',
        b'{"value":999999999999999999999999999999999999999}',
        b'{"value":"\\ud800"}',
        b"[]",
    ),
)
def test_control_json_rejects_duplicates_nonfinite_unbounded_and_nonobjects(
    payload: bytes,
) -> None:
    with pytest.raises(CaptureContractError):
        strict_json_object(payload)


def test_frozen_contract_json_loader_rejects_duplicate_shadow_fields() -> None:
    with pytest.raises(CaptureContractError):
        ProviderRequestSpec.model_validate_json(
            b'{"endpoint":"/v4/sports/soccer_epl/odds",'
            b'"sport_key":"soccer_epl","sport_key":"soccer_spain_la_liga",'
            b'"region":"eu","markets":["h2h","totals"]}'
        )


def test_budget_is_required_and_cannot_be_exceeded(
    tmp_path: Path,
    synthetic_pack: dict[str, Any],
) -> None:
    missing_budget_root = tmp_path / "missing-budget"
    store = CaptureStore(
        missing_budget_root,
        InternalRetentionPolicy(),
        approved_local_root=missing_budget_root,
    )
    with pytest.raises(CaptureGuardError, match="CAPTURE_BUDGET_REQUIRED"):
        CaptureHarness(store, None)
    exhausted = harness(
        tmp_path / "exhausted",
        capture_budget=CaptureBudget(
            maximum_requests=1,
            used_requests=1,
            maximum_credits=2,
            used_credits=2,
        ),
    )
    with pytest.raises(CaptureGuardError, match="CAPTURE_REQUEST_BUDGET_EXCEEDED"):
        exhausted.prepare(request())

    bounded = harness(
        tmp_path / "bounded",
        capture_budget=CaptureBudget(maximum_requests=1, maximum_credits=2),
    )
    record(bounded, encoded(synthetic_pack, "h2h_plus_totals"))
    assert bounded.current_budget.used_requests == 1
    assert bounded.current_budget.used_credits == 2
    with pytest.raises(CaptureGuardError, match="CAPTURE_REQUEST_BUDGET_EXCEEDED"):
        record(bounded, encoded(synthetic_pack, "h2h_plus_totals"))
    bounded_root = bounded.store.root
    restarted_store = CaptureStore(
        bounded_root,
        InternalRetentionPolicy(),
        approved_local_root=bounded_root,
    )
    restarted = CaptureHarness(
        restarted_store,
        CaptureBudget(maximum_requests=1, maximum_credits=2),
    )
    with pytest.raises(CaptureGuardError, match="CAPTURE_REQUEST_BUDGET_EXCEEDED"):
        record(restarted, encoded(synthetic_pack, "h2h_plus_totals"))
    budget_entries = bounded.store.budget_ledger.read_text("utf-8").splitlines()
    assert len(budget_entries) == 1
    assert "entry_sha256" in budget_entries[0]


@pytest.mark.parametrize(("requests", "credits"), ((True, 1), (0.5, 1), (1, True)))
def test_budget_runtime_boundary_rejects_non_integer_scalars_without_append(
    tmp_path: Path,
    requests: Any,
    credits: Any,
) -> None:
    root = tmp_path / f"invalid-budget-{requests}-{credits}"
    store = CaptureStore(root, InternalRetentionPolicy(), approved_local_root=root)
    with pytest.raises(CaptureStorageError, match="CAPTURE_BUDGET_RESERVATION_INVALID"):
        store.reserve_budget(
            CaptureBudget(maximum_requests=2, maximum_credits=2),
            requests=requests,
            credits=credits,
            consume=True,
        )
    assert not store.budget_ledger.exists()


def test_budget_runtime_boundary_reparses_constructed_budget(tmp_path: Path) -> None:
    root = tmp_path / "constructed-budget"
    store = CaptureStore(root, InternalRetentionPolicy(), approved_local_root=root)
    forged = CaptureBudget.model_construct(
        maximum_requests=True,
        used_requests=0,
        maximum_credits=2,
        used_credits=0,
    )
    with pytest.raises(CaptureStorageError, match="CAPTURE_BUDGET_INVALID"):
        store.reserve_budget(forged, requests=1, credits=1, consume=True)
    assert not store.budget_ledger.exists()


def test_retention_and_workspace_guards(tmp_path: Path) -> None:
    missing_policy_root = tmp_path / "missing-policy"
    with pytest.raises(CaptureStorageError, match="CAPTURE_RETENTION_POLICY_REQUIRED"):
        CaptureStore(
            missing_policy_root,
            None,
            approved_local_root=missing_policy_root,
        )
    approval_root = tmp_path / "approval-required"
    with pytest.raises(CaptureStorageError, match="CAPTURE_LOCAL_ROOT_APPROVAL_REQUIRED"):
        CaptureStore(approval_root, InternalRetentionPolicy(), approved_local_root=None)
    with pytest.raises(CaptureStorageError, match="CAPTURE_LOCAL_ROOT_APPROVAL_MISMATCH"):
        CaptureStore(
            approval_root,
            InternalRetentionPolicy(),
            approved_local_root=tmp_path / "different-root",
        )
    onedrive_root = tmp_path / "OneDrive" / "capture"
    with pytest.raises(CaptureStorageError, match="CAPTURE_WORKSPACE_SYNCHRONIZED"):
        CaptureStore(
            onedrive_root,
            InternalRetentionPolicy(),
            approved_local_root=onedrive_root,
        )
    organization_root = tmp_path / "OneDrive - Synthetic Org" / "capture"
    with pytest.raises(CaptureStorageError, match="CAPTURE_WORKSPACE_SYNCHRONIZED"):
        CaptureStore(
            organization_root,
            InternalRetentionPolicy(),
            approved_local_root=organization_root,
        )
    repository_root = Path(__file__).parents[2]
    git_capture_root = repository_root / "data" / "capture"
    with pytest.raises(CaptureStorageError, match="CAPTURE_WORKSPACE_IN_GIT"):
        CaptureStore(
            git_capture_root,
            InternalRetentionPolicy(),
            approved_local_root=git_capture_root,
        )


def test_secret_capability_never_retains_or_exposes_sentinel(
    tmp_path: Path,
    synthetic_pack: dict[str, Any],
) -> None:
    sentinel = str(synthetic_pack["secret_sentinel"])
    instance = harness(tmp_path)
    preparation = instance.prepare(request())
    public = instance.public_preparation_bytes(preparation)
    capability = SecretCapability.from_environment(
        {"THE_ODDS_API_KEY": sentinel},
        public_material=public,
    )
    assert sentinel not in capability.model_dump_json()
    assert sentinel.encode() not in public
    with pytest.raises(CaptureGuardError) as missing:
        SecretCapability.from_environment({}, public_material=b"{}")
    assert str(missing.value) == "CAPTURE_SECRET_MISSING"
    with pytest.raises(CaptureGuardError) as exposable:
        SecretCapability.from_environment(
            {"THE_ODDS_API_KEY": sentinel},
            public_material=sentinel.encode(),
        )
    assert str(exposable.value) == "CAPTURE_SECRET_EXPOSABLE"
    assert sentinel not in str(exposable.value)


def test_request_fingerprint_is_stable_and_secret_free(
    synthetic_pack: dict[str, Any],
) -> None:
    sentinel = str(synthetic_pack["secret_sentinel"])
    left = RequestFingerprint.create(request())
    right = RequestFingerprint.create(request())
    assert left == right
    assert sentinel not in left.model_dump_json()
    assert "apiKey" not in left.model_dump_json()


def test_invalid_request_exception_hides_secret_sentinel(
    synthetic_pack: dict[str, Any],
) -> None:
    sentinel = str(synthetic_pack["secret_sentinel"])
    unsafe = {
        "endpoint": f"/v4/sports/x/odds?apiKey={sentinel}",
        "sport_key": "soccer_fictional_alpha",
        "markets": ("h2h",),
    }
    factories = (
        lambda: ProviderRequestSpec(**unsafe),
        lambda: ProviderRequestSpec.model_validate(unsafe),
        lambda: ProviderRequestSpec.model_validate_json(json.dumps(unsafe)),
        lambda: RequestFingerprint.model_validate({"request_sha256": "0" * 64, "request": unsafe}),
    )
    for factory in factories:
        with pytest.raises(CaptureContractError) as rejected:
            factory()
        serialized_exception = "\n".join(
            (
                str(rejected.value),
                repr(rejected.value),
                json.dumps(vars(rejected.value), sort_keys=True),
                "".join(traceback.format_exception(rejected.value)),
            )
        )
        assert sentinel not in serialized_exception
        assert not hasattr(rejected.value, "errors")
        assert not hasattr(rejected.value, "json")


def test_content_addressed_capture_and_offline_replay_are_deterministic(
    tmp_path: Path,
    synthetic_pack: dict[str, Any],
) -> None:
    instance = harness(tmp_path)
    payload = encoded(synthetic_pack, "h2h_plus_totals")
    manifest = record(instance, payload)
    repeated = record(instance, payload)

    assert repeated == manifest
    assert manifest.observation_count == 5
    raw_path = instance.store.root / "raw" / "sha256" / manifest.raw_payload_sha256[:2]
    assert (raw_path / f"{manifest.raw_payload_sha256}.bin").read_bytes() == payload
    assert (instance.store.root / "receipts" / f"{manifest.receipt_id}.json").is_file()
    assert (instance.store.root / "normalized" / f"{manifest.snapshot_id}.jsonl").is_file()
    assert (instance.store.root / "manifests" / f"{manifest.snapshot_id}.json").is_file()

    first = instance.store.replay(manifest.snapshot_id)
    second = instance.store.replay(manifest.snapshot_id)
    assert first == second
    assert first.byte_identical is first.deterministic is True
    assert first.network_calls == first.provider_calls == 0
    assert first.verdict == "ROBIN_OFFLINE_CAPTURE_REPLAY_PROVEN"


def test_totals_absence_market_timestamp_absence_and_incomplete_bookmaker(
    tmp_path: Path,
    synthetic_pack: dict[str, Any],
) -> None:
    instance = harness(tmp_path)
    totals_absent = record(
        instance,
        encoded(synthetic_pack, "totals_absent"),
        mappings=(mapping("synthetic-event-002"),),
    )
    absent_update = record(
        instance,
        encoded(synthetic_pack, "market_last_update_absent"),
    )
    combined = record(instance, encoded(synthetic_pack, "h2h_plus_totals"))

    assert totals_absent.observation_count == 3
    absent_lines = (
        instance.store.root / "normalized" / f"{absent_update.snapshot_id}.jsonl"
    ).read_text(encoding="utf-8")
    assert '"market_last_update":null' in absent_lines
    combined_lines = (
        instance.store.root / "normalized" / f"{combined.snapshot_id}.jsonl"
    ).read_text(encoding="utf-8")
    assert "synthetic-book-incomplete" not in combined_lines


def test_available_at_is_never_backdated(
    tmp_path: Path,
    synthetic_pack: dict[str, Any],
) -> None:
    instance = harness(tmp_path)
    manifest = record(instance, encoded(synthetic_pack, "h2h_plus_totals"))
    path = instance.store.root / "normalized" / f"{manifest.snapshot_id}.jsonl"
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert rows
    assert all(datetime.fromisoformat(row["available_at"]) >= OBSERVED for row in rows)


@pytest.mark.parametrize(
    ("fixture", "expected"),
    [
        ("event_duplicated", "CAPTURE_EVENT_DUPLICATED"),
        ("timestamp_invalid", "CAPTURE_TIMESTAMP_INVALID"),
    ],
)
def test_invalid_synthetic_payloads_are_quarantined_after_hashing(
    tmp_path: Path,
    synthetic_pack: dict[str, Any],
    fixture: str,
    expected: str,
) -> None:
    instance = harness(tmp_path)
    payload = encoded(synthetic_pack, fixture)
    with pytest.raises(CaptureRejected, match=expected) as rejected:
        record(instance, payload)
    receipt = instance.store.load_receipt(rejected.value.receipt_id)
    assert receipt.payload_sha256 == hashlib.sha256(payload).hexdigest()
    assert receipt.raw_storage_key is not None
    assert instance.store.load_raw(receipt) == payload
    assert (instance.store.root / "quarantine" / f"{receipt.receipt_id}.json").is_file()


def test_ambiguous_mapping_is_quarantined(
    tmp_path: Path,
    synthetic_pack: dict[str, Any],
) -> None:
    instance = harness(tmp_path)
    ambiguous = FixtureMapping(
        provider_event_id="synthetic-event-ambiguous",
        fixture_id=None,
        status=MappingStatus.AMBIGUOUS,
        candidate_fixture_ids=("synthetic-fixture-a", "synthetic-fixture-b"),
        mapping_revision="synthetic-mapping-v1",
    )
    with pytest.raises(CaptureRejected, match="CAPTURE_FIXTURE_MAPPING_AMBIGUOUS"):
        record(
            instance,
            encoded(synthetic_pack, "mapping_ambiguous"),
            mappings=(ambiguous,),
        )


def test_invalid_json_is_hashed_before_parse_and_quarantined(
    tmp_path: Path,
    synthetic_pack: dict[str, Any],
) -> None:
    instance = harness(tmp_path)
    payload = str(synthetic_pack["responses"]["json_invalid"]).encode()
    with pytest.raises(CaptureRejected, match="CAPTURE_JSON_INVALID") as rejected:
        record(instance, payload)
    receipt = instance.store.load_receipt(rejected.value.receipt_id)
    assert receipt.payload_sha256 == rejected.value.payload_sha256
    assert receipt.payload_sha256 == hashlib.sha256(payload).hexdigest()


def test_http_redirect_size_and_quota_fail_closed(
    tmp_path: Path,
    synthetic_pack: dict[str, Any],
) -> None:
    payload = encoded(synthetic_pack, "h2h_complete")
    instance = harness(tmp_path)
    with pytest.raises(CaptureRejected, match="CAPTURE_HTTP_STATUS_REJECTED"):
        record(instance, payload, status=503)
    with pytest.raises(CaptureRejected, match="CAPTURE_REDIRECT_FORBIDDEN"):
        record(instance, payload, status=302, headers={"location": "synthetic"})
    with pytest.raises(CaptureRejected, match="CAPTURE_QUOTA_HEADERS_INVALID"):
        record(
            instance,
            payload,
            headers=dict(synthetic_pack["responses"]["quota_headers_invalid"]),
        )
    with pytest.raises(CaptureRejected, match="CAPTURE_QUOTA_HEADERS_MISSING"):
        record(instance, payload, headers={"content-type": "application/json"})
    with pytest.raises(CaptureRejected, match="CAPTURE_QUOTA_RECONCILIATION_FAILED"):
        record(
            instance,
            payload,
            headers={
                "x-requests-remaining": "500",
                "x-requests-used": "0",
                "x-requests-last": "2",
            },
        )
    small = harness(tmp_path / "small", maximum_payload_bytes=8)
    with pytest.raises(CaptureRejected, match="CAPTURE_PAYLOAD_TOO_LARGE") as oversized:
        record(small, payload)
    oversized_receipt = small.store.load_receipt(oversized.value.receipt_id)
    assert oversized_receipt.raw_storage_key is None
    assert list((small.store.root / "raw" / "sha256").rglob("*.bin")) == []

    invalid_status = harness(tmp_path / "invalid-status")
    with pytest.raises(CaptureGuardError, match="CAPTURE_HTTP_STATUS_INVALID"):
        record(invalid_status, payload, status=99)
    assert list((invalid_status.store.root / "raw" / "sha256").rglob("*.bin")) == []


def test_raw_ttl_deletion_preserves_receipt_and_normalized_data(
    tmp_path: Path,
    synthetic_pack: dict[str, Any],
) -> None:
    instance = harness(tmp_path)
    manifest = record(instance, encoded(synthetic_pack, "h2h_plus_totals"))
    receipt_path = instance.store.root / "receipts" / f"{manifest.receipt_id}.json"
    normalized_path = instance.store.root / "normalized" / f"{manifest.snapshot_id}.jsonl"
    deleted = instance.store.enforce_raw_ttl(now=OBSERVED + timedelta(days=30, seconds=1))

    assert deleted == (manifest.raw_payload_sha256,)
    assert receipt_path.is_file()
    assert normalized_path.is_file()
    assert instance.store.deletion_ledger.is_file()
    assert manifest.raw_payload_sha256 in instance.store.deletion_ledger.read_text("utf-8")
    assert "RAW_TTL_DELETION_INTENT" in instance.store.deletion_ledger.read_text("utf-8")
    assert "RAW_TTL_DELETION_COMMITTED" in instance.store.deletion_ledger.read_text("utf-8")
    with pytest.raises(CaptureStorageError, match="CAPTURE_RAW_PAYLOAD_NOT_RETAINED"):
        instance.store.replay(manifest.snapshot_id)


@pytest.mark.parametrize("receipt_loss", ("corrupt", "deleted"))
def test_ttl_enforcer_deletes_orphan_raw_when_all_receipt_copies_are_lost(
    tmp_path: Path,
    synthetic_pack: dict[str, Any],
    receipt_loss: str,
) -> None:
    instance = harness(tmp_path / receipt_loss)
    manifest = record(instance, encoded(synthetic_pack, "h2h_plus_totals"))
    final_receipt = instance.store.load_receipt(manifest.receipt_id)
    assert final_receipt.intake_receipt_id is not None
    assert final_receipt.raw_storage_key is not None
    receipt_paths = (
        instance.store.root / "receipts" / f"{manifest.receipt_id}.json",
        instance.store.root / "receipts" / f"{final_receipt.intake_receipt_id}.json",
    )
    for receipt_path in receipt_paths:
        if receipt_loss == "corrupt":
            receipt_path.write_bytes(b"{}\n")
        else:
            receipt_path.unlink()

    deleted = instance.store.enforce_raw_ttl(now=OBSERVED + timedelta(days=1))
    raw_path = instance.store.root / final_receipt.raw_storage_key
    assert deleted == (manifest.raw_payload_sha256,)
    assert not raw_path.exists()
    ledger = instance.store.deletion_ledger.read_text("utf-8")
    assert "RAW_ORPHAN_DELETION_INTENT" in ledger
    assert "RAW_ORPHAN_DELETION_COMMITTED" in ledger
    if receipt_loss == "corrupt":
        assert ledger.count("RECEIPT_CORRUPTION_DETECTED") == 2


def test_storage_collision_fails_closed(
    tmp_path: Path,
    synthetic_pack: dict[str, Any],
) -> None:
    instance = harness(tmp_path)
    payload = encoded(synthetic_pack, "h2h_plus_totals")
    manifest = record(instance, payload)
    normalized_path = instance.store.root / "normalized" / f"{manifest.snapshot_id}.jsonl"
    normalized_path.write_bytes(b"tampered\n")
    with pytest.raises(CaptureStorageError, match="CAPTURE_STORAGE_COLLISION"):
        record(instance, payload)


def test_receipt_manifest_and_normalized_links_fail_closed_on_tamper(
    tmp_path: Path,
    synthetic_pack: dict[str, Any],
) -> None:
    payload = encoded(synthetic_pack, "h2h_plus_totals")

    receipt_instance = harness(tmp_path / "receipt")
    receipt_manifest = record(receipt_instance, payload)
    receipt_path = receipt_instance.store.root / "receipts" / f"{receipt_manifest.receipt_id}.json"
    receipt_data = json.loads(receipt_path.read_text("utf-8"))
    receipt_data["payload_byte_length"] += 1
    receipt_path.write_text(json.dumps(receipt_data), encoding="utf-8")
    with pytest.raises(CaptureContractError, match="CAPTURE_CONTRACT_INVALID"):
        receipt_instance.store.load_receipt(receipt_manifest.receipt_id)

    manifest_instance = harness(tmp_path / "manifest")
    manifest = record(manifest_instance, payload)
    manifest_path = manifest_instance.store.root / "manifests" / f"{manifest.snapshot_id}.json"
    manifest_data = json.loads(manifest_path.read_text("utf-8"))
    manifest_data["raw_payload_sha256"] = "0" * 64
    identity = {key: value for key, value in manifest_data.items() if key != "manifest_sha256"}
    manifest_data["manifest_sha256"] = hashlib.sha256(
        json.dumps(
            identity,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    manifest_path.write_text(json.dumps(manifest_data), encoding="utf-8")
    with pytest.raises(CaptureStorageError, match="CAPTURE_MANIFEST_RECEIPT_LINK_MISMATCH"):
        manifest_instance.store.replay(manifest.snapshot_id)

    normalized_instance = harness(tmp_path / "normalized")
    normalized_manifest = record(normalized_instance, payload)
    normalized_path = (
        normalized_instance.store.root / "normalized" / f"{normalized_manifest.snapshot_id}.jsonl"
    )
    normalized_path.write_bytes(normalized_path.read_bytes() + b"{}\n")
    with pytest.raises(CaptureStorageError, match="CAPTURE_NORMALIZED_HASH_MISMATCH"):
        normalized_instance.store.replay(normalized_manifest.snapshot_id)

    temporal_instance = harness(tmp_path / "temporal")
    temporal_manifest = record(temporal_instance, payload)
    temporal_path = (
        temporal_instance.store.root / "manifests" / f"{temporal_manifest.snapshot_id}.json"
    )
    temporal_data = json.loads(temporal_path.read_text("utf-8"))
    temporal_data["captured_at"] = "2000-01-01T00:00:00Z"
    temporal_identity = {
        key: value for key, value in temporal_data.items() if key != "manifest_sha256"
    }
    temporal_data["manifest_sha256"] = hashlib.sha256(
        json.dumps(
            temporal_identity,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    temporal_path.write_text(json.dumps(temporal_data), encoding="utf-8")
    with pytest.raises(CaptureStorageError, match="CAPTURE_MANIFEST_RECEIPT_LINK_MISMATCH"):
        temporal_instance.store.replay(temporal_manifest.snapshot_id)

    intake_instance = harness(tmp_path / "intake-link")
    intake_manifest = record(intake_instance, payload)
    final_receipt = intake_instance.store.load_receipt(intake_manifest.receipt_id)
    assert final_receipt.intake_receipt_id is not None
    intake_path = (
        intake_instance.store.root / "receipts" / f"{final_receipt.intake_receipt_id}.json"
    )
    intake_path.unlink()
    with pytest.raises(CaptureStorageError, match="CAPTURE_INTAKE_RECEIPT_MISSING"):
        intake_instance.store.replay(intake_manifest.snapshot_id)


def test_budget_ledger_rejects_semantically_rehashed_reset(
    tmp_path: Path,
    synthetic_pack: dict[str, Any],
) -> None:
    instance = harness(
        tmp_path,
        capture_budget=CaptureBudget(maximum_requests=2, maximum_credits=4),
    )
    record(instance, encoded(synthetic_pack, "h2h_plus_totals"))
    ledger_path = instance.store.budget_ledger
    entry = json.loads(ledger_path.read_text("utf-8"))
    entry["used_requests"] = 0
    identity = {key: value for key, value in entry.items() if key != "entry_sha256"}
    entry["entry_sha256"] = hashlib.sha256(
        json.dumps(
            identity,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    ledger_path.write_text(json.dumps(entry) + "\n", encoding="utf-8")

    restarted_store = CaptureStore(
        instance.store.root,
        InternalRetentionPolicy(),
        approved_local_root=instance.store.root,
    )
    restarted = CaptureHarness(
        restarted_store,
        CaptureBudget(maximum_requests=2, maximum_credits=4),
    )
    with pytest.raises(
        CaptureStorageError,
        match="CAPTURE_BUDGET_LEDGER_ROLLBACK_DETECTED",
    ):
        record(restarted, encoded(synthetic_pack, "h2h_plus_totals"))


@pytest.mark.parametrize("rollback", ("last_line", "ledger_absent", "old_prefix"))
def test_budget_immutable_events_restore_deleted_or_rolled_back_jsonl_view(
    tmp_path: Path,
    synthetic_pack: dict[str, Any],
    rollback: str,
) -> None:
    maximum = CaptureBudget(maximum_requests=3, maximum_credits=6)
    instance = harness(tmp_path / rollback, capture_budget=maximum)
    payload = encoded(synthetic_pack, "h2h_plus_totals")
    for _ in range(3):
        record(instance, payload)
    ledger_path = instance.store.budget_ledger
    complete = ledger_path.read_bytes()
    lines = complete.splitlines(keepends=True)
    assert len(lines) == 3
    assert len(tuple((instance.store.root / "budget-events").glob("*.json"))) == 3

    if rollback == "ledger_absent":
        ledger_path.unlink()
    elif rollback == "last_line":
        ledger_path.write_bytes(b"".join(lines[:-1]))
    else:
        ledger_path.write_bytes(lines[0])

    restarted_store = CaptureStore(
        instance.store.root,
        InternalRetentionPolicy(),
        approved_local_root=instance.store.root,
    )
    restarted = CaptureHarness(restarted_store, maximum)
    with pytest.raises(CaptureGuardError, match="CAPTURE_REQUEST_BUDGET_EXCEEDED"):
        record(restarted, payload)
    assert ledger_path.read_bytes() == complete


def test_budget_partial_jsonl_tail_is_audited_then_restored_from_event(
    tmp_path: Path,
    synthetic_pack: dict[str, Any],
) -> None:
    maximum = CaptureBudget(maximum_requests=2, maximum_credits=4)
    instance = harness(tmp_path / "partial-tail", capture_budget=maximum)
    payload = encoded(synthetic_pack, "h2h_plus_totals")
    record(instance, payload)
    record(instance, payload)
    ledger_path = instance.store.budget_ledger
    complete = ledger_path.read_bytes()
    lines = complete.splitlines(keepends=True)
    ledger_path.write_bytes(lines[0] + lines[1][: len(lines[1]) // 2])

    restarted_store = CaptureStore(
        instance.store.root,
        InternalRetentionPolicy(),
        approved_local_root=instance.store.root,
    )
    restarted = CaptureHarness(restarted_store, maximum)
    with pytest.raises(CaptureGuardError, match="CAPTURE_REQUEST_BUDGET_EXCEEDED"):
        record(restarted, payload)
    assert ledger_path.read_bytes() == complete
    recoveries = tuple((instance.store.root / "budget-ledger-recovery").glob("*.json"))
    assert len(recoveries) == 1


@pytest.mark.parametrize("tamper", ["revision", "extra"])
def test_mapping_lineage_is_bound_to_snapshot_identity(
    tmp_path: Path,
    synthetic_pack: dict[str, Any],
    tamper: str,
) -> None:
    instance = harness(tmp_path / tamper)
    manifest = record(instance, encoded(synthetic_pack, "h2h_plus_totals"))
    manifest_path = instance.store.root / "manifests" / f"{manifest.snapshot_id}.json"
    manifest_data = json.loads(manifest_path.read_text("utf-8"))
    if tamper == "revision":
        manifest_data["fixture_mappings"][0]["mapping_revision"] = "tampered-revision"
        expected = "CAPTURE_REPLAY_NOT_DETERMINISTIC"
    else:
        manifest_data["fixture_mappings"].append(
            {
                "candidate_fixture_ids": ["synthetic-fixture-unused"],
                "fixture_id": "synthetic-fixture-unused",
                "mapping_revision": "synthetic-mapping-v1",
                "provider_event_id": "synthetic-event-unused",
                "status": "MAPPED",
            }
        )
        expected = "CAPTURE_FIXTURE_MAPPING_UNUSED"
    identity = {key: value for key, value in manifest_data.items() if key != "manifest_sha256"}
    manifest_data["manifest_sha256"] = hashlib.sha256(
        json.dumps(
            identity,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    manifest_path.write_text(json.dumps(manifest_data), encoding="utf-8")
    with pytest.raises((CaptureStorageError, CaptureValidationError), match=expected):
        instance.store.replay(manifest.snapshot_id)


def test_ttl_ledger_failure_cannot_delete_raw(
    tmp_path: Path,
    synthetic_pack: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    instance = harness(tmp_path)
    manifest = record(instance, encoded(synthetic_pack, "h2h_plus_totals"))
    raw_path = (
        instance.store.root
        / "raw"
        / "sha256"
        / manifest.raw_payload_sha256[:2]
        / f"{manifest.raw_payload_sha256}.bin"
    )

    def fail_ledger(record: dict[str, object]) -> None:
        del record
        raise CaptureStorageError("SYNTHETIC_LEDGER_FAILURE")

    monkeypatch.setattr(instance.store, "_append_deletion_record", fail_ledger)
    with pytest.raises(CaptureStorageError, match="SYNTHETIC_LEDGER_FAILURE"):
        instance.store.enforce_raw_ttl(now=OBSERVED + timedelta(days=30, seconds=1))
    assert raw_path.is_file()


def test_capture_and_ttl_are_serialized_for_the_same_raw_hash(
    tmp_path: Path,
    synthetic_pack: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = encoded(synthetic_pack, "h2h_plus_totals")
    first = harness(tmp_path)
    first_manifest = record(first, payload)
    shared_root = first.store.root
    second_store = CaptureStore(
        shared_root,
        InternalRetentionPolicy(),
        approved_local_root=shared_root,
    )
    second = CaptureHarness(
        second_store,
        CaptureBudget(maximum_requests=100, maximum_credits=200),
    )
    intent_written = Event()
    allow_ttl_to_continue = Event()
    capture_started = Event()
    capture_finished = Event()
    thread_errors: list[Exception] = []
    second_manifest: list[Any] = []
    original_append = first.store._append_deletion_record

    def pause_after_intent(record: dict[str, object]) -> None:
        original_append(record)
        if record.get("action") == "RAW_TTL_DELETION_INTENT":
            intent_written.set()
            if not allow_ttl_to_continue.wait(timeout=5):
                raise AssertionError("SYNTHETIC_TTL_RESUME_TIMEOUT")

    def run_ttl() -> None:
        try:
            first.store.enforce_raw_ttl(now=OBSERVED + timedelta(days=30, seconds=1))
        except Exception as exc:  # pragma: no cover - asserted below
            thread_errors.append(exc)

    def run_capture() -> None:
        capture_started.set()
        try:
            captured = second.record_offline_response(
                request(),
                payload=payload,
                http_status=200,
                response_headers={
                    "x-requests-remaining": "496",
                    "x-requests-used": "4",
                    "x-requests-last": "2",
                },
                mappings=(mapping(),),
                first_observed_at=OBSERVED + timedelta(days=31),
                ingested_at=INGESTED + timedelta(days=31),
            )
            second_manifest.append(captured)
        except Exception as exc:  # pragma: no cover - asserted below
            thread_errors.append(exc)
        finally:
            capture_finished.set()

    monkeypatch.setattr(first.store, "_append_deletion_record", pause_after_intent)
    ttl_thread = Thread(target=run_ttl, daemon=True)
    ttl_thread.start()
    assert intent_written.wait(timeout=5)
    capture_thread = Thread(target=run_capture, daemon=True)
    capture_thread.start()
    assert capture_started.wait(timeout=5)
    assert not capture_finished.wait(timeout=0.2)
    allow_ttl_to_continue.set()
    ttl_thread.join(timeout=5)
    capture_thread.join(timeout=5)

    assert not ttl_thread.is_alive()
    assert not capture_thread.is_alive()
    assert thread_errors == []
    assert len(second_manifest) == 1
    assert second_manifest[0].raw_payload_sha256 == first_manifest.raw_payload_sha256
    replay = second.store.replay(second_manifest[0].snapshot_id)
    assert replay.deterministic is True


def test_crash_after_raw_write_leaves_ttl_governed_intake_receipt(
    tmp_path: Path,
    synthetic_pack: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    instance = harness(tmp_path)
    original_store_raw = instance.store.store_raw

    def crash_after_write(payload: bytes) -> tuple[str, str]:
        original_store_raw(payload)
        raise CaptureStorageError("SYNTHETIC_POST_WRITE_CRASH")

    monkeypatch.setattr(instance.store, "store_raw", crash_after_write)
    with pytest.raises(CaptureStorageError, match="SYNTHETIC_POST_WRITE_CRASH"):
        record(instance, encoded(synthetic_pack, "h2h_plus_totals"))

    raw_files = list((instance.store.root / "raw" / "sha256").rglob("*.bin"))
    receipts = list((instance.store.root / "receipts").glob("*.json"))
    assert len(raw_files) == len(receipts) == 1
    raw_sha256 = hashlib.sha256(raw_files[0].read_bytes()).hexdigest()
    monkeypatch.setattr(instance.store, "store_raw", original_store_raw)
    deleted = instance.store.enforce_raw_ttl(now=OBSERVED + timedelta(days=30, seconds=1))
    assert deleted == (raw_sha256,)
    assert not raw_files[0].exists()


def test_mapping_must_be_bijective_and_bookmakers_unique(
    tmp_path: Path,
    synthetic_pack: dict[str, Any],
) -> None:
    duplicated_event_payload = copy.deepcopy(synthetic_pack["responses"]["h2h_complete"])
    second_event = copy.deepcopy(duplicated_event_payload[0])
    second_event["id"] = "synthetic-event-second"
    duplicated_event_payload.append(second_event)
    duplicate_mapping = FixtureMapping(
        provider_event_id="synthetic-event-second",
        fixture_id="synthetic-fixture-001",
        status=MappingStatus.MAPPED,
        candidate_fixture_ids=("synthetic-fixture-001",),
        mapping_revision="synthetic-mapping-v1",
    )
    with pytest.raises(CaptureRejected, match="CAPTURE_FIXTURE_MAPPING_NOT_BIJECTIVE"):
        record(
            harness(tmp_path / "mapping"),
            json.dumps(duplicated_event_payload, separators=(",", ":")).encode(),
            mappings=(mapping(), duplicate_mapping),
        )

    duplicated_bookmaker_payload = copy.deepcopy(synthetic_pack["responses"]["h2h_complete"])
    duplicated_bookmaker_payload[0]["bookmakers"].append(
        copy.deepcopy(duplicated_bookmaker_payload[0]["bookmakers"][0])
    )
    with pytest.raises(CaptureRejected, match="CAPTURE_BOOKMAKER_DUPLICATED"):
        record(
            harness(tmp_path / "bookmaker"),
            json.dumps(duplicated_bookmaker_payload, separators=(",", ":")).encode(),
        )


def test_secret_sentinel_has_zero_occurrences_in_all_capture_outputs(
    tmp_path: Path,
    synthetic_pack: dict[str, Any],
) -> None:
    sentinel = str(synthetic_pack["secret_sentinel"])
    instance = harness(tmp_path)
    preparation = instance.prepare(request())
    SecretCapability.from_environment(
        {"THE_ODDS_API_KEY": sentinel},
        public_material=instance.public_preparation_bytes(preparation),
    )
    manifest = record(instance, encoded(synthetic_pack, "h2h_plus_totals"))
    assert manifest.promoted is False
    assert manifest.bet_calculated is False
    outputs = b"".join(
        path.read_bytes() for path in instance.store.root.rglob("*") if path.is_file()
    )
    assert outputs.count(sentinel.encode()) == 0


def test_capture_workspace_guard_prevents_raw_payload_in_git() -> None:
    repository_root = Path(__file__).parents[2]
    with pytest.raises(CaptureStorageError, match="CAPTURE_WORKSPACE_IN_GIT"):
        CaptureStore(
            repository_root / "raw",
            InternalRetentionPolicy(),
            approved_local_root=repository_root / "raw",
        )
