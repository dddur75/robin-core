from __future__ import annotations

import hashlib
import importlib.util
import inspect
import json
import os
import socket
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

import robin.capture.official_schedule_sources as official_sources_module
import robin.capture.owner_review_pack as owner_review_pack_module
from robin.capture.bootstrap_contracts import (
    FIRST_C0_CANARY_RANKING_POLICY,
    FIRST_C0_CANARY_SELECTION_REVISION,
    CampaignWindowCandidateV1,
    FirstC0CanarySelectionV1,
    FixtureTargetSetV1,
    OfficialFixtureTargetV1,
    OwnerReviewPackV1,
    ProviderNetworkBindingV1,
    ProviderNetworkResolutionClaimV1,
    RealCaptureWorkspaceReceiptV1,
    RealExecutionMissionManifestV1,
    _first_c0_canary_candidate_rank_v1,
    load_campaign_selection_authority_v1,
)
from robin.capture.contracts import CaptureContractError, canonical_sha256
from robin.capture.official_schedule_sources import (
    DFB_DATACENTER_HTML_V1,
    LALIGA_BOOTSTRAP_URL,
    BuiltinHttpsOfficialScheduleFetcher,
    OfficialHttpResponse,
    OfficialScheduleSourceError,
    OfficialSourceSpec,
    SupportingOfficialRead,
)
from robin.capture.owner_review_pack import (
    OwnerReviewPackError,
    _build_first_c0_owner_review_pack_after_atomic_binding_v1,
    build_owner_review_pack_v1,
    owner_authorization_statement_v1,
)
from robin.capture.owner_review_pack import (
    _write_first_c0_owner_review_pack_after_atomic_binding_v1 as write_owner_review_pack_v1,
)
from robin.capture.owner_review_pack import (
    write_owner_review_pack_v1 as public_write_owner_review_pack_v1,
)
from robin.capture.provider_network import (
    _PROVIDER_RESOLUTION_RESERVATION_AUTHORITY_V1,
    ProviderNetworkPreparationError,
    _prepare_provider_network_binding_after_reservation_v1,
    _reserve_first_c0_provider_network_resolution_after_atomic_preflight_v1,
)
from robin.capture.workspace_bootstrap import WorkspaceBootstrapError

BASE = datetime(2026, 8, 25, 12, 0, tzinfo=UTC)
MAIN_SHA = "a" * 40
LALIGA_SOURCE = (
    "https://apim.laliga.com/public-service/api/v1/matches?"
    "subscription=laliga-easports-2026&competition=primera-division&limit=100&offset=300"
)
BUNDESLIGA_SOURCE = "https://datencenter.dfb.de/competitions/12/seasons/current"


def _load_canary_cli() -> ModuleType:
    path = (
        Path(__file__).resolve().parents[2]
        / "tools"
        / "data-sourcing"
        / "prepare_first_c0_canary_selection_v1.py"
    )
    specification = importlib.util.spec_from_file_location("first_c0_canary_cli_tests", path)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


CANARY_CLI = _load_canary_cli()


def _load_data_sourcing_cli(filename: str, module_name: str) -> ModuleType:
    path = Path(__file__).resolve().parents[2] / "tools" / "data-sourcing" / filename
    specification = importlib.util.spec_from_file_location(module_name, path)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


PROVIDER_BINDING_CLI = _load_data_sourcing_cli(
    "prepare_provider_network_binding_v1.py",
    "first_c0_canary_provider_binding_cli_tests",
)
OWNER_PACK_CLI = _load_data_sourcing_cli(
    "build_owner_review_pack_v1.py",
    "first_c0_canary_owner_pack_cli_tests",
)
OWNER_ATOMIC_CLI = _load_data_sourcing_cli(
    "run_first_c0_owner_pack_atomic_v1.py",
    "first_c0_owner_atomic_cli_tests",
)


@pytest.fixture(autouse=True)
def _isolated_mission_global_preparation_registry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    registry = tmp_path / "mission-global-preparation-registry"
    registry.mkdir()
    legacy_registry = tmp_path / "legacy-global-preparation-registry"
    monkeypatch.setattr(
        CANARY_CLI.global_claims,
        "resolve_global_claim_root_candidate_v2",
        lambda _workspace: registry,
    )
    monkeypatch.setattr(
        CANARY_CLI.global_claims,
        "ensure_global_claim_root_v2",
        lambda _workspace, **_kwargs: registry,
    )
    monkeypatch.setattr(
        CANARY_CLI.global_claims,
        "inspect_global_claim_root_identity_v2",
        lambda _workspace: ("synthetic-stable-global-root",),
    )

    def read_snapshot(_workspace: object) -> tuple[Path, tuple[object, ...]]:
        selected = CANARY_CLI.global_claims.resolve_global_claim_root_candidate_v2(_workspace)
        metadata = selected.lstat()
        return selected, ("synthetic-global-root", metadata.st_dev, metadata.st_ino)

    monkeypatch.setattr(
        CANARY_CLI.global_claims,
        "_global_claim_root_read_snapshot_v2",
        read_snapshot,
    )
    monkeypatch.setattr(
        CANARY_CLI.global_claims,
        "inspect_global_claim_root_identity_v2",
        lambda workspace: read_snapshot(workspace)[1],
    )

    def ensure_with_identity(
        workspace: object,
        *,
        expected_read_identity: tuple[object, ...] | None = None,
    ) -> object:
        selected, identity = read_snapshot(workspace)
        if expected_read_identity is not None and identity != expected_read_identity:
            raise CANARY_CLI.global_claims.GlobalClaimBoundaryError(
                "GLOBAL_CLAIM_ROOT_IDENTITY_CHANGED"
            )
        return CANARY_CLI.global_claims._EnsuredGlobalClaimRootV2(selected, identity)

    monkeypatch.setattr(
        CANARY_CLI.global_claims,
        "_ensure_global_claim_root_with_identity_v2",
        ensure_with_identity,
    )
    monkeypatch.setattr(
        CANARY_CLI.global_claims,
        "resolve_legacy_global_claim_root_read_only_v1",
        lambda: legacy_registry,
    )
    return registry


def test_public_selector_constructs_its_fetcher_and_exposes_no_injected_effect_adapter(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    public_selector = CANARY_CLI.prepare_first_c0_canary_selection_v1
    assert tuple(inspect.signature(public_selector).parameters) == (
        "workspace_receipt",
        "workspace_receipt_bytes",
        "mission_manifest_path",
        "source_plan_bytes",
        "output_directory",
    )
    assert not hasattr(OWNER_ATOMIC_CLI, "run_first_c0_owner_pack_atomic_v1")
    workspace = workspace_receipt(tmp_path)
    manifest = first_c0_vertical_manifest()
    forged_manifests = (
        manifest.model_copy(update={"expires_at": manifest.expires_at - timedelta(hours=1)}),
        manifest.model_copy(
            update={
                "source_hash": ("3d3b43f68c0d339448e52de7ec66cce068646a4a006e267dfe063bffe2767f5e")
            }
        ),
        manifest.model_copy(
            update={
                "source_hash": ("0270bdd51d8d50b7d3c9f608e4f429b46b94b789d92d4b13055b81c9b72e6291")
            }
        ),
    )
    repository = Path(workspace.runtime_repository_root)
    manifest_path = repository / "configs/execution/first-c0-vertical-v1.json"
    manifest_path.parent.mkdir(parents=True)
    manifest_path.write_text(manifest.model_dump_json(), encoding="utf-8")
    forged_manifest_path = tmp_path / "forged-manifest.json"
    forged_manifest_path.write_text(
        forged_manifests[0].model_dump_json(),
        encoding="utf-8",
    )
    tracked_fetcher = object()
    constructor_calls = 0
    constructor_arguments: list[dict[str, object]] = []
    observed: dict[str, object] = {}
    sentinel = object()

    def construct_tracked_fetcher(**kwargs: object) -> object:
        nonlocal constructor_calls
        constructor_calls += 1
        constructor_arguments.append(kwargs)
        return tracked_fetcher

    def observe_private_core(**kwargs: object) -> object:
        observed.update(kwargs)
        return sentinel

    monkeypatch.setattr(
        CANARY_CLI,
        "BuiltinHttpsOfficialScheduleFetcher",
        construct_tracked_fetcher,
    )
    monkeypatch.setattr(
        CANARY_CLI,
        "_prepare_first_c0_canary_selection_v1",
        observe_private_core,
    )
    arguments = {
        "workspace_receipt": workspace,
        "workspace_receipt_bytes": workspace.model_dump_json().encode(),
        "mission_manifest_path": manifest_path,
        "source_plan_bytes": b"synthetic-not-consumed-by-observer",
        "output_directory": tmp_path / "bundle",
    }
    with pytest.raises(TypeError, match="unexpected keyword argument 'fetcher'"):
        public_selector(**arguments, fetcher=object())
    assert constructor_calls == 0
    for forged_manifest in forged_manifests:
        with pytest.raises(
            TypeError,
            match="unexpected keyword argument 'mission_manifest'",
        ):
            public_selector(**arguments, mission_manifest=forged_manifest)
    assert constructor_calls == 0
    with pytest.raises(
        WorkspaceBootstrapError,
        match="^BOOTSTRAP_MISSION_MANIFEST_PATH_MISMATCH$",
    ):
        public_selector(**{**arguments, "mission_manifest_path": forged_manifest_path})
    assert constructor_calls == 0
    assert public_selector(**arguments) is sentinel
    assert constructor_calls == 1
    assert constructor_arguments == [{"maximum_redirects": 0}]
    assert observed == {
        "workspace_receipt": workspace,
        "workspace_receipt_bytes": arguments["workspace_receipt_bytes"],
        "mission_manifest": manifest,
        "mission_manifest_bytes": manifest_path.read_bytes(),
        "source_plan_bytes": arguments["source_plan_bytes"],
        "output_directory": arguments["output_directory"],
        "fetcher": tracked_fetcher,
    }


def test_first_c0_pinned_fetcher_rejects_redirect_after_one_physical_get(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for invalid_limit in (-1, 6, True, 0.5):
        with pytest.raises(ValueError, match="^OFFICIAL_FETCH_LIMIT_INVALID$"):
            BuiltinHttpsOfficialScheduleFetcher(maximum_redirects=invalid_limit)  # type: ignore[arg-type]
    physical_gets = 0

    class RedirectResponse:
        status = 302

        @staticmethod
        def getheader(name: str, default: str | None = None) -> str | None:
            if name == "Location":
                return BUNDESLIGA_SOURCE
            return default

        @staticmethod
        def getheaders() -> list[tuple[str, str]]:
            return []

        @staticmethod
        def read(_maximum_bytes: int) -> bytes:
            return b""

    class RedirectConnection:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def request(self, *_args: object, **_kwargs: object) -> None:
            nonlocal physical_gets
            physical_gets += 1

        @staticmethod
        def getresponse() -> RedirectResponse:
            return RedirectResponse()

        @staticmethod
        def close() -> None:
            pass

    monkeypatch.setattr(
        official_sources_module.http.client,
        "HTTPSConnection",
        RedirectConnection,
    )
    fetcher = BuiltinHttpsOfficialScheduleFetcher(maximum_redirects=0)
    source = OfficialSourceSpec(
        sport_key="soccer_germany_bundesliga",
        adapter=DFB_DATACENTER_HTML_V1,
        url=BUNDESLIGA_SOURCE,
    )
    with pytest.raises(
        OfficialScheduleSourceError,
        match="^OFFICIAL_SOURCE_REDIRECT_LIMIT_EXCEEDED$",
    ):
        fetcher.fetch(source)
    assert physical_gets == 1


def test_preparation_reservation_is_mission_global_across_fresh_workspaces(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    _isolated_mission_global_preparation_registry: Path,
) -> None:
    first_workspace = workspace_receipt(tmp_path / "first-runtime")
    second_workspace = workspace_receipt(tmp_path / "second-runtime")
    Path(first_workspace.control_temp_root).mkdir(parents=True)
    Path(second_workspace.control_temp_root).mkdir(parents=True)
    manifest = mission_manifest(expires_at=BASE + timedelta(days=10))
    plan_bytes = _source_plan_bytes(
        "soccer_spain_la_liga",
        "LALIGA_PUBLIC_MATCHES_JSON_V1",
        LALIGA_SOURCE,
    )
    plan = CANARY_CLI.load_first_c0_canary_source_plan_v1(plan_bytes)
    reservation = CANARY_CLI._write_official_read_reservation(
        first_workspace,
        manifest,
        plan,
        cycle_index=1,
        cycle_role="PRIMARY_INITIAL",
        prior_cycle_receipt_sha256=None,
        official_reads_reserved=2,
        cumulative_official_reads_reserved=2,
        recorded_at_utc=BASE,
    )
    reservation_bytes = reservation.payload
    global_reservation = CANARY_CLI._mission_global_cycle_reservation_path(
        first_workspace, manifest, 1
    )
    assert global_reservation.parent == _isolated_mission_global_preparation_registry
    assert global_reservation.read_bytes() == reservation_bytes
    legacy_reservation = CANARY_CLI.global_claims.global_claim_marker_paths_v2(
        first_workspace,
        global_reservation.name,
    ).legacy
    assert not legacy_reservation.parent.exists()
    assert json.loads(reservation_bytes)["workspace_receipt_sha256"] == (
        first_workspace.canonical_receipt_hash
    )

    fetch_calls = 0

    class ForbiddenFetcher:
        def fetch(self, _source: object) -> object:
            nonlocal fetch_calls
            fetch_calls += 1
            raise AssertionError("second runtime reached an official read")

    monkeypatch.setattr(
        CANARY_CLI,
        "assert_workspace_control_artifact_destination_v1",
        lambda _workspace, destination: destination,
    )
    with pytest.raises(
        CANARY_CLI.FirstC0CanaryPreparationError,
        match="^FIRST_C0_CANARY_GLOBAL_PREPARATION_CYCLE_ALREADY_RESERVED$",
    ):
        CANARY_CLI._prepare_first_c0_canary_selection_v1(
            workspace_receipt=second_workspace,
            workspace_receipt_bytes=second_workspace.model_dump_json().encode(),
            mission_manifest=manifest,
            mission_manifest_bytes=manifest.model_dump_json().encode(),
            source_plan_bytes=plan_bytes,
            output_directory=Path(second_workspace.control_temp_root) / "bundle",
            fetcher=ForbiddenFetcher(),
            clock=lambda: BASE,
            workspace_validator=lambda _workspace: None,
            marker_inspector=lambda _workspace, _manifest: {
                "local_marker_present": False,
                "v2_global_marker_present": False,
                "legacy_global_marker_present": False,
                "inspected_read_only": True,
            },
        )
    assert fetch_calls == 0
    assert global_reservation.read_bytes() == reservation_bytes
    assert not (
        Path(second_workspace.control_temp_root)
        / "first-c0-canary-cycle-01-read-reservation-v1.json"
    ).exists()
    assert not (Path(second_workspace.control_temp_root) / "bundle").exists()


@pytest.mark.parametrize(
    ("global_state", "expected_code"),
    (
        ("legacy", "FIRST_C0_CANARY_GLOBAL_PREPARATION_CYCLE_ALREADY_RESERVED"),
        ("v2", "FIRST_C0_CANARY_GLOBAL_PREPARATION_CYCLE_ALREADY_RESERVED"),
        ("equal", "FIRST_C0_CANARY_GLOBAL_PREPARATION_CYCLE_ALREADY_RESERVED"),
        ("conflict", "GLOBAL_CLAIM_LEGACY_CONFLICT"),
        ("invalid", "GLOBAL_CLAIM_MARKER_INVALID"),
    ),
)
def test_preparation_reservation_migration_states_fail_closed_before_fetch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    global_state: str,
    expected_code: str,
) -> None:
    first_workspace = workspace_receipt(tmp_path / "first-runtime")
    second_workspace = workspace_receipt(tmp_path / "second-runtime")
    Path(first_workspace.control_temp_root).mkdir(parents=True)
    Path(second_workspace.control_temp_root).mkdir(parents=True)
    manifest = mission_manifest(expires_at=BASE + timedelta(days=10))
    plan_bytes = _source_plan_bytes(
        "soccer_spain_la_liga",
        "LALIGA_PUBLIC_MATCHES_JSON_V1",
        LALIGA_SOURCE,
    )
    plan = CANARY_CLI.load_first_c0_canary_source_plan_v1(plan_bytes)
    reservation = CANARY_CLI._write_official_read_reservation(
        first_workspace,
        manifest,
        plan,
        cycle_index=1,
        cycle_role="PRIMARY_INITIAL",
        prior_cycle_receipt_sha256=None,
        official_reads_reserved=2,
        cumulative_official_reads_reserved=2,
        recorded_at_utc=BASE,
    )
    reservation_bytes = reservation.payload
    marker_name = CANARY_CLI._mission_global_cycle_reservation_path(
        first_workspace,
        manifest,
        1,
    ).name
    paths = CANARY_CLI.global_claims.global_claim_marker_paths_v2(
        first_workspace,
        marker_name,
    )
    paths.legacy.parent.mkdir()
    if global_state == "legacy":
        paths.legacy.write_bytes(reservation_bytes)
        paths.v2.unlink()
    elif global_state == "equal":
        paths.legacy.write_bytes(reservation_bytes)
    elif global_state == "conflict":
        conflicting = json.loads(reservation_bytes)
        conflicting["workspace_receipt_sha256"] = "f" * 64
        paths.legacy.write_bytes(CANARY_CLI.canonical_json_bytes(conflicting) + b"\n")
    elif global_state == "invalid":
        paths.legacy.write_bytes(b"{}\n")
        paths.v2.unlink()
    else:
        assert global_state == "v2"
    before = {path: path.read_bytes() for path in (paths.v2, paths.legacy) if path.exists()}
    fetch_calls = 0

    class ForbiddenFetcher:
        def fetch(self, _source: object) -> object:
            nonlocal fetch_calls
            fetch_calls += 1
            raise AssertionError("migration state reached an official read")

    monkeypatch.setattr(
        CANARY_CLI,
        "assert_workspace_control_artifact_destination_v1",
        lambda _workspace, destination: destination,
    )
    with pytest.raises(
        CANARY_CLI.FirstC0CanaryPreparationError,
        match=f"^{expected_code}$",
    ):
        CANARY_CLI._prepare_first_c0_canary_selection_v1(
            workspace_receipt=second_workspace,
            workspace_receipt_bytes=second_workspace.model_dump_json().encode(),
            mission_manifest=manifest,
            mission_manifest_bytes=manifest.model_dump_json().encode(),
            source_plan_bytes=plan_bytes,
            output_directory=Path(second_workspace.control_temp_root) / "bundle",
            fetcher=ForbiddenFetcher(),
            clock=lambda: BASE,
            workspace_validator=lambda _workspace: None,
            marker_inspector=lambda _workspace, _manifest: {
                "local_marker_present": False,
                "v2_global_marker_present": False,
                "legacy_global_marker_present": False,
                "inspected_read_only": True,
            },
        )
    assert fetch_calls == 0
    assert before == {path: path.read_bytes() for path in (paths.v2, paths.legacy) if path.exists()}
    assert not (
        Path(second_workspace.control_temp_root)
        / "first-c0-canary-cycle-01-read-reservation-v1.json"
    ).exists()
    assert not (Path(second_workspace.control_temp_root) / "bundle").exists()


@pytest.mark.parametrize(
    ("late_legacy_payload", "expected_code"),
    (
        (b'{"race":"legacy-conflict"}\n', "GLOBAL_CLAIM_LEGACY_CONFLICT"),
        (None, "GLOBAL_CLAIM_ALREADY_CONSUMED"),
    ),
)
def test_legacy_marker_inserted_after_reservation_is_rechecked_before_fetch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    late_legacy_payload: bytes | None,
    expected_code: str,
) -> None:
    workspace = workspace_receipt(tmp_path)
    control = Path(workspace.control_temp_root)
    control.mkdir(parents=True)
    manifest = mission_manifest(expires_at=BASE + timedelta(days=10))
    real_reserve = CANARY_CLI.global_claims.reserve_global_claim_marker_v2
    fetch_calls = 0

    def reserve_then_inject_legacy_conflict(
        receipt: RealCaptureWorkspaceReceiptV1,
        marker_name: str,
        payload: bytes,
        *,
        validator: object,
        expected_v2_read_identity: tuple[object, ...] | None = None,
        expected_legacy_root_identity: tuple[object, ...] | None = None,
    ) -> CANARY_CLI.global_claims.GlobalClaimReservationV2:
        written = real_reserve(
            receipt,
            marker_name,
            payload,
            validator=validator,
            expected_v2_read_identity=expected_v2_read_identity,
            expected_legacy_root_identity=expected_legacy_root_identity,
        )
        legacy = CANARY_CLI.global_claims.global_claim_marker_paths_v2(
            receipt,
            marker_name,
        ).legacy
        legacy.parent.mkdir()
        legacy.write_bytes(payload if late_legacy_payload is None else late_legacy_payload)
        return written

    class ForbiddenFetcher:
        def fetch(self, _source: object) -> object:
            nonlocal fetch_calls
            fetch_calls += 1
            raise AssertionError("legacy race reached an official read")

    monkeypatch.setattr(
        CANARY_CLI.global_claims,
        "reserve_global_claim_marker_v2",
        reserve_then_inject_legacy_conflict,
    )
    monkeypatch.setattr(
        CANARY_CLI,
        "assert_workspace_control_artifact_destination_v1",
        lambda _workspace, destination: destination,
    )
    with pytest.raises(
        CANARY_CLI.FirstC0CanaryPreparationError,
        match=f"^{expected_code}$",
    ):
        CANARY_CLI._prepare_first_c0_canary_selection_v1(
            workspace_receipt=workspace,
            workspace_receipt_bytes=workspace.model_dump_json().encode(),
            mission_manifest=manifest,
            mission_manifest_bytes=manifest.model_dump_json().encode(),
            source_plan_bytes=_source_plan_bytes(
                "soccer_spain_la_liga",
                "LALIGA_PUBLIC_MATCHES_JSON_V1",
                LALIGA_SOURCE,
            ),
            output_directory=control / "bundle",
            fetcher=ForbiddenFetcher(),
            clock=lambda: BASE,
            workspace_validator=lambda _workspace: None,
            marker_inspector=lambda _workspace, _manifest: {
                "local_marker_present": False,
                "v2_global_marker_present": False,
                "legacy_global_marker_present": False,
                "inspected_read_only": True,
            },
        )

    assert fetch_calls == 0
    assert (control / "first-c0-canary-cycle-01-read-reservation-v1.json").is_file()
    assert not (control / "bundle").exists()


def test_global_root_replacement_after_reservation_stops_before_official_fetch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    _isolated_mission_global_preparation_registry: Path,
) -> None:
    workspace = workspace_receipt(tmp_path)
    control = Path(workspace.control_temp_root)
    control.mkdir(parents=True)
    manifest = mission_manifest(expires_at=BASE + timedelta(days=10))
    registry = _isolated_mission_global_preparation_registry
    displaced = registry.parent / "mission-global-preparation-registry-displaced"
    real_reserve = CANARY_CLI.global_claims.reserve_global_claim_marker_v2
    fetch_calls = 0
    monkeypatch.setattr(
        CANARY_CLI.global_claims,
        "inspect_global_claim_root_identity_v2",
        lambda _workspace: (
            "synthetic-global-root",
            registry.stat().st_dev,
            registry.stat().st_ino,
        ),
    )

    def reserve_then_replace_root(
        receipt: RealCaptureWorkspaceReceiptV1,
        marker_name: str,
        payload: bytes,
        *,
        validator: object,
        expected_v2_read_identity: tuple[object, ...] | None = None,
        expected_legacy_root_identity: tuple[object, ...] | None = None,
    ) -> CANARY_CLI.global_claims.GlobalClaimReservationV2:
        reservation = real_reserve(
            receipt,
            marker_name,
            payload,
            validator=validator,
            expected_v2_read_identity=expected_v2_read_identity,
            expected_legacy_root_identity=expected_legacy_root_identity,
        )
        registry.rename(displaced)
        registry.mkdir()
        (registry / marker_name).write_bytes((displaced / marker_name).read_bytes())
        return reservation

    class ForbiddenFetcher:
        def fetch(self, _source: object) -> object:
            nonlocal fetch_calls
            fetch_calls += 1
            raise AssertionError("replacement root reached an official read")

    monkeypatch.setattr(
        CANARY_CLI.global_claims,
        "reserve_global_claim_marker_v2",
        reserve_then_replace_root,
    )
    monkeypatch.setattr(
        CANARY_CLI,
        "assert_workspace_control_artifact_destination_v1",
        lambda _workspace, destination: destination,
    )
    with pytest.raises(
        CANARY_CLI.FirstC0CanaryPreparationError,
        match="^GLOBAL_CLAIM_ROOT_IDENTITY_CHANGED$",
    ):
        CANARY_CLI._prepare_first_c0_canary_selection_v1(
            workspace_receipt=workspace,
            workspace_receipt_bytes=workspace.model_dump_json().encode(),
            mission_manifest=manifest,
            mission_manifest_bytes=manifest.model_dump_json().encode(),
            source_plan_bytes=_source_plan_bytes(
                "soccer_spain_la_liga",
                "LALIGA_PUBLIC_MATCHES_JSON_V1",
                LALIGA_SOURCE,
            ),
            output_directory=control / "bundle",
            fetcher=ForbiddenFetcher(),
            clock=lambda: BASE,
            workspace_validator=lambda _workspace: None,
            marker_inspector=lambda _workspace, _manifest: {
                "local_marker_present": False,
                "v2_global_marker_present": False,
                "legacy_global_marker_present": False,
                "inspected_read_only": True,
            },
        )

    assert fetch_calls == 0
    assert (control / "first-c0-canary-cycle-01-read-reservation-v1.json").is_file()
    assert not (control / "bundle").exists()


def test_workspace_replacement_during_global_assertion_stops_before_official_fetch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = workspace_receipt(tmp_path)
    control = Path(workspace.control_temp_root)
    control.mkdir(parents=True)
    original_identity = (control.stat().st_dev, control.stat().st_ino)
    retired = tmp_path / "retired-control"
    manifest = mission_manifest(expires_at=BASE + timedelta(days=10))
    real_assert = CANARY_CLI._assert_new_mission_global_reservation_current
    replaced = False
    fetch_calls = 0

    def assert_then_replace(*args: object, **kwargs: object) -> None:
        nonlocal replaced
        real_assert(*args, **kwargs)
        if not replaced:
            replaced = True
            control.rename(retired)
            control.mkdir()

    def validate_workspace(_workspace: RealCaptureWorkspaceReceiptV1) -> None:
        if (control.stat().st_dev, control.stat().st_ino) != original_identity:
            raise CANARY_CLI.FirstC0CanaryPreparationError(
                "FIRST_C0_CANARY_WORKSPACE_IDENTITY_CHANGED"
            )

    class ForbiddenFetcher:
        def fetch(self, _source: object) -> object:
            nonlocal fetch_calls
            fetch_calls += 1
            raise AssertionError("replacement workspace reached an official read")

    monkeypatch.setattr(
        CANARY_CLI,
        "_assert_new_mission_global_reservation_current",
        assert_then_replace,
    )
    monkeypatch.setattr(
        CANARY_CLI,
        "assert_workspace_control_artifact_destination_v1",
        lambda _workspace, destination: destination,
    )

    with pytest.raises(
        CANARY_CLI.FirstC0CanaryPreparationError,
        match="^FIRST_C0_CANARY_WORKSPACE_IDENTITY_CHANGED$",
    ):
        CANARY_CLI._prepare_first_c0_canary_selection_v1(
            workspace_receipt=workspace,
            workspace_receipt_bytes=workspace.model_dump_json().encode(),
            mission_manifest=manifest,
            mission_manifest_bytes=manifest.model_dump_json().encode(),
            source_plan_bytes=_source_plan_bytes(
                "soccer_spain_la_liga",
                "LALIGA_PUBLIC_MATCHES_JSON_V1",
                LALIGA_SOURCE,
            ),
            output_directory=control / "bundle",
            fetcher=ForbiddenFetcher(),
            clock=lambda: BASE,
            workspace_validator=validate_workspace,
            marker_inspector=lambda _workspace, _manifest: {
                "local_marker_present": False,
                "v2_global_marker_present": False,
                "legacy_global_marker_present": False,
                "inspected_read_only": True,
            },
        )

    assert fetch_calls == 0
    assert (retired / "first-c0-canary-cycle-01-read-reservation-v1.json").is_file()
    assert not (control / "bundle").exists()


@pytest.mark.parametrize("mutation", ("delete", "replace"))
def test_local_cycle_reservation_mutation_during_authority_sandwich_stops_before_fetch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    workspace = workspace_receipt(tmp_path)
    control = Path(workspace.control_temp_root)
    control.mkdir(parents=True)
    manifest = mission_manifest(expires_at=BASE + timedelta(days=10))
    real_assert = CANARY_CLI._assert_new_mission_global_reservation_current
    assertion_calls = 0
    fetch_calls = 0

    def assert_then_mutate(*args: object, **kwargs: object) -> None:
        nonlocal assertion_calls
        real_assert(*args, **kwargs)
        assertion_calls += 1
        if assertion_calls == 2:
            marker = CANARY_CLI._cycle_reservation_path(workspace, 1)
            if mutation == "delete":
                marker.unlink()
            else:
                marker.write_bytes(b'{"mutated":true}\n')

    class ForbiddenFetcher:
        def fetch(self, _source: object) -> object:
            nonlocal fetch_calls
            fetch_calls += 1
            raise AssertionError("mutated local reservation reached an official read")

    monkeypatch.setattr(
        CANARY_CLI,
        "_assert_new_mission_global_reservation_current",
        assert_then_mutate,
    )
    monkeypatch.setattr(
        CANARY_CLI,
        "assert_workspace_control_artifact_destination_v1",
        lambda _workspace, destination: destination,
    )

    with pytest.raises(
        CANARY_CLI.FirstC0CanaryPreparationError,
        match="^FIRST_C0_CANARY_OFFICIAL_READ_RESERVATION_INVALID$",
    ):
        CANARY_CLI._prepare_first_c0_canary_selection_v1(
            workspace_receipt=workspace,
            workspace_receipt_bytes=workspace.model_dump_json().encode(),
            mission_manifest=manifest,
            mission_manifest_bytes=manifest.model_dump_json().encode(),
            source_plan_bytes=_source_plan_bytes(
                "soccer_spain_la_liga",
                "LALIGA_PUBLIC_MATCHES_JSON_V1",
                LALIGA_SOURCE,
            ),
            output_directory=control / "bundle",
            fetcher=ForbiddenFetcher(),
            clock=lambda: BASE,
            workspace_validator=lambda _workspace: None,
            marker_inspector=lambda _workspace, _manifest: {
                "local_marker_present": False,
                "v2_global_marker_present": False,
                "legacy_global_marker_present": False,
                "inspected_read_only": True,
            },
        )

    assert fetch_calls == 0
    assert not (control / "bundle").exists()


def _seed_failed_primary_cycle(
    workspace: RealCaptureWorkspaceReceiptV1,
    manifest: RealExecutionMissionManifestV1,
) -> None:
    plan = CANARY_CLI.load_first_c0_canary_source_plan_v1(
        _source_plan_bytes(
            "soccer_spain_la_liga",
            "LALIGA_PUBLIC_MATCHES_JSON_V1",
            LALIGA_SOURCE,
        )
    )
    reservation = CANARY_CLI._write_official_read_reservation(
        workspace,
        manifest,
        plan,
        cycle_index=1,
        cycle_role="PRIMARY_INITIAL",
        prior_cycle_receipt_sha256=None,
        official_reads_reserved=2,
        cumulative_official_reads_reserved=2,
        recorded_at_utc=BASE,
    )
    CANARY_CLI._write_attempt_receipt(
        workspace,
        manifest,
        plan,
        cycle_index=1,
        cycle_role="PRIMARY_INITIAL",
        prior_cycle_receipt_sha256=None,
        reservation_sha256=hashlib.sha256(reservation.payload).hexdigest(),
        status="FAILED_BEFORE_DNS",
        code="OFFICIAL_SOURCE_HTTP_STATUS_INVALID",
        fallback_category="SOURCE_UNAVAILABLE",
        failure_classification="DETERMINISTIC",
        http_status=403,
        official_reads=2,
        supporting_official_reads=1,
        cumulative_official_reads=2,
        recommended_refresh_utc=None,
        selected_not_before_utc=None,
        bundle_manifest_sha256=None,
        official_fetch_receipt={},
        recorded_at_utc=BASE + timedelta(seconds=1),
    )


@pytest.mark.parametrize(
    ("artifact", "expected_code"),
    (
        ("local-reservation-delete", "FIRST_C0_CANARY_PREPARATION_HISTORY_INVALID"),
        ("local-receipt-mutate", "FIRST_C0_CANARY_ATTEMPT_RECEIPT_INVALID"),
        ("global-v2-delete", "FIRST_C0_CANARY_GLOBAL_PREPARATION_HISTORY_INVALID"),
        ("global-legacy-mutate", "GLOBAL_CLAIM_LEGACY_CONFLICT"),
    ),
)
def test_previous_cycle_authority_mutation_after_replay_stops_before_fetch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    artifact: str,
    expected_code: str,
) -> None:
    workspace = workspace_receipt(tmp_path)
    control = Path(workspace.control_temp_root)
    control.mkdir(parents=True)
    manifest = mission_manifest(expires_at=BASE + timedelta(days=10))
    _seed_failed_primary_cycle(workspace, manifest)
    marker_name = CANARY_CLI._mission_global_cycle_reservation_path(
        workspace,
        manifest,
        1,
    ).name
    marker_paths = CANARY_CLI.global_claims.global_claim_marker_paths_v2(
        workspace,
        marker_name,
    )
    if artifact == "global-legacy-mutate":
        marker_paths.legacy.parent.mkdir()
        marker_paths.legacy.write_bytes(marker_paths.v2.read_bytes())
    real_assert = CANARY_CLI._assert_new_mission_global_reservation_current
    mutated = False
    fetch_calls = 0

    def assert_then_mutate(*args: object, **kwargs: object) -> None:
        nonlocal mutated
        real_assert(*args, **kwargs)
        if mutated:
            return
        mutated = True
        if artifact == "local-reservation-delete":
            CANARY_CLI._cycle_reservation_path(workspace, 1).unlink()
        elif artifact == "local-receipt-mutate":
            CANARY_CLI._cycle_receipt_path(workspace, 1).write_bytes(b'{"mutated":true}\n')
        elif artifact == "global-v2-delete":
            marker_paths.v2.unlink()
        else:
            marker_paths.legacy.write_bytes(b'{"mutated":true}\n')

    class ForbiddenFetcher:
        def fetch(self, _source: object) -> object:
            nonlocal fetch_calls
            fetch_calls += 1
            raise AssertionError("revoked history reached an official read")

    monkeypatch.setattr(
        CANARY_CLI,
        "_assert_new_mission_global_reservation_current",
        assert_then_mutate,
    )
    monkeypatch.setattr(
        CANARY_CLI,
        "assert_workspace_control_artifact_destination_v1",
        lambda _workspace, destination: destination,
    )
    with pytest.raises(
        CANARY_CLI.FirstC0CanaryPreparationError,
        match=f"^{expected_code}$",
    ):
        CANARY_CLI._prepare_first_c0_canary_selection_v1(
            workspace_receipt=workspace,
            workspace_receipt_bytes=workspace.model_dump_json().encode(),
            mission_manifest=manifest,
            mission_manifest_bytes=manifest.model_dump_json().encode(),
            source_plan_bytes=_source_plan_bytes(
                "soccer_germany_bundesliga",
                "DFB_DATACENTER_HTML_V1",
                BUNDESLIGA_SOURCE,
            ),
            output_directory=control / "fallback-bundle",
            fetcher=ForbiddenFetcher(),
            clock=lambda: BASE + timedelta(seconds=2),
            workspace_validator=lambda _workspace: None,
            marker_inspector=lambda _workspace, _manifest: {
                "local_marker_present": False,
                "v2_global_marker_present": False,
                "legacy_global_marker_present": False,
                "inspected_read_only": True,
            },
        )

    assert mutated
    assert fetch_calls == 0
    assert not (control / "fallback-bundle").exists()


@pytest.mark.parametrize(
    ("root", "expected_code"),
    (
        ("v2", "GLOBAL_CLAIM_ROOT_IDENTITY_CHANGED"),
        ("legacy", "GLOBAL_CLAIM_LEGACY_CONFLICT"),
    ),
)
def test_root_swap_between_history_replay_and_new_reservation_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    _isolated_mission_global_preparation_registry: Path,
    root: str,
    expected_code: str,
) -> None:
    workspace = workspace_receipt(tmp_path)
    control = Path(workspace.control_temp_root)
    control.mkdir(parents=True)
    manifest = mission_manifest(expires_at=BASE + timedelta(days=10))
    _seed_failed_primary_cycle(workspace, manifest)
    real_write = CANARY_CLI._write_official_read_reservation
    swapped = False
    fetch_calls = 0

    def swap_then_write(*args: object, **kwargs: object) -> object:
        nonlocal swapped
        if not swapped:
            swapped = True
            if root == "v2":
                displaced = _isolated_mission_global_preparation_registry.with_name(
                    "mission-global-preparation-registry-v2-displaced"
                )
                _isolated_mission_global_preparation_registry.rename(displaced)
                _isolated_mission_global_preparation_registry.mkdir()
            else:
                legacy = CANARY_CLI.global_claims.resolve_legacy_global_claim_root_read_only_v1()
                legacy.mkdir()
        return real_write(*args, **kwargs)

    class ForbiddenFetcher:
        def fetch(self, _source: object) -> object:
            nonlocal fetch_calls
            fetch_calls += 1
            raise AssertionError("split-root history reached an official read")

    monkeypatch.setattr(CANARY_CLI, "_write_official_read_reservation", swap_then_write)
    monkeypatch.setattr(
        CANARY_CLI,
        "assert_workspace_control_artifact_destination_v1",
        lambda _workspace, destination: destination,
    )
    with pytest.raises(
        CANARY_CLI.FirstC0CanaryPreparationError,
        match=f"^{expected_code}$",
    ):
        CANARY_CLI._prepare_first_c0_canary_selection_v1(
            workspace_receipt=workspace,
            workspace_receipt_bytes=workspace.model_dump_json().encode(),
            mission_manifest=manifest,
            mission_manifest_bytes=manifest.model_dump_json().encode(),
            source_plan_bytes=_source_plan_bytes(
                "soccer_germany_bundesliga",
                "DFB_DATACENTER_HTML_V1",
                BUNDESLIGA_SOURCE,
            ),
            output_directory=control / "fallback-bundle",
            fetcher=ForbiddenFetcher(),
            clock=lambda: BASE + timedelta(seconds=2),
            workspace_validator=lambda _workspace: None,
            marker_inspector=lambda _workspace, _manifest: {
                "local_marker_present": False,
                "v2_global_marker_present": False,
                "legacy_global_marker_present": False,
                "inspected_read_only": True,
            },
        )

    cycle_2_marker = CANARY_CLI._mission_global_cycle_reservation_path(
        workspace,
        manifest,
        2,
    )
    assert swapped
    assert fetch_calls == 0
    assert not CANARY_CLI._cycle_reservation_path(workspace, 2).exists()
    assert not cycle_2_marker.exists()
    assert not (control / "fallback-bundle").exists()


def test_clock_mutation_before_final_fetch_barrier_stops_official_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = workspace_receipt(tmp_path)
    control = Path(workspace.control_temp_root)
    control.mkdir(parents=True)
    manifest = mission_manifest(expires_at=BASE + timedelta(days=10))
    clock_calls = 0
    fetch_calls = 0

    def mutating_clock() -> datetime:
        nonlocal clock_calls
        clock_calls += 1
        if clock_calls == 2:
            CANARY_CLI._cycle_reservation_path(workspace, 1).write_bytes(
                b'{"mutated-by-clock":true}\n'
            )
        return BASE

    class ForbiddenFetcher:
        def fetch(self, _source: object) -> object:
            nonlocal fetch_calls
            fetch_calls += 1
            raise AssertionError("clock-revoked authority reached an official read")

    monkeypatch.setattr(
        CANARY_CLI,
        "assert_workspace_control_artifact_destination_v1",
        lambda _workspace, destination: destination,
    )
    with pytest.raises(
        CANARY_CLI.FirstC0CanaryPreparationError,
        match="^FIRST_C0_CANARY_OFFICIAL_READ_RESERVATION_INVALID$",
    ):
        CANARY_CLI._prepare_first_c0_canary_selection_v1(
            workspace_receipt=workspace,
            workspace_receipt_bytes=workspace.model_dump_json().encode(),
            mission_manifest=manifest,
            mission_manifest_bytes=manifest.model_dump_json().encode(),
            source_plan_bytes=_source_plan_bytes(
                "soccer_spain_la_liga",
                "LALIGA_PUBLIC_MATCHES_JSON_V1",
                LALIGA_SOURCE,
            ),
            output_directory=control / "bundle",
            fetcher=ForbiddenFetcher(),
            clock=mutating_clock,
            workspace_validator=lambda _workspace: None,
            marker_inspector=lambda _workspace, _manifest: {
                "local_marker_present": False,
                "v2_global_marker_present": False,
                "legacy_global_marker_present": False,
                "inspected_read_only": True,
            },
        )

    assert clock_calls == 2
    assert fetch_calls == 0
    assert not (control / "bundle").exists()


def test_failure_receipt_refuses_replaced_control_root_after_official_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = workspace_receipt(tmp_path)
    control = Path(workspace.control_temp_root)
    control.mkdir(parents=True)
    original_identity = (control.stat().st_dev, control.stat().st_ino)
    retired = tmp_path / "retired-control-after-fetch"
    manifest = mission_manifest(expires_at=BASE + timedelta(days=10))
    supporting_raw = b"<html>public LaLiga bootstrap unavailable</html>"
    supporting = SupportingOfficialRead(
        requested_url=LALIGA_BOOTSTRAP_URL,
        final_url=LALIGA_BOOTSTRAP_URL,
        official_domain="www.laliga.com",
        status_code=200,
        content_type="text/html",
        byte_count=len(supporting_raw),
        raw_sha256=hashlib.sha256(supporting_raw).hexdigest(),
        redirect_chain=(),
    )
    fetch_calls = 0

    class ReplacingRejectedFetcher:
        def fetch(self, source: object) -> OfficialHttpResponse:
            nonlocal fetch_calls
            fetch_calls += 1
            control.rename(retired)
            control.mkdir()
            return OfficialHttpResponse(
                status_code=503,
                final_url=getattr(source, "url"),
                content_type="application/json",
                body=b"unavailable",
                supporting_official_reads=(supporting,),
                supporting_official_raw_bytes=(supporting_raw,),
            )

    def validate_workspace(_workspace: RealCaptureWorkspaceReceiptV1) -> None:
        if (control.stat().st_dev, control.stat().st_ino) != original_identity:
            raise CANARY_CLI.FirstC0CanaryPreparationError(
                "FIRST_C0_CANARY_WORKSPACE_IDENTITY_CHANGED"
            )

    monkeypatch.setattr(
        CANARY_CLI,
        "assert_workspace_control_artifact_destination_v1",
        lambda _workspace, destination: destination,
    )

    with pytest.raises(
        CANARY_CLI.FirstC0CanaryPreparationError,
        match="^FIRST_C0_CANARY_WORKSPACE_IDENTITY_CHANGED$",
    ):
        CANARY_CLI._prepare_first_c0_canary_selection_v1(
            workspace_receipt=workspace,
            workspace_receipt_bytes=workspace.model_dump_json().encode(),
            mission_manifest=manifest,
            mission_manifest_bytes=manifest.model_dump_json().encode(),
            source_plan_bytes=_source_plan_bytes(
                "soccer_spain_la_liga",
                "LALIGA_PUBLIC_MATCHES_JSON_V1",
                LALIGA_SOURCE,
            ),
            output_directory=control / "bundle",
            fetcher=ReplacingRejectedFetcher(),
            clock=lambda: BASE,
            workspace_validator=validate_workspace,
            marker_inspector=lambda _workspace, _manifest: {
                "local_marker_present": False,
                "v2_global_marker_present": False,
                "legacy_global_marker_present": False,
                "inspected_read_only": True,
            },
        )

    assert fetch_calls == 1
    assert not CANARY_CLI._cycle_receipt_path(workspace, 1).exists()
    assert not (retired / "first-c0-canary-cycle-01-attempt-receipt-v1.json").exists()


@pytest.mark.parametrize("location", ("v2", "legacy", "equal"))
def test_later_cycle_inserted_during_current_assertion_stops_before_official_fetch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    location: str,
) -> None:
    workspace = workspace_receipt(tmp_path)
    control = Path(workspace.control_temp_root)
    control.mkdir(parents=True)
    manifest = mission_manifest(expires_at=BASE + timedelta(days=10))
    real_assert = CANARY_CLI._assert_new_mission_global_reservation_current
    injected = False
    fetch_calls = 0

    def assert_then_inject(*args: object, **kwargs: object) -> None:
        nonlocal injected
        real_assert(*args, **kwargs)
        if injected:
            return
        injected = True
        marker = CANARY_CLI._mission_global_cycle_reservation_path(
            workspace,
            manifest,
            2,
        )
        paths = CANARY_CLI.global_claims.global_claim_marker_paths_v2(
            workspace,
            marker.name,
        )
        if location in {"v2", "equal"}:
            paths.v2.write_bytes(b'{"orphan_cycle":2}\n')
        if location in {"legacy", "equal"}:
            paths.legacy.parent.mkdir()
            paths.legacy.write_bytes(b'{"orphan_cycle":2}\n')

    class ForbiddenFetcher:
        def fetch(self, _source: object) -> object:
            nonlocal fetch_calls
            fetch_calls += 1
            raise AssertionError("late cycle reached an official read")

    monkeypatch.setattr(
        CANARY_CLI,
        "_assert_new_mission_global_reservation_current",
        assert_then_inject,
    )
    monkeypatch.setattr(
        CANARY_CLI,
        "assert_workspace_control_artifact_destination_v1",
        lambda _workspace, destination: destination,
    )

    with pytest.raises(
        CANARY_CLI.FirstC0CanaryPreparationError,
        match="^FIRST_C0_CANARY_PREPARATION_HISTORY_GAP$",
    ):
        CANARY_CLI._prepare_first_c0_canary_selection_v1(
            workspace_receipt=workspace,
            workspace_receipt_bytes=workspace.model_dump_json().encode(),
            mission_manifest=manifest,
            mission_manifest_bytes=manifest.model_dump_json().encode(),
            source_plan_bytes=_source_plan_bytes(
                "soccer_spain_la_liga",
                "LALIGA_PUBLIC_MATCHES_JSON_V1",
                LALIGA_SOURCE,
            ),
            output_directory=control / "bundle",
            fetcher=ForbiddenFetcher(),
            clock=lambda: BASE,
            workspace_validator=lambda _workspace: None,
            marker_inspector=lambda _workspace, _manifest: {
                "local_marker_present": False,
                "v2_global_marker_present": False,
                "legacy_global_marker_present": False,
                "inspected_read_only": True,
            },
        )

    assert fetch_calls == 0
    assert CANARY_CLI._cycle_reservation_path(workspace, 1).is_file()
    assert not (control / "bundle").exists()


@pytest.mark.parametrize("location", ("v2", "legacy", "equal"))
def test_provider_marker_inserted_during_current_assertion_stops_before_official_fetch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    location: str,
) -> None:
    workspace = workspace_receipt(tmp_path)
    control = Path(workspace.control_temp_root)
    control.mkdir(parents=True)
    manifest = mission_manifest(expires_at=BASE + timedelta(days=10))
    real_assert = CANARY_CLI._assert_new_mission_global_reservation_current
    injected = False
    fetch_calls = 0
    provider_marker_name = (
        f"{manifest.mission_id.casefold()}-{manifest.canonical_manifest_sha256()}.json"
    )
    provider_paths = CANARY_CLI.global_claims.global_claim_marker_paths_v2(
        workspace,
        provider_marker_name,
    )
    provider_claim = ProviderNetworkResolutionClaimV1.issue(
        mission_manifest_sha256=manifest.canonical_manifest_sha256(),
        workspace_receipt_sha256=workspace.canonical_receipt_hash,
        campaign_selection_sha256="3" * 64,
        fixture_target_set_sha256="4" * 64,
        claimed_at_utc=BASE,
        mission_expires_at_utc=manifest.expires_at,
    )
    provider_payload = (
        CANARY_CLI.canonical_json_bytes(provider_claim.model_dump(mode="json")) + b"\n"
    )

    def assert_then_inject(*args: object, **kwargs: object) -> None:
        nonlocal injected
        real_assert(*args, **kwargs)
        if injected:
            return
        injected = True
        if location in {"v2", "equal"}:
            provider_paths.v2.write_bytes(provider_payload)
        if location in {"legacy", "equal"}:
            provider_paths.legacy.parent.mkdir()
            provider_paths.legacy.write_bytes(provider_payload)

    class ForbiddenFetcher:
        def fetch(self, _source: object) -> object:
            nonlocal fetch_calls
            fetch_calls += 1
            raise AssertionError("provider marker reached an official read")

    monkeypatch.setattr(
        CANARY_CLI,
        "_assert_new_mission_global_reservation_current",
        assert_then_inject,
    )
    monkeypatch.setattr(
        CANARY_CLI,
        "assert_workspace_control_artifact_destination_v1",
        lambda _workspace, destination: destination,
    )

    with pytest.raises(
        CANARY_CLI.FirstC0CanaryPreparationError,
        match="^FIRST_C0_CANARY_PROVIDER_MARKER_PRESENT$",
    ):
        CANARY_CLI._prepare_first_c0_canary_selection_v1(
            workspace_receipt=workspace,
            workspace_receipt_bytes=workspace.model_dump_json().encode(),
            mission_manifest=manifest,
            mission_manifest_bytes=manifest.model_dump_json().encode(),
            source_plan_bytes=_source_plan_bytes(
                "soccer_spain_la_liga",
                "LALIGA_PUBLIC_MATCHES_JSON_V1",
                LALIGA_SOURCE,
            ),
            output_directory=control / "bundle",
            fetcher=ForbiddenFetcher(),
            clock=lambda: BASE,
            workspace_validator=lambda _workspace: None,
            marker_inspector=CANARY_CLI.inspect_first_c0_canary_markers_read_only_v1,
        )

    assert fetch_calls == 0
    assert CANARY_CLI._cycle_reservation_path(workspace, 1).is_file()
    assert not (control / "bundle").exists()


def test_provider_marker_inserted_after_later_cycle_scan_stops_before_official_fetch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = workspace_receipt(tmp_path)
    control = Path(workspace.control_temp_root)
    control.mkdir(parents=True)
    manifest = mission_manifest(expires_at=BASE + timedelta(days=10))
    real_later_scan = CANARY_CLI._assert_no_later_cycle_artifacts
    injected = False
    fetch_calls = 0
    provider_marker_name = (
        f"{manifest.mission_id.casefold()}-{manifest.canonical_manifest_sha256()}.json"
    )
    provider_paths = CANARY_CLI.global_claims.global_claim_marker_paths_v2(
        workspace,
        provider_marker_name,
    )
    provider_claim = ProviderNetworkResolutionClaimV1.issue(
        mission_manifest_sha256=manifest.canonical_manifest_sha256(),
        workspace_receipt_sha256=workspace.canonical_receipt_hash,
        campaign_selection_sha256="3" * 64,
        fixture_target_set_sha256="4" * 64,
        claimed_at_utc=BASE,
        mission_expires_at_utc=manifest.expires_at,
    )
    provider_payload = (
        CANARY_CLI.canonical_json_bytes(provider_claim.model_dump(mode="json")) + b"\n"
    )

    def scan_then_inject(
        *args: object,
        **kwargs: object,
    ) -> tuple[tuple[object, ...], tuple[object, ...]]:
        nonlocal injected
        identities = real_later_scan(*args, **kwargs)
        if not injected:
            injected = True
            provider_paths.v2.write_bytes(provider_payload)
        return identities

    class ForbiddenFetcher:
        def fetch(self, _source: object) -> object:
            nonlocal fetch_calls
            fetch_calls += 1
            raise AssertionError("late provider marker reached an official read")

    monkeypatch.setattr(
        CANARY_CLI,
        "_assert_no_later_cycle_artifacts",
        scan_then_inject,
    )
    monkeypatch.setattr(
        CANARY_CLI,
        "assert_workspace_control_artifact_destination_v1",
        lambda _workspace, destination: destination,
    )

    with pytest.raises(
        CANARY_CLI.FirstC0CanaryPreparationError,
        match="^FIRST_C0_CANARY_PROVIDER_MARKER_PRESENT$",
    ):
        CANARY_CLI._prepare_first_c0_canary_selection_v1(
            workspace_receipt=workspace,
            workspace_receipt_bytes=workspace.model_dump_json().encode(),
            mission_manifest=manifest,
            mission_manifest_bytes=manifest.model_dump_json().encode(),
            source_plan_bytes=_source_plan_bytes(
                "soccer_spain_la_liga",
                "LALIGA_PUBLIC_MATCHES_JSON_V1",
                LALIGA_SOURCE,
            ),
            output_directory=control / "bundle",
            fetcher=ForbiddenFetcher(),
            clock=lambda: BASE,
            workspace_validator=lambda _workspace: None,
            marker_inspector=lambda _workspace, _manifest: {
                "local_marker_present": False,
                "v2_global_marker_present": False,
                "legacy_global_marker_present": False,
                "inspected_read_only": True,
            },
        )

    assert fetch_calls == 0
    assert not (control / "bundle").exists()


@pytest.mark.parametrize("location", ("v2", "legacy", "equal"))
def test_later_global_cycle_marker_blocks_backfill_before_official_fetch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    location: str,
) -> None:
    workspace = workspace_receipt(tmp_path)
    control = Path(workspace.control_temp_root)
    control.mkdir(parents=True)
    manifest = mission_manifest(expires_at=BASE + timedelta(days=10))
    marker = CANARY_CLI._mission_global_cycle_reservation_path(workspace, manifest, 2)
    paths = CANARY_CLI.global_claims.global_claim_marker_paths_v2(workspace, marker.name)
    payload = b'{"orphan_cycle":2}\n'
    if location in {"v2", "equal"}:
        paths.v2.write_bytes(payload)
    if location in {"legacy", "equal"}:
        paths.legacy.parent.mkdir()
        paths.legacy.write_bytes(payload)
    observed = tuple(path for path in (paths.v2, paths.legacy) if path.exists())
    before = {path: path.read_bytes() for path in observed}
    fetch_calls = 0

    class ForbiddenFetcher:
        def fetch(self, _source: object) -> object:
            nonlocal fetch_calls
            fetch_calls += 1
            raise AssertionError("global history gap reached an official read")

    monkeypatch.setattr(
        CANARY_CLI,
        "assert_workspace_control_artifact_destination_v1",
        lambda _workspace, destination: destination,
    )
    with pytest.raises(
        CANARY_CLI.FirstC0CanaryPreparationError,
        match="^FIRST_C0_CANARY_PREPARATION_HISTORY_GAP$",
    ):
        CANARY_CLI._prepare_first_c0_canary_selection_v1(
            workspace_receipt=workspace,
            workspace_receipt_bytes=workspace.model_dump_json().encode(),
            mission_manifest=manifest,
            mission_manifest_bytes=manifest.model_dump_json().encode(),
            source_plan_bytes=_source_plan_bytes(
                "soccer_spain_la_liga",
                "LALIGA_PUBLIC_MATCHES_JSON_V1",
                LALIGA_SOURCE,
            ),
            output_directory=control / "bundle",
            fetcher=ForbiddenFetcher(),
            clock=lambda: BASE,
            workspace_validator=lambda _workspace: None,
            marker_inspector=lambda _workspace, _manifest: {
                "local_marker_present": False,
                "v2_global_marker_present": False,
                "legacy_global_marker_present": False,
                "inspected_read_only": True,
            },
        )

    assert fetch_calls == 0
    assert before == {path: path.read_bytes() for path in observed}
    assert not CANARY_CLI._cycle_reservation_path(workspace, 1).exists()
    assert not (control / "bundle").exists()


def test_rehashed_primary_refresh_after_failed_primary_is_rejected_before_fetch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = workspace_receipt(tmp_path)
    control = Path(workspace.control_temp_root)
    control.mkdir(parents=True)
    manifest = mission_manifest(expires_at=BASE + timedelta(days=10))
    plan_bytes = _source_plan_bytes(
        "soccer_spain_la_liga",
        "LALIGA_PUBLIC_MATCHES_JSON_V1",
        LALIGA_SOURCE,
    )
    plan = CANARY_CLI.load_first_c0_canary_source_plan_v1(plan_bytes)

    cycle_1 = CANARY_CLI._write_official_read_reservation(
        workspace,
        manifest,
        plan,
        cycle_index=1,
        cycle_role="PRIMARY_INITIAL",
        prior_cycle_receipt_sha256=None,
        official_reads_reserved=2,
        cumulative_official_reads_reserved=2,
        recorded_at_utc=BASE,
    )
    CANARY_CLI._write_attempt_receipt(
        workspace,
        manifest,
        plan,
        cycle_index=1,
        cycle_role="PRIMARY_INITIAL",
        prior_cycle_receipt_sha256=None,
        reservation_sha256=hashlib.sha256(cycle_1.payload).hexdigest(),
        status="FAILED_BEFORE_DNS",
        code="OFFICIAL_SOURCE_HTTP_STATUS_INVALID",
        fallback_category="SOURCE_UNAVAILABLE",
        failure_classification="TRANSIENT",
        http_status=503,
        official_reads=2,
        supporting_official_reads=1,
        cumulative_official_reads=2,
        recommended_refresh_utc=None,
        selected_not_before_utc=None,
        bundle_manifest_sha256=None,
        official_fetch_receipt={},
        recorded_at_utc=BASE + timedelta(seconds=1),
    )
    cycle_1_receipt = CANARY_CLI._cycle_receipt_path(workspace, 1).read_bytes()
    prior_hash = hashlib.sha256(cycle_1_receipt).hexdigest()

    cycle_2 = CANARY_CLI._write_official_read_reservation(
        workspace,
        manifest,
        plan,
        cycle_index=2,
        cycle_role="PRIMARY_REFRESH",
        prior_cycle_receipt_sha256=prior_hash,
        official_reads_reserved=2,
        cumulative_official_reads_reserved=4,
        recorded_at_utc=BASE + timedelta(seconds=2),
    )
    CANARY_CLI._write_attempt_receipt(
        workspace,
        manifest,
        plan,
        cycle_index=2,
        cycle_role="PRIMARY_REFRESH",
        prior_cycle_receipt_sha256=prior_hash,
        reservation_sha256=hashlib.sha256(cycle_2.payload).hexdigest(),
        status="FAILED_BEFORE_DNS",
        code="OFFICIAL_SOURCE_HTTP_STATUS_INVALID",
        fallback_category="SOURCE_UNAVAILABLE",
        failure_classification="TRANSIENT",
        http_status=503,
        official_reads=2,
        supporting_official_reads=1,
        cumulative_official_reads=4,
        recommended_refresh_utc=None,
        selected_not_before_utc=None,
        bundle_manifest_sha256=None,
        official_fetch_receipt={},
        recorded_at_utc=BASE + timedelta(seconds=3),
    )
    marker = CANARY_CLI._mission_global_cycle_reservation_path(workspace, manifest, 2)
    pair = CANARY_CLI.global_claims.global_claim_marker_paths_v2(workspace, marker.name)
    pair.legacy.parent.mkdir(parents=True)
    pair.legacy.write_bytes(cycle_2.payload)
    tracked = (
        CANARY_CLI._cycle_reservation_path(workspace, 1),
        CANARY_CLI._cycle_receipt_path(workspace, 1),
        CANARY_CLI._cycle_reservation_path(workspace, 2),
        CANARY_CLI._cycle_receipt_path(workspace, 2),
        pair.v2,
        pair.legacy,
    )
    before = {path: path.read_bytes() for path in tracked}
    fetch_calls = 0

    class ForbiddenFetcher:
        def fetch(self, _source: object) -> object:
            nonlocal fetch_calls
            fetch_calls += 1
            raise AssertionError("illegal persisted transition reached fetch")

    monkeypatch.setattr(
        CANARY_CLI,
        "assert_workspace_control_artifact_destination_v1",
        lambda _workspace, destination: destination,
    )
    with pytest.raises(
        CANARY_CLI.FirstC0CanaryPreparationError,
        match="^FIRST_C0_CANARY_OFFICIAL_READ_RESERVATION_INVALID$",
    ):
        CANARY_CLI._prepare_first_c0_canary_selection_v1(
            workspace_receipt=workspace,
            workspace_receipt_bytes=workspace.model_dump_json().encode(),
            mission_manifest=manifest,
            mission_manifest_bytes=manifest.model_dump_json().encode(),
            source_plan_bytes=plan_bytes,
            output_directory=control / "illegal-transition-bundle",
            fetcher=ForbiddenFetcher(),
            clock=lambda: BASE + timedelta(seconds=4),
            workspace_validator=lambda _workspace: None,
            marker_inspector=lambda _workspace, _manifest: {
                "local_marker_present": False,
                "v2_global_marker_present": False,
                "legacy_global_marker_present": False,
                "inspected_read_only": True,
            },
        )

    assert fetch_calls == 0
    assert before == {path: path.read_bytes() for path in tracked}
    assert not (control / "illegal-transition-bundle").exists()


@pytest.mark.parametrize(
    ("field", "invalid_value"),
    (
        ("workspace_receipt_sha256", "g" * 64),
        ("source_plan_sha256", "f" * 64),
        ("cycle_role", "ARBITRARY"),
        ("official_reads_reserved", -1),
        ("official_reads_reserved", 1),
        ("cumulative_official_reads_reserved", 13),
        ("recorded_at_utc", "not-a-datetime"),
        ("url", "https://example.invalid/"),
    ),
)
def test_global_preparation_marker_validator_rejects_noncontract_fields(
    tmp_path: Path,
    field: str,
    invalid_value: object,
) -> None:
    workspace = workspace_receipt(tmp_path)
    Path(workspace.control_temp_root).mkdir(parents=True)
    manifest = mission_manifest(expires_at=BASE + timedelta(days=10))
    plan = CANARY_CLI.load_first_c0_canary_source_plan_v1(
        _source_plan_bytes(
            "soccer_spain_la_liga",
            "LALIGA_PUBLIC_MATCHES_JSON_V1",
            LALIGA_SOURCE,
        )
    )
    reservation = CANARY_CLI._write_official_read_reservation(
        workspace,
        manifest,
        plan,
        cycle_index=1,
        cycle_role="PRIMARY_INITIAL",
        prior_cycle_receipt_sha256=None,
        official_reads_reserved=2,
        cumulative_official_reads_reserved=2,
        recorded_at_utc=BASE,
    )
    valid_bytes = reservation.payload
    assert CANARY_CLI._valid_mission_global_reservation_v2(
        valid_bytes,
        manifest,
        1,
        expected_cycle_role="PRIMARY_INITIAL",
        expected_prior_cycle_receipt_sha256=None,
        expected_previous_cumulative_reads=0,
    )
    malformed = json.loads(valid_bytes)
    malformed[field] = invalid_value

    assert not CANARY_CLI._valid_mission_global_reservation_v2(
        CANARY_CLI.canonical_json_bytes(malformed) + b"\n",
        manifest,
        1,
        expected_cycle_role="PRIMARY_INITIAL",
        expected_prior_cycle_receipt_sha256=None,
        expected_previous_cumulative_reads=0,
    )


def mission_manifest(
    *, expires_at: datetime = BASE + timedelta(days=2)
) -> RealExecutionMissionManifestV1:
    return RealExecutionMissionManifestV1.issue(
        mission_id="REAL_EXECUTION_BOOTSTRAP_CLOSURE_V1",
        authorized_stages=("E1",),
        maximum_stage="E1",
        external_effects=(
            "local_standalone_runtime_create_after_merge",
            "github_public_full_clone_after_merge",
            "provider_public_dns_resolution_exactly_once_after_merge",
            "official_schedule_public_read_after_merge",
            "git_remote_write_non_force",
            "github_pull_request_write",
            "github_merge_commit",
            "github_actions_observe",
        ),
        compute_budget=8000,
        time_budget=345600,
        source_hash="204e4323d0b99fdfa8c655cdc3a08a8d2b3c82ac0a784f9a97982c90ab3a7312",
        expires_at=expires_at,
    )


def first_c0_vertical_manifest() -> RealExecutionMissionManifestV1:
    return RealExecutionMissionManifestV1.model_validate_json(
        (Path(__file__).parents[2] / "configs/execution/first-c0-vertical-v1.json").read_bytes()
    )


def workspace_receipt(tmp_path: Path) -> RealCaptureWorkspaceReceiptV1:
    repository = os.path.abspath(tmp_path / "repository")
    control = os.path.abspath(tmp_path / "control")
    capture = os.path.abspath(tmp_path / "capture")
    git_path = os.path.abspath(tmp_path / "git.exe")
    return RealCaptureWorkspaceReceiptV1.issue(
        authorized_main_sha=MAIN_SHA,
        bootstrap_mode="VERIFY",
        bootstrap_tool_source_repository_root=repository,
        bootstrap_tool_loaded_from_runtime_repository=True,
        bootstrap_package_source_repository_root=repository,
        bootstrap_package_loaded_from_runtime_repository=True,
        authority_eligible_for_real_execution=True,
        prepared_at_utc=BASE - timedelta(minutes=5),
        runtime_repository_root=repository,
        repository_root_fingerprint="1" * 64,
        repository_security_descriptor_sha256="2" * 64,
        control_temp_root=control,
        control_temp_fingerprint="3" * 64,
        control_temp_security_descriptor_sha256="4" * 64,
        capture_root=capture,
        capture_root_fingerprint="5" * 64,
        capture_security_descriptor_sha256="6" * 64,
        git_executable_path=git_path,
        git_executable_sha256="7" * 64,
        exact_detached_checkout=True,
        worktree_pristine=True,
        index_pristine=True,
        expected_remote_verified=True,
        submodules_absent=True,
        alternates_absent=True,
        unsafe_config_includes_absent=True,
        synchronized_roots_absent=True,
        cloud_placeholders_absent=True,
        reparse_escapes_absent=True,
        roots_non_overlapping=True,
        local_fixed_filesystem_verified=True,
        acl_exclusivity_verified=True,
    )


def source_target_set(
    workspace: RealCaptureWorkspaceReceiptV1,
    *,
    kickoffs: tuple[datetime, ...] = (BASE + timedelta(minutes=135),),
    sport_key: str = "soccer_spain_la_liga",
    authority: str | None = None,
    created_at: datetime = BASE - timedelta(minutes=3),
    observed_at: datetime = BASE - timedelta(minutes=4),
) -> FixtureTargetSetV1:
    expected_authority = (
        authority
        if authority is not None
        else LALIGA_SOURCE
        if sport_key == "soccer_spain_la_liga"
        else BUNDESLIGA_SOURCE
    )
    competition = "LALIGA EA SPORTS" if sport_key == "soccer_spain_la_liga" else "Bundesliga"
    targets = tuple(
        OfficialFixtureTargetV1.issue(
            internal_fixture_target_id=f"canary-fixture-{index}",
            competition=competition,
            sport_key=sport_key,
            official_home_team=f"Home {index}",
            official_away_team=f"Away {index}",
            official_kickoff_utc=kickoff,
            official_source_authority=expected_authority,
            source_observed_at_utc=observed_at,
            source_evidence_sha256="f" * 64,
        )
        for index, kickoff in enumerate(kickoffs, start=1)
    )
    return FixtureTargetSetV1.issue(
        target_set_id=f"canary-source-{sport_key}",
        sport_key=sport_key,
        workspace_receipt_sha256=workspace.canonical_receipt_hash,
        created_at_utc=created_at,
        official_schedule_horizon_not_before_utc=BASE - timedelta(hours=1),
        official_schedule_horizon_expires_at_utc=BASE + timedelta(days=8),
        official_schedule_fixture_count=len(targets),
        official_schedule_completeness="OWNER_REVIEWED_COMPLETE_OFFICIAL_HORIZON",
        targets=targets,
    )


def canary_selection(
    workspace: RealCaptureWorkspaceReceiptV1,
    manifest: RealExecutionMissionManifestV1,
    *,
    target_sets: tuple[FixtureTargetSetV1, ...] | None = None,
    selected_at: datetime = BASE,
) -> FirstC0CanarySelectionV1:
    return FirstC0CanarySelectionV1.issue(
        mission_id=manifest.mission_id,
        selected_at_utc=selected_at,
        workspace_receipt_sha256=workspace.canonical_receipt_hash,
        workspace_prepared_at_utc=workspace.prepared_at_utc,
        mission_manifest_sha256=manifest.canonical_manifest_sha256(),
        mission_expires_at_utc=manifest.expires_at,
        source_target_sets=target_sets or (source_target_set(workspace),),
    )


def test_nominal_single_laliga_h2_contract_is_one_call_one_credit(tmp_path: Path) -> None:
    workspace = workspace_receipt(tmp_path)
    manifest = mission_manifest()
    selection = canary_selection(workspace, manifest)
    selected = selection.selected_candidate()

    assert selection.schema_version == "robin-first-c0-canary-selection-v1"
    assert selection.mission_id == manifest.mission_id
    assert selection.selection_revision == FIRST_C0_CANARY_SELECTION_REVISION
    assert selection.purpose == "FIRST_REAL_CAPTURE_CANARY_ONLY"
    assert selection.ranking_policy == FIRST_C0_CANARY_RANKING_POLICY
    assert selection.source_target_set_count == selection.sport_key_count == 1
    assert selection.sport_key == "soccer_spain_la_liga"
    assert selected.window_id == "H2"
    assert selected.status == "OPEN_SELECTABLE"
    assert selected.request.sport_key == selection.sport_key
    assert selected.request.markets == selection.markets == ("h2h",)
    assert selected.request.region == selection.region == "eu"
    assert selected.one_call_http_ceiling == selection.maximum_http_calls == 1
    assert selected.one_call_credit_ceiling == selection.maximum_credits == 1
    assert selected.prior_admitted_fixture_count == 0
    assert selected.cross_league_corpus_value == 0
    assert selection.production_selection_authority is False
    assert selection.promotion_authority is False
    assert selection.batch_authority is False
    assert selection.scientific_edge_claim is False
    assert selection.selected_fixture_target_set_sha256 == (
        selected.fixture_target_set.canonical_set_hash
    )
    assert selection.canonical_selection_hash == canonical_sha256(selection.identity_material())


def test_exactly_one_official_target_set_and_one_sport_are_required(tmp_path: Path) -> None:
    workspace = workspace_receipt(tmp_path)
    manifest = mission_manifest()
    laliga = source_target_set(workspace)
    bundesliga = source_target_set(
        workspace,
        sport_key="soccer_germany_bundesliga",
        kickoffs=(BASE + timedelta(minutes=130),),
    )
    common = {
        "selected_at_utc": BASE,
        "workspace_receipt_sha256": workspace.canonical_receipt_hash,
        "workspace_prepared_at_utc": workspace.prepared_at_utc,
        "mission_manifest_sha256": manifest.canonical_manifest_sha256(),
        "mission_expires_at_utc": manifest.expires_at,
    }
    with pytest.raises(
        ValueError,
        match="FIRST_C0_CANARY_SOURCE_TARGET_SET_COUNT_INVALID",
    ):
        FirstC0CanarySelectionV1.issue(**common, source_target_sets=())
    with pytest.raises(
        ValueError,
        match="FIRST_C0_CANARY_SOURCE_TARGET_SET_COUNT_INVALID",
    ):
        FirstC0CanarySelectionV1.issue(
            **common,
            source_target_sets=(laliga, bundesliga),
        )


def test_official_source_staleness_forgery_and_kickoff_past_are_rejected(
    tmp_path: Path,
) -> None:
    workspace = workspace_receipt(tmp_path)
    manifest = mission_manifest()
    stale = source_target_set(
        workspace,
        created_at=BASE - timedelta(minutes=31),
        observed_at=BASE - timedelta(minutes=32),
        kickoffs=(BASE + timedelta(hours=3),),
    )
    with pytest.raises(ValueError, match="CAPTURE_CONTRACT_INVALID"):
        canary_selection(workspace, manifest, target_sets=(stale,))

    forged = source_target_set(
        workspace,
        authority="https://fixtures.example.test/not-official",
    )
    with pytest.raises(ValueError, match="CAPTURE_CONTRACT_INVALID"):
        canary_selection(workspace, manifest, target_sets=(forged,))

    passed = source_target_set(
        workspace,
        kickoffs=(BASE - timedelta(minutes=1),),
    )
    with pytest.raises(
        ValueError,
        match="FIRST_C0_CANARY_NO_REMAINING_SELECTABLE_CANDIDATE",
    ):
        canary_selection(workspace, manifest, target_sets=(passed,))


def test_temporal_statuses_roll_without_backdating_and_margin_is_required(
    tmp_path: Path,
) -> None:
    workspace = workspace_receipt(tmp_path)
    manifest = mission_manifest()
    future = canary_selection(
        workspace,
        manifest,
        target_sets=(
            source_target_set(
                workspace,
                kickoffs=(BASE + timedelta(hours=3),),
            ),
        ),
    )
    assert future.selected_candidate().status == "FUTURE_NOT_OPEN"
    assert future.selected_ready_at_selection is False
    with pytest.raises(
        ValueError,
        match="FIRST_C0_CANARY_SELECTED_CANDIDATE_NOT_OPEN",
    ):
        future.assert_selected_candidate_current(BASE)

    rollover = canary_selection(
        workspace,
        manifest,
        target_sets=(
            source_target_set(
                workspace,
                kickoffs=(
                    BASE + timedelta(minutes=119),
                    BASE + timedelta(hours=3),
                ),
            ),
        ),
    )
    assert any(candidate.status == "MISSED_NOT_BACKDATED" for candidate in rollover.candidates)
    assert rollover.selected_candidate().status == "FUTURE_NOT_OPEN"

    short_manifest = mission_manifest(expires_at=BASE + timedelta(seconds=60))
    with pytest.raises(
        ValueError,
        match="FIRST_C0_CANARY_NO_REMAINING_SELECTABLE_CANDIDATE",
    ):
        canary_selection(workspace, short_manifest)


def test_intrinsically_short_h2_clique_is_never_selected_for_canary_execution(
    tmp_path: Path,
) -> None:
    workspace = workspace_receipt(tmp_path)
    selection = canary_selection(
        workspace,
        mission_manifest(),
        target_sets=(
            source_target_set(
                workspace,
                kickoffs=(
                    BASE + timedelta(minutes=140),
                    BASE + timedelta(minutes=149),
                ),
            ),
        ),
    )
    short_cliques = tuple(
        candidate
        for candidate in selection.candidates
        if candidate.window_id == "H2"
        and candidate.fixture_coverage == 2
        and candidate.timing_margin_seconds < 840
    )
    assert short_cliques
    selected = selection.selected_candidate()
    assert selected.timing_margin_seconds >= 840
    assert selected.fixture_coverage == 1


def _changed_candidate(
    candidate: CampaignWindowCandidateV1,
    **updates: object,
) -> CampaignWindowCandidateV1:
    return candidate.model_copy(update=updates)


def test_canary_ranking_is_coverage_protocol_margin_readiness_then_hash(
    tmp_path: Path,
) -> None:
    workspace = workspace_receipt(tmp_path)
    manifest = mission_manifest()
    coverage_selection = canary_selection(
        workspace,
        manifest,
        target_sets=(
            source_target_set(
                workspace,
                kickoffs=(
                    BASE + timedelta(hours=25),
                    BASE + timedelta(hours=25, minutes=20),
                ),
            ),
        ),
    )
    assert coverage_selection.selected_candidate().window_id == "H24"
    assert coverage_selection.selected_candidate().fixture_coverage == 2

    protocol_selection = canary_selection(
        workspace,
        manifest,
        target_sets=(
            source_target_set(
                workspace,
                kickoffs=(BASE + timedelta(hours=25),),
            ),
        ),
    )
    assert protocol_selection.selected_candidate().window_id == "H2"

    readiness_selection = canary_selection(
        workspace,
        manifest,
        target_sets=(
            source_target_set(
                workspace,
                kickoffs=(
                    BASE + timedelta(hours=3),
                    BASE + timedelta(hours=4),
                ),
            ),
        ),
    )
    assert readiness_selection.selected_candidate().window_not_before_utc == (
        BASE + timedelta(minutes=45)
    )

    candidate = readiness_selection.selected_candidate()
    higher_coverage = _changed_candidate(
        candidate,
        fixture_coverage=candidate.fixture_coverage + 1,
    )
    higher_protocol = _changed_candidate(
        candidate,
        protocol_role_value=candidate.protocol_role_value + 1,
    )
    no_margin = _changed_candidate(candidate, timing_margin_seconds=0)
    later = _changed_candidate(
        candidate,
        window_not_before_utc=candidate.window_not_before_utc + timedelta(minutes=1),
    )
    higher_hash = _changed_candidate(candidate, stable_group_hash="f" * 64)
    assert _first_c0_canary_candidate_rank_v1(higher_coverage) < (
        _first_c0_canary_candidate_rank_v1(candidate)
    )
    assert _first_c0_canary_candidate_rank_v1(higher_protocol) < (
        _first_c0_canary_candidate_rank_v1(candidate)
    )
    assert _first_c0_canary_candidate_rank_v1(candidate) < (
        _first_c0_canary_candidate_rank_v1(no_margin)
    )
    assert _first_c0_canary_candidate_rank_v1(candidate) < (
        _first_c0_canary_candidate_rank_v1(later)
    )
    if candidate.stable_group_hash < higher_hash.stable_group_hash:
        assert _first_c0_canary_candidate_rank_v1(candidate) < (
            _first_c0_canary_candidate_rank_v1(higher_hash)
        )


def test_discriminated_loader_accepts_only_exact_known_schema(tmp_path: Path) -> None:
    selection = canary_selection(workspace_receipt(tmp_path), mission_manifest())
    loaded = load_campaign_selection_authority_v1(selection.model_dump(mode="json"))
    assert isinstance(loaded, FirstC0CanarySelectionV1)
    assert loaded == selection
    for payload, code in (
        ([], "CAMPAIGN_SELECTION_AUTHORITY_PAYLOAD_INVALID"),
        ({"schema_version": "unknown"}, "CAMPAIGN_SELECTION_AUTHORITY_SCHEMA_UNSUPPORTED"),
        ({}, "CAMPAIGN_SELECTION_AUTHORITY_SCHEMA_UNSUPPORTED"),
    ):
        with pytest.raises(CaptureContractError, match=code):
            load_campaign_selection_authority_v1(payload)
    tampered = selection.model_dump(mode="json")
    tampered["production_selection_authority"] = True
    with pytest.raises(
        CaptureContractError,
        match="FIRST_C0_CANARY_SELECTION_AUTHORITY_INVALID",
    ):
        load_campaign_selection_authority_v1(tampered)

    class DuckSelection:
        schema_version = selection.schema_version

        def model_dump(self) -> dict[str, object]:
            return selection.model_dump(mode="json")

    for duck_payload in (selection, DuckSelection()):
        with pytest.raises(
            CaptureContractError,
            match="CAMPAIGN_SELECTION_AUTHORITY_PAYLOAD_INVALID",
        ):
            load_campaign_selection_authority_v1(duck_payload)

    canary_masquerading_as_five_league = selection.model_dump(mode="json")
    canary_masquerading_as_five_league["schema_version"] = "robin-campaign-window-selection-v1"
    with pytest.raises(
        CaptureContractError,
        match="CAMPAIGN_WINDOW_SELECTION_AUTHORITY_INVALID",
    ):
        load_campaign_selection_authority_v1(canary_masquerading_as_five_league)

    five_league_masquerading_as_canary = {
        "schema_version": "robin-first-c0-canary-selection-v1",
        "selection_revision": "complete-five-league-interval-clique-ranking-v2",
        "source_target_sets": [],
    }
    with pytest.raises(
        CaptureContractError,
        match="FIRST_C0_CANARY_SELECTION_AUTHORITY_INVALID",
    ):
        load_campaign_selection_authority_v1(five_league_masquerading_as_canary)


def test_legacy_provider_and_owner_pack_clis_reject_v5_effects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    workspace = workspace_receipt(tmp_path)
    manifest = mission_manifest()
    selection = canary_selection(workspace, manifest, selected_at=BASE)
    selected = selection.selected_candidate()
    claim = ProviderNetworkResolutionClaimV1.issue(
        mission_manifest_sha256=manifest.canonical_manifest_sha256(),
        workspace_receipt_sha256=workspace.canonical_receipt_hash,
        campaign_selection_sha256=selection.canonical_selection_hash,
        fixture_target_set_sha256=selected.fixture_target_set.canonical_set_hash,
        claimed_at_utc=BASE - timedelta(seconds=65),
        mission_expires_at_utc=manifest.expires_at,
    )
    binding = ProviderNetworkBindingV1.issue(
        resolution_claim=claim,
        resolver_identity="SYNTHETIC_CLI_RESOLVER",
        observed_at_utc=BASE - timedelta(minutes=1),
        expires_at_utc=BASE + timedelta(minutes=14),
        binding_ttl_seconds=900,
        resolved_ip_addresses=("8.8.8.8",),
    )
    control = Path(workspace.control_temp_root)
    control.mkdir()
    workspace_path = control / "workspace.json"
    manifest_path = control / "manifest.json"
    selection_path = control / "selection.json"
    binding_path = control / "binding.json"
    provider_output = control / "provider-output.json"
    pack_output = control / "owner-pack"
    payloads: dict[Path, object] = {
        workspace_path: workspace.model_dump(mode="json"),
        selection_path: selection.model_dump(mode="json"),
        binding_path: binding.model_dump(mode="json"),
    }

    observed_provider_selection: list[FirstC0CanarySelectionV1] = []
    original_provider_builder = PROVIDER_BINDING_CLI.prepare_provider_network_binding_once_v1

    def fake_prepare_binding(**kwargs: object) -> ProviderNetworkBindingV1:
        campaign_selection = kwargs["campaign_selection"]
        assert isinstance(campaign_selection, FirstC0CanarySelectionV1)
        observed_provider_selection.append(campaign_selection)
        return original_provider_builder(**kwargs)

    monkeypatch.setattr(
        PROVIDER_BINDING_CLI,
        "parse_args",
        lambda: SimpleNamespace(
            workspace_receipt=workspace_path,
            mission_manifest=manifest_path,
            campaign_selection=selection_path,
            output=provider_output,
            binding_ttl_seconds=900,
        ),
    )
    monkeypatch.setattr(PROVIDER_BINDING_CLI, "_load", lambda path: payloads[path])
    monkeypatch.setattr(
        PROVIDER_BINDING_CLI,
        "assert_real_capture_workspace_receipt_current_v1",
        lambda _workspace: None,
    )
    monkeypatch.setattr(
        PROVIDER_BINDING_CLI,
        "assert_workspace_control_artifact_destination_v1",
        lambda _workspace, destination: destination,
    )
    monkeypatch.setattr(
        PROVIDER_BINDING_CLI,
        "load_tracked_real_execution_mission_manifest_v1",
        lambda _root, _path: manifest,
    )
    monkeypatch.setattr(
        PROVIDER_BINDING_CLI,
        "prepare_provider_network_binding_once_v1",
        fake_prepare_binding,
    )
    payloads[selection_path] = {"schema_version": "unknown-selection-schema"}
    assert PROVIDER_BINDING_CLI.main() == 2
    rejected_provider = json.loads(capsys.readouterr().out)
    assert rejected_provider == {
        "code": "CAMPAIGN_SELECTION_AUTHORITY_SCHEMA_UNSUPPORTED",
        "status": "FAILED",
    }
    assert observed_provider_selection == []
    assert not provider_output.exists()
    assert not (control / "provider-network-resolution-one-shot-v1.json").exists()

    payloads[selection_path] = selection.model_dump(mode="json")
    assert PROVIDER_BINDING_CLI.main() == 2
    provider_result = json.loads(capsys.readouterr().out)
    assert provider_result == {
        "code": "FIRST_C0_ATOMIC_PREFLIGHT_REQUIRED",
        "status": "FAILED",
    }
    assert observed_provider_selection == [selection]
    assert not provider_output.exists()
    assert not (control / "provider-network-resolution-one-shot-v1.json").exists()

    class FrozenDateTime(datetime):
        @classmethod
        def now(cls, tz: object = None) -> datetime:
            assert tz is UTC
            return BASE

    monkeypatch.setattr(
        OWNER_PACK_CLI,
        "_parser",
        lambda: SimpleNamespace(
            parse_args=lambda: SimpleNamespace(
                workspace_receipt=workspace_path,
                mission_manifest=manifest_path,
                provider_network_binding=binding_path,
                campaign_selection=selection_path,
                output_directory=pack_output,
            )
        ),
    )
    monkeypatch.setattr(OWNER_PACK_CLI, "_load", lambda path: payloads[path])
    monkeypatch.setattr(OWNER_PACK_CLI, "datetime", FrozenDateTime)
    monkeypatch.setattr(
        OWNER_PACK_CLI,
        "assert_real_capture_workspace_receipt_current_v1",
        lambda _workspace: None,
    )
    monkeypatch.setattr(
        OWNER_PACK_CLI,
        "assert_workspace_control_artifact_destination_v1",
        lambda _workspace, destination: destination,
    )
    monkeypatch.setattr(
        OWNER_PACK_CLI,
        "load_tracked_real_execution_mission_manifest_v1",
        lambda _root, _path: manifest,
    )
    monkeypatch.setattr(
        OWNER_PACK_CLI,
        "assert_owner_review_pack_completion_current_v1",
        lambda _pack, _observed_at: None,
    )
    original_public_pack_builder = OWNER_PACK_CLI.build_owner_review_pack_v1
    original_public_pack_writer = OWNER_PACK_CLI.write_owner_review_pack_v1
    public_builder_invocations = 0
    public_writer_invocations = 0
    actual_pack_builds = 0
    actual_pack_writes = 0

    def observed_pack_builder(**kwargs: object) -> OwnerReviewPackV1:
        nonlocal public_builder_invocations
        public_builder_invocations += 1
        return original_public_pack_builder(**kwargs)

    def observed_pack_writer(output: Path, pack: OwnerReviewPackV1) -> object:
        nonlocal public_writer_invocations
        public_writer_invocations += 1
        return original_public_pack_writer(output, pack)

    def forbidden_actual_pack_build(**_kwargs: object) -> OwnerReviewPackV1:
        nonlocal actual_pack_builds
        actual_pack_builds += 1
        raise AssertionError("standalone public path reached the private pack builder")

    def forbidden_actual_pack_write(_output: Path, _pack: OwnerReviewPackV1) -> object:
        nonlocal actual_pack_writes
        actual_pack_writes += 1
        raise AssertionError("standalone public path reached the private pack writer")

    monkeypatch.setattr(OWNER_PACK_CLI, "build_owner_review_pack_v1", observed_pack_builder)
    monkeypatch.setattr(OWNER_PACK_CLI, "write_owner_review_pack_v1", observed_pack_writer)
    monkeypatch.setattr(
        owner_review_pack_module,
        "_build_owner_review_pack_v1",
        forbidden_actual_pack_build,
    )
    monkeypatch.setattr(
        owner_review_pack_module,
        "_write_owner_review_pack_v1",
        forbidden_actual_pack_write,
    )
    payloads[selection_path] = {}
    assert OWNER_PACK_CLI.main() == 2
    rejected_pack = json.loads(capsys.readouterr().out)
    assert rejected_pack == {
        "code": "CAMPAIGN_SELECTION_AUTHORITY_SCHEMA_UNSUPPORTED",
        "status": "FAILED",
    }
    assert public_builder_invocations == public_writer_invocations == 0
    assert actual_pack_builds == actual_pack_writes == 0
    assert not pack_output.exists()

    payloads[selection_path] = selection.model_dump(mode="json")
    assert OWNER_PACK_CLI.main() == 2
    pack_result = json.loads(capsys.readouterr().out)
    assert pack_result == {
        "code": "FIRST_C0_SINGLE_OWNER_ENTRYPOINT_REQUIRED",
        "status": "FAILED",
    }
    assert public_builder_invocations == 1
    assert public_writer_invocations == 0
    assert actual_pack_builds == actual_pack_writes == 0
    assert not pack_output.exists()


def test_injected_dns_is_once_exact_and_system_resolver_is_never_called(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = workspace_receipt(tmp_path)
    manifest = mission_manifest()
    selection = canary_selection(workspace, manifest, selected_at=BASE - timedelta(minutes=2))
    selected = selection.selected_candidate()
    claim = ProviderNetworkResolutionClaimV1.issue(
        mission_manifest_sha256=manifest.canonical_manifest_sha256(),
        workspace_receipt_sha256=workspace.canonical_receipt_hash,
        campaign_selection_sha256=selection.canonical_selection_hash,
        fixture_target_set_sha256=selected.fixture_target_set.canonical_set_hash,
        claimed_at_utc=BASE - timedelta(seconds=65),
        mission_expires_at_utc=manifest.expires_at,
    )
    system_calls = 0

    def forbidden_system_resolver(*_args: object, **_kwargs: object) -> object:
        nonlocal system_calls
        system_calls += 1
        raise AssertionError("TEST_REAL_NETWORK_FORBIDDEN")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden_system_resolver)
    resolver_calls: list[tuple[object, ...]] = []

    def resolver(*args: object) -> tuple[tuple[object, ...], ...]:
        resolver_calls.append(args)
        return (
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("8.8.8.8", 443),
            ),
        )

    binding = _prepare_provider_network_binding_after_reservation_v1(
        resolution_claim=claim,
        resolver=resolver,
        observed_at_utc=BASE - timedelta(minutes=1),
        binding_ttl_seconds=900,
        resolver_identity="SYNTHETIC_INJECTED_RESOLVER",
        _reservation_authority=_PROVIDER_RESOLUTION_RESERVATION_AUTHORITY_V1,
    )
    assert len(resolver_calls) == 1
    assert system_calls == 0
    assert binding.resolution_operations == 1
    assert binding.resolution_claim.campaign_selection_sha256 == (
        selection.canonical_selection_hash
    )
    assert binding.resolution_claim.fixture_target_set_sha256 == (
        selected.fixture_target_set.canonical_set_hash
    )
    assert binding.provider_tcp_connections == binding.provider_http_requests == 0
    assert binding.provider_secret_reads == 0


def test_canary_atomic_path_840_second_gate_rejects_before_marker_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = workspace_receipt(tmp_path)
    manifest = mission_manifest()
    selection = canary_selection(workspace, manifest)
    output = tmp_path / "binding.json"
    writes = 0

    monkeypatch.setattr(
        "robin.capture.provider_network._validated_control_destination",
        lambda _workspace, _output: (tmp_path, output),
    )

    def write_forbidden(*_args: object, **_kwargs: object) -> None:
        nonlocal writes
        writes += 1

    monkeypatch.setattr(
        "robin.capture.provider_network._write_resolution_claim_marker_v1",
        write_forbidden,
    )
    with pytest.raises(
        ProviderNetworkPreparationError,
        match="PROVIDER_NETWORK_OWNER_REVIEW_WINDOW_INSUFFICIENT",
    ):
        _reserve_first_c0_provider_network_resolution_after_atomic_preflight_v1(
            workspace_receipt=workspace,
            mission_manifest=manifest,
            campaign_selection=selection,
            output_path=output,
            clock=lambda: BASE,
            binding_ttl_seconds=839,
            expected_global_v2_read_identity=("unused-before-margin-gate",),
            expected_global_legacy_root_identity=("unused-before-margin-gate",),
        )
    assert writes == 0


def test_synthetic_canary_pack_has_11_recomputable_artifacts_and_no_authority(
    tmp_path: Path,
) -> None:
    workspace = workspace_receipt(tmp_path)
    manifest = mission_manifest()
    selection = canary_selection(workspace, manifest, selected_at=BASE - timedelta(minutes=2))
    selected = selection.selected_candidate()
    claim = ProviderNetworkResolutionClaimV1.issue(
        mission_manifest_sha256=manifest.canonical_manifest_sha256(),
        workspace_receipt_sha256=workspace.canonical_receipt_hash,
        campaign_selection_sha256=selection.canonical_selection_hash,
        fixture_target_set_sha256=selected.fixture_target_set.canonical_set_hash,
        claimed_at_utc=BASE - timedelta(seconds=65),
        mission_expires_at_utc=manifest.expires_at,
    )
    binding = _prepare_provider_network_binding_after_reservation_v1(
        resolution_claim=claim,
        resolver=lambda *_args: (
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("8.8.8.8", 443),
            ),
        ),
        observed_at_utc=BASE - timedelta(minutes=1),
        binding_ttl_seconds=900,
        resolver_identity="SYNTHETIC_INJECTED_RESOLVER",
        _reservation_authority=_PROVIDER_RESOLUTION_RESERVATION_AUTHORITY_V1,
    )
    request_hash = canonical_sha256(selected.request.fingerprint_material())
    generated_text = BASE.isoformat().replace("+00:00", "Z")
    nonce_hash = canonical_sha256(
        {
            "workspace": workspace.canonical_receipt_hash,
            "binding": binding.canonical_binding_hash,
            "targets": selected.fixture_target_set.canonical_set_hash,
            "campaign_selection": selection.canonical_selection_hash,
            "request": request_hash,
            "generated_at": generated_text,
        }
    )
    owner_nonce = f"owner-{nonce_hash[:40]}"
    activation_nonce = f"activation-{nonce_hash[24:64]}"
    pack = _build_first_c0_owner_review_pack_after_atomic_binding_v1(
        workspace_receipt=workspace,
        mission_manifest=manifest,
        provider_network_binding=binding,
        campaign_selection=selection,
        generated_at_utc=BASE,
        authorization_nonce=owner_nonce,
        activation_nonce=activation_nonce,
    )
    for source_hash in (
        manifest.source_hash,
        "3d3b43f68c0d339448e52de7ec66cce068646a4a006e267dfe063bffe2767f5e",
        "0270bdd51d8d50b7d3c9f608e4f429b46b94b789d92d4b13055b81c9b72e6291",
    ):
        forged_manifest = manifest.model_copy(update={"source_hash": source_hash})
        with pytest.raises(
            OwnerReviewPackError,
            match="^FIRST_C0_SINGLE_OWNER_ENTRYPOINT_REQUIRED$",
        ):
            build_owner_review_pack_v1(
                workspace_receipt=workspace,
                mission_manifest=forged_manifest,
                provider_network_binding=binding,
                campaign_selection=selection,
                generated_at_utc=BASE,
                authorization_nonce=owner_nonce,
                activation_nonce=activation_nonce,
            )
        public_output = tmp_path / f"public-pack-{source_hash[:8]}"
        forged_pack = pack.model_copy(update={"mission_manifest": forged_manifest})
        with pytest.raises(
            OwnerReviewPackError,
            match="^FIRST_C0_SINGLE_OWNER_ENTRYPOINT_REQUIRED$",
        ):
            public_write_owner_review_pack_v1(public_output, forged_pack)
        assert not public_output.exists()
    round_trip = OwnerReviewPackV1.model_validate(pack.model_dump(mode="json"))
    assert isinstance(round_trip.campaign_selection, FirstC0CanarySelectionV1)
    assert round_trip.campaign_selection == selection
    assert pack.canonical_pack_hash == canonical_sha256(pack.identity_material())
    assert pack.owner_authorization_candidate.canonical_authorization_hash == canonical_sha256(
        pack.owner_authorization_candidate.identity_material()
    )
    assert pack.activation_candidate.canonical_activation_hash == canonical_sha256(
        pack.activation_candidate.identity_material()
    )
    assert pack.owner_authorization_candidate.authorization_nonce == owner_nonce
    assert pack.activation_candidate.activation_nonce == activation_nonce
    assert pack.owner_authorization_candidate.authorization_status == "OWNER_REVIEW_CANDIDATE"
    assert pack.owner_authorization_candidate.review_candidate_sha256 is None
    assert pack.owner_authorization_candidate.maximum_http_calls == 1
    assert pack.owner_authorization_candidate.maximum_credits == 1
    assert pack.owner_authorization_candidate.maximum_plan_items == 1
    assert pack.provider_http_calls == pack.real_secret_reads == pack.real_capture_calls == 0
    output = tmp_path / "owner-review-pack"
    output.mkdir()
    paths = write_owner_review_pack_v1(output, pack)
    assert len(paths) == 11
    assert set(paths) == {
        "owner_review_pack",
        "owner_authorization_candidate",
        "activation_candidate",
        "plan_candidate",
        "plan_item_candidate",
        "campaign_selection",
        "fixture_target_set",
        "provider_network_binding",
        "mission_manifest",
        "workspace_receipt",
        "request",
    }
    assert all(path.is_file() for path in paths.values())
    statement = owner_authorization_statement_v1(pack)
    for literal in (
        "SELECTION_SCHEMA=robin-first-c0-canary-selection-v1",
        "SELECTION_PURPOSE=FIRST_REAL_CAPTURE_CANARY_ONLY",
        "SOURCE_TARGET_SET_COUNT=1",
        "PRODUCTION_SELECTION_AUTHORITY=false",
        "PROMOTION_AUTHORITY=false",
        "BATCH_AUTHORITY=false",
        "SCIENTIFIC_EDGE_CLAIM=false",
    ):
        assert literal in statement


def _source_plan_bytes(sport_key: str, adapter: str, url: str) -> bytes:
    return json.dumps(
        {
            "schema_version": "robin-first-c0-canary-source-plan-v1",
            "sport_key": sport_key,
            "adapter": adapter,
            "url": url,
        },
        sort_keys=True,
    ).encode()


def _round_robin_rounds(clubs: list[str], count: int) -> list[list[tuple[str, str]]]:
    rotating = list(clubs)
    rounds: list[list[tuple[str, str]]] = []
    for _ in range(count):
        rounds.append(
            [(rotating[index], rotating[-index - 1]) for index in range(len(rotating) // 2)]
        )
        rotating = [rotating[0], rotating[-1], *rotating[1:-1]]
    return rounds


def _laliga_payload(*, latest: datetime | None = None) -> bytes:
    matches: list[dict[str, object]] = []
    collapse_round_kickoffs = latest is not None
    latest = latest or datetime(2026, 9, 7, 21, 0, tzinfo=UTC)
    clubs = [f"Liga Club {index:02d}" for index in range(20)]
    for week_index, games in enumerate(_round_robin_rounds(clubs, 8), start=1):
        for game_index, (home, away) in enumerate(games):
            matches.append(
                {
                    "id": f"laliga-{len(matches):03d}",
                    "competition": {"slug": "primera-division"},
                    "date": (
                        latest
                        - timedelta(
                            days=week_index - 1,
                            minutes=0 if collapse_round_kickoffs else game_index,
                        )
                    )
                    .isoformat()
                    .replace("+00:00", "Z"),
                    "home_team": {"name": home},
                    "away_team": {"name": away},
                    "gameweek": {"week": week_index},
                }
            )
    return json.dumps({"total": 380, "matches": matches}, sort_keys=True).encode()


def _bundesliga_payload() -> bytes:
    sections: list[str] = []
    base = datetime(2026, 8, 29, 15, 30)
    weekdays = {
        0: "Montag",
        1: "Dienstag",
        2: "Mittwoch",
        3: "Donnerstag",
        4: "Freitag",
        5: "Samstag",
        6: "Sonntag",
    }
    clubs = [f"Bund Club {index:02d}" for index in range(18)]
    rounds = _round_robin_rounds(clubs, 5)
    fixture_index = 0
    for matchday in range(1, 35):
        rows: list[str] = []
        if matchday <= 5:
            for game_index, (home, away) in enumerate(rounds[matchday - 1]):
                kickoff = base + timedelta(days=matchday - 1, minutes=game_index)
                rows.append(
                    '<div class="c-MatchTable-row">'
                    f'<span id="match_{1000 + fixture_index}"></span>'
                    f"{weekdays[kickoff.weekday()]}, {kickoff.strftime('%d.%m.%Y %H:%M')} Uhr"
                    '<div class="c-MatchTable-team--home"><a href="#">'
                    f"{home}</a></div>"
                    '<div class="c-MatchTable-team--away"><a href="#">'
                    f"{away}</a></div></div>"
                )
                fixture_index += 1
        sections.append(f"<h2>{matchday}. Spieltag</h2>{''.join(rows)}")
    return f"Bundesliga 2026/27 der Spielplan{''.join(sections)}".encode()


def test_cli_pipeline_publishes_one_immutable_selection_bundle_before_dns(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    control = tmp_path / "control"
    control.mkdir()
    workspace = workspace_receipt(tmp_path)
    manifest = mission_manifest(expires_at=BASE + timedelta(days=10))
    plan_bytes = _source_plan_bytes(
        "soccer_spain_la_liga",
        "LALIGA_PUBLIC_MATCHES_JSON_V1",
        LALIGA_SOURCE,
    )
    raw = _laliga_payload()
    supporting_raw = b"<html>public LaLiga bootstrap</html>"
    supporting = SupportingOfficialRead(
        requested_url=LALIGA_BOOTSTRAP_URL,
        final_url=LALIGA_BOOTSTRAP_URL,
        official_domain="www.laliga.com",
        status_code=200,
        content_type="text/html",
        byte_count=len(supporting_raw),
        raw_sha256=hashlib.sha256(supporting_raw).hexdigest(),
        redirect_chain=(),
    )
    fetch_calls = 0

    class SyntheticFetcher:
        def fetch(self, source: object) -> OfficialHttpResponse:
            nonlocal fetch_calls
            fetch_calls += 1
            return OfficialHttpResponse(
                status_code=200,
                final_url=getattr(source, "url"),
                content_type="application/json",
                body=raw,
                supporting_official_reads=(supporting,),
                supporting_official_raw_bytes=(supporting_raw,),
            )

    tick = BASE

    def clock() -> datetime:
        nonlocal tick
        observed = tick
        tick += timedelta(seconds=1)
        return observed

    monkeypatch.setattr(
        CANARY_CLI,
        "assert_workspace_control_artifact_destination_v1",
        lambda _workspace, destination: destination,
    )
    result = CANARY_CLI._prepare_first_c0_canary_selection_v1(
        workspace_receipt=workspace,
        workspace_receipt_bytes=workspace.model_dump_json().encode(),
        mission_manifest=manifest,
        mission_manifest_bytes=manifest.model_dump_json().encode(),
        source_plan_bytes=plan_bytes,
        output_directory=control / "canary-bundle",
        fetcher=SyntheticFetcher(),
        clock=clock,
        workspace_validator=lambda _workspace: None,
        marker_inspector=lambda _workspace, _manifest: {
            "schema_version": "synthetic-marker-inspection-v1",
            "local_marker_present": False,
            "v2_global_marker_present": False,
            "legacy_global_marker_present": False,
            "inspected_read_only": True,
        },
    )
    assert fetch_calls == 1
    assert result.official_reads == 2
    assert result.cycle_index == 1
    assert result.cumulative_official_reads == 2
    assert result.supporting_official_reads == 1
    assert result.status in {"CANARY_READY_NOW", "CANARY_FUTURE_WINDOW"}
    assert result.selection.source_target_set_count == 1
    assert result.selection.sport_key == "soccer_spain_la_liga"
    names = {path.name for path in result.bundle_directory.iterdir()}
    assert {
        "workspace-receipt.json",
        "mission-manifest.json",
        "source-plan.json",
        "official-source-raw.bin",
        "official-supporting-source-raw-1.bin",
        "official-fetch-receipt.json",
        "official-schedule-evidence.json",
        "fixture-target-set.json",
        "first-c0-canary-selection.json",
        "marker-inspection.json",
        "preparation-counters.json",
        "current-cycle-read-reservation.json",
        "bundle-manifest.json",
    } == names
    manifest_payload = json.loads((result.bundle_directory / "bundle-manifest.json").read_bytes())
    for name, expected_hash in manifest_payload["artifact_sha256"].items():
        assert (
            hashlib.sha256((result.bundle_directory / name).read_bytes()).hexdigest()
            == expected_hash
        )
    assert manifest_payload["provider_dns"] == 0
    assert manifest_payload["provider_http"] == 0
    assert manifest_payload["secret_reads"] == 0
    assert (control / "first-c0-canary-cycle-01-read-reservation-v1.json").is_file()
    assert (control / "first-c0-canary-cycle-01-attempt-receipt-v1.json").is_file()


def test_mission_expiry_between_reservation_and_official_read_stops_before_fetch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    control = tmp_path / "control"
    control.mkdir()
    workspace = workspace_receipt(tmp_path)
    manifest = mission_manifest(expires_at=BASE + timedelta(seconds=1))
    fetch_calls = 0
    clock_calls = 0

    class ForbiddenFetcher:
        def fetch(self, _source: object) -> object:
            nonlocal fetch_calls
            fetch_calls += 1
            raise AssertionError("expired mission reached the official read")

    def clock() -> datetime:
        nonlocal clock_calls
        clock_calls += 1
        return BASE if clock_calls == 1 else manifest.expires_at

    monkeypatch.setattr(
        CANARY_CLI,
        "assert_workspace_control_artifact_destination_v1",
        lambda _workspace, destination: destination,
    )
    with pytest.raises(
        CANARY_CLI.FirstC0CanaryPreparationError,
        match="BOOTSTRAP_MISSION_EXPIRED",
    ):
        CANARY_CLI._prepare_first_c0_canary_selection_v1(
            workspace_receipt=workspace,
            workspace_receipt_bytes=workspace.model_dump_json().encode(),
            mission_manifest=manifest,
            mission_manifest_bytes=manifest.model_dump_json().encode(),
            source_plan_bytes=_source_plan_bytes(
                "soccer_spain_la_liga",
                "LALIGA_PUBLIC_MATCHES_JSON_V1",
                LALIGA_SOURCE,
            ),
            output_directory=control / "canary-bundle",
            fetcher=ForbiddenFetcher(),
            clock=clock,
            workspace_validator=lambda _workspace: None,
            marker_inspector=lambda _workspace, _manifest: {
                "local_marker_present": False,
                "v2_global_marker_present": False,
                "legacy_global_marker_present": False,
                "inspected_read_only": True,
            },
        )
    assert fetch_calls == 0
    assert (control / "first-c0-canary-cycle-01-read-reservation-v1.json").is_file()
    attempt = json.loads(
        (control / "first-c0-canary-cycle-01-attempt-receipt-v1.json").read_bytes()
    )
    assert attempt["status"] == "FAILED_NO_FALLBACK"
    assert attempt["code"] == "BOOTSTRAP_MISSION_EXPIRED"
    assert attempt["fallback_category"] is None
    assert attempt["http_status"] == 0
    assert attempt["official_fetch_receipt"] is None
    assert not (control / "canary-bundle").exists()


def test_failed_official_read_observed_at_expiry_is_terminal_not_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    control = tmp_path / "control"
    control.mkdir()
    workspace = workspace_receipt(tmp_path)
    manifest = mission_manifest(expires_at=BASE + timedelta(seconds=1))
    supporting_raw = b"<html>public LaLiga bootstrap unavailable</html>"
    supporting = SupportingOfficialRead(
        requested_url=LALIGA_BOOTSTRAP_URL,
        final_url=LALIGA_BOOTSTRAP_URL,
        official_domain="www.laliga.com",
        status_code=200,
        content_type="text/html",
        byte_count=len(supporting_raw),
        raw_sha256=hashlib.sha256(supporting_raw).hexdigest(),
        redirect_chain=(),
    )
    fetch_calls = 0
    clock_calls = 0

    class RejectedFetcher:
        def fetch(self, source: object) -> OfficialHttpResponse:
            nonlocal fetch_calls
            fetch_calls += 1
            return OfficialHttpResponse(
                status_code=503,
                final_url=getattr(source, "url"),
                content_type="application/json",
                body=b"unavailable",
                supporting_official_reads=(supporting,),
                supporting_official_raw_bytes=(supporting_raw,),
            )

    def clock() -> datetime:
        nonlocal clock_calls
        clock_calls += 1
        return BASE if clock_calls <= 2 else manifest.expires_at

    monkeypatch.setattr(
        CANARY_CLI,
        "assert_workspace_control_artifact_destination_v1",
        lambda _workspace, destination: destination,
    )
    with pytest.raises(
        CANARY_CLI.FirstC0CanaryPreparationError,
        match="BOOTSTRAP_MISSION_EXPIRED",
    ):
        CANARY_CLI._prepare_first_c0_canary_selection_v1(
            workspace_receipt=workspace,
            workspace_receipt_bytes=workspace.model_dump_json().encode(),
            mission_manifest=manifest,
            mission_manifest_bytes=manifest.model_dump_json().encode(),
            source_plan_bytes=_source_plan_bytes(
                "soccer_spain_la_liga",
                "LALIGA_PUBLIC_MATCHES_JSON_V1",
                LALIGA_SOURCE,
            ),
            output_directory=control / "canary-bundle",
            fetcher=RejectedFetcher(),
            clock=clock,
            workspace_validator=lambda _workspace: None,
            marker_inspector=lambda _workspace, _manifest: {
                "local_marker_present": False,
                "v2_global_marker_present": False,
                "legacy_global_marker_present": False,
                "inspected_read_only": True,
            },
        )
    attempt = json.loads(
        (control / "first-c0-canary-cycle-01-attempt-receipt-v1.json").read_bytes()
    )
    assert fetch_calls == 1
    assert attempt["status"] == "FAILED_NO_FALLBACK"
    assert attempt["code"] == "BOOTSTRAP_MISSION_EXPIRED"
    assert attempt["fallback_category"] is None
    assert attempt["http_status"] == 503
    assert not (control / "canary-bundle").exists()


def test_post_fetch_processing_failure_after_expiry_cannot_authorize_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    control = tmp_path / "control"
    control.mkdir()
    workspace = workspace_receipt(tmp_path)
    manifest = mission_manifest(expires_at=BASE + timedelta(days=10))
    raw = _laliga_payload()
    supporting_raw = b"<html>public LaLiga bootstrap</html>"
    supporting = SupportingOfficialRead(
        requested_url=LALIGA_BOOTSTRAP_URL,
        final_url=LALIGA_BOOTSTRAP_URL,
        official_domain="www.laliga.com",
        status_code=200,
        content_type="text/html",
        byte_count=len(supporting_raw),
        raw_sha256=hashlib.sha256(supporting_raw).hexdigest(),
        redirect_chain=(),
    )
    expired = False
    fetch_calls = 0

    class SyntheticFetcher:
        def fetch(self, source: object) -> OfficialHttpResponse:
            nonlocal fetch_calls
            fetch_calls += 1
            return OfficialHttpResponse(
                status_code=200,
                final_url=getattr(source, "url"),
                content_type="application/json",
                body=raw,
                supporting_official_reads=(supporting,),
                supporting_official_raw_bytes=(supporting_raw,),
            )

    def expire_during_parse(*_args: object, **_kwargs: object) -> object:
        nonlocal expired
        expired = True
        raise OfficialScheduleSourceError("OFFICIAL_SCHEDULE_HORIZON_PARTIAL")

    monkeypatch.setattr(
        CANARY_CLI,
        "assert_workspace_control_artifact_destination_v1",
        lambda _workspace, destination: destination,
    )
    monkeypatch.setattr(CANARY_CLI, "build_official_schedule_evidence", expire_during_parse)
    with pytest.raises(
        CANARY_CLI.FirstC0CanaryPreparationError,
        match="BOOTSTRAP_MISSION_EXPIRED",
    ):
        CANARY_CLI._prepare_first_c0_canary_selection_v1(
            workspace_receipt=workspace,
            workspace_receipt_bytes=workspace.model_dump_json().encode(),
            mission_manifest=manifest,
            mission_manifest_bytes=manifest.model_dump_json().encode(),
            source_plan_bytes=_source_plan_bytes(
                "soccer_spain_la_liga",
                "LALIGA_PUBLIC_MATCHES_JSON_V1",
                LALIGA_SOURCE,
            ),
            output_directory=control / "canary-bundle",
            fetcher=SyntheticFetcher(),
            clock=lambda: manifest.expires_at if expired else BASE,
            workspace_validator=lambda _workspace: None,
            marker_inspector=lambda _workspace, _manifest: {
                "local_marker_present": False,
                "v2_global_marker_present": False,
                "legacy_global_marker_present": False,
                "inspected_read_only": True,
            },
        )
    attempt = json.loads(
        (control / "first-c0-canary-cycle-01-attempt-receipt-v1.json").read_bytes()
    )
    assert fetch_calls == 1
    assert attempt["status"] == "FAILED_NO_FALLBACK"
    assert attempt["code"] == "BOOTSTRAP_MISSION_EXPIRED"
    assert attempt["fallback_category"] is None
    assert not (control / "canary-bundle").exists()


@pytest.mark.parametrize("expiry_stage", ["pre_atomic_publish", "post_atomic_publish"])
def test_mission_expiry_during_bundle_publication_never_records_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    expiry_stage: str,
) -> None:
    control = tmp_path / "control"
    control.mkdir()
    workspace = workspace_receipt(tmp_path)
    manifest = mission_manifest(expires_at=BASE + timedelta(days=10))
    raw = _laliga_payload()
    supporting_raw = b"<html>public LaLiga bootstrap</html>"
    supporting = SupportingOfficialRead(
        requested_url=LALIGA_BOOTSTRAP_URL,
        final_url=LALIGA_BOOTSTRAP_URL,
        official_domain="www.laliga.com",
        status_code=200,
        content_type="text/html",
        byte_count=len(supporting_raw),
        raw_sha256=hashlib.sha256(supporting_raw).hexdigest(),
        redirect_chain=(),
    )
    expired = False
    fetch_calls = 0

    class SyntheticFetcher:
        def fetch(self, source: object) -> OfficialHttpResponse:
            nonlocal fetch_calls
            fetch_calls += 1
            return OfficialHttpResponse(
                status_code=200,
                final_url=getattr(source, "url"),
                content_type="application/json",
                body=raw,
                supporting_official_reads=(supporting,),
                supporting_official_raw_bytes=(supporting_raw,),
            )

    def clock() -> datetime:
        return manifest.expires_at if expired else BASE

    original_write_exclusive = CANARY_CLI._write_exclusive

    def write_exclusive(path: Path, payload: bytes) -> None:
        nonlocal expired
        original_write_exclusive(path, payload)
        if expiry_stage == "pre_atomic_publish" and path.name == "bundle-manifest.json":
            expired = True

    original_rename = CANARY_CLI.os.rename

    def rename(source: Path, destination: Path) -> None:
        nonlocal expired
        original_rename(source, destination)
        if expiry_stage == "post_atomic_publish":
            expired = True

    monkeypatch.setattr(CANARY_CLI, "_write_exclusive", write_exclusive)
    monkeypatch.setattr(CANARY_CLI.os, "rename", rename)
    monkeypatch.setattr(
        CANARY_CLI,
        "assert_workspace_control_artifact_destination_v1",
        lambda _workspace, destination: destination,
    )
    output = control / "canary-bundle"
    plan_bytes = _source_plan_bytes(
        "soccer_spain_la_liga",
        "LALIGA_PUBLIC_MATCHES_JSON_V1",
        LALIGA_SOURCE,
    )
    with pytest.raises(
        CANARY_CLI.FirstC0CanaryPreparationError,
        match="BOOTSTRAP_MISSION_EXPIRED",
    ):
        CANARY_CLI._prepare_first_c0_canary_selection_v1(
            workspace_receipt=workspace,
            workspace_receipt_bytes=workspace.model_dump_json().encode(),
            mission_manifest=manifest,
            mission_manifest_bytes=manifest.model_dump_json().encode(),
            source_plan_bytes=plan_bytes,
            output_directory=output,
            fetcher=SyntheticFetcher(),
            clock=clock,
            workspace_validator=lambda _workspace: None,
            marker_inspector=lambda _workspace, _manifest: {
                "local_marker_present": False,
                "v2_global_marker_present": False,
                "legacy_global_marker_present": False,
                "inspected_read_only": True,
            },
        )
    attempt = json.loads(
        (control / "first-c0-canary-cycle-01-attempt-receipt-v1.json").read_bytes()
    )
    assert fetch_calls == 1
    assert attempt["status"] == "FAILED_NO_FALLBACK"
    assert attempt["code"] == "BOOTSTRAP_MISSION_EXPIRED"
    assert attempt["bundle_manifest_sha256"] is None
    assert output.exists() is (expiry_stage == "post_atomic_publish")
    with pytest.raises(
        CANARY_CLI.FirstC0CanaryPreparationError,
        match="FIRST_C0_CANARY_ATTEMPT_RECEIPT_INVALID",
    ):
        CANARY_CLI._load_cycle_history(
            workspace,
            manifest,
            evaluated_at_utc=manifest.expires_at - timedelta(microseconds=1),
        )
    history = CANARY_CLI._load_cycle_history(
        workspace,
        manifest,
        evaluated_at_utc=manifest.expires_at + timedelta(seconds=1),
    )
    assert len(history) == 1
    assert history[0].receipt["code"] == "BOOTSTRAP_MISSION_EXPIRED"
    with pytest.raises(
        CANARY_CLI.FirstC0CanaryPreparationError,
        match="FIRST_C0_CANARY_FALLBACK_NOT_AUTHORIZED",
    ):
        CANARY_CLI._next_cycle_authority(
            history,
            CANARY_CLI.load_first_c0_canary_source_plan_v1(plan_bytes),
            started_at_utc=manifest.expires_at + timedelta(seconds=1),
        )


@pytest.mark.parametrize("preparation_seconds", [60, 120, 180])
def test_h2_prefetch_starts_at_t_minus_300_and_closes_reads_before_local_activation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    preparation_seconds: int,
) -> None:
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local-app-data"))
    control = tmp_path / "control"
    control.mkdir()
    workspace = workspace_receipt(tmp_path)
    manifest = mission_manifest(expires_at=BASE + timedelta(days=10))
    plan_bytes = _source_plan_bytes(
        "soccer_spain_la_liga",
        "LALIGA_PUBLIC_MATCHES_JSON_V1",
        LALIGA_SOURCE,
    )
    raw = _laliga_payload(latest=BASE + timedelta(hours=3))
    supporting_raw = b"<html>public LaLiga bootstrap</html>"
    supporting = SupportingOfficialRead(
        requested_url=LALIGA_BOOTSTRAP_URL,
        final_url=LALIGA_BOOTSTRAP_URL,
        official_domain="www.laliga.com",
        status_code=200,
        content_type="text/html",
        byte_count=len(supporting_raw),
        raw_sha256=hashlib.sha256(supporting_raw).hexdigest(),
        redirect_chain=(),
    )
    fetch_calls = 0

    class SyntheticFetcher:
        def fetch(self, source: object) -> OfficialHttpResponse:
            nonlocal fetch_calls
            fetch_calls += 1
            return OfficialHttpResponse(
                status_code=200,
                final_url=getattr(source, "url"),
                content_type="application/json",
                body=raw,
                supporting_official_reads=(supporting,),
                supporting_official_raw_bytes=(supporting_raw,),
            )

    tick = BASE
    clock_step = timedelta(seconds=1)

    def clock() -> datetime:
        nonlocal tick, clock_step
        observed = tick
        tick += clock_step
        return observed

    monkeypatch.setattr(
        CANARY_CLI,
        "assert_workspace_control_artifact_destination_v1",
        lambda _workspace, destination: destination,
    )
    common = {
        "workspace_receipt": workspace,
        "workspace_receipt_bytes": workspace.model_dump_json().encode(),
        "mission_manifest": manifest,
        "mission_manifest_bytes": manifest.model_dump_json().encode(),
        "source_plan_bytes": plan_bytes,
        "fetcher": SyntheticFetcher(),
        "clock": clock,
        "workspace_validator": lambda _workspace: None,
        "marker_inspector": CANARY_CLI.inspect_first_c0_canary_markers_read_only_v1,
    }
    first = CANARY_CLI._prepare_first_c0_canary_selection_v1(
        **common,
        output_directory=control / "cycle-1-bundle",
    )
    assert first.status == "CANARY_FUTURE_WINDOW"
    assert first.cycle_index == 1
    assert first.cumulative_official_reads == 2
    first_candidate = first.selection.selected_candidate()
    assert first_candidate.window_id == "H2"
    assert first.recommended_refresh_utc == (
        first_candidate.window_not_before_utc - timedelta(seconds=300)
    )
    tick = first.recommended_refresh_utc
    prefetch_started_at = tick
    # Twelve explicit authority/time boundaries span the modeled preparation.
    clock_step = timedelta(seconds=preparation_seconds / 12)
    second = CANARY_CLI._prepare_first_c0_canary_selection_v1(
        **common,
        output_directory=control / "cycle-2-bundle",
    )
    second_candidate = second.selection.selected_candidate()
    assert second.status == "PREFETCHED_FUTURE_WINDOW", (
        second.selection.selected_at_utc,
        second_candidate.window_id,
        second_candidate.status,
        second_candidate.window_not_before_utc,
        second_candidate.window_expires_at_utc,
    )
    assert second.cycle_index == 2
    assert second.cumulative_official_reads == 4
    assert fetch_calls == 2
    assert second.prefetch_handoff_path.is_file()
    assert len(second.prefetch_handoff_sha256) == 64
    handoff = json.loads(second.prefetch_handoff_path.read_bytes())
    handoff_at = datetime.fromisoformat(handoff["prefetched_at_utc"].replace("Z", "+00:00"))
    attempt = json.loads(
        (control / "first-c0-canary-cycle-02-attempt-receipt-v1.json").read_bytes()
    )
    completion_at = datetime.fromisoformat(attempt["recorded_at_utc"].replace("Z", "+00:00"))
    assert (completion_at - prefetch_started_at).total_seconds() == pytest.approx(
        preparation_seconds,
        abs=0.000_01,
    )
    assert handoff_at <= completion_at < second_candidate.window_not_before_utc
    names = {path.name for path in second.bundle_directory.iterdir()}
    assert "prior-cycle-01-read-reservation.json" in names
    assert "prior-cycle-01-attempt-receipt.json" in names
    assert "current-cycle-read-reservation.json" in names
    tick = second.selection.selected_not_before_utc
    second.selection.assert_selected_candidate_current(tick)
    assert fetch_calls == 2


@pytest.mark.parametrize("crossing_stage", ["published_at", "bundle", "handoff"])
def test_prefetch_publication_crossing_window_open_is_terminal_before_dns(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    crossing_stage: str,
) -> None:
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local-app-data"))
    control = tmp_path / "control"
    control.mkdir()
    workspace = workspace_receipt(tmp_path)
    manifest = mission_manifest(expires_at=BASE + timedelta(days=10))
    plan_bytes = _source_plan_bytes(
        "soccer_spain_la_liga",
        "LALIGA_PUBLIC_MATCHES_JSON_V1",
        LALIGA_SOURCE,
    )
    raw = _laliga_payload(latest=BASE + timedelta(hours=3))
    supporting_raw = b"<html>public LaLiga bootstrap</html>"
    supporting = SupportingOfficialRead(
        requested_url=LALIGA_BOOTSTRAP_URL,
        final_url=LALIGA_BOOTSTRAP_URL,
        official_domain="www.laliga.com",
        status_code=200,
        content_type="text/html",
        byte_count=len(supporting_raw),
        raw_sha256=hashlib.sha256(supporting_raw).hexdigest(),
        redirect_chain=(),
    )
    fetch_calls = 0

    class SyntheticFetcher:
        def fetch(self, source: object) -> OfficialHttpResponse:
            nonlocal fetch_calls
            fetch_calls += 1
            return OfficialHttpResponse(
                status_code=200,
                final_url=getattr(source, "url"),
                content_type="application/json",
                body=raw,
                supporting_official_reads=(supporting,),
                supporting_official_raw_bytes=(supporting_raw,),
            )

    tick = BASE
    window_open = BASE
    cross_during_publication_clock = False
    second_cycle_clock_calls = 0

    def clock() -> datetime:
        nonlocal second_cycle_clock_calls
        if cross_during_publication_clock:
            second_cycle_clock_calls += 1
            if second_cycle_clock_calls >= 6:
                return window_open
        return tick

    monkeypatch.setattr(
        CANARY_CLI,
        "assert_workspace_control_artifact_destination_v1",
        lambda _workspace, destination: destination,
    )
    common = {
        "workspace_receipt": workspace,
        "workspace_receipt_bytes": workspace.model_dump_json().encode(),
        "mission_manifest": manifest,
        "mission_manifest_bytes": manifest.model_dump_json().encode(),
        "source_plan_bytes": plan_bytes,
        "fetcher": SyntheticFetcher(),
        "clock": clock,
        "workspace_validator": lambda _workspace: None,
        "marker_inspector": CANARY_CLI.inspect_first_c0_canary_markers_read_only_v1,
    }
    first = CANARY_CLI._prepare_first_c0_canary_selection_v1(
        **common,
        output_directory=control / "cycle-1-bundle",
    )
    assert first.status == "CANARY_FUTURE_WINDOW"
    tick = first.recommended_refresh_utc
    window_open = first.selection.selected_candidate().window_not_before_utc
    if crossing_stage == "published_at":
        cross_during_publication_clock = True
    else:
        original_publish = (
            CANARY_CLI._publish_bundle
            if crossing_stage == "bundle"
            else CANARY_CLI._publish_prefetch_handoff
        )

        def crossing_publish(**kwargs: object) -> object:
            nonlocal tick
            published = original_publish(**kwargs)
            tick = window_open
            return published

        monkeypatch.setattr(
            CANARY_CLI,
            "_publish_bundle" if crossing_stage == "bundle" else "_publish_prefetch_handoff",
            crossing_publish,
        )
    with pytest.raises(
        CANARY_CLI.FirstC0CanaryPreparationError,
        match="FIRST_C0_PREFETCH_COMPLETION_TOO_LATE",
    ):
        CANARY_CLI._prepare_first_c0_canary_selection_v1(
            **common,
            output_directory=control / "cycle-2-bundle",
        )
    attempt = json.loads(
        (control / "first-c0-canary-cycle-02-attempt-receipt-v1.json").read_bytes()
    )
    assert attempt["status"] == "FAILED_NO_FALLBACK"
    assert attempt["code"] == "FIRST_C0_PREFETCH_COMPLETION_TOO_LATE"
    assert attempt["selected_not_before_utc"] is None
    assert attempt["bundle_manifest_sha256"] is None
    assert all(
        attempt[field] == 0
        for field in (
            "provider_dns",
            "provider_tcp",
            "provider_http",
            "secret_reads",
            "owner_review_pack_builds",
        )
    )
    assert (control / "cycle-2-bundle").is_dir() is (crossing_stage != "published_at")
    assert (control / "first-c0-prefetched-window-handoff-v1.json").exists() is (
        crossing_stage == "handoff"
    )
    if crossing_stage == "handoff":
        dns_calls = 0

        def forbidden_resolver(*_args: object, **_kwargs: object) -> tuple[str, ...]:
            nonlocal dns_calls
            dns_calls += 1
            raise AssertionError("late prefetch handoff reached DNS")

        with pytest.raises(
            OWNER_ATOMIC_CLI.PreDnsOrchestrationError,
            match="FIRST_C0_CANARY_BUNDLE_LINEAGE_INVALID",
        ):
            OWNER_ATOMIC_CLI._run_first_c0_owner_pack_atomic_v1(
                bundle_directory=control / "cycle-2-bundle",
                prefetch_handoff_path=(control / "first-c0-prefetched-window-handoff-v1.json"),
                window_open_receipt_path=control / "late-window-open-receipt.json",
                workspace_receipt=workspace,
                mission_manifest=manifest,
                output_binding_path=control / "late-provider-network-binding.json",
                output_pack_directory=control / "late-owner-review-pack",
                resolver=forbidden_resolver,
                marker_inspector=lambda *_args, **_kwargs: (_ for _ in ()).throw(
                    AssertionError("late prefetch handoff reached marker inspection")
                ),
                execute=True,
                owner_present_for_at_least_20_minutes=True,
                clock=clock,
                monotonic=lambda: 0.0,
                workspace_validator=lambda _workspace: None,
            )
        assert dns_calls == 0
        assert not (control / "late-window-open-receipt.json").exists()
        assert not (control / "late-provider-network-binding.json").exists()
        assert not (control / "late-owner-review-pack").exists()
    with pytest.raises(
        CANARY_CLI.FirstC0CanaryPreparationError,
        match="FIRST_C0_CANARY_FALLBACK_NOT_AUTHORIZED",
    ):
        CANARY_CLI._prepare_first_c0_canary_selection_v1(
            **common,
            output_directory=control / "cycle-3-bundle",
        )
    assert fetch_calls == 2


def test_h24_h2_no_window_flow_is_explicit_and_effect_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    control = tmp_path / "control"
    control.mkdir()
    workspace = workspace_receipt(tmp_path)
    manifest = mission_manifest(expires_at=BASE + timedelta(seconds=60))
    plan_bytes = _source_plan_bytes(
        "soccer_spain_la_liga",
        "LALIGA_PUBLIC_MATCHES_JSON_V1",
        LALIGA_SOURCE,
    )
    raw = _laliga_payload(latest=BASE + timedelta(hours=27))
    supporting_raw = b"<html>public LaLiga bootstrap</html>"
    supporting = SupportingOfficialRead(
        requested_url=LALIGA_BOOTSTRAP_URL,
        final_url=LALIGA_BOOTSTRAP_URL,
        official_domain="www.laliga.com",
        status_code=200,
        content_type="text/html",
        byte_count=len(supporting_raw),
        raw_sha256=hashlib.sha256(supporting_raw).hexdigest(),
        redirect_chain=(),
    )

    class SyntheticFetcher:
        def fetch(self, source: object) -> OfficialHttpResponse:
            return OfficialHttpResponse(
                status_code=200,
                final_url=getattr(source, "url"),
                content_type="application/json",
                body=raw,
                supporting_official_reads=(supporting,),
                supporting_official_raw_bytes=(supporting_raw,),
            )

    monkeypatch.setattr(
        CANARY_CLI,
        "assert_workspace_control_artifact_destination_v1",
        lambda _workspace, destination: destination,
    )
    with pytest.raises(
        CANARY_CLI.FirstC0CanaryPreparationError,
        match="FIRST_C0_CANARY_NO_REMAINING_SELECTABLE_CANDIDATE",
    ):
        CANARY_CLI._prepare_first_c0_canary_selection_v1(
            workspace_receipt=workspace,
            workspace_receipt_bytes=workspace.model_dump_json().encode(),
            mission_manifest=manifest,
            mission_manifest_bytes=manifest.model_dump_json().encode(),
            source_plan_bytes=plan_bytes,
            output_directory=control / "no-window-bundle",
            fetcher=SyntheticFetcher(),
            clock=lambda: BASE,
            workspace_validator=lambda _workspace: None,
            marker_inspector=lambda _workspace, _manifest: {
                "local_marker_present": False,
                "v2_global_marker_present": False,
                "legacy_global_marker_present": False,
                "inspected_read_only": True,
            },
        )
    attempt = json.loads(
        (control / "first-c0-canary-cycle-01-attempt-receipt-v1.json").read_bytes()
    )
    assert attempt["status"] == "FAILED_BEFORE_DNS"
    assert attempt["fallback_category"] == "NO_H24_H2_WINDOW"
    assert attempt["official_reads"] == 2
    assert all(
        attempt[field] == 0
        for field in (
            "provider_dns",
            "provider_tcp",
            "provider_http",
            "secret_reads",
            "owner_review_pack_builds",
        )
    )


def test_single_source_plan_is_strict_and_bundesliga_requires_primary_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    laliga_bytes = _source_plan_bytes(
        "soccer_spain_la_liga",
        "LALIGA_PUBLIC_MATCHES_JSON_V1",
        LALIGA_SOURCE,
    )
    plan = CANARY_CLI.load_first_c0_canary_source_plan_v1(laliga_bytes)
    assert plan.source.sport_key == "soccer_spain_la_liga"
    assert len(plan.canonical_sha256) == 64
    bad_offset = laliga_bytes.replace(b"offset=300", b"offset=200")
    with pytest.raises(
        CANARY_CLI.FirstC0CanaryPreparationError,
        match="FIRST_C0_CANARY_SOURCE_PLAN_AUTHORITY_INVALID",
    ):
        CANARY_CLI.load_first_c0_canary_source_plan_v1(bad_offset)
    extra_query = laliga_bytes.replace(b"offset=300", b"offset=300&extra=1")
    with pytest.raises(
        CANARY_CLI.FirstC0CanaryPreparationError,
        match="FIRST_C0_CANARY_SOURCE_PLAN_AUTHORITY_INVALID",
    ):
        CANARY_CLI.load_first_c0_canary_source_plan_v1(extra_query)
    bad_dfb_path = _source_plan_bytes(
        "soccer_germany_bundesliga",
        "DFB_DATACENTER_HTML_V1",
        f"{BUNDESLIGA_SOURCE}/extra",
    )
    with pytest.raises(
        CANARY_CLI.FirstC0CanaryPreparationError,
        match="FIRST_C0_CANARY_SOURCE_PLAN_AUTHORITY_INVALID",
    ):
        CANARY_CLI.load_first_c0_canary_source_plan_v1(bad_dfb_path)

    workspace = workspace_receipt(tmp_path)
    manifest = mission_manifest()
    bundesliga_bytes = _source_plan_bytes(
        "soccer_germany_bundesliga",
        "DFB_DATACENTER_HTML_V1",
        BUNDESLIGA_SOURCE,
    )
    monkeypatch.setattr(
        CANARY_CLI,
        "assert_workspace_control_artifact_destination_v1",
        lambda _workspace, destination: destination,
    )
    fetch_calls = 0

    class ForbiddenFetcher:
        def fetch(self, _source: object) -> object:
            nonlocal fetch_calls
            fetch_calls += 1
            raise AssertionError("FALLBACK_FETCH_BEFORE_PRIMARY_RECEIPT")

    with pytest.raises(
        CANARY_CLI.FirstC0CanaryPreparationError,
        match="FIRST_C0_CANARY_PRIMARY_SOURCE_REQUIRED_FIRST",
    ):
        CANARY_CLI._prepare_first_c0_canary_selection_v1(
            workspace_receipt=workspace,
            workspace_receipt_bytes=workspace.model_dump_json().encode(),
            mission_manifest=manifest,
            mission_manifest_bytes=manifest.model_dump_json().encode(),
            source_plan_bytes=bundesliga_bytes,
            output_directory=tmp_path / "bundle",
            fetcher=ForbiddenFetcher(),
            clock=lambda: BASE,
            workspace_validator=lambda _workspace: None,
            marker_inspector=lambda _workspace, _manifest: {
                "local_marker_present": False,
                "v2_global_marker_present": False,
                "legacy_global_marker_present": False,
                "inspected_read_only": True,
            },
        )
    assert fetch_calls == 0


def test_failed_no_fallback_receipt_cannot_authorize_a_bundesliga_read() -> None:
    laliga_plan = CANARY_CLI.load_first_c0_canary_source_plan_v1(
        _source_plan_bytes(
            "soccer_spain_la_liga",
            "LALIGA_PUBLIC_MATCHES_JSON_V1",
            LALIGA_SOURCE,
        )
    )
    bundesliga_plan = CANARY_CLI.load_first_c0_canary_source_plan_v1(
        _source_plan_bytes(
            "soccer_germany_bundesliga",
            "DFB_DATACENTER_HTML_V1",
            BUNDESLIGA_SOURCE,
        )
    )
    history = (
        CANARY_CLI.FirstC0CanaryCycleHistoryV1(
            cycle_index=1,
            reservation={},
            receipt={
                "sport_key": "soccer_spain_la_liga",
                "source_plan_sha256": laliga_plan.canonical_sha256,
                "cumulative_official_reads": 2,
                "status": "FAILED_NO_FALLBACK",
                "failure_classification": "DETERMINISTIC",
                "fallback_category": None,
            },
            reservation_bytes=b"reservation",
            receipt_bytes=b"receipt",
            receipt_sha256="0" * 64,
        ),
    )

    with pytest.raises(
        CANARY_CLI.FirstC0CanaryPreparationError,
        match="FIRST_C0_CANARY_FALLBACK_NOT_AUTHORIZED",
    ):
        CANARY_CLI._next_cycle_authority(
            history,
            bundesliga_plan,
            started_at_utc=BASE,
        )


def test_transient_failure_allows_fallback_but_never_an_identical_retry() -> None:
    laliga_plan = CANARY_CLI.load_first_c0_canary_source_plan_v1(
        _source_plan_bytes(
            "soccer_spain_la_liga",
            "LALIGA_PUBLIC_MATCHES_JSON_V1",
            LALIGA_SOURCE,
        )
    )
    bundesliga_plan = CANARY_CLI.load_first_c0_canary_source_plan_v1(
        _source_plan_bytes(
            "soccer_germany_bundesliga",
            "DFB_DATACENTER_HTML_V1",
            BUNDESLIGA_SOURCE,
        )
    )
    primary_history = (
        CANARY_CLI.FirstC0CanaryCycleHistoryV1(
            cycle_index=1,
            reservation={},
            receipt={
                "sport_key": "soccer_spain_la_liga",
                "source_plan_sha256": laliga_plan.canonical_sha256,
                "cumulative_official_reads": 2,
                "status": "FAILED_BEFORE_DNS",
                "failure_classification": "TRANSIENT",
                "fallback_category": "SOURCE_UNAVAILABLE",
            },
            reservation_bytes=b"reservation-1",
            receipt_bytes=b"receipt-1",
            receipt_sha256="1" * 64,
        ),
    )
    with pytest.raises(
        CANARY_CLI.FirstC0CanaryPreparationError,
        match="FIRST_C0_CANARY_IDENTICAL_RETRY_NOT_AUTHORIZED",
    ):
        CANARY_CLI._next_cycle_authority(
            primary_history,
            laliga_plan,
            started_at_utc=BASE,
        )
    assert CANARY_CLI._next_cycle_authority(
        primary_history,
        bundesliga_plan,
        started_at_utc=BASE,
    ) == (2, "FALLBACK_INITIAL", 2, "1" * 64)

    fallback_history = (
        *primary_history,
        CANARY_CLI.FirstC0CanaryCycleHistoryV1(
            cycle_index=2,
            reservation={},
            receipt={
                "sport_key": "soccer_germany_bundesliga",
                "source_plan_sha256": bundesliga_plan.canonical_sha256,
                "cumulative_official_reads": 3,
                "status": "FAILED_BEFORE_DNS",
                "failure_classification": "TRANSIENT",
                "fallback_category": "SOURCE_UNAVAILABLE",
            },
            reservation_bytes=b"reservation-2",
            receipt_bytes=b"receipt-2",
            receipt_sha256="2" * 64,
        ),
    )
    with pytest.raises(
        CANARY_CLI.FirstC0CanaryPreparationError,
        match="FIRST_C0_CANARY_FALLBACK_SOURCE_EXHAUSTED",
    ):
        CANARY_CLI._next_cycle_authority(
            fallback_history,
            bundesliga_plan,
            started_at_utc=BASE,
        )


def test_deterministic_primary_rejection_falls_back_and_refreshes_with_lineage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    control = tmp_path / "control"
    control.mkdir()
    workspace = workspace_receipt(tmp_path)
    manifest = mission_manifest(expires_at=BASE + timedelta(days=10))
    laliga_plan = _source_plan_bytes(
        "soccer_spain_la_liga",
        "LALIGA_PUBLIC_MATCHES_JSON_V1",
        LALIGA_SOURCE,
    )
    bundesliga_plan = _source_plan_bytes(
        "soccer_germany_bundesliga",
        "DFB_DATACENTER_HTML_V1",
        BUNDESLIGA_SOURCE,
    )
    tick = BASE

    def clock() -> datetime:
        nonlocal tick
        observed = tick
        tick += timedelta(seconds=1)
        return observed

    monkeypatch.setattr(
        CANARY_CLI,
        "assert_workspace_control_artifact_destination_v1",
        lambda _workspace, destination: destination,
    )
    shared = {
        "workspace_receipt": workspace,
        "workspace_receipt_bytes": workspace.model_dump_json().encode(),
        "mission_manifest": manifest,
        "mission_manifest_bytes": manifest.model_dump_json().encode(),
        "clock": clock,
        "workspace_validator": lambda _workspace: None,
        "marker_inspector": lambda _workspace, _manifest: {
            "local_marker_present": False,
            "v2_global_marker_present": False,
            "legacy_global_marker_present": False,
            "inspected_read_only": True,
        },
    }

    class DeterministicRejectedFetcher:
        def fetch(self, source: object) -> OfficialHttpResponse:
            return OfficialHttpResponse(
                status_code=403,
                final_url=getattr(source, "url"),
                content_type="application/json",
                body=b"forbidden",
            )

    with pytest.raises(
        CANARY_CLI.FirstC0CanaryPreparationError,
        match="OFFICIAL_SOURCE_HTTP_STATUS_INVALID",
    ):
        CANARY_CLI._prepare_first_c0_canary_selection_v1(
            **shared,
            source_plan_bytes=laliga_plan,
            output_directory=control / "cycle-1-rejected",
            fetcher=DeterministicRejectedFetcher(),
        )
    primary_receipt = json.loads(
        (control / "first-c0-canary-cycle-01-attempt-receipt-v1.json").read_bytes()
    )
    assert primary_receipt["failure_classification"] == "DETERMINISTIC"
    assert primary_receipt["http_status"] == 403
    assert primary_receipt["cumulative_official_reads"] == 2

    bundesliga_raw = _bundesliga_payload()

    class BundesligaFetcher:
        def fetch(self, source: object) -> OfficialHttpResponse:
            return OfficialHttpResponse(
                status_code=200,
                final_url=getattr(source, "url"),
                content_type="text/html",
                body=bundesliga_raw,
            )

    fallback = CANARY_CLI._prepare_first_c0_canary_selection_v1(
        **shared,
        source_plan_bytes=bundesliga_plan,
        output_directory=control / "cycle-2-fallback",
        fetcher=BundesligaFetcher(),
    )
    assert fallback.status == "CANARY_FUTURE_WINDOW"
    assert fallback.cycle_index == 2
    assert fallback.cumulative_official_reads == 3
    tick = fallback.recommended_refresh_utc
    refreshed = CANARY_CLI._prepare_first_c0_canary_selection_v1(
        **shared,
        source_plan_bytes=bundesliga_plan,
        output_directory=control / "cycle-3-fallback-refresh",
        fetcher=BundesligaFetcher(),
    )
    assert refreshed.status == "CANARY_FUTURE_WINDOW"
    assert refreshed.cycle_index == 3
    assert refreshed.cumulative_official_reads == 4
    tick = refreshed.selection.selected_not_before_utc
    refreshed.selection.assert_selected_candidate_current(tick)
    final_names = {path.name for path in refreshed.bundle_directory.iterdir()}
    for cycle in (1, 2):
        assert f"prior-cycle-{cycle:02d}-read-reservation.json" in final_names
        assert f"prior-cycle-{cycle:02d}-attempt-receipt.json" in final_names


def test_official_read_reservation_is_durable_before_fetch_and_blocks_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    control = tmp_path / "control"
    control.mkdir()
    workspace = workspace_receipt(tmp_path)
    manifest = mission_manifest()
    plan_bytes = _source_plan_bytes(
        "soccer_spain_la_liga",
        "LALIGA_PUBLIC_MATCHES_JSON_V1",
        LALIGA_SOURCE,
    )
    monkeypatch.setattr(
        CANARY_CLI,
        "assert_workspace_control_artifact_destination_v1",
        lambda _workspace, destination: destination,
    )
    fetch_calls = 0

    class InterruptedFetcher:
        def fetch(self, _source: object) -> object:
            nonlocal fetch_calls
            fetch_calls += 1
            raise RuntimeError("SYNTHETIC_PROCESS_INTERRUPTION")

    arguments = {
        "workspace_receipt": workspace,
        "workspace_receipt_bytes": workspace.model_dump_json().encode(),
        "mission_manifest": manifest,
        "mission_manifest_bytes": manifest.model_dump_json().encode(),
        "source_plan_bytes": plan_bytes,
        "output_directory": control / "bundle",
        "fetcher": InterruptedFetcher(),
        "clock": lambda: BASE,
        "workspace_validator": lambda _workspace: None,
        "marker_inspector": lambda _workspace, _manifest: {
            "local_marker_present": False,
            "v2_global_marker_present": False,
            "legacy_global_marker_present": False,
            "inspected_read_only": True,
        },
    }
    with pytest.raises(RuntimeError, match="SYNTHETIC_PROCESS_INTERRUPTION"):
        CANARY_CLI._prepare_first_c0_canary_selection_v1(**arguments)
    reservation = control / "first-c0-canary-cycle-01-read-reservation-v1.json"
    assert reservation.is_file()
    payload = json.loads(reservation.read_bytes())
    assert payload["status"] == "RESERVED_BEFORE_OFFICIAL_READ"
    assert payload["official_reads_reserved"] == 2
    assert payload["provider_dns"] == payload["provider_http"] == 0
    with pytest.raises(
        CANARY_CLI.FirstC0CanaryPreparationError,
        match="FIRST_C0_CANARY_PREVIOUS_CYCLE_INCOMPLETE",
    ):
        CANARY_CLI._prepare_first_c0_canary_selection_v1(**arguments)
    assert fetch_calls == 1
