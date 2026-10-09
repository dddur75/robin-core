from __future__ import annotations

import os
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

import robin.capture.global_claim_boundary as boundary_module
import robin.capture.storage as storage_module
from robin.capture.bootstrap_contracts import RealCaptureWorkspaceReceiptV1
from robin.capture.global_claim_boundary import (
    GLOBAL_CLAIM_ROOT_V2_NAME,
    LEGACY_GLOBAL_CLAIM_ROOT_V1_NAME,
    GlobalClaimBoundaryError,
    ensure_global_claim_root_v2,
    global_claim_marker_paths_v2,
    read_global_claim_marker_pair_v2,
    reserve_global_claim_marker_v2,
    resolve_global_claim_root_candidate_v2,
    resolve_owner_execution_boundary_v2,
)
from robin.capture.storage import CaptureStorageError
from robin.capture.workspace_bootstrap import LocalBoundaryInspection, WorkspaceBootstrapError

_CLAIM_NAME = "real_execution_bootstrap_closure_v1-" + "a" * 64 + ".json"


def _normalized(path: Path) -> Path:
    return Path(os.path.normcase(os.path.abspath(os.fspath(path))))


class RecordingInspector:
    def __init__(self) -> None:
        self.calls: list[Path] = []
        self.call_existing: list[bool] = []
        self.overrides: dict[Path, dict[str, Any]] = {}
        self.sequences: dict[Path, list[LocalBoundaryInspection]] = {}

    def inspect(self, path: Path) -> LocalBoundaryInspection:
        normalized = _normalized(path)
        self.calls.append(normalized)
        self.call_existing.append(os.path.lexists(normalized))
        sequence = self.sequences.get(normalized)
        if sequence:
            return sequence.pop(0)
        try:
            metadata = normalized.lstat()
        except OSError:
            raise WorkspaceBootstrapError("LOCAL_RUNTIME_PATH_IDENTITY_UNAVAILABLE") from None
        if not normalized.is_dir():
            raise WorkspaceBootstrapError("LOCAL_RUNTIME_DIRECTORY_REQUIRED")
        values: dict[str, Any] = {
            "canonical_path": normalized,
            "filesystem_name": "NTFS",
            "volume_identity": "1" * 64,
            "device": metadata.st_dev,
            "inode": metadata.st_ino,
            "attributes": 0,
            "security_descriptor_sha256": "2" * 64,
            "fixed_local_filesystem": True,
            "acl_exclusive": True,
            "synchronized": False,
        }
        values.update(self.overrides.get(normalized, {}))
        return LocalBoundaryInspection(**values)

    def override(self, path: Path, **values: Any) -> None:
        self.overrides[_normalized(path)] = values


def _receipt(
    repository: Path,
    control_temp: Path,
    capture: Path,
    *,
    authority_eligible: bool = True,
) -> RealCaptureWorkspaceReceiptV1:
    for path in (repository, control_temp, capture):
        path.mkdir(parents=True, exist_ok=False)
    return RealCaptureWorkspaceReceiptV1.issue(
        authorized_main_sha="3" * 40,
        bootstrap_mode="VERIFY" if authority_eligible else "CREATE",
        bootstrap_tool_source_repository_root=os.fspath(repository),
        bootstrap_tool_loaded_from_runtime_repository=True,
        bootstrap_package_source_repository_root=os.fspath(repository),
        bootstrap_package_loaded_from_runtime_repository=True,
        authority_eligible_for_real_execution=authority_eligible,
        prepared_at_utc=datetime(2026, 8, 28, 12, 0, tzinfo=UTC),
        runtime_repository_root=os.fspath(repository),
        repository_root_fingerprint="4" * 64,
        repository_security_descriptor_sha256="5" * 64,
        control_temp_root=os.fspath(control_temp),
        control_temp_fingerprint="6" * 64,
        control_temp_security_descriptor_sha256="7" * 64,
        capture_root=os.fspath(capture),
        capture_root_fingerprint="8" * 64,
        capture_security_descriptor_sha256="9" * 64,
        git_executable_path=os.fspath(repository.parent / "approved-git.exe"),
        git_executable_sha256="a" * 64,
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


def _workspace(boundary: Path, name: str = "W1") -> RealCaptureWorkspaceReceiptV1:
    runtime = boundary / name
    return _receipt(runtime / "repository", runtime / "control-temp", runtime / "capture")


def _install_contract(
    monkeypatch: pytest.MonkeyPatch,
    *,
    profile: Path,
    local_app_data: Path,
    inspector: RecordingInspector,
) -> None:
    monkeypatch.setattr(boundary_module, "_windows_profile_root_v2", lambda: profile)
    monkeypatch.setattr(
        boundary_module,
        "_windows_local_app_data_read_only_v1",
        lambda: local_app_data,
    )
    monkeypatch.setattr(boundary_module, "WindowsBoundaryInspector", lambda: inspector)


def _error_code(call: Callable[[], object]) -> str:
    with pytest.raises(GlobalClaimBoundaryError) as captured:
        call()
    return captured.value.code


def _identity(path: Path, *, inode: int, acl: str = "2" * 64) -> LocalBoundaryInspection:
    metadata = path.lstat()
    return LocalBoundaryInspection(
        canonical_path=_normalized(path),
        filesystem_name="NTFS",
        volume_identity="1" * 64,
        device=metadata.st_dev,
        inode=inode,
        attributes=0,
        security_descriptor_sha256=acl,
        fixed_local_filesystem=True,
        acl_exclusive=True,
        synchronized=False,
    )


def test_workspace_under_profile_rds_is_accepted_without_creating_the_child(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = tmp_path / "profile"
    boundary = profile / "RDS"
    boundary.mkdir(parents=True)
    receipt = _workspace(boundary)
    inspector = RecordingInspector()
    local_app_data = tmp_path / "local-app-data"
    _install_contract(
        monkeypatch,
        profile=profile,
        local_app_data=local_app_data,
        inspector=inspector,
    )

    resolved = resolve_owner_execution_boundary_v2(receipt)
    candidate = resolve_global_claim_root_candidate_v2(receipt)

    assert resolved.canonical_path == _normalized(boundary)
    assert candidate == _normalized(boundary / GLOBAL_CLAIM_ROOT_V2_NAME)
    assert not os.path.lexists(candidate)
    assert not os.path.lexists(local_app_data)


def test_non_authority_workspace_reports_owner_boundary_unavailable_without_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = tmp_path / "profile"
    boundary = profile / "RDS"
    boundary.mkdir(parents=True)
    runtime = boundary / "W1"
    receipt = _receipt(
        runtime / "repository",
        runtime / "control-temp",
        runtime / "capture",
        authority_eligible=False,
    )
    _install_contract(
        monkeypatch,
        profile=profile,
        local_app_data=tmp_path / "local-app-data",
        inspector=RecordingInspector(),
    )

    assert _error_code(lambda: ensure_global_claim_root_v2(receipt)) == (
        "GLOBAL_CLAIM_OWNER_BOUNDARY_UNAVAILABLE"
    )
    assert not os.path.lexists(boundary / GLOBAL_CLAIM_ROOT_V2_NAME)


def test_workspace_outside_profile_rds_is_rejected_and_cannot_create_an_alternate_registry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = tmp_path / "profile"
    (profile / "RDS").mkdir(parents=True)
    outside = profile / "outside"
    outside.mkdir()
    receipt = _workspace(outside)
    inspector = RecordingInspector()
    _install_contract(
        monkeypatch,
        profile=profile,
        local_app_data=tmp_path / "local-app-data",
        inspector=inspector,
    )

    assert _error_code(lambda: ensure_global_claim_root_v2(receipt)) == (
        "GLOBAL_CLAIM_OWNER_BOUNDARY_MISMATCH"
    )
    assert not os.path.lexists(outside / GLOBAL_CLAIM_ROOT_V2_NAME)


def test_repository_control_and_capture_parent_divergence_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = tmp_path / "profile"
    boundary = profile / "RDS"
    boundary.mkdir(parents=True)
    receipt = _receipt(
        boundary / "W1" / "repository",
        boundary / "W2" / "control-temp",
        boundary / "W1" / "capture",
    )
    inspector = RecordingInspector()
    _install_contract(
        monkeypatch,
        profile=profile,
        local_app_data=tmp_path / "local-app-data",
        inspector=inspector,
    )

    assert _error_code(lambda: resolve_owner_execution_boundary_v2(receipt)) == (
        "GLOBAL_CLAIM_OWNER_BOUNDARY_MISMATCH"
    )


def test_same_canonical_boundary_with_different_physical_identity_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = tmp_path / "profile"
    boundary = profile / "RDS"
    boundary.mkdir(parents=True)
    receipt = _workspace(boundary)
    inspector = RecordingInspector()
    inspector.sequences[_normalized(boundary)] = [
        _identity(boundary, inode=11),
        _identity(boundary, inode=12),
    ]
    _install_contract(
        monkeypatch,
        profile=profile,
        local_app_data=tmp_path / "local-app-data",
        inspector=inspector,
    )

    assert _error_code(lambda: resolve_owner_execution_boundary_v2(receipt)) == (
        "GLOBAL_CLAIM_OWNER_BOUNDARY_MISMATCH"
    )


def test_unsafe_profile_canonicalization_keeps_owner_unsafe_taxonomy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = tmp_path / "profile"
    boundary = profile / "RDS"
    boundary.mkdir(parents=True)
    receipt = _workspace(boundary)
    inspector = RecordingInspector()
    _install_contract(
        monkeypatch,
        profile=profile,
        local_app_data=tmp_path / "local-app-data",
        inspector=inspector,
    )
    real_canonical = boundary_module._canonical_existing_path_v2

    def reject_profile(path: Path) -> Path:
        if _normalized(path) == _normalized(profile):
            raise GlobalClaimBoundaryError("GLOBAL_CLAIM_OWNER_BOUNDARY_UNSAFE")
        return real_canonical(path)

    monkeypatch.setattr(boundary_module, "_canonical_existing_path_v2", reject_profile)

    assert _error_code(lambda: resolve_owner_execution_boundary_v2(receipt)) == (
        "GLOBAL_CLAIM_OWNER_BOUNDARY_UNSAFE"
    )


@pytest.mark.parametrize(
    ("override", "expected"),
    (
        ({"acl_exclusive": False}, "GLOBAL_CLAIM_OWNER_BOUNDARY_UNSAFE"),
        ({"synchronized": True}, "GLOBAL_CLAIM_OWNER_BOUNDARY_UNSAFE"),
        ({"attributes": 0x00001000}, "GLOBAL_CLAIM_OWNER_BOUNDARY_UNSAFE"),
        ({"fixed_local_filesystem": False}, "GLOBAL_CLAIM_OWNER_BOUNDARY_UNSAFE"),
    ),
)
def test_nonexclusive_sync_cloud_or_nonlocal_parent_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    override: dict[str, object],
    expected: str,
) -> None:
    profile = tmp_path / "profile"
    boundary = profile / "RDS"
    boundary.mkdir(parents=True)
    receipt = _workspace(boundary)
    inspector = RecordingInspector()
    inspector.override(boundary, **override)
    _install_contract(
        monkeypatch,
        profile=profile,
        local_app_data=tmp_path / "local-app-data",
        inspector=inspector,
    )

    assert _error_code(lambda: resolve_owner_execution_boundary_v2(receipt)) == expected


def test_reparse_parent_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    profile = tmp_path / "profile"
    target = tmp_path / "target-rds"
    target.mkdir()
    profile.mkdir()
    boundary = profile / "RDS"
    try:
        boundary.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlink unavailable")
    receipt = _workspace(target)
    receipt = receipt.model_copy(
        update={
            "runtime_repository_root": os.fspath(boundary / "W1" / "repository"),
            "bootstrap_tool_source_repository_root": os.fspath(boundary / "W1" / "repository"),
            "bootstrap_package_source_repository_root": os.fspath(boundary / "W1" / "repository"),
            "control_temp_root": os.fspath(boundary / "W1" / "control-temp"),
            "capture_root": os.fspath(boundary / "W1" / "capture"),
        }
    )
    inspector = RecordingInspector()
    _install_contract(
        monkeypatch,
        profile=profile,
        local_app_data=tmp_path / "local-app-data",
        inspector=inspector,
    )

    assert _error_code(lambda: resolve_owner_execution_boundary_v2(receipt)) == (
        "GLOBAL_CLAIM_OWNER_BOUNDARY_UNSAFE"
    )


@pytest.mark.skipif(os.name != "nt", reason="Windows capability regression")
def test_nonexclusive_localappdata_does_not_block_v2_or_change_its_acl(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = tmp_path / "profile"
    boundary = profile / "RDS"
    boundary.mkdir(parents=True)
    local_app_data = profile / "AppData" / "Local"
    local_app_data.mkdir(parents=True)
    receipt = _workspace(boundary)
    inspector = RecordingInspector()
    inspector.override(local_app_data, acl_exclusive=False)
    before_mode = local_app_data.stat().st_mode
    _install_contract(
        monkeypatch,
        profile=profile,
        local_app_data=local_app_data,
        inspector=inspector,
    )

    assert resolve_global_claim_root_candidate_v2(receipt) == _normalized(
        boundary / GLOBAL_CLAIM_ROOT_V2_NAME
    )
    assert _normalized(local_app_data) not in inspector.calls
    assert local_app_data.stat().st_mode == before_mode


@pytest.mark.skipif(os.name != "nt", reason="Windows known-folder regression")
def test_production_localappdata_resolver_is_legacy_read_only_during_v2_inspection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    actual_local_app_data = boundary_module._windows_local_app_data_read_only_v1()
    actual_legacy_root = actual_local_app_data / LEGACY_GLOBAL_CLAIM_ROOT_V1_NAME
    real_inspector = boundary_module.WindowsBoundaryInspector()
    local_app_data_security_before = real_inspector._security_facts(actual_local_app_data)
    legacy_existed_before = actual_legacy_root.exists()
    legacy_names_before = (
        tuple(sorted(entry.name for entry in actual_legacy_root.iterdir()))
        if legacy_existed_before
        else ()
    )
    profile = tmp_path / "profile"
    boundary = profile / "RDS"
    boundary.mkdir(parents=True)
    receipt = _workspace(boundary)
    inspector = RecordingInspector()
    monkeypatch.setattr(boundary_module, "_windows_profile_root_v2", lambda: profile)
    monkeypatch.setattr(boundary_module, "WindowsBoundaryInspector", lambda: inspector)

    observed = read_global_claim_marker_pair_v2(receipt, _CLAIM_NAME)

    assert observed.paths.legacy.parent == _normalized(actual_legacy_root)
    assert observed.v2_payload is None
    assert actual_legacy_root.exists() is legacy_existed_before
    assert (
        tuple(sorted(entry.name for entry in actual_legacy_root.iterdir()))
        if actual_legacy_root.exists()
        else ()
    ) == legacy_names_before
    assert real_inspector._security_facts(actual_local_app_data) == (local_app_data_security_before)


def test_missing_child_is_created_only_after_safe_parent_inspection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = tmp_path / "profile"
    boundary = profile / "RDS"
    boundary.mkdir(parents=True)
    receipt = _workspace(boundary)
    inspector = RecordingInspector()
    _install_contract(
        monkeypatch,
        profile=profile,
        local_app_data=tmp_path / "local-app-data",
        inspector=inspector,
    )

    root = ensure_global_claim_root_v2(receipt)

    boundary_calls = [
        index for index, path in enumerate(inspector.calls) if path == _normalized(boundary)
    ]
    root_calls = [index for index, path in enumerate(inspector.calls) if path == root]
    assert root.is_dir()
    assert len(root_calls) >= 2
    assert boundary_calls and max(boundary_calls[:2]) < min(root_calls)
    assert all(inspector.call_existing[index] for index in root_calls)


def test_missing_child_appearance_on_second_presence_check_is_identity_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = tmp_path / "profile"
    boundary = profile / "RDS"
    boundary.mkdir(parents=True)
    receipt = _workspace(boundary)
    child = boundary / GLOBAL_CLAIM_ROOT_V2_NAME
    inspector = RecordingInspector()
    _install_contract(
        monkeypatch,
        profile=profile,
        local_app_data=tmp_path / "local-app-data",
        inspector=inspector,
    )
    real_exists = boundary_module._path_exists_no_follow
    candidate_checks = 0

    def create_on_second_presence_check(path: Path) -> bool:
        nonlocal candidate_checks
        if _normalized(path) == _normalized(child):
            candidate_checks += 1
            if candidate_checks == 2:
                child.mkdir()
        return real_exists(path)

    monkeypatch.setattr(
        boundary_module,
        "_path_exists_no_follow",
        create_on_second_presence_check,
    )

    assert _error_code(lambda: ensure_global_claim_root_v2(receipt)) == (
        "GLOBAL_CLAIM_ROOT_IDENTITY_CHANGED"
    )


def test_existing_safe_child_is_accepted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    profile = tmp_path / "profile"
    boundary = profile / "RDS"
    boundary.mkdir(parents=True)
    receipt = _workspace(boundary)
    child = boundary / GLOBAL_CLAIM_ROOT_V2_NAME
    child.mkdir()
    inspector = RecordingInspector()
    _install_contract(
        monkeypatch,
        profile=profile,
        local_app_data=tmp_path / "local-app-data",
        inspector=inspector,
    )

    assert ensure_global_claim_root_v2(receipt) == _normalized(child)


def test_existing_file_collision_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = tmp_path / "profile"
    boundary = profile / "RDS"
    boundary.mkdir(parents=True)
    receipt = _workspace(boundary)
    (boundary / GLOBAL_CLAIM_ROOT_V2_NAME).write_bytes(b"collision")
    inspector = RecordingInspector()
    _install_contract(
        monkeypatch,
        profile=profile,
        local_app_data=tmp_path / "local-app-data",
        inspector=inspector,
    )

    assert _error_code(lambda: ensure_global_claim_root_v2(receipt)) == (
        "GLOBAL_CLAIM_ROOT_COLLISION"
    )


def test_existing_reparse_child_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = tmp_path / "profile"
    boundary = profile / "RDS"
    boundary.mkdir(parents=True)
    receipt = _workspace(boundary)
    target = tmp_path / "target-child"
    target.mkdir()
    child = boundary / GLOBAL_CLAIM_ROOT_V2_NAME
    try:
        child.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlink unavailable")
    inspector = RecordingInspector()
    _install_contract(
        monkeypatch,
        profile=profile,
        local_app_data=tmp_path / "local-app-data",
        inspector=inspector,
    )

    assert _error_code(lambda: ensure_global_claim_root_v2(receipt)) == (
        "GLOBAL_CLAIM_ROOT_REPARSE_FORBIDDEN"
    )


def test_existing_nonexclusive_child_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = tmp_path / "profile"
    boundary = profile / "RDS"
    boundary.mkdir(parents=True)
    receipt = _workspace(boundary)
    child = boundary / GLOBAL_CLAIM_ROOT_V2_NAME
    child.mkdir()
    inspector = RecordingInspector()
    inspector.override(child, acl_exclusive=False)
    _install_contract(
        monkeypatch,
        profile=profile,
        local_app_data=tmp_path / "local-app-data",
        inspector=inspector,
    )

    assert _error_code(lambda: ensure_global_claim_root_v2(receipt)) == (
        "GLOBAL_CLAIM_ROOT_ACL_REQUIRED"
    )


def test_child_identity_change_after_inspection_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = tmp_path / "profile"
    boundary = profile / "RDS"
    boundary.mkdir(parents=True)
    receipt = _workspace(boundary)
    child = boundary / GLOBAL_CLAIM_ROOT_V2_NAME
    child.mkdir()
    inspector = RecordingInspector()
    inspector.sequences[_normalized(child)] = [
        _identity(child, inode=21),
        _identity(child, inode=22),
    ]
    _install_contract(
        monkeypatch,
        profile=profile,
        local_app_data=tmp_path / "local-app-data",
        inspector=inspector,
    )

    assert _error_code(lambda: ensure_global_claim_root_v2(receipt)) == (
        "GLOBAL_CLAIM_ROOT_IDENTITY_CHANGED"
    )


def test_child_disappearance_during_physical_inspection_is_identity_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = tmp_path / "profile"
    boundary = profile / "RDS"
    boundary.mkdir(parents=True)
    receipt = _workspace(boundary)
    child = boundary / GLOBAL_CLAIM_ROOT_V2_NAME
    displaced = boundary / f"{GLOBAL_CLAIM_ROOT_V2_NAME}-displaced"
    child.mkdir()
    inspector = RecordingInspector()
    real_inspect = inspector.inspect

    def disappear_before_inspection(path: Path) -> LocalBoundaryInspection:
        if _normalized(path) == _normalized(child) and child.exists():
            child.rename(displaced)
        return real_inspect(path)

    monkeypatch.setattr(inspector, "inspect", disappear_before_inspection)
    _install_contract(
        monkeypatch,
        profile=profile,
        local_app_data=tmp_path / "local-app-data",
        inspector=inspector,
    )

    assert _error_code(lambda: ensure_global_claim_root_v2(receipt)) == (
        "GLOBAL_CLAIM_ROOT_IDENTITY_CHANGED"
    )


@pytest.mark.parametrize("replacement", (False, True))
def test_existing_child_cannot_disappear_or_be_replaced_after_initial_inspection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    replacement: bool,
) -> None:
    profile = tmp_path / "profile"
    boundary = profile / "RDS"
    boundary.mkdir(parents=True)
    receipt = _workspace(boundary)
    child = boundary / GLOBAL_CLAIM_ROOT_V2_NAME
    displaced = boundary / f"{GLOBAL_CLAIM_ROOT_V2_NAME}-displaced"
    child.mkdir()
    inspector = RecordingInspector()
    _install_contract(
        monkeypatch,
        profile=profile,
        local_app_data=tmp_path / "local-app-data",
        inspector=inspector,
    )
    real_exists = boundary_module._path_exists_no_follow
    candidate_checks = 0

    def replace_on_second_presence_check(path: Path) -> bool:
        nonlocal candidate_checks
        if _normalized(path) == _normalized(child):
            candidate_checks += 1
            if candidate_checks == 2:
                child.rename(displaced)
                if replacement:
                    child.mkdir()
        return real_exists(path)

    monkeypatch.setattr(
        boundary_module,
        "_path_exists_no_follow",
        replace_on_second_presence_check,
    )

    assert _error_code(lambda: ensure_global_claim_root_v2(receipt)) == (
        "GLOBAL_CLAIM_ROOT_IDENTITY_CHANGED"
    )
    assert displaced.is_dir()
    assert child.exists() is replacement


def test_ambiguous_cloud_or_reparse_inspector_error_is_reported_as_unsafe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = tmp_path / "profile"
    boundary = profile / "RDS"
    boundary.mkdir(parents=True)
    receipt = _workspace(boundary)
    child = boundary / GLOBAL_CLAIM_ROOT_V2_NAME
    child.mkdir()
    inspector = RecordingInspector()
    real_inspect = inspector.inspect

    def report_reparse(path: Path) -> LocalBoundaryInspection:
        if _normalized(path) == _normalized(child):
            raise WorkspaceBootstrapError("LOCAL_RUNTIME_CLOUD_OR_REPARSE_FORBIDDEN")
        return real_inspect(path)

    monkeypatch.setattr(inspector, "inspect", report_reparse)
    _install_contract(
        monkeypatch,
        profile=profile,
        local_app_data=tmp_path / "local-app-data",
        inspector=inspector,
    )

    assert _error_code(lambda: ensure_global_claim_root_v2(receipt)) == ("GLOBAL_CLAIM_ROOT_UNSAFE")


@pytest.mark.parametrize(
    ("storage_code", "expected_code"),
    (
        (
            "CAPTURE_WORKSPACE_REPARSE_POINT_FORBIDDEN",
            "GLOBAL_CLAIM_ROOT_REPARSE_FORBIDDEN",
        ),
        (
            "CAPTURE_WORKSPACE_IDENTITY_UNAVAILABLE",
            "GLOBAL_CLAIM_ROOT_IDENTITY_CHANGED",
        ),
    ),
)
def test_write_time_storage_failures_keep_reparse_and_identity_taxonomy_distinct(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    storage_code: str,
    expected_code: str,
) -> None:
    first, _second, _v2_root, _legacy_root = _marker_fixture(tmp_path, monkeypatch)

    def reject_write(
        _path: Path,
        _payload: bytes,
        *,
        before_create: Callable[[], None],
    ) -> None:
        before_create()
        raise CaptureStorageError(storage_code)

    monkeypatch.setattr(boundary_module, "_write_exclusive_marker_v2", reject_write)

    assert (
        _error_code(
            lambda: reserve_global_claim_marker_v2(
                first,
                _CLAIM_NAME,
                b'{"valid":true}\n',
                validator=lambda _: True,
            )
        )
        == expected_code
    )


def test_child_replacement_between_ensure_and_marker_write_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = tmp_path / "profile"
    boundary = profile / "RDS"
    boundary.mkdir(parents=True)
    receipt = _workspace(boundary)
    child = boundary / GLOBAL_CLAIM_ROOT_V2_NAME
    displaced = boundary / f"{GLOBAL_CLAIM_ROOT_V2_NAME}-displaced"
    inspector = RecordingInspector()
    _install_contract(
        monkeypatch,
        profile=profile,
        local_app_data=tmp_path / "local-app-data",
        inspector=inspector,
    )
    real_write = boundary_module._write_exclusive_marker_v2

    def replace_root_then_write(
        path: Path,
        payload: bytes,
        *,
        before_create: Callable[[], None],
    ) -> None:
        child.rename(displaced)
        child.mkdir()
        real_write(path, payload, before_create=before_create)

    monkeypatch.setattr(
        boundary_module,
        "_write_exclusive_marker_v2",
        replace_root_then_write,
    )

    assert (
        _error_code(
            lambda: reserve_global_claim_marker_v2(
                receipt,
                _CLAIM_NAME,
                b'{"valid":true}\n',
                validator=lambda _: True,
            )
        )
        == "GLOBAL_CLAIM_ROOT_IDENTITY_CHANGED"
    )
    assert not (child / _CLAIM_NAME).exists()
    assert not (displaced / _CLAIM_NAME).exists()
    assert child.stat().st_ino != displaced.stat().st_ino


def test_two_verified_workspaces_resolve_the_same_physical_registry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = tmp_path / "profile"
    boundary = profile / "RDS"
    boundary.mkdir(parents=True)
    first = _workspace(boundary, "W1")
    second = _workspace(boundary, "W2")
    inspector = RecordingInspector()
    _install_contract(
        monkeypatch,
        profile=profile,
        local_app_data=tmp_path / "local-app-data",
        inspector=inspector,
    )

    first_root = ensure_global_claim_root_v2(first)
    first_identity = first_root.stat()
    second_root = ensure_global_claim_root_v2(second)
    second_identity = second_root.stat()

    assert first_root == second_root
    assert (first_identity.st_dev, first_identity.st_ino) == (
        second_identity.st_dev,
        second_identity.st_ino,
    )


def _marker_fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[RealCaptureWorkspaceReceiptV1, RealCaptureWorkspaceReceiptV1, Path, Path]:
    profile = tmp_path / "profile"
    boundary = profile / "RDS"
    boundary.mkdir(parents=True)
    first = _workspace(boundary, "W1")
    second = _workspace(boundary, "W2")
    local_app_data = tmp_path / "local-app-data"
    local_app_data.mkdir()
    inspector = RecordingInspector()
    _install_contract(
        monkeypatch,
        profile=profile,
        local_app_data=local_app_data,
        inspector=inspector,
    )
    return (
        first,
        second,
        boundary / GLOBAL_CLAIM_ROOT_V2_NAME,
        local_app_data / LEGACY_GLOBAL_CLAIM_ROOT_V1_NAME,
    )


def test_claim_written_by_workspace_a_blocks_workspace_b(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first, second, v2_root, legacy_root = _marker_fixture(tmp_path, monkeypatch)
    payload = b'{"valid":true}\n'

    written = reserve_global_claim_marker_v2(first, _CLAIM_NAME, payload, validator=lambda _: True)

    assert written.path == _normalized(v2_root / _CLAIM_NAME)
    assert written.path.read_bytes() == payload
    assert written.root_identity
    assert (
        _error_code(
            lambda: reserve_global_claim_marker_v2(
                second,
                _CLAIM_NAME,
                b'{"valid":"second"}\n',
                validator=lambda _: True,
            )
        )
        == "GLOBAL_CLAIM_ALREADY_CONSUMED"
    )
    assert not os.path.lexists(legacy_root)


def test_absent_legacy_root_token_binds_nearest_physical_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first, _second, v2_root, legacy_root = _marker_fixture(tmp_path, monkeypatch)
    observed = read_global_claim_marker_pair_v2(first, _CLAIM_NAME)
    legacy_parent = legacy_root.parent
    displaced = legacy_parent.with_name("local-app-data-displaced")
    legacy_parent.rename(displaced)
    legacy_parent.mkdir()

    assert (
        _error_code(
            lambda: reserve_global_claim_marker_v2(
                first,
                _CLAIM_NAME,
                b'{"valid":true}\n',
                validator=lambda _: True,
                expected_v2_read_identity=observed.v2_root_identity,
                expected_legacy_root_identity=observed.legacy_root_identity,
            )
        )
        == "GLOBAL_CLAIM_LEGACY_CONFLICT"
    )
    assert not (v2_root / _CLAIM_NAME).exists()
    assert not legacy_root.exists()


def test_absent_legacy_root_rejects_reparse_ancestor_without_writes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first, _second, v2_root, legacy_root = _marker_fixture(tmp_path, monkeypatch)
    real_is_reparse = storage_module._is_reparse_point

    def report_legacy_parent_reparse(path: Path) -> bool:
        return _normalized(path) == _normalized(legacy_root.parent) or real_is_reparse(path)

    monkeypatch.setattr(storage_module, "_is_reparse_point", report_legacy_parent_reparse)

    assert (
        _error_code(lambda: read_global_claim_marker_pair_v2(first, _CLAIM_NAME))
        == "GLOBAL_CLAIM_LEGACY_CONFLICT"
    )
    assert not (v2_root / _CLAIM_NAME).exists()
    assert not legacy_root.exists()


def test_owner_boundary_replacement_invalidates_reservation_even_when_child_is_preserved(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first, _second, v2_root, _legacy_root = _marker_fixture(tmp_path, monkeypatch)
    payload = b'{"valid":true}\n'
    reservation = reserve_global_claim_marker_v2(
        first,
        _CLAIM_NAME,
        payload,
        validator=lambda _: True,
    )
    boundary = v2_root.parent
    displaced = boundary.with_name("RDS-displaced")
    boundary.rename(displaced)
    boundary.mkdir()
    (displaced / "W1").rename(boundary / "W1")
    (displaced / GLOBAL_CLAIM_ROOT_V2_NAME).rename(v2_root)

    assert (
        _error_code(
            lambda: boundary_module.assert_global_claim_marker_current_v2(
                first,
                _CLAIM_NAME,
                payload,
                expected_root_identity=reservation.root_identity,
                expected_legacy_root_identity=reservation.legacy_root_identity,
                validator=lambda _: True,
            )
        )
        == "GLOBAL_CLAIM_ROOT_IDENTITY_CHANGED"
    )
    assert (v2_root / _CLAIM_NAME).read_bytes() == payload


@pytest.mark.parametrize("location", ("legacy", "v2"))
def test_legacy_only_or_v2_only_marker_blocks_duplicate_without_writing_legacy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    location: str,
) -> None:
    first, _second, v2_root, legacy_root = _marker_fixture(tmp_path, monkeypatch)
    selected = legacy_root if location == "legacy" else v2_root
    selected.mkdir()
    marker = selected / _CLAIM_NAME
    marker.write_bytes(b'{"valid":true}\n')
    legacy_before = tuple(legacy_root.iterdir()) if legacy_root.exists() else ()

    assert (
        _error_code(
            lambda: reserve_global_claim_marker_v2(
                first,
                _CLAIM_NAME,
                b'{"valid":"new"}\n',
                validator=lambda _: True,
            )
        )
        == "GLOBAL_CLAIM_ALREADY_CONSUMED"
    )
    assert (tuple(legacy_root.iterdir()) if legacy_root.exists() else ()) == legacy_before
    if location == "legacy":
        assert not os.path.lexists(v2_root)


def test_equal_markers_in_both_roots_are_accepted_as_already_consumed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first, _second, v2_root, legacy_root = _marker_fixture(tmp_path, monkeypatch)
    payload = b'{"valid":true}\n'
    for root in (v2_root, legacy_root):
        root.mkdir()
        (root / _CLAIM_NAME).write_bytes(payload)

    assert (
        _error_code(
            lambda: reserve_global_claim_marker_v2(
                first,
                _CLAIM_NAME,
                payload,
                validator=lambda _: True,
            )
        )
        == "GLOBAL_CLAIM_ALREADY_CONSUMED"
    )


def test_conflicting_markers_in_both_roots_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first, _second, v2_root, legacy_root = _marker_fixture(tmp_path, monkeypatch)
    v2_root.mkdir()
    legacy_root.mkdir()
    (v2_root / _CLAIM_NAME).write_bytes(b'{"valid":"v2"}\n')
    (legacy_root / _CLAIM_NAME).write_bytes(b'{"valid":"legacy"}\n')

    assert (
        _error_code(
            lambda: reserve_global_claim_marker_v2(
                first,
                _CLAIM_NAME,
                b'{"valid":"new"}\n',
                validator=lambda _: True,
            )
        )
        == "GLOBAL_CLAIM_LEGACY_CONFLICT"
    )


@pytest.mark.parametrize(
    ("legacy_payload", "expected_code"),
    (
        (b'{"valid":"conflict"}\n', "GLOBAL_CLAIM_LEGACY_CONFLICT"),
        (b'{"valid":"v2"}\n', "GLOBAL_CLAIM_ALREADY_CONSUMED"),
    ),
)
def test_legacy_marker_inserted_during_v2_write_fails_post_write_revalidation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    legacy_payload: bytes,
    expected_code: str,
) -> None:
    first, _second, _v2_root, legacy_root = _marker_fixture(tmp_path, monkeypatch)
    real_write = boundary_module._write_exclusive_marker_v2

    def write_v2_then_inject_legacy(
        path: Path,
        payload: bytes,
        *,
        before_create: Callable[[], None],
    ) -> None:
        real_write(path, payload, before_create=before_create)
        legacy_root.mkdir()
        (legacy_root / _CLAIM_NAME).write_bytes(legacy_payload)

    monkeypatch.setattr(
        boundary_module,
        "_write_exclusive_marker_v2",
        write_v2_then_inject_legacy,
    )

    assert (
        _error_code(
            lambda: reserve_global_claim_marker_v2(
                first,
                _CLAIM_NAME,
                b'{"valid":"v2"}\n',
                validator=lambda _: True,
            )
        )
        == expected_code
    )


@pytest.mark.parametrize(
    ("location", "expected_code"),
    (
        ("v2", "GLOBAL_CLAIM_MARKER_INVALID"),
        ("legacy", "GLOBAL_CLAIM_LEGACY_CONFLICT"),
    ),
)
def test_marker_filesystem_hazards_keep_v2_and_legacy_taxonomy_distinct(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    location: str,
    expected_code: str,
) -> None:
    first, _second, v2_root, legacy_root = _marker_fixture(tmp_path, monkeypatch)
    root = v2_root if location == "v2" else legacy_root
    root.mkdir()
    source = tmp_path / f"{location}-hardlink-source.json"
    source.write_bytes(b'{"valid":true}\n')
    os.link(source, root / _CLAIM_NAME)

    assert _error_code(lambda: read_global_claim_marker_pair_v2(first, _CLAIM_NAME)) == (
        expected_code
    )


def test_invalid_existing_marker_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first, _second, _v2_root, legacy_root = _marker_fixture(tmp_path, monkeypatch)
    legacy_root.mkdir()
    (legacy_root / _CLAIM_NAME).write_bytes(b"invalid")

    assert (
        _error_code(
            lambda: reserve_global_claim_marker_v2(
                first,
                _CLAIM_NAME,
                b'{"valid":"new"}\n',
                validator=lambda value: value.endswith(b"}\n"),
            )
        )
        == "GLOBAL_CLAIM_MARKER_INVALID"
    )


def test_read_only_inspection_checks_both_roots_without_creating_any_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first, _second, v2_root, legacy_root = _marker_fixture(tmp_path, monkeypatch)

    observed = read_global_claim_marker_pair_v2(first, _CLAIM_NAME)

    assert observed.v2_payload is None
    assert observed.legacy_payload is None
    assert observed.canonical_payload is None
    assert not os.path.lexists(v2_root)
    assert not os.path.lexists(legacy_root)


@pytest.mark.parametrize(
    ("location", "expected_code"),
    (
        ("v2", "GLOBAL_CLAIM_ROOT_IDENTITY_CHANGED"),
        ("legacy", "GLOBAL_CLAIM_LEGACY_CONFLICT"),
    ),
)
def test_marker_pair_read_rejects_claim_root_swap_during_absence_check(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    location: str,
    expected_code: str,
) -> None:
    first, _second, v2_root, legacy_root = _marker_fixture(tmp_path, monkeypatch)
    selected = v2_root if location == "v2" else legacy_root
    selected.mkdir()
    marker = selected / _CLAIM_NAME
    marker.write_bytes(b'{"valid":true}\n')
    displaced = selected.with_name(f"{selected.name}-displaced")
    real_optional_read = boundary_module._optional_marker_payload_v2
    swapped = False

    def swap_then_read(
        path: Path,
        *,
        maximum_bytes: int,
        failure_code: str,
    ) -> bytes | None:
        nonlocal swapped
        if not swapped and path.parent == _normalized(selected):
            swapped = True
            selected.rename(displaced)
            selected.mkdir()
        return real_optional_read(
            path,
            maximum_bytes=maximum_bytes,
            failure_code=failure_code,
        )

    monkeypatch.setattr(
        boundary_module,
        "_optional_marker_payload_v2",
        swap_then_read,
    )

    assert (
        _error_code(lambda: read_global_claim_marker_pair_v2(first, _CLAIM_NAME)) == expected_code
    )
    assert (displaced / _CLAIM_NAME).read_bytes() == b'{"valid":true}\n'
    assert not (selected / _CLAIM_NAME).exists()


@pytest.mark.parametrize(
    ("location", "expected_code"),
    (
        ("v2_existing", "GLOBAL_CLAIM_ROOT_IDENTITY_CHANGED"),
        ("v2_absent", "GLOBAL_CLAIM_ROOT_IDENTITY_CHANGED"),
        ("legacy", "GLOBAL_CLAIM_LEGACY_CONFLICT"),
    ),
)
def test_reservation_carries_initial_root_identities_across_ensure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    location: str,
    expected_code: str,
) -> None:
    first, _second, v2_root, legacy_root = _marker_fixture(tmp_path, monkeypatch)
    selected = legacy_root if location == "legacy" else v2_root
    if location != "v2_absent":
        selected.mkdir()
    displaced = selected.with_name(f"{selected.name}-displaced")
    real_ensure = boundary_module._ensure_global_claim_root_with_identity_v2
    swapped = False

    def swap_then_ensure(
        workspace: RealCaptureWorkspaceReceiptV1,
        **kwargs: object,
    ) -> object:
        nonlocal swapped
        if not swapped:
            swapped = True
            if selected.exists():
                selected.rename(displaced)
            selected.mkdir()
        return real_ensure(workspace, **kwargs)

    monkeypatch.setattr(
        boundary_module,
        "_ensure_global_claim_root_with_identity_v2",
        swap_then_ensure,
    )

    assert (
        _error_code(
            lambda: reserve_global_claim_marker_v2(
                first,
                _CLAIM_NAME,
                b'{"valid":true}\n',
                validator=lambda _: True,
            )
        )
        == expected_code
    )
    assert not (v2_root / _CLAIM_NAME).exists()
    assert not (legacy_root / _CLAIM_NAME).exists()


@pytest.mark.parametrize("preexisting", (False, True))
def test_reservation_rejects_root_swap_after_ensure_returns_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    preexisting: bool,
) -> None:
    first, _second, v2_root, _legacy_root = _marker_fixture(tmp_path, monkeypatch)
    if preexisting:
        v2_root.mkdir()
    displaced = v2_root.with_name(f"{v2_root.name}-displaced")
    real_ensure = boundary_module._ensure_global_claim_root_with_identity_v2
    swapped = False

    def ensure_then_swap(
        workspace: RealCaptureWorkspaceReceiptV1,
        **kwargs: object,
    ) -> object:
        nonlocal swapped
        ensured = real_ensure(workspace, **kwargs)
        if not swapped:
            swapped = True
            v2_root.rename(displaced)
            v2_root.mkdir()
        return ensured

    monkeypatch.setattr(
        boundary_module,
        "_ensure_global_claim_root_with_identity_v2",
        ensure_then_swap,
    )

    assert (
        _error_code(
            lambda: reserve_global_claim_marker_v2(
                first,
                _CLAIM_NAME,
                b'{"valid":true}\n',
                validator=lambda _: True,
            )
        )
        == "GLOBAL_CLAIM_ROOT_IDENTITY_CHANGED"
    )
    assert not (v2_root / _CLAIM_NAME).exists()
    assert not (displaced / _CLAIM_NAME).exists()


def test_current_assertion_rejects_v2_aba_even_when_payload_and_final_root_match(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first, _second, v2_root, _legacy_root = _marker_fixture(tmp_path, monkeypatch)
    payload = b'{"valid":true}\n'
    reservation = reserve_global_claim_marker_v2(
        first,
        _CLAIM_NAME,
        payload,
        validator=lambda _: True,
    )
    displaced = v2_root.with_name(f"{v2_root.name}-displaced")
    real_read = boundary_module.read_global_claim_marker_pair_v2
    swapped = False

    def read_through_temporary_replacement(
        workspace: RealCaptureWorkspaceReceiptV1,
        marker_name: str,
        **kwargs: object,
    ) -> object:
        nonlocal swapped
        if swapped:
            return real_read(workspace, marker_name, **kwargs)
        swapped = True
        v2_root.rename(displaced)
        v2_root.mkdir()
        (v2_root / marker_name).write_bytes(payload)
        observed = real_read(workspace, marker_name, **kwargs)
        (v2_root / marker_name).unlink()
        v2_root.rmdir()
        displaced.rename(v2_root)
        return observed

    monkeypatch.setattr(
        boundary_module,
        "read_global_claim_marker_pair_v2",
        read_through_temporary_replacement,
    )

    assert (
        _error_code(
            lambda: boundary_module.assert_global_claim_marker_current_v2(
                first,
                _CLAIM_NAME,
                payload,
                expected_root_identity=reservation.root_identity,
                expected_legacy_root_identity=reservation.legacy_root_identity,
                validator=lambda _: True,
            )
        )
        == "GLOBAL_CLAIM_ROOT_IDENTITY_CHANGED"
    )
    assert (v2_root / _CLAIM_NAME).read_bytes() == payload


def test_historical_legacy_marker_validates_read_only_and_is_never_written(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first, _second, v2_root, legacy_root = _marker_fixture(tmp_path, monkeypatch)
    legacy_root.mkdir()
    marker = legacy_root / _CLAIM_NAME
    payload = b'{"historical":true}\n'
    marker.write_bytes(payload)
    before = marker.read_bytes()

    observed = read_global_claim_marker_pair_v2(first, _CLAIM_NAME)

    assert observed.canonical_payload == payload
    assert observed.legacy_payload == payload
    assert observed.v2_payload is None
    assert observed.canonical_path == _normalized(marker)
    assert marker.read_bytes() == before
    assert not os.path.lexists(v2_root)


def test_arbitrary_marker_path_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    first, _second, _v2_root, _legacy_root = _marker_fixture(tmp_path, monkeypatch)

    assert _error_code(lambda: global_claim_marker_paths_v2(first, "../escape.json")) == (
        "GLOBAL_CLAIM_MARKER_NAME_INVALID"
    )
