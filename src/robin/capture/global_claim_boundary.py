"""Receipt-bound owner registry for mission-global immutable claims."""

from __future__ import annotations

import ctypes
import os
import stat
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Iterator, cast

from robin.capture.bootstrap_contracts import RealCaptureWorkspaceReceiptV1
from robin.capture.storage import CaptureStorageError, _path_exists_no_follow, _reject_reparse_path
from robin.capture.workspace_bootstrap import (
    LocalBoundaryInspection,
    WindowsBoundaryInspector,
    WorkspaceBootstrapError,
)

GLOBAL_CLAIM_ROOT_V2_NAME: Final = "RobinGlobalClaimsV2"
LEGACY_GLOBAL_CLAIM_ROOT_V1_NAME: Final = "RobinRealExecutionMissionClaimsV1"

_CSIDL_LOCAL_APPDATA: Final = 0x001C
_CSIDL_PROFILE: Final = 0x0028
_MAXIMUM_GLOBAL_MARKER_BYTES: Final = 1_048_576
_FORBIDDEN_CLOUD_ATTRIBUTES: Final = 0x00000400 | 0x00001000 | 0x00040000 | 0x00400000


@contextmanager
def _hold_directory_rebinding_guard_v2(
    directory: Path,
    *,
    failure_code: str,
) -> Iterator[None]:
    """On Windows, prevent a verified directory from being renamed during a write."""

    if os.name != "nt":
        yield
        return
    loader = getattr(ctypes, "WinDLL", None)
    if not callable(loader):
        raise GlobalClaimBoundaryError(failure_code)
    try:
        kernel32 = loader("kernel32", use_last_error=True)
        create_file = kernel32.CreateFileW
        create_file.argtypes = (
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
        )
        create_file.restype = ctypes.c_void_p
        handle = create_file(
            os.fspath(directory),
            0x0080,
            0x00000001 | 0x00000002,
            None,
            3,
            0x02000000 | 0x00200000,
            None,
        )
    except (AttributeError, OSError, TypeError, ValueError):
        raise GlobalClaimBoundaryError(failure_code) from None
    invalid_handle = ctypes.c_void_p(-1).value
    if handle in {None, invalid_handle}:
        raise GlobalClaimBoundaryError(failure_code)
    try:
        yield
    finally:
        try:
            close_handle = kernel32.CloseHandle
            close_handle.argtypes = (ctypes.c_void_p,)
            close_handle.restype = ctypes.c_int
            close_handle(ctypes.c_void_p(handle))
        except (AttributeError, OSError, TypeError, ValueError):
            pass


class GlobalClaimBoundaryError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class GlobalClaimMarkerPathsV2:
    v2: Path
    legacy: Path


@dataclass(frozen=True, slots=True)
class GlobalClaimMarkerPairV2:
    paths: GlobalClaimMarkerPathsV2
    v2_root_identity: tuple[object, ...]
    legacy_root_identity: tuple[object, ...]
    v2_payload: bytes | None
    legacy_payload: bytes | None
    canonical_payload: bytes | None
    canonical_path: Path | None


@dataclass(frozen=True, slots=True)
class GlobalClaimReservationV2:
    path: Path
    root_identity: tuple[object, ...]
    v2_read_identity: tuple[object, ...]
    legacy_root_identity: tuple[object, ...]


@dataclass(frozen=True, slots=True)
class _EnsuredGlobalClaimRootV2:
    path: Path
    identity: tuple[object, ...]


def _known_windows_folder_v2(csidl: int, *, failure_code: str) -> Path:
    if os.name != "nt":
        raise GlobalClaimBoundaryError(failure_code)
    try:
        buffer = ctypes.create_unicode_buffer(32_768)
        windows_api = cast(Any, ctypes).windll
        result = windows_api.shell32.SHGetFolderPathW(None, csidl, None, 0, buffer)
    except (AttributeError, OSError, TypeError, ValueError):
        raise GlobalClaimBoundaryError(failure_code) from None
    if result != 0 or not buffer.value:
        raise GlobalClaimBoundaryError(failure_code)
    return Path(os.path.normcase(os.path.abspath(buffer.value)))


def _windows_profile_root_v2() -> Path:
    return _known_windows_folder_v2(
        _CSIDL_PROFILE,
        failure_code="GLOBAL_CLAIM_OWNER_BOUNDARY_UNAVAILABLE",
    )


def _windows_local_app_data_read_only_v1() -> Path:
    return _known_windows_folder_v2(
        _CSIDL_LOCAL_APPDATA,
        failure_code="GLOBAL_CLAIM_LEGACY_BOUNDARY_UNAVAILABLE",
    )


def resolve_legacy_global_claim_root_read_only_v1() -> Path:
    """Return the deterministic legacy candidate without creating or repairing it."""

    local_app_data = _windows_local_app_data_read_only_v1()
    return Path(
        os.path.normcase(
            os.path.abspath(os.fspath(local_app_data / LEGACY_GLOBAL_CLAIM_ROOT_V1_NAME))
        )
    )


def _canonical_existing_path_v2(path: Path) -> Path:
    raw = os.path.abspath(os.fspath(path))
    if raw.startswith(("\\\\", "//")) or raw.casefold().startswith("\\\\?\\unc\\"):
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_OWNER_BOUNDARY_UNSAFE")
    try:
        _reject_reparse_path(Path(raw))
        resolved = Path(raw).resolve(strict=True)
    except (CaptureStorageError, OSError):
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_OWNER_BOUNDARY_UNSAFE") from None
    if os.fspath(resolved).startswith(("\\\\", "//")):
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_OWNER_BOUNDARY_UNSAFE")
    return Path(os.path.normcase(os.fspath(resolved)))


def _normalized_candidate_v2(path: Path) -> Path:
    raw = os.path.abspath(os.fspath(path))
    if raw.startswith(("\\\\", "//")) or raw.casefold().startswith("\\\\?\\unc\\"):
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_OWNER_BOUNDARY_UNSAFE")
    return Path(os.path.normcase(raw))


def _inspection_identity_v2(inspection: LocalBoundaryInspection) -> tuple[object, ...]:
    return (
        os.path.normcase(os.path.abspath(os.fspath(inspection.canonical_path))),
        inspection.volume_identity,
        inspection.device,
        inspection.inode,
        inspection.security_descriptor_sha256,
        inspection.filesystem_name,
        inspection.attributes,
        inspection.fixed_local_filesystem,
        inspection.acl_exclusive,
        inspection.synchronized,
    )


def _validate_owner_inspection_v2(
    inspection: LocalBoundaryInspection,
    *,
    expected_path: Path,
) -> None:
    if (
        inspection.canonical_path != expected_path
        or inspection.filesystem_name.upper() not in {"NTFS", "REFS"}
        or not inspection.fixed_local_filesystem
        or inspection.synchronized
        or inspection.attributes & _FORBIDDEN_CLOUD_ATTRIBUTES
        or not inspection.acl_exclusive
        or inspection.security_descriptor_sha256 == "0" * 64
    ):
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_OWNER_BOUNDARY_UNSAFE")


def _inspect_owner_boundary_v2(
    inspector: WindowsBoundaryInspector,
    path: Path,
) -> LocalBoundaryInspection:
    canonical = _canonical_existing_path_v2(path)
    try:
        inspection = inspector.inspect(canonical)
    except WorkspaceBootstrapError as error:
        if error.code == "LOCAL_RUNTIME_PATH_IDENTITY_UNAVAILABLE":
            code = "GLOBAL_CLAIM_OWNER_BOUNDARY_UNAVAILABLE"
        else:
            code = "GLOBAL_CLAIM_OWNER_BOUNDARY_UNSAFE"
        raise GlobalClaimBoundaryError(code) from None
    _validate_owner_inspection_v2(inspection, expected_path=canonical)
    return inspection


def _resolve_owner_execution_boundary_v2(
    workspace_receipt: RealCaptureWorkspaceReceiptV1,
    *,
    inspector: WindowsBoundaryInspector,
) -> LocalBoundaryInspection:
    if not workspace_receipt.authority_eligible_for_real_execution:
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_OWNER_BOUNDARY_UNAVAILABLE")
    roots = (
        Path(workspace_receipt.runtime_repository_root),
        Path(workspace_receipt.control_temp_root),
        Path(workspace_receipt.capture_root),
    )
    try:
        canonical_roots = tuple(_canonical_existing_path_v2(root) for root in roots)
    except GlobalClaimBoundaryError as error:
        if error.code == "GLOBAL_CLAIM_OWNER_BOUNDARY_UNSAFE":
            raise
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_OWNER_BOUNDARY_UNAVAILABLE") from None
    runtime_parents = tuple(root.parent for root in canonical_roots)
    if len(set(runtime_parents)) != 1:
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_OWNER_BOUNDARY_MISMATCH")
    derived_nominal = runtime_parents[0].parent
    profile = _canonical_existing_path_v2(_windows_profile_root_v2())
    expected_nominal = profile / "RDS"
    derived = _inspect_owner_boundary_v2(inspector, derived_nominal)
    expected = _inspect_owner_boundary_v2(inspector, expected_nominal)
    if _inspection_identity_v2(derived) != _inspection_identity_v2(expected):
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_OWNER_BOUNDARY_MISMATCH")
    return derived


def resolve_owner_execution_boundary_v2(
    workspace_receipt: RealCaptureWorkspaceReceiptV1,
) -> LocalBoundaryInspection:
    """Bind all three receipt roots to the one physical ``<profile>\\RDS`` boundary."""

    try:
        inspector = WindowsBoundaryInspector()
    except WorkspaceBootstrapError:
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_OWNER_BOUNDARY_UNAVAILABLE") from None
    return _resolve_owner_execution_boundary_v2(workspace_receipt, inspector=inspector)


def _validate_root_inspection_v2(
    inspection: LocalBoundaryInspection,
    *,
    expected_path: Path,
    owner_boundary: LocalBoundaryInspection,
) -> None:
    if inspection.canonical_path != expected_path:
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_ROOT_IDENTITY_CHANGED")
    if not inspection.acl_exclusive or inspection.security_descriptor_sha256 == "0" * 64:
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_ROOT_ACL_REQUIRED")
    if (
        inspection.filesystem_name.upper() not in {"NTFS", "REFS"}
        or not inspection.fixed_local_filesystem
        or inspection.synchronized
        or inspection.attributes & _FORBIDDEN_CLOUD_ATTRIBUTES
        or inspection.volume_identity != owner_boundary.volume_identity
        or inspection.device != owner_boundary.device
    ):
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_ROOT_UNSAFE")


def _inspect_existing_root_v2(
    inspector: WindowsBoundaryInspector,
    candidate: Path,
    *,
    owner_boundary: LocalBoundaryInspection,
) -> LocalBoundaryInspection:
    try:
        _reject_reparse_path(candidate)
        metadata = candidate.lstat()
    except CaptureStorageError:
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_ROOT_REPARSE_FORBIDDEN") from None
    except OSError:
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_ROOT_IDENTITY_CHANGED") from None
    attributes = int(getattr(metadata, "st_file_attributes", 0))
    if stat.S_ISLNK(metadata.st_mode) or attributes & 0x00000400:
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_ROOT_REPARSE_FORBIDDEN")
    if not stat.S_ISDIR(metadata.st_mode):
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_ROOT_COLLISION")
    try:
        first = inspector.inspect(candidate)
        second = inspector.inspect(candidate)
    except WorkspaceBootstrapError as error:
        if error.code == "LOCAL_RUNTIME_CLOUD_OR_REPARSE_FORBIDDEN":
            code = "GLOBAL_CLAIM_ROOT_UNSAFE"
        elif "REPARSE" in error.code:
            code = "GLOBAL_CLAIM_ROOT_REPARSE_FORBIDDEN"
        elif error.code == "LOCAL_RUNTIME_PATH_IDENTITY_UNAVAILABLE":
            code = "GLOBAL_CLAIM_ROOT_IDENTITY_CHANGED"
        else:
            code = "GLOBAL_CLAIM_ROOT_UNSAFE"
        raise GlobalClaimBoundaryError(code) from None
    _validate_root_inspection_v2(first, expected_path=candidate, owner_boundary=owner_boundary)
    _validate_root_inspection_v2(second, expected_path=candidate, owner_boundary=owner_boundary)
    if _inspection_identity_v2(first) != _inspection_identity_v2(second):
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_ROOT_IDENTITY_CHANGED")
    return second


def _resolve_global_claim_root_candidate_v2(
    workspace_receipt: RealCaptureWorkspaceReceiptV1,
    *,
    inspector: WindowsBoundaryInspector,
) -> tuple[Path, LocalBoundaryInspection, LocalBoundaryInspection | None]:
    owner_boundary = _resolve_owner_execution_boundary_v2(
        workspace_receipt,
        inspector=inspector,
    )
    candidate = _normalized_candidate_v2(owner_boundary.canonical_path / GLOBAL_CLAIM_ROOT_V2_NAME)
    try:
        present = _path_exists_no_follow(candidate)
    except CaptureStorageError:
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_ROOT_IDENTITY_CHANGED") from None
    root_inspection: LocalBoundaryInspection | None = None
    if present:
        root_inspection = _inspect_existing_root_v2(
            inspector,
            candidate,
            owner_boundary=owner_boundary,
        )
        candidate = root_inspection.canonical_path
    return candidate, owner_boundary, root_inspection


def _v2_root_read_identity_v2(
    candidate: Path,
    owner: LocalBoundaryInspection,
    root: LocalBoundaryInspection | None,
) -> tuple[object, ...]:
    root_identity: tuple[object, ...] = (
        ("GLOBAL_CLAIM_ROOT_ABSENT", os.fspath(candidate))
        if root is None
        else ("GLOBAL_CLAIM_ROOT_PRESENT", _inspection_identity_v2(root))
    )
    return (
        "OWNER_BOUNDARY_V2",
        _inspection_identity_v2(owner),
        *root_identity,
    )


def resolve_global_claim_root_candidate_v2(
    workspace_receipt: RealCaptureWorkspaceReceiptV1,
) -> Path:
    """Resolve and inspect the V2 candidate without creating any object."""

    try:
        inspector = WindowsBoundaryInspector()
    except WorkspaceBootstrapError:
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_OWNER_BOUNDARY_UNAVAILABLE") from None
    candidate, _owner, _root = _resolve_global_claim_root_candidate_v2(
        workspace_receipt,
        inspector=inspector,
    )
    return candidate


def _ensure_global_claim_root_with_identity_v2(
    workspace_receipt: RealCaptureWorkspaceReceiptV1,
    *,
    expected_read_identity: tuple[object, ...] | None = None,
) -> _EnsuredGlobalClaimRootV2:
    """Create only the deterministic child under an already verified owner boundary."""

    try:
        inspector = WindowsBoundaryInspector()
    except WorkspaceBootstrapError:
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_OWNER_BOUNDARY_UNAVAILABLE") from None
    candidate, owner_before, root_before = _resolve_global_claim_root_candidate_v2(
        workspace_receipt,
        inspector=inspector,
    )
    observed_read_identity = _v2_root_read_identity_v2(
        candidate,
        owner_before,
        root_before,
    )
    if expected_read_identity is not None and observed_read_identity != expected_read_identity:
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_ROOT_IDENTITY_CHANGED")
    try:
        present = _path_exists_no_follow(candidate)
    except CaptureStorageError:
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_ROOT_IDENTITY_CHANGED") from None
    if root_before is not None and not present:
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_ROOT_IDENTITY_CHANGED")
    if root_before is None and present:
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_ROOT_IDENTITY_CHANGED")
    if root_before is None and not present:
        try:
            with _hold_directory_rebinding_guard_v2(
                owner_before.canonical_path,
                failure_code="GLOBAL_CLAIM_ROOT_IDENTITY_CHANGED",
            ):
                owner_current = _inspect_owner_boundary_v2(
                    inspector,
                    owner_before.canonical_path,
                )
                if _inspection_identity_v2(owner_current) != _inspection_identity_v2(owner_before):
                    raise GlobalClaimBoundaryError("GLOBAL_CLAIM_ROOT_IDENTITY_CHANGED")
                candidate.mkdir(mode=0o700, parents=False, exist_ok=False)
        except FileExistsError:
            raise GlobalClaimBoundaryError("GLOBAL_CLAIM_ROOT_IDENTITY_CHANGED") from None
        except GlobalClaimBoundaryError:
            raise
        except OSError:
            raise GlobalClaimBoundaryError("GLOBAL_CLAIM_ROOT_CREATE_FAILED") from None
    root = _inspect_existing_root_v2(
        inspector,
        candidate,
        owner_boundary=owner_before,
    )
    if root_before is not None and _inspection_identity_v2(root_before) != _inspection_identity_v2(
        root
    ):
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_ROOT_IDENTITY_CHANGED")
    owner_after = _inspect_owner_boundary_v2(inspector, owner_before.canonical_path)
    if _inspection_identity_v2(owner_before) != _inspection_identity_v2(owner_after):
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_ROOT_IDENTITY_CHANGED")
    return _EnsuredGlobalClaimRootV2(
        path=root.canonical_path,
        identity=_v2_root_read_identity_v2(root.canonical_path, owner_after, root),
    )


def ensure_global_claim_root_v2(
    workspace_receipt: RealCaptureWorkspaceReceiptV1,
    *,
    expected_read_identity: tuple[object, ...] | None = None,
) -> Path:
    """Create only the deterministic child under an already verified owner boundary."""

    return _ensure_global_claim_root_with_identity_v2(
        workspace_receipt,
        expected_read_identity=expected_read_identity,
    ).path


def inspect_global_claim_root_identity_v2(
    workspace_receipt: RealCaptureWorkspaceReceiptV1,
) -> tuple[object, ...]:
    """Return a stable full-identity token for an existing verified V2 root."""

    try:
        inspector = WindowsBoundaryInspector()
    except WorkspaceBootstrapError:
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_OWNER_BOUNDARY_UNAVAILABLE") from None
    candidate, owner_boundary, root_before = _resolve_global_claim_root_candidate_v2(
        workspace_receipt,
        inspector=inspector,
    )
    try:
        present = _path_exists_no_follow(candidate)
    except CaptureStorageError:
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_ROOT_IDENTITY_CHANGED") from None
    if not present or root_before is None:
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_ROOT_IDENTITY_CHANGED")
    inspection = _inspect_existing_root_v2(
        inspector,
        candidate,
        owner_boundary=owner_boundary,
    )
    if _inspection_identity_v2(root_before) != _inspection_identity_v2(inspection):
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_ROOT_IDENTITY_CHANGED")
    owner_after = _inspect_owner_boundary_v2(inspector, owner_boundary.canonical_path)
    if _inspection_identity_v2(owner_boundary) != _inspection_identity_v2(owner_after):
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_ROOT_IDENTITY_CHANGED")
    return _v2_root_read_identity_v2(candidate, owner_boundary, inspection)


def _validate_marker_name_v2(marker_name: str) -> None:
    if (
        not marker_name
        or len(marker_name) > 240
        or marker_name in {".", ".."}
        or Path(marker_name).name != marker_name
        or "/" in marker_name
        or "\\" in marker_name
        or not marker_name.endswith(".json")
    ):
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_MARKER_NAME_INVALID")


def _inspect_legacy_root_candidate_v1(root: Path) -> None:
    try:
        normalized = _normalized_candidate_v2(root)
        _reject_reparse_path(normalized)
    except (CaptureStorageError, GlobalClaimBoundaryError, OSError):
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_LEGACY_CONFLICT") from None
    try:
        present = _path_exists_no_follow(normalized)
    except CaptureStorageError:
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_LEGACY_CONFLICT") from None
    if not present:
        return
    try:
        metadata = normalized.lstat()
    except (CaptureStorageError, OSError):
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_LEGACY_CONFLICT") from None
    if not stat.S_ISDIR(metadata.st_mode):
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_LEGACY_CONFLICT")


def _legacy_nearest_parent_identity_v1(path: Path) -> tuple[object, ...]:
    anchor = path.parent
    while True:
        try:
            if _path_exists_no_follow(anchor):
                metadata = anchor.lstat()
                break
        except (CaptureStorageError, OSError):
            raise GlobalClaimBoundaryError("GLOBAL_CLAIM_LEGACY_CONFLICT") from None
        if anchor == anchor.parent:
            raise GlobalClaimBoundaryError("GLOBAL_CLAIM_LEGACY_CONFLICT")
        anchor = anchor.parent
    if not stat.S_ISDIR(metadata.st_mode):
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_LEGACY_CONFLICT")
    return (
        os.path.normcase(os.path.abspath(os.fspath(anchor))),
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        int(getattr(metadata, "st_file_attributes", 0)),
    )


def _legacy_root_read_identity_v1(root: Path) -> tuple[object, ...]:
    try:
        normalized = _normalized_candidate_v2(root)
        _reject_reparse_path(normalized)
        present = _path_exists_no_follow(normalized)
    except (CaptureStorageError, GlobalClaimBoundaryError, OSError):
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_LEGACY_CONFLICT") from None
    parent_identity = _legacy_nearest_parent_identity_v1(normalized)
    if not present:
        return ("LEGACY_ROOT_ABSENT", os.fspath(normalized), parent_identity)
    try:
        metadata = normalized.lstat()
    except OSError:
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_LEGACY_CONFLICT") from None
    if not stat.S_ISDIR(metadata.st_mode):
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_LEGACY_CONFLICT")
    return (
        "LEGACY_ROOT_PRESENT",
        os.fspath(normalized),
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        int(getattr(metadata, "st_file_attributes", 0)),
        parent_identity,
    )


def _global_claim_root_read_snapshot_v2(
    workspace_receipt: RealCaptureWorkspaceReceiptV1,
) -> tuple[Path, tuple[object, ...]]:
    try:
        inspector = WindowsBoundaryInspector()
    except WorkspaceBootstrapError:
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_OWNER_BOUNDARY_UNAVAILABLE") from None
    candidate, owner, root = _resolve_global_claim_root_candidate_v2(
        workspace_receipt,
        inspector=inspector,
    )
    return candidate, _v2_root_read_identity_v2(candidate, owner, root)


def global_claim_marker_paths_v2(
    workspace_receipt: RealCaptureWorkspaceReceiptV1,
    marker_name: str,
) -> GlobalClaimMarkerPathsV2:
    _validate_marker_name_v2(marker_name)
    v2_root = resolve_global_claim_root_candidate_v2(workspace_receipt)
    legacy_root = resolve_legacy_global_claim_root_read_only_v1()
    _inspect_legacy_root_candidate_v1(legacy_root)
    return GlobalClaimMarkerPathsV2(
        v2=_normalized_candidate_v2(v2_root / marker_name),
        legacy=_normalized_candidate_v2(legacy_root / marker_name),
    )


def _read_marker_v2(
    path: Path,
    *,
    maximum_bytes: int,
    failure_code: str,
) -> bytes:
    try:
        _reject_reparse_path(path)
        before = path.lstat()
    except (CaptureStorageError, OSError):
        raise GlobalClaimBoundaryError(failure_code) from None
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise GlobalClaimBoundaryError(failure_code)
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOINHERIT", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise GlobalClaimBoundaryError(failure_code)
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            payload = stream.read(maximum_bytes + 1)
        after = path.lstat()
    except GlobalClaimBoundaryError:
        raise
    except OSError:
        raise GlobalClaimBoundaryError(failure_code) from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if (
        len(payload) > maximum_bytes
        or not stat.S_ISREG(after.st_mode)
        or after.st_nlink != 1
        or (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino)
    ):
        raise GlobalClaimBoundaryError(failure_code)
    return payload


def _optional_marker_payload_v2(
    path: Path,
    *,
    maximum_bytes: int,
    failure_code: str,
) -> bytes | None:
    try:
        present = _path_exists_no_follow(path)
    except CaptureStorageError:
        raise GlobalClaimBoundaryError(failure_code) from None
    if not present:
        return None
    return _read_marker_v2(
        path,
        maximum_bytes=maximum_bytes,
        failure_code=failure_code,
    )


def read_global_claim_marker_pair_v2(
    workspace_receipt: RealCaptureWorkspaceReceiptV1,
    marker_name: str,
    *,
    maximum_bytes: int = _MAXIMUM_GLOBAL_MARKER_BYTES,
) -> GlobalClaimMarkerPairV2:
    """Read deterministic V2 and legacy markers without creating either root."""

    if not 1 <= maximum_bytes <= _MAXIMUM_GLOBAL_MARKER_BYTES:
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_MARKER_READ_LIMIT_INVALID")
    _validate_marker_name_v2(marker_name)
    v2_root, v2_identity_before = _global_claim_root_read_snapshot_v2(workspace_receipt)
    legacy_root = resolve_legacy_global_claim_root_read_only_v1()
    legacy_identity_before = _legacy_root_read_identity_v1(legacy_root)
    paths = GlobalClaimMarkerPathsV2(
        v2=_normalized_candidate_v2(v2_root / marker_name),
        legacy=_normalized_candidate_v2(legacy_root / marker_name),
    )
    v2_payload = _optional_marker_payload_v2(
        paths.v2,
        maximum_bytes=maximum_bytes,
        failure_code="GLOBAL_CLAIM_MARKER_INVALID",
    )
    legacy_payload = _optional_marker_payload_v2(
        paths.legacy,
        maximum_bytes=maximum_bytes,
        failure_code="GLOBAL_CLAIM_LEGACY_CONFLICT",
    )
    v2_root_after, v2_identity_after = _global_claim_root_read_snapshot_v2(workspace_receipt)
    legacy_identity_after = _legacy_root_read_identity_v1(legacy_root)
    if v2_root_after != v2_root or v2_identity_after != v2_identity_before:
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_ROOT_IDENTITY_CHANGED")
    if legacy_identity_after != legacy_identity_before:
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_LEGACY_CONFLICT")
    v2_payload_after = _optional_marker_payload_v2(
        paths.v2,
        maximum_bytes=maximum_bytes,
        failure_code="GLOBAL_CLAIM_MARKER_INVALID",
    )
    legacy_payload_after = _optional_marker_payload_v2(
        paths.legacy,
        maximum_bytes=maximum_bytes,
        failure_code="GLOBAL_CLAIM_LEGACY_CONFLICT",
    )
    v2_root_final, v2_identity_final = _global_claim_root_read_snapshot_v2(workspace_receipt)
    legacy_identity_final = _legacy_root_read_identity_v1(legacy_root)
    if v2_root_final != v2_root or v2_identity_final != v2_identity_before:
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_ROOT_IDENTITY_CHANGED")
    if v2_payload_after != v2_payload:
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_MARKER_INVALID")
    if legacy_identity_final != legacy_identity_before or legacy_payload_after != legacy_payload:
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_LEGACY_CONFLICT")
    if v2_payload is not None and legacy_payload is not None and v2_payload != legacy_payload:
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_LEGACY_CONFLICT")
    canonical_payload = v2_payload if v2_payload is not None else legacy_payload
    canonical_path = (
        paths.v2 if v2_payload is not None else paths.legacy if legacy_payload is not None else None
    )
    return GlobalClaimMarkerPairV2(
        paths=paths,
        v2_root_identity=v2_identity_before,
        legacy_root_identity=legacy_identity_before,
        v2_payload=v2_payload,
        legacy_payload=legacy_payload,
        canonical_payload=canonical_payload,
        canonical_path=canonical_path,
    )


def _existing_marker_is_valid_v2(
    observed: GlobalClaimMarkerPairV2,
    validator: Callable[[bytes], bool],
) -> bool:
    payloads = tuple(
        payload for payload in (observed.v2_payload, observed.legacy_payload) if payload is not None
    )
    if not payloads:
        return False
    try:
        return all(validator(payload) for payload in payloads)
    except (TypeError, ValueError):
        return False


def _raise_if_consumed_v2(
    observed: GlobalClaimMarkerPairV2,
    validator: Callable[[bytes], bool],
) -> None:
    if observed.canonical_payload is None:
        return
    if not _existing_marker_is_valid_v2(observed, validator):
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_MARKER_INVALID")
    raise GlobalClaimBoundaryError("GLOBAL_CLAIM_ALREADY_CONSUMED")


def _write_exclusive_marker_v2(
    path: Path,
    payload: bytes,
    *,
    before_create: Callable[[], None] = lambda: None,
) -> None:
    descriptor = -1
    try:
        with _hold_directory_rebinding_guard_v2(
            path.parent,
            failure_code="GLOBAL_CLAIM_ROOT_IDENTITY_CHANGED",
        ):
            before_create()
            _reject_reparse_path(path)
            descriptor = os.open(
                path,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_BINARY", 0)
                | getattr(os, "O_NOINHERIT", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            with os.fdopen(descriptor, "wb") as stream:
                descriptor = -1
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _assert_write_root_identities_current_v2(
    workspace_receipt: RealCaptureWorkspaceReceiptV1,
    *,
    expected_v2_root_identity: tuple[object, ...],
    legacy_root: Path,
    expected_legacy_root_identity: tuple[object, ...],
) -> None:
    if inspect_global_claim_root_identity_v2(workspace_receipt) != expected_v2_root_identity:
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_ROOT_IDENTITY_CHANGED")
    if _legacy_root_read_identity_v1(legacy_root) != expected_legacy_root_identity:
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_LEGACY_CONFLICT")


def assert_global_claim_marker_current_v2(
    workspace_receipt: RealCaptureWorkspaceReceiptV1,
    marker_name: str,
    expected_payload: bytes,
    *,
    expected_root_identity: tuple[object, ...],
    expected_legacy_root_identity: tuple[object, ...],
    validator: Callable[[bytes], bool],
) -> Path:
    """Revalidate one V2 reservation, both roots, and root identity without writes."""

    identity_before = inspect_global_claim_root_identity_v2(workspace_receipt)
    if identity_before != expected_root_identity:
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_ROOT_IDENTITY_CHANGED")
    observed = read_global_claim_marker_pair_v2(workspace_receipt, marker_name)
    if observed.v2_root_identity != expected_root_identity:
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_ROOT_IDENTITY_CHANGED")
    if observed.v2_payload != expected_payload:
        if observed.v2_payload is None:
            raise GlobalClaimBoundaryError("GLOBAL_CLAIM_ROOT_IDENTITY_CHANGED")
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_MARKER_INVALID")
    if observed.legacy_payload is not None:
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_ALREADY_CONSUMED")
    if observed.legacy_root_identity != expected_legacy_root_identity:
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_LEGACY_CONFLICT")
    identity_after = inspect_global_claim_root_identity_v2(workspace_receipt)
    if identity_after != expected_root_identity:
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_ROOT_IDENTITY_CHANGED")
    if not _existing_marker_is_valid_v2(observed, validator):
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_MARKER_INVALID")
    return observed.paths.v2


def reserve_global_claim_marker_v2(
    workspace_receipt: RealCaptureWorkspaceReceiptV1,
    marker_name: str,
    payload: bytes,
    *,
    validator: Callable[[bytes], bool],
    expected_v2_read_identity: tuple[object, ...] | None = None,
    expected_legacy_root_identity: tuple[object, ...] | None = None,
) -> GlobalClaimReservationV2:
    """Reserve one marker in V2 only after checking V2 and legacy read-only state."""

    if not payload or len(payload) > _MAXIMUM_GLOBAL_MARKER_BYTES:
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_MARKER_PAYLOAD_INVALID")
    try:
        payload_valid = validator(payload)
    except (TypeError, ValueError):
        payload_valid = False
    if not payload_valid:
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_MARKER_PAYLOAD_INVALID")
    initial = read_global_claim_marker_pair_v2(workspace_receipt, marker_name)
    _raise_if_consumed_v2(initial, validator)
    if (
        expected_v2_read_identity is not None
        and initial.v2_root_identity != expected_v2_read_identity
    ):
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_ROOT_IDENTITY_CHANGED")
    if (
        expected_legacy_root_identity is not None
        and initial.legacy_root_identity != expected_legacy_root_identity
    ):
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_LEGACY_CONFLICT")
    ensured = _ensure_global_claim_root_with_identity_v2(
        workspace_receipt,
        expected_read_identity=initial.v2_root_identity,
    )
    root = ensured.path
    root_identity = ensured.identity
    root_after_ensure, v2_identity_after_ensure = _global_claim_root_read_snapshot_v2(
        workspace_receipt
    )
    if root_after_ensure != root:
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_ROOT_IDENTITY_CHANGED")
    if v2_identity_after_ensure != root_identity:
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_ROOT_IDENTITY_CHANGED")
    legacy_path = initial.paths.legacy
    legacy_identity = _legacy_root_read_identity_v1(legacy_path.parent)
    if legacy_identity != initial.legacy_root_identity:
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_LEGACY_CONFLICT")
    v2_path = _normalized_candidate_v2(root / marker_name)
    observed = read_global_claim_marker_pair_v2(workspace_receipt, marker_name)
    if observed.paths.v2 != v2_path or observed.paths.legacy != legacy_path:
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_ROOT_IDENTITY_CHANGED")
    _raise_if_consumed_v2(observed, validator)
    if observed.v2_root_identity != v2_identity_after_ensure:
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_ROOT_IDENTITY_CHANGED")
    if observed.legacy_root_identity != legacy_identity:
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_LEGACY_CONFLICT")
    if resolve_global_claim_root_candidate_v2(workspace_receipt) != root:
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_ROOT_IDENTITY_CHANGED")
    if inspect_global_claim_root_identity_v2(workspace_receipt) != root_identity:
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_ROOT_IDENTITY_CHANGED")
    if _legacy_root_read_identity_v1(legacy_path.parent) != legacy_identity:
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_LEGACY_CONFLICT")
    try:
        _write_exclusive_marker_v2(
            v2_path,
            payload,
            before_create=lambda: _assert_write_root_identities_current_v2(
                workspace_receipt,
                expected_v2_root_identity=root_identity,
                legacy_root=legacy_path.parent,
                expected_legacy_root_identity=legacy_identity,
            ),
        )
    except FileExistsError:
        raced = read_global_claim_marker_pair_v2(workspace_receipt, marker_name)
        _raise_if_consumed_v2(raced, validator)
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_ROOT_IDENTITY_CHANGED") from None
    except CaptureStorageError as error:
        code = (
            "GLOBAL_CLAIM_ROOT_REPARSE_FORBIDDEN"
            if "REPARSE" in error.code
            else "GLOBAL_CLAIM_ROOT_IDENTITY_CHANGED"
        )
        raise GlobalClaimBoundaryError(code) from None
    except PermissionError:
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_ROOT_ACL_REQUIRED") from None
    except (FileNotFoundError, NotADirectoryError):
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_ROOT_IDENTITY_CHANGED") from None
    except OSError:
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_MARKER_WRITE_FAILED") from None
    if inspect_global_claim_root_identity_v2(workspace_receipt) != root_identity:
        raise GlobalClaimBoundaryError("GLOBAL_CLAIM_ROOT_IDENTITY_CHANGED")
    marker_path = assert_global_claim_marker_current_v2(
        workspace_receipt,
        marker_name,
        payload,
        expected_root_identity=root_identity,
        expected_legacy_root_identity=legacy_identity,
        validator=validator,
    )
    return GlobalClaimReservationV2(
        path=marker_path,
        root_identity=root_identity,
        v2_read_identity=v2_identity_after_ensure,
        legacy_root_identity=legacy_identity,
    )
