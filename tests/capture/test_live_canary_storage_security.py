from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from robin.capture import CaptureStore, InternalRetentionPolicy
from robin.capture.storage import (
    _LOCAL_LINUX_FILESYSTEMS,
    CaptureStorageError,
    _is_unc_path,
    _linux_mount_filesystem,
    _safe_read_bytes,
)

_REQUIRE_WINDOWS_LINK_CAPABILITIES = os.environ.get("ROBIN_REQUIRE_WINDOWS_STORAGE_LINKS") == "1"


def test_linux_mount_parser_uses_deepest_mount_and_positive_local_allowlist(
    tmp_path: Path,
) -> None:
    mountinfo = tmp_path / "mountinfo"
    mount_root = tmp_path / "capture"
    mount_point = os.fspath(mount_root).replace(" ", r"\040")
    mountinfo.write_text(
        f"24 1 0:20 / {os.path.abspath(os.sep)} rw - ext4 /dev/root rw\n"
        f"25 24 0:21 / {mount_point} rw - fuse.rclone remote: rw\n",
        encoding="utf-8",
    )

    filesystem = _linux_mount_filesystem(
        mount_root / "bounded-canary",
        mountinfo_path=mountinfo,
    )

    assert filesystem == "fuse.rclone"
    assert filesystem not in _LOCAL_LINUX_FILESYSTEMS
    assert "ext4" in _LOCAL_LINUX_FILESYSTEMS
    assert not any(value.startswith("fuse") for value in _LOCAL_LINUX_FILESYSTEMS)


@pytest.mark.parametrize(
    "filesystem",
    ("autofs", "ceph", "cifs", "fuse", "fuse.sshfs", "glusterfs", "nfs4", "virtiofs"),
)
def test_distributed_and_dynamic_linux_filesystems_are_not_local(filesystem: str) -> None:
    assert filesystem not in _LOCAL_LINUX_FILESYSTEMS


def test_missing_linux_mount_identity_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(CaptureStorageError, match="MOUNT_IDENTITY_UNAVAILABLE"):
        _linux_mount_filesystem(
            tmp_path,
            mountinfo_path=tmp_path / "missing-mountinfo",
        )


def test_unc_paths_are_rejected_by_path_semantics() -> None:
    assert _is_unc_path(Path(r"\\synthetic-server\capture")) is True  # PORTABILITY_TEST_FIXTURE
    assert _is_unc_path(Path("//synthetic-server/capture")) is True  # PORTABILITY_TEST_FIXTURE


def test_capture_store_constructor_does_not_write_through_raw_symlink(
    tmp_path: Path,
) -> None:
    root = tmp_path / "capture"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    try:
        (root / "raw").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are not available on this host")

    with pytest.raises(CaptureStorageError, match="REPARSE_POINT_FORBIDDEN"):
        CaptureStore(root, InternalRetentionPolicy(), approved_local_root=root)

    assert not (outside / "sha256").exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows junction semantics")
def test_capture_store_constructor_does_not_write_through_raw_junction(
    tmp_path: Path,
) -> None:
    root = tmp_path / "capture-junction"
    outside = tmp_path / "outside-junction"
    root.mkdir()
    outside.mkdir()
    result = subprocess.run(
        ["cmd.exe", "/d", "/c", "mklink", "/J", str(root / "raw"), str(outside)],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        if _REQUIRE_WINDOWS_LINK_CAPABILITIES:
            pytest.fail("Windows CI must support junction creation for reparse tests")
        pytest.skip("junction creation is not available on this Windows host")

    with pytest.raises(CaptureStorageError, match="REPARSE_POINT_FORBIDDEN"):
        CaptureStore(root, InternalRetentionPolicy(), approved_local_root=root)

    assert not (outside / "sha256").exists()


def test_safe_storage_rejects_hardlinked_mutable_files(tmp_path: Path) -> None:
    outside = tmp_path / "outside-ledger"
    inside = tmp_path / "inside-ledger"
    outside.write_bytes(b"synthetic\n")
    try:
        os.link(outside, inside)
    except OSError:
        if os.name == "nt" and _REQUIRE_WINDOWS_LINK_CAPABILITIES:
            pytest.fail("Windows CI must support hardlinks for storage tests")
        pytest.skip("hardlinks are not available on this host")

    with pytest.raises(CaptureStorageError, match="CAPTURE_STORAGE_FILE_UNSAFE"):
        _safe_read_bytes(inside)
