"""Content-addressed local storage with immutable metadata and raw TTL deletion."""

from __future__ import annotations

import hashlib
import os
import stat
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from threading import Lock
from typing import Any, cast

from robin.capture.contracts import (
    AdmissionStatus,
    CaptureBudget,
    CaptureContractError,
    CaptureManifest,
    InternalRetentionPolicy,
    NormalizedMarketObservation,
    OfflineReplayResult,
    RawPayloadReceipt,
    canonical_json_bytes,
    canonical_sha256,
    ensure_utc,
    strict_json_object,
)
from robin.capture.normalization import (
    normalize_payload,
    normalized_jsonl_bytes,
    snapshot_id_for_observation_rows,
)

_SYNCHRONIZED_PATH_MARKERS = frozenset(
    {"onedrive", "dropbox", "google drive", "googledrive", "icloud", "icloud drive"}
)
_LOCAL_LINUX_FILESYSTEMS = frozenset(
    {
        "btrfs",
        "exfat",
        "ext2",
        "ext3",
        "ext4",
        "f2fs",
        "hfsplus",
        "jfs",
        "ntfs",
        "ntfs3",
        "overlay",
        "reiserfs",
        "ufs",
        "vfat",
        "xfs",
        "zfs",
    }
)
_MAX_CONTRACT_BYTES = 1_048_576
_MAX_RAW_PAYLOAD_BYTES = 10_485_760
_MAX_NORMALIZED_BYTES = 67_108_864
_MAX_LEDGER_BYTES = 67_108_864


def _is_unc_path(path: Path) -> bool:
    raw = os.fspath(path)
    return raw.startswith("\\\\") or raw.startswith("//")


def _is_reparse_point(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        raise CaptureStorageError("CAPTURE_WORKSPACE_IDENTITY_UNAVAILABLE") from None
    junction = getattr(path, "is_junction", None)
    return (
        path.is_symlink()
        or (callable(junction) and bool(junction()))
        or bool(
            getattr(metadata, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        )
    )


def _reject_reparse_path(path: Path) -> None:
    absolute = path.absolute()
    for component in reversed((absolute, *absolute.parents)):
        if _is_reparse_point(component):
            raise CaptureStorageError("CAPTURE_WORKSPACE_REPARSE_POINT_FORBIDDEN")


def _is_remote_drive(path: Path) -> bool:
    if os.name != "nt":
        return False
    drive, _tail = os.path.splitdrive(os.path.abspath(os.fspath(path)))
    if not drive:
        return False
    import ctypes

    loader = getattr(ctypes, "WinDLL", None)
    if not callable(loader):
        raise CaptureStorageError("CAPTURE_WORKSPACE_DRIVE_TYPE_UNAVAILABLE")
    try:
        kernel32 = loader("kernel32", use_last_error=True)
        get_drive_type = getattr(kernel32, "GetDriveTypeW")
        drive_type = int(get_drive_type(f"{drive}\\"))
    except (AttributeError, OSError, TypeError, ValueError):
        raise CaptureStorageError("CAPTURE_WORKSPACE_DRIVE_TYPE_UNAVAILABLE") from None
    return drive_type != 3


def _path_exists_no_follow(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        raise CaptureStorageError("CAPTURE_STORAGE_PATH_IDENTITY_UNAVAILABLE") from None
    return True


def _linux_mount_filesystem(
    path: Path,
    *,
    mountinfo_path: Path = Path("/proc/self/mountinfo"),
) -> str:
    try:
        lines = mountinfo_path.read_text(encoding="utf-8").splitlines()
    except (FileNotFoundError, OSError):
        raise CaptureStorageError("CAPTURE_WORKSPACE_MOUNT_IDENTITY_UNAVAILABLE") from None
    candidate = os.path.abspath(os.fspath(path))
    selected: tuple[int, str] | None = None
    for line in lines:
        left, separator, right = line.partition(" - ")
        fields = left.split()
        after = right.split()
        if not separator or len(fields) < 5 or not after:
            continue
        mount_point = (
            fields[4]
            .replace("\\040", " ")
            .replace("\\011", "\t")
            .replace("\\012", "\n")
            .replace("\\134", "\\")
        )
        try:
            within = os.path.commonpath((candidate, mount_point)) == mount_point
        except ValueError:
            within = False
        if within and (selected is None or len(mount_point) > selected[0]):
            selected = (len(mount_point), after[0].casefold())
    if selected is None:
        raise CaptureStorageError("CAPTURE_WORKSPACE_MOUNT_IDENTITY_UNAVAILABLE")
    return selected[1]


def _is_known_network_mount(path: Path) -> bool:
    if os.name == "nt":
        return False
    if not sys.platform.startswith("linux"):
        raise CaptureStorageError("CAPTURE_WORKSPACE_PLATFORM_UNSUPPORTED")
    return _linux_mount_filesystem(path) not in _LOCAL_LINUX_FILESYSTEMS


def _validate_open_file(path: Path, descriptor: int) -> None:
    _reject_reparse_path(path)
    opened = os.fstat(descriptor)
    try:
        current = path.lstat()
    except OSError:
        raise CaptureStorageError("CAPTURE_STORAGE_FILE_IDENTITY_UNAVAILABLE") from None
    if (
        not stat.S_ISREG(opened.st_mode)
        or opened.st_nlink != 1
        or not stat.S_ISREG(current.st_mode)
        or current.st_dev != opened.st_dev
        or current.st_ino != opened.st_ino
    ):
        raise CaptureStorageError("CAPTURE_STORAGE_FILE_UNSAFE")


@contextmanager
def _safe_regular_file(path: Path, *, flags: int, mode: str) -> Iterator[Any]:
    _reject_reparse_path(path)
    safe_flags = flags | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0)
    safe_flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, safe_flags, 0o600)
    except OSError:
        raise
    try:
        _validate_open_file(path, descriptor)
        with os.fdopen(descriptor, mode) as stream:
            descriptor = -1
            try:
                yield stream
            finally:
                _validate_open_file(path, stream.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    _reject_reparse_path(path)
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        opened = os.fstat(descriptor)
        current = path.lstat()
        if (
            not os.path.samestat(opened, current)
            or not stat.S_ISDIR(opened.st_mode)
            or not stat.S_ISDIR(current.st_mode)
        ):
            raise CaptureStorageError("CAPTURE_STORAGE_DIRECTORY_IDENTITY_CHANGED")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _safe_read_bytes(path: Path) -> bytes:
    try:
        with _safe_regular_file(path, flags=os.O_RDONLY, mode="rb") as stream:
            return cast(bytes, stream.read())
    except FileNotFoundError:
        raise
    except OSError:
        raise CaptureStorageError("CAPTURE_STORAGE_FILE_UNSAFE") from None


def _safe_read_bounded(path: Path, *, maximum_bytes: int) -> bytes:
    if maximum_bytes <= 0:
        raise CaptureStorageError("CAPTURE_STORAGE_READ_LIMIT_INVALID")
    try:
        with _safe_regular_file(path, flags=os.O_RDONLY, mode="rb") as stream:
            if os.fstat(stream.fileno()).st_size > maximum_bytes:
                raise CaptureStorageError("CAPTURE_STORAGE_FILE_TOO_LARGE")
            payload = cast(bytes, stream.read(maximum_bytes + 1))
            if len(payload) > maximum_bytes:
                raise CaptureStorageError("CAPTURE_STORAGE_FILE_TOO_LARGE")
            _validate_open_file(path, stream.fileno())
            return payload
    except FileNotFoundError:
        raise
    except CaptureStorageError:
        raise
    except OSError:
        raise CaptureStorageError("CAPTURE_STORAGE_FILE_UNSAFE") from None


def _safe_sha256_file(path: Path, *, maximum_bytes: int) -> tuple[str, int]:
    if maximum_bytes <= 0:
        raise CaptureStorageError("CAPTURE_STORAGE_READ_LIMIT_INVALID")
    digest = hashlib.sha256()
    total = 0
    try:
        with _safe_regular_file(path, flags=os.O_RDONLY, mode="rb") as stream:
            if os.fstat(stream.fileno()).st_size > maximum_bytes:
                raise CaptureStorageError("CAPTURE_STORAGE_FILE_TOO_LARGE")
            while chunk := stream.read(min(1_048_576, maximum_bytes - total + 1)):
                total += len(chunk)
                if total > maximum_bytes:
                    raise CaptureStorageError("CAPTURE_STORAGE_FILE_TOO_LARGE")
                digest.update(chunk)
            _validate_open_file(path, stream.fileno())
    except CaptureStorageError:
        raise
    except OSError:
        raise CaptureStorageError("CAPTURE_STORAGE_FILE_UNSAFE") from None
    return digest.hexdigest(), total


def _repair_truncated_jsonl_tail(
    path: Path,
    *,
    maximum_bytes: int,
) -> dict[str, object] | None:
    if not _path_exists_no_follow(path):
        return None
    with _safe_regular_file(path, flags=os.O_RDWR, mode="r+b") as stream:
        if os.fstat(stream.fileno()).st_size > maximum_bytes:
            raise CaptureStorageError("CAPTURE_STORAGE_FILE_TOO_LARGE")
        payload = cast(bytes, stream.read(maximum_bytes + 1))
        if len(payload) > maximum_bytes:
            raise CaptureStorageError("CAPTURE_STORAGE_FILE_TOO_LARGE")
        if not payload or payload.endswith(b"\n"):
            return None
        boundary = payload.rfind(b"\n")
        complete = payload[: boundary + 1] if boundary >= 0 else b""
        tail = payload[boundary + 1 :]
        stream.seek(len(complete))
        stream.truncate()
        stream.flush()
        os.fsync(stream.fileno())
    _fsync_directory(path.parent)
    return {
        "schema_version": "robin-jsonl-tail-recovery-v1",
        "complete_prefix_sha256": hashlib.sha256(complete).hexdigest(),
        "truncated_tail_byte_length": len(tail),
        "truncated_tail_sha256": hashlib.sha256(tail).hexdigest(),
    }


def _safe_directory_tree(path: Path) -> Path:
    """Create only missing components, checking every existing/new component."""

    target = Path(os.path.abspath(os.fspath(path)))
    missing: list[str] = []
    current = target
    while True:
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            if current.parent == current:
                raise CaptureStorageError("CAPTURE_STORAGE_DIRECTORY_UNAVAILABLE") from None
            missing.append(current.name)
            current = current.parent
            continue
        except OSError:
            raise CaptureStorageError("CAPTURE_STORAGE_DIRECTORY_UNAVAILABLE") from None
        _reject_reparse_path(current)
        if not stat.S_ISDIR(metadata.st_mode):
            raise CaptureStorageError("CAPTURE_STORAGE_DIRECTORY_UNSAFE")
        break
    for part in reversed(missing):
        current = current / part
        _reject_reparse_path(current)
        try:
            current.mkdir()
        except FileExistsError:
            pass
        except OSError:
            raise CaptureStorageError("CAPTURE_STORAGE_DIRECTORY_UNAVAILABLE") from None
        _reject_reparse_path(current)
        try:
            metadata = current.lstat()
        except OSError:
            raise CaptureStorageError("CAPTURE_STORAGE_DIRECTORY_UNAVAILABLE") from None
        if not stat.S_ISDIR(metadata.st_mode):
            raise CaptureStorageError("CAPTURE_STORAGE_DIRECTORY_UNSAFE")
        _fsync_directory(current.parent)
    return target


@contextmanager
def _exclusive_file_lock(path: Path) -> Iterator[None]:
    with _safe_regular_file(
        path,
        flags=os.O_RDWR | os.O_CREAT,
        mode="r+b",
    ) as stream:
        if stream.seek(0, os.SEEK_END) == 0:
            stream.write(b"\0")
            stream.flush()
            os.fsync(stream.fileno())
        stream.seek(0)
        if os.name == "nt":
            import msvcrt

            getattr(msvcrt, "locking")(stream.fileno(), getattr(msvcrt, "LK_LOCK"), 1)
        else:
            import fcntl

            getattr(fcntl, "flock")(stream.fileno(), getattr(fcntl, "LOCK_EX"))
        try:
            _validate_open_file(path, stream.fileno())
            yield
        finally:
            stream.seek(0)
            if os.name == "nt":
                import msvcrt

                getattr(msvcrt, "locking")(stream.fileno(), getattr(msvcrt, "LK_UNLCK"), 1)
            else:
                import fcntl

                getattr(fcntl, "flock")(stream.fileno(), getattr(fcntl, "LOCK_UN"))


class CaptureStorageError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _is_inside_git(path: Path) -> bool:
    candidate = path.resolve()
    for parent in (candidate, *candidate.parents):
        if _path_exists_no_follow(parent / ".git"):
            return True
    return False


def _is_synchronized(path: Path) -> bool:
    for part in path.resolve().parts:
        normalized = part.casefold()
        if any(
            normalized == marker
            or normalized.startswith(f"{marker} ")
            or normalized.startswith(f"{marker}-")
            for marker in _SYNCHRONIZED_PATH_MARKERS
        ):
            return True
    return False


def validate_capture_workspace(path: Path) -> Path:
    if _is_unc_path(path) or _is_remote_drive(path) or _is_known_network_mount(path):
        raise CaptureStorageError("CAPTURE_WORKSPACE_NETWORK_DRIVE_FORBIDDEN")
    unresolved = Path(os.path.abspath(os.fspath(path)))
    _reject_reparse_path(unresolved)
    resolved = unresolved.resolve()
    if _is_inside_git(resolved):
        raise CaptureStorageError("CAPTURE_WORKSPACE_IN_GIT")
    if _is_synchronized(resolved):
        raise CaptureStorageError("CAPTURE_WORKSPACE_SYNCHRONIZED")
    return resolved


def validate_local_directory_identity(path: Path) -> Path:
    """Validate a local control directory without applying capture-root policy."""

    if _is_unc_path(path) or _is_remote_drive(path) or _is_known_network_mount(path):
        raise CaptureStorageError("CAPTURE_CONTROL_PATH_NETWORK_FORBIDDEN")
    unresolved = Path(os.path.abspath(os.fspath(path)))
    _reject_reparse_path(unresolved)
    try:
        metadata = unresolved.lstat()
    except OSError:
        raise CaptureStorageError("CAPTURE_CONTROL_PATH_IDENTITY_UNAVAILABLE") from None
    if not stat.S_ISDIR(metadata.st_mode):
        raise CaptureStorageError("CAPTURE_CONTROL_PATH_DIRECTORY_REQUIRED")
    return unresolved


def validate_exclusive_local_directory_identity(path: Path) -> Path:
    """Validate an owner-controlled local directory outside sync providers.

    The live Git preflight relies on a separately pinned owner attestation that no
    concurrent principal can mutate this directory while its local evidence is
    inspected.  Synchronized directories cannot satisfy that boundary.
    """

    resolved = validate_local_directory_identity(path)
    if _is_synchronized(resolved):
        raise CaptureStorageError("CAPTURE_CONTROL_PATH_SYNCHRONIZED")
    return resolved


def exclusive_local_directory_fingerprint(path: Path) -> str:
    resolved = validate_exclusive_local_directory_identity(path)
    try:
        metadata = os.stat(resolved, follow_symlinks=False)
    except OSError:
        raise CaptureStorageError("CAPTURE_CONTROL_PATH_IDENTITY_UNAVAILABLE") from None
    if not stat.S_ISDIR(metadata.st_mode):
        raise CaptureStorageError("CAPTURE_CONTROL_PATH_DIRECTORY_REQUIRED")
    return canonical_sha256(
        {
            "schema_version": "robin-exclusive-local-directory-identity-v1",
            "os_name": os.name,
            "resolved_path": os.path.normcase(os.fspath(resolved)),
            "device": metadata.st_dev,
            "inode": metadata.st_ino,
        }
    )


def capture_root_fingerprint(path: Path) -> str:
    resolved = validate_capture_workspace(path)
    try:
        metadata = os.stat(resolved, follow_symlinks=False)
    except OSError:
        raise CaptureStorageError("CAPTURE_WORKSPACE_IDENTITY_UNAVAILABLE") from None
    if not stat.S_ISDIR(metadata.st_mode):
        raise CaptureStorageError("CAPTURE_WORKSPACE_NOT_DIRECTORY")
    return canonical_sha256(
        {
            "schema_version": "robin-capture-root-identity-v1",
            "os_name": os.name,
            "resolved_path": os.path.normcase(os.fspath(resolved)),
            "device": metadata.st_dev,
            "inode": metadata.st_ino,
        }
    )


class CaptureStore:
    """A local, content-addressed capture store that never accepts a Git path."""

    def __init__(
        self,
        root: Path,
        retention_policy: InternalRetentionPolicy | None,
        *,
        approved_local_root: Path | None,
    ) -> None:
        if retention_policy is None:
            raise CaptureStorageError("CAPTURE_RETENTION_POLICY_REQUIRED")
        if approved_local_root is None:
            raise CaptureStorageError("CAPTURE_LOCAL_ROOT_APPROVAL_REQUIRED")
        if os.path.normcase(os.path.abspath(os.fspath(root))) != os.path.normcase(
            os.path.abspath(os.fspath(approved_local_root))
        ):
            raise CaptureStorageError("CAPTURE_LOCAL_ROOT_APPROVAL_MISMATCH")
        self.policy = retention_policy
        self.root = validate_capture_workspace(root)
        _safe_directory_tree(self.root)
        self._approved_root_fingerprint = capture_root_fingerprint(self.root)
        self._immutable_repair_lock = self._path(".immutable-repair.lock")
        for relative in (
            "raw/sha256",
            "receipts",
            "normalized",
            "manifests",
            "quarantine",
        ):
            self._directory(relative)
        if validate_capture_workspace(self.root) != self.root:
            raise CaptureStorageError("CAPTURE_WORKSPACE_IDENTITY_CHANGED")
        self.deletion_ledger = self.root / "deletion-ledger.jsonl"
        self.budget_ledger = self.root / "budget-ledger.jsonl"
        self._budget_lock_path = self.root / ".budget-ledger.lock"
        self._ttl_lock_path = self.root / ".ttl-enforcement.lock"
        self._deletion_ledger_lock_path = self.root / ".deletion-ledger.lock"
        self._deletion_ledger_lock = Lock()

    @contextmanager
    def capture_transaction(self) -> Iterator[None]:
        """Serialize receipt/raw finalization with TTL scans across processes."""
        with _exclusive_file_lock(self._ttl_lock_path):
            yield

    def _load_anchored_jsonl_entries(
        self,
        *,
        ledger: Path,
        event_directory_key: str,
        rollback_error: str,
    ) -> list[dict[str, Any]]:
        """Return one anchored hash chain, restoring only a missing ledger suffix.

        The content-addressed event objects are written before the JSONL view.  A
        process crash can therefore leave the view behind the immutable objects,
        but deleting or replacing JSONL records cannot make spent budget disappear.
        This method is called only while the caller holds the ledger's OS lock.
        """

        event_directory = self._directory(event_directory_key)
        entries_by_hash: dict[str, dict[str, Any]] = {}
        total_event_bytes = 0
        try:
            candidates = sorted(event_directory.iterdir(), key=lambda path: path.name)
        except OSError:
            raise CaptureStorageError(rollback_error) from None
        for path in candidates:
            _reject_reparse_path(path)
            if (
                path.parent != event_directory
                or path.suffix != ".json"
                or len(path.stem) != 64
                or any(character not in "0123456789abcdef" for character in path.stem)
            ):
                raise CaptureStorageError(rollback_error)
            try:
                payload = _safe_read_bounded(path, maximum_bytes=_MAX_CONTRACT_BYTES)
                total_event_bytes += len(payload)
                if total_event_bytes > _MAX_LEDGER_BYTES:
                    raise CaptureStorageError(rollback_error)
                entry = strict_json_object(payload)
            except (CaptureContractError, UnicodeDecodeError, OSError):
                raise CaptureStorageError(rollback_error) from None
            entry_hash = entry.get("entry_sha256")
            identity = {key: value for key, value in entry.items() if key != "entry_sha256"}
            if (
                entry_hash != path.stem
                or canonical_sha256(identity) != entry_hash
                or payload != canonical_json_bytes(entry) + b"\n"
                or entry_hash in entries_by_hash
            ):
                raise CaptureStorageError(rollback_error)
            entries_by_hash[path.stem] = entry

        ordered: list[dict[str, Any]] = []
        if entries_by_hash:
            genesis = [
                entry
                for entry in entries_by_hash.values()
                if entry.get("previous_entry_sha256") is None
            ]
            if len(genesis) != 1:
                raise CaptureStorageError(rollback_error)
            child_by_parent: dict[str, dict[str, Any]] = {}
            for entry in entries_by_hash.values():
                parent = entry.get("previous_entry_sha256")
                if parent is None:
                    continue
                if (
                    not isinstance(parent, str)
                    or parent not in entries_by_hash
                    or parent in child_by_parent
                ):
                    raise CaptureStorageError(rollback_error)
                child_by_parent[parent] = entry
            current = genesis[0]
            while True:
                ordered.append(current)
                current_hash = cast(str, current["entry_sha256"])
                successor = child_by_parent.get(current_hash)
                if successor is None:
                    break
                current = successor
            if len(ordered) != len(entries_by_hash):
                raise CaptureStorageError(rollback_error)

        ledger_exists = _path_exists_no_follow(ledger)
        ledger_entries: list[dict[str, Any]] = []
        if ledger_exists:
            try:
                payload = _safe_read_bounded(ledger, maximum_bytes=_MAX_LEDGER_BYTES)
                ledger_entries = [strict_json_object(line) for line in payload.splitlines()]
            except (CaptureContractError, UnicodeDecodeError, OSError):
                raise CaptureStorageError(rollback_error) from None
            if not ledger_entries and not ordered:
                raise CaptureStorageError(rollback_error)
        if len(ledger_entries) > len(ordered) or any(
            observed != anchored
            for observed, anchored in zip(
                ledger_entries,
                ordered[: len(ledger_entries)],
                strict=True,
            )
        ):
            raise CaptureStorageError(rollback_error)
        missing = ordered[len(ledger_entries) :]
        if missing:
            try:
                with _safe_regular_file(
                    ledger,
                    flags=os.O_WRONLY | os.O_CREAT | os.O_APPEND,
                    mode="ab",
                ) as stream:
                    for entry in missing:
                        stream.write(canonical_json_bytes(entry) + b"\n")
                    stream.flush()
                    os.fsync(stream.fileno())
                _fsync_directory(ledger.parent)
            except OSError:
                raise CaptureStorageError(rollback_error) from None
        return ordered

    def _append_anchored_jsonl_entry(
        self,
        *,
        ledger: Path,
        event_directory_key: str,
        entry: dict[str, Any],
    ) -> None:
        entry_hash = cast(str, entry["entry_sha256"])
        payload = canonical_json_bytes(entry) + b"\n"
        self._write_immutable(
            f"{event_directory_key}/{entry_hash}.json",
            payload,
        )
        with _safe_regular_file(
            ledger,
            flags=os.O_WRONLY | os.O_CREAT | os.O_APPEND,
            mode="ab",
        ) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        _fsync_directory(ledger.parent)

    def reserve_budget(
        self,
        budget: CaptureBudget,
        *,
        requests: int,
        credits: int,
        consume: bool,
    ) -> CaptureBudget:
        try:
            if any(
                isinstance(getattr(budget, name), bool)
                or not isinstance(getattr(budget, name), int)
                for name in (
                    "maximum_requests",
                    "used_requests",
                    "maximum_credits",
                    "used_credits",
                )
            ):
                raise ValueError
            budget_material = budget.model_dump(mode="json")
            if any(
                isinstance(budget_material.get(name), bool)
                or not isinstance(budget_material.get(name), int)
                for name in (
                    "maximum_requests",
                    "used_requests",
                    "maximum_credits",
                    "used_credits",
                )
            ):
                raise ValueError
            budget = CaptureBudget.model_validate(budget_material)
        except (AttributeError, CaptureContractError, TypeError, ValueError):
            raise CaptureStorageError("CAPTURE_BUDGET_INVALID") from None
        if (
            isinstance(requests, bool)
            or not isinstance(requests, int)
            or isinstance(credits, bool)
            or not isinstance(credits, int)
        ):
            raise CaptureStorageError("CAPTURE_BUDGET_RESERVATION_INVALID")
        with _exclusive_file_lock(self._budget_lock_path):
            recovery = _repair_truncated_jsonl_tail(
                self.budget_ledger,
                maximum_bytes=_MAX_LEDGER_BYTES,
            )
            if recovery is not None:
                recovery_record = {
                    **recovery,
                    "ledger": "capture-budget-ledger-v1",
                }
                self._write_immutable(
                    f"budget-ledger-recovery/{canonical_sha256(recovery_record)}.json",
                    canonical_json_bytes(recovery_record) + b"\n",
                )
            entries = self._load_anchored_jsonl_entries(
                ledger=self.budget_ledger,
                event_directory_key="budget-events",
                rollback_error="CAPTURE_BUDGET_LEDGER_ROLLBACK_DETECTED",
            )
            current = budget
            previous_entry_sha256: str | None = None
            previous_used_requests = 0
            previous_used_credits = 0
            if entries:
                for entry in entries:
                    if set(entry) != {
                        "action",
                        "entry_sha256",
                        "maximum_credits",
                        "maximum_requests",
                        "previous_entry_sha256",
                        "prior_used_credits",
                        "prior_used_requests",
                        "reserved_credits",
                        "reserved_requests",
                        "used_credits",
                        "used_requests",
                    }:
                        raise CaptureStorageError("CAPTURE_BUDGET_LEDGER_INVALID")
                    entry_sha256 = entry.get("entry_sha256")
                    if not isinstance(entry_sha256, str):
                        raise CaptureStorageError("CAPTURE_BUDGET_LEDGER_INVALID")
                    identity = {key: value for key, value in entry.items() if key != "entry_sha256"}
                    if canonical_sha256(identity) != entry_sha256:
                        raise CaptureStorageError("CAPTURE_BUDGET_LEDGER_HASH_MISMATCH")
                    if entry.get("previous_entry_sha256") != previous_entry_sha256:
                        raise CaptureStorageError("CAPTURE_BUDGET_LEDGER_CHAIN_MISMATCH")
                    if entry.get("action") != "CAPTURE_BUDGET_RESERVATION":
                        raise CaptureStorageError("CAPTURE_BUDGET_LEDGER_INVALID")
                    if (
                        entry.get("maximum_requests") != budget.maximum_requests
                        or entry.get("maximum_credits") != budget.maximum_credits
                    ):
                        raise CaptureStorageError("CAPTURE_BUDGET_CONFIGURATION_MISMATCH")
                    used_requests = entry.get("used_requests")
                    used_credits = entry.get("used_credits")
                    prior_used_requests = entry.get("prior_used_requests")
                    prior_used_credits = entry.get("prior_used_credits")
                    reserved_requests = entry.get("reserved_requests")
                    reserved_credits = entry.get("reserved_credits")
                    integer_fields = (
                        entry.get("maximum_requests"),
                        entry.get("maximum_credits"),
                        used_requests,
                        used_credits,
                        prior_used_requests,
                        prior_used_credits,
                        reserved_requests,
                        reserved_credits,
                    )
                    if any(
                        isinstance(value, bool) or not isinstance(value, int)
                        for value in integer_fields
                    ):
                        raise CaptureStorageError("CAPTURE_BUDGET_LEDGER_INVALID")
                    validated_used_requests = cast(int, used_requests)
                    validated_used_credits = cast(int, used_credits)
                    validated_prior_requests = cast(int, prior_used_requests)
                    validated_prior_credits = cast(int, prior_used_credits)
                    validated_reserved_requests = cast(int, reserved_requests)
                    validated_reserved_credits = cast(int, reserved_credits)
                    if (
                        validated_prior_requests != previous_used_requests
                        or validated_prior_credits != previous_used_credits
                        or validated_reserved_requests <= 0
                        or validated_reserved_credits < 0
                        or validated_used_requests
                        != validated_prior_requests + validated_reserved_requests
                        or validated_used_credits
                        != validated_prior_credits + validated_reserved_credits
                    ):
                        raise CaptureStorageError("CAPTURE_BUDGET_LEDGER_TRANSITION_INVALID")
                    current = CaptureBudget(
                        maximum_requests=budget.maximum_requests,
                        maximum_credits=budget.maximum_credits,
                        used_requests=validated_used_requests,
                        used_credits=validated_used_credits,
                    )
                    previous_entry_sha256 = entry_sha256
                    previous_used_requests = validated_used_requests
                    previous_used_credits = validated_used_credits
            reserved = current.reserve(requests=requests, credits=credits)
            if not consume:
                return reserved
            if previous_entry_sha256 is None and (
                current.used_requests != 0 or current.used_credits != 0
            ):
                raise CaptureStorageError("CAPTURE_BUDGET_INITIAL_USAGE_MUST_BE_ZERO")
            identity = {
                "action": "CAPTURE_BUDGET_RESERVATION",
                "maximum_credits": reserved.maximum_credits,
                "maximum_requests": reserved.maximum_requests,
                "previous_entry_sha256": previous_entry_sha256,
                "prior_used_credits": current.used_credits,
                "prior_used_requests": current.used_requests,
                "reserved_credits": credits,
                "reserved_requests": requests,
                "used_credits": reserved.used_credits,
                "used_requests": reserved.used_requests,
            }
            entry = {
                "entry_sha256": canonical_sha256(identity),
                **identity,
            }
            self._append_anchored_jsonl_entry(
                ledger=self.budget_ledger,
                event_directory_key="budget-events",
                entry=entry,
            )
            return reserved

    def _path(self, key: str) -> Path:
        self._assert_root_identity()
        logical = Path(key)
        if logical.is_absolute() or ".." in logical.parts:
            raise CaptureStorageError("CAPTURE_STORAGE_KEY_INVALID")
        unresolved = self.root / logical
        _reject_reparse_path(unresolved)
        candidate = Path(os.path.abspath(os.fspath(unresolved)))
        try:
            common = Path(os.path.commonpath((self.root, candidate)))
        except ValueError:
            raise CaptureStorageError("CAPTURE_STORAGE_KEY_INVALID") from None
        if candidate == self.root or common != self.root:
            raise CaptureStorageError("CAPTURE_STORAGE_KEY_INVALID")
        self._assert_root_identity()
        return candidate

    def _assert_root_identity(self) -> None:
        if capture_root_fingerprint(self.root) != self._approved_root_fingerprint:
            raise CaptureStorageError("CAPTURE_WORKSPACE_IDENTITY_CHANGED")

    def capture_root_fingerprint(self) -> str:
        return capture_root_fingerprint(self.root)

    def _directory(self, key: str) -> Path:
        directory = self._path(key)
        return _safe_directory_tree(directory)

    def _write_immutable(self, key: str, payload: bytes) -> None:
        destination = self._path(key)
        self._directory(str(Path(key).parent).replace("\\", "/"))
        try:
            existing = _safe_read_bounded(
                destination,
                maximum_bytes=max(len(payload), 1),
            )
        except FileNotFoundError:
            existing = None
        if existing is not None:
            if existing != payload:
                self._repair_incomplete_immutable(destination, payload, existing)
            return
        try:
            with _safe_regular_file(
                destination,
                flags=os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                mode="wb",
            ) as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            _fsync_directory(destination.parent)
        except FileExistsError:
            existing = _safe_read_bounded(
                destination,
                maximum_bytes=max(len(payload), 1),
            )
            if existing != payload:
                self._repair_incomplete_immutable(destination, payload, existing)

    def _repair_incomplete_immutable(
        self,
        destination: Path,
        payload: bytes,
        observed: bytes,
    ) -> None:
        if not payload.startswith(observed) or len(observed) >= len(payload):
            raise CaptureStorageError("CAPTURE_STORAGE_COLLISION")
        with _exclusive_file_lock(self._immutable_repair_lock):
            current = _safe_read_bounded(
                destination,
                maximum_bytes=max(len(payload), 1),
            )
            if current == payload:
                return
            if not payload.startswith(current) or len(current) >= len(payload):
                raise CaptureStorageError("CAPTURE_STORAGE_COLLISION")
            with _safe_regular_file(
                destination,
                flags=os.O_RDWR,
                mode="r+b",
            ) as stream:
                stream.seek(len(current))
                stream.write(payload[len(current) :])
                stream.flush()
                os.fsync(stream.fileno())
            _fsync_directory(destination.parent)

    def store_raw(self, payload: bytes) -> tuple[str, str]:
        digest = hashlib.sha256(payload).hexdigest()
        key = f"raw/sha256/{digest[:2]}/{digest}.bin"
        self._write_immutable(key, payload)
        return digest, key

    def store_receipt(self, receipt: RawPayloadReceipt) -> str:
        key = f"receipts/{receipt.receipt_id}.json"
        payload = canonical_json_bytes(receipt.model_dump(mode="json")) + b"\n"
        self._write_immutable(key, payload)
        return key

    def store_quarantine(self, receipt: RawPayloadReceipt) -> str:
        if receipt.rejection_code is None:
            raise CaptureStorageError("CAPTURE_QUARANTINE_REASON_REQUIRED")
        record = {
            "receipt_id": receipt.receipt_id,
            "payload_sha256": receipt.payload_sha256,
            "payload_byte_length": receipt.payload_byte_length,
            "reason": receipt.rejection_code,
            "raw_storage_key": receipt.raw_storage_key,
        }
        key = f"quarantine/{receipt.receipt_id}.json"
        self._write_immutable(key, canonical_json_bytes(record) + b"\n")
        return key

    def store_normalized(
        self,
        *,
        snapshot_id: str,
        payload: bytes,
    ) -> str:
        key = f"normalized/{snapshot_id}.jsonl"
        self._write_immutable(key, payload)
        return key

    def store_manifest(self, manifest: CaptureManifest) -> str:
        key = f"manifests/{manifest.snapshot_id}.json"
        payload = canonical_json_bytes(manifest.model_dump(mode="json")) + b"\n"
        self._write_immutable(key, payload)
        return key

    def load_receipt(self, receipt_id: str) -> RawPayloadReceipt:
        path = self._path(f"receipts/{receipt_id}.json")
        receipt = RawPayloadReceipt.model_validate_json(
            _safe_read_bounded(path, maximum_bytes=_MAX_CONTRACT_BYTES)
        )
        if receipt.receipt_id != receipt_id:
            raise CaptureStorageError("CAPTURE_RECEIPT_PATH_IDENTITY_MISMATCH")
        if receipt.intake_receipt_id is not None:
            intake_path = self._path(f"receipts/{receipt.intake_receipt_id}.json")
            try:
                intake = RawPayloadReceipt.model_validate_json(
                    _safe_read_bounded(
                        intake_path,
                        maximum_bytes=_MAX_CONTRACT_BYTES,
                    )
                )
            except FileNotFoundError:
                raise CaptureStorageError("CAPTURE_INTAKE_RECEIPT_MISSING") from None
            if (
                intake.receipt_id != receipt.intake_receipt_id
                or intake.admission_status is not AdmissionStatus.INTAKE_PENDING
                or intake.intake_receipt_id is not None
                or intake.request_fingerprint_sha256 != receipt.request_fingerprint_sha256
                or intake.payload_sha256 != receipt.payload_sha256
                or intake.payload_byte_length != receipt.payload_byte_length
                or intake.http_status != receipt.http_status
                or intake.robin_first_observed_at != receipt.robin_first_observed_at
                or intake.robin_ingested_at != receipt.robin_ingested_at
                or intake.raw_expires_at != receipt.raw_expires_at
                or intake.raw_storage_key != receipt.raw_storage_key
            ):
                raise CaptureStorageError("CAPTURE_INTAKE_RECEIPT_LINK_MISMATCH")
        return receipt

    def load_manifest(self, snapshot_id: str) -> CaptureManifest:
        path = self._path(f"manifests/{snapshot_id}.json")
        manifest = CaptureManifest.model_validate_json(
            _safe_read_bounded(path, maximum_bytes=_MAX_CONTRACT_BYTES)
        )
        if manifest.snapshot_id != snapshot_id:
            raise CaptureStorageError("CAPTURE_MANIFEST_PATH_IDENTITY_MISMATCH")
        receipt = self.load_receipt(manifest.receipt_id)
        if (
            receipt.request_fingerprint_sha256 != manifest.request_fingerprint_sha256
            or receipt.payload_sha256 != manifest.raw_payload_sha256
            or receipt.schema_fingerprint_sha256 != manifest.schema_fingerprint.schema_sha256
            or manifest.captured_at != receipt.robin_ingested_at
        ):
            raise CaptureStorageError("CAPTURE_MANIFEST_RECEIPT_LINK_MISMATCH")
        normalized = _safe_read_bounded(
            self._path(manifest.normalized_storage_key),
            maximum_bytes=_MAX_NORMALIZED_BYTES,
        )
        if hashlib.sha256(normalized).hexdigest() != manifest.normalized_sha256:
            raise CaptureStorageError("CAPTURE_NORMALIZED_HASH_MISMATCH")
        try:
            observations = tuple(
                NormalizedMarketObservation.model_validate_json(line)
                for line in normalized.splitlines()
                if line
            )
        except (ValueError, TypeError):
            raise CaptureStorageError("CAPTURE_NORMALIZED_RECORD_INVALID") from None
        if len(observations) != manifest.observation_count:
            raise CaptureStorageError("CAPTURE_OBSERVATION_COUNT_MISMATCH")
        if any(
            observation.snapshot_id != manifest.snapshot_id
            or observation.receipt_id != receipt.receipt_id
            or observation.payload_sha256 != receipt.payload_sha256
            for observation in observations
        ):
            raise CaptureStorageError("CAPTURE_NORMALIZED_PROVENANCE_LINK_MISMATCH")
        return manifest

    def store_fixture_target_set(self, target_set: object) -> None:
        from robin.capture.bootstrap_contracts import FixtureTargetSetV1

        validated = FixtureTargetSetV1.model_validate(cast(Any, target_set).model_dump(mode="json"))
        self._write_immutable(
            f"live/fixture-target-sets/{validated.canonical_set_hash}.json",
            canonical_json_bytes(validated.model_dump(mode="json")) + b"\n",
        )

    def load_fixture_target_set(self, target_set_sha256: str) -> object:
        from robin.capture.bootstrap_contracts import FixtureTargetSetV1

        try:
            payload = _safe_read_bounded(
                self._path(f"live/fixture-target-sets/{target_set_sha256}.json"),
                maximum_bytes=_MAX_CONTRACT_BYTES,
            )
            target_set = FixtureTargetSetV1.model_validate_json(payload)
        except (OSError, ValueError):
            raise CaptureStorageError("FIXTURE_TARGET_SET_INVALID_OR_MISSING") from None
        if (
            payload != canonical_json_bytes(target_set.model_dump(mode="json")) + b"\n"
            or target_set.canonical_set_hash != target_set_sha256
        ):
            raise CaptureStorageError("FIXTURE_TARGET_SET_HASH_MISMATCH")
        return target_set

    def store_provider_network_binding(self, binding: object) -> None:
        from robin.capture.bootstrap_contracts import ProviderNetworkBindingV1

        validated = ProviderNetworkBindingV1.model_validate(
            cast(Any, binding).model_dump(mode="json")
        )
        self._write_immutable(
            f"live/provider-network-bindings/{validated.canonical_binding_hash}.json",
            canonical_json_bytes(validated.model_dump(mode="json")) + b"\n",
        )

    def load_provider_network_binding(self, binding_sha256: str) -> object:
        from robin.capture.bootstrap_contracts import ProviderNetworkBindingV1

        try:
            payload = _safe_read_bounded(
                self._path(f"live/provider-network-bindings/{binding_sha256}.json"),
                maximum_bytes=_MAX_CONTRACT_BYTES,
            )
            binding = ProviderNetworkBindingV1.model_validate_json(payload)
        except (OSError, ValueError):
            raise CaptureStorageError("PROVIDER_NETWORK_BINDING_INVALID_OR_MISSING") from None
        if (
            payload != canonical_json_bytes(binding.model_dump(mode="json")) + b"\n"
            or binding.canonical_binding_hash != binding_sha256
        ):
            raise CaptureStorageError("PROVIDER_NETWORK_BINDING_HASH_MISMATCH")
        return binding

    def store_post_capture_fixture_mapping(self, mapping: object) -> None:
        from robin.capture.fixture_mapping import (
            PostCaptureFixtureMappingV1,
            derive_post_capture_fixture_mappings_v1,
        )

        validated = PostCaptureFixtureMappingV1.model_validate(
            cast(Any, mapping).model_dump(mode="json")
        )
        target_set = self.load_fixture_target_set(validated.fixture_target_set_sha256)
        receipt = self.load_receipt(validated.intake_receipt_id)
        raw = self.load_raw(receipt)
        if (
            receipt.payload_sha256 != validated.raw_payload_sha256
            or receipt.raw_storage_key != validated.raw_storage_key
            or hashlib.sha256(raw).hexdigest() != validated.raw_payload_sha256
            or receipt.admission_status is not AdmissionStatus.INTAKE_PENDING
        ):
            raise CaptureStorageError("POST_CAPTURE_MAPPING_RAW_LINEAGE_MISMATCH")
        try:
            derived = derive_post_capture_fixture_mappings_v1(
                raw,
                target_set=cast(Any, target_set),
                intake_receipt=receipt,
                raw_storage_key=validated.raw_storage_key,
            )
        except (CaptureContractError, ValueError):
            raise CaptureStorageError("POST_CAPTURE_MAPPING_SEMANTIC_REDERIVATION_FAILED") from None
        if derived != validated:
            raise CaptureStorageError("POST_CAPTURE_MAPPING_SEMANTIC_MISMATCH")
        self._write_immutable(
            f"live/post-capture-mappings/{validated.canonical_mapping_hash}.json",
            canonical_json_bytes(validated.model_dump(mode="json")) + b"\n",
        )

    def load_post_capture_fixture_mapping(self, mapping_sha256: str) -> object:
        from robin.capture.fixture_mapping import (
            PostCaptureFixtureMappingV1,
            derive_post_capture_fixture_mappings_v1,
        )

        try:
            payload = _safe_read_bounded(
                self._path(f"live/post-capture-mappings/{mapping_sha256}.json"),
                maximum_bytes=_MAX_CONTRACT_BYTES,
            )
            mapping = PostCaptureFixtureMappingV1.model_validate_json(payload)
        except (OSError, ValueError):
            raise CaptureStorageError("POST_CAPTURE_MAPPING_INVALID_OR_MISSING") from None
        if (
            payload != canonical_json_bytes(mapping.model_dump(mode="json")) + b"\n"
            or mapping.canonical_mapping_hash != mapping_sha256
        ):
            raise CaptureStorageError("POST_CAPTURE_MAPPING_HASH_MISMATCH")
        target_set = self.load_fixture_target_set(mapping.fixture_target_set_sha256)
        receipt = self.load_receipt(mapping.intake_receipt_id)
        raw = self.load_raw(receipt)
        if (
            cast(Any, target_set).canonical_set_hash != mapping.fixture_target_set_sha256
            or receipt.payload_sha256 != mapping.raw_payload_sha256
            or receipt.raw_storage_key != mapping.raw_storage_key
            or hashlib.sha256(raw).hexdigest() != mapping.raw_payload_sha256
            or receipt.admission_status is not AdmissionStatus.INTAKE_PENDING
        ):
            raise CaptureStorageError("POST_CAPTURE_MAPPING_LINEAGE_MISMATCH")
        try:
            derived = derive_post_capture_fixture_mappings_v1(
                raw,
                target_set=cast(Any, target_set),
                intake_receipt=receipt,
                raw_storage_key=mapping.raw_storage_key,
            )
        except (CaptureContractError, ValueError):
            raise CaptureStorageError("POST_CAPTURE_MAPPING_SEMANTIC_REDERIVATION_FAILED") from None
        if derived != mapping:
            raise CaptureStorageError("POST_CAPTURE_MAPPING_SEMANTIC_MISMATCH")
        return mapping

    @staticmethod
    def _assert_v2_lineage_mapping_summary(lineage: object, mapping: object) -> None:
        mapped_targets = len(cast(Any, mapping).mapped_target_ids)
        non_admitted_targets = len(cast(Any, mapping).unmatched_target_ids)
        expected_admission = (
            "NONE" if mapped_targets == 0 else "FULL" if non_admitted_targets == 0 else "PARTIAL"
        )
        if (
            cast(Any, lineage).mapped_target_count != mapped_targets
            or cast(Any, lineage).non_admitted_target_count != non_admitted_targets
            or cast(Any, lineage).mapped_provider_event_count
            != cast(Any, mapping).mapped_provider_event_count
            or cast(Any, lineage).non_admitted_provider_event_count
            != cast(Any, mapping).non_admitted_provider_event_count
            or cast(Any, lineage).scientific_admission != expected_admission
        ):
            raise CaptureStorageError("LIVE_V2_MAPPING_SUMMARY_MISMATCH")

    def store_live_capture_lineage(self, lineage: object) -> None:
        from robin.capture.bootstrap_contracts import LiveCaptureLineageV2
        from robin.capture.live_contracts import LiveCaptureLineageV1
        from robin.capture.live_storage import LiveStateStore

        material = cast(Any, lineage).model_dump(mode="json")
        validated: LiveCaptureLineageV1 | LiveCaptureLineageV2
        if material.get("schema_version") == "robin-live-capture-lineage-v2":
            validated = LiveCaptureLineageV2.model_validate(material)
            mapping = self.load_post_capture_fixture_mapping(validated.post_capture_mapping_sha256)
            if cast(Any, mapping).fixture_target_set_sha256 != validated.fixture_target_set_sha256:
                raise CaptureStorageError("LIVE_V2_MAPPING_LINEAGE_MISMATCH")
            self._assert_v2_lineage_mapping_summary(validated, mapping)
        else:
            validated = LiveCaptureLineageV1.model_validate(material)
        if (
            LiveStateStore(self).load_response_intake_claim(validated.admission_permit.item_hash)
            != validated.response_intake_claim
        ):
            raise CaptureStorageError("LIVE_RESPONSE_INTAKE_CLAIM_MISMATCH")
        self._write_immutable(
            f"live/capture-lineage/{validated.manifest_id}.json",
            canonical_json_bytes(validated.model_dump(mode="json")) + b"\n",
        )

    def _load_live_capture_lineage(self, manifest: CaptureManifest) -> object:
        from robin.capture.bootstrap_contracts import LiveCaptureLineageV2
        from robin.capture.live_contracts import LiveCaptureLineageV1

        try:
            lineage_bytes = _safe_read_bounded(
                self._path(f"live/capture-lineage/{manifest.snapshot_id}.json"),
                maximum_bytes=_MAX_CONTRACT_BYTES,
            )
            lineage_material = strict_json_object(lineage_bytes)
            lineage: LiveCaptureLineageV1 | LiveCaptureLineageV2
            if lineage_material.get("schema_version") == "robin-live-capture-lineage-v2":
                lineage = LiveCaptureLineageV2.model_validate(lineage_material)
            else:
                lineage = LiveCaptureLineageV1.model_validate(lineage_material)
        except (OSError, ValueError):
            raise CaptureStorageError("LIVE_CAPTURE_LINEAGE_INVALID_OR_MISSING") from None
        if (
            lineage_bytes != canonical_json_bytes(lineage.model_dump(mode="json")) + b"\n"
            or lineage.manifest_id != manifest.snapshot_id
            or lineage.manifest_hash != manifest.manifest_sha256
            or lineage.request_fingerprint_sha256 != manifest.request_fingerprint_sha256
            or lineage.admission_permit.capture_root_fingerprint != self.capture_root_fingerprint()
        ):
            raise CaptureStorageError("LIVE_CAPTURE_LINEAGE_MISMATCH")
        from robin.capture.live_storage import LiveStateStore

        live_state = LiveStateStore(self)
        live_state.verify_admission_permit(
            lineage.admission_permit,
            consume=False,
        )
        claim = live_state.load_response_intake_claim(lineage.admission_permit.item_hash)
        receipt = self.load_receipt(manifest.receipt_id)
        if (
            claim != lineage.response_intake_claim
            or claim.payload_sha256 != manifest.raw_payload_sha256
            or claim.payload_byte_length != receipt.payload_byte_length
            or claim.first_observed_at_utc != receipt.robin_first_observed_at
            or claim.ingested_at_utc != receipt.robin_ingested_at
        ):
            raise CaptureStorageError("LIVE_RESPONSE_INTAKE_CLAIM_MISMATCH")
        if isinstance(lineage, LiveCaptureLineageV2):
            mapping = self.load_post_capture_fixture_mapping(lineage.post_capture_mapping_sha256)
            if cast(Any, mapping).fixture_target_set_sha256 != lineage.fixture_target_set_sha256:
                raise CaptureStorageError("LIVE_V2_MAPPING_LINEAGE_MISMATCH")
            self._assert_v2_lineage_mapping_summary(lineage, mapping)
        return lineage

    def _verify_live_execution_lineage(
        self,
        manifest: CaptureManifest,
        lineage: object,
        *,
        allow_preterminal: bool,
    ) -> None:
        from robin.capture.live_contracts import (
            LiveCaptureLineageV1,
            LiveExecutionAttemptReceiptV1,
            LiveExecutionReceiptV1,
        )

        validated_lineage = cast(LiveCaptureLineageV1, lineage)
        try:
            attempt_alias_bytes = _safe_read_bounded(
                self._path(f"live/execution-attempts/by-manifest/{manifest.snapshot_id}.json"),
                maximum_bytes=_MAX_CONTRACT_BYTES,
            )
            attempt = LiveExecutionAttemptReceiptV1.model_validate_json(attempt_alias_bytes)
            if (
                attempt_alias_bytes != canonical_json_bytes(attempt.model_dump(mode="json")) + b"\n"
                or _safe_read_bounded(
                    self._path(f"live/execution-attempts/{attempt.execution_attempt_id}.json"),
                    maximum_bytes=_MAX_CONTRACT_BYTES,
                )
                != attempt_alias_bytes
            ):
                raise CaptureStorageError("LIVE_EXECUTION_ATTEMPT_COPIES_MISMATCH")
        except (OSError, ValueError):
            raise CaptureStorageError("LIVE_EXECUTION_ATTEMPT_INVALID_OR_MISSING") from None
        permit = validated_lineage.admission_permit
        from robin.capture.live_storage import LiveStateStore, LiveStorageError

        live_state = LiveStateStore(self)
        dispatch_started = live_state.load_dispatch_started(permit.item_hash)
        if (
            dispatch_started is None
            or dispatch_started.admission_permit != permit
            or dispatch_started.dispatch_started_at_utc != attempt.dispatch_started_at_utc
        ):
            raise CaptureStorageError("LIVE_DISPATCH_STARTED_LINEAGE_MISMATCH")
        capture_receipt = self.load_receipt(manifest.receipt_id)
        if (
            attempt.manifest_id != manifest.snapshot_id
            or attempt.manifest_hash != manifest.manifest_sha256
            or attempt.capture_receipt_id != manifest.receipt_id
            or attempt.request_fingerprint_sha256 != manifest.request_fingerprint_sha256
            or attempt.response_intake_claim_sha256
            != validated_lineage.response_intake_claim.canonical_intake_claim_sha256
            or attempt.payload_sha256 != manifest.raw_payload_sha256
            or attempt.authorization_hash != permit.authorization_hash
            or attempt.activation_hash != permit.activation_hash
            or attempt.plan_hash != permit.plan_hash
            or attempt.item_hash != permit.item_hash
            or attempt.lease_id != permit.lease_id
            or attempt.http_status != capture_receipt.http_status
            or attempt.first_observed_at_utc != capture_receipt.robin_first_observed_at
            or attempt.ingested_at_utc != capture_receipt.robin_ingested_at
            or attempt.payload_byte_length != capture_receipt.payload_byte_length
            or attempt.payload_sha256 != capture_receipt.payload_sha256
            or attempt.request_fingerprint_sha256 != capture_receipt.request_fingerprint_sha256
        ):
            raise CaptureStorageError("LIVE_EXECUTION_ATTEMPT_LINEAGE_MISMATCH")

        terminal_path = self._path(
            f"live/execution-receipts/by-manifest/{manifest.snapshot_id}.json"
        )
        try:
            terminal_bytes = _safe_read_bounded(
                terminal_path,
                maximum_bytes=_MAX_CONTRACT_BYTES,
            )
        except FileNotFoundError:
            if allow_preterminal:
                return
            raise CaptureStorageError("LIVE_EXECUTION_RECEIPT_INVALID_OR_MISSING") from None
        try:
            terminal = LiveExecutionReceiptV1.model_validate_json(terminal_bytes)
            if (
                terminal_bytes != canonical_json_bytes(terminal.model_dump(mode="json")) + b"\n"
                or _safe_read_bounded(
                    self._path(f"live/execution-receipts/{terminal.execution_receipt_id}.json"),
                    maximum_bytes=_MAX_CONTRACT_BYTES,
                )
                != terminal_bytes
            ):
                raise CaptureStorageError("LIVE_EXECUTION_RECEIPT_COPIES_MISMATCH")
        except (OSError, ValueError):
            raise CaptureStorageError("LIVE_EXECUTION_RECEIPT_INVALID") from None
        if (
            terminal.execution_attempt_id != attempt.execution_attempt_id
            or terminal.authorization_id != permit.authorization_id
            or terminal.authorization_hash != permit.authorization_hash
            or terminal.activation_id != permit.activation_id
            or terminal.activation_hash != permit.activation_hash
            or terminal.repository_sha != permit.repository_sha
            or terminal.plan_id != permit.plan_id
            or terminal.plan_hash != permit.plan_hash
            or terminal.item_id != permit.item_id
            or terminal.item_hash != permit.item_hash
            or terminal.lease_id != permit.lease_id
            or terminal.lease_hash != permit.lease_id
            or terminal.manifest_id != manifest.snapshot_id
            or terminal.manifest_hash != manifest.manifest_sha256
            or terminal.final_receipt_id != manifest.receipt_id
            or terminal.request_fingerprint_sha256 != manifest.request_fingerprint_sha256
            or terminal.response_intake_claim_sha256 != attempt.response_intake_claim_sha256
            or terminal.payload_sha256 != manifest.raw_payload_sha256
            or terminal.dispatch_started_at_utc != attempt.dispatch_started_at_utc
            or terminal.first_observed_at_utc != attempt.first_observed_at_utc
            or terminal.ingested_at_utc != attempt.ingested_at_utc
            or terminal.http_status != attempt.http_status
            or terminal.payload_byte_length != attempt.payload_byte_length
            or terminal.final_receipt_id != attempt.capture_receipt_id
            or terminal.intake_receipt_id != capture_receipt.intake_receipt_id
            or terminal.observed_quota != capture_receipt.quota
            or terminal.reserved_requests != 1
            or terminal.reserved_credits != permit.reserved_credits
            or terminal.offline_replay_verdict != "ROBIN_OFFLINE_CAPTURE_REPLAY_PROVEN"
            or terminal.terminal_disposition.value not in {"SUCCESS", "QUOTA_RECONCILIATION_FAILED"}
        ):
            raise CaptureStorageError("LIVE_EXECUTION_RECEIPT_LINEAGE_MISMATCH")
        try:
            live_state.verify_terminal_budget_state(terminal)
        except LiveStorageError:
            raise CaptureStorageError("LIVE_EXECUTION_RECEIPT_BUDGET_LINEAGE_MISMATCH") from None
        try:
            marker_bytes = _safe_read_bounded(
                self._path(f"live/terminal/{permit.item_hash}.json"),
                maximum_bytes=_MAX_CONTRACT_BYTES,
            )
            marker = strict_json_object(marker_bytes)
        except FileNotFoundError:
            if allow_preterminal:
                return
            raise CaptureStorageError("LIVE_TERMINAL_MARKER_INVALID_OR_MISSING") from None
        except (OSError, ValueError):
            raise CaptureStorageError("LIVE_TERMINAL_MARKER_INVALID_OR_MISSING") from None
        if marker_bytes != canonical_json_bytes(marker) + b"\n" or marker != {
            "schema_version": "robin-live-item-terminal-v1",
            "execution_receipt_id": terminal.execution_receipt_id,
            "item_hash": permit.item_hash,
            "terminal_at_utc": terminal.terminal_at_utc.isoformat().replace("+00:00", "Z"),
            "terminal_disposition": terminal.terminal_disposition.value,
            "retry_authorized": False,
        }:
            raise CaptureStorageError("LIVE_TERMINAL_MARKER_LINEAGE_MISMATCH")

    def load_raw(self, receipt: RawPayloadReceipt) -> bytes:
        if receipt.raw_storage_key is None:
            raise CaptureStorageError("CAPTURE_RAW_PAYLOAD_NOT_RETAINED")
        try:
            payload = _safe_read_bounded(
                self._path(receipt.raw_storage_key),
                maximum_bytes=_MAX_RAW_PAYLOAD_BYTES,
            )
        except FileNotFoundError:
            raise CaptureStorageError("CAPTURE_RAW_PAYLOAD_NOT_RETAINED") from None
        if (
            len(payload) != receipt.payload_byte_length
            or hashlib.sha256(payload).hexdigest() != receipt.payload_sha256
        ):
            raise CaptureStorageError("CAPTURE_RAW_HASH_MISMATCH")
        return payload

    def replay(self, snapshot_id: str) -> OfflineReplayResult:
        return self._replay(snapshot_id, allow_preterminal_live=False)

    def _replay_preterminal_live(self, snapshot_id: str) -> OfflineReplayResult:
        """Internal replay used while the enclosing live receipt is not terminal yet."""

        return self._replay(snapshot_id, allow_preterminal_live=True)

    def _replay(
        self,
        snapshot_id: str,
        *,
        allow_preterminal_live: bool,
    ) -> OfflineReplayResult:
        manifest = self.load_manifest(snapshot_id)
        live_lineage = (
            self._load_live_capture_lineage(manifest) if manifest.mode == "LIVE_CANARY" else None
        )
        receipt = self.load_receipt(manifest.receipt_id)
        raw = self.load_raw(receipt)
        # load_raw verifies the raw SHA-256 before JSON decoding or normalization.
        from robin.capture.bootstrap_contracts import LiveCaptureLineageV2
        from robin.capture.normalization import decode_json_payload, normalize_payload_v2

        decoded = decode_json_payload(raw)
        replayed_v2_snapshot_id: str | None = None
        if isinstance(live_lineage, LiveCaptureLineageV2):
            mapping_evidence = self.load_post_capture_fixture_mapping(
                live_lineage.post_capture_mapping_sha256
            )
            schema, observations, replayed_v2_snapshot_id = normalize_payload_v2(
                decoded,
                receipt=receipt,
                mapping_evidence=mapping_evidence,
                allowed_markets=live_lineage.expected_markets,
                expected_sport_key=live_lineage.expected_sport_key,
            )
            if (
                cast(Any, mapping_evidence).mappings != manifest.fixture_mappings
                or cast(Any, mapping_evidence).fixture_target_set_sha256
                != live_lineage.fixture_target_set_sha256
            ):
                raise CaptureStorageError("POST_CAPTURE_MAPPING_MANIFEST_MISMATCH")
        else:
            schema, observations = normalize_payload(
                decoded,
                receipt=receipt,
                mappings=manifest.fixture_mappings,
                allowed_markets=(
                    cast(Any, live_lineage).expected_markets if live_lineage is not None else None
                ),
                expected_sport_key=(
                    cast(Any, live_lineage).expected_sport_key if live_lineage is not None else None
                ),
            )
        replayed = normalized_jsonl_bytes(observations)
        expected = _safe_read_bounded(
            self._path(manifest.normalized_storage_key),
            maximum_bytes=_MAX_NORMALIZED_BYTES,
        )
        replayed_sha256 = hashlib.sha256(replayed).hexdigest()
        byte_identical = replayed == expected
        replayed_snapshot_id = (
            observations[0].snapshot_id
            if observations
            else replayed_v2_snapshot_id
            if replayed_v2_snapshot_id is not None
            else snapshot_id_for_observation_rows(
                receipt_id=receipt.receipt_id,
                schema_fingerprint_sha256=schema.schema_sha256,
                mappings=manifest.fixture_mappings,
                observations=(),
            )
        )
        deterministic = (
            byte_identical
            and replayed_snapshot_id == manifest.snapshot_id
            and replayed_sha256 == manifest.normalized_sha256
            and schema.schema_sha256 == manifest.schema_fingerprint.schema_sha256
            and len(observations) == manifest.observation_count
            and receipt.request_fingerprint_sha256 == manifest.request_fingerprint_sha256
            and receipt.payload_sha256 == manifest.raw_payload_sha256
        )
        if not deterministic:
            raise CaptureStorageError("CAPTURE_REPLAY_NOT_DETERMINISTIC")
        if live_lineage is not None:
            self._verify_live_execution_lineage(
                manifest,
                live_lineage,
                allow_preterminal=allow_preterminal_live,
            )
        return OfflineReplayResult(
            snapshot_id=manifest.snapshot_id,
            receipt_id=receipt.receipt_id,
            raw_payload_sha256=receipt.payload_sha256,
            normalized_sha256=replayed_sha256,
            observation_count=len(observations),
            byte_identical=True,
            deterministic=True,
        )

    def _append_deletion_record(self, record: dict[str, object]) -> None:
        record_id = canonical_sha256(record)
        with self._deletion_ledger_lock, _exclusive_file_lock(self._deletion_ledger_lock_path):
            previous_entry_sha256: str | None = None
            with _safe_regular_file(
                self.deletion_ledger,
                flags=os.O_RDWR | os.O_CREAT,
                mode="r+b",
            ) as stream:
                if os.fstat(stream.fileno()).st_size > _MAX_LEDGER_BYTES:
                    raise CaptureStorageError("CAPTURE_STORAGE_FILE_TOO_LARGE")
                payload = cast(bytes, stream.read(_MAX_LEDGER_BYTES + 1))
                if len(payload) > _MAX_LEDGER_BYTES:
                    raise CaptureStorageError("CAPTURE_STORAGE_FILE_TOO_LARGE")
                complete = payload
                truncated_tail = b""
                if payload and not payload.endswith(b"\n"):
                    boundary = payload.rfind(b"\n")
                    complete = payload[: boundary + 1] if boundary >= 0 else b""
                    truncated_tail = payload[boundary + 1 :]
                existing_record = False
                for existing in complete.splitlines():
                    parsed = strict_json_object(existing)
                    entry_sha256 = parsed.get("entry_sha256")
                    if not isinstance(entry_sha256, str):
                        raise CaptureStorageError("CAPTURE_DELETION_LEDGER_INVALID")
                    identity = {
                        key: value for key, value in parsed.items() if key != "entry_sha256"
                    }
                    if canonical_sha256(identity) != entry_sha256:
                        raise CaptureStorageError("CAPTURE_DELETION_LEDGER_HASH_MISMATCH")
                    if parsed.get("previous_entry_sha256") != previous_entry_sha256:
                        raise CaptureStorageError("CAPTURE_DELETION_LEDGER_CHAIN_MISMATCH")
                    if parsed.get("record_id") == record_id:
                        if any(parsed.get(key) != value for key, value in record.items()):
                            raise CaptureStorageError("CAPTURE_DELETION_LEDGER_COLLISION")
                        existing_record = True
                    previous_entry_sha256 = entry_sha256

                def append_one(candidate: dict[str, object]) -> None:
                    nonlocal previous_entry_sha256
                    identity = {
                        "record_id": canonical_sha256(candidate),
                        "previous_entry_sha256": previous_entry_sha256,
                        **candidate,
                    }
                    material = {
                        "entry_sha256": canonical_sha256(identity),
                        **identity,
                    }
                    stream.write(canonical_json_bytes(material) + b"\n")
                    previous_entry_sha256 = cast(str, material["entry_sha256"])

                stream.seek(len(complete))
                if truncated_tail:
                    stream.truncate()
                    append_one(
                        {
                            "action": "DELETION_LEDGER_TAIL_RECOVERED",
                            "truncated_tail_byte_length": len(truncated_tail),
                            "truncated_tail_sha256": hashlib.sha256(truncated_tail).hexdigest(),
                        }
                    )
                if not existing_record:
                    append_one(record)
                stream.flush()
                os.fsync(stream.fileno())
            _fsync_directory(self.deletion_ledger.parent)

    def enforce_raw_ttl(self, *, now: datetime) -> tuple[str, ...]:
        with _exclusive_file_lock(self._ttl_lock_path):
            return self._enforce_raw_ttl(now=now)

    def _enforce_raw_ttl(self, *, now: datetime) -> tuple[str, ...]:
        checked_at = ensure_utc(now, field="ttl_checked_at")
        receipts_root = self._directory("receipts")
        receipts: list[RawPayloadReceipt] = []
        for path in sorted(receipts_root.glob("*.json")):
            payload = _safe_read_bounded(
                path,
                maximum_bytes=_MAX_CONTRACT_BYTES,
            )
            try:
                receipts.append(RawPayloadReceipt.model_validate_json(payload))
            except (CaptureContractError, ValueError):
                # An O_EXCL tombstone interrupted before fsync is retained but
                # cannot poison valid receipt enumeration or authorize raw use.
                if payload.endswith(b"\n"):
                    self._append_deletion_record(
                        {
                            "action": "RECEIPT_CORRUPTION_DETECTED",
                            "checked_at": checked_at.isoformat().replace("+00:00", "Z"),
                            "receipt_filename": path.name,
                            "observed_sha256": hashlib.sha256(payload).hexdigest(),
                        }
                    )
                continue
        active_hashes = {
            receipt.payload_sha256
            for receipt in receipts
            if receipt.raw_storage_key is not None and receipt.raw_expires_at > checked_at
        }
        deleted: list[str] = []
        for receipt in receipts:
            if (
                receipt.raw_storage_key is None
                or receipt.raw_expires_at > checked_at
                or receipt.payload_sha256 in active_hashes
            ):
                continue
            raw_path = self._path(receipt.raw_storage_key)
            if not _path_exists_no_follow(raw_path):
                self._append_deletion_record(
                    {
                        "action": "RAW_TTL_ABSENCE_CONFIRMED",
                        "checked_at": checked_at.isoformat().replace("+00:00", "Z"),
                        "payload_sha256": receipt.payload_sha256,
                        "raw_storage_key": receipt.raw_storage_key,
                        "retained_receipt_id": receipt.receipt_id,
                    }
                )
                continue
            before_delete = raw_path.lstat()
            try:
                observed_sha256, observed_length = _safe_sha256_file(
                    raw_path,
                    maximum_bytes=_MAX_RAW_PAYLOAD_BYTES,
                )
            except CaptureStorageError as error:
                if error.code != "CAPTURE_STORAGE_FILE_TOO_LARGE":
                    raise
                observed_sha256 = None
                observed_length = before_delete.st_size
            raw_matches_receipt = (
                observed_sha256 == receipt.payload_sha256
                and observed_length == receipt.payload_byte_length
            )
            action_prefix = (
                "RAW_TTL_DELETION" if raw_matches_receipt else "RAW_TTL_CORRUPT_TOMBSTONE_DELETION"
            )
            self._append_deletion_record(
                {
                    "action": f"{action_prefix}_INTENT",
                    "planned_at": checked_at.isoformat().replace("+00:00", "Z"),
                    "payload_sha256": receipt.payload_sha256,
                    "raw_storage_key": receipt.raw_storage_key,
                    "retained_receipt_id": receipt.receipt_id,
                }
            )
            immediately_before_delete = raw_path.lstat()
            if (
                before_delete.st_dev != immediately_before_delete.st_dev
                or before_delete.st_ino != immediately_before_delete.st_ino
                or immediately_before_delete.st_nlink != 1
                or not stat.S_ISREG(immediately_before_delete.st_mode)
            ):
                raise CaptureStorageError("CAPTURE_RAW_DELETE_IDENTITY_CHANGED")
            raw_path.unlink()
            _fsync_directory(raw_path.parent)
            self._append_deletion_record(
                {
                    "action": f"{action_prefix}_COMMITTED",
                    "deleted_at": checked_at.isoformat().replace("+00:00", "Z"),
                    "payload_sha256": receipt.payload_sha256,
                    "raw_storage_key": receipt.raw_storage_key,
                    "retained_receipt_id": receipt.receipt_id,
                }
            )
            deleted.append(receipt.payload_sha256)
        referenced_hashes = {
            receipt.payload_sha256 for receipt in receipts if receipt.raw_storage_key is not None
        }
        raw_root = self._directory("raw/sha256")
        try:
            prefix_directories = sorted(raw_root.iterdir())
        except OSError:
            raise CaptureStorageError("CAPTURE_RAW_ENUMERATION_FAILED") from None
        for prefix_directory in prefix_directories:
            _reject_reparse_path(prefix_directory)
            metadata = prefix_directory.lstat()
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or len(prefix_directory.name) != 2
                or any(value not in "0123456789abcdef" for value in prefix_directory.name)
            ):
                raise CaptureStorageError("CAPTURE_RAW_LAYOUT_INVALID")
            for raw_path in sorted(prefix_directory.iterdir()):
                _reject_reparse_path(raw_path)
                raw_metadata = raw_path.lstat()
                payload_sha256 = raw_path.stem
                if (
                    raw_path.suffix != ".bin"
                    or len(payload_sha256) != 64
                    or payload_sha256[:2] != prefix_directory.name
                    or any(value not in "0123456789abcdef" for value in payload_sha256)
                    or not stat.S_ISREG(raw_metadata.st_mode)
                    or raw_metadata.st_nlink != 1
                ):
                    raise CaptureStorageError("CAPTURE_RAW_LAYOUT_INVALID")
                if payload_sha256 in referenced_hashes:
                    continue
                self._append_deletion_record(
                    {
                        "action": "RAW_ORPHAN_DELETION_INTENT",
                        "planned_at": checked_at.isoformat().replace("+00:00", "Z"),
                        "payload_sha256": payload_sha256,
                        "raw_storage_key": (f"raw/sha256/{prefix_directory.name}/{raw_path.name}"),
                    }
                )
                immediately_before_delete = raw_path.lstat()
                if (
                    immediately_before_delete.st_dev != raw_metadata.st_dev
                    or immediately_before_delete.st_ino != raw_metadata.st_ino
                    or immediately_before_delete.st_nlink != 1
                    or not stat.S_ISREG(immediately_before_delete.st_mode)
                ):
                    raise CaptureStorageError("CAPTURE_RAW_DELETE_IDENTITY_CHANGED")
                raw_path.unlink()
                _fsync_directory(raw_path.parent)
                self._append_deletion_record(
                    {
                        "action": "RAW_ORPHAN_DELETION_COMMITTED",
                        "deleted_at": checked_at.isoformat().replace("+00:00", "Z"),
                        "payload_sha256": payload_sha256,
                        "raw_storage_key": (f"raw/sha256/{prefix_directory.name}/{raw_path.name}"),
                    }
                )
                deleted.append(payload_sha256)
        return tuple(sorted(set(deleted)))
