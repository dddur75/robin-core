#!/usr/bin/env python3
"""Admit only provenance-preserving documentary advances between exact Git commits."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any

_SHA1 = re.compile(r"[0-9a-f]{40}")
_ALLOWED_PREFIXES = ("docs/", "reports/", "tests/")
_PROTECTED_PATHS = frozenset(
    {
        "docs/data-sourcing/ROBIN-AUTONOMOUS-LAB-2026-10-04.md",
        "docs/data-sourcing/ROBIN-AUTONOMOUS-LAB-SCHEDULE-RELIABILITY-2026-10-04.md",
        "docs/data-sourcing/ROBIN-AUTONOMOUS-LAB-ESTABLISHED-SCHEDULER-2026-10-04.md",
        "docs/data-sourcing/ROBIN-AUTONOMOUS-LAB-TRIGGER-RECOVERY-V2-2026-10-05.md",
        "reports/evidence/robin-real-data-result-run-37153158456-public-receipt.json",
    }
)
_REGULAR_BLOB_MODES = frozenset({"100644", "100755"})
_MAX_CHANGED_PATHS = 1_000
_GIT_TIMEOUT_SECONDS = 30


class _InspectionError(RuntimeError):
    pass


def _git(
    repository: Path,
    *arguments: str,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    try:
        completed = subprocess.run(
            ["git", "--no-replace-objects", *arguments],
            cwd=repository,
            check=False,
            capture_output=True,
            timeout=_GIT_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise _InspectionError("git invocation failed") from error
    if check and completed.returncode != 0:
        raise _InspectionError("git command rejected the requested comparison")
    return completed


def _exact_commit(repository: Path, revision: str) -> str:
    if _SHA1.fullmatch(revision) is None:
        raise _InspectionError("revision is not an exact lowercase SHA-1")
    resolved = _git(repository, "rev-parse", "--verify", f"{revision}^{{commit}}").stdout
    try:
        text = resolved.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise _InspectionError("commit identity is not ASCII") from error
    if text != revision:
        raise _InspectionError("commit identity did not resolve exactly")
    return text


def _changed_paths(repository: Path, base_sha: str, head_sha: str) -> list[str]:
    payload = _git(
        repository,
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--name-status",
        "--no-renames",
        "-z",
        base_sha,
        head_sha,
        "--",
    ).stdout
    fields = payload.split(b"\0")
    if fields and fields[-1] == b"":
        fields.pop()
    if len(fields) % 2 != 0:
        raise _InspectionError("Git returned an incomplete name-status record")
    paths: list[str] = []
    for offset in range(0, len(fields), 2):
        try:
            status = fields[offset].decode("ascii")
            path = fields[offset + 1].decode("utf-8")
        except UnicodeDecodeError as error:
            raise _InspectionError("Git returned a non-UTF-8 path record") from error
        if status not in {"A", "D", "M"}:
            raise _InspectionError("Git returned an unsupported change status")
        portable = PurePosixPath(path)
        if (
            not path
            or path.startswith("/")
            or "\\" in path
            or any(part in {"", ".", ".."} for part in portable.parts)
        ):
            raise _InspectionError("Git returned an unsafe path")
        paths.append(path)
    if len(paths) > _MAX_CHANGED_PATHS:
        raise _InspectionError("documentary comparison exceeded the path bound")
    return paths


def _tree_entry(repository: Path, revision: str, path: str) -> tuple[str, str] | None:
    payload = _git(repository, "ls-tree", "-z", revision, "--", path).stdout
    if not payload:
        return None
    records = payload.rstrip(b"\0").split(b"\0")
    if len(records) != 1:
        raise _InspectionError("Git returned an ambiguous tree entry")
    try:
        metadata, observed_path = records[0].split(b"\t", 1)
        mode, object_type, _object_id = metadata.decode("ascii").split(" ", 2)
        decoded_path = observed_path.decode("utf-8")
    except (UnicodeDecodeError, ValueError) as error:
        raise _InspectionError("Git returned an invalid tree entry") from error
    if decoded_path != path:
        raise _InspectionError("Git tree path did not match the requested path")
    return mode, object_type


def _is_documentary_path(path: str) -> bool:
    return path not in _PROTECTED_PATHS and path.startswith(_ALLOWED_PREFIXES)


def _regular_documentary_transition(
    repository: Path,
    base_sha: str,
    head_sha: str,
    path: str,
) -> bool:
    base_entry = _tree_entry(repository, base_sha, path)
    head_entry = _tree_entry(repository, head_sha, path)
    entries = [entry for entry in (base_entry, head_entry) if entry is not None]
    if not entries:
        return False
    if any(mode not in _REGULAR_BLOB_MODES or kind != "blob" for mode, kind in entries):
        return False
    return not (
        base_entry is not None and head_entry is not None and base_entry[0] != head_entry[0]
    )


def _decision(
    *,
    accepted: bool,
    reason: str,
    base_sha: str,
    head_sha: str,
    changed_paths: list[str] | None = None,
    rejected_paths: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": "robin-documentary-continuity-v1",
        "accepted": accepted,
        "reason": reason,
        "base_sha": base_sha,
        "head_sha": head_sha,
        "changed_paths": sorted(changed_paths or []),
        "rejected_paths": sorted(rejected_paths or []),
    }


def evaluate_repository(repository: Path | str, base_sha: str, head_sha: str) -> dict[str, Any]:
    """Return a fail-closed decision without changing the repository."""

    root = Path(repository).resolve()
    try:
        if not root.is_dir():
            raise _InspectionError("repository root is unavailable")
        shallow = _git(root, "rev-parse", "--is-shallow-repository").stdout
        if shallow.strip() != b"false":
            return _decision(
                accepted=False,
                reason="INCOMPLETE_HISTORY",
                base_sha=base_sha,
                head_sha=head_sha,
            )
        exact_base = _exact_commit(root, base_sha)
        exact_head = _exact_commit(root, head_sha)
        if exact_base == exact_head:
            return _decision(
                accepted=True,
                reason="IDENTICAL_SHA",
                base_sha=exact_base,
                head_sha=exact_head,
            )
        ancestry = _git(
            root,
            "merge-base",
            "--is-ancestor",
            exact_base,
            exact_head,
            check=False,
        )
        if ancestry.returncode == 1:
            return _decision(
                accepted=False,
                reason="HEAD_NOT_DESCENDANT",
                base_sha=exact_base,
                head_sha=exact_head,
            )
        if ancestry.returncode != 0:
            raise _InspectionError("Git could not establish commit ancestry")
        paths = _changed_paths(root, exact_base, exact_head)
        rejected = [path for path in paths if not _is_documentary_path(path)]
        if rejected:
            return _decision(
                accepted=False,
                reason="NON_DOCUMENTARY_PATH",
                base_sha=exact_base,
                head_sha=exact_head,
                changed_paths=paths,
                rejected_paths=rejected,
            )
        irregular = [
            path
            for path in paths
            if not _regular_documentary_transition(root, exact_base, exact_head, path)
        ]
        if irregular:
            return _decision(
                accepted=False,
                reason="NON_REGULAR_DOCUMENTARY_OBJECT",
                base_sha=exact_base,
                head_sha=exact_head,
                changed_paths=paths,
                rejected_paths=irregular,
            )
        return _decision(
            accepted=True,
            reason="DOCUMENTARY_DESCENDANT",
            base_sha=exact_base,
            head_sha=exact_head,
            changed_paths=paths,
        )
    except _InspectionError:
        return _decision(
            accepted=False,
            reason="GIT_INSPECTION_FAILED",
            base_sha=base_sha,
            head_sha=head_sha,
        )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate a provenance-preserving Robin documentary Git advance"
    )
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    decision = evaluate_repository(arguments.repository, arguments.base, arguments.head)
    print(json.dumps(decision, sort_keys=True, separators=(",", ":")))
    return 0 if decision["accepted"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
