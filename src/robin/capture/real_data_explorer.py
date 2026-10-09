"""Fail-closed localhost explorer for verified Robin real-data artifacts."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess  # nosec B404 - fixed argv-only invocation of the read-only GitHub CLI.
import threading
import urllib.parse
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

from robin.capture.real_data_dashboard import (
    build_explorer_snapshot,
    render_dashboard_csv,
    render_dashboard_html,
)

SOURCE_FILES = (
    "public-receipt.json",
    "robin-real-data.json",
    "robin-real-data.csv",
    "robin-real-data.html",
)
PUBLIC_FILES = (
    "robin-real-data.html",
    "robin-real-data.json",
    "robin-real-data.csv",
)
_HASH_FIELDS = {
    "robin-real-data.json": "normalized_json_sha256",
    "robin-real-data.csv": "csv_sha256",
    "robin-real-data.html": "html_sha256",
}
_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_MAX_EXPORT_BYTES = 32 * 1024 * 1024
LOCAL_RENDERER_REVISION = "v13"


class BundleValidationError(ValueError):
    """A stable, secret-free validation error."""


def _utc(value: object) -> datetime:
    if not isinstance(value, str):
        raise BundleValidationError("SOURCE_TIME_INVALID")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise BundleValidationError("SOURCE_TIME_INVALID") from None
    if parsed.tzinfo is None:
        raise BundleValidationError("SOURCE_TIME_INVALID")
    return parsed.astimezone(UTC)


def _iso_z(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _read_json(path: Path, code: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise BundleValidationError(code) from None
    if not isinstance(value, dict):
        raise BundleValidationError(code)
    return cast(dict[str, Any], value)


def _source_semantic_sha256(snapshot: Mapping[str, object]) -> str:
    """Bind immutable acquisition identity without renderer or delivery metadata."""

    derived_fields = {
        "comparison_available",
        "explorer_rows",
        "freshness",
        "generated_at_utc",
        "price_movement",
    }
    semantic = {key: value for key, value in snapshot.items() if key not in derived_fields}
    encoded = json.dumps(
        semantic,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class ValidatedBundle:
    source: Path
    mission_id: str
    run_id: str
    delivery_run_id: str
    slot_start_utc: str
    slot_time: datetime
    receipt: Mapping[str, object]
    snapshot: Mapping[str, object]
    receipt_sha256: str


def validate_source_bundle(
    source: Path, *, expected_delivery_run_id: str | None = None
) -> ValidatedBundle:
    """Validate a downloaded artifact before it can influence the served pointer."""

    source = source.resolve()
    if not source.is_dir() or any(not (source / name).is_file() for name in SOURCE_FILES):
        raise BundleValidationError("SOURCE_BUNDLE_INCOMPLETE")
    receipt = _read_json(source / "public-receipt.json", "SOURCE_RECEIPT_INVALID")
    if receipt.get("schema_version") != "robin-autonomous-lab-public-receipt-v1":
        raise BundleValidationError("SOURCE_RECEIPT_SCHEMA_UNSUPPORTED")
    mission_id = str(receipt.get("mission_id", ""))
    run_id = str(receipt.get("github_run_id", ""))
    delivery_run_id = str(receipt.get("delivery_github_run_id", ""))
    if not _RUN_ID.fullmatch(run_id):
        raise BundleValidationError("SOURCE_RUN_ID_INVALID")
    if not mission_id or mission_id != str(receipt.get("mission_id")):
        raise BundleValidationError("SOURCE_MISSION_INVALID")
    if not _RUN_ID.fullmatch(delivery_run_id):
        raise BundleValidationError("SOURCE_DELIVERY_RUN_ID_INVALID")
    if expected_delivery_run_id is not None and delivery_run_id != expected_delivery_run_id:
        raise BundleValidationError("SOURCE_DELIVERY_RUN_MISMATCH")
    for name, field in _HASH_FIELDS.items():
        expected = receipt.get(field)
        actual = hashlib.sha256((source / name).read_bytes()).hexdigest()
        if not isinstance(expected, str) or expected != actual:
            raise BundleValidationError("SOURCE_HASH_MISMATCH")
    snapshot = _read_json(source / "robin-real-data.json", "SOURCE_JSON_INVALID")
    if snapshot.get("schema_version") not in {
        "robin-real-data-dashboard-v1",
        "robin-real-data-explorer-v2",
    }:
        raise BundleValidationError("SOURCE_JSON_SCHEMA_UNSUPPORTED")
    rows = snapshot.get("rows")
    if not isinstance(rows, list):
        raise BundleValidationError("SOURCE_JSON_ROWS_INVALID")
    if snapshot.get("schema_version") == "robin-real-data-explorer-v2":
        explorer_rows = snapshot.get("explorer_rows")
        movement = snapshot.get("price_movement")
        if (
            not isinstance(explorer_rows, list)
            or any(not isinstance(row, dict) for row in explorer_rows)
            or not isinstance(movement, dict)
            or not isinstance(snapshot.get("comparison_available"), bool)
            or any(
                not isinstance(movement.get(field), int) or movement[field] < 0
                for field in (
                    "matched_offer_count",
                    "changed_offer_count",
                    "excluded_row_count",
                )
            )
        ):
            raise BundleValidationError("SOURCE_EXPLORER_CONTRACT_INVALID")
    if snapshot.get("data_role") == "CARRY_FORWARD_STALE":
        raise BundleValidationError("SOURCE_CARRY_FORWARD_STALE")
    if str(snapshot.get("mission_id", "")) != mission_id:
        raise BundleValidationError("SOURCE_MISSION_MISMATCH")
    if str(snapshot.get("github_run_id", "")) != run_id:
        raise BundleValidationError("SOURCE_ORIGIN_RUN_MISMATCH")
    receipt_slot = _utc(receipt.get("slot_start_utc"))
    snapshot_slot = _utc(snapshot.get("data_slot_start_utc") or snapshot.get("slot_start_utc"))
    if snapshot_slot != receipt_slot:
        raise BundleValidationError("SOURCE_SLOT_MISMATCH")
    receipt_sha = hashlib.sha256((source / "public-receipt.json").read_bytes()).hexdigest()
    return ValidatedBundle(
        source=source,
        mission_id=mission_id,
        run_id=run_id,
        delivery_run_id=delivery_run_id,
        slot_start_utc=_iso_z(receipt_slot),
        slot_time=receipt_slot,
        receipt=receipt,
        snapshot=snapshot,
        receipt_sha256=receipt_sha,
    )


class AtomicExplorerStore:
    """Immutable versions with one atomically replaced current pointer."""

    def __init__(self, root: Path, *, clock: Callable[[], datetime] | None = None) -> None:
        self.root = root.resolve()
        self.versions = self.root / "versions"
        self.staging = self.root / "staging"
        self.pointer_path = self.root / "current.json"
        self.status_path = self.root / "status.json"
        self._clock = clock or (lambda: datetime.now(UTC))
        self._lock = threading.RLock()
        self.versions.mkdir(parents=True, exist_ok=True)
        self.staging.mkdir(parents=True, exist_ok=True)

    def current_pointer(self) -> dict[str, Any] | None:
        with self._lock:
            if not self.pointer_path.is_file():
                return None
            pointer = _read_json(self.pointer_path, "LOCAL_POINTER_INVALID")
            run_id = str(pointer.get("run_id", ""))
            version = str(pointer.get("version", ""))
            if (
                pointer.get("schema_version") != "robin-local-explorer-pointer-v1"
                or not _RUN_ID.fullmatch(run_id)
                or not version.startswith(f"run-{run_id}")
            ):
                raise BundleValidationError("LOCAL_POINTER_INVALID")
            self._verify_version(version, pointer=pointer)
            return pointer

    def _verify_version(
        self,
        version: str,
        *,
        pointer: Mapping[str, object] | None = None,
        expected_run_id: str | None = None,
    ) -> Path:
        if not version.startswith("run-") or not _RUN_ID.fullmatch(version[4:]):
            raise BundleValidationError("LOCAL_VERSION_INVALID")
        root = (self.versions / version).resolve()
        if root.parent != self.versions or not root.is_dir():
            raise BundleValidationError("LOCAL_VIEW_UNAVAILABLE")
        manifest = _read_json(root / "manifest.json", "LOCAL_MANIFEST_INVALID")
        public_hashes = manifest.get("public_sha256")
        if (
            manifest.get("schema_version") != "robin-local-explorer-version-v1"
            or not _RUN_ID.fullmatch(str(manifest.get("run_id", "")))
            or not isinstance(public_hashes, dict)
        ):
            raise BundleValidationError("LOCAL_MANIFEST_INVALID")
        if expected_run_id is not None and str(manifest.get("run_id")) != expected_run_id:
            raise BundleValidationError("LOCAL_MANIFEST_INVALID")
        receipt_path = root / "source" / "public-receipt.json"
        try:
            receipt_hash = hashlib.sha256(receipt_path.read_bytes()).hexdigest()
            public_actual = {
                name: hashlib.sha256((root / "public" / name).read_bytes()).hexdigest()
                for name in PUBLIC_FILES
            }
        except OSError:
            raise BundleValidationError("LOCAL_VERSION_INCOMPLETE") from None
        if receipt_hash != manifest.get("source_receipt_sha256") or any(
            public_actual[name] != public_hashes.get(name) for name in PUBLIC_FILES
        ):
            raise BundleValidationError("LOCAL_VERSION_HASH_MISMATCH")
        if pointer is not None and any(
            (
                str(pointer.get("run_id", "")) != str(manifest.get("run_id", "")),
                str(pointer.get("delivery_run_id", "")) != str(manifest.get("delivery_run_id", "")),
                str(pointer.get("renderer_revision", ""))
                != str(manifest.get("renderer_revision", "")),
                str(pointer.get("slot_start_utc", "")) != str(manifest.get("slot_start_utc", "")),
                str(pointer.get("source_receipt_sha256", ""))
                != str(manifest.get("source_receipt_sha256", "")),
            )
        ):
            raise BundleValidationError("LOCAL_POINTER_MANIFEST_MISMATCH")
        return root

    def _public_root(self, *, run_id: str | None = None) -> Path:
        pointer: dict[str, Any] | None = None
        pointer = self.current_pointer()
        if run_id is None:
            if pointer is None:
                raise BundleValidationError("LOCAL_VIEW_UNAVAILABLE")
            version = str(pointer["version"])
        else:
            if not _RUN_ID.fullmatch(run_id):
                raise BundleValidationError("LOCAL_HISTORY_ID_INVALID")
            version = self._ensure_history_renderer(run_id)
        return (
            self._verify_version(
                version,
                pointer=pointer if run_id is None else None,
                expected_run_id=run_id,
            )
            / "public"
        )

    def _ensure_history_renderer(self, run_id: str) -> str:
        """Re-render an immutable legacy snapshot without changing the current pointer."""

        version_name = f"run-{run_id}-view-{LOCAL_RENDERER_REVISION}"
        destination = self.versions / version_name
        with self._lock:
            if destination.is_dir():
                return version_name
            legacy_names = [f"run-{run_id}"]
            legacy_names.extend(
                path.name
                for path in sorted(self.versions.glob(f"run-{run_id}-view-*"), reverse=True)
                if path.name != version_name
            )
            legacy_name = next(
                (name for name in legacy_names if (self.versions / name).is_dir()),
                None,
            )
            if legacy_name is None:
                raise BundleValidationError("LOCAL_VIEW_UNAVAILABLE")
            legacy_root = self._verify_version(legacy_name, expected_run_id=run_id)
            validated = validate_source_bundle(legacy_root / "source")
            snapshot_bytes = (legacy_root / "public" / "robin-real-data.json").read_bytes()
            try:
                snapshot = json.loads(snapshot_bytes.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                raise BundleValidationError("LOCAL_VERSION_INCOMPLETE") from None
            if not isinstance(snapshot, dict):
                raise BundleValidationError("LOCAL_VERSION_INCOMPLETE")
            stage = self.staging / uuid4().hex
            try:
                shutil.copytree(validated.source, stage / "source")
                public = stage / "public"
                public.mkdir()
                (public / "robin-real-data.json").write_bytes(snapshot_bytes)
                (public / "robin-real-data.csv").write_bytes(render_dashboard_csv(snapshot))
                (public / "robin-real-data.html").write_bytes(
                    render_dashboard_html(snapshot, csv_filename="robin-real-data.csv")
                )
                manifest = {
                    "schema_version": "robin-local-explorer-version-v1",
                    "run_id": validated.run_id,
                    "delivery_run_id": validated.delivery_run_id,
                    "renderer_revision": LOCAL_RENDERER_REVISION,
                    "slot_start_utc": validated.slot_start_utc,
                    "source_receipt_sha256": validated.receipt_sha256,
                    "public_sha256": {
                        name: hashlib.sha256((public / name).read_bytes()).hexdigest()
                        for name in PUBLIC_FILES
                    },
                }
                (stage / "manifest.json").write_text(
                    json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
                    encoding="utf-8",
                )
                os.replace(stage, destination)
            finally:
                if stage.exists():
                    shutil.rmtree(stage)
            return version_name

    def read_public_bytes(self, name: str, *, run_id: str | None = None) -> bytes:
        if name not in PUBLIC_FILES:
            raise BundleValidationError("LOCAL_PUBLIC_PATH_DENIED")
        return (self._public_root(run_id=run_id) / name).read_bytes()

    def read_public(self, name: str, *, run_id: str | None = None) -> dict[str, Any]:
        return cast(
            dict[str, Any],
            json.loads(self.read_public_bytes(name, run_id=run_id).decode("utf-8")),
        )

    def current_source(self) -> Path:
        """Return the already verified source bundle behind the current pointer."""

        pointer = self.current_pointer()
        if pointer is None:
            raise BundleValidationError("LOCAL_VIEW_UNAVAILABLE")
        root = self._verify_version(str(pointer["version"]), pointer=pointer)
        source = root / "source"
        validate_source_bundle(source)
        return source

    def _switch_pointer(self, pointer: Mapping[str, object]) -> None:
        temporary = self.root / f".current-{uuid4().hex}.json"
        temporary.write_text(
            json.dumps(pointer, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, self.pointer_path)

    def publish(self, source: Path) -> dict[str, Any]:
        validated = validate_source_bundle(source)
        with self._lock:
            current = self.current_pointer()
            same_origin = current is not None and str(current.get("run_id")) == validated.run_id
            if current is not None:
                renderer_current = current.get("renderer_revision") == LOCAL_RENDERER_REVISION
                if same_origin:
                    existing_source = self.current_source()
                    existing_snapshot = _read_json(
                        existing_source / "robin-real-data.json",
                        "LOCAL_VERSION_INCOMPLETE",
                    )
                    if _source_semantic_sha256(existing_snapshot) != (
                        _source_semantic_sha256(validated.snapshot)
                    ):
                        raise BundleValidationError("LOCAL_SOURCE_IDENTITY_COLLISION")
                if same_origin and renderer_current:
                    self.write_status(
                        current_run_id=validated.run_id,
                        last_delivery_run_id=validated.delivery_run_id,
                        last_success_at_utc=self.status().get("last_success_at_utc"),
                        last_checked_at_utc=_iso_z(self._clock()),
                        last_error_code=None,
                    )
                    return current
                if not same_origin and validated.slot_time <= _utc(current.get("slot_start_utc")):
                    raise BundleValidationError("LATE_ARTIFACT")
            stage = self.staging / uuid4().hex
            version_name = f"run-{validated.run_id}-view-{LOCAL_RENDERER_REVISION}"
            destination = self.versions / version_name
            if destination.exists():
                existing_root = self._verify_version(
                    version_name,
                    expected_run_id=validated.run_id,
                )
                existing_manifest = _read_json(
                    existing_root / "manifest.json", "LOCAL_MANIFEST_INVALID"
                )
                if not (
                    same_origin
                    and existing_manifest.get("delivery_run_id") == validated.delivery_run_id
                    and existing_manifest.get("renderer_revision") == LOCAL_RENDERER_REVISION
                    and existing_manifest.get("slot_start_utc") == validated.slot_start_utc
                    and existing_manifest.get("source_receipt_sha256") == validated.receipt_sha256
                ):
                    raise BundleValidationError("LOCAL_VERSION_COLLISION")
                pointer = {
                    "schema_version": "robin-local-explorer-pointer-v1",
                    "run_id": validated.run_id,
                    "delivery_run_id": validated.delivery_run_id,
                    "renderer_revision": LOCAL_RENDERER_REVISION,
                    "version": version_name,
                    "slot_start_utc": validated.slot_start_utc,
                    "source_receipt_sha256": validated.receipt_sha256,
                    "updated_at_utc": _iso_z(self._clock()),
                }
                self._switch_pointer(pointer)
                self.write_status(
                    current_run_id=validated.run_id,
                    last_delivery_run_id=validated.delivery_run_id,
                    last_success_at_utc=_iso_z(self._clock()),
                    last_error_code=None,
                )
                return pointer
            try:
                shutil.copytree(validated.source, stage / "source")
                public = stage / "public"
                public.mkdir()
                previous = self.read_public("robin-real-data.json") if current else None
                if same_origin and previous is not None:
                    snapshot = dict(previous)
                elif validated.snapshot.get("schema_version") == "robin-real-data-explorer-v2":
                    snapshot = dict(validated.snapshot)
                else:
                    snapshot = build_explorer_snapshot(
                        validated.snapshot,
                        previous or {"rows": [], "claim_ids": []},
                        generated_at=self._clock(),
                    )
                normalized = (
                    json.dumps(
                        snapshot,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    + "\n"
                ).encode()
                csv_payload = render_dashboard_csv(snapshot)
                html_payload = render_dashboard_html(snapshot, csv_filename="robin-real-data.csv")
                (public / "robin-real-data.json").write_bytes(normalized)
                (public / "robin-real-data.csv").write_bytes(csv_payload)
                (public / "robin-real-data.html").write_bytes(html_payload)
                local_manifest = {
                    "schema_version": "robin-local-explorer-version-v1",
                    "run_id": validated.run_id,
                    "delivery_run_id": validated.delivery_run_id,
                    "renderer_revision": LOCAL_RENDERER_REVISION,
                    "slot_start_utc": validated.slot_start_utc,
                    "source_receipt_sha256": validated.receipt_sha256,
                    "public_sha256": {
                        name: hashlib.sha256((public / name).read_bytes()).hexdigest()
                        for name in PUBLIC_FILES
                    },
                }
                (stage / "manifest.json").write_text(
                    json.dumps(local_manifest, sort_keys=True, separators=(",", ":")) + "\n",
                    encoding="utf-8",
                )
                os.replace(stage, destination)
                pointer = {
                    "schema_version": "robin-local-explorer-pointer-v1",
                    "run_id": validated.run_id,
                    "delivery_run_id": validated.delivery_run_id,
                    "renderer_revision": LOCAL_RENDERER_REVISION,
                    "version": version_name,
                    "slot_start_utc": validated.slot_start_utc,
                    "source_receipt_sha256": validated.receipt_sha256,
                    "updated_at_utc": _iso_z(self._clock()),
                }
                self._switch_pointer(pointer)
                self.write_status(
                    current_run_id=validated.run_id,
                    last_delivery_run_id=validated.delivery_run_id,
                    last_success_at_utc=_iso_z(self._clock()),
                    last_error_code=None,
                )
                return pointer
            finally:
                if stage.exists():
                    shutil.rmtree(stage)

    def write_status(self, **fields: object) -> None:
        status = {
            "schema_version": "robin-local-explorer-status-v1",
            **fields,
        }
        temporary = self.root / f".status-{uuid4().hex}.json"
        temporary.write_text(
            json.dumps(status, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, self.status_path)

    def status(self) -> dict[str, Any]:
        with self._lock:
            status = (
                _read_json(self.status_path, "LOCAL_STATUS_INVALID")
                if self.status_path.is_file()
                else {
                    "schema_version": "robin-local-explorer-status-v1",
                    "current_run_id": None,
                    "last_success_at_utc": None,
                    "last_error_code": None,
                }
            )
            try:
                pointer = self.current_pointer()
            except BundleValidationError as exc:
                status["last_error_code"] = str(exc)
                return status
            status["current_run_id"] = pointer.get("run_id") if pointer else None
            return status


@dataclass(frozen=True)
class DownloadedArtifact:
    path: Path
    delivery_run_id: str


class GhArtifactClient:
    """Read-only GitHub Actions artifact client backed by the existing gh login."""

    def __init__(
        self,
        *,
        repository: str,
        workflow_id: str,
        runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
        candidate_limit: int = 6,
        windows: bool | None = None,
        hidden_gh_wrapper: Path | None = None,
    ) -> None:
        self.repository = repository
        self.workflow_id = workflow_id
        self._runner = runner
        self.candidate_limit = candidate_limit
        self._windows = os.name == "nt" if windows is None else windows
        self._hidden_gh_wrapper = hidden_gh_wrapper or (
            Path(__file__).resolve().parents[3] / "scripts" / "invoke_gh_hidden.ps1"
        )

    def _process_command(self, command: Sequence[str]) -> tuple[list[str], dict[str, int]]:
        argv = list(command)
        if not self._windows:
            return argv, {}
        if not argv or argv[0] != "gh" or not self._hidden_gh_wrapper.is_file():
            raise BundleValidationError("GITHUB_PROCESS_FAILED")
        return (
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(self._hidden_gh_wrapper),
                *argv[1:],
            ],
            {"creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)},
        )

    def _run(
        self, command: Sequence[str], *, timeout: int = 120
    ) -> subprocess.CompletedProcess[str]:
        argv, platform_options = self._process_command(command)
        try:
            result = self._runner(
                argv,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                **platform_options,
            )
        except FileNotFoundError:
            raise BundleValidationError("GITHUB_CLI_UNAVAILABLE") from None
        except subprocess.TimeoutExpired:
            raise BundleValidationError("GITHUB_READ_TIMEOUT") from None
        except OSError:
            raise BundleValidationError("GITHUB_PROCESS_FAILED") from None
        if result.returncode != 0:
            diagnostic = (result.stderr or "").casefold()
            if any(word in diagnostic for word in ("auth", "login", "token")):
                raise BundleValidationError("GITHUB_AUTH_REQUIRED")
            raise BundleValidationError("GITHUB_READ_FAILED")
        return result

    def download_candidates(
        self, destination: Path, *, current_delivery_run_id: str | None = None
    ) -> list[DownloadedArtifact]:
        destination.mkdir(parents=True, exist_ok=True)
        url = (
            f"repos/{self.repository}/actions/workflows/{self.workflow_id}/runs"
            f"?status=completed&per_page={self.candidate_limit}"
        )
        payload = _read_process_json(self._run(("gh", "api", url)).stdout)
        runs = payload.get("workflow_runs")
        if not isinstance(runs, list):
            raise BundleValidationError("GITHUB_RUNS_INVALID")
        downloaded: list[DownloadedArtifact] = []
        for raw in runs[: self.candidate_limit]:
            if (
                not isinstance(raw, dict)
                or not isinstance(raw.get("id"), int)
                or raw.get("conclusion") != "success"
            ):
                continue
            run_id = str(raw["id"])
            if run_id == current_delivery_run_id:
                break
            artifact_name = f"robin-autonomous-lab-{run_id}"
            artifact_payload = _read_process_json(
                self._run(
                    (
                        "gh",
                        "api",
                        f"repos/{self.repository}/actions/runs/{run_id}/artifacts",
                    )
                ).stdout
            )
            artifacts = artifact_payload.get("artifacts")
            if not isinstance(artifacts, list):
                raise BundleValidationError("GITHUB_ARTIFACTS_INVALID")
            matching = [
                item
                for item in artifacts
                if isinstance(item, dict) and item.get("name") == artifact_name
            ]
            if not matching:
                continue
            if len(matching) != 1 or matching[0].get("expired") is True:
                raise BundleValidationError("GITHUB_ARTIFACT_UNAVAILABLE")
            target = destination / run_id
            try:
                self._run(
                    [
                        "gh",
                        "run",
                        "download",
                        run_id,
                        "--repo",
                        self.repository,
                        "--name",
                        artifact_name,
                        "--dir",
                        str(target),
                    ],
                    timeout=180,
                )
            except BundleValidationError as exc:
                if str(exc) in {"GITHUB_READ_FAILED", "GITHUB_PROCESS_FAILED"}:
                    raise BundleValidationError("GITHUB_ARTIFACT_DOWNLOAD_FAILED") from None
                raise
            downloaded.append(DownloadedArtifact(target, run_id))
        if not downloaded and current_delivery_run_id is None:
            raise BundleValidationError("GITHUB_ARTIFACT_UNAVAILABLE")
        return downloaded


def _read_process_json(payload: str) -> dict[str, Any]:
    try:
        value = json.loads(payload)
    except json.JSONDecodeError:
        raise BundleValidationError("GITHUB_RESPONSE_INVALID") from None
    if not isinstance(value, dict):
        raise BundleValidationError("GITHUB_RESPONSE_INVALID")
    return cast(dict[str, Any], value)


class ExplorerRefreshController:
    def __init__(
        self,
        store: AtomicExplorerStore,
        client: Any,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.store = store
        self.client = client
        self._clock = clock or (lambda: datetime.now(UTC))

    def refresh_once(self) -> bool:
        download_root = self.store.staging / f"refresh-{uuid4().hex}"
        changed = False
        try:
            pointer = self.store.current_pointer()
            prior_status = self.store.status()
            renderer_needs_refresh = bool(
                pointer and pointer.get("renderer_revision") != LOCAL_RENDERER_REVISION
            )
            if renderer_needs_refresh:
                self.store.publish(self.store.current_source())
                changed = True
                pointer = self.store.current_pointer()
                prior_status = self.store.status()
            sources = self.client.download_candidates(
                download_root,
                current_delivery_run_id=(
                    prior_status.get("last_delivery_run_id")
                    or (
                        str(pointer.get("delivery_run_id"))
                        if pointer and pointer.get("delivery_run_id")
                        else None
                    )
                ),
            )
            validated_items: list[ValidatedBundle] = []
            rejected_carry_forward: DownloadedArtifact | None = None
            for candidate in sources:
                try:
                    validated_items.append(
                        validate_source_bundle(
                            candidate.path,
                            expected_delivery_run_id=candidate.delivery_run_id,
                        )
                        if isinstance(candidate, DownloadedArtifact)
                        else validate_source_bundle(candidate)
                    )
                except BundleValidationError as exc:
                    if (
                        str(exc) == "SOURCE_CARRY_FORWARD_STALE"
                        and isinstance(candidate, DownloadedArtifact)
                        and rejected_carry_forward is None
                    ):
                        rejected_carry_forward = candidate
                        continue
                    raise
            validated = sorted(validated_items, key=lambda item: item.slot_time)
            seen_slots: set[datetime] = set()
            for item in validated:
                if item.slot_time in seen_slots:
                    continue
                seen_slots.add(item.slot_time)
                current = self.store.current_pointer()
                if current is not None:
                    if str(current.get("run_id")) == item.run_id:
                        self.store.publish(item.source)
                        continue
                    if item.slot_time <= _utc(current["slot_start_utc"]):
                        continue
                self.store.publish(item.source)
                changed = True
            if rejected_carry_forward is not None:
                self.record_rejected_delivery(
                    rejected_carry_forward.delivery_run_id,
                    "SOURCE_CARRY_FORWARD_STALE",
                )
            elif not changed:
                pointer = self.store.current_pointer()
                prior = self.store.status()
                sticky_error = (
                    prior.get("last_error_code")
                    if prior.get("last_rejected_delivery_run_id")
                    == prior.get("last_delivery_run_id")
                    else None
                )
                self.store.write_status(
                    current_run_id=pointer.get("run_id") if pointer else None,
                    last_delivery_run_id=(
                        prior.get("last_delivery_run_id")
                        or (pointer.get("delivery_run_id") if pointer else None)
                    ),
                    last_rejected_delivery_run_id=prior.get("last_rejected_delivery_run_id"),
                    last_success_at_utc=prior.get("last_success_at_utc"),
                    last_checked_at_utc=_iso_z(self._clock()),
                    last_error_code=sticky_error,
                )
            return changed
        except BundleValidationError as exc:
            self.record_failure(str(exc))
            return changed
        except (OSError, subprocess.SubprocessError):
            self.record_failure("LOCAL_IO_FAILURE")
            return changed
        finally:
            if download_root.exists():
                shutil.rmtree(download_root, ignore_errors=True)

    def record_failure(self, code: str) -> None:
        prior = self.store.status()
        try:
            pointer = self.store.current_pointer()
        except BundleValidationError:
            pointer = None
        self.store.write_status(
            current_run_id=(pointer.get("run_id") if pointer else prior.get("current_run_id")),
            last_delivery_run_id=(
                prior.get("last_delivery_run_id")
                or (pointer.get("delivery_run_id") if pointer else None)
            ),
            last_success_at_utc=prior.get("last_success_at_utc"),
            last_checked_at_utc=_iso_z(self._clock()),
            last_error_code=code,
        )

    def record_rejected_delivery(self, delivery_run_id: str, code: str) -> None:
        prior = self.store.status()
        try:
            pointer = self.store.current_pointer()
        except BundleValidationError:
            pointer = None
        self.store.write_status(
            current_run_id=(pointer.get("run_id") if pointer else prior.get("current_run_id")),
            last_delivery_run_id=delivery_run_id,
            last_rejected_delivery_run_id=delivery_run_id,
            last_success_at_utc=prior.get("last_success_at_utc"),
            last_checked_at_utc=_iso_z(self._clock()),
            last_error_code=code,
        )


def run_refresh_loop(
    controller: Any,
    stopped: Any,
    refresh_seconds: float,
    *,
    refresh_immediately: bool = False,
) -> None:
    """Keep polling after an unexpected defect and expose a stable error code."""

    def refresh() -> None:
        try:
            controller.refresh_once()
        except Exception:  # fail closed at the long-lived process boundary
            try:
                controller.record_failure("REFRESH_UNEXPECTED_FAILURE")
            except Exception:
                return

    if refresh_immediately:
        refresh()
    while not stopped.wait(refresh_seconds):
        refresh()


def _handler(store: AtomicExplorerStore) -> type[BaseHTTPRequestHandler]:
    class ExplorerHandler(BaseHTTPRequestHandler):
        server_version = "RobinExplorer/1"

        def log_message(self, _format: str, *_args: object) -> None:
            return

        def _send(self, status: HTTPStatus, payload: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self) -> None:  # noqa: N802
            path = urllib.parse.urlsplit(self.path).path
            if path == "/":
                self.send_response(HTTPStatus.FOUND)
                self.send_header("Location", "/robin-real-data.html")
                self.end_headers()
                return
            try:
                if path == "/status.json":
                    payload = json.dumps(
                        store.status(), sort_keys=True, separators=(",", ":")
                    ).encode()
                    self._send(HTTPStatus.OK, payload, "application/json; charset=utf-8")
                    return
                parts = path.strip("/").split("/")
                run_id: str | None = None
                if len(parts) == 3 and parts[0] == "history":
                    run_id, name = parts[1], parts[2]
                elif len(parts) == 1:
                    name = parts[0]
                else:
                    raise BundleValidationError("LOCAL_PUBLIC_PATH_DENIED")
                payload = store.read_public_bytes(name, run_id=run_id)
                content_type = {
                    ".html": "text/html; charset=utf-8",
                    ".json": "application/json; charset=utf-8",
                    ".csv": "text/csv; charset=utf-8",
                }[Path(name).suffix]
                self._send(HTTPStatus.OK, payload, content_type)
            except (BundleValidationError, KeyError, OSError):
                self._send(HTTPStatus.NOT_FOUND, b"not found\n", "text/plain")

        def do_POST(self) -> None:  # noqa: N802
            if self.path not in {"/export.csv", "/export.json"}:
                self._send(HTTPStatus.NOT_FOUND, b"not found\n", "text/plain")
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = 0
            if not 0 < length <= _MAX_EXPORT_BYTES:
                self._send(HTTPStatus.BAD_REQUEST, b"invalid export\n", "text/plain")
                return
            values = urllib.parse.parse_qs(
                self.rfile.read(length).decode("utf-8"),
                keep_blank_values=True,
                max_num_fields=4,
            )
            content = values.get("content", [""])[0]
            if not content:
                self._send(HTTPStatus.BAD_REQUEST, b"invalid export\n", "text/plain")
                return
            suffix = "csv" if self.path.endswith(".csv") else "json"
            payload = content.encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header(
                "Content-Type",
                "text/csv; charset=utf-8" if suffix == "csv" else "application/json; charset=utf-8",
            )
            self.send_header(
                "Content-Disposition", f'attachment; filename="robin-selection.{suffix}"'
            )
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(payload)

    return ExplorerHandler


def make_server(store: AtomicExplorerStore, *, port: int = 4173) -> ThreadingHTTPServer:
    return ThreadingHTTPServer(("127.0.0.1", port), _handler(store))


__all__ = [
    "AtomicExplorerStore",
    "BundleValidationError",
    "ExplorerRefreshController",
    "GhArtifactClient",
    "DownloadedArtifact",
    "ValidatedBundle",
    "make_server",
    "run_refresh_loop",
    "validate_source_bundle",
]
