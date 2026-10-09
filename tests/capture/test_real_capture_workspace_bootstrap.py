from __future__ import annotations

import hashlib
import inspect
import json
import os
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Mapping, Sequence

import pytest

import robin.capture.workspace_bootstrap as workspace_bootstrap
from robin.capture.workspace_bootstrap import (
    EXPECTED_ORIGIN,
    LocalBoundaryInspection,
    SubprocessCommandRunner,
    WorkspaceBootstrapError,
    _acl_security_probe_script_v1,
    _assert_roots_non_overlapping,
    assert_real_capture_workspace_receipt_current_v1,
    assert_workspace_control_artifact_destination_v1,
    load_tracked_real_execution_mission_manifest_v1,
    prepare_real_capture_workspace_v1,
)

MAIN_SHA = "a" * 40


def _mission_manifest_payload(*, expires_at: str) -> dict[str, object]:
    return {
        "mission_id": "REAL_EXECUTION_BOOTSTRAP_CLOSURE_V1",
        "authorized_stages": ["E1"],
        "maximum_stage": "E1",
        "external_effects": [
            "local_standalone_runtime_create_after_merge",
            "github_public_full_clone_after_merge",
            "provider_public_dns_resolution_exactly_once_after_merge",
            "official_schedule_public_read_after_merge",
            "git_remote_write_non_force",
            "github_pull_request_write",
            "github_merge_commit",
            "github_actions_observe",
        ],
        "compute_budget": 8000,
        "time_budget": 345600,
        "source_hash": "204e4323d0b99fdfa8c655cdc3a08a8d2b3c82ac0a784f9a97982c90ab3a7312",
        "expires_at": expires_at,
    }


class FakeInspector:
    def __init__(
        self,
        *,
        synchronized: bool = False,
        fixed: bool = True,
        acl_exclusive: bool = True,
        attributes: int = 0,
        security_descriptor_sha256: str = "b" * 64,
    ) -> None:
        self.synchronized = synchronized
        self.fixed = fixed
        self.acl_exclusive = acl_exclusive
        self.attributes = attributes
        self.security_descriptor_sha256 = security_descriptor_sha256

    def inspect(self, path: Path) -> LocalBoundaryInspection:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
        return LocalBoundaryInspection(
            canonical_path=resolved,
            filesystem_name="NTFS",
            volume_identity="volume-1",
            device=metadata.st_dev,
            inode=metadata.st_ino,
            attributes=self.attributes,
            security_descriptor_sha256=self.security_descriptor_sha256,
            fixed_local_filesystem=self.fixed,
            acl_exclusive=self.acl_exclusive,
            synchronized=self.synchronized,
        )


class ReceiptEscapeInspector(FakeInspector):
    def __init__(self, alias: Path, outside: Path) -> None:
        super().__init__()
        self.alias = alias.absolute()
        self.outside = outside.resolve(strict=True)

    def inspect(self, path: Path) -> LocalBoundaryInspection:
        if path.absolute() == self.alias:
            metadata = self.outside.stat()
            return LocalBoundaryInspection(
                canonical_path=self.outside,
                filesystem_name="NTFS",
                volume_identity="volume-1",
                device=metadata.st_dev,
                inode=metadata.st_ino,
                attributes=0,
                security_descriptor_sha256="c" * 64,
                fixed_local_filesystem=True,
                acl_exclusive=True,
                synchronized=False,
            )
        return super().inspect(path)


class FakeGitRunner:
    def __init__(
        self,
        main_sha: str,
        *,
        dirty: bool = False,
        mutate_git_on_checkout: bool = False,
        attached_head: bool = False,
        index_flag_output: str = "",
    ) -> None:
        self.main_sha = main_sha
        self.dirty = dirty
        self.mutate_git_on_checkout = mutate_git_on_checkout
        self.attached_head = attached_head
        self.index_flag_output = index_flag_output
        self.calls: list[tuple[str, ...]] = []
        self.timed_calls: list[tuple[tuple[str, ...], int]] = []

    def run(
        self,
        arguments: Sequence[str],
        *,
        cwd: Path | None,
        environment: Mapping[str, str],
        timeout_seconds: int,
    ) -> str:
        del cwd
        call = tuple(arguments)
        self.calls.append(call)
        self.timed_calls.append((call, timeout_seconds))
        assert "THE_ODDS_API_KEY" not in environment
        if "clone" in call:
            destination = Path(call[-1])
            (destination / ".git").mkdir(parents=True)
            (destination / ".git" / "config").write_text(
                "[core]\n"
                "\trepositoryformatversion = 0\n"
                "\tbare = false\n"
                '[remote "origin"]\n'
                f"\turl = {EXPECTED_ORIGIN}\n"
                "\tfetch = +refs/heads/*:refs/remotes/origin/*\n",
                encoding="utf-8",
            )
            return ""
        if "ls-tree" in call:
            return "100644 blob deadbeef\tREADME.md"
        if "remote" in call and "get-url" in call:
            return EXPECTED_ORIGIN
        if "rev-parse" in call and "--abbrev-ref" in call:
            return "main" if self.attached_head else "HEAD"
        if "rev-parse" in call:
            return self.main_sha
        if "status" in call:
            return " M README.md" if self.dirty else ""
        if "checkout" in call and self.mutate_git_on_checkout:
            Path(call[0]).write_bytes(b"mutated-git-binary")
            return ""
        if "ls-files" in call and "-v" in call:
            return self.index_flag_output
        if "ls-files" in call or "fsck" in call or "checkout" in call:
            return ""
        return ""


def git_executable(tmp_path: Path) -> Path:
    path = tmp_path / "git-bin" / "git.exe"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"synthetic-git-binary")
    return path


def _isolated_python_environment() -> dict[str, str]:
    environment = {
        "PYTHONDONTWRITEBYTECODE": "1",
        "LANG": "C",
        "LC_ALL": "C",
    }
    for name in ("SystemRoot", "WINDIR"):
        if name in os.environ:
            environment[name] = os.environ[name]
    return environment


def test_contained_command_success_returns_strict_utf8_stdout() -> None:
    stdout = SubprocessCommandRunner().run(
        (
            os.path.abspath(sys.executable),
            "-I",
            "-B",
            "-c",
            "print('contained-ok')",
        ),
        cwd=None,
        environment=_isolated_python_environment(),
        timeout_seconds=5,
    )
    assert stdout == "contained-ok\n"


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object accounting")
def test_windows_success_waits_for_job_accounting_to_settle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_active_processes = workspace_bootstrap._WindowsJobObject.active_processes
    stale_zero_observations = 0

    def active_processes_with_settlement_lag(
        job: workspace_bootstrap._WindowsJobObject,
    ) -> int:
        nonlocal stale_zero_observations
        active_processes = real_active_processes(job)
        if active_processes == 0 and stale_zero_observations < 3:
            stale_zero_observations += 1
            return 1
        return active_processes

    monkeypatch.setattr(
        workspace_bootstrap._WindowsJobObject,
        "active_processes",
        active_processes_with_settlement_lag,
    )

    stdout = SubprocessCommandRunner().run(
        (
            os.path.abspath(sys.executable),
            "-I",
            "-B",
            "-c",
            "print('settled-ok')",
        ),
        cwd=None,
        environment=_isolated_python_environment(),
        timeout_seconds=5,
    )

    assert stdout == "settled-ok\n"
    assert stale_zero_observations == 3


def test_contained_command_start_failure_is_sanitized(tmp_path: Path) -> None:
    missing = tmp_path / "missing-command.exe"
    with pytest.raises(WorkspaceBootstrapError, match="WORKSPACE_COMMAND_START_FAILED"):
        SubprocessCommandRunner().run(
            (os.fspath(missing),),
            cwd=None,
            environment=_isolated_python_environment(),
            timeout_seconds=5,
        )


def test_command_timeout_returns_only_after_descendant_tree_is_quiescent(
    tmp_path: Path,
) -> None:
    heartbeat = tmp_path / "descendant-heartbeat.bin"
    descendant = (
        "import pathlib,signal,sys,time\n"
        "signal.signal(signal.SIGTERM,signal.SIG_IGN)\n"
        "path=pathlib.Path(sys.argv[1])\n"
        "while True:\n"
        "    with path.open('ab') as stream:\n"
        "        stream.write(b'x')\n"
        "        stream.flush()\n"
        "    time.sleep(0.02)\n"
    )
    root = (
        "import subprocess,sys,time\n"
        "subprocess.Popen(\n"
        "    [sys.executable,'-I','-B','-c',sys.argv[1],sys.argv[2]],\n"
        "    stdin=subprocess.DEVNULL,\n"
        "    stdout=subprocess.DEVNULL,\n"
        "    stderr=subprocess.DEVNULL,\n"
        "    close_fds=True,\n"
        ")\n"
        "time.sleep(60)\n"
    )
    runner = SubprocessCommandRunner()
    with pytest.raises(WorkspaceBootstrapError, match="WORKSPACE_COMMAND_TIMEOUT"):
        runner.run(
            (
                os.path.abspath(sys.executable),
                "-I",
                "-B",
                "-c",
                root,
                descendant,
                os.fspath(heartbeat),
            ),
            cwd=None,
            environment=_isolated_python_environment(),
            timeout_seconds=2,
        )
    assert heartbeat.is_file()
    observed_size = heartbeat.stat().st_size
    assert observed_size > 0
    time.sleep(0.25)
    assert heartbeat.stat().st_size == observed_size


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object assignment barrier")
def test_windows_gate_never_launches_target_before_job_assignment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = tmp_path / "target-launched.txt"

    def reject_assignment(_job: object, _process_id: int) -> None:
        raise WorkspaceBootstrapError("WORKSPACE_COMMAND_CONTAINMENT_FAILED")

    monkeypatch.setattr(
        workspace_bootstrap._WindowsJobObject,
        "assign_process",
        reject_assignment,
    )
    with pytest.raises(
        WorkspaceBootstrapError,
        match="WORKSPACE_COMMAND_CONTAINMENT_FAILED",
    ):
        SubprocessCommandRunner().run(
            (
                os.path.abspath(sys.executable),
                "-I",
                "-B",
                "-c",
                "import pathlib,sys; pathlib.Path(sys.argv[1]).write_text('launched')",
                os.fspath(marker),
            ),
            cwd=None,
            environment=_isolated_python_environment(),
            timeout_seconds=5,
        )
    assert not marker.exists()


def test_completed_root_with_live_descendant_is_failed_and_terminated() -> None:
    root = (
        "import subprocess,sys\n"
        "subprocess.Popen(\n"
        "    [sys.executable,'-I','-B','-c','import time; time.sleep(60)'],\n"
        "    stdin=subprocess.DEVNULL,\n"
        "    stdout=subprocess.DEVNULL,\n"
        "    stderr=subprocess.DEVNULL,\n"
        "    close_fds=True,\n"
        ")\n"
    )
    with pytest.raises(
        WorkspaceBootstrapError,
        match="WORKSPACE_COMMAND_RESIDUAL_DESCENDANT",
    ):
        SubprocessCommandRunner().run(
            (os.path.abspath(sys.executable), "-I", "-B", "-c", root),
            cwd=None,
            environment=_isolated_python_environment(),
            timeout_seconds=5,
        )


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object termination proof")
def test_windows_unconfirmed_termination_has_a_distinct_failure_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_terminate = workspace_bootstrap._WindowsJobObject.terminate_and_confirm

    def terminate_then_refuse_attestation(
        job: workspace_bootstrap._WindowsJobObject,
    ) -> None:
        real_terminate(job)
        raise WorkspaceBootstrapError("WORKSPACE_COMMAND_TERMINATION_UNCONFIRMED")

    monkeypatch.setattr(
        workspace_bootstrap._WindowsJobObject,
        "terminate_and_confirm",
        terminate_then_refuse_attestation,
    )
    with pytest.raises(
        WorkspaceBootstrapError,
        match="WORKSPACE_COMMAND_TERMINATION_UNCONFIRMED",
    ):
        SubprocessCommandRunner().run(
            (
                os.path.abspath(sys.executable),
                "-I",
                "-B",
                "-c",
                "import time; time.sleep(60)",
            ),
            cwd=None,
            environment=_isolated_python_environment(),
            timeout_seconds=1,
        )


@pytest.mark.skipif(os.name != "nt", reason="Windows registry behavior")
def test_absent_sync_provider_registry_root_is_a_safe_empty_source(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import winreg

    real_open_key = winreg.OpenKey

    def open_key(root: int, sub_key: str, *args: object, **kwargs: object) -> object:
        if root == winreg.HKEY_CURRENT_USER and sub_key == r"Software\SyncEngines\Providers":
            raise FileNotFoundError(2, "registry key not found", sub_key)
        return real_open_key(root, sub_key, *args, **kwargs)

    sync_root = tmp_path / "environment-sync-root"
    monkeypatch.setenv("OneDrive", str(sync_root))
    for variable in ("OneDriveConsumer", "OneDriveCommercial", "Dropbox"):
        monkeypatch.delenv(variable, raising=False)
    monkeypatch.setattr(winreg, "OpenKey", open_key)

    assert workspace_bootstrap._registered_windows_sync_roots() == (
        Path(os.path.normcase(os.path.abspath(sync_root))),
    )


@pytest.mark.skipif(os.name != "nt", reason="Windows registry behavior")
@pytest.mark.parametrize(
    "failure_point",
    [
        "root_open",
        "enum_key",
        "enum_key_missing",
        "child_open",
        "enum_value",
        "enum_value_missing",
    ],
)
def test_sync_provider_registry_inspection_errors_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    failure_point: str,
) -> None:
    import winreg

    class FakeKey:
        def __init__(self, name: str) -> None:
            self.name = name

        def __enter__(self) -> FakeKey:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

    providers = FakeKey("providers")
    provider = FakeKey("provider")

    def open_key(root: object, sub_key: str, *args: object, **kwargs: object) -> FakeKey:
        del args, kwargs
        if root == winreg.HKEY_CURRENT_USER:
            assert sub_key == r"Software\SyncEngines\Providers"
            if failure_point == "root_open":
                raise PermissionError(5, "registry access denied", sub_key)
            return providers
        assert root is providers
        assert sub_key == "provider-1"
        if failure_point == "child_open":
            raise PermissionError(5, "registry access denied", sub_key)
        return provider

    def enum_key(key: FakeKey, index: int) -> str:
        assert key is providers
        assert index == 0
        if failure_point == "enum_key":
            raise PermissionError(5, "registry access denied")
        if failure_point == "enum_key_missing":
            raise FileNotFoundError(2, "registry key disappeared")
        return "provider-1"

    def enum_value(key: FakeKey, index: int) -> tuple[str, str, int]:
        assert key is provider
        assert index == 0
        if failure_point == "enum_value":
            raise PermissionError(5, "registry access denied")
        if failure_point == "enum_value_missing":
            raise FileNotFoundError(2, "registry value disappeared")
        raise AssertionError("EnumValue should only succeed at the selected failure point")

    monkeypatch.setattr(winreg, "OpenKey", open_key)
    monkeypatch.setattr(winreg, "EnumKey", enum_key)
    monkeypatch.setattr(winreg, "EnumValue", enum_value)

    with pytest.raises(
        WorkspaceBootstrapError, match="LOCAL_RUNTIME_SYNC_ROOT_INSPECTION_UNAVAILABLE"
    ):
        workspace_bootstrap._registered_windows_sync_roots()


@pytest.mark.skipif(os.name != "nt", reason="Windows registry behavior")
def test_sync_provider_registry_no_more_items_is_normal_completion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import winreg

    class FakeKey:
        def __enter__(self) -> FakeKey:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

    def no_more_items(*_args: object) -> str:
        error = OSError(259, "no more data")
        error.winerror = 259
        raise error

    monkeypatch.setattr(winreg, "OpenKey", lambda *_args, **_kwargs: FakeKey())
    monkeypatch.setattr(winreg, "EnumKey", no_more_items)
    for variable in ("OneDrive", "OneDriveConsumer", "OneDriveCommercial", "Dropbox"):
        monkeypatch.delenv(variable, raising=False)

    assert workspace_bootstrap._registered_windows_sync_roots() == ()


@pytest.mark.skipif(os.name != "nt", reason="Windows registry behavior")
def test_disappearing_sync_provider_child_key_is_safely_skipped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import winreg

    class FakeKey:
        def __enter__(self) -> FakeKey:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

    providers = FakeKey()

    def open_key(root: object, sub_key: str, *args: object, **kwargs: object) -> FakeKey:
        del args, kwargs
        if root == winreg.HKEY_CURRENT_USER:
            return providers
        raise FileNotFoundError(2, "provider key disappeared", sub_key)

    def enum_key(key: FakeKey, index: int) -> str:
        assert key is providers
        if index == 0:
            return "provider-1"
        error = OSError(259, "no more data")
        error.winerror = 259
        raise error

    monkeypatch.setattr(winreg, "OpenKey", open_key)
    monkeypatch.setattr(winreg, "EnumKey", enum_key)
    for variable in ("OneDrive", "OneDriveConsumer", "OneDriveCommercial", "Dropbox"):
        monkeypatch.delenv(variable, raising=False)

    assert workspace_bootstrap._registered_windows_sync_roots() == ()


def test_create_produces_standalone_exact_clone_receipt_and_zero_provider_effects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = tmp_path / "RobinRuntime"
    git = git_executable(tmp_path)
    runner = FakeGitRunner(MAIN_SHA)
    receipt = prepare_real_capture_workspace_v1(
        runtime_parent=runtime,
        expected_main_sha=MAIN_SHA,
        git_executable=git,
        mode="CREATE",
        prepared_at_utc=datetime(2026, 8, 22, 9, 0, tzinfo=UTC),
        inspector=FakeInspector(),
        command_runner=runner,
    )
    assert (runtime / "repository" / ".git").is_dir()
    assert not (runtime / "repository" / ".git").is_file()
    assert receipt.authorized_main_sha == MAIN_SHA
    assert receipt.bootstrap_mode == "CREATE"
    assert receipt.bootstrap_tool_loaded_from_runtime_repository is False
    assert receipt.bootstrap_package_loaded_from_runtime_repository is False
    assert receipt.authority_eligible_for_real_execution is False
    assert receipt.git_executable_sha256 == hashlib.sha256(b"synthetic-git-binary").hexdigest()
    assert receipt.provider_http_requests == receipt.provider_tcp_connections == 0
    assert receipt.provider_secret_reads == 0
    receipt_path = runtime / "control-temp" / f"workspace-{receipt.canonical_receipt_hash}.json"
    assert receipt_path.is_file()
    assert sum("clone" in call for call in runner.calls) == 1
    assert [timeout for call, timeout in runner.timed_calls if "clone" in call] == [3600]
    assert [timeout for call, timeout in runner.timed_calls if "checkout" in call] == [900]
    assert [timeout for call, timeout in runner.timed_calls if "fsck" in call] == [1800]
    assert all(
        timeout == 120
        for call, timeout in runner.timed_calls
        if not any(command in call for command in ("clone", "checkout", "fsck"))
    )

    monkeypatch.setattr(
        workspace_bootstrap,
        "_loaded_package_repository_root_v1",
        lambda: (runtime / "repository").resolve(),
    )
    monkeypatch.setattr(
        workspace_bootstrap,
        "_calling_entrypoint_repository_root_v1",
        lambda: (runtime / "repository").resolve(),
    )
    verified = prepare_real_capture_workspace_v1(
        runtime_parent=runtime,
        expected_main_sha=MAIN_SHA,
        git_executable=git,
        mode="VERIFY",
        prepared_at_utc=datetime(2026, 8, 22, 9, 1, tzinfo=UTC),
        inspector=FakeInspector(),
        command_runner=runner,
    )
    assert verified.bootstrap_mode == "VERIFY"
    assert verified.bootstrap_tool_loaded_from_runtime_repository is True
    assert verified.bootstrap_package_loaded_from_runtime_repository is True
    assert verified.authority_eligible_for_real_execution is True
    assert_real_capture_workspace_receipt_current_v1(
        verified,
        inspector=FakeInspector(),
        command_runner=runner,
    )
    with pytest.raises(
        WorkspaceBootstrapError,
        match="BOOTSTRAP_WORKSPACE_RECEIPT_STALE",
    ):
        assert_real_capture_workspace_receipt_current_v1(
            verified,
            inspector=FakeInspector(security_descriptor_sha256="c" * 64),
            command_runner=runner,
        )
    config = runtime / "repository" / ".git" / "config"
    unsafe_include_path = "/".join(("C:", "unsafe", "external-git-config"))
    config.write_text(
        config.read_text(encoding="utf-8") + f"[include]\n\tpath = {unsafe_include_path}\n",
        encoding="utf-8",
    )
    with pytest.raises(
        WorkspaceBootstrapError,
        match="BOOTSTRAP_GIT_METADATA_OR_TREE_CHANGED",
    ):
        assert_real_capture_workspace_receipt_current_v1(
            verified,
            inspector=FakeInspector(),
            command_runner=runner,
        )
    with pytest.raises(
        WorkspaceBootstrapError,
        match="BOOTSTRAP_ARTIFACT_OUTSIDE_CONTROL_TEMP",
    ):
        assert_workspace_control_artifact_destination_v1(
            verified,
            runtime / "repository" / "must-not-dirty-git.json",
        )
    assert (
        runtime / "control-temp" / f"workspace-{verified.canonical_receipt_hash}.json"
    ).is_file()
    assert sum("clone" in call for call in runner.calls) == 1


def test_out_of_clone_api_verify_cannot_mint_authority(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime-spoof"
    git = git_executable(tmp_path)
    runner = FakeGitRunner(MAIN_SHA)
    prepare_real_capture_workspace_v1(
        runtime_parent=runtime,
        expected_main_sha=MAIN_SHA,
        git_executable=git,
        mode="CREATE",
        prepared_at_utc=datetime(2026, 8, 22, 9, 0, tzinfo=UTC),
        inspector=FakeInspector(),
        command_runner=runner,
    )
    receipt = prepare_real_capture_workspace_v1(
        runtime_parent=runtime,
        expected_main_sha=MAIN_SHA,
        git_executable=git,
        mode="VERIFY",
        prepared_at_utc=datetime(2026, 8, 22, 9, 1, tzinfo=UTC),
        inspector=FakeInspector(),
        command_runner=runner,
    )
    assert receipt.bootstrap_tool_loaded_from_runtime_repository is False
    assert receipt.bootstrap_package_loaded_from_runtime_repository is False
    assert receipt.authority_eligible_for_real_execution is False
    assert (
        "tool_source_repository_root"
        not in inspect.signature(prepare_real_capture_workspace_v1).parameters
    )


def test_runtime_entrypoint_with_external_import_cannot_mint_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = tmp_path / "runtime-import-drift"
    git = git_executable(tmp_path)
    runner = FakeGitRunner(MAIN_SHA)
    prepare_real_capture_workspace_v1(
        runtime_parent=runtime,
        expected_main_sha=MAIN_SHA,
        git_executable=git,
        mode="CREATE",
        prepared_at_utc=datetime(2026, 8, 22, 9, 0, tzinfo=UTC),
        inspector=FakeInspector(),
        command_runner=runner,
    )
    monkeypatch.setattr(
        workspace_bootstrap,
        "_calling_entrypoint_repository_root_v1",
        lambda: (runtime / "repository").resolve(),
    )
    receipt = prepare_real_capture_workspace_v1(
        runtime_parent=runtime,
        expected_main_sha=MAIN_SHA,
        git_executable=git,
        mode="VERIFY",
        prepared_at_utc=datetime(2026, 8, 22, 9, 1, tzinfo=UTC),
        inspector=FakeInspector(),
        command_runner=runner,
    )
    assert receipt.bootstrap_tool_loaded_from_runtime_repository is True
    assert receipt.bootstrap_package_loaded_from_runtime_repository is False
    assert receipt.authority_eligible_for_real_execution is False


@pytest.mark.parametrize(
    ("inspector", "code"),
    (
        (FakeInspector(synchronized=True), "LOCAL_RUNTIME_SYNCHRONIZED_ROOT_FORBIDDEN"),
        (FakeInspector(fixed=False), "LOCAL_RUNTIME_FIXED_ACL_FILESYSTEM_REQUIRED"),
        (FakeInspector(acl_exclusive=False), "LOCAL_RUNTIME_ACL_EXCLUSIVITY_REQUIRED"),
        (FakeInspector(attributes=0x1000), "LOCAL_RUNTIME_CLOUD_OR_REPARSE_FORBIDDEN"),
    ),
)
def test_unsafe_runtime_boundaries_fail_before_clone(
    tmp_path: Path,
    inspector: FakeInspector,
    code: str,
) -> None:
    runner = FakeGitRunner(MAIN_SHA)
    runtime = tmp_path / f"runtime-{code}"
    with pytest.raises(WorkspaceBootstrapError, match=code):
        prepare_real_capture_workspace_v1(
            runtime_parent=runtime,
            expected_main_sha=MAIN_SHA,
            git_executable=git_executable(tmp_path / code),
            mode="CREATE",
            prepared_at_utc=datetime(2026, 8, 22, 9, 0, tzinfo=UTC),
            inspector=inspector,
            command_runner=runner,
        )
    assert not any("clone" in call for call in runner.calls)
    assert not runtime.exists()


def test_partial_state_fails_closed(tmp_path: Path) -> None:
    runtime = tmp_path / "existing-runtime"
    runtime.mkdir()
    with pytest.raises(WorkspaceBootstrapError, match="BOOTSTRAP_PARTIAL_STATE_PRESENT"):
        prepare_real_capture_workspace_v1(
            runtime_parent=runtime,
            expected_main_sha=MAIN_SHA,
            git_executable=git_executable(tmp_path),
            mode="CREATE",
            prepared_at_utc=datetime(2026, 8, 22, 9, 0, tzinfo=UTC),
            inspector=FakeInspector(),
            command_runner=FakeGitRunner("b" * 40),
        )


def test_wrong_remote_main_fails_after_clone(tmp_path: Path) -> None:
    runner = FakeGitRunner("b" * 40)
    with pytest.raises(WorkspaceBootstrapError, match="BOOTSTRAP_GIT_MAIN_MISMATCH"):
        prepare_real_capture_workspace_v1(
            runtime_parent=tmp_path / "wrong-main-runtime",
            expected_main_sha=MAIN_SHA,
            git_executable=git_executable(tmp_path),
            mode="CREATE",
            prepared_at_utc=datetime(2026, 8, 22, 9, 0, tzinfo=UTC),
            inspector=FakeInspector(),
            command_runner=runner,
        )
    assert sum("clone" in call for call in runner.calls) == 1


@pytest.mark.parametrize(
    ("runner", "code"),
    (
        (
            FakeGitRunner(MAIN_SHA, attached_head=True),
            "BOOTSTRAP_GIT_DETACHED_HEAD_REQUIRED",
        ),
        (
            FakeGitRunner(MAIN_SHA, index_flag_output="S README.md"),
            "BOOTSTRAP_GIT_INDEX_FLAGS_FORBIDDEN",
        ),
        (
            FakeGitRunner(MAIN_SHA, index_flag_output="h README.md"),
            "BOOTSTRAP_GIT_INDEX_FLAGS_FORBIDDEN",
        ),
    ),
)
def test_attached_head_or_hidden_index_flags_fail_closed(
    tmp_path: Path,
    runner: FakeGitRunner,
    code: str,
) -> None:
    with pytest.raises(WorkspaceBootstrapError, match=code):
        prepare_real_capture_workspace_v1(
            runtime_parent=tmp_path / f"runtime-{code}",
            expected_main_sha=MAIN_SHA,
            git_executable=git_executable(tmp_path / code),
            mode="CREATE",
            prepared_at_utc=datetime(2026, 8, 22, 9, 0, tzinfo=UTC),
            inspector=FakeInspector(),
            command_runner=runner,
        )


def test_canonical_alias_overlap_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "root"
    nested = root / "nested"
    nested.mkdir(parents=True)
    metadata = root.stat()
    left = LocalBoundaryInspection(
        canonical_path=root.resolve(),
        filesystem_name="NTFS",
        volume_identity="same-volume",
        device=metadata.st_dev,
        inode=metadata.st_ino,
        attributes=0,
        security_descriptor_sha256="a" * 64,
        fixed_local_filesystem=True,
        acl_exclusive=True,
        synchronized=False,
    )
    right = LocalBoundaryInspection(
        canonical_path=nested.resolve(),
        filesystem_name="NTFS",
        volume_identity="same-volume",
        device=nested.stat().st_dev,
        inode=nested.stat().st_ino,
        attributes=0,
        security_descriptor_sha256="b" * 64,
        fixed_local_filesystem=True,
        acl_exclusive=True,
        synchronized=False,
    )
    with pytest.raises(WorkspaceBootstrapError, match="LOCAL_RUNTIME_ROOTS_OVERLAP"):
        _assert_roots_non_overlapping((left, right))


def test_unc_candidate_is_rejected_before_any_mutation(tmp_path: Path) -> None:
    runner = FakeGitRunner(MAIN_SHA)
    separator = chr(92)
    unc_runtime = Path(separator * 2 + separator.join(("server", "share", "RobinRuntime")))
    with pytest.raises(WorkspaceBootstrapError, match="LOCAL_RUNTIME_UNC_FORBIDDEN"):
        prepare_real_capture_workspace_v1(
            runtime_parent=unc_runtime,
            expected_main_sha=MAIN_SHA,
            git_executable=git_executable(tmp_path),
            mode="CREATE",
            prepared_at_utc=datetime(2026, 8, 22, 9, 0, tzinfo=UTC),
            inspector=FakeInspector(),
            command_runner=runner,
        )
    assert not runner.calls


def test_reparse_candidate_parent_is_rejected_before_runtime_create(tmp_path: Path) -> None:
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    alias = tmp_path / "alias-parent"
    try:
        alias.symlink_to(real_parent, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlink unavailable")
    runner = FakeGitRunner(MAIN_SHA)
    with pytest.raises(
        WorkspaceBootstrapError,
        match="LOCAL_RUNTIME_REPARSE_PARENT_FORBIDDEN",
    ):
        prepare_real_capture_workspace_v1(
            runtime_parent=alias / "RobinRuntime",
            expected_main_sha=MAIN_SHA,
            git_executable=git_executable(tmp_path),
            mode="CREATE",
            prepared_at_utc=datetime(2026, 8, 22, 9, 0, tzinfo=UTC),
            inspector=FakeInspector(),
            command_runner=runner,
        )
    assert not (real_parent / "RobinRuntime").exists()
    assert not runner.calls


@pytest.mark.parametrize(
    ("runner", "code"),
    (
        (FakeGitRunner(MAIN_SHA, dirty=True), "BOOTSTRAP_GIT_WORKTREE_DIRTY"),
        (
            FakeGitRunner(MAIN_SHA, mutate_git_on_checkout=True),
            "BOOTSTRAP_GIT_EXECUTABLE_CHANGED",
        ),
    ),
)
def test_dirty_clone_or_git_binary_mutation_fails_closed(
    tmp_path: Path,
    runner: FakeGitRunner,
    code: str,
) -> None:
    with pytest.raises(WorkspaceBootstrapError, match=code):
        prepare_real_capture_workspace_v1(
            runtime_parent=tmp_path / f"runtime-{code}",
            expected_main_sha=MAIN_SHA,
            git_executable=git_executable(tmp_path / code),
            mode="CREATE",
            prepared_at_utc=datetime(2026, 8, 22, 9, 0, tzinfo=UTC),
            inspector=FakeInspector(),
            command_runner=runner,
        )


def test_acl_probe_uses_locale_independent_well_known_sids() -> None:
    script = _acl_security_probe_script_v1()
    assert "S-1-5-18" in script
    assert "S-1-5-32-544" in script
    assert "NT AUTHORITY" not in script
    assert "Administrators" not in script


def test_receipt_output_canonical_escape_is_rejected(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    git = git_executable(tmp_path)
    prepare_real_capture_workspace_v1(
        runtime_parent=runtime,
        expected_main_sha=MAIN_SHA,
        git_executable=git,
        mode="CREATE",
        prepared_at_utc=datetime(2026, 8, 22, 9, 0, tzinfo=UTC),
        inspector=FakeInspector(),
        command_runner=FakeGitRunner(MAIN_SHA),
    )
    alias = runtime / "control-temp" / "escape"
    outside = tmp_path / "outside"
    alias.mkdir()
    outside.mkdir()
    with pytest.raises(
        WorkspaceBootstrapError,
        match="BOOTSTRAP_RECEIPT_OUTPUT_OUTSIDE_CONTROL_TEMP",
    ):
        prepare_real_capture_workspace_v1(
            runtime_parent=runtime,
            expected_main_sha=MAIN_SHA,
            git_executable=git,
            mode="VERIFY",
            prepared_at_utc=datetime(2026, 8, 22, 9, 1, tzinfo=UTC),
            receipt_output=alias / "receipt.json",
            inspector=ReceiptEscapeInspector(alias, outside),
            command_runner=FakeGitRunner(MAIN_SHA),
        )
    assert not (outside / "receipt.json").exists()


def test_only_exact_tracked_runtime_mission_manifest_is_loadable(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    manifest_path = repository / "configs/execution/first-c0-vertical-v1.json"
    manifest_path.parent.mkdir(parents=True)
    tracked = (
        Path(__file__).parents[2] / "configs/execution/first-c0-vertical-v1.json"
    ).read_bytes()
    manifest_path.write_bytes(tracked)
    loaded = load_tracked_real_execution_mission_manifest_v1(
        repository,
        manifest_path,
    )
    assert loaded.mission_id == "FIRST_C0_VERTICAL_V1"
    assert loaded.expires_at == datetime(2026, 9, 4, 8, 8, 40, tzinfo=UTC)
    assert (
        loaded.canonical_manifest_sha256()
        == "0a2fa273481921a6207a30b27f50a1e293bfbf6d3e19f78596b1308628072ce4"
    )

    alternate = tmp_path / "substituted-first-c0-manifest.json"
    alternate.write_bytes(tracked)
    with pytest.raises(
        WorkspaceBootstrapError,
        match="BOOTSTRAP_MISSION_MANIFEST_PATH_MISMATCH",
    ):
        load_tracked_real_execution_mission_manifest_v1(repository, alternate)

    old_path = repository / "configs/execution/real-execution-bootstrap-closure-v1.json"
    old_path.write_text(
        json.dumps(_mission_manifest_payload(expires_at="2026-09-01T20:00:00Z")),
        encoding="utf-8",
    )
    historical = load_tracked_real_execution_mission_manifest_v1(repository, old_path)
    assert historical.mission_id == "REAL_EXECUTION_BOOTSTRAP_CLOSURE_V1"
    assert (
        historical.canonical_manifest_sha256()
        == "d3d570be434b61c0875212061d92419d074b0d8357ba60e55c9f10cd79458e14"
    )


@pytest.mark.parametrize("mutation", ("expired", "altered", "effect-expanded"))
def test_tracked_first_c0_manifest_rejects_any_profile_change(
    tmp_path: Path,
    mutation: str,
) -> None:
    repository = tmp_path / "repository"
    manifest_path = repository / "configs/execution/first-c0-vertical-v1.json"
    manifest_path.parent.mkdir(parents=True)
    payload = json.loads(
        (Path(__file__).parents[2] / "configs/execution/first-c0-vertical-v1.json").read_text(
            encoding="utf-8"
        )
    )
    if mutation == "expired":
        payload["expires_at"] = "2026-09-04T08:08:39Z"
    elif mutation == "altered":
        payload["compute_budget"] = 3999
    else:
        payload["external_effects"].append("multi_league_scale")
    manifest_path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(
        WorkspaceBootstrapError,
        match="BOOTSTRAP_MISSION_MANIFEST_INVALID",
    ):
        load_tracked_real_execution_mission_manifest_v1(repository, manifest_path)
