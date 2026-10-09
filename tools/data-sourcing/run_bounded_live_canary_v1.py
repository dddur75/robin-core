#!/usr/bin/env python3
"""Run one externally authorized live canary item; never creates authority."""

from __future__ import annotations

import argparse
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import robin.capture as capture_package
from robin.capture import (
    LIVE_ALLOWED_SPORT_KEYS,
    ActivationEnvelopeV1,
    BoundedLiveCanaryExecutor,
    CaptureContractError,
    CaptureMode,
    CaptureStore,
    EnvironmentSecretReader,
    FixtureMapping,
    GitRepositoryStateReader,
    InternalRetentionPolicy,
    LiveGuardError,
    LivePlanV1,
    LiveStateStore,
    LiveStorageError,
    LiveTransportError,
    OwnerAuthorizationV1,
    PinnedOwnerAuthorizationVerifier,
    ProviderRequestSpec,
    StrictHttpsTransport,
)
from robin.capture.contracts import canonical_json_bytes, strict_json_loads
from robin.capture.storage import (
    CaptureStorageError,
    _safe_read_bounded,
    capture_root_fingerprint,
    exclusive_local_directory_fingerprint,
    validate_capture_workspace,
    validate_exclusive_local_directory_identity,
)

_MAXIMUM_CONTROL_ARTIFACT_BYTES = 1_048_576


def _load_json(path: Path) -> Any:
    unresolved = path.absolute()
    validate_capture_workspace(unresolved.parent)
    payload = _safe_read_bounded(
        unresolved,
        maximum_bytes=_MAXIMUM_CONTROL_ARTIFACT_BYTES,
    )
    return strict_json_loads(payload)


def _directories_overlap(left: Path, right: Path) -> bool:
    left_text = os.path.normcase(os.path.abspath(os.fspath(left)))
    right_text = os.path.normcase(os.path.abspath(os.fspath(right)))
    try:
        common = os.path.normcase(os.path.commonpath((left_text, right_text)))
    except ValueError:
        return False
    return common in {left_text, right_text}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Execute exactly one pre-authorized Odds API plan item. This command does not "
            "create an OwnerAuthorization, activation, plan, mapping, or retry."
        )
    )
    parser.add_argument("--mode", required=True, choices=["LIVE_CANARY"])
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument(
        "--git-executable",
        type=Path,
        required=True,
        help="Owner-approved absolute path to the local Git executable.",
    )
    parser.add_argument(
        "--git-executable-sha256",
        required=True,
        help=(
            "Separately supplied owner SHA-256 pin; it must equal the Git binding "
            "covered by OwnerAuthorization."
        ),
    )
    parser.add_argument(
        "--control-temp-root",
        type=Path,
        required=True,
        help="Existing approved local directory for an ephemeral sanitized Git index.",
    )
    parser.add_argument("--capture-root", type=Path, required=True)
    parser.add_argument("--authorization", type=Path, required=True)
    parser.add_argument(
        "--owner-authorization-sha256",
        required=True,
        help="Hash pin supplied separately by the owner; it is not read from the bundle.",
    )
    parser.add_argument("--activation", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--item-id", required=True)
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--fixture-mappings", type=Path, required=True)
    parser.add_argument("--maximum-response-bytes", type=int, default=1_048_576)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.maximum_response_bytes <= 0:
            raise LiveGuardError("LIVE_PAYLOAD_LIMIT_INVALID")
        repository_root = validate_exclusive_local_directory_identity(args.repository_root)
        if not args.git_executable.is_absolute():
            raise LiveGuardError("LIVE_GIT_EXECUTABLE_ABSOLUTE_PATH_REQUIRED")
        capture_root = args.capture_root.absolute()
        observed_capture_root_fingerprint = capture_root_fingerprint(capture_root)
        control_temp_root = validate_capture_workspace(args.control_temp_root)
        control_temp_root = validate_exclusive_local_directory_identity(control_temp_root)
        if _directories_overlap(control_temp_root, repository_root):
            raise LiveGuardError("LIVE_GIT_CONTROL_TEMP_REPOSITORY_OVERLAP")
        if _directories_overlap(control_temp_root, capture_root):
            raise LiveGuardError("LIVE_GIT_CONTROL_TEMP_CAPTURE_OVERLAP")
        expected_script = repository_root / "tools/data-sourcing/run_bounded_live_canary_v1.py"
        expected_package = repository_root / "src/robin/capture/__init__.py"
        loaded_package = Path(capture_package.__file__)
        if any(
            os.path.normcase(os.path.abspath(os.fspath(actual)))
            != os.path.normcase(os.path.abspath(os.fspath(expected)))
            for actual, expected in (
                (Path(__file__), expected_script),
                (loaded_package, expected_package),
            )
        ):
            raise LiveGuardError("LIVE_LOADED_CODE_REPOSITORY_MISMATCH")
        authorization = OwnerAuthorizationV1.model_validate(_load_json(args.authorization))
        verifier = PinnedOwnerAuthorizationVerifier(args.owner_authorization_sha256)
        verifier.verify(authorization)
        if args.git_executable_sha256 != authorization.approved_git_executable_sha256:
            raise LiveGuardError("LIVE_GIT_EXECUTABLE_AUTHORIZATION_PIN_MISMATCH")
        if observed_capture_root_fingerprint != authorization.approved_capture_root_fingerprint:
            raise LiveGuardError("LIVE_CAPTURE_ROOT_FINGERPRINT_MISMATCH")
        repository_root_fingerprint = exclusive_local_directory_fingerprint(repository_root)
        control_temp_root_fingerprint = exclusive_local_directory_fingerprint(control_temp_root)
        if (
            repository_root_fingerprint != authorization.approved_repository_root_fingerprint
            or control_temp_root_fingerprint != authorization.approved_control_temp_root_fingerprint
        ):
            raise LiveGuardError("LIVE_GIT_OWNER_ATTESTED_ROOT_MISMATCH")
        activation = ActivationEnvelopeV1.model_validate(_load_json(args.activation))
        plan = LivePlanV1.model_validate(_load_json(args.plan))
        matching_items = tuple(item for item in plan.items if item.item_id == args.item_id)
        if len(matching_items) != 1:
            raise LiveGuardError("LIVE_PLAN_ITEM_SELECTION_INVALID")
        request = ProviderRequestSpec.model_validate(_load_json(args.request))
        raw_mapping_value = _load_json(args.fixture_mappings)
        if not isinstance(raw_mapping_value, list):
            raise LiveGuardError("LIVE_FIXTURE_MAPPINGS_INPUT_INVALID")
        raw_mappings = cast(list[dict[str, Any]], raw_mapping_value)
        mappings = tuple(FixtureMapping.model_validate(value) for value in raw_mappings)
        preflight_now = datetime.now(UTC)
        BoundedLiveCanaryExecutor._validate_authority(
            authorization,
            activation,
            now=preflight_now,
        )
        BoundedLiveCanaryExecutor._validate_activation_ttl(
            activation,
            now=preflight_now,
        )
        if activation.sport_key not in LIVE_ALLOWED_SPORT_KEYS:
            raise LiveGuardError("LIVE_SPORT_FORBIDDEN")
        BoundedLiveCanaryExecutor._validate_plan(authorization, activation, plan)
        BoundedLiveCanaryExecutor._validate_item(
            activation,
            plan,
            matching_items[0],
            request,
            mappings,
            now=preflight_now,
        )
        repository_reader = GitRepositoryStateReader(
            repository_root,
            git_executable=args.git_executable,
            git_executable_sha256=authorization.approved_git_executable_sha256,
            control_temp_root=control_temp_root,
            repository_root_fingerprint=authorization.approved_repository_root_fingerprint,
            control_temp_root_fingerprint=authorization.approved_control_temp_root_fingerprint,
        )
        repository = repository_reader.read()
        if (
            repository.head_sha != authorization.authorized_main_sha
            or repository.main_sha != authorization.authorized_main_sha
        ):
            raise LiveGuardError("LIVE_REPOSITORY_SHA_MISMATCH")
        store = CaptureStore(
            capture_root,
            InternalRetentionPolicy(),
            approved_local_root=capture_root,
        )
        LiveStateStore(store).assert_capture_root(authorization.approved_capture_root_fingerprint)

        def now() -> datetime:
            return datetime.now(UTC)

        executor = BoundedLiveCanaryExecutor(
            capture_store=store,
            repository_state_reader=repository_reader,
            owner_authorization_verifier=verifier,
            secret_reader=EnvironmentSecretReader(),
            transport=StrictHttpsTransport(clock=now),
            clock=now,
            maximum_payload_bytes=args.maximum_response_bytes,
        )
        receipt = executor.execute(
            mode=CaptureMode(args.mode),
            authorization=authorization,
            activation=activation,
            plan=plan,
            item=matching_items[0],
            request=request,
            mappings=mappings,
        )
    except (
        CaptureContractError,
        CaptureStorageError,
        LiveGuardError,
        LiveStorageError,
        LiveTransportError,
        OSError,
        TypeError,
        ValueError,
    ) as error:
        code = getattr(error, "code", "LIVE_CANARY_INPUT_OR_EXECUTION_INVALID")
        print(f"LIVE_CANARY_FAILED:{code}", file=sys.stderr)
        return 2
    sys.stdout.buffer.write(canonical_json_bytes(receipt.model_dump(mode="json")) + b"\n")
    return 0 if receipt.terminal_disposition.value == "SUCCESS" else 3


if __name__ == "__main__":
    raise SystemExit(main())
