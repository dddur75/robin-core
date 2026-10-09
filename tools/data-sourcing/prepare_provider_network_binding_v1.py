#!/usr/bin/env python3
"""Perform the one authorized DNS preparation operation; never provider transport."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from robin.capture import (
    RealCaptureWorkspaceReceiptV1,
)
from robin.capture.bootstrap_contracts import load_campaign_selection_authority_v1
from robin.capture.contracts import strict_json_loads
from robin.capture.provider_network import (
    ProviderNetworkPreparationError,
    prepare_provider_network_binding_once_v1,
)
from robin.capture.storage import (
    CaptureStorageError,
    _safe_read_bounded,
    validate_exclusive_local_directory_identity,
)
from robin.capture.workspace_bootstrap import (
    WorkspaceBootstrapError,
    assert_real_capture_workspace_receipt_current_v1,
    assert_workspace_control_artifact_destination_v1,
    load_tracked_real_execution_mission_manifest_v1,
)

_MAXIMUM_ARTIFACT_BYTES = 1_048_576


def _load(path: Path) -> object:
    validate_exclusive_local_directory_identity(path.absolute().parent)
    return strict_json_loads(
        _safe_read_bounded(path.absolute(), maximum_bytes=_MAXIMUM_ARTIFACT_BYTES)
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace-receipt", required=True, type=Path)
    parser.add_argument("--mission-manifest", required=True, type=Path)
    parser.add_argument("--campaign-selection", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--binding-ttl-seconds", type=int, default=900)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        workspace = RealCaptureWorkspaceReceiptV1.model_validate(_load(args.workspace_receipt))
        assert_real_capture_workspace_receipt_current_v1(workspace)
        assert_workspace_control_artifact_destination_v1(workspace, args.output)
        manifest = load_tracked_real_execution_mission_manifest_v1(
            Path(workspace.runtime_repository_root),
            args.mission_manifest,
        )
        campaign_selection = load_campaign_selection_authority_v1(_load(args.campaign_selection))
        binding = prepare_provider_network_binding_once_v1(
            workspace_receipt=workspace,
            mission_manifest=manifest,
            campaign_selection=campaign_selection,
            output_path=args.output,
            binding_ttl_seconds=args.binding_ttl_seconds,
        )
    except (
        CaptureStorageError,
        ProviderNetworkPreparationError,
        WorkspaceBootstrapError,
        OSError,
        TypeError,
        ValueError,
    ) as error:
        code = getattr(error, "code", "PROVIDER_NETWORK_INPUT_INVALID")
        print(json.dumps({"status": "FAILED", "code": code}, sort_keys=True))
        return 2
    print(
        json.dumps(
            {
                "status": "BOUND",
                "provider_network_binding_sha256": binding.canonical_binding_hash,
                "resolution_claim_sha256": binding.resolution_claim.canonical_claim_hash,
                "campaign_selection_sha256": (binding.resolution_claim.campaign_selection_sha256),
                "fixture_target_set_sha256": (binding.resolution_claim.fixture_target_set_sha256),
                "resolution_operations": binding.resolution_operations,
                "provider_http_requests": binding.provider_http_requests,
                "provider_tcp_connections": binding.provider_tcp_connections,
                "provider_secret_reads": binding.provider_secret_reads,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
