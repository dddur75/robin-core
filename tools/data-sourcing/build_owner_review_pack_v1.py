#!/usr/bin/env python3
"""Build, but never execute, a real successor owner-review pack."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

from robin.capture import (
    CaptureContractError,
    ProviderNetworkBindingV1,
    RealCaptureWorkspaceReceiptV1,
)
from robin.capture.bootstrap_contracts import load_campaign_selection_authority_v1
from robin.capture.contracts import canonical_sha256, strict_json_loads
from robin.capture.owner_review_pack import (
    OwnerReviewPackError,
    assert_owner_review_pack_completion_current_v1,
    build_owner_review_pack_v1,
    owner_authorization_statement_v1,
    write_owner_review_pack_v1,
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

ZERO_EFFECT_COUNT = 0
_MAXIMUM_ARTIFACT_BYTES = 1_048_576


def _load(path: Path) -> object:
    validate_exclusive_local_directory_identity(path.absolute().parent)
    return strict_json_loads(
        _safe_read_bounded(path.absolute(), maximum_bytes=_MAXIMUM_ARTIFACT_BYTES)
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace-receipt", type=Path, required=True)
    parser.add_argument("--mission-manifest", type=Path, required=True)
    parser.add_argument("--provider-network-binding", type=Path, required=True)
    parser.add_argument("--campaign-selection", type=Path, required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    generated = datetime.now(UTC)
    generated_text = generated.isoformat().replace("+00:00", "Z")
    try:
        workspace = RealCaptureWorkspaceReceiptV1.model_validate(_load(arguments.workspace_receipt))
        assert_real_capture_workspace_receipt_current_v1(workspace)
        assert_workspace_control_artifact_destination_v1(
            workspace,
            arguments.output_directory,
        )
        manifest = load_tracked_real_execution_mission_manifest_v1(
            Path(workspace.runtime_repository_root),
            arguments.mission_manifest,
        )
        binding = ProviderNetworkBindingV1.model_validate(_load(arguments.provider_network_binding))
        campaign_selection = load_campaign_selection_authority_v1(
            _load(arguments.campaign_selection)
        )
        selected_campaign = campaign_selection.selected_candidate()
        targets = selected_campaign.fixture_target_set
        request = selected_campaign.request
        nonce_material = {
            "workspace": workspace.canonical_receipt_hash,
            "binding": binding.canonical_binding_hash,
            "targets": targets.canonical_set_hash,
            "campaign_selection": campaign_selection.canonical_selection_hash,
            "request": canonical_sha256(request.fingerprint_material()),
            "generated_at": generated_text,
        }
        nonce_hash = canonical_sha256(nonce_material)
        pack = build_owner_review_pack_v1(
            workspace_receipt=workspace,
            mission_manifest=manifest,
            provider_network_binding=binding,
            campaign_selection=campaign_selection,
            generated_at_utc=generated,
            authorization_nonce=f"owner-{nonce_hash[:40]}",
            activation_nonce=f"activation-{nonce_hash[24:64]}",
        )
        arguments.output_directory.mkdir(parents=False, exist_ok=False)
        paths = write_owner_review_pack_v1(arguments.output_directory, pack)
        assert_real_capture_workspace_receipt_current_v1(workspace)
        assert_owner_review_pack_completion_current_v1(pack, datetime.now(UTC))
    except (
        CaptureContractError,
        CaptureStorageError,
        OwnerReviewPackError,
        WorkspaceBootstrapError,
        OSError,
        TypeError,
        ValueError,
    ) as error:
        code = getattr(error, "code", "OWNER_REVIEW_PACK_INPUT_INVALID")
        print(json.dumps({"status": "FAILED", "code": code}, sort_keys=True))
        return 2
    print(
        json.dumps(
            {
                "status": "OWNER_AUTHORIZATION_READY",
                "pack_sha256": pack.canonical_pack_hash,
                "owner_authorization_candidate_sha256": (
                    pack.owner_authorization_candidate.canonical_authorization_hash
                ),
                "expected_owner_authorization_sha256": (pack.expected_owner_authorization_sha256),
                "activation_candidate_sha256": (
                    pack.activation_candidate.canonical_activation_hash
                ),
                "plan_sha256": pack.plan_candidate.canonical_plan_hash,
                "plan_item_sha256": pack.plan_item_candidate.canonical_item_hash,
                "request_fingerprint_sha256": pack.request_fingerprint_sha256,
                "campaign_selection_sha256": pack.campaign_selection_sha256,
                "selected_campaign_candidate_sha256": (pack.selected_campaign_candidate_sha256),
                "selected_campaign_window_id": pack.selected_campaign_window_id,
                "fixture_target_set_sha256": pack.fixture_target_set.canonical_set_hash,
                "provider_network_binding_sha256": (
                    pack.provider_network_binding.canonical_binding_hash
                ),
                "outputs": {label: str(path) for label, path in sorted(paths.items())},
                "provider_http_calls": ZERO_EFFECT_COUNT,
                "real_secret_reads": ZERO_EFFECT_COUNT,
                "real_capture_calls": ZERO_EFFECT_COUNT,
                "owner_authorization_statement": owner_authorization_statement_v1(pack),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
