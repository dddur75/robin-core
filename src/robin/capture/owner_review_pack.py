"""Build an unexecuted successor owner-review pack from frozen bootstrap evidence."""

from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path

from robin.capture.bootstrap_contracts import (
    PRE_KICKOFF_SAFETY_MARGIN,
    ActivationEnvelopeV2,
    CampaignSelectionAuthorityV1,
    FirstC0CanarySelectionV1,
    LivePlanItemV2,
    LivePlanV2,
    OwnerAuthorizationV2,
    OwnerReviewPackV1,
    ProviderNetworkBindingV1,
    RealCaptureWorkspaceReceiptV1,
    RealExecutionMissionManifestV1,
)
from robin.capture.contracts import RequestFingerprint, canonical_json_bytes, ensure_utc
from robin.capture.storage import CaptureStorageError, validate_exclusive_local_directory_identity


class OwnerReviewPackError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _build_owner_review_pack_v1(
    *,
    workspace_receipt: RealCaptureWorkspaceReceiptV1,
    mission_manifest: RealExecutionMissionManifestV1,
    provider_network_binding: ProviderNetworkBindingV1,
    campaign_selection: CampaignSelectionAuthorityV1,
    generated_at_utc: datetime,
    authorization_nonce: str,
    activation_nonce: str,
) -> OwnerReviewPackV1:
    generated = ensure_utc(generated_at_utc, field="owner_pack_generated_at")
    selected_campaign = campaign_selection.selected_candidate()
    fixture_target_set = selected_campaign.fixture_target_set
    request = selected_campaign.request
    earliest_kickoff = min(target.official_kickoff_utc for target in fixture_target_set.targets)
    expires = min(
        provider_network_binding.expires_at_utc,
        mission_manifest.expires_at,
        selected_campaign.usable_expires_at_utc,
        earliest_kickoff - PRE_KICKOFF_SAFETY_MARGIN,
    )
    try:
        provider_network_binding.assert_current(generated)
    except ValueError:
        raise OwnerReviewPackError("NETWORK_BINDING_EXPIRED") from None
    try:
        campaign_selection.assert_selected_candidate_current(generated)
    except ValueError:
        raise OwnerReviewPackError("OWNER_REVIEW_AUTHORITY_NOT_CURRENT") from None
    if (
        expires > provider_network_binding.expires_at_utc
        or expires <= generated
        or fixture_target_set.sport_key != request.sport_key
        or not workspace_receipt.authority_eligible_for_real_execution
        or workspace_receipt.provider_http_requests != 0
        or workspace_receipt.provider_tcp_connections != 0
        or workspace_receipt.provider_secret_reads != 0
        or workspace_receipt.prepared_at_utc > fixture_target_set.created_at_utc
        or fixture_target_set.workspace_receipt_sha256 != workspace_receipt.canonical_receipt_hash
        or provider_network_binding.resolution_claim.workspace_receipt_sha256
        != workspace_receipt.canonical_receipt_hash
        or provider_network_binding.resolution_claim.mission_manifest_sha256
        != mission_manifest.canonical_manifest_sha256()
        or provider_network_binding.resolution_claim.mission_id != mission_manifest.mission_id
        or provider_network_binding.resolution_claim.campaign_selection_sha256
        != campaign_selection.canonical_selection_hash
        or provider_network_binding.resolution_claim.fixture_target_set_sha256
        != fixture_target_set.canonical_set_hash
        or campaign_selection.workspace_receipt_sha256 != workspace_receipt.canonical_receipt_hash
        or campaign_selection.workspace_prepared_at_utc != workspace_receipt.prepared_at_utc
        or campaign_selection.mission_manifest_sha256
        != mission_manifest.canonical_manifest_sha256()
        or (
            isinstance(campaign_selection, FirstC0CanarySelectionV1)
            and campaign_selection.mission_id != mission_manifest.mission_id
        )
        or campaign_selection.mission_expires_at_utc != mission_manifest.expires_at
        or campaign_selection.selected_fixture_target_set_sha256
        != fixture_target_set.canonical_set_hash
        or fixture_target_set.created_at_utc
        > provider_network_binding.resolution_claim.claimed_at_utc
        or provider_network_binding.observed_at_utc > generated
    ):
        raise OwnerReviewPackError("OWNER_REVIEW_PACK_INPUT_SCOPE_INVALID")
    fingerprint = RequestFingerprint.create(request)
    authorization = OwnerAuthorizationV2.issue(
        authorization_id=f"owner-review-{fingerprint.request_sha256[:20]}",
        authorization_status="OWNER_REVIEW_CANDIDATE",
        mission_id=mission_manifest.mission_id,
        authorized_main_sha=workspace_receipt.authorized_main_sha,
        mission_manifest_sha256=mission_manifest.canonical_manifest_sha256(),
        mission_expires_at_utc=mission_manifest.expires_at,
        workspace_receipt_sha256=workspace_receipt.canonical_receipt_hash,
        issued_at_utc=generated,
        not_before_utc=generated,
        expires_at_utc=expires,
        allowed_sport_keys=(request.sport_key,),
        allowed_region=request.region,
        allowed_market_sets=(request.markets,),
        maximum_http_calls=1,
        maximum_credits=len(request.markets),
        maximum_plan_items=1,
        approved_capture_root_fingerprint=workspace_receipt.capture_root_fingerprint,
        approved_repository_root_fingerprint=(workspace_receipt.repository_root_fingerprint),
        approved_control_temp_root_fingerprint=workspace_receipt.control_temp_fingerprint,
        approved_git_executable_path=workspace_receipt.git_executable_path,
        approved_git_executable_sha256=workspace_receipt.git_executable_sha256,
        provider_network_binding_sha256=(provider_network_binding.canonical_binding_hash),
        approved_provider_ip_address=provider_network_binding.selected_ip_address,
        campaign_selection_sha256=campaign_selection.canonical_selection_hash,
        fixture_target_set_sha256=fixture_target_set.canonical_set_hash,
        authorization_nonce=authorization_nonce,
    )
    expected_authorization_sha256 = authorization.expected_promoted_authorization_hash()
    activation_seed = ActivationEnvelopeV2.issue(
        activation_id=f"activation-review-{fingerprint.request_sha256[:20]}",
        mission_id=mission_manifest.mission_id,
        mission_manifest_sha256=mission_manifest.canonical_manifest_sha256(),
        mission_expires_at_utc=mission_manifest.expires_at,
        authorization_id=authorization.authorization_id,
        authorization_hash=expected_authorization_sha256,
        repository_sha=workspace_receipt.authorized_main_sha,
        provider_network_binding_sha256=(provider_network_binding.canonical_binding_hash),
        fixture_target_set_sha256=fixture_target_set.canonical_set_hash,
        sport_key=request.sport_key,
        region=request.region,
        markets=request.markets,
        not_before_utc=generated,
        expires_at_utc=expires,
        maximum_http_calls=1,
        maximum_credits=len(request.markets),
        plan_sha256="0" * 64,
        activation_nonce=activation_nonce,
    )
    plan_id = f"plan-review-{fingerprint.request_sha256[:20]}"
    item = LivePlanItemV2.issue(
        item_id=f"item-review-{fingerprint.request_sha256[:20]}",
        mission_id=mission_manifest.mission_id,
        mission_manifest_sha256=mission_manifest.canonical_manifest_sha256(),
        mission_expires_at_utc=mission_manifest.expires_at,
        plan_id=plan_id,
        sequence=1,
        sport_key=request.sport_key,
        region=request.region,
        markets=request.markets,
        provider_request_fingerprint=fingerprint.request_sha256,
        fixture_target_set_sha256=fixture_target_set.canonical_set_hash,
        provider_network_binding_sha256=(provider_network_binding.canonical_binding_hash),
        not_before_utc=generated,
        expires_at_utc=expires,
        maximum_credits=len(request.markets),
        purpose="first real receipt-backed capture after explicit owner approval",
        window_label=(
            f"campaign:{selected_campaign.window_id}:"
            f"{selected_campaign.canonical_candidate_hash[:32]}"
        ),
    )
    plan = LivePlanV2.issue(
        plan_id=plan_id,
        mission_id=mission_manifest.mission_id,
        mission_manifest_sha256=mission_manifest.canonical_manifest_sha256(),
        mission_expires_at_utc=mission_manifest.expires_at,
        activation_id=activation_seed.activation_id,
        activation_hash=activation_seed.activation_scope_sha256,
        repository_sha=workspace_receipt.authorized_main_sha,
        provider_network_binding_sha256=(provider_network_binding.canonical_binding_hash),
        fixture_target_set_sha256=fixture_target_set.canonical_set_hash,
        created_at_utc=generated,
        expires_at_utc=expires,
        items=(item,),
        maximum_http_calls=1,
        maximum_credits=len(request.markets),
    )
    activation = ActivationEnvelopeV2.issue(
        **{
            **activation_seed.model_dump(
                mode="python",
                exclude={
                    "activation_scope_sha256",
                    "canonical_activation_hash",
                    "plan_sha256",
                },
            ),
            "plan_sha256": plan.canonical_plan_hash,
        }
    )
    return OwnerReviewPackV1.issue(
        generated_at_utc=generated,
        mission_manifest=mission_manifest,
        mission_manifest_sha256=mission_manifest.canonical_manifest_sha256(),
        workspace_receipt=workspace_receipt,
        workspace_receipt_sha256=workspace_receipt.canonical_receipt_hash,
        campaign_selection=campaign_selection,
        campaign_selection_sha256=campaign_selection.canonical_selection_hash,
        selected_campaign_candidate_id=selected_campaign.candidate_id,
        selected_campaign_candidate_sha256=selected_campaign.canonical_candidate_hash,
        selected_campaign_window_id=selected_campaign.window_id,
        selected_campaign_temporal_role=selected_campaign.temporal_role,
        selected_campaign_predictor_protocol_ids=(selected_campaign.predictor_protocol_ids),
        selected_campaign_target_protocol_ids=selected_campaign.target_protocol_ids,
        selected_fixture_target_ids=tuple(
            target.internal_fixture_target_id for target in fixture_target_set.targets
        ),
        selected_fixture_target_hashes=tuple(
            target.canonical_target_hash for target in fixture_target_set.targets
        ),
        earliest_target_kickoff_utc=earliest_kickoff,
        target_window_not_before_utc=generated,
        target_window_expires_at_utc=expires,
        request=request,
        request_fingerprint_sha256=fingerprint.request_sha256,
        fixture_target_set=fixture_target_set,
        provider_network_binding=provider_network_binding,
        owner_authorization_candidate=authorization,
        expected_owner_authorization_sha256=expected_authorization_sha256,
        activation_candidate=activation,
        plan_candidate=plan,
        plan_item_candidate=item,
    )


def build_owner_review_pack_v1(
    *,
    workspace_receipt: RealCaptureWorkspaceReceiptV1,
    mission_manifest: RealExecutionMissionManifestV1,
    provider_network_binding: ProviderNetworkBindingV1,
    campaign_selection: CampaignSelectionAuthorityV1,
    generated_at_utc: datetime,
    authorization_nonce: str,
    activation_nonce: str,
) -> OwnerReviewPackV1:
    """Reject standalone builds; the atomic owner path owns the one pack."""

    raise OwnerReviewPackError("FIRST_C0_SINGLE_OWNER_ENTRYPOINT_REQUIRED")


def _build_first_c0_owner_review_pack_after_atomic_binding_v1(
    *,
    workspace_receipt: RealCaptureWorkspaceReceiptV1,
    mission_manifest: RealExecutionMissionManifestV1,
    provider_network_binding: ProviderNetworkBindingV1,
    campaign_selection: CampaignSelectionAuthorityV1,
    generated_at_utc: datetime,
    authorization_nonce: str,
    activation_nonce: str,
) -> OwnerReviewPackV1:
    return _build_owner_review_pack_v1(
        workspace_receipt=workspace_receipt,
        mission_manifest=mission_manifest,
        provider_network_binding=provider_network_binding,
        campaign_selection=campaign_selection,
        generated_at_utc=generated_at_utc,
        authorization_nonce=authorization_nonce,
        activation_nonce=activation_nonce,
    )


def assert_owner_review_pack_completion_current_v1(
    pack: OwnerReviewPackV1,
    completed_at_utc: datetime,
) -> None:
    """Refuse a success result if authority expired while artifacts were written."""

    completed = ensure_utc(completed_at_utc, field="owner_pack_completed_at")
    if completed < pack.generated_at_utc:
        raise OwnerReviewPackError("OWNER_REVIEW_COMPLETION_TIME_INVALID")
    try:
        pack.provider_network_binding.assert_current(completed)
    except ValueError:
        raise OwnerReviewPackError("NETWORK_BINDING_EXPIRED") from None
    try:
        pack.campaign_selection.assert_selected_candidate_current(completed)
    except ValueError:
        raise OwnerReviewPackError("OWNER_REVIEW_AUTHORITY_NOT_CURRENT") from None
    if completed >= pack.target_window_expires_at_utc:
        raise OwnerReviewPackError("OWNER_REVIEW_AUTHORITY_NOT_CURRENT")


def _write_immutable(path: Path, payload: bytes) -> None:
    try:
        with path.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError:
        raise OwnerReviewPackError("OWNER_REVIEW_PACK_OUTPUT_EXISTS") from None
    except OSError:
        raise OwnerReviewPackError("OWNER_REVIEW_PACK_WRITE_FAILED") from None


def _write_owner_review_pack_v1(
    output_directory: Path,
    pack: OwnerReviewPackV1,
) -> dict[str, Path]:
    try:
        root = validate_exclusive_local_directory_identity(output_directory)
    except CaptureStorageError:
        raise OwnerReviewPackError("OWNER_REVIEW_PACK_OUTPUT_UNSAFE") from None
    artifacts = {
        "owner_review_pack": pack,
        "owner_authorization_candidate": pack.owner_authorization_candidate,
        "activation_candidate": pack.activation_candidate,
        "plan_candidate": pack.plan_candidate,
        "plan_item_candidate": pack.plan_item_candidate,
        "campaign_selection": pack.campaign_selection,
        "fixture_target_set": pack.fixture_target_set,
        "provider_network_binding": pack.provider_network_binding,
        "mission_manifest": pack.mission_manifest,
        "workspace_receipt": pack.workspace_receipt,
        "request": pack.request,
    }
    paths: dict[str, Path] = {}
    for label, artifact in artifacts.items():
        digest = (
            pack.canonical_pack_hash
            if label == "owner_review_pack"
            else getattr(
                artifact,
                "canonical_authorization_hash",
                getattr(
                    artifact,
                    "canonical_activation_hash",
                    getattr(
                        artifact,
                        "canonical_plan_hash",
                        getattr(
                            artifact,
                            "canonical_item_hash",
                            getattr(
                                artifact,
                                "canonical_selection_hash",
                                getattr(
                                    artifact,
                                    "canonical_set_hash",
                                    getattr(
                                        artifact,
                                        "canonical_binding_hash",
                                        getattr(
                                            artifact,
                                            "canonical_receipt_hash",
                                            pack.mission_manifest_sha256
                                            if label == "mission_manifest"
                                            else pack.request_fingerprint_sha256,
                                        ),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            )
        )
        path = root / f"{label.replace('_', '-')}-{digest}.json"
        _write_immutable(
            path,
            canonical_json_bytes(artifact.model_dump(mode="json")) + b"\n",
        )
        paths[label] = path
    return paths


def write_owner_review_pack_v1(
    output_directory: Path,
    pack: OwnerReviewPackV1,
) -> dict[str, Path]:
    """Reject standalone publication of an Owner Review Pack."""

    raise OwnerReviewPackError("FIRST_C0_SINGLE_OWNER_ENTRYPOINT_REQUIRED")


def _write_first_c0_owner_review_pack_after_atomic_binding_v1(
    output_directory: Path,
    pack: OwnerReviewPackV1,
) -> dict[str, Path]:
    return _write_owner_review_pack_v1(output_directory, pack)


def owner_authorization_statement_v1(pack: OwnerReviewPackV1) -> str:
    authorization = pack.owner_authorization_candidate
    item = pack.plan_item_candidate
    selection = pack.campaign_selection
    if isinstance(selection, FirstC0CanarySelectionV1):
        canary_boundary = (
            f"SELECTION_SCHEMA={selection.schema_version}; "
            f"SELECTION_PURPOSE={selection.purpose}; "
            f"SINGLE_SPORT_KEY={selection.sport_key}; "
            f"SOURCE_TARGET_SET_COUNT={selection.source_target_set_count}; "
            f"PRODUCTION_SELECTION_AUTHORITY={str(selection.production_selection_authority).lower()}; "
            f"PROMOTION_AUTHORITY={str(selection.promotion_authority).lower()}; "
            f"BATCH_AUTHORITY={str(selection.batch_authority).lower()}; "
            f"SCIENTIFIC_EDGE_CLAIM={str(selection.scientific_edge_claim).lower()}; "
        )
    else:
        canary_boundary = ""
    return (
        "I authorize exactly one future bounded live capture under "
        f"BOOTSTRAP_CLOSURE_MAIN_SHA={pack.owner_authorization_candidate.authorized_main_sha}; "
        "OWNER_AUTHORIZATION_CANDIDATE_HASH="
        f"{pack.owner_authorization_candidate.canonical_authorization_hash}; "
        "EXPECTED_OWNER_AUTHORIZATION_HASH="
        f"{pack.expected_owner_authorization_sha256}; "
        f"ACTIVATION_CANDIDATE_HASH={pack.activation_candidate.canonical_activation_hash}; "
        f"OWNER_REVIEW_PACK_HASH={pack.canonical_pack_hash}; "
        f"MISSION_MANIFEST_HASH={pack.mission_manifest_sha256}; "
        f"{canary_boundary}"
        f"CAMPAIGN_SELECTION_HASH={pack.campaign_selection_sha256}; "
        f"SELECTED_CAMPAIGN_CANDIDATE_HASH={pack.selected_campaign_candidate_sha256}; "
        f"CAMPAIGN_WINDOW={pack.selected_campaign_window_id}; "
        f"CAMPAIGN_TEMPORAL_ROLE={pack.selected_campaign_temporal_role}; "
        "CAMPAIGN_PREDICTOR_PROTOCOLS="
        f"{','.join(pack.selected_campaign_predictor_protocol_ids) or 'NONE'}; "
        "CAMPAIGN_TARGET_PROTOCOLS="
        f"{','.join(pack.selected_campaign_target_protocol_ids) or 'NONE'}; "
        "PROVIDER_NETWORK_BINDING_HASH="
        f"{pack.provider_network_binding.canonical_binding_hash}; "
        f"SELECTED_PROVIDER_IP={pack.provider_network_binding.selected_ip_address}; "
        f"SPORT_KEY={item.sport_key}; REGION={item.region}; "
        f"MARKETS={','.join(item.markets)}; "
        f"HTTP_CALL_CEILING={authorization.maximum_http_calls}; "
        f"CREDIT_CEILING={authorization.maximum_credits}; "
        f"PLAN_ITEM_CEILING={authorization.maximum_plan_items}; "
        f"REQUEST_FINGERPRINT={pack.request_fingerprint_sha256}; "
        f"PLAN_HASH={pack.plan_candidate.canonical_plan_hash}; "
        f"PLAN_ITEM_HASH={item.canonical_item_hash}; "
        f"NOT_BEFORE_UTC={item.not_before_utc.isoformat().replace('+00:00', 'Z')}; "
        f"EXPIRES_AT_UTC={item.expires_at_utc.isoformat().replace('+00:00', 'Z')}; "
        f"FIXTURE_TARGET_SET_HASH={item.fixture_target_set_sha256}; "
        "SELECTED_FIXTURE_TARGET_IDS="
        f"{','.join(pack.selected_fixture_target_ids)}."
    )
