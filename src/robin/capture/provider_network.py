"""Owner-preparation DNS boundary for an immutable provider network binding."""

from __future__ import annotations

import os
import socket
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

from robin.capture import global_claim_boundary as global_claims
from robin.capture.bootstrap_contracts import (
    BOOTSTRAP_MISSION_ID,
    FIRST_C0_VERTICAL_MISSION_ID,
    MIN_OWNER_REVIEW_WINDOW,
    PRE_KICKOFF_SAFETY_MARGIN,
    PROVIDER_CANONICAL_HOSTNAME,
    CampaignSelectionAuthorityV1,
    FirstC0CanarySelectionV1,
    ProviderNetworkBindingV1,
    ProviderNetworkResolutionClaimV1,
    RealCaptureWorkspaceReceiptV1,
    RealExecutionMissionManifestV1,
)
from robin.capture.contracts import canonical_json_bytes, ensure_utc
from robin.capture.storage import (
    CaptureStorageError,
    _path_exists_no_follow,
    _reject_reparse_path,
    _safe_read_bounded,
    capture_root_fingerprint,
    exclusive_local_directory_fingerprint,
    validate_exclusive_local_directory_identity,
)

_RESOLUTION_CLAIM_NAME = "provider-network-resolution-one-shot-v1.json"
_FIRST_C0_CANARY_MINIMUM_PRE_DNS_MARGIN = timedelta(seconds=840)
_PROVIDER_RESOLUTION_RESERVATION_AUTHORITY_V1 = object()


class ProviderNetworkPreparationError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class _ProviderNetworkResolutionReservationV1:
    claim: ProviderNetworkResolutionClaimV1
    global_marker_name: str
    payload: bytes
    global_root_identity: tuple[object, ...]
    global_legacy_root_identity: tuple[object, ...]


class ResolverV1(Protocol):
    def __call__(
        self,
        host: str,
        port: int,
        family: int,
        socket_type: int,
        protocol: int,
    ) -> Iterable[tuple[Any, ...]]: ...


def _minimum_pre_dns_margin_v1(
    campaign_selection: CampaignSelectionAuthorityV1,
) -> timedelta:
    if isinstance(campaign_selection, FirstC0CanarySelectionV1):
        return _FIRST_C0_CANARY_MINIMUM_PRE_DNS_MARGIN
    return MIN_OWNER_REVIEW_WINDOW


def _system_getaddrinfo(
    host: str,
    port: int,
    family: int,
    socket_type: int,
    protocol: int,
) -> Iterable[tuple[Any, ...]]:
    return socket.getaddrinfo(host, port, family, socket_type, protocol)


def system_resolver_identity_v1() -> str:
    if os.name == "nt":
        return "WINDOWS_WINSOCK_SYSTEM_STUB_RESOLVER"
    if os.name == "posix":
        return "POSIX_LIBC_SYSTEM_STUB_RESOLVER"
    return "PYTHON_SOCKET_SYSTEM_STUB_RESOLVER"


def _prepare_provider_network_binding_after_reservation_v1(
    *,
    resolution_claim: ProviderNetworkResolutionClaimV1,
    resolver: ResolverV1 = _system_getaddrinfo,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    binding_ttl_seconds: int = 900,
    resolver_identity: str | None = None,
    maximum_expires_at_utc: datetime | None = None,
    minimum_binding_ttl_seconds: int = 1,
    observed_at_utc: datetime | None = None,
    _reservation_authority: object | None = None,
) -> ProviderNetworkBindingV1:
    """Resolve only after the durable reservation boundary has succeeded."""

    if _reservation_authority is not _PROVIDER_RESOLUTION_RESERVATION_AUTHORITY_V1:
        raise ProviderNetworkPreparationError("PROVIDER_NETWORK_RESOLUTION_RESERVATION_REQUIRED")
    if (
        not 1 <= binding_ttl_seconds <= 900
        or not 1 <= minimum_binding_ttl_seconds <= binding_ttl_seconds
    ):
        raise ProviderNetworkPreparationError("PROVIDER_NETWORK_BINDING_TTL_INVALID")
    observed_at = ensure_utc(
        observed_at_utc if observed_at_utc is not None else clock(),
        field="network_binding_observed_at",
    )
    if observed_at >= resolution_claim.mission_expires_at_utc:
        raise ProviderNetworkPreparationError("BOOTSTRAP_MISSION_EXPIRED")
    if (
        observed_at < resolution_claim.claimed_at_utc
        or observed_at - resolution_claim.claimed_at_utc > timedelta(minutes=1)
    ):
        raise ProviderNetworkPreparationError("PROVIDER_NETWORK_RESOLUTION_CLAIM_NOT_CURRENT")
    expiry_ceiling = resolution_claim.mission_expires_at_utc
    if maximum_expires_at_utc is not None:
        expiry_ceiling = min(
            expiry_ceiling,
            ensure_utc(maximum_expires_at_utc, field="network_binding_maximum_expires_at"),
        )
    available_whole_seconds = int((expiry_ceiling - observed_at).total_seconds())
    effective_ttl_seconds = min(binding_ttl_seconds, available_whole_seconds)
    if effective_ttl_seconds < minimum_binding_ttl_seconds:
        raise ProviderNetworkPreparationError("PROVIDER_NETWORK_OWNER_REVIEW_WINDOW_INSUFFICIENT")
    try:
        # This is the sole resolver operation.  No fallback invocation is permitted.
        answers = tuple(
            resolver(
                PROVIDER_CANONICAL_HOSTNAME,
                443,
                socket.AF_UNSPEC,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
            )
        )
    except (OSError, TypeError, ValueError):
        raise ProviderNetworkPreparationError("PROVIDER_NETWORK_RESOLUTION_FAILED") from None
    addresses: list[str] = []
    for answer in answers:
        if not isinstance(answer, tuple) or len(answer) < 5:
            raise ProviderNetworkPreparationError("PROVIDER_NETWORK_RESOLUTION_RESULT_INVALID")
        socket_address = answer[4]
        if not isinstance(socket_address, tuple) or not socket_address:
            raise ProviderNetworkPreparationError("PROVIDER_NETWORK_RESOLUTION_RESULT_INVALID")
        address = socket_address[0]
        if not isinstance(address, str):
            raise ProviderNetworkPreparationError("PROVIDER_NETWORK_RESOLUTION_RESULT_INVALID")
        addresses.append(address)
    try:
        return ProviderNetworkBindingV1.issue(
            resolution_claim=resolution_claim,
            resolver_identity=resolver_identity or system_resolver_identity_v1(),
            observed_at_utc=observed_at,
            expires_at_utc=observed_at + timedelta(seconds=effective_ttl_seconds),
            binding_ttl_seconds=effective_ttl_seconds,
            resolved_ip_addresses=tuple(addresses),
        )
    except ValueError:
        raise ProviderNetworkPreparationError("PROVIDER_NETWORK_BINDING_INVALID") from None


def _validated_control_destination(
    workspace_receipt: RealCaptureWorkspaceReceiptV1,
    output_path: Path,
) -> tuple[Path, Path]:
    try:
        control_root = validate_exclusive_local_directory_identity(
            Path(workspace_receipt.control_temp_root)
        )
        parent = validate_exclusive_local_directory_identity(output_path.absolute().parent)
        destination = parent / output_path.name
        _reject_reparse_path(destination)
    except (CaptureStorageError, OSError, ValueError):
        raise ProviderNetworkPreparationError("PROVIDER_NETWORK_OUTPUT_UNSAFE") from None
    if parent != control_root:
        raise ProviderNetworkPreparationError("PROVIDER_NETWORK_OUTPUT_OUTSIDE_CONTROL_TEMP")
    try:
        if (
            exclusive_local_directory_fingerprint(control_root)
            != workspace_receipt.control_temp_fingerprint
        ):
            raise ProviderNetworkPreparationError("PROVIDER_NETWORK_WORKSPACE_IDENTITY_CHANGED")
    except CaptureStorageError:
        raise ProviderNetworkPreparationError(
            "PROVIDER_NETWORK_WORKSPACE_IDENTITY_CHANGED"
        ) from None
    return control_root, destination


def _assert_workspace_root_identities_current(
    workspace_receipt: RealCaptureWorkspaceReceiptV1,
) -> None:
    try:
        observed = (
            exclusive_local_directory_fingerprint(Path(workspace_receipt.runtime_repository_root)),
            exclusive_local_directory_fingerprint(Path(workspace_receipt.control_temp_root)),
            capture_root_fingerprint(Path(workspace_receipt.capture_root)),
        )
    except (CaptureStorageError, OSError, ValueError):
        raise ProviderNetworkPreparationError(
            "PROVIDER_NETWORK_WORKSPACE_IDENTITY_CHANGED"
        ) from None
    expected = (
        workspace_receipt.repository_root_fingerprint,
        workspace_receipt.control_temp_fingerprint,
        workspace_receipt.capture_root_fingerprint,
    )
    if observed != expected:
        raise ProviderNetworkPreparationError("PROVIDER_NETWORK_WORKSPACE_IDENTITY_CHANGED")


def _assert_local_resolution_claim_current(
    workspace_receipt: RealCaptureWorkspaceReceiptV1,
    expected_payload: bytes,
) -> None:
    marker = Path(workspace_receipt.control_temp_root) / _RESOLUTION_CLAIM_NAME
    try:
        _validated_control_destination(workspace_receipt, marker)
        observed = _safe_read_bounded(
            marker,
            maximum_bytes=1_048_576,
        )
    except (CaptureStorageError, OSError, ValueError, ProviderNetworkPreparationError):
        raise ProviderNetworkPreparationError(
            "PROVIDER_NETWORK_RESOLUTION_CLAIM_NOT_CURRENT"
        ) from None
    if observed != expected_payload:
        raise ProviderNetworkPreparationError("PROVIDER_NETWORK_RESOLUTION_CLAIM_NOT_CURRENT")


def _write_resolution_claim_marker_v1(
    marker: Path,
    payload: bytes,
    *,
    failure_code: str,
) -> None:
    try:
        descriptor = os.open(
            marker,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOINHERIT", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            with os.fdopen(descriptor, "wb") as stream:
                descriptor = -1
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            if descriptor >= 0:
                os.close(descriptor)
    except FileExistsError:
        raise ProviderNetworkPreparationError(
            "PROVIDER_NETWORK_RESOLUTION_ALREADY_CONSUMED"
        ) from None
    except OSError:
        raise ProviderNetworkPreparationError(failure_code) from None


def _valid_provider_resolution_claim_marker_v2(
    payload: bytes,
    mission_manifest: RealExecutionMissionManifestV1,
) -> bool:
    try:
        parsed = ProviderNetworkResolutionClaimV1.model_validate_json(payload)
    except ValueError:
        return False
    return (
        canonical_json_bytes(parsed.model_dump(mode="json")) + b"\n" == payload
        and parsed.mission_id == mission_manifest.mission_id
        and parsed.mission_manifest_sha256 == mission_manifest.canonical_manifest_sha256()
        and parsed.mission_expires_at_utc == mission_manifest.expires_at
    )


def _reserve_provider_network_resolution_v1(
    *,
    workspace_receipt: RealCaptureWorkspaceReceiptV1,
    mission_manifest: RealExecutionMissionManifestV1,
    campaign_selection: CampaignSelectionAuthorityV1,
    output_path: Path,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    binding_ttl_seconds: int = 900,
    expected_global_v2_read_identity: tuple[object, ...],
    expected_global_legacy_root_identity: tuple[object, ...],
    first_c0_atomic_preflight_complete: bool,
) -> _ProviderNetworkResolutionReservationV1:
    """Durably consume the sole DNS attempt before the resolver can run."""

    if first_c0_atomic_preflight_complete is not True:
        raise ProviderNetworkPreparationError("FIRST_C0_ATOMIC_PREFLIGHT_REQUIRED")
    selection_mission_id = getattr(campaign_selection, "mission_id", BOOTSTRAP_MISSION_ID)
    if selection_mission_id == FIRST_C0_VERTICAL_MISSION_ID:
        try:
            mission_manifest.assert_first_c0_live_effect_ceiling()
        except ValueError:
            raise ProviderNetworkPreparationError(
                "FIRST_C0_VERTICAL_LIVE_EFFECT_CEILING_INVALID"
            ) from None
    if not 1 <= binding_ttl_seconds <= 900:
        raise ProviderNetworkPreparationError("PROVIDER_NETWORK_BINDING_TTL_INVALID")
    minimum_pre_dns_margin = _minimum_pre_dns_margin_v1(campaign_selection)
    if binding_ttl_seconds < int(minimum_pre_dns_margin.total_seconds()):
        raise ProviderNetworkPreparationError("PROVIDER_NETWORK_OWNER_REVIEW_WINDOW_INSUFFICIENT")
    control_root, destination = _validated_control_destination(workspace_receipt, output_path)
    if not workspace_receipt.authority_eligible_for_real_execution:
        raise ProviderNetworkPreparationError("WORKSPACE_IN_CLONE_VERIFY_REQUIRED")
    marker = control_root / _RESOLUTION_CLAIM_NAME
    if _path_exists_no_follow(destination):
        raise ProviderNetworkPreparationError("PROVIDER_NETWORK_BINDING_OUTPUT_EXISTS")
    claimed_at = ensure_utc(clock(), field="network_resolution_claimed_at")
    if claimed_at >= mission_manifest.expires_at:
        raise ProviderNetworkPreparationError("BOOTSTRAP_MISSION_EXPIRED")
    try:
        campaign_selection.assert_selected_candidate_current(claimed_at)
    except ValueError:
        raise ProviderNetworkPreparationError("CAMPAIGN_SELECTION_NOT_CURRENT") from None
    selected = campaign_selection.selected_candidate()
    earliest_kickoff = min(
        target.official_kickoff_utc for target in selected.fixture_target_set.targets
    )
    campaign_expiry_ceiling = min(
        mission_manifest.expires_at,
        selected.usable_expires_at_utc,
        earliest_kickoff - PRE_KICKOFF_SAFETY_MARGIN,
    )
    requested_expiry = claimed_at + timedelta(seconds=binding_ttl_seconds)
    if min(requested_expiry, campaign_expiry_ceiling) - claimed_at < minimum_pre_dns_margin:
        raise ProviderNetworkPreparationError("PROVIDER_NETWORK_OWNER_REVIEW_WINDOW_INSUFFICIENT")
    if (
        campaign_selection.workspace_receipt_sha256 != workspace_receipt.canonical_receipt_hash
        or campaign_selection.workspace_prepared_at_utc != workspace_receipt.prepared_at_utc
        or campaign_selection.mission_manifest_sha256
        != mission_manifest.canonical_manifest_sha256()
        or (
            isinstance(campaign_selection, FirstC0CanarySelectionV1)
            and selection_mission_id != mission_manifest.mission_id
        )
        or campaign_selection.mission_expires_at_utc != mission_manifest.expires_at
        or campaign_selection.selected_fixture_target_set_sha256
        != selected.fixture_target_set.canonical_set_hash
    ):
        raise ProviderNetworkPreparationError("CAMPAIGN_SELECTION_AUTHORITY_MISMATCH")
    claim = ProviderNetworkResolutionClaimV1.issue(
        mission_id=mission_manifest.mission_id,
        mission_manifest_sha256=mission_manifest.canonical_manifest_sha256(),
        workspace_receipt_sha256=workspace_receipt.canonical_receipt_hash,
        campaign_selection_sha256=campaign_selection.canonical_selection_hash,
        fixture_target_set_sha256=selected.fixture_target_set.canonical_set_hash,
        claimed_at_utc=claimed_at,
        mission_expires_at_utc=mission_manifest.expires_at,
    )
    payload = canonical_json_bytes(claim.model_dump(mode="json")) + b"\n"
    global_marker_name = (
        f"{mission_manifest.mission_id.casefold()}-"
        f"{mission_manifest.canonical_manifest_sha256()}.json"
    )

    try:
        global_reservation = global_claims.reserve_global_claim_marker_v2(
            workspace_receipt,
            global_marker_name,
            payload,
            validator=lambda existing: _valid_provider_resolution_claim_marker_v2(
                existing,
                mission_manifest,
            ),
            expected_v2_read_identity=expected_global_v2_read_identity,
            expected_legacy_root_identity=expected_global_legacy_root_identity,
        )
    except global_claims.GlobalClaimBoundaryError as error:
        raise ProviderNetworkPreparationError(error.code) from None
    _write_resolution_claim_marker_v1(
        marker,
        payload,
        failure_code="PROVIDER_NETWORK_RESOLUTION_CLAIM_FAILED",
    )
    return _ProviderNetworkResolutionReservationV1(
        claim=claim,
        global_marker_name=global_marker_name,
        payload=payload,
        global_root_identity=global_reservation.root_identity,
        global_legacy_root_identity=global_reservation.legacy_root_identity,
    )


def reserve_provider_network_resolution_v1(
    *,
    workspace_receipt: RealCaptureWorkspaceReceiptV1,
    mission_manifest: RealExecutionMissionManifestV1,
    campaign_selection: CampaignSelectionAuthorityV1,
    output_path: Path,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    binding_ttl_seconds: int = 900,
) -> ProviderNetworkResolutionClaimV1:
    """Reject direct reservation; the atomic owner path owns this effect."""

    raise ProviderNetworkPreparationError("FIRST_C0_ATOMIC_PREFLIGHT_REQUIRED")


def _reserve_first_c0_provider_network_resolution_after_atomic_preflight_v1(
    *,
    workspace_receipt: RealCaptureWorkspaceReceiptV1,
    mission_manifest: RealExecutionMissionManifestV1,
    campaign_selection: CampaignSelectionAuthorityV1,
    output_path: Path,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    binding_ttl_seconds: int = 900,
    expected_global_v2_read_identity: tuple[object, ...],
    expected_global_legacy_root_identity: tuple[object, ...],
) -> ProviderNetworkResolutionClaimV1:
    return _reserve_provider_network_resolution_v1(
        workspace_receipt=workspace_receipt,
        mission_manifest=mission_manifest,
        campaign_selection=campaign_selection,
        output_path=output_path,
        clock=clock,
        binding_ttl_seconds=binding_ttl_seconds,
        expected_global_v2_read_identity=expected_global_v2_read_identity,
        expected_global_legacy_root_identity=expected_global_legacy_root_identity,
        first_c0_atomic_preflight_complete=True,
    ).claim


def _prepare_provider_network_binding_once_v1(
    *,
    workspace_receipt: RealCaptureWorkspaceReceiptV1,
    mission_manifest: RealExecutionMissionManifestV1,
    campaign_selection: CampaignSelectionAuthorityV1,
    output_path: Path,
    resolver: ResolverV1 = _system_getaddrinfo,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    binding_ttl_seconds: int = 900,
    resolver_identity: str | None = None,
    expected_global_v2_read_identity: tuple[object, ...],
    expected_global_legacy_root_identity: tuple[object, ...],
    final_pre_effect_assertion: Callable[[], None],
    first_c0_atomic_preflight_complete: bool,
) -> ProviderNetworkBindingV1:
    """Reserve, resolve exactly once, and persist; any failure permanently forbids retry."""

    if first_c0_atomic_preflight_complete is not True:
        raise ProviderNetworkPreparationError("FIRST_C0_ATOMIC_PREFLIGHT_REQUIRED")
    reservation = _reserve_provider_network_resolution_v1(
        workspace_receipt=workspace_receipt,
        mission_manifest=mission_manifest,
        campaign_selection=campaign_selection,
        output_path=output_path,
        clock=clock,
        binding_ttl_seconds=binding_ttl_seconds,
        expected_global_v2_read_identity=expected_global_v2_read_identity,
        expected_global_legacy_root_identity=expected_global_legacy_root_identity,
        first_c0_atomic_preflight_complete=first_c0_atomic_preflight_complete,
    )
    claim = reservation.claim
    selected = campaign_selection.selected_candidate()
    earliest_kickoff = min(
        target.official_kickoff_utc for target in selected.fixture_target_set.targets
    )
    campaign_expiry_ceiling = min(
        mission_manifest.expires_at,
        selected.usable_expires_at_utc,
        earliest_kickoff - PRE_KICKOFF_SAFETY_MARGIN,
    )
    observed_at = ensure_utc(clock(), field="network_binding_observed_at")
    if observed_at >= mission_manifest.expires_at:
        raise ProviderNetworkPreparationError("BOOTSTRAP_MISSION_EXPIRED")
    if observed_at < claim.claimed_at_utc or observed_at - claim.claimed_at_utc > timedelta(
        minutes=1
    ):
        raise ProviderNetworkPreparationError("PROVIDER_NETWORK_RESOLUTION_CLAIM_NOT_CURRENT")
    try:
        campaign_selection.assert_selected_candidate_current(observed_at)
    except ValueError:
        raise ProviderNetworkPreparationError("CAMPAIGN_SELECTION_NOT_CURRENT") from None
    _validated_control_destination(workspace_receipt, output_path)
    try:
        global_claims.assert_global_claim_marker_current_v2(
            workspace_receipt,
            reservation.global_marker_name,
            reservation.payload,
            expected_root_identity=reservation.global_root_identity,
            expected_legacy_root_identity=reservation.global_legacy_root_identity,
            validator=lambda existing: _valid_provider_resolution_claim_marker_v2(
                existing,
                mission_manifest,
            ),
        )
    except global_claims.GlobalClaimBoundaryError as error:
        raise ProviderNetworkPreparationError(error.code) from None
    _assert_workspace_root_identities_current(workspace_receipt)
    _validated_control_destination(workspace_receipt, output_path)
    _assert_local_resolution_claim_current(workspace_receipt, reservation.payload)
    observed_at = ensure_utc(clock(), field="network_binding_observed_at")
    if observed_at >= mission_manifest.expires_at:
        raise ProviderNetworkPreparationError("BOOTSTRAP_MISSION_EXPIRED")
    if observed_at < claim.claimed_at_utc or observed_at - claim.claimed_at_utc > timedelta(
        minutes=1
    ):
        raise ProviderNetworkPreparationError("PROVIDER_NETWORK_RESOLUTION_CLAIM_NOT_CURRENT")
    try:
        campaign_selection.assert_selected_candidate_current(observed_at)
    except ValueError:
        raise ProviderNetworkPreparationError("CAMPAIGN_SELECTION_NOT_CURRENT") from None
    try:
        global_claims.assert_global_claim_marker_current_v2(
            workspace_receipt,
            reservation.global_marker_name,
            reservation.payload,
            expected_root_identity=reservation.global_root_identity,
            expected_legacy_root_identity=reservation.global_legacy_root_identity,
            validator=lambda existing: _valid_provider_resolution_claim_marker_v2(
                existing,
                mission_manifest,
            ),
        )
    except global_claims.GlobalClaimBoundaryError as error:
        raise ProviderNetworkPreparationError(error.code) from None
    _assert_workspace_root_identities_current(workspace_receipt)
    _validated_control_destination(workspace_receipt, output_path)
    _assert_local_resolution_claim_current(workspace_receipt, reservation.payload)
    try:
        # This assertion is the last callback before the sole resolver operation.
        # It binds historical evidence that the provider module cannot reconstruct
        # itself without importing the higher-level pre-DNS orchestration layer.
        final_pre_effect_assertion()
    except ProviderNetworkPreparationError:
        raise
    except Exception as error:
        code = getattr(error, "code", None)
        if not isinstance(code, str) or not code:
            code = "PROVIDER_NETWORK_FINAL_AUTHORITY_CHANGED"
        raise ProviderNetworkPreparationError(code) from None
    binding = _prepare_provider_network_binding_after_reservation_v1(
        resolution_claim=claim,
        resolver=resolver,
        clock=clock,
        binding_ttl_seconds=binding_ttl_seconds,
        resolver_identity=resolver_identity,
        maximum_expires_at_utc=campaign_expiry_ceiling,
        minimum_binding_ttl_seconds=int(
            _minimum_pre_dns_margin_v1(campaign_selection).total_seconds()
        ),
        observed_at_utc=observed_at,
        _reservation_authority=_PROVIDER_RESOLUTION_RESERVATION_AUTHORITY_V1,
    )
    write_immutable_network_binding_v1(binding, output_path)
    return binding


def prepare_provider_network_binding_once_v1(
    *,
    workspace_receipt: RealCaptureWorkspaceReceiptV1,
    mission_manifest: RealExecutionMissionManifestV1,
    campaign_selection: CampaignSelectionAuthorityV1,
    output_path: Path,
    resolver: ResolverV1 = _system_getaddrinfo,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    binding_ttl_seconds: int = 900,
    resolver_identity: str | None = None,
) -> ProviderNetworkBindingV1:
    """Reject direct binding; the atomic owner path owns this effect."""

    raise ProviderNetworkPreparationError("FIRST_C0_ATOMIC_PREFLIGHT_REQUIRED")


def _prepare_first_c0_provider_network_binding_once_after_atomic_preflight_v1(
    *,
    workspace_receipt: RealCaptureWorkspaceReceiptV1,
    mission_manifest: RealExecutionMissionManifestV1,
    campaign_selection: CampaignSelectionAuthorityV1,
    output_path: Path,
    resolver: ResolverV1 = _system_getaddrinfo,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    binding_ttl_seconds: int = 900,
    resolver_identity: str | None = None,
    expected_global_v2_read_identity: tuple[object, ...],
    expected_global_legacy_root_identity: tuple[object, ...],
    final_pre_effect_assertion: Callable[[], None],
) -> ProviderNetworkBindingV1:
    return _prepare_provider_network_binding_once_v1(
        workspace_receipt=workspace_receipt,
        mission_manifest=mission_manifest,
        campaign_selection=campaign_selection,
        output_path=output_path,
        resolver=resolver,
        clock=clock,
        binding_ttl_seconds=binding_ttl_seconds,
        resolver_identity=resolver_identity,
        expected_global_v2_read_identity=expected_global_v2_read_identity,
        expected_global_legacy_root_identity=expected_global_legacy_root_identity,
        final_pre_effect_assertion=final_pre_effect_assertion,
        first_c0_atomic_preflight_complete=True,
    )


def write_immutable_network_binding_v1(
    binding: ProviderNetworkBindingV1,
    output_path: Path,
) -> None:
    """Create one immutable artifact and refuse replacement or reparse traversal."""

    try:
        validated = ProviderNetworkBindingV1.model_validate(binding.model_dump(mode="json"))
        parent = validate_exclusive_local_directory_identity(output_path.parent)
        destination = parent / output_path.name
        _reject_reparse_path(destination)
        payload = canonical_json_bytes(validated.model_dump(mode="json")) + b"\n"
        descriptor = os.open(
            destination,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOINHERIT", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            with os.fdopen(descriptor, "wb") as stream:
                descriptor = -1
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            if descriptor >= 0:
                os.close(descriptor)
    except FileExistsError:
        raise ProviderNetworkPreparationError("PROVIDER_NETWORK_BINDING_OUTPUT_EXISTS") from None
    except (AttributeError, CaptureStorageError, OSError, TypeError, ValueError):
        raise ProviderNetworkPreparationError("PROVIDER_NETWORK_BINDING_WRITE_FAILED") from None


def default_binding_output_name(binding: ProviderNetworkBindingV1) -> str:
    return f"provider-network-binding-{binding.canonical_binding_hash}.json"
