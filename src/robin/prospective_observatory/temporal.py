"""Pre-registered capture windows and strict point-in-time semantics."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from robin.prospective_observatory.contracts import (
    AvailabilityStatus,
    CaptureFamily,
    CaptureReceipt,
    CaptureWindow,
    HistoricalSemanticStatus,
    ProspectiveFixture,
    RetryDisposition,
    canonical_sha256,
    ensure_utc,
)

WINDOW_POLICY_VERSION = "prospective-capture-window-v2"
VERSIONED_WINDOW_ID_PREFIX = "prospective-window-v3:"
LEGACY_VERSIONED_WINDOW_ID_PREFIXES = (
    "prospective-window-v1:",
    "prospective-window-v2:",
)
VERSIONED_WINDOW_ID_PREFIXES = (
    *LEGACY_VERSIONED_WINDOW_ID_PREFIXES,
    VERSIONED_WINDOW_ID_PREFIX,
)
# Scheduled workflows run no more frequently than hourly. Canonical H-2 and
# near-kickoff buckets therefore cover adjacent, non-overlapping intervals. The
# other, more widely spaced windows retain the symmetric operational tolerance.
DEFAULT_OPERATIONAL_TOLERANCE = timedelta(hours=1)


@dataclass(frozen=True, slots=True)
class WindowOffset:
    label: str
    before_kickoff: timedelta
    opens_before_kickoff: timedelta | None = None
    cutoff_before_kickoff: timedelta | None = None


_H2_WINDOW = WindowOffset(
    "H-2",
    timedelta(hours=2),
    opens_before_kickoff=timedelta(hours=3),
    cutoff_before_kickoff=timedelta(hours=1),
)
_NEAR_KICKOFF_WINDOW = WindowOffset(
    "NEAR_KICKOFF",
    timedelta(hours=1),
    opens_before_kickoff=timedelta(hours=1),
    cutoff_before_kickoff=timedelta(0),
)


_GENERAL_WINDOWS = (
    WindowOffset("J-21", timedelta(days=21)),
    WindowOffset("J-14", timedelta(days=14)),
    WindowOffset("J-7", timedelta(days=7)),
    WindowOffset("J-3", timedelta(days=3)),
    WindowOffset("J-1", timedelta(days=1)),
    WindowOffset("H-6", timedelta(hours=6)),
    _H2_WINDOW,
    _NEAR_KICKOFF_WINDOW,
)
_INJURY_WINDOWS = (
    WindowOffset("J-7", timedelta(days=7)),
    WindowOffset("J-3", timedelta(days=3)),
    WindowOffset("J-1", timedelta(days=1)),
    WindowOffset("H-6", timedelta(hours=6)),
    _H2_WINDOW,
    _NEAR_KICKOFF_WINDOW,
)
_PLAYER_WINDOWS = (
    WindowOffset("J-7", timedelta(days=7)),
    WindowOffset("J-3", timedelta(days=3)),
    WindowOffset("J-1", timedelta(days=1)),
)
_LINEUP_WINDOWS = (
    _H2_WINDOW,
    _NEAR_KICKOFF_WINDOW,
)
_ODDS_WINDOWS = (
    WindowOffset("J-7", timedelta(days=7)),
    WindowOffset("J-3", timedelta(days=3)),
    WindowOffset("J-1", timedelta(days=1)),
    WindowOffset("H-6", timedelta(hours=6)),
    _H2_WINDOW,
    _NEAR_KICKOFF_WINDOW,
)

CAPTURE_POLICIES: dict[CaptureFamily, tuple[WindowOffset, ...]] = {
    CaptureFamily.FIXTURE: _GENERAL_WINDOWS,
    CaptureFamily.TEAM: _GENERAL_WINDOWS,
    CaptureFamily.SQUAD: _PLAYER_WINDOWS,
    CaptureFamily.PLAYER_STATUS: _INJURY_WINDOWS,
    CaptureFamily.INJURY: _INJURY_WINDOWS,
    CaptureFamily.LINEUP: _LINEUP_WINDOWS,
    CaptureFamily.FORMATION: _LINEUP_WINDOWS,
    CaptureFamily.ODDS: _ODDS_WINDOWS,
    CaptureFamily.EVENT_STATUS: _GENERAL_WINDOWS,
}

# Immutable v1 topology retained only so a database can be rebuilt from old
# R2 receipts after the v2 policy has replaced these active windows.
_LEGACY_GENERAL_WINDOWS = (
    WindowOffset("J-21", timedelta(days=21)),
    WindowOffset("J-14", timedelta(days=14)),
    WindowOffset("J-7", timedelta(days=7)),
    WindowOffset("J-3", timedelta(days=3)),
    WindowOffset("J-1", timedelta(days=1)),
    WindowOffset("H-6", timedelta(hours=6)),
    WindowOffset("H-2", timedelta(hours=2)),
    WindowOffset("H-1", timedelta(hours=1)),
    WindowOffset("H-0:30", timedelta(minutes=30)),
)
_LEGACY_INJURY_WINDOWS = (
    WindowOffset("J-7", timedelta(days=7)),
    WindowOffset("J-3", timedelta(days=3)),
    WindowOffset("J-1", timedelta(days=1)),
    WindowOffset("H-6", timedelta(hours=6)),
    WindowOffset("H-2", timedelta(hours=2)),
    WindowOffset("H-1", timedelta(hours=1)),
)
_LEGACY_LINEUP_WINDOWS = (
    WindowOffset("H-2", timedelta(hours=2)),
    WindowOffset("H-1", timedelta(hours=1)),
    WindowOffset("H-0:45", timedelta(minutes=45)),
    WindowOffset("H-0:30", timedelta(minutes=30)),
    WindowOffset("H-0:15", timedelta(minutes=15)),
)
_LEGACY_ODDS_WINDOWS = (
    WindowOffset("J-7", timedelta(days=7)),
    WindowOffset("J-3", timedelta(days=3)),
    WindowOffset("J-1", timedelta(days=1)),
    WindowOffset("H-6", timedelta(hours=6)),
    WindowOffset("H-2", timedelta(hours=2)),
    WindowOffset("H-1", timedelta(hours=1)),
    WindowOffset("H-0:30", timedelta(minutes=30)),
)
_LEGACY_CAPTURE_POLICIES: dict[
    CaptureFamily,
    tuple[WindowOffset, ...],
] = {
    CaptureFamily.FIXTURE: _LEGACY_GENERAL_WINDOWS,
    CaptureFamily.TEAM: _LEGACY_GENERAL_WINDOWS,
    CaptureFamily.SQUAD: _PLAYER_WINDOWS,
    CaptureFamily.PLAYER_STATUS: _LEGACY_INJURY_WINDOWS,
    CaptureFamily.INJURY: _LEGACY_INJURY_WINDOWS,
    CaptureFamily.LINEUP: _LEGACY_LINEUP_WINDOWS,
    CaptureFamily.FORMATION: _LEGACY_LINEUP_WINDOWS,
    CaptureFamily.ODDS: _LEGACY_ODDS_WINDOWS,
    CaptureFamily.EVENT_STATUS: _LEGACY_GENERAL_WINDOWS,
}


def reconstructible_legacy_windows(
    fixture: ProspectiveFixture,
    family: CaptureFamily,
    *,
    scheduled_at: datetime,
    tolerance: timedelta = DEFAULT_OPERATIONAL_TOLERANCE,
) -> tuple[CaptureWindow, ...]:
    """Recreate inactive v1 windows solely for provider-free R2 recovery."""

    scheduled_at = ensure_utc(scheduled_at, field="scheduled_at")
    kickoff_at = ensure_utc(fixture.kickoff_at, field="kickoff_at")
    if tolerance < timedelta(0) or tolerance > timedelta(hours=1):
        raise ValueError("CAPTURE_WINDOW_TOLERANCE_OUT_OF_RANGE")
    windows: list[CaptureWindow] = []
    for offset in _LEGACY_CAPTURE_POLICIES[family]:
        due_at = kickoff_at - offset.before_kickoff
        opens_at = due_at - tolerance
        cutoff_at = min(
            due_at + tolerance,
            kickoff_at - timedelta(microseconds=1),
        )
        hash_body = {
            "fixture_registry_hash": fixture.registry_hash,
            "family": family.value,
            "label": offset.label,
            "due_at": due_at.isoformat(),
            "policy_version": "prospective-capture-window-v1",
        }
        for prefix in LEGACY_VERSIONED_WINDOW_ID_PREFIXES:
            windows.append(
                CaptureWindow(
                    window_id=prefix + canonical_sha256(hash_body),
                    fixture_id=fixture.fixture_id,
                    family=family,
                    label=offset.label,
                    due_at=due_at,
                    opens_at=opens_at,
                    cutoff_at=cutoff_at,
                    kickoff_at=kickoff_at,
                    scheduled_at=scheduled_at,
                    operational_tolerance_seconds=int(
                        tolerance.total_seconds()
                    ),
                    policy_version="prospective-capture-window-v1",
                    code_revision=fixture.code_revision,
                )
            )
    return tuple(windows)


def is_versioned_window_id(window_id: str) -> bool:
    """Return whether an identifier belongs to any immutable policy generation."""

    return window_id.startswith(VERSIONED_WINDOW_ID_PREFIXES)


def schedule_windows(
    fixture: ProspectiveFixture,
    family: CaptureFamily,
    *,
    scheduled_at: datetime,
    tolerance: timedelta = DEFAULT_OPERATIONAL_TOLERANCE,
) -> tuple[CaptureWindow, ...]:
    scheduled_at = ensure_utc(scheduled_at, field="scheduled_at")
    kickoff_at = ensure_utc(fixture.kickoff_at, field="kickoff_at")
    if tolerance < timedelta(0) or tolerance > timedelta(hours=1):
        raise ValueError("CAPTURE_WINDOW_TOLERANCE_OUT_OF_RANGE")
    windows: list[CaptureWindow] = []
    for offset in CAPTURE_POLICIES[family]:
        due_at = kickoff_at - offset.before_kickoff
        if (
            offset.opens_before_kickoff is None
            and offset.cutoff_before_kickoff is None
        ):
            opens_at = due_at - tolerance
            cutoff_at = due_at + tolerance
        elif (
            offset.opens_before_kickoff is not None
            and offset.cutoff_before_kickoff is not None
        ):
            opens_at = kickoff_at - offset.opens_before_kickoff
            cutoff_at = kickoff_at - offset.cutoff_before_kickoff
        else:
            raise ValueError("CAPTURE_WINDOW_CANONICAL_BOUNDS_INCOMPLETE")
        cutoff_at = min(cutoff_at, kickoff_at - timedelta(microseconds=1))
        # Bind the operational window to the complete immutable fixture
        # business version.  A provider correction to teams, phase, season or
        # kickoff must never allow an earlier window/receipt to certify the
        # corrected fixture.
        window_id = VERSIONED_WINDOW_ID_PREFIX + canonical_sha256(
            {
                "fixture_registry_hash": fixture.registry_hash,
                "family": family.value,
                "label": offset.label,
                "due_at": due_at.isoformat(),
                "policy_version": WINDOW_POLICY_VERSION,
            }
        )
        windows.append(
            CaptureWindow(
                window_id=window_id,
                fixture_id=fixture.fixture_id,
                family=family,
                label=offset.label,
                due_at=due_at,
                opens_at=opens_at,
                cutoff_at=cutoff_at,
                kickoff_at=kickoff_at,
                scheduled_at=scheduled_at,
                operational_tolerance_seconds=int(tolerance.total_seconds()),
                policy_version=WINDOW_POLICY_VERSION,
                code_revision=fixture.code_revision,
            )
        )
    return tuple(windows)


def classify_window(
    window: CaptureWindow,
    *,
    now: datetime,
    already_captured: bool = False,
) -> AvailabilityStatus:
    now = ensure_utc(now, field="now")
    if already_captured:
        return AvailabilityStatus.COMPLETE
    if now < window.opens_at:
        return AvailabilityStatus.NOT_DUE
    if window.opens_at <= now < window.cutoff_at:
        return AvailabilityStatus.DUE
    return AvailabilityStatus.MISSED_WINDOW


def temporal_admissibility(
    receipt: CaptureReceipt,
) -> AvailabilityStatus:
    if receipt.temporally_admissible:
        return AvailabilityStatus.COMPLETE
    return AvailabilityStatus.TEMPORALITY_FAILED


def retry_disposition(
    *,
    window: CaptureWindow,
    now: datetime,
    attempts: int,
    maximum_attempts: int = 3,
) -> RetryDisposition:
    now = ensure_utc(now, field="now")
    if attempts >= maximum_attempts:
        return RetryDisposition.RETRY_EXHAUSTED
    if now >= window.cutoff_at:
        return RetryDisposition.LATE_RETRY
    return RetryDisposition.RETRY_PENDING


def classify_historical_semantics(
    *,
    family: CaptureFamily,
    source_event_at: datetime | None,
    target_cutoff_at: datetime,
    retrieved_after_target: bool,
    safety_delay: timedelta = timedelta(hours=1),
) -> HistoricalSemanticStatus:
    cutoff = ensure_utc(target_cutoff_at, field="target_cutoff_at")
    if family in {CaptureFamily.INJURY, CaptureFamily.PLAYER_STATUS}:
        return HistoricalSemanticStatus.BLOCKED_BY_TEMPORALITY
    if family in {CaptureFamily.LINEUP, CaptureFamily.FORMATION} and retrieved_after_target:
        return HistoricalSemanticStatus.HISTORICAL_SEMANTIC_POST_LINEUP_EXPOSED
    if source_event_at is None:
        return HistoricalSemanticStatus.BLOCKED_BY_TEMPORALITY
    source = ensure_utc(source_event_at, field="source_event_at")
    if source + safety_delay < cutoff:
        return HistoricalSemanticStatus.HISTORICAL_EVENT_TIME_USABLE
    return HistoricalSemanticStatus.BLOCKED_BY_TEMPORALITY
