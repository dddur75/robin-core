from __future__ import annotations

import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from robin.capture.real_data_dashboard import (
    build_dashboard_snapshot,
    build_explorer_snapshot,
    compare_acquisitions,
    render_dashboard_html,
)
from robin.capture.recurring_real_data import RECURRING_CLAIM_IDS, SEED_CLAIM_IDS, _branch_stub

NOW = datetime(2026, 10, 4, 13, 0, tzinfo=UTC)


def _row(
    *,
    sport: str = "soccer_epl",
    event: str = "event-1",
    bookmaker: str = "book-a",
    market: str = "h2h",
    outcome: str = "Home",
    price: float = 2.0,
    point: float | None = None,
    capture: datetime = NOW - timedelta(hours=1),
) -> dict[str, object]:
    return {
        "slot_start_utc": "2026-10-04T12:00:00Z",
        "sport_key": sport,
        "sport_title": sport,
        "capture_time_utc": capture.isoformat().replace("+00:00", "Z"),
        "source_timestamp_utc": (capture - timedelta(minutes=2)).isoformat().replace("+00:00", "Z"),
        "event_id": event,
        "match": "Home — Away",
        "kickoff_utc": (NOW + timedelta(days=1)).isoformat().replace("+00:00", "Z"),
        "bookmaker_key": bookmaker,
        "bookmaker": bookmaker,
        "market_key": market,
        "outcome": outcome,
        "point": point,
        "price": price,
        "quota_remaining": 19_900,
    }


def _report(
    *,
    rows: list[dict[str, object]] | None = None,
    capture: datetime = NOW - timedelta(hours=1),
    status: str = "REAL_DATA_COMPLETE",
    diagnostic: dict[str, object] | None = None,
    limitations: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    observed_rows = rows if rows is not None else [_row(capture=capture)]
    branch_status = "INCOMPLETE" if diagnostic else "COMPLETE"
    return {
        "schema_version": "robin-autonomous-lab-private-report-v1",
        "mission_id": "ROBIN_AUTONOMOUS_LAB_20261004",
        "repository_sha": "a" * 40,
        "github_run_id": "40000000001",
        "claim_ids": list(RECURRING_CLAIM_IDS),
        "slot_start_utc": "2026-10-04T12:00:00Z",
        "generated_at_utc": capture.isoformat().replace("+00:00", "Z"),
        "status": status,
        "branches": [
            {
                "sport_key": "soccer_epl",
                "status": branch_status,
                "capture_time_utc": capture.isoformat().replace("+00:00", "Z"),
                "limitations": limitations or [],
                "diagnostic": diagnostic,
                "market_branch_coverage": {"h2h": 1, "totals": 0},
            }
        ],
        "rows": observed_rows,
        "row_count": len(observed_rows),
        "validated_capture_count": 1 if observed_rows else 0,
        "incomplete_branch_count": int(diagnostic is not None),
        "capture_times_utc": [capture.isoformat().replace("+00:00", "Z")] if observed_rows else [],
        "source_timestamp_min_utc": observed_rows[0]["source_timestamp_utc"]
        if observed_rows
        else None,
        "source_timestamp_max_utc": observed_rows[-1]["source_timestamp_utc"]
        if observed_rows
        else None,
        "match_count": len({row["event_id"] for row in observed_rows}),
        "bookmaker_count": len({row["bookmaker_key"] for row in observed_rows}),
        "market_branch_coverage": {"h2h": 1, "totals": 0},
        "market_outcome_row_counts": {
            "h2h": sum(row["market_key"] == "h2h" for row in observed_rows),
            "totals": sum(row["market_key"] == "totals" for row in observed_rows),
        },
        "market_limitation_counts": {
            "RESULT_MARKET_MISSING": sum(
                item.get("code") == "RESULT_MARKET_MISSING" for item in (limitations or [])
            ),
            "RESULT_MARKET_DUPLICATED": sum(
                item.get("code") == "RESULT_MARKET_DUPLICATED" for item in (limitations or [])
            ),
            "RESULT_MARKET_MISSING_OR_DUPLICATED": sum(
                item.get("code") == "RESULT_MARKET_MISSING_OR_DUPLICATED"
                for item in (limitations or [])
            ),
        },
        "provider_requests_new": 5,
        "provider_requests_reserved": 5,
        "provider_credits_reserved": 10,
        "accounting": {
            "rolling_24h_requests": 21,
            "rolling_24h_credits": 44,
            "rolling_30d_requests": 21,
            "rolling_30d_credits": 44,
            "lifetime_requests": 21,
            "lifetime_credits": 44,
            "provider_remaining_floor": 19_959,
        },
        "effect_accounting": {
            "automatic_retries": 0,
            "purchases": 0,
            "real_bets": 0,
            "backfills": 0,
            "promotions": 0,
        },
        "scientific_status": "DESCRIPTIVE_ONLY_NO_EDGE_VALIDATED",
    }


def test_freshness_collection_health_and_market_availability_are_separate() -> None:
    limitations = [
        {
            "code": "RESULT_MARKET_MISSING",
            "event_id": "event-1",
            "bookmaker_key": "book-a",
            "market_key": "totals",
        },
        {
            "code": "RESULT_MARKET_DUPLICATED",
            "event_id": "event-2",
            "bookmaker_key": "book-b",
            "market_key": "h2h",
        },
        {
            "code": "RESULT_MARKET_MISSING_OR_DUPLICATED",
            "event_id": "legacy",
            "bookmaker_key": "book-c",
            "market_key": "totals",
        },
    ]
    snapshot = build_dashboard_snapshot(
        _report(status="REAL_DATA_PARTIAL", limitations=limitations),
        previous_report=None,
        generated_at=NOW,
    )
    assert snapshot["claim_ids"] == list(RECURRING_CLAIM_IDS)
    assert snapshot["collection_health"] == "PARTIAL"
    assert snapshot["freshness"]["status"] == "FRESH"
    assert snapshot["market_availability"] == {
        "missing": 1,
        "duplicated": 1,
        "legacy_unknown": 1,
    }


def test_old_capture_is_stale_and_empty_capture_is_unavailable() -> None:
    stale = build_dashboard_snapshot(
        _report(capture=NOW - timedelta(hours=3, seconds=1)),
        previous_report=None,
        generated_at=NOW,
    )
    unavailable = build_dashboard_snapshot(
        _report(rows=[], status="REAL_DATA_FAILED"),
        previous_report=None,
        generated_at=NOW,
    )
    assert stale["freshness"]["status"] == "STALE"
    assert stale["freshness"]["age_seconds"] == 10_801
    assert unavailable["freshness"] == {
        "status": "UNAVAILABLE",
        "latest_capture_time_utc": None,
        "age_seconds": None,
        "freshness_limit_seconds": 10_800,
    }
    assert unavailable["collection_health"] == "FAILED"


def test_failed_current_slot_carries_last_usable_rows_as_explicitly_stale() -> None:
    previous = _report(capture=NOW - timedelta(hours=2))
    previous["slot_start_utc"] = "2026-10-04T10:00:00Z"
    failed = _report(
        rows=[],
        capture=NOW,
        status="REAL_DATA_FAILED",
        diagnostic={
            "stage": "DNS_RESOLUTION",
            "code": "RECURRING_DNS_RESOLUTION_FAILED",
            "exception_class": "RecurringError",
        },
    )
    snapshot = build_dashboard_snapshot(
        failed,
        previous_report=previous,
        generated_at=NOW,
    )
    assert snapshot["collection_health"] == "FAILED"
    assert snapshot["data_role"] == "CARRY_FORWARD_STALE"
    assert snapshot["data_slot_start_utc"] == "2026-10-04T10:00:00Z"
    assert snapshot["freshness"]["status"] == "STALE"
    assert len(snapshot["rows"]) == 1
    assert snapshot["rows"][0]["branch_status"] == "STALE"
    assert snapshot["comparison_available"] is False
    assert snapshot["price_movement"]["appeared_offer_count"] == 0
    assert snapshot["price_movement"]["not_observed_offer_count"] == 0
    assert snapshot["price_movement"]["current_only_offer_count"] == 1
    assert snapshot["explorer_rows"][0]["comparison_status"] == "STALE_CURRENT_ONLY"
    assert snapshot["incidents"][0]["code"] == "RECURRING_DNS_RESOLUTION_FAILED"
    rendered = render_dashboard_html(snapshot).decode("utf-8")
    assert "Dernières observations utilisables conservées" in rendered


def test_verified_empty_current_slot_never_carries_older_rows() -> None:
    current = _report(rows=[], status="REAL_DATA_COMPLETE", capture=NOW)
    current["validated_capture_count"] = 1
    current["capture_times_utc"] = [NOW.isoformat().replace("+00:00", "Z")]
    snapshot = build_dashboard_snapshot(
        current,
        previous_report=_report(capture=NOW - timedelta(hours=2)),
        generated_at=NOW,
    )
    assert snapshot["collection_health"] == "HEALTHY"
    assert snapshot["freshness"]["status"] == "FRESH"
    assert snapshot["data_role"] == "CURRENT"
    assert snapshot["rows"] == []


def test_coverage_has_explicit_offer_group_denominators() -> None:
    rows = [
        _row(event="event-1", market="h2h", outcome="Home"),
        _row(event="event-1", market="h2h", outcome="Draw"),
        _row(event="event-1", market="h2h", outcome="Away"),
        _row(event="event-1", market="totals", outcome="Over", point=2.5),
        _row(event="event-1", market="totals", outcome="Under", point=2.5),
        _row(event="event-2", market="h2h", outcome="Home"),
    ]
    limitations = [
        {
            "code": "RESULT_MARKET_MISSING",
            "event_id": "event-2",
            "bookmaker_key": "book-a",
            "market_key": "totals",
        }
    ]
    snapshot = build_dashboard_snapshot(
        _report(rows=rows, limitations=limitations),
        previous_report=None,
        generated_at=NOW,
    )
    coverage = snapshot["coverage"]
    assert coverage["soccer_epl"]["h2h"] == {
        "observed_offer_groups": 2,
        "eligible_bookmaker_event_groups": 2,
        "ratio": 1.0,
    }
    assert coverage["soccer_epl"]["totals"] == {
        "observed_offer_groups": 1,
        "eligible_bookmaker_event_groups": 2,
        "ratio": 0.5,
    }


def test_price_quantiles_are_hand_checked_and_grouped() -> None:
    rows = [
        _row(outcome="Home", price=1.0, event="event-1"),
        _row(outcome="Home", price=2.0, event="event-2"),
        _row(outcome="Home", price=3.0, event="event-3"),
        _row(outcome="Home", price=4.0, event="event-4"),
    ]
    snapshot = build_dashboard_snapshot(_report(rows=rows), previous_report=None, generated_at=NOW)
    distribution = snapshot["price_distribution"][0]
    assert distribution == {
        "market_key": "h2h",
        "outcome": "Home",
        "count": 4,
        "minimum": 1.0,
        "p25": 1.75,
        "median": 2.5,
        "p75": 3.25,
        "maximum": 4.0,
    }


def test_matched_offer_movements_do_not_invent_unmatched_changes() -> None:
    previous_capture = NOW - timedelta(hours=2)
    current_capture = NOW - timedelta(hours=1)
    previous = [
        _row(event="event-1", price=2.0, capture=previous_capture),
        _row(event="event-2", price=3.0, capture=previous_capture),
    ]
    current = [
        _row(event="event-1", price=2.2, capture=current_capture),
        _row(event="event-2", price=3.0, capture=current_capture),
        _row(event="event-3", price=9.0, capture=current_capture),
    ]
    previous_report = _report(rows=previous, capture=previous_capture)
    previous_report["claim_ids"] = list(SEED_CLAIM_IDS)
    snapshot = build_dashboard_snapshot(
        _report(rows=current, capture=current_capture),
        previous_report=previous_report,
        generated_at=NOW,
    )
    movement = snapshot["price_movement"]
    assert movement["matched_offer_count"] == 2
    assert movement["changed_offer_count"] == 1
    assert movement["unchanged_offer_count"] == 1
    assert movement["unmatched_current_count"] == 1
    assert movement["changes"][0]["delta"] == 0.2
    assert snapshot["claim_ids"] == [*RECURRING_CLAIM_IDS, *SEED_CLAIM_IDS]


def test_comparison_uses_exact_h2h_and_totals_offer_identities() -> None:
    previous_capture = NOW - timedelta(hours=2)
    current_capture = NOW - timedelta(hours=1)
    previous = [
        _row(event="event-1", market="h2h", outcome="Home", price=2.0, capture=previous_capture),
        _row(
            event="event-1",
            market="totals",
            outcome="Over",
            point=2.5,
            price=1.9,
            capture=previous_capture,
        ),
        _row(
            event="event-1",
            market="totals",
            outcome="Under",
            point=2.5,
            price=1.8,
            capture=previous_capture,
        ),
    ]
    current = [
        _row(event="event-1", market="h2h", outcome="Home", price=2.1, capture=current_capture),
        _row(
            event="event-1",
            market="totals",
            outcome="Over",
            point=2.5,
            price=1.85,
            capture=current_capture,
        ),
        _row(
            event="event-1",
            market="totals",
            outcome="Over",
            point=3.5,
            price=2.4,
            capture=current_capture,
        ),
    ]

    comparison = compare_acquisitions(current, previous)

    assert comparison["matched_offer_count"] == 2
    assert comparison["changed_offer_count"] == 2
    assert comparison["appeared_offer_count"] == 1
    assert comparison["not_observed_offer_count"] == 1
    assert comparison["excluded_row_count"] == 0
    assert comparison["changed_proportion"] == 1.0
    assert {row["point"] for row in comparison["matched_offers"]} == {None, 2.5}
    assert comparison["appeared_offers"][0]["point"] == 3.5
    assert comparison["not_observed_offers"][0]["outcome"] == "Under"


def test_comparison_excludes_duplicates_invalid_prices_and_unordered_branches() -> None:
    previous_capture = NOW - timedelta(hours=2)
    current_capture = NOW - timedelta(hours=1)
    duplicate = _row(event="duplicate", price=2.0, capture=previous_capture)
    previous = [
        duplicate,
        dict(duplicate),
        _row(event="invalid", price=2.0, capture=previous_capture),
        _row(
            sport="soccer_france_ligue_one",
            event="unordered",
            price=2.0,
            capture=current_capture,
        ),
    ]
    current = [
        _row(event="duplicate", price=2.1, capture=current_capture),
        _row(event="invalid", price=float("nan"), capture=current_capture),
        _row(
            sport="soccer_france_ligue_one",
            event="unordered",
            price=2.2,
            capture=previous_capture,
        ),
    ]

    comparison = compare_acquisitions(current, previous)

    assert comparison["matched_offer_count"] == 0
    assert comparison["appeared_offer_count"] == 0
    assert comparison["not_observed_offer_count"] == 0
    assert comparison["excluded_row_count"] == 7
    assert comparison["excluded_identity_count"] == 3
    assert comparison["exclusion_reason_counts"] == {
        "DUPLICATE_OFFER_IDENTITY": 3,
        "INVALID_PRICE": 2,
        "NON_FORWARD_BRANCH_TIME": 2,
    }


def test_comparison_excludes_sports_missing_from_either_acquisition() -> None:
    previous_capture = NOW - timedelta(hours=2)
    current_capture = NOW - timedelta(hours=1)
    previous = [
        _row(event="shared", capture=previous_capture),
        _row(
            sport="soccer_italy_serie_a",
            event="missing-branch",
            capture=previous_capture,
        ),
    ]
    current = [_row(event="shared", capture=current_capture)]

    comparison = compare_acquisitions(current, previous)

    assert comparison["matched_offer_count"] == 1
    assert comparison["not_observed_offer_count"] == 0
    assert comparison["excluded_row_count"] == 1
    assert comparison["exclusion_reason_counts"] == {"BRANCH_NOT_COMPARABLE": 1}


def test_comparison_does_not_infer_disappearances_from_an_unscoped_empty_current() -> None:
    previous = [_row(event="previous-only", capture=NOW - timedelta(hours=2))]

    comparison = compare_acquisitions([], previous)

    assert comparison["not_observed_offer_count"] == 0
    assert comparison["excluded_row_count"] == 1
    assert comparison["exclusion_reason_counts"] == {"BRANCH_NOT_COMPARABLE": 1}


def test_comparison_excludes_incomplete_public_branches() -> None:
    previous = _row(capture=NOW - timedelta(hours=2))
    current = _row(capture=NOW - timedelta(hours=1))
    previous["branch_status"] = "COMPLETE"
    current["branch_status"] = "INCOMPLETE"

    comparison = compare_acquisitions([current], [previous])

    assert comparison["matched_offer_count"] == 0
    assert comparison["excluded_row_count"] == 2
    assert comparison["exclusion_reason_counts"] == {"BRANCH_NOT_COMPARABLE": 2}


def test_comparison_refuses_different_provider_or_settlement_period_lineage() -> None:
    previous = _row(capture=NOW - timedelta(hours=2))
    current = _row(capture=NOW - timedelta(hours=1))
    previous.update(
        {
            "provider_key": "THE_ODDS_API_V4",
            "settlement_period_key": "PROVIDER_DEFAULT_UNSPECIFIED",
        }
    )
    current.update(
        {
            "provider_key": "OTHER_PROVIDER",
            "settlement_period_key": "PROVIDER_DEFAULT_UNSPECIFIED",
        }
    )

    comparison = compare_acquisitions([current], [previous])

    assert comparison["matched_offer_count"] == 0
    assert comparison["appeared_offer_count"] == 0
    assert comparison["not_observed_offer_count"] == 0
    assert comparison["excluded_row_count"] == 2
    assert comparison["exclusion_reason_counts"] == {"BRANCH_LINEAGE_INCOMPARABLE": 2}


def test_snapshot_uses_branch_receipts_to_exclude_incomplete_comparisons() -> None:
    previous_capture = NOW - timedelta(hours=2)
    current_capture = NOW - timedelta(hours=1)
    previous = _report(
        rows=[_row(capture=previous_capture)],
        capture=previous_capture,
    )
    current = _report(
        rows=[_row(capture=current_capture)],
        capture=current_capture,
        diagnostic={"stage": "BODY_READ", "code": "BRANCH_INCOMPLETE"},
    )

    snapshot = build_dashboard_snapshot(current, previous_report=previous, generated_at=NOW)

    movement = snapshot["price_movement"]
    assert snapshot["comparison_available"] is False
    assert movement["matched_offer_count"] == 0
    assert movement["not_observed_offer_count"] == 0
    assert movement["appeared_offer_count"] == 0
    assert movement["current_only_offer_count"] == 1
    assert snapshot["explorer_rows"][0]["comparison_status"] == "CURRENT_ONLY"


def test_comparison_reports_direction_amplitude_and_breakdowns() -> None:
    previous_capture = NOW - timedelta(hours=2)
    current_capture = NOW - timedelta(hours=1)
    previous = [
        _row(event="event-1", bookmaker="book-a", price=2.0, capture=previous_capture),
        _row(event="event-2", bookmaker="book-a", price=3.0, capture=previous_capture),
        _row(
            event="event-2",
            bookmaker="book-b",
            market="totals",
            outcome="Over",
            point=2.5,
            price=1.8,
            capture=previous_capture,
        ),
    ]
    current = [
        _row(event="event-1", bookmaker="book-a", price=2.2, capture=current_capture),
        _row(event="event-2", bookmaker="book-a", price=2.9, capture=current_capture),
        _row(
            event="event-2",
            bookmaker="book-b",
            market="totals",
            outcome="Over",
            point=2.5,
            price=1.8,
            capture=current_capture,
        ),
    ]

    comparison = compare_acquisitions(current, previous)

    assert comparison["direction_counts"] == {"UP": 1, "DOWN": 1, "UNCHANGED": 1}
    assert comparison["mean_absolute_delta"] == 0.1
    assert comparison["median_absolute_delta"] == 0.1
    assert comparison["maximum_absolute_delta"] == 0.2
    assert comparison["breakdowns"]["league"] == [
        {
            "key": "soccer_epl",
            "matched_offer_count": 3,
            "distinct_match_count": 2,
            "changed_offer_count": 2,
            "changed_proportion": 0.666667,
            "up_count": 1,
            "down_count": 1,
            "unchanged_count": 1,
            "mean_absolute_delta": 0.1,
        }
    ]
    assert [item["key"] for item in comparison["breakdowns"]["bookmaker"]] == [
        "book-a",
        "book-b",
    ]
    assert [item["key"] for item in comparison["breakdowns"]["market"]] == [
        "h2h",
        "totals",
    ]


def test_snapshot_exposes_one_explorer_row_model_for_both_acquisitions() -> None:
    previous_capture = NOW - timedelta(hours=2)
    current_capture = NOW - timedelta(hours=1)
    previous = _report(
        rows=[
            _row(event="matched", price=2.0, capture=previous_capture),
            _row(event="missing", price=3.0, capture=previous_capture),
        ],
        capture=previous_capture,
    )
    previous["slot_start_utc"] = "2026-10-04T10:00:00Z"
    current = _report(
        rows=[
            _row(event="matched", price=2.2, capture=current_capture),
            _row(event="appeared", price=4.0, capture=current_capture),
        ],
        capture=current_capture,
    )

    snapshot = build_dashboard_snapshot(current, previous_report=previous, generated_at=NOW)

    assert [row["comparison_status"] for row in snapshot["explorer_rows"]] == [
        "MATCHED_CHANGED",
        "APPEARED",
        "NOT_OBSERVED",
    ]
    matched = snapshot["explorer_rows"][0]
    assert matched["previous_slot_start_utc"] == "2026-10-04T12:00:00Z"
    assert matched["current_slot_start_utc"] == "2026-10-04T12:00:00Z"
    assert matched["previous_price"] == 2.0
    assert matched["current_price"] == 2.2
    assert matched["delta"] == 0.2
    assert matched["kickoff_utc"]


def test_explorer_snapshot_upgrades_two_verified_public_snapshots() -> None:
    previous = build_dashboard_snapshot(
        _report(
            rows=[_row(event="same", price=2.0, capture=NOW - timedelta(hours=2))],
            capture=NOW - timedelta(hours=2),
        ),
        previous_report=None,
        generated_at=NOW - timedelta(hours=2),
    )
    current = build_dashboard_snapshot(
        _report(
            rows=[_row(event="same", price=2.3, capture=NOW - timedelta(hours=1))],
            capture=NOW - timedelta(hours=1),
        ),
        previous_report=None,
        generated_at=NOW - timedelta(hours=1),
    )

    upgraded = build_explorer_snapshot(current, previous, generated_at=NOW)

    assert upgraded["schema_version"] == "robin-real-data-explorer-v2"
    assert upgraded["generated_at_utc"] == "2026-10-04T13:00:00Z"
    assert upgraded["price_movement"]["changed_offer_count"] == 1
    assert upgraded["explorer_rows"][0]["previous_price"] == 2.0
    assert upgraded["explorer_rows"][0]["current_price"] == 2.3


def test_first_snapshot_is_current_only_not_an_unproved_appearance() -> None:
    current = build_dashboard_snapshot(
        _report(rows=[_row(event="current-only")]),
        previous_report=None,
        generated_at=NOW,
    )

    assert current["comparison_available"] is False
    assert current["price_movement"]["appeared_offer_count"] == 0
    assert current["price_movement"]["current_only_offer_count"] == 1
    assert current["explorer_rows"][0]["comparison_status"] == "CURRENT_ONLY"


def test_current_only_snapshot_excludes_duplicate_invalid_identity_and_invalid_price() -> None:
    duplicate = _row(event="duplicate")
    invalid_price = _row(event="invalid-price", price=0.0)
    invalid_total = _row(event="invalid-total", market="totals", outcome="Over")
    current = build_dashboard_snapshot(
        _report(
            rows=[
                _row(event="valid"),
                duplicate,
                dict(duplicate),
                invalid_price,
                invalid_total,
            ]
        ),
        previous_report=None,
        generated_at=NOW,
    )

    movement = current["price_movement"]
    assert movement["current_only_offer_count"] == 1
    assert movement["excluded_row_count"] == 4
    assert movement["exclusion_reason_counts"] == {
        "DUPLICATE_OFFER_IDENTITY": 2,
        "INVALID_OFFER_IDENTITY": 1,
        "INVALID_PRICE": 1,
    }
    assert [row["event_id"] for row in current["explorer_rows"]] == ["valid"]


def test_verified_empty_branch_can_prove_non_observation_with_shared_coverage() -> None:
    previous = build_dashboard_snapshot(
        _report(
            rows=[_row(event="previous", capture=NOW - timedelta(hours=2))],
            capture=NOW - timedelta(hours=2),
        ),
        previous_report=None,
        generated_at=NOW - timedelta(hours=2),
    )
    current_report = _report(rows=[], capture=NOW - timedelta(hours=1))
    current_report["validated_capture_count"] = 1
    current_report["capture_times_utc"] = [(NOW - timedelta(hours=1)).isoformat()]
    current = build_dashboard_snapshot(
        current_report,
        previous_report=None,
        generated_at=NOW - timedelta(hours=1),
    )

    upgraded = build_explorer_snapshot(current, previous, generated_at=NOW)

    assert upgraded["comparison_available"] is True
    assert upgraded["price_movement"]["not_observed_offer_count"] == 1
    assert upgraded["explorer_rows"][0]["comparison_status"] == "NOT_OBSERVED"


def test_empty_branch_cannot_claim_disappearance_before_previous_observation() -> None:
    previous_capture = NOW - timedelta(minutes=30)
    previous_report = _report(
        rows=[_row(event="previous", capture=previous_capture)],
        capture=previous_capture,
    )
    previous_branch = previous_report["branches"][0]
    previous_branch.update(
        {
            "provider_key": "THE_ODDS_API_V4",
            "settlement_period_key": "PROVIDER_DEFAULT_UNSPECIFIED",
            "acquisition_started_at_utc": (previous_capture - timedelta(minutes=1))
            .isoformat()
            .replace("+00:00", "Z"),
            "acquisition_finished_at_utc": (previous_capture + timedelta(minutes=1))
            .isoformat()
            .replace("+00:00", "Z"),
        }
    )
    previous_report["rows"][0].update(
        {
            "provider_key": "THE_ODDS_API_V4",
            "settlement_period_key": "PROVIDER_DEFAULT_UNSPECIFIED",
        }
    )
    previous = build_dashboard_snapshot(
        previous_report,
        previous_report=None,
        generated_at=previous_capture,
    )
    current_capture = NOW - timedelta(minutes=45)
    current_report = _report(rows=[], capture=current_capture)
    current_report["validated_capture_count"] = 1
    current_report["branches"][0].update(
        {
            "provider_key": "THE_ODDS_API_V4",
            "settlement_period_key": "PROVIDER_DEFAULT_UNSPECIFIED",
            "acquisition_started_at_utc": (current_capture - timedelta(minutes=1))
            .isoformat()
            .replace("+00:00", "Z"),
            "acquisition_finished_at_utc": (current_capture + timedelta(minutes=1))
            .isoformat()
            .replace("+00:00", "Z"),
        }
    )
    current = build_dashboard_snapshot(
        current_report,
        previous_report=None,
        generated_at=current_capture,
    )

    upgraded = build_explorer_snapshot(current, previous, generated_at=NOW)

    assert upgraded["comparison_available"] is True
    movement = upgraded["price_movement"]
    assert movement["not_observed_offer_count"] == 0
    assert movement["exclusion_reason_counts"] == {"NON_FORWARD_BRANCH_TIME": 1}


def test_empty_v2_branch_cannot_claim_v1_offer_disappeared() -> None:
    previous = build_dashboard_snapshot(
        _report(
            rows=[_row(event="previous", capture=NOW - timedelta(hours=2))],
            capture=NOW - timedelta(hours=2),
        ),
        previous_report=None,
        generated_at=NOW - timedelta(hours=2),
    )
    current_report = _report(rows=[], capture=NOW - timedelta(hours=1))
    current_report["validated_capture_count"] = 1
    current_branch = current_report["branches"][0]
    current_branch.update(
        {
            "provider_key": "THE_ODDS_API_V4",
            "settlement_period_key": "PROVIDER_DEFAULT_UNSPECIFIED",
        }
    )
    current = build_dashboard_snapshot(
        current_report,
        previous_report=None,
        generated_at=NOW - timedelta(hours=1),
    )

    upgraded = build_explorer_snapshot(current, previous, generated_at=NOW)

    assert upgraded["comparison_available"] is False
    movement = upgraded["price_movement"]
    assert movement["not_observed_offer_count"] == 0
    assert movement["current_only_offer_count"] == 0
    assert movement["comparison_unavailable_reason"] == "BRANCH_LINEAGE_INCOMPARABLE"
    assert movement["comparison_unavailable_row_count"] == 1


def test_v1_to_v2_provenance_transition_keeps_current_offer_visible() -> None:
    previous = build_dashboard_snapshot(
        _report(
            rows=[_row(event="same", price=2.0, capture=NOW - timedelta(hours=2))],
            capture=NOW - timedelta(hours=2),
        ),
        previous_report=None,
        generated_at=NOW - timedelta(hours=2),
    )
    current_report = _report(
        rows=[_row(event="same", price=2.3, capture=NOW - timedelta(hours=1))],
        capture=NOW - timedelta(hours=1),
    )
    current_report["branches"][0].update(
        {
            "provider_key": "THE_ODDS_API_V4",
            "settlement_period_key": "PROVIDER_DEFAULT_UNSPECIFIED",
        }
    )
    current_report["rows"][0].update(
        {
            "provider_key": "THE_ODDS_API_V4",
            "settlement_period_key": "PROVIDER_DEFAULT_UNSPECIFIED",
        }
    )
    current = build_dashboard_snapshot(
        current_report,
        previous_report=None,
        generated_at=NOW - timedelta(hours=1),
    )

    upgraded = build_explorer_snapshot(current, previous, generated_at=NOW)

    assert upgraded["comparison_available"] is False
    movement = upgraded["price_movement"]
    assert movement["matched_offer_count"] == 0
    assert movement["changed_offer_count"] == 0
    assert movement["current_only_offer_count"] == 1
    assert movement["comparison_unavailable_reason"] == "BRANCH_LINEAGE_INCOMPARABLE"
    assert movement["comparison_unavailable_row_count"] == 2
    assert len(upgraded["explorer_rows"]) == 1
    assert upgraded["explorer_rows"][0]["comparison_status"] == "CURRENT_ONLY"
    assert upgraded["explorer_rows"][0]["current_price"] == 2.3


def test_direct_producer_v1_to_v2_transition_keeps_current_offer_visible() -> None:
    previous_report = _report(
        rows=[_row(event="same", price=2.0, capture=NOW - timedelta(hours=2))],
        capture=NOW - timedelta(hours=2),
    )
    current_report = _report(
        rows=[_row(event="same", price=2.3, capture=NOW - timedelta(hours=1))],
        capture=NOW - timedelta(hours=1),
    )
    current_report["branches"][0].update(
        {
            "provider_key": "THE_ODDS_API_V4",
            "settlement_period_key": "PROVIDER_DEFAULT_UNSPECIFIED",
        }
    )
    current_report["rows"][0].update(
        {
            "provider_key": "THE_ODDS_API_V4",
            "settlement_period_key": "PROVIDER_DEFAULT_UNSPECIFIED",
        }
    )

    snapshot = build_dashboard_snapshot(
        current_report,
        previous_report=previous_report,
        generated_at=NOW,
    )

    assert snapshot["comparison_available"] is False
    movement = snapshot["price_movement"]
    assert movement["matched_offer_count"] == 0
    assert movement["changed_offer_count"] == 0
    assert movement["current_only_offer_count"] == 1
    assert movement["comparison_unavailable_reason"] == "BRANCH_LINEAGE_INCOMPARABLE"
    assert movement["comparison_unavailable_row_count"] == 2
    assert len(snapshot["explorer_rows"]) == 1
    assert snapshot["explorer_rows"][0]["comparison_status"] == "CURRENT_ONLY"
    assert snapshot["explorer_rows"][0]["current_price"] == 2.3


def test_empty_incomplete_branch_cannot_prove_non_observation() -> None:
    previous = build_dashboard_snapshot(
        _report(
            rows=[_row(event="previous", capture=NOW - timedelta(hours=2))],
            capture=NOW - timedelta(hours=2),
        ),
        previous_report=None,
        generated_at=NOW - timedelta(hours=2),
    )
    current = build_dashboard_snapshot(
        _report(
            rows=[],
            capture=NOW - timedelta(hours=1),
            diagnostic={"stage": "BODY_READ", "code": "BRANCH_INCOMPLETE"},
        ),
        previous_report=None,
        generated_at=NOW - timedelta(hours=1),
    )

    upgraded = build_explorer_snapshot(current, previous, generated_at=NOW)

    assert current["comparable_branch_sports"] == []
    assert upgraded["comparison_available"] is False
    assert upgraded["price_movement"]["not_observed_offer_count"] == 0
    assert upgraded["explorer_rows"] == []


def test_html_is_self_contained_paginated_searchable_and_safe() -> None:
    malicious = _row()
    malicious["match"] = "</script><img src=x onerror=alert(1)>"
    snapshot = build_dashboard_snapshot(
        _report(rows=[malicious]), previous_report=None, generated_at=NOW
    )
    rendered = render_dashboard_html(snapshot, csv_filename="robin-real-data.csv")
    html = rendered.decode("utf-8")
    assert "<script src=" not in html
    assert 'id="search"' in html
    assert 'id="league-filter"' in html
    assert 'id="market-filter"' in html
    assert "Provenance des métriques" in html
    assert RECURRING_CLAIM_IDS[0] in html
    assert 'id="bookmaker-filter"' in html
    assert 'id="capture-filter"' in html
    assert 'id="status-filter"' in html
    assert 'id="odds-min"' in html
    assert 'id="odds-max"' in html
    assert 'id="delta-min"' in html
    assert 'id="delta-max"' in html
    assert 'id="sort-field"' in html
    assert 'id="sort-direction"' in html
    assert 'id="reset-filters"' in html
    assert 'id="export-filtered-csv"' in html
    assert 'id="export-filtered-json"' in html
    assert 'id="previous-page"' in html
    assert 'id="next-page"' in html
    assert 'id="freshness-status"' in html
    assert 'id="freshness-detail"' in html
    assert 'id="local-refresh-status"' in html
    assert 'id="new-run-notice"' in html
    assert "function refreshFreshness" in html
    assert "Date.now()" in html
    assert "freshness_limit_seconds" in html
    assert "function pollForNewRun" in html
    assert 'fetch("/status.json"' in html
    assert "status.last_error_code" in html
    assert "Actualisation locale en échec" in html
    assert "Nouvelle capture disponible" in html
    assert "Comparaison indisponible : transition de provenance" in html
    assert 'location.pathname.startsWith("/history/")' in html
    assert "current!==LOADED_RUN_ID" in html
    assert "location.reload()" in html
    assert "sessionStorage.setItem" in html
    assert "restoreFilterState()" in html
    assert "function selectRows" in html
    assert "function exportFilteredCsv" in html
    assert "function exportFilteredJson" in html
    assert "function downloadSelection" not in html
    assert "const exportRows=filtered.slice()" in html
    assert 'id="export-filtered-csv" type="submit"' in html
    assert 'id="export-filtered-json" type="submit"' in html
    assert 'byId("export-filtered-csv").addEventListener("click",' in html
    assert 'byId("export-filtered-json").addEventListener("click",' in html
    assert "saveFilterState();exportFilteredCsv()" in html
    assert "saveFilterState();exportFilteredJson()" in html
    assert "URL.createObjectURL(blob)" not in html
    assert 'method="post"' in html
    assert 'formaction="/export.csv"' in html
    assert 'formaction="/export.json"' in html
    assert 'id="export-content"' in html
    assert "previous_price" in html
    assert "current_price" in html
    assert "kickoff_utc" in html
    assert "previous_slot_start_utc" in html
    assert "previous_source_timestamp_utc" in html
    assert "current_slot_start_utc" in html
    assert "current_source_timestamp_utc" in html
    assert "Début · fin · capture · source" in html
    assert "previous_acquisition_started_at_utc" in html
    assert "current_acquisition_finished_at_utc" in html
    assert "Europe/Paris" in html
    assert "function formatInstant" in html
    assert "const PAGE_SIZE = 100" in html
    assert "Aucun edge n’est validé" in html
    assert "Instants conservés en UTC" in html
    assert html.index("void pollForNewRun();") < html.index("setInterval(")
    assert "</script><img" not in html
    escaped_closing_script = "\\u003c" + "/script" + "\\u003e"
    assert escaped_closing_script in html
    assert html.count("<tbody") == 1
    assert html.count("<tr") < 20


def test_narrow_viewport_exposes_comparison_as_labeled_cards() -> None:
    snapshot = build_dashboard_snapshot(
        _report(rows=[_row()]), previous_report=None, generated_at=NOW
    )

    html = render_dashboard_html(snapshot).decode("utf-8")

    assert 'class="narrow-table-help"' in html
    assert "sans défilement horizontal" in html
    assert "const TABLE_LABELS =" in html
    assert "const NARROW_PAGE_SIZE = 25" in html
    assert "function currentPageSize()" in html
    assert 'const pageMedia=window.matchMedia("(max-width:620px)")' in html
    assert 'pageMedia.addEventListener("change",()=>{page=0;renderRows();})' in html
    assert "td.dataset.label=TABLE_LABELS[index]" in html
    assert "td::before{content:attr(data-label)" in html
    assert "thead{display:none}" in html
    assert "tbody tr{display:block" in html
    assert html.index("<th>Bookmaker</th>") < html.index("<th>Ancienne cote</th>")
    assert html.index("<th>Nouvelle cote</th>") < html.index("<th>Acquisition précédente")


def test_partial_incident_and_empty_filter_state_are_visible() -> None:
    snapshot = build_dashboard_snapshot(
        _report(
            status="REAL_DATA_PARTIAL",
            diagnostic={
                "stage": "BODY_READ",
                "code": "LIVE_TRANSPORT_DISPATCH_FAILED",
                "exception_class": "OSError",
                "errno": 9,
                "http_status": 200,
            },
        ),
        previous_report=None,
        generated_at=NOW,
    )
    html = render_dashboard_html(snapshot).decode("utf-8")
    assert "LIVE_TRANSPORT_DISPATCH_FAILED" in html
    assert "Aucune observation ne correspond aux filtres" in html
    assert "Panne de collecte" in html
    assert "Marché absent" in html


_FAILURE_DIAGNOSTIC = {
    "stage": "PROVIDER_ACCESS",
    "code": "LIVE_PROVIDER_FAILURE",
    "exception_class": "RecurringError",
}


def _two_league_report(*, capture: datetime, failed: bool) -> dict[str, object]:
    healthy = _row(capture=capture)
    report = _report(rows=[healthy], capture=capture)
    branches = report["branches"]
    assert isinstance(branches, list)
    branches[0].update(provider_key="the_odds_api", settlement_period_key="full_time")
    if failed:
        branch = _branch_stub("soccer_spain_la_liga", source="LIVE", diagnostic=_FAILURE_DIAGNOSTIC)
        report.update(status="REAL_DATA_PARTIAL", incomplete_branch_count=1)
    else:
        branch = dict(branches[0], sport_key="soccer_spain_la_liga")
        rows = report["rows"]
        assert isinstance(rows, list)
        rows.append(_row(sport="soccer_spain_la_liga", capture=capture))
    branches.append(branch)
    return report


@pytest.mark.parametrize(
    "current_failed,previous_failed", [(True, False), (False, True), (True, True)]
)
def test_failed_branch_without_capture_time_is_reported_never_compared(
    current_failed: bool, previous_failed: bool
) -> None:
    current = _two_league_report(capture=NOW, failed=current_failed)
    previous = _two_league_report(capture=NOW - timedelta(hours=2), failed=previous_failed)
    snapshot = build_dashboard_snapshot(current, previous_report=previous, generated_at=NOW)
    movement = snapshot["price_movement"]
    assert movement["matched_offer_count"] == 1
    assert movement["appeared_offer_count"] == movement["not_observed_offer_count"] == 0
    assert movement["exclusion_reason_counts"] == (
        {} if current_failed and previous_failed else {"BRANCH_NOT_COMPARABLE": 1}
    )
    for failed, report in ((current_failed, current), (previous_failed, previous)):
        if not failed:
            continue
        failed_snapshot = build_dashboard_snapshot(report, previous_report=None, generated_at=NOW)
        assert failed_snapshot["collection_health"] == "PARTIAL"
        assert failed_snapshot["summary"]["incomplete_branch_count"] == 1
        assert failed_snapshot["incidents"] == [
            dict(_FAILURE_DIAGNOSTIC, sport_key="soccer_spain_la_liga")
        ]
        branch = next(
            b for b in failed_snapshot["branch_lineage"] if b["sport_key"] == "soccer_spain_la_liga"
        )
        assert branch["capture_time_utc"] is None


@pytest.mark.parametrize(
    "current_failed,previous_failed", [(True, False), (False, True), (True, True)]
)
def test_failed_branch_without_time_is_compared_like_a_failed_branch_with_time(
    current_failed: bool, previous_failed: bool
) -> None:
    current = _two_league_report(capture=NOW, failed=current_failed)
    previous = _two_league_report(capture=NOW - timedelta(hours=2), failed=previous_failed)
    expected_current, expected_previous = deepcopy(current), deepcopy(previous)
    for failed, report, capture in (
        (current_failed, expected_current, NOW),
        (previous_failed, expected_previous, NOW - timedelta(hours=2)),
    ):
        if failed:
            branch = report["branches"][1]
            branch["capture_time_utc"] = capture.isoformat().replace("+00:00", "Z")
            branch["diagnostic"] = dict(_FAILURE_DIAGNOSTIC, code="LIVE_STORAGE_FAILURE")
    actual = build_dashboard_snapshot(current, previous_report=previous, generated_at=NOW)
    expected = build_dashboard_snapshot(
        expected_current, previous_report=expected_previous, generated_at=NOW
    )
    assert actual["price_movement"] == expected["price_movement"]
    assert actual["explorer_rows"] == expected["explorer_rows"]


@pytest.mark.parametrize("current_failed", [True, False])
def test_explorer_snapshot_accepts_a_public_branch_without_capture_time(
    current_failed: bool,
) -> None:
    current = build_dashboard_snapshot(
        _two_league_report(capture=NOW, failed=current_failed),
        previous_report=None,
        generated_at=NOW,
    )
    previous = build_dashboard_snapshot(
        _two_league_report(capture=NOW - timedelta(hours=2), failed=not current_failed),
        previous_report=None,
        generated_at=NOW,
    )
    snapshot = build_explorer_snapshot(current, previous, generated_at=NOW)
    assert snapshot["comparison_available"] is True
    assert snapshot["price_movement"]["matched_offer_count"] == 1
    assert snapshot["price_movement"]["exclusion_reason_counts"] == {"BRANCH_NOT_COMPARABLE": 1}
    assert snapshot["price_movement"]["appeared_offer_count"] == 0
    assert snapshot["price_movement"]["not_observed_offer_count"] == 0


@pytest.mark.parametrize("invalid_current", [True, False])
@pytest.mark.parametrize("unparseable", [None, "not-a-time"])
def test_unparseable_observation_never_becomes_an_empty_instant_list(
    invalid_current: bool, unparseable: object
) -> None:
    current = [_row(capture=NOW), _row(sport="soccer_spain_la_liga", capture=NOW)]
    previous = [
        _row(capture=NOW - timedelta(hours=2)),
        _row(sport="soccer_spain_la_liga", capture=NOW - timedelta(hours=2)),
    ]
    (current if invalid_current else previous)[1]["capture_time_utc"] = unparseable
    movement = compare_acquisitions(current, previous)
    assert movement["matched_offer_count"] == 1
    assert movement["exclusion_reason_counts"] == {"BRANCH_NOT_COMPARABLE": 2}
    assert movement["appeared_offer_count"] == movement["not_observed_offer_count"] == 0


@pytest.mark.parametrize("failed_indices", [(None, 1, 1, 2), (1, None, 2, 1)])
def test_delivery_survives_a_real_failed_branch_across_consecutive_slots(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failed_indices: tuple[int | None, ...]
) -> None:
    import scripts.run_recurring_real_data as cli
    from robin.capture.real_data_result import SPORT_KEYS
    from tests.capture.test_recurring_real_data import (
        START,
        FakeSecretReader,
        FakeStore,
        FakeTransportFactory,
        _config,
        _resolution,
    )
    from tests.capture.test_run_recurring_real_data_cli import _github_environment

    _github_environment(monkeypatch)
    observed = START

    class SlotClock(datetime):
        @classmethod
        def now(cls, tz: object = None) -> datetime:
            return observed

    store = FakeStore()
    transport = FakeTransportFactory(lambda: observed)
    monkeypatch.setattr(cli, "datetime", SlotClock)
    monkeypatch.setattr(cli, "recover_latest_report", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(cli.ChronosR2ConditionalStore, "from_environment", lambda _env: store)
    monkeypatch.setattr(cli, "EnvironmentSecretReader", lambda _env: FakeSecretReader())
    monkeypatch.setattr(cli, "StrictHttpsTransport", lambda **_kwargs: transport(lambda: observed))
    monkeypatch.setattr(cli, "resolve_provider_once", lambda **_kwargs: _resolution(observed))
    manifest = _config(tmp_path).manifest_path
    for index, failed_index in enumerate(failed_indices):
        observed = START + timedelta(hours=2 * index)
        transport.failing_sport = SPORT_KEYS[failed_index] if failed_index is not None else None
        monkeypatch.setenv("GITHUB_RUN_ID", str(424242 + index))
        output = tmp_path / str(index)
        output.mkdir()
        assert (
            cli.main(
                [
                    "--execute",
                    "ROBIN_AUTONOMOUS_LAB_20261004",
                    "--manifest",
                    str(manifest),
                    "--output-directory",
                    str(output),
                ]
            )
            == 0
        )
        for name in (
            "robin-real-data.json",
            "robin-real-data.csv",
            "robin-real-data.html",
            "public-receipt.json",
        ):
            assert (output / name).stat().st_size > 0
        snapshot = json.loads((output / "robin-real-data.json").read_bytes())
        assert snapshot["summary"]["incomplete_branch_count"] == int(failed_index is not None)
        if failed_index is not None:
            branch = next(
                b for b in snapshot["branch_lineage"] if b["sport_key"] == SPORT_KEYS[failed_index]
            )
            assert branch["capture_time_utc"] is None
        if index:
            assert snapshot["comparison_available"] is True
            assert snapshot["price_movement"]["matched_offer_count"] > 0
            assert snapshot["price_movement"]["appeared_offer_count"] == 0
            assert snapshot["price_movement"]["not_observed_offer_count"] == 0
