from __future__ import annotations

import hashlib
import json
import shutil
import socket
import threading
import urllib.error
import urllib.request
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from robin.capture.real_data_dashboard import (
    build_dashboard_snapshot,
    render_dashboard_csv,
    render_dashboard_html,
)
from robin.capture.real_data_explorer import AtomicExplorerStore
from robin.capture.real_data_questions import (
    AcquisitionCatalog,
    QuestionError,
    answer_q1,
    answer_q3,
    run_question_command,
    to_csv_bytes,
    to_json_bytes,
)
from robin.capture.real_data_questions_web import QuestionPages, make_server
from robin.capture.recurring_real_data import RECURRING_CLAIM_IDS

ROOT = Path(__file__).resolve().parents[2]
KICKOFF = datetime(2026, 10, 18, 14, 0, tzinfo=UTC)
PROVIDER = "THE_ODDS_API_V4"
PERIOD = "PROVIDER_DEFAULT_UNSPECIFIED"
SPORTS = ("soccer_epl", "soccer_france_ligue_one")
_REAL_SOCKET = socket.socket
_REAL_CREATE_CONNECTION = socket.create_connection
_REAL_GETADDRINFO = socket.getaddrinfo
_REAL_GETHOSTBYADDR = socket.gethostbyaddr


def _z(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _slot(capture: datetime) -> datetime:
    return capture.replace(hour=capture.hour - capture.hour % 2, minute=0, second=0, microsecond=0)


def _offer(
    book: str,
    outcome: str,
    price: float,
    *,
    event: str = "event-1",
    match: str = "Arsenal — Leeds United",
    kickoff: datetime = KICKOFF,
    market: str = "h2h",
    point: float | None = None,
    sport: str = "soccer_epl",
    provider: str | None = PROVIDER,
    period: str | None = PERIOD,
) -> dict[str, object]:
    return {
        "sport_key": sport,
        "provider_key": provider,
        "settlement_period_key": period,
        "event_id": event,
        "match": match,
        "kickoff_utc": _z(kickoff),
        "bookmaker_key": book,
        "bookmaker": book.upper(),
        "market_key": market,
        "outcome": outcome,
        "point": point,
        "price": price,
    }


def _book(
    book: str, home: float, draw: float, away: float, **kwargs: object
) -> list[dict[str, object]]:
    return [
        _offer(book, "Arsenal", home, **kwargs),  # type: ignore[arg-type]
        _offer(book, "Draw", draw, **kwargs),  # type: ignore[arg-type]
        _offer(book, "Leeds United", away, **kwargs),  # type: ignore[arg-type]
    ]


def _report(
    run_id: int,
    capture: datetime,
    offers: Sequence[dict[str, object]],
    *,
    incomplete: Sequence[str] = (),
    sports: Sequence[str] = SPORTS,
) -> dict[str, object]:
    slot = _slot(capture)
    stamp = _z(capture.replace(microsecond=0))
    rows = [
        {
            "slot_start_utc": _z(slot),
            "acquisition_started_at_utc": _z(capture - timedelta(seconds=5)),
            "acquisition_finished_at_utc": _z(capture + timedelta(seconds=5)),
            "capture_time_utc": stamp,
            "source_timestamp_utc": _z(capture - timedelta(minutes=2)),
            "quota_remaining": 19_000,
            **offer,
        }
        for offer in offers
        if offer["sport_key"] not in incomplete and offer["sport_key"] in sports
    ]
    branches = [
        {
            "sport_key": sport,
            "status": "INCOMPLETE" if sport in incomplete else "COMPLETE",
            "provider_key": PROVIDER,
            "settlement_period_key": PERIOD,
            "acquisition_started_at_utc": _z(capture - timedelta(seconds=5)),
            "acquisition_finished_at_utc": _z(capture + timedelta(seconds=5)),
            "capture_time_utc": stamp,
            "row_count": sum(row["sport_key"] == sport for row in rows),
            "limitations": [],
            "diagnostic": None,
        }
        for sport in sports
    ]
    return {
        "mission_id": "ROBIN_AUTONOMOUS_LAB_20261004",
        "claim_ids": list(RECURRING_CLAIM_IDS),
        "repository_sha": "a" * 40,
        "github_run_id": str(run_id),
        "slot_start_utc": _z(slot),
        "generated_at_utc": stamp,
        "status": "REAL_DATA_PARTIAL" if incomplete else "REAL_DATA_COMPLETE",
        "branches": branches,
        "rows": rows,
        "validated_capture_count": len(sports) - len(incomplete),
        "incomplete_branch_count": len(incomplete),
        "accounting": {"rolling_24h_requests": 5, "rolling_24h_credits": 10},
    }


def _write_bundle(root: Path, snapshot: dict[str, object], run_id: int, slot: str) -> Path:
    root.mkdir(parents=True)
    normalized = (
        json.dumps(snapshot, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    csv_payload = render_dashboard_csv(snapshot)
    html_payload = render_dashboard_html(snapshot, csv_filename="robin-real-data.csv")
    (root / "robin-real-data.json").write_bytes(normalized)
    (root / "robin-real-data.csv").write_bytes(csv_payload)
    (root / "robin-real-data.html").write_bytes(html_payload)
    receipt = {
        "schema_version": "robin-autonomous-lab-public-receipt-v1",
        "mission_id": "ROBIN_AUTONOMOUS_LAB_20261004",
        "github_run_id": str(run_id),
        "delivery_github_run_id": str(run_id),
        "slot_start_utc": slot,
        "normalized_json_sha256": hashlib.sha256(normalized).hexdigest(),
        "csv_sha256": hashlib.sha256(csv_payload).hexdigest(),
        "html_sha256": hashlib.sha256(html_payload).hexdigest(),
    }
    (root / "public-receipt.json").write_text(json.dumps(receipt, sort_keys=True), encoding="utf-8")
    return root


def _store(
    tmp_path: Path,
    acquisitions: Sequence[tuple[int, datetime, Sequence[dict[str, object]]]],
    *,
    incomplete: dict[int, Sequence[str]] | None = None,
    branches: dict[int, Sequence[str]] | None = None,
    stubs: dict[int, Sequence[str]] | None = None,
    fresh: Sequence[int] = (),
) -> AtomicExplorerStore:
    """Publish acquisitions the way the collection delivers them, oldest first."""

    store = AtomicExplorerStore(tmp_path / "store", clock=lambda: KICKOFF + timedelta(days=3))
    previous: dict[str, object] | None = None
    for run_id, capture, offers in acquisitions:
        if run_id in fresh:
            # Published without a previous report, as the collection's first run is.
            previous = None
        stubbed = tuple((stubs or {}).get(run_id, ()))
        report = _report(
            run_id,
            capture,
            offers,
            incomplete=tuple((incomplete or {}).get(run_id, ())) + stubbed,
            sports=(branches or {}).get(run_id, SPORTS),
        )
        for branch in report["branches"]:  # type: ignore[attr-defined]
            if branch["sport_key"] in stubbed:
                # The collector's _branch_stub: a failed branch with no observed time.
                branch.update(
                    capture_time_utc=None,
                    acquisition_started_at_utc=None,
                    acquisition_finished_at_utc=None,
                )
        snapshot = build_dashboard_snapshot(
            report, previous_report=previous, generated_at=capture + timedelta(minutes=1)
        )
        store.publish(
            _write_bundle(
                tmp_path / f"bundle-{run_id}", snapshot, run_id, str(report["slot_start_utc"])
            )
        )
        previous = report
    return store


def _q3(store: AtomicExplorerStore, **options: str | None) -> dict[str, object]:
    return answer_q3(AcquisitionCatalog(store), options)


def _statuses(payload: dict[str, object]) -> dict[str, str]:
    return {str(row["bookmaker_key"]): str(row["status"]) for row in payload["rows"]}  # type: ignore[union-attr]


def _pair_store(tmp_path: Path) -> AtomicExplorerStore:
    before = KICKOFF - timedelta(hours=20)
    after = KICKOFF - timedelta(hours=10)
    return _store(
        tmp_path,
        [
            (
                101,
                before,
                [
                    *_book("a", 2.0, 3.4, 3.9),
                    *_book("b", 2.0, 3.4, 3.9),
                    *_book("c", 2.0, 3.4, 3.9),
                    *_book("d", 2.0, 3.4, 3.9),
                ],
            ),
            (
                102,
                after,
                [
                    *_book("a", 2.1, 3.3, 3.8),
                    *_book("b", 1.9, 3.5, 4.0),
                    *_book("c", 2.0, 3.4, 3.9),
                    *_book("e", 2.05, 3.4, 3.9),
                ],
            ),
        ],
    )


def test_q3_compares_one_exact_selection_per_bookmaker_with_a_consistent_summary(
    tmp_path: Path,
) -> None:
    store = _pair_store(tmp_path)
    payload = _q3(
        store, previous="101", current="102", event="event-1", market="h2h", outcome="Arsenal"
    )

    assert payload["status"] == "COMPARED"
    assert _statuses(payload) == {
        "a": "UP",
        "b": "DOWN",
        "c": "UNCHANGED",
        "d": "NOT_OBSERVED",
        "e": "APPEARED",
    }
    rows = payload["rows"]
    assert isinstance(rows, list)
    assert {row["outcome"] for row in rows if "outcome" in row} == set()
    summary = payload["summary"]
    assert isinstance(summary, dict)
    assert sum(summary["status_counts"].values()) == summary["row_count"] == len(rows) == 5
    assert summary["matched_count"] == 3
    assert summary["previous_median_matched"] == 2.0
    assert summary["current_median_matched"] == 2.0
    first = next(row for row in rows if row["bookmaker_key"] == "a")
    assert (
        first["previous_price"] == 2.0 and first["current_price"] == 2.1 and first["delta"] == 0.1
    )
    assert first["previous_capture_time_utc"] == _z(KICKOFF - timedelta(hours=20))
    assert first["current_capture_time_utc"] == _z(KICKOFF - timedelta(hours=10))
    selection = payload["selection"]
    assert isinstance(selection, dict)
    assert (selection["provider_key"], selection["settlement_period_key"]) == (PROVIDER, PERIOD)


def test_q3_exports_are_byte_reproducible_and_spreadsheet_safe(tmp_path: Path) -> None:
    store = _pair_store(tmp_path)
    options = {
        "previous": "101",
        "current": "102",
        "event": "event-1",
        "market": "h2h",
        "outcome": "Arsenal",
    }
    first = _q3(store, **options)
    second = answer_q3(AcquisitionCatalog(store), options)

    assert to_json_bytes(first) == to_json_bytes(second)
    assert to_csv_bytes(first) == to_csv_bytes(second)
    lines = to_csv_bytes(first).decode().splitlines()
    assert lines[0].startswith("previous_run_id,current_run_id,event_id")
    assert len(lines) == 6
    assert ",-0.1," in to_csv_bytes(first).decode()
    hostile = dict(first)
    hostile["rows"] = [dict(first["rows"][0], bookmaker="=HYPERLINK(1)")]  # type: ignore[index]
    assert "'=HYPERLINK(1)" in to_csv_bytes(hostile).decode()
    assert "=HYPERLINK(1)" in to_json_bytes(hostile).decode()
    assert b"closing" not in to_json_bytes(first).lower()


def test_q3_never_mixes_totals_thresholds_and_parses_points_strictly(tmp_path: Path) -> None:
    before = KICKOFF - timedelta(hours=20)
    after = KICKOFF - timedelta(hours=10)
    store = _store(
        tmp_path,
        [
            (
                101,
                before,
                [
                    _offer("a", "Over", 1.9, market="totals", point=2.5),
                    _offer("b", "Over", 1.8, market="totals", point=2.5),
                ],
            ),
            (
                102,
                after,
                [
                    _offer("a", "Over", 2.0, market="totals", point=2.5),
                    _offer("b", "Over", 2.6, market="totals", point=3.5),
                ],
            ),
        ],
    )
    two_and_half = _q3(
        store,
        previous="101",
        current="102",
        event="event-1",
        market="totals",
        outcome="Over",
        point="2.50",
    )
    assert _statuses(two_and_half) == {"a": "UP", "b": "NOT_OBSERVED"}
    by_book = {row["bookmaker_key"]: row for row in two_and_half["rows"]}  # type: ignore[union-attr]
    assert by_book["b"]["other_points_observed"] == [3.5]
    three_and_half = _q3(
        store,
        previous="101",
        current="102",
        event="event-1",
        market="totals",
        outcome="Over",
        point="3.5",
    )
    assert _statuses(three_and_half) == {"b": "APPEARED"}
    for point in ("2,5", "nan", "inf", "1e1", "0", "101", None):
        with pytest.raises(QuestionError, match="SELECTION_POINT_INVALID"):
            _q3(
                store,
                previous="101",
                current="102",
                event="event-1",
                market="totals",
                outcome="Over",
                point=point,
            )
    with pytest.raises(QuestionError, match="SELECTION_POINT_INVALID"):
        _q3(
            store,
            previous="101",
            current="102",
            event="event-1",
            market="h2h",
            outcome="Over",
            point="2.5",
        )


def test_q3_refuses_same_reversed_unknown_or_ambiguous_requests(tmp_path: Path) -> None:
    store = _pair_store(tmp_path)
    base = {"event": "event-1", "market": "h2h", "outcome": "Arsenal"}
    for previous, current, code in (
        ("101", "101", "Q3_SAME_ACQUISITION"),
        ("102", "101", "Q3_ORDER_INVALID"),
        ("999", "101", "ACQUISITION_UNKNOWN"),
    ):
        with pytest.raises(QuestionError, match=code):
            _q3(store, previous=previous, current=current, **base)
    with pytest.raises(QuestionError, match="SELECTION_NOT_FOUND"):
        _q3(store, previous="101", current="102", event="event-1", market="h2h", outcome="arsenal")
    with pytest.raises(QuestionError, match="SELECTION_NOT_FOUND"):
        _q3(
            store,
            previous="101",
            current="102",
            event="event-1",
            market="h2h",
            outcome="Arsenal",
            provider="OTHER",
        )


def test_q3_marks_provenance_changes_and_inadmissible_branches_instead_of_movements(
    tmp_path: Path,
) -> None:
    before = KICKOFF - timedelta(hours=20)
    after = KICKOFF - timedelta(hours=10)
    lineage = _store(
        tmp_path / "lineage",
        [
            (101, before, _book("a", 2.0, 3.4, 3.9, provider=None, period=None)),
            (102, after, _book("a", 2.1, 3.4, 3.9)),
        ],
    )
    payload = _q3(
        lineage,
        previous="101",
        current="102",
        event="event-1",
        market="h2h",
        outcome="Arsenal",
        provider=PROVIDER,
        period=PERIOD,
    )
    assert payload["status"] == "BRANCH_LINEAGE_INCOMPARABLE"
    assert _statuses(payload) == {"a": "EXCLUDED"}
    with pytest.raises(QuestionError, match="SELECTION_AMBIGUOUS"):
        _q3(
            lineage, previous="101", current="102", event="event-1", market="h2h", outcome="Arsenal"
        )

    failed = _store(
        tmp_path / "failed",
        [
            (
                101,
                before,
                _book("a", 2.0, 3.4, 3.9)
                + _book("x", 1.5, 4.0, 6.0, event="event-2", sport="soccer_france_ligue_one"),
            ),
            (
                102,
                after,
                _book("x", 1.6, 4.0, 5.5, event="event-2", sport="soccer_france_ligue_one"),
            ),
        ],
        incomplete={102: ("soccer_epl",)},
    )
    payload = _q3(
        failed, previous="101", current="102", event="event-1", market="h2h", outcome="Arsenal"
    )
    assert payload["status"] == "BRANCH_NOT_COMPARABLE"
    assert payload["summary"]["status_counts"]["NOT_OBSERVED"] == 0  # type: ignore[index]


def test_q3_reports_matches_started_before_the_current_acquisition(tmp_path: Path) -> None:
    store = _store(
        tmp_path,
        [
            (
                101,
                KICKOFF - timedelta(hours=1),
                _book("a", 2.0, 3.4, 3.9)
                + _book("x", 1.5, 4.0, 6.0, event="event-2", kickoff=KICKOFF + timedelta(days=1)),
            ),
            (
                102,
                KICKOFF + timedelta(hours=1),
                _book("x", 1.6, 4.0, 5.5, event="event-2", kickoff=KICKOFF + timedelta(days=1)),
            ),
        ],
    )
    payload = _q3(
        store, previous="101", current="102", event="event-1", market="h2h", outcome="Arsenal"
    )
    assert _statuses(payload) == {"a": "EVENT_STARTED_BEFORE_CURRENT"}
    assert payload["summary"]["status_counts"]["NOT_OBSERVED"] == 0  # type: ignore[index]


def test_q3_excludes_duplicate_identities_on_both_sides(tmp_path: Path) -> None:
    store = _store(
        tmp_path,
        [
            (
                101,
                KICKOFF - timedelta(hours=20),
                _book("a", 2.0, 3.4, 3.9) + _book("b", 2.0, 3.4, 3.9),
            ),
            (
                102,
                KICKOFF - timedelta(hours=10),
                _book("a", 2.1, 3.4, 3.9)
                + [_offer("a", "Arsenal", 2.2)]
                + _book("b", 2.1, 3.4, 3.9),
            ),
        ],
    )
    payload = _q3(
        store, previous="101", current="102", event="event-1", market="h2h", outcome="Arsenal"
    )
    assert _statuses(payload)["b"] == "UP"
    duplicates = [row for row in payload["rows"] if row["reason"] == "DUPLICATE_OFFER_IDENTITY"]  # type: ignore[union-attr]
    assert len(duplicates) == 3
    assert {row["current_price"] for row in duplicates if row["side"] == "current"} == {2.1, 2.2}


def test_catalog_reads_each_acquisition_once_without_writing_to_the_store(tmp_path: Path) -> None:
    store = _pair_store(tmp_path)
    legacy = store.versions / "run-101-view-v13"
    shutil.copytree(legacy, store.versions / "run-101")
    before = sorted(path.name for path in store.versions.iterdir())
    pointer = store.pointer_path.read_bytes()
    catalog = AcquisitionCatalog(store)

    view = catalog.view()
    answer_q1(catalog)
    _q3(store, previous="101", current="102", event="event-1", market="h2h", outcome="Arsenal")

    assert [item.run_id for item in view.acquisitions] == ["101", "102"]
    assert sorted(path.name for path in store.versions.iterdir()) == before
    assert store.pointer_path.read_bytes() == pointer
    loads = catalog.loads
    catalog.view()
    assert catalog.loads == loads


def test_catalog_refuses_two_origins_for_one_slot(tmp_path: Path) -> None:
    store = _pair_store(tmp_path)
    impostor = tmp_path / "impostor"
    report = _report(103, KICKOFF - timedelta(hours=10, minutes=-30), _book("a", 9.0, 3.4, 3.9))
    snapshot = build_dashboard_snapshot(report, previous_report=None, generated_at=KICKOFF)
    bundle = _write_bundle(impostor, snapshot, 103, str(report["slot_start_utc"]))
    target = store.versions / "run-103-view-v13"
    shutil.copytree(store.versions / "run-102-view-v13", target)
    shutil.rmtree(target / "source")
    shutil.copytree(bundle, target / "source")
    manifest = json.loads((target / "manifest.json").read_text("utf-8"))
    manifest |= {
        "run_id": "103",
        "source_receipt_sha256": hashlib.sha256(
            (bundle / "public-receipt.json").read_bytes()
        ).hexdigest(),
    }
    (target / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    view = AcquisitionCatalog(store).view()

    assert [item.run_id for item in view.acquisitions] == ["101"]
    assert {code for _, code in view.rejected} == {"SLOT_IDENTITY_CONFLICT"}


def _q1_store(
    tmp_path: Path, extra: Sequence[tuple[int, datetime, Sequence[dict[str, object]]]] = ()
) -> AtomicExplorerStore:
    books = ("a", "b", "c", "d")
    timeline = [
        (
            201,
            KICKOFF - timedelta(hours=30),
            [row for book in books for row in _book(book, 2.0, 3.4, 3.9)],
        ),
        (
            202,
            KICKOFF - timedelta(hours=23, minutes=50),
            [row for book in books for row in _book(book, 2.0, 3.4, 3.9)],
        ),
        (
            203,
            KICKOFF - timedelta(hours=12),
            [row for book in books for row in _book(book, 1.95, 3.5, 4.0)],
        ),
        (
            204,
            KICKOFF - timedelta(minutes=70),
            [row for book in books[:3] for row in _book(book, 1.8, 3.6, 4.4)]
            + _book("e", 1.9, 3.5, 4.2),
        ),
        (
            205,
            KICKOFF + timedelta(hours=2),
            _book("a", 1.5, 4.0, 6.0, event="later", kickoff=KICKOFF + timedelta(days=5)),
        ),
    ]
    return _store(tmp_path, [*timeline, *extra])


def test_q1_follows_the_reference_favourite_to_the_last_prematch_observation(
    tmp_path: Path,
) -> None:
    payload = answer_q1(AcquisitionCatalog(_q1_store(tmp_path)))
    rows = {row["event_id"]: row for row in payload["rows"]}  # type: ignore[union-attr]
    match = rows["event-1"]

    assert match["status"] == "INCLUDED"
    assert match["reference_run_id"] == "202"
    assert match["reference_class"] == "J_MINUS_24H"
    assert match["reference_offset_minutes"] == 10.0
    assert match["last_prematch_run_id"] == "204"
    assert match["last_prematch_class"] == "WITHIN_2H"
    assert match["last_prematch_minutes_before_kickoff"] == 70.0
    assert match["strict_windows"] is True
    assert match["favourite_outcome"] == "Arsenal"
    assert match["consensus_bookmakers_at_reference"] == 4
    assert (match["paired_bookmakers"], match["down_count"]) == (3, 3)
    assert (match["reference_only_count"], match["last_prematch_only_count"]) == (1, 1)
    assert (match["paired_median_at_reference"], match["paired_median_last_prematch"]) == (2.0, 1.8)
    assert match["median_delta"] == -0.2
    assert rows["later"]["status"] == "PENDING"
    summary = payload["summary"]
    assert summary["status_counts"] == {
        "INCLUDED": 1,
        "EXCLUDED": 0,
        "PENDING": 1,
        "OUT_OF_STORE": 0,
    }  # type: ignore[index]
    exported = to_json_bytes(payload).decode().lower() + to_csv_bytes(payload).decode().lower()
    assert "closing" not in exported.replace("never a closing price", "")
    assert "clôture" not in exported


@pytest.mark.parametrize(
    ("offset", "expected"),
    [
        (timedelta(minutes=60), "J_MINUS_24H"),
        (timedelta(minutes=60, seconds=1), "NEAR"),
        (timedelta(minutes=-60), "J_MINUS_24H"),
    ],
)
def test_q1_reference_class_boundaries_are_exact(
    tmp_path: Path, offset: timedelta, expected: str
) -> None:
    books = [row for book in ("a", "b", "c") for row in _book(book, 2.0, 3.4, 3.9)]
    store = _store(
        tmp_path,
        [
            (301, KICKOFF - timedelta(hours=30), books),
            (302, KICKOFF - timedelta(hours=24) + offset, books),
            (303, KICKOFF - timedelta(minutes=120), books),
            (304, KICKOFF + timedelta(hours=1), []),
        ],
    )
    row = answer_q1(AcquisitionCatalog(store))["rows"][0]  # type: ignore[index]
    assert row["reference_class"] == expected
    assert row["last_prematch_class"] == "WITHIN_2H"


@pytest.mark.parametrize(
    ("books", "reason"),
    [
        ([("a", 2.0, 3.4, 3.9), ("b", 2.0, 3.4, 3.9)], "CONSENSUS_INSUFFICIENT"),
        ([("a", 2.5, 3.0, 2.5), ("b", 2.5, 3.0, 2.5), ("c", 2.5, 3.0, 2.5)], "FAVOURITE_TIE"),
        ([("a", 3.1, 2.9, 3.2), ("b", 3.1, 2.9, 3.2), ("c", 3.1, 2.9, 3.2)], "FAVOURITE_IS_DRAW"),
    ],
)
def test_q1_refuses_undetermined_favourites(
    tmp_path: Path, books: list[tuple[str, float, float, float]], reason: str
) -> None:
    offers = [row for book in books for row in _book(*book)]
    store = _store(
        tmp_path,
        [
            (401, KICKOFF - timedelta(hours=30), offers),
            (402, KICKOFF - timedelta(hours=24), offers),
            (403, KICKOFF - timedelta(hours=1), offers),
            (404, KICKOFF + timedelta(hours=1), []),
        ],
    )
    row = answer_q1(AcquisitionCatalog(store))["rows"][0]  # type: ignore[index]
    assert (row["status"], row["reason"]) == ("EXCLUDED", reason)
    assert row["median_delta"] is None


def test_q1_separates_out_of_store_absent_windows_and_kickoff_changes(tmp_path: Path) -> None:
    def three(event: str, kickoff: datetime) -> list[dict[str, object]]:
        return [
            row
            for book in ("a", "b", "c")
            for row in _book(book, 1.7, 3.8, 5.0, event=event, kickoff=kickoff)
        ]

    gap_kickoff = KICKOFF + timedelta(hours=48)
    windows = _store(
        tmp_path / "windows",
        [
            (
                501,
                KICKOFF - timedelta(hours=22),
                three("event-1", KICKOFF) + three("gap", gap_kickoff),
            ),
            (502, KICKOFF - timedelta(hours=1), three("event-1", KICKOFF)),
            (503, KICKOFF + timedelta(hours=40), three("gap", gap_kickoff)),
            (504, KICKOFF + timedelta(hours=50), []),
        ],
    )
    rows = {row["event_id"]: row for row in answer_q1(AcquisitionCatalog(windows))["rows"]}  # type: ignore[union-attr]
    assert rows["event-1"]["status"] == "OUT_OF_STORE"
    assert (rows["gap"]["status"], rows["gap"]["reason"]) == (
        "EXCLUDED",
        "REFERENCE_ABSENT:NO_ACQUISITION_IN_WINDOW",
    )

    moved = KICKOFF + timedelta(hours=6)
    postponed = _store(
        tmp_path / "postponed",
        [
            (601, KICKOFF - timedelta(hours=30), three("moved", KICKOFF)),
            (602, KICKOFF - timedelta(hours=18), three("moved", KICKOFF)),
            (603, moved - timedelta(hours=1), three("moved", moved)),
            (604, moved + timedelta(hours=2), []),
        ],
    )
    row = answer_q1(AcquisitionCatalog(postponed))["rows"][0]  # type: ignore[index]
    assert (row["status"], row["reason"], row["kickoff_utc"]) == (
        "EXCLUDED",
        "KICKOFF_CHANGED",
        _z(moved),
    )
    assert row["median_delta"] is None


def test_q1_reference_target_uses_utc_across_the_daylight_saving_change(tmp_path: Path) -> None:
    kickoff = datetime(2026, 10, 25, 15, 0, tzinfo=UTC)
    books = [row for book in ("a", "b", "c") for row in _book(book, 2.0, 3.4, 3.9, kickoff=kickoff)]
    store = _store(
        tmp_path,
        [
            (601, kickoff - timedelta(hours=30), books),
            (602, datetime(2026, 10, 24, 14, 0, tzinfo=UTC), books),
            (603, kickoff - timedelta(hours=1), books),
            (604, kickoff + timedelta(hours=1), []),
        ],
    )
    row = answer_q1(AcquisitionCatalog(store))["rows"][0]  # type: ignore[index]
    assert row["reference_target_utc"] == "2026-10-24T15:00:00Z"
    assert (row["reference_offset_minutes"], row["reference_class"]) == (-60.0, "J_MINUS_24H")


def test_pages_render_escaped_content_and_exports_match_the_engine(tmp_path: Path) -> None:
    hostile = "</script><img src=x onerror=alert(1)>"
    store = _store(
        tmp_path,
        [
            (
                101,
                KICKOFF - timedelta(hours=20),
                _book("a", 2.0, 3.4, 3.9, match=hostile) + _book("b", 2.0, 3.4, 3.9, match=hostile),
            ),
            (
                102,
                KICKOFF - timedelta(hours=10),
                _book("a", 2.1, 3.4, 3.9, match=hostile) + _book("b", 1.9, 3.4, 3.9, match=hostile),
            ),
        ],
    )
    pages = QuestionPages(AcquisitionCatalog(store))
    query = "previous=101&current=102&event=event-1&market=h2h&outcome=Arsenal"

    for path, needle in (
        ("/questions", "2 acquisitions"),
        ("/questions/q3", "1. Match"),
        ("/questions/q3", "Arsenal"),
        ("/questions/q1", "pas une cote de clôture"),
    ):
        status, body, kind, headers = pages.respond(path, query if needle == "Arsenal" else "")
        assert status == 200 and kind.startswith("text/html")
        assert "script-src 'sha256-" in headers["Content-Security-Policy"]
        assert needle in body.decode()
        assert hostile.encode() not in body
    status, body, kind, headers = pages.respond("/questions/q3.csv", query)
    assert body == to_csv_bytes(
        _q3(store, previous="101", current="102", event="event-1", market="h2h", outcome="Arsenal")
    )
    assert headers["Content-Disposition"] == 'attachment; filename="robin-q3-selection.csv"'
    status, body, _, _ = pages.respond("/questions/q3", "previous=102&current=101")
    assert status == 400 and b"Q3_ORDER_INVALID" in body
    status, _, _, _ = pages.respond("/questions/q3", "&".join(f"x{index}=1" for index in range(40)))
    assert status == 400
    broken = QuestionPages(AcquisitionCatalog(store, row_cache_size=2))
    broken.catalog.view()
    broken.catalog._rows.clear()
    (store.versions / "run-102-view-v13" / "source" / "robin-real-data.json").write_text(
        "{", encoding="utf-8"
    )
    status, body, _, _ = broken.respond("/questions/q3.json", query)
    assert status == 503 and b"LOCAL_STORE_UNAVAILABLE" in body


def test_http_server_keeps_existing_routes_and_guards_question_hosts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Explicit loopback integration test, as in test_real_data_explorer.
    monkeypatch.setattr(socket, "socket", _REAL_SOCKET)
    monkeypatch.setattr(socket, "create_connection", _REAL_CREATE_CONNECTION)
    monkeypatch.setattr(socket, "getaddrinfo", _REAL_GETADDRINFO)
    monkeypatch.setattr(socket, "gethostbyaddr", _REAL_GETHOSTBYADDR)
    store = _pair_store(tmp_path)
    server = make_server(store, port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        assert (
            json.loads(urllib.request.urlopen(f"{base}/status.json").read())["current_run_id"]
            == "102"
        )
        with urllib.request.urlopen(f"{base}/questions/q1.json") as response:
            assert response.headers["Cache-Control"] == "no-store"
            assert json.loads(response.read())["question"] == "Q1"
        for path, data in (
            ("/questions", None),
            ("/status.json", None),
            ("/export.csv", b"content=x"),
        ):
            request = urllib.request.Request(
                f"{base}{path}", data=data, headers={"Host": "evil.example"}
            )
            with pytest.raises(urllib.error.HTTPError) as refused:
                urllib.request.urlopen(request)
            assert refused.value.code == 403
        with urllib.request.urlopen(
            urllib.request.Request(f"{base}/export.csv", data=b"content=a%2Cb")
        ) as response:
            assert response.read() == b"a,b"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_runner_answers_questions_from_the_local_store_only(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    import scripts.run_real_data_explorer as runner

    store = _pair_store(tmp_path)
    output = tmp_path / "q3.csv"
    arguments = [
        "--root",
        str(store.root),
        "--question",
        "q3",
        "--previous",
        "101",
        "--current",
        "102",
        "--event",
        "event-1",
        "--market",
        "h2h",
        "--outcome",
        "Arsenal",
        "--format",
        "csv",
        "--output",
        str(output),
    ]

    assert runner.main(arguments) == 0
    assert output.read_bytes() == to_csv_bytes(
        _q3(store, previous="101", current="102", event="event-1", market="h2h", outcome="Arsenal")
    )
    assert (
        runner.main(
            [
                "--root",
                str(store.root),
                "--question",
                "q3",
                "--previous",
                "102",
                "--current",
                "101",
                "--event",
                "e",
                "--market",
                "h2h",
                "--outcome",
                "x",
            ]
        )
        == 2
    )
    assert "Q3_ORDER_INVALID" in capsys.readouterr().err
    code, payload = run_question_command(store, "acquisitions", {}, "json")
    assert code == 0 and [row["run_id"] for row in json.loads(payload)["rows"]] == ["101", "102"]


def test_stub_branches_without_capture_time_never_reach_the_shared_engine() -> None:
    from robin.capture.real_data_questions import _sport_states

    snapshot: dict[str, object] = {
        "comparable_branch_sports": ["soccer_france_ligue_one"],
        "branch_lineage": [
            {
                "sport_key": "soccer_epl",
                "provider_key": PROVIDER,
                "settlement_period_key": PERIOD,
                "capture_time_utc": None,
            },
            {
                "sport_key": "soccer_france_ligue_one",
                "provider_key": PROVIDER,
                "settlement_period_key": PERIOD,
                "capture_time_utc": "2026-10-17T08:00:00Z",
            },
        ],
        "rows": [],
    }
    states = _sport_states(snapshot, [])

    assert (states["soccer_epl"].admissible, states["soccer_epl"].reason) == (
        False,
        "BRANCH_NOT_ADMISSIBLE",
    )
    assert states["soccer_france_ligue_one"].admissible is True
    snapshot["comparable_branch_sports"] = ["soccer_epl"]
    assert _sport_states(snapshot, [])["soccer_epl"].reason == "BRANCH_TIME_INVALID"


def _q1_rows(store: AtomicExplorerStore) -> dict[tuple[object, ...], dict[str, object]]:
    rows = answer_q1(AcquisitionCatalog(store))["rows"]
    return {(row["provider_key"], row["sport_key"], row["event_id"]): row for row in rows}  # type: ignore[union-attr]


def test_q1_keeps_one_row_per_lineage_and_names_lineage_changes(tmp_path: Path) -> None:
    def three(event: str, **kwargs: object) -> list[dict[str, object]]:
        return [
            row
            for book in ("a", "b", "c")
            for row in _book(book, 2.0, 3.4, 3.9, event=event, **kwargs)
        ]

    legacy = {"provider": None, "period": None}
    store = _store(
        tmp_path,
        [
            (
                701,
                KICKOFF - timedelta(hours=30),
                three("event-1") + three("legacy", **legacy) + three("switch", **legacy),
            ),
            (
                702,
                KICKOFF - timedelta(hours=24),
                three("event-1") + three("legacy", **legacy) + three("switch", **legacy),
            ),
            (
                703,
                KICKOFF - timedelta(hours=1),
                three("event-1") + three("legacy", **legacy) + three("switch"),
            ),
            (704, KICKOFF + timedelta(hours=1), []),
        ],
    )
    rows = _q1_rows(store)
    assert rows[(PROVIDER, "soccer_epl", "event-1")]["status"] == "INCLUDED"
    assert rows[(None, "soccer_epl", "legacy")]["status"] == "INCLUDED"
    assert rows[(None, "soccer_epl", "switch")]["reason"] == "PREMATCH_ABSENT:LINEAGE_CHANGED"
    assert rows[(PROVIDER, "soccer_epl", "switch")]["reason"] == "REFERENCE_ABSENT:LINEAGE_CHANGED"


def test_q1_isolates_a_stray_row_from_another_sport(tmp_path: Path) -> None:
    books = [row for book in ("a", "b", "c") for row in _book(book, 2.0, 3.4, 3.9)]
    stray = [_offer("z", "Arsenal", 2.2, sport="soccer_france_ligue_one")]
    store = _store(
        tmp_path,
        [
            (711, KICKOFF - timedelta(hours=30), books),
            (712, KICKOFF - timedelta(hours=24), books + stray),
            (713, KICKOFF - timedelta(hours=1), books),
            (714, KICKOFF + timedelta(hours=1), []),
        ],
    )
    rows = _q1_rows(store)
    assert rows[(PROVIDER, "soccer_epl", "event-1")]["status"] == "INCLUDED"
    assert rows[(PROVIDER, "soccer_france_ligue_one", "event-1")]["status"] == "EXCLUDED"


def test_q1_store_bounds_count_inadmissible_branches_and_prematch_window_is_open(
    tmp_path: Path,
) -> None:
    books = [row for book in ("a", "b", "c") for row in _book(book, 2.0, 3.4, 3.9)]
    failed = _store(
        tmp_path / "failed",
        [
            (801, KICKOFF - timedelta(hours=30), books),
            (802, KICKOFF - timedelta(hours=24), books),
            (803, KICKOFF - timedelta(hours=1), books),
            (804, KICKOFF + timedelta(hours=1), books),
        ],
        incomplete={801: ("soccer_epl",), 802: ("soccer_epl",), 804: ("soccer_epl",)},
    )
    row = _q1_rows(failed)[(PROVIDER, "soccer_epl", "event-1")]
    assert (row["status"], row["reason"]) == ("EXCLUDED", "REFERENCE_ABSENT:BRANCH_NOT_ADMISSIBLE")
    at_kickoff = _store(
        tmp_path / "kickoff",
        [
            (811, KICKOFF - timedelta(hours=30), books),
            (812, KICKOFF - timedelta(hours=24), books),
            (813, KICKOFF, books),
            (814, KICKOFF + timedelta(hours=2), []),
        ],
    )
    row = _q1_rows(at_kickoff)[(PROVIDER, "soccer_epl", "event-1")]
    assert row["reason"] == "PREMATCH_ABSENT:NO_ACQUISITION_IN_WINDOW"


def test_q3_other_thresholds_stay_within_the_selection_lineage(tmp_path: Path) -> None:
    def totals(book: str, *, full: bool) -> list[dict[str, object]]:
        half = [_offer(book, "Over", 1.6, market="totals", point=1.5, period="FIRST_HALF")]
        return half + ([_offer(book, "Over", 1.9, market="totals", point=2.5)] if full else [])

    store = _store(
        tmp_path,
        [
            (821, KICKOFF - timedelta(hours=20), totals("a", full=True) + totals("b", full=True)),
            (822, KICKOFF - timedelta(hours=10), totals("a", full=True) + totals("b", full=False)),
        ],
    )
    payload = _q3(
        store,
        previous="821",
        current="822",
        event="event-1",
        market="totals",
        outcome="Over",
        point="2.5",
        period=PERIOD,
    )
    rows = {row["bookmaker_key"]: row for row in payload["rows"]}  # type: ignore[union-attr]
    assert (rows["b"]["status"], rows["b"]["other_points_observed"]) == ("NOT_OBSERVED", [])


def test_q3_duplicates_keep_engine_priority_over_out_of_range_prices(tmp_path: Path) -> None:
    store = _store(
        tmp_path,
        [
            (831, KICKOFF - timedelta(hours=20), _book("a", 2.0, 3.4, 3.9)),
            (
                832,
                KICKOFF - timedelta(hours=10),
                _book("a", 2.1, 3.4, 3.9) + [_offer("a", "Arsenal", 1.0)],
            ),
        ],
    )
    payload = _q3(
        store, previous="831", current="832", event="event-1", market="h2h", outcome="Arsenal"
    )
    assert payload["summary"]["exclusion_reason_counts"] == {"DUPLICATE_OFFER_IDENTITY": 3}  # type: ignore[index]


def test_catalog_retries_transient_failures_and_web_q1_tracks_rejections(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import robin.capture.real_data_questions as questions

    store = _pair_store(tmp_path)
    original = questions.validate_source_bundle
    calls = {"failed": False}

    def flaky(source: Path, **kwargs: object) -> object:
        if not calls["failed"] and "run-102" in str(source):
            calls["failed"] = True
            raise PermissionError("locked")
        return original(source)

    monkeypatch.setattr(questions, "validate_source_bundle", flaky)
    catalog = AcquisitionCatalog(store)
    assert [item.run_id for item in catalog.view().acquisitions] == ["101"]
    assert [item.run_id for item in catalog.view().acquisitions] == ["101", "102"]

    pages = QuestionPages(catalog)
    first = json.loads(pages.respond("/questions/q1.json", "")[1])
    damaged = store.versions / "run-101"
    shutil.copytree(store.versions / "run-101-view-v13", damaged)
    (damaged / "source" / "robin-real-data.json").write_text("{}", encoding="utf-8")
    second = json.loads(pages.respond("/questions/q1.json", "")[1])
    assert first["store"]["rejected_versions"] == []
    assert second["store"]["rejected_versions"] == [
        {"version": "run-101", "code": "SOURCE_HASH_MISMATCH"}
    ]


def test_q1_filtered_exports_carry_their_own_summary_and_cli_refuses_bad_inputs(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    import scripts.run_real_data_explorer as runner

    store = _q1_store(tmp_path / "store")
    pages = QuestionPages(AcquisitionCatalog(store))
    for suffix in ("json", "csv"):
        assert (
            pages.respond(f"/questions/q1.{suffix}", "")[1]
            == (run_question_command(store, "q1", {}, suffix)[1])
        )

    filtered = json.loads(pages.respond("/questions/q1.json", "status=PENDING")[1])
    assert [row["status"] for row in filtered["rows"]] == ["PENDING"]
    assert filtered["filters"] == {"status": "PENDING", "strict_windows_only": False}
    assert filtered["filtered_summary"]["match_count"] == 1
    assert filtered["filtered_summary"]["status_counts"] == {
        "INCLUDED": 0,
        "EXCLUDED": 0,
        "PENDING": 1,
        "OUT_OF_STORE": 0,
    }
    assert filtered["summary"]["match_count"] == 2
    page = pages.respond("/questions/q1", "status=PENDING")[1].decode()
    assert "Synthèse des matchs affichés" in page and "1 matchs affichés" in page

    assert run_question_command(store, "acquisitions", {}, "csv") == (2, b"FORMAT_UNSUPPORTED\n")
    typo = tmp_path / "typo-root"
    assert runner.main(["--root", str(typo), "--question", "q1", "--format", "csv"]) == 2
    assert "LOCAL_STORE_UNAVAILABLE" in capsys.readouterr().err
    assert not typo.exists()


def test_q1_reports_matches_seen_only_on_inadmissible_branches(tmp_path: Path) -> None:
    def offers(capture: datetime) -> list[dict[str, object]]:
        healthy = [row for book in ("a", "b", "c") for row in _book(book, 2.0, 3.4, 3.9)]
        split = [
            row
            | {"capture_time_utc": _z(capture.replace(microsecond=0) + timedelta(minutes=index))}
            for index, row in enumerate(
                _book("a", 1.8, 3.6, 4.4, event="event-2", sport="soccer_france_ligue_one")
            )
        ]
        return healthy + split

    times = [KICKOFF - timedelta(hours=hours) for hours in (30, 24, 1)] + [
        KICKOFF + timedelta(hours=1)
    ]
    store = _store(tmp_path, [(901 + index, at, offers(at)) for index, at in enumerate(times)])
    payload = answer_q1(AcquisitionCatalog(store))
    rows = _q1_rows(store)

    assert rows[(PROVIDER, "soccer_epl", "event-1")]["status"] == "INCLUDED"
    hidden = rows[(PROVIDER, "soccer_france_ligue_one", "event-2")]
    assert (hidden["status"], hidden["reason"]) == (
        "EXCLUDED",
        "REFERENCE_ABSENT:BRANCH_NOT_ADMISSIBLE",
    )
    assert payload["summary"]["match_count"] == 2  # type: ignore[index]


def test_q3_started_match_uses_the_exact_selected_lineage(tmp_path: Path) -> None:
    other = {"provider": None, "period": None, "kickoff": KICKOFF - timedelta(days=2)}
    store = _store(
        tmp_path,
        [
            (
                101,
                KICKOFF - timedelta(hours=1),
                _book("x", 1.5, 4.0, 6.0, **other) + _book("a", 2.0, 3.4, 3.9),
            ),
            (102, KICKOFF + timedelta(hours=1), _book("x", 1.6, 4.0, 5.5, **other)),
        ],
    )
    payload = _q3(
        store,
        previous="101",
        current="102",
        event="event-1",
        market="h2h",
        outcome="Arsenal",
        provider=PROVIDER,
        period=PERIOD,
    )
    assert _statuses(payload) == {"a": "EVENT_STARTED_BEFORE_CURRENT"}
    assert payload["kickoff"] == {
        "previous_kickoff_utc": [_z(KICKOFF)],
        "current_kickoff_utc": [],
        "changed": False,
    }


def test_runner_question_mode_never_completes_a_partial_store(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    import scripts.run_real_data_explorer as runner

    store = _pair_store(tmp_path / "source")
    copy = tmp_path / "copy"
    shutil.copytree(store.versions, copy / "versions")

    assert runner.main(["--root", str(copy), "--question", "acquisitions"]) == 2
    assert "LOCAL_STORE_UNAVAILABLE" in capsys.readouterr().err
    assert sorted(path.name for path in copy.iterdir()) == ["versions"]


def test_q3_never_labels_a_match_started_from_conflicting_kickoffs(tmp_path: Path) -> None:
    late = KICKOFF + timedelta(hours=2)
    for name, first, second in (("early-first", KICKOFF, late), ("late-first", late, KICKOFF)):
        store = _store(
            tmp_path / name,
            [
                (
                    101,
                    KICKOFF - timedelta(hours=1),
                    _book("a", 2.0, 3.4, 3.9, kickoff=first)
                    + _book("b", 2.0, 3.4, 3.9, kickoff=second),
                ),
                (
                    102,
                    KICKOFF + timedelta(hours=1),
                    _book("x", 1.6, 4.0, 5.5, event="event-2", kickoff=KICKOFF + timedelta(days=1)),
                ),
            ],
        )
        payload = _q3(
            store, previous="101", current="102", event="event-1", market="h2h", outcome="Arsenal"
        )
        assert _statuses(payload) == {"a": "NOT_OBSERVED", "b": "NOT_OBSERVED"}
        assert payload["kickoff"]["previous_kickoff_utc"] == [_z(KICKOFF), _z(late)]  # type: ignore[index]


def _totals(book: str, **kwargs: object) -> list[dict[str, object]]:
    return [
        _offer(book, "Over", 1.9, market="totals", point=2.5, **kwargs),  # type: ignore[arg-type]
        _offer(book, "Under", 1.95, market="totals", point=2.5, **kwargs),  # type: ignore[arg-type]
    ]


def test_q1_kickoff_follows_the_latest_admissible_listing_in_any_market(tmp_path: Path) -> None:
    def full(**kwargs: object) -> list[dict[str, object]]:
        return [
            row
            for book in ("a", "b", "c")
            for row in (*_book(book, 2.0, 3.4, 3.9, **kwargs), *_totals(book, **kwargs))
        ]

    later = KICKOFF + timedelta(hours=3)
    other = {"event": "event-2", "kickoff": KICKOFF + timedelta(days=2)}
    store = _store(
        tmp_path,
        [
            (201, KICKOFF - timedelta(hours=30), full()),
            (202, KICKOFF - timedelta(hours=24), full()),
            (203, KICKOFF - timedelta(hours=1), full()),
            # The match is postponed; this admissible acquisition lists it in totals only.
            (204, KICKOFF + timedelta(hours=1), _totals("a", kickoff=later) + full(**other)),
            (205, KICKOFF + timedelta(hours=5), full(**other)),
        ],
    )
    row = _q1_rows(store)[(PROVIDER, "soccer_epl", "event-1")]
    assert (row["kickoff_utc"], row["status"], row["reason"]) == (
        _z(later),
        "EXCLUDED",
        "KICKOFF_CHANGED",
    )


def test_q1_reports_matches_listed_without_1x2_rows(tmp_path: Path) -> None:
    books = [row for book in ("a", "b", "c") for row in _book(book, 2.0, 3.4, 3.9)]
    totals_only = [row for book in ("a", "b") for row in _totals(book, event="event-9")]
    store = _store(
        tmp_path / "gap",
        [
            (1100, KICKOFF - timedelta(hours=30), books + totals_only),
            (1101, KICKOFF - timedelta(hours=24), books + totals_only),
            (1102, KICKOFF - timedelta(hours=1), _totals("a") + totals_only),
            (1104, KICKOFF + timedelta(hours=2), []),
        ],
    )
    payload = answer_q1(AcquisitionCatalog(store))
    rows = _q1_rows(store)
    assert rows[(PROVIDER, "soccer_epl", "event-1")]["reason"] == "PREMATCH_ABSENT:H2H_NOT_LISTED"
    assert rows[(PROVIDER, "soccer_epl", "event-9")]["reason"] == "REFERENCE_ABSENT:H2H_NOT_LISTED"
    assert payload["summary"]["match_count"] == 2  # type: ignore[index]


def test_match_labels_and_q1_order_never_depend_on_row_order(tmp_path: Path) -> None:
    swapped = "Leeds United — Arsenal"

    def offers() -> list[dict[str, object]]:
        return [
            *_book("a", 2.0, 3.4, 3.9),
            *_book("b", 2.0, 3.4, 3.9, match=swapped),
            *_book("c", 2.0, 3.4, 3.9, match=swapped),
            *_book("a", 1.5, 4.0, 6.0, event="event-3", period="FIRST_HALF"),
            *_book("a", 1.5, 4.0, 6.0, event="event-3"),
        ]

    answers = []
    for name, order in (("forward", 1), ("reverse", -1)):
        store = _store(
            tmp_path / name,
            [
                (301, KICKOFF - timedelta(hours=30), offers()[::order]),
                (302, KICKOFF - timedelta(hours=24), offers()[::order]),
                (303, KICKOFF - timedelta(hours=1), offers()[::order]),
                (304, KICKOFF + timedelta(hours=1), []),
            ],
        )
        q1 = answer_q1(AcquisitionCatalog(store))["rows"]
        q3 = _q3(
            store, previous="302", current="303", event="event-1", market="h2h", outcome="Arsenal"
        )
        answers.append((q1, q3["selection"], q3["rows"]))
    assert answers[0] == answers[1]
    rows = {row["event_id"]: row for row in answers[0][0]}  # type: ignore[union-attr]
    assert rows["event-1"]["match"] == f"Arsenal — Leeds United / {swapped}"


def test_q3_selection_names_the_sport_and_q1_links_carry_it(tmp_path: Path) -> None:
    from robin.capture.real_data_questions import list_selections

    books = [row for book in ("a", "b", "c") for row in _book(book, 2.0, 3.4, 3.9)]
    stray = [_offer("z", "Arsenal", 2.2, sport="soccer_france_ligue_one")]
    store = _store(
        tmp_path,
        [
            (711, KICKOFF - timedelta(hours=30), books),
            (712, KICKOFF - timedelta(hours=24), books + stray),
            (713, KICKOFF - timedelta(hours=1), books),
            (714, KICKOFF + timedelta(hours=1), []),
        ],
    )
    catalog = AcquisitionCatalog(store)
    view = catalog.view()
    previous, current = view.by_run("712"), view.by_run("713")
    listed = list_selections(catalog.rows(previous), catalog.rows(current), "event-1")
    arsenal = [item for item in listed if item["outcome"] == "Arsenal"]
    assert [(item["sport_key"], item["previous_bookmakers"]) for item in arsenal] == [
        ("soccer_epl", 3),
        ("soccer_france_ligue_one", 1),
    ]
    request = {"previous": "712", "current": "713", "event": "event-1", "market": "h2h"}
    with pytest.raises(QuestionError, match="SELECTION_AMBIGUOUS"):
        _q3(store, **request, outcome="Arsenal")
    payload = _q3(store, **request, outcome="Arsenal", sport="soccer_epl")
    assert payload["selection"]["sport_key"] == "soccer_epl"  # type: ignore[index]
    assert set(_statuses(payload)) == {"a", "b", "c"}
    assert (
        to_csv_bytes(payload)
        .splitlines()[0]
        .startswith(b"previous_run_id,current_run_id,event_id,sport_key,")
    )
    page = QuestionPages(catalog).respond("/questions/q1", "")[1].decode()
    assert "sport=soccer_epl" in page


def test_q1_boundaries_follow_the_whole_store_and_name_missing_branches(tmp_path: Path) -> None:
    both = [row for book in ("a", "b", "c") for row in _book(book, 2.0, 3.4, 3.9)] + [
        row
        for book in ("a", "b", "c")
        for row in _book(book, 1.7, 3.8, 4.6, event="event-7", sport="soccer_france_ligue_one")
    ]
    times = [KICKOFF - timedelta(hours=hours) for hours in (30, 24, 1)] + [
        KICKOFF + timedelta(hours=1)
    ]
    acquisitions = [(1300 + index, at, both) for index, at in enumerate(times)]
    ligue_one = ("soccer_france_ligue_one",)
    dropped = _store(
        tmp_path / "dropped", acquisitions, branches={1302: ligue_one, 1303: ligue_one}
    )
    row = _q1_rows(dropped)[(PROVIDER, "soccer_epl", "event-1")]
    assert (row["status"], row["reason"]) == ("EXCLUDED", "PREMATCH_ABSENT:BRANCH_ABSENT")
    added = _store(tmp_path / "added", acquisitions, branches={1300: ligue_one, 1301: ligue_one})
    row = _q1_rows(added)[(PROVIDER, "soccer_epl", "event-1")]
    assert (row["status"], row["reason"]) == ("EXCLUDED", "REFERENCE_ABSENT:BRANCH_ABSENT")


def test_q1_absence_windows_use_the_candidates_exact_boundaries(tmp_path: Path) -> None:
    both = [row for book in ("a", "b", "c") for row in _book(book, 2.0, 3.4, 3.9)] + [
        row
        for book in ("a", "b", "c")
        for row in _book(book, 1.7, 3.8, 4.6, event="event-7", sport="soccer_france_ligue_one")
    ]
    times = [KICKOFF - timedelta(hours=hours) for hours in (30, 24, 6)] + [
        KICKOFF + timedelta(hours=1)
    ]
    store = _store(
        tmp_path,
        [(1400 + index, at, both) for index, at in enumerate(times)],
        branches={1402: ("soccer_france_ligue_one",)},
    )
    row = _q1_rows(store)[(PROVIDER, "soccer_epl", "event-1")]
    assert (row["status"], row["reason"]) == ("EXCLUDED", "PREMATCH_ABSENT:BRANCH_ABSENT")


def test_q1_reference_settled_by_the_first_acquisition_is_not_out_of_store(
    tmp_path: Path,
) -> None:
    books = [row for book in ("a", "b", "c") for row in _book(book, 2.0, 3.4, 3.9)]
    later = [row for book in ("a", "b", "c") for row in _book(book, 1.9, 3.5, 4.0)]
    times = [
        KICKOFF - timedelta(hours=24),
        KICKOFF - timedelta(hours=1),
        KICKOFF + timedelta(hours=1),
    ]
    store = _store(
        tmp_path, [(1500, times[0], books), (1501, times[1], later), (1502, times[2], [])]
    )
    payload = answer_q1(AcquisitionCatalog(store))
    row = _q1_rows(store)[(PROVIDER, "soccer_epl", "event-1")]
    assert (row["status"], row["reference_run_id"], row["reference_class"]) == (
        "INCLUDED",
        "1500",
        "J_MINUS_24H",
    )
    assert payload["store"]["first_acquired_at_utc"] == _z(times[0])  # type: ignore[index]


def test_q1_store_start_ignores_slot_times_of_failed_branches(tmp_path: Path) -> None:
    kickoff = KICKOFF + timedelta(hours=1)
    books = [row for book in ("a", "b", "c") for row in _book(book, 2.0, 3.4, 3.9, kickoff=kickoff)]
    first = kickoff - timedelta(hours=23, minutes=30)  # 30 min after the reference target
    store = _store(
        tmp_path,
        [
            (1600, first, books),
            (1601, kickoff - timedelta(hours=1), books),
            (1602, kickoff + timedelta(hours=1), []),
        ],
        stubs={1600: ("soccer_france_ligue_one",)},
        # Later runs without that sport avoid the shared engine's known stub defect.
        branches={1601: ("soccer_epl",), 1602: ("soccer_epl",)},
    )
    payload = answer_q1(AcquisitionCatalog(store))
    row = _q1_rows(store)[(PROVIDER, "soccer_epl", "event-1")]
    # A capture before the store could be nearer the target than the first stored one.
    assert row["status"] == "OUT_OF_STORE"
    assert payload["store"]["first_acquired_at_utc"] == _z(first)  # type: ignore[index]


def test_q1_never_claims_not_listed_over_failed_captures(tmp_path: Path) -> None:
    match = [row for book in ("a", "b", "c") for row in _book(book, 2.0, 3.4, 3.9)]
    other = [
        row
        for book in ("a", "b", "c")
        for row in _book(book, 1.5, 4.0, 6.0, event="event-2", kickoff=KICKOFF + timedelta(days=2))
    ]
    hours = (30, 24, 5, 3, 1)
    acquisitions = [
        (1700 + index, KICKOFF - timedelta(hours=value), (match if value >= 24 else []) + other)
        for index, value in enumerate(hours)
    ] + [(1705, KICKOFF + timedelta(hours=1), other)]
    store = _store(
        tmp_path, acquisitions, incomplete={1702: ("soccer_epl",), 1703: ("soccer_epl",)}
    )
    row = _q1_rows(store)[(PROVIDER, "soccer_epl", "event-1")]
    assert (row["status"], row["reason"]) == ("EXCLUDED", "PREMATCH_ABSENT:BRANCH_NOT_ADMISSIBLE")


def test_q1_web_filters_refuse_unknown_values(tmp_path: Path) -> None:
    pages = QuestionPages(AcquisitionCatalog(_q1_store(tmp_path)))
    for query in ("status=included", "status=BOGUS", "strict=true", "strict=on"):
        for path in ("/questions/q1", "/questions/q1.json", "/questions/q1.csv"):
            status, body, _, _ = pages.respond(path, query)
            assert status == 400 and b"QUERY_INVALID" in body, (path, query)
    assert pages.respond("/questions/q1.json", "status=INCLUDED&strict=1")[0] == 200


def test_q1_never_invents_a_capture_time_for_a_run_without_one(tmp_path: Path) -> None:
    kickoff = KICKOFF + timedelta(hours=1)
    books = [row for book in ("a", "b", "c") for row in _book(book, 2.0, 3.4, 3.9, kickoff=kickoff)]
    other = [
        row
        for book in ("a", "b", "c")
        for row in _book(book, 1.5, 4.0, 6.0, event="event-2", kickoff=kickoff + timedelta(days=2))
    ]
    start = [
        (1800, kickoff - timedelta(hours=30), books),
        (1801, kickoff - timedelta(hours=24), books),
    ]

    # A failed run after kickoff does not extend the store: the match stays pending.
    late = _store(
        tmp_path / "late",
        [
            *start,
            (1802, kickoff - timedelta(hours=1), books),
            (1803, kickoff + timedelta(hours=1), []),
        ],
        stubs={1803: SPORTS},
        fresh=(1803,),
    )
    payload = answer_q1(AcquisitionCatalog(late))
    assert _q1_rows(late)[(PROVIDER, "soccer_epl", "event-1")]["status"] == "PENDING"
    assert payload["store"]["last_acquired_at_utc"] == _z(kickoff - timedelta(hours=1))  # type: ignore[index]

    # A failed run whose slot straddles the window cannot be placed in it or out of it.
    straddle = kickoff - timedelta(hours=6, minutes=30)  # slot starts before the 6 h bound
    unknown = _store(
        tmp_path / "unknown",
        [*start, (1802, straddle, []), (1803, kickoff + timedelta(hours=1), other)],
        stubs={1802: SPORTS},
        fresh=(1802, 1803),
    )
    row = _q1_rows(unknown)[(PROVIDER, "soccer_epl", "event-1")]
    assert row["reason"] == "PREMATCH_ABSENT:CAPTURE_TIME_UNKNOWN"

    # A failed run whose whole slot lies in the window is a failed branch in that window.
    inside = _store(
        tmp_path / "inside",
        [
            *start,
            (1802, kickoff - timedelta(hours=2, minutes=30), []),
            (1803, kickoff + timedelta(hours=1), other),
        ],
        stubs={1802: SPORTS},
        fresh=(1802, 1803),
    )
    row = _q1_rows(inside)[(PROVIDER, "soccer_epl", "event-1")]
    assert row["reason"] == "PREMATCH_ABSENT:BRANCH_NOT_ADMISSIBLE"


def test_q1_never_places_a_failed_branch_with_another_sports_time(tmp_path: Path) -> None:
    kickoff = KICKOFF + timedelta(hours=1)
    books = [row for book in ("a", "b", "c") for row in _book(book, 2.0, 3.4, 3.9, kickoff=kickoff)]
    ligue_one = [
        row
        for book in ("a", "b", "c")
        for row in _book(
            book, 1.5, 4.0, 6.0, event="event-2", sport="soccer_france_ligue_one", kickoff=kickoff
        )
    ]
    # The run's Ligue 1 capture lies inside the 6 h window, but its slot starts before it.
    straddle = kickoff - timedelta(hours=5, minutes=30)
    store = _store(
        tmp_path,
        [
            (1900, kickoff - timedelta(hours=30), books + ligue_one),
            (1901, kickoff - timedelta(hours=24), books + ligue_one),
            (1902, straddle, ligue_one),
            (1903, kickoff + timedelta(hours=1), ligue_one),
        ],
        stubs={1902: ("soccer_epl",)},
        fresh=(1902, 1903),
        branches={1903: ("soccer_france_ligue_one",)},
    )
    row = _q1_rows(store)[(PROVIDER, "soccer_epl", "event-1")]
    assert row["reason"] == "PREMATCH_ABSENT:CAPTURE_TIME_UNKNOWN"


def test_q1_unplaced_runs_take_precedence_over_definite_absences(tmp_path: Path) -> None:
    kickoff = KICKOFF + timedelta(hours=1)
    books = [row for book in ("a", "b", "c") for row in _book(book, 2.0, 3.4, 3.9, kickoff=kickoff)]
    ligue_one = [
        row
        for book in ("a", "b", "c")
        for row in _book(
            book, 1.5, 4.0, 6.0, event="event-2", sport="soccer_france_ligue_one", kickoff=kickoff
        )
    ]
    only_ligue_one = ("soccer_france_ligue_one",)
    store = _store(
        tmp_path,
        [
            (2000, kickoff - timedelta(hours=30), books + ligue_one),
            (2001, kickoff - timedelta(hours=24), books + ligue_one),
            # A failed run whose slot straddles the 6 h bound: it cannot be placed.
            (2002, kickoff - timedelta(hours=6, minutes=30), []),
            # A run wholly inside the window without the EPL branch.
            (2003, kickoff - timedelta(hours=2, minutes=30), ligue_one),
            (2004, kickoff + timedelta(hours=1), ligue_one),
        ],
        stubs={2002: SPORTS},
        fresh=(2002, 2003),
        branches={2003: only_ligue_one, 2004: only_ligue_one},
    )
    row = _q1_rows(store)[(PROVIDER, "soccer_epl", "event-1")]
    assert row["reason"] == "PREMATCH_ABSENT:CAPTURE_TIME_UNKNOWN"
