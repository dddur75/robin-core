"""Explorer-only descriptive questions over verified local acquisitions.

Q3 compares one exact offer selection between two chosen acquisitions. Q1 follows
the 1X2 favourite from its initial reference to the last pre-match observation.
Both reuse ``compare_acquisitions``; the collection never imports this module, and
nothing here supports a betting decision or a causal reading.
"""

from __future__ import annotations

import csv
import io
import json
import math
import re
import threading
from collections import OrderedDict, defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from robin.capture.real_data_dashboard import (
    _quantile,
    _snapshot_branch_lineages,
    _snapshot_branch_observation_times,
    compare_acquisitions,
)
from robin.capture.real_data_explorer import (
    AtomicExplorerStore,
    BundleValidationError,
    _source_semantic_sha256,
    validate_source_bundle,
)

NOTICE = "Exploration descriptive : aucun edge validé, aucun conseil de pari, aucune causalité."
ENGINE = "robin.capture.real_data_dashboard.compare_acquisitions"
REFERENCE_OFFSET = timedelta(hours=24)
REFERENCE_EXACT = timedelta(minutes=60)
REFERENCE_NEAR = timedelta(minutes=180)
PREMATCH_CLOSE = timedelta(minutes=120)
PREMATCH_FAR = timedelta(minutes=360)
MINIMUM_CONSENSUS_BOOKMAKERS = 3
Q1_RULES: dict[str, object] = {
    "market_key": "h2h",
    "kickoff": "kickoff_utc of the latest admissible acquisition listing the match",
    "observation_time": "capture_time_utc of the sport branch, one value per acquisition",
    "reference_target": "kickoff - 24 h in UTC",
    "reference_classes_minutes": {"J_MINUS_24H": 60, "NEAR": 180},
    "prematch": "last admissible capture strictly after the reference and before kickoff",
    "prematch_classes_minutes": {"WITHIN_2H": 120, "WITHIN_6H": 360},
    "favourite": "lowest median price at the reference over complete 1X2 bookmakers",
    "minimum_consensus_bookmakers": MINIMUM_CONSENSUS_BOOKMAKERS,
    "excluded": ["FAVOURITE_TIE", "FAVOURITE_IS_DRAW", "CONSENSUS_INSUFFICIENT"],
    "movement": "bookmakers observed at both instants, compared by compare_acquisitions",
    "last_prematch_price": "last price observed before kickoff, never a closing price",
}
_ADMISSIBLE = frozenset({"COMPLETE", "PARTIAL"})
_POINT_TEXT = re.compile(r"^[0-9]{1,3}(?:\.[0-9]{1,4})?$")
_MARKETS = ("h2h", "totals")
_MATCHED = frozenset({"UP", "DOWN", "UNCHANGED"})
_STATUS_ORDER = (
    "UP",
    "DOWN",
    "UNCHANGED",
    "APPEARED",
    "NOT_OBSERVED",
    "EVENT_STARTED_BEFORE_CURRENT",
    "EXCLUDED",
)
_GATES = {
    "BRANCH_NOT_ADMISSIBLE": "BRANCH_NOT_COMPARABLE",
    "BRANCH_TIME_INVALID": "BRANCH_TIME_INVALID",
    "ACQUISITION_MULTI_CAPTURE": "ACQUISITION_MULTI_CAPTURE",
    "BRANCH_LINEAGE_MISSING": "BRANCH_LINEAGE_INCOMPARABLE",
}
EventKey = tuple[str | None, str | None, str, str]
Row = Mapping[str, object]


class QuestionError(ValueError):
    """A stable refusal code that never echoes a request parameter."""


def _instant(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return None if parsed.utcoffset() is None else parsed.astimezone(UTC)


def _iso(value: datetime | None) -> str | None:
    return None if value is None else value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _minutes(value: timedelta) -> float:
    return round(value.total_seconds() / 60, 2)


def _number(value: object) -> float:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    return math.nan


def _price(row: Row | None) -> float | None:
    price = _number(row.get("price")) if row is not None else math.nan
    return price if math.isfinite(price) and 1.0 < price <= 10_000.0 else None


def _same_point(left: object, right: object) -> bool:
    if left is None or right is None:
        return left is None and right is None
    return math.isfinite(_number(left)) and _number(left) == _number(right)


def _median(values: Sequence[float]) -> float | None:
    return round(_quantile(values, 0.5), 6) if values else None


def _counts(rows: Sequence[Row], field: str, values: Sequence[str]) -> dict[str, int]:
    return {value: sum(row.get(field) == value for row in rows) for value in values}


def event_key(row: Row) -> EventKey | None:
    sport, event = row.get("sport_key"), row.get("event_id")
    if not isinstance(sport, str) or not sport or not isinstance(event, str) or not event:
        return None
    provider, period = row.get("provider_key"), row.get("settlement_period_key")
    return (
        provider if isinstance(provider, str) else None,
        period if isinstance(period, str) else None,
        sport,
        event,
    )


@dataclass(frozen=True)
class SportState:
    admissible: bool
    reason: str | None
    observed_at: datetime | None
    lineage: frozenset[tuple[object, object]]
    branch_times: tuple[datetime, ...]


@dataclass(frozen=True)
class EventState:
    match: str
    kickoff: datetime | None
    h2h_outcomes: frozenset[str]


@dataclass(frozen=True)
class Acquisition:
    run_id: str
    slot_start_utc: str
    slot_time: datetime
    version: str
    source_semantic_sha256: str
    receipt_sha256: str
    collection_health: str
    row_count: int
    sports: Mapping[str, SportState]
    events: Mapping[EventKey, EventState]

    def provenance(self) -> dict[str, object]:
        return {
            "run_id": self.run_id,
            "slot_start_utc": self.slot_start_utc,
            "source_semantic_sha256": self.source_semantic_sha256,
            "source_receipt_sha256": self.receipt_sha256,
        }


def _sport_states(snapshot: Row, rows: Sequence[Row]) -> dict[str, SportState]:
    explicit = snapshot.get("comparable_branch_sports")
    statuses: dict[str, set[object]] = defaultdict(set)
    captures: dict[str, set[datetime | None]] = defaultdict(set)
    row_lineages: dict[str, set[tuple[object, object]]] = defaultdict(set)
    for row in rows:
        sport = row.get("sport_key")
        if isinstance(sport, str) and sport:
            captures[sport].add(_instant(row.get("capture_time_utc")))
            row_lineages[sport].add((row.get("provider_key"), row.get("settlement_period_key")))
            if "branch_status" in row:
                statuses[sport].add(row.get("branch_status"))
    if isinstance(explicit, list):
        comparable = {value for value in explicit if isinstance(value, str)}
    else:
        comparable = {sport for sport, seen in statuses.items() if seen and seen <= _ADMISSIBLE}
    lineages = _snapshot_branch_lineages(snapshot)
    raw_times = _snapshot_branch_observation_times(snapshot)
    states: dict[str, SportState] = {}
    for sport in sorted(set(lineages) | set(raw_times) | set(captures)):
        parsed = [_instant(value) for value in raw_times.get(sport, [])]
        valid = [value for value in parsed if value is not None]
        seen = captures.get(sport, set())
        reason = None
        if sport not in comparable:
            reason = "BRANCH_NOT_ADMISSIBLE"
        elif not parsed or len(valid) != len(parsed) or None in seen:
            reason = "BRANCH_TIME_INVALID"
        elif len(seen) > 1:
            reason = "ACQUISITION_MULTI_CAPTURE"
        elif not lineages.get(sport):
            reason = "BRANCH_LINEAGE_MISSING"
        observed = (
            next(iter(seen)) if len(seen) == 1 else (max(valid) if valid and not seen else None)
        )
        states[sport] = SportState(
            admissible=reason is None,
            reason=reason,
            observed_at=observed,
            lineage=frozenset(lineages.get(sport, set()) | row_lineages.get(sport, set())),
            branch_times=tuple(sorted(valid)),
        )
    return states


def _event_states(rows: Sequence[Row]) -> dict[EventKey, EventState]:
    matches: dict[EventKey, set[str]] = defaultdict(set)
    kickoffs: dict[EventKey, set[datetime | None]] = defaultdict(set)
    outcomes: dict[EventKey, set[str]] = defaultdict(set)
    for row in rows:
        key = event_key(row)
        if key is None:
            continue
        matches[key].add(str(row.get("match") or key[3]))
        kickoffs[key].add(_instant(row.get("kickoff_utc")))
        if row.get("market_key") == "h2h" and isinstance(row.get("outcome"), str):
            outcomes[key].add(str(row["outcome"]))
    return {
        key: EventState(
            # Every stored label is kept, in a fixed order, so row order never picks one.
            match=" / ".join(sorted(match)),
            kickoff=next(iter(kickoffs[key])) if len(kickoffs[key]) == 1 else None,
            h2h_outcomes=frozenset(outcomes[key]),
        )
        for key, match in matches.items()
    }


@dataclass(frozen=True)
class CatalogView:
    acquisitions: tuple[Acquisition, ...]
    rejected: tuple[tuple[str, str], ...]

    def by_run(self, run_id: str | None) -> Acquisition:
        for acquisition in self.acquisitions:
            if acquisition.run_id == run_id:
                return acquisition
        raise QuestionError("ACQUISITION_UNKNOWN")

    def fingerprint(self) -> tuple[object, ...]:
        accepted = tuple(
            (item.run_id, item.version, item.source_semantic_sha256, item.receipt_sha256)
            for item in self.acquisitions
        )
        return accepted, self.rejected

    def store_summary(self) -> dict[str, object]:
        items = self.acquisitions
        return {
            "acquisition_count": len(items),
            "first_slot_start_utc": items[0].slot_start_utc if items else None,
            "last_slot_start_utc": items[-1].slot_start_utc if items else None,
            "acquisitions": [item.provenance() for item in items],
            "rejected_versions": [{"version": name, "code": code} for name, code in self.rejected],
        }


class AcquisitionCatalog:
    """Read verified stored versions without moving the pointer or re-rendering history."""

    def __init__(self, store: AtomicExplorerStore, *, row_cache_size: int = 8) -> None:
        self.store = store
        self.loads = 0
        self._lock = threading.RLock()
        self._index: dict[str, tuple[bytes, Acquisition | None, str | None]] = {}
        self._rows: OrderedDict[str, tuple[Row, ...]] = OrderedDict()
        self._row_cache_size = max(2, row_cache_size)

    def _remember(self, version: str, rows: tuple[Row, ...]) -> None:
        self._rows[version] = rows
        self._rows.move_to_end(version)
        while len(self._rows) > self._row_cache_size:
            self._rows.popitem(last=False)

    def _load(self, version: str) -> tuple[dict[str, object], tuple[Row, ...], str]:
        root = self.store.versions / version
        manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
        validated = validate_source_bundle(root / "source")
        if (
            not isinstance(manifest, dict)
            or manifest.get("schema_version") != "robin-local-explorer-version-v1"
            or str(manifest.get("run_id")) != validated.run_id
            or manifest.get("source_receipt_sha256") != validated.receipt_sha256
        ):
            raise QuestionError("LOCAL_MANIFEST_INVALID")
        snapshot = dict(validated.snapshot)
        rows = snapshot.get("rows")
        if snapshot.get("data_role", "CURRENT") != "CURRENT":
            raise QuestionError("DATA_ROLE_NOT_CURRENT")
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise QuestionError("SOURCE_JSON_ROWS_INVALID")
        self.loads += 1
        return snapshot, tuple(rows), validated.receipt_sha256

    def _index_version(self, version: str, marker: bytes) -> None:
        try:
            snapshot, rows, receipt = self._load(version)
            slot = _instant(snapshot.get("data_slot_start_utc") or snapshot.get("slot_start_utc"))
            if slot is None:
                raise QuestionError("SOURCE_TIME_INVALID")
            acquisition = Acquisition(
                run_id=str(snapshot.get("github_run_id")),
                slot_start_utc=_iso(slot) or "",
                slot_time=slot,
                version=version,
                source_semantic_sha256=_source_semantic_sha256(snapshot),
                receipt_sha256=receipt,
                collection_health=str(snapshot.get("collection_health") or "UNKNOWN"),
                row_count=len(rows),
                sports=_sport_states(snapshot, rows),
                events=_event_states(rows),
            )
        except (BundleValidationError, QuestionError) as exc:
            self._index[version] = (marker, None, str(exc))
        except (OSError, ValueError, TypeError, KeyError, AttributeError):
            self._index[version] = (marker, None, "LOCAL_VERSION_UNREADABLE")
        else:
            self._index[version] = (marker, acquisition, None)
            self._remember(version, rows)

    def view(self) -> CatalogView:
        """List verified acquisitions once each; conflicting copies or slots are refused."""

        with self._lock:
            names = sorted(
                path.name
                for path in self.store.versions.iterdir()
                if path.is_dir() and path.name.startswith("run-")
            )
            for stale in set(self._index) - set(names):
                del self._index[stale]
            for name in names:
                try:
                    marker = (self.store.versions / name / "manifest.json").read_bytes()
                except OSError:
                    marker = b""
                cached = self._index.get(name)
                if cached is None or cached[0] != marker or cached[1] is None:
                    self._index_version(name, marker)
            rejected = [(name, code) for name, (_, item, code) in self._index.items() if code]
            by_run: dict[str, list[Acquisition]] = defaultdict(list)
            for _, item, _ in self._index.values():
                if item is not None:
                    by_run[item.run_id].append(item)
            by_slot: dict[datetime, list[Acquisition]] = defaultdict(list)
            for copies in by_run.values():
                if len({copy.source_semantic_sha256 for copy in copies}) != 1:
                    rejected += [(copy.version, "ACQUISITION_IDENTITY_CONFLICT") for copy in copies]
                    continue
                chosen = min(copies, key=lambda copy: copy.version)
                by_slot[chosen.slot_time].append(chosen)
            accepted = []
            for items in by_slot.values():
                if len(items) > 1:
                    rejected += [(item.version, "SLOT_IDENTITY_CONFLICT") for item in items]
                else:
                    accepted.extend(items)
            accepted.sort(key=lambda item: (item.slot_time, item.run_id))
            return CatalogView(tuple(accepted), tuple(sorted(rejected)))

    def rows(self, acquisition: Acquisition) -> tuple[Row, ...]:
        with self._lock:
            cached = self._rows.get(acquisition.version)
            if cached is None:
                try:
                    snapshot, cached, _ = self._load(acquisition.version)
                except (OSError, json.JSONDecodeError, UnicodeDecodeError):
                    raise BundleValidationError("LOCAL_VERSION_UNREADABLE") from None
                if _source_semantic_sha256(snapshot) != acquisition.source_semantic_sha256:
                    raise QuestionError("ACQUISITION_CHANGED_ON_DISK")
            self._remember(acquisition.version, cached)
            return cached


@dataclass(frozen=True)
class Selection:
    event_id: str
    market_key: str
    outcome: str
    point: float | None
    provider_key: str | None
    settlement_period_key: str | None
    sport_key: str

    def matches(self, row: Row) -> bool:
        return (
            row.get("event_id") == self.event_id
            and row.get("sport_key") == self.sport_key
            and row.get("market_key") == self.market_key
            and row.get("outcome") == self.outcome
            and _same_point(row.get("point"), self.point)
            and row.get("provider_key") == self.provider_key
            and row.get("settlement_period_key") == self.settlement_period_key
        )


def _bounded_text(value: str | None, code: str) -> str:
    if value is None or not value.strip() or len(value) > 200:
        raise QuestionError(code)
    if any(ord(character) < 32 for character in value):
        raise QuestionError(code)
    return value


def resolve_selection(
    options: Mapping[str, str | None], previous_rows: Sequence[Row], current_rows: Sequence[Row]
) -> Selection:
    """Resolve an exact selection; an omitted sport, provider or period must be unique."""

    event = _bounded_text(options.get("event"), "SELECTION_EVENT_INVALID")
    market = options.get("market")
    outcome = _bounded_text(options.get("outcome"), "SELECTION_OUTCOME_INVALID")
    point_text = options.get("point") or None
    if market not in _MARKETS:
        raise QuestionError("SELECTION_MARKET_INVALID")
    if (market == "h2h") != (point_text is None):
        raise QuestionError("SELECTION_POINT_INVALID")
    point = None
    if point_text is not None:
        point = float(point_text) if _POINT_TEXT.fullmatch(point_text) else 0.0
        if not 0 < point <= 100:
            raise QuestionError("SELECTION_POINT_INVALID")
    candidates = {
        (row.get("sport_key"), row.get("provider_key"), row.get("settlement_period_key"))
        for row in (*previous_rows, *current_rows)
        if row.get("event_id") == event
        and row.get("market_key") == market
        and row.get("outcome") == outcome
        and _same_point(row.get("point"), point)
    }
    for position, name in enumerate(("sport", "provider", "period")):
        if name in options:
            candidates = {item for item in candidates if item[position] == (options[name] or None)}
    if len(candidates) != 1:
        raise QuestionError("SELECTION_AMBIGUOUS" if candidates else "SELECTION_NOT_FOUND")
    sport, provider, period = next(iter(candidates))
    return Selection(
        event,
        str(market),
        outcome,
        point,
        provider if isinstance(provider, str) else None,
        period if isinstance(period, str) else None,
        str(sport),
    )


def _pair_gate(previous: Acquisition, current: Acquisition, sport: str) -> str | None:
    before, after = previous.sports.get(sport), current.sports.get(sport)
    if before is None or after is None:
        return "BRANCH_NOT_COMPARABLE"
    for state in (before, after):
        if not state.admissible:
            return _GATES.get(state.reason or "", "BRANCH_NOT_COMPARABLE")
    if before.lineage != after.lineage:
        return "BRANCH_LINEAGE_INCOMPARABLE"
    if min(after.branch_times) <= max(before.branch_times):
        return "NON_FORWARD_BRANCH_TIME"
    return None


def _offer(
    status: str, before: Row | None, after: Row | None, reason: str | None = None
) -> dict[str, object]:
    source = after or before or {}
    row: dict[str, object] = {
        "status": status,
        "reason": reason,
        "side": None if reason is None else ("current" if after is not None else "previous"),
        "bookmaker_key": source.get("bookmaker_key"),
        "bookmaker": source.get("bookmaker"),
    }
    for prefix, item in (("previous", before), ("current", after)):
        row[f"{prefix}_price"] = _price(item)
        row[f"{prefix}_capture_time_utc"] = item.get("capture_time_utc") if item else None
        row[f"{prefix}_source_timestamp_utc"] = item.get("source_timestamp_utc") if item else None
    prices = (_price(before), _price(after))
    if reason is None and prices[0] is not None and prices[1] is not None:
        row["delta"] = round(prices[1] - prices[0], 6)
    else:
        row["delta"] = None
    row["other_points_observed"] = []
    return row


def _excluded(side: str, row: Row | None, reason: str) -> dict[str, object]:
    if side == "previous":
        return _offer("EXCLUDED", row, None, reason)
    return _offer("EXCLUDED", None, row, reason)


def _items(value: object) -> list[dict[str, object]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def compare_selection(
    previous: Acquisition,
    previous_rows: Sequence[Row],
    current: Acquisition,
    current_rows: Sequence[Row],
    selection: Selection,
) -> dict[str, object]:
    """Compare one exact selection between two ordered acquisitions with the shared engine."""

    if previous.run_id == current.run_id:
        raise QuestionError("Q3_SAME_ACQUISITION")
    if previous.slot_time >= current.slot_time:
        raise QuestionError("Q3_ORDER_INVALID")
    lineage = (selection.provider_key, selection.settlement_period_key)
    in_event = [
        row
        for row in (*previous_rows, *current_rows)
        if (key := event_key(row)) is not None
        and key[2:] == (selection.sport_key, selection.event_id)
        and key[:2] == lineage
    ]
    sports = {str(row.get("sport_key")) for row in in_event}
    sides = {
        "previous": [row for row in previous_rows if selection.matches(row)],
        "current": [row for row in current_rows if selection.matches(row)],
    }
    if len(sports) != 1 or not (sides["previous"] or sides["current"]):
        raise QuestionError("SELECTION_AMBIGUOUS" if len(sports) > 1 else "SELECTION_NOT_FOUND")
    sport = next(iter(sports))
    match_key = (*lineage, sport, selection.event_id)
    gate = _pair_gate(previous, current, sport)
    rows: list[dict[str, object]] = []
    if gate is not None:
        rows = [_excluded(side, row, gate) for side, items in sides.items() for row in items]
    else:
        kept = sides
        before, after = previous.sports[sport], current.sports[sport]
        comparison = compare_acquisitions(
            kept["current"],
            kept["previous"],
            comparable_sports={sport},
            current_branch_lineages={sport: set(after.lineage)},
            previous_branch_lineages={sport: set(before.lineage)},
            current_branch_observation_times={sport: [_iso(at) for at in after.branch_times]},
            previous_branch_observation_times={sport: [_iso(at) for at in before.branch_times]},
        )
        books = {
            side: {row.get("bookmaker_key"): row for row in items} for side, items in kept.items()
        }
        # Same rule as Q1: a kickoff counts only when the stored rows agree on one value.
        listed = previous.events.get(match_key)
        kickoff = listed.kickoff if listed is not None else None
        started = (
            kickoff is not None
            and after.observed_at is not None
            and after.observed_at >= kickoff
            and not any(event_key(row) == match_key for row in current_rows)
        )
        for item in _items(comparison["matched_offers"]):
            book = item.get("bookmaker_key")
            pair = (books["previous"].get(book), books["current"].get(book))
            if _price(pair[0]) is None or _price(pair[1]) is None:
                rows += [_excluded("previous", pair[0], "INVALID_PRICE")]
                rows += [_excluded("current", pair[1], "INVALID_PRICE")]
            else:
                rows.append(_offer(str(item["direction"]), *pair))
        for item in _items(comparison["appeared_offers"]):
            offer = books["current"].get(item.get("bookmaker_key"))
            if _price(offer) is None:
                rows.append(_excluded("current", offer, "INVALID_PRICE"))
            else:
                rows.append(_offer("APPEARED", None, offer))
        for item in _items(comparison["not_observed_offers"]):
            offer = books["previous"].get(item.get("bookmaker_key"))
            status = "EVENT_STARTED_BEFORE_CURRENT" if started else "NOT_OBSERVED"
            if _price(offer) is None:
                rows.append(_excluded("previous", offer, "INVALID_PRICE"))
            else:
                rows.append(_offer(status, offer, None))
        used: dict[tuple[str, object], int] = defaultdict(int)
        for item in _items(comparison["excluded_rows"]):
            side, book = str(item.get("side")), item.get("bookmaker_key")
            originals = [row for row in kept.get(side, []) if row.get("bookmaker_key") == book]
            original = originals[min(used[(side, book)], len(originals) - 1)] if originals else None
            used[(side, book)] += 1
            rows.append(_excluded(side, original, str(item.get("reason"))))
    if selection.market_key == "totals":
        for row in rows:
            other = {"APPEARED": previous_rows, "NOT_OBSERVED": current_rows}.get(
                str(row["status"]), ()
            )
            row["other_points_observed"] = sorted(
                {
                    _number(item.get("point"))
                    for item in other
                    if event_key(item) == match_key
                    and item.get("bookmaker_key") == row["bookmaker_key"]
                    and item.get("market_key") == "totals"
                    and item.get("outcome") == selection.outcome
                    and math.isfinite(_number(item.get("point")))
                    and not _same_point(item.get("point"), selection.point)
                }
            )
    rows.sort(
        key=lambda row: (
            _STATUS_ORDER.index(str(row["status"])),
            str(row["bookmaker_key"]),
            str(row["side"]),
            str(row["reason"]),
        )
    )
    kickoffs = {
        side: sorted({str(row.get("kickoff_utc")) for row in items if event_key(row) == match_key})
        for side, items in (("previous", previous_rows), ("current", current_rows))
    }
    return {
        "schema_version": "robin-explorer-q3-v1",
        "question": "Q3",
        "notice": NOTICE,
        "engine": ENGINE,
        "status": gate or "COMPARED",
        "selection": {
            "event_id": selection.event_id,
            "sport_key": sport,
            "match": " / ".join(
                sorted({str(row.get("match") or selection.event_id) for row in in_event})
            ),
            "market_key": selection.market_key,
            "outcome": selection.outcome,
            "point": selection.point,
            "provider_key": selection.provider_key,
            "settlement_period_key": selection.settlement_period_key,
        },
        "acquisitions": {"previous": previous.provenance(), "current": current.provenance()},
        "kickoff": {
            "previous_kickoff_utc": kickoffs["previous"],
            "current_kickoff_utc": kickoffs["current"],
            "changed": bool(
                kickoffs["previous"]
                and kickoffs["current"]
                and kickoffs["previous"] != kickoffs["current"]
            ),
        },
        "summary": summarize_q3(rows),
        "rows": rows,
    }


def summarize_q3(rows: Sequence[Row]) -> dict[str, object]:
    """Summary of exactly the listed rows, so table, summary and exports agree."""

    matched = [row for row in rows if row["status"] in _MATCHED]
    reasons: dict[str, int] = defaultdict(int)
    for row in rows:
        if row["status"] == "EXCLUDED":
            reasons[str(row["reason"])] += 1
    return {
        "row_count": len(rows),
        "bookmaker_count": len({row["bookmaker_key"] for row in rows}),
        "status_counts": _counts(rows, "status", _STATUS_ORDER),
        "exclusion_reason_counts": dict(sorted(reasons.items())),
        "matched_count": len(matched),
        "previous_median_matched": _median([_number(row["previous_price"]) for row in matched]),
        "current_median_matched": _median([_number(row["current_price"]) for row in matched]),
        "median_delta": _median([_number(row["delta"]) for row in matched]),
    }


def list_selections(
    previous_rows: Sequence[Row], current_rows: Sequence[Row], event_id: str
) -> list[dict[str, object]]:
    """Exact selections offered for one match, with bookmaker counts on each side."""

    books: dict[tuple[object, ...], tuple[set[object], set[object]]] = defaultdict(
        lambda: (set(), set())
    )
    for position, rows in enumerate((previous_rows, current_rows)):
        for row in rows:
            if row.get("event_id") == event_id and row.get("market_key") in _MARKETS:
                point = None if row.get("point") is None else _number(row.get("point"))
                key = (
                    row.get("sport_key"),
                    row.get("market_key"),
                    point,
                    row.get("outcome"),
                    row.get("provider_key"),
                    row.get("settlement_period_key"),
                )
                books[key][position].add(row.get("bookmaker_key"))
    ordered = sorted(books.items(), key=lambda pair: tuple(repr(part) for part in pair[0]))
    return [
        {
            "sport_key": key[0],
            "market_key": key[1],
            "point": key[2],
            "outcome": key[3],
            "provider_key": key[4],
            "settlement_period_key": key[5],
            "previous_bookmakers": len(sides[0]),
            "current_bookmakers": len(sides[1]),
        }
        for key, sides in ordered
    ]


def answer_q3(catalog: AcquisitionCatalog, options: Mapping[str, str | None]) -> dict[str, object]:
    view = catalog.view()
    previous, current = view.by_run(options.get("previous")), view.by_run(options.get("current"))
    if previous.run_id == current.run_id:
        raise QuestionError("Q3_SAME_ACQUISITION")
    if previous.slot_time >= current.slot_time:
        raise QuestionError("Q3_ORDER_INVALID")
    previous_rows, current_rows = catalog.rows(previous), catalog.rows(current)
    selection = resolve_selection(options, previous_rows, current_rows)
    return compare_selection(previous, previous_rows, current, current_rows, selection)


# recurring_real_data.slot_start_utc maps every run to a two-hour UTC slot.
SLOT_WIDTH = timedelta(hours=2)


@dataclass(frozen=True)
class _Window:
    """One Q1 time window, shared by its candidates and its absence explanation."""

    start: datetime
    end: datetime
    start_open: bool
    end_open: bool

    def __contains__(self, at: datetime) -> bool:
        after = self.start < at if self.start_open else self.start <= at
        before = at < self.end if self.end_open else at <= self.end
        return after and before

    def holds_slot(self, slot: datetime) -> bool:
        """Whether the whole half-open slot [slot, slot + SLOT_WIDTH) is inside."""

        starts = self.start < slot if self.start_open else self.start <= slot
        return starts and self.end >= slot + SLOT_WIDTH

    def meets_slot(self, slot: datetime) -> bool:
        """Whether some instant of the half-open slot [slot, slot + SLOT_WIDTH) is inside."""

        low, low_open = (self.start, self.start_open) if self.start >= slot else (slot, False)
        high, high_open = (
            (self.end, self.end_open) if self.end < slot + SLOT_WIDTH else (slot + SLOT_WIDTH, True)
        )
        return low < high or (low == high and not low_open and not high_open)


def _absence(view: CatalogView, key: EventKey, window: _Window) -> str:
    """Explain an empty window from what was stored; a capture time is never invented."""

    stored = []
    without_branch = False
    unplaced = False
    for item in view.acquisitions:
        state = item.sports.get(key[2])
        # A branch is placed by its own time only; an absent branch by every capture of its run.
        if state is not None:
            times = [] if state.observed_at is None else [state.observed_at]
        else:
            times = [run.observed_at for run in item.sports.values() if run.observed_at is not None]
        if times:
            inside = [at in window for at in times]
            if not all(inside):
                unplaced = unplaced or any(inside)
                continue
        elif not window.holds_slot(item.slot_time):
            # No observed time: the run happened somewhere in its slot.
            unplaced = unplaced or window.meets_slot(item.slot_time)
            continue
        if state is None:
            without_branch = True
        else:
            stored.append(item)
    # One precedence for every window:
    # 1. a positive observation of the match without 1X2 rows;
    # 2. an acquisition that cannot be placed in or out of the window;
    # 3. evidence gaps among placed acquisitions (failed, then absent branch);
    # 4. only on complete evidence, a definite "not listed" or "lineage changed".
    admissible = [item for item in stored if item.sports[key[2]].admissible]
    if any(key in item.events for item in admissible):
        return "H2H_NOT_LISTED"
    if unplaced:
        return "CAPTURE_TIME_UNKNOWN"
    if len(admissible) < len(stored):
        return "BRANCH_NOT_ADMISSIBLE"
    if without_branch:
        return "BRANCH_ABSENT"
    if not stored:
        return "NO_ACQUISITION_IN_WINDOW"
    if any(other != key and other[2:] == key[2:] for item in admissible for other in item.events):
        return "LINEAGE_CHANGED"
    return "EVENT_NOT_LISTED"


def _favourite(
    rows: Sequence[Row], key: EventKey, labels: frozenset[str], kickoff: datetime
) -> tuple[str | None, str | None, int, float | None]:
    books: dict[object, dict[str, list[float | None]]] = defaultdict(lambda: defaultdict(list))
    for row in rows:
        source = _instant(row.get("source_timestamp_utc"))
        if event_key(row) == key and row.get("market_key") == "h2h":
            price = _price(row) if source is not None and source < kickoff else None
            books[row.get("bookmaker_key")][str(row.get("outcome"))].append(price)
    complete = [
        {label: _number(values[0]) for label, values in book.items()}
        for book in books.values()
        if set(book) == labels
        and all(len(values) == 1 and values[0] is not None for values in book.values())
    ]
    if len(complete) < MINIMUM_CONSENSUS_BOOKMAKERS:
        return None, "CONSENSUS_INSUFFICIENT", len(complete), None
    medians = {label: _median([book[label] for book in complete]) for label in labels}
    lowest = min(_number(value) for value in medians.values())
    leaders = sorted(label for label, value in medians.items() if value == lowest)
    if len(leaders) != 1:
        return None, "FAVOURITE_TIE", len(complete), lowest
    if leaders[0] == "Draw":
        return None, "FAVOURITE_IS_DRAW", len(complete), lowest
    return leaders[0], None, len(complete), lowest


Q1_FIELDS = (
    "event_id sport_key provider_key settlement_period_key match kickoff_utc status reason "
    "reference_target_utc reference_run_id reference_observed_at_utc reference_offset_minutes "
    "reference_class last_prematch_run_id last_prematch_observed_at_utc "
    "last_prematch_minutes_before_kickoff last_prematch_class favourite_outcome "
    "consensus_bookmakers_at_reference favourite_median_at_reference paired_bookmakers "
    "paired_median_at_reference paired_median_last_prematch median_delta median_relative_change "
    "up_count down_count unchanged_count reference_only_count last_prematch_only_count "
    "excluded_offer_count strict_windows"
).split()


def _q1_windows(
    view: CatalogView,
    key: EventKey,
    latest: EventState,
    seen: list[tuple[datetime, Acquisition]],
    stored: tuple[datetime, datetime] | None,
) -> tuple[dict[str, object], tuple[Acquisition, Acquisition] | None]:
    kickoff = latest.kickoff
    row: dict[str, object] = dict.fromkeys(Q1_FIELDS)
    row |= {"provider_key": key[0], "settlement_period_key": key[1]}
    row |= {"sport_key": key[2], "event_id": key[3]}
    row |= {
        "match": latest.match,
        "kickoff_utc": _iso(kickoff),
        "status": "EXCLUDED",
        "strict_windows": False,
    }
    if kickoff is None:
        return row | {"reason": "KICKOFF_UNKNOWN"}, None
    if stored is not None and stored[1] < kickoff:
        return row | {"status": "PENDING"}, None
    target = kickoff - REFERENCE_OFFSET
    row["reference_target_utc"] = _iso(target)
    # The reference window ends before kickoff whatever the declared offsets.
    near_end = target + REFERENCE_NEAR
    reference_window = (
        _Window(target - REFERENCE_NEAR, near_end, False, False)
        if near_end < kickoff
        else _Window(target - REFERENCE_NEAR, kickoff, False, True)
    )
    candidates = [(abs(at - target), at, item) for at, item in seen if at in reference_window]
    best = min(candidates, key=lambda item: (item[0], item[1])) if candidates else None
    # Out of store only while a capture before the store could still be nearer the target.
    if (
        stored is not None
        and stored[0] > target - REFERENCE_NEAR
        and (best is None or best[0] > target - stored[0])
    ):
        return row | {"status": "OUT_OF_STORE"}, None
    if best is None:
        absence = _absence(view, key, reference_window)
        return row | {"reason": f"REFERENCE_ABSENT:{absence}"}, None
    distance, reference_at, reference = best
    row |= {
        "reference_run_id": reference.run_id,
        "reference_observed_at_utc": _iso(reference_at),
        "reference_offset_minutes": _minutes(reference_at - target),
        "reference_class": "J_MINUS_24H" if distance <= REFERENCE_EXACT else "NEAR",
    }

    far = kickoff - PREMATCH_FAR
    prematch_window = (
        _Window(far, kickoff, False, True)
        if far > reference_at
        else _Window(reference_at, kickoff, True, True)
    )
    later = [(at, item) for at, item in seen if at in prematch_window]
    if not later:
        absence = _absence(view, key, prematch_window)
        return row | {"reason": f"PREMATCH_ABSENT:{absence}"}, None
    prematch_at, prematch = later[-1]
    row |= {
        "last_prematch_run_id": prematch.run_id,
        "last_prematch_observed_at_utc": _iso(prematch_at),
        "last_prematch_minutes_before_kickoff": _minutes(kickoff - prematch_at),
        "last_prematch_class": "WITHIN_2H"
        if kickoff - prematch_at <= PREMATCH_CLOSE
        else "WITHIN_6H",
    }
    row["strict_windows"] = (
        row["reference_class"] == "J_MINUS_24H" and row["last_prematch_class"] == "WITHIN_2H"
    )
    first, last = reference.events[key], prematch.events[key]
    if first.kickoff != kickoff or last.kickoff != kickoff:
        return row | {"reason": "KICKOFF_CHANGED"}, None
    if len(first.h2h_outcomes) != 3 or first.h2h_outcomes != last.h2h_outcomes:
        return row | {"reason": "OUTCOME_LABELS_CHANGED"}, None
    return row, (reference, prematch)


def _q1_movement(
    catalog: AcquisitionCatalog,
    row: dict[str, object],
    key: EventKey,
    reference: Acquisition,
    prematch: Acquisition,
) -> dict[str, object]:
    kickoff = _instant(row["kickoff_utc"])
    first = reference.events[key]
    if kickoff is None:
        return row | {"reason": "KICKOFF_UNKNOWN"}
    reference_rows = catalog.rows(reference)
    favourite, refusal, consensus, median = _favourite(
        reference_rows, key, first.h2h_outcomes, kickoff
    )
    row |= {"consensus_bookmakers_at_reference": consensus, "favourite_median_at_reference": median}
    if favourite is None:
        return row | {"reason": refusal}
    row["favourite_outcome"] = favourite
    selection = Selection(key[3], "h2h", favourite, None, key[0], key[1], key[2])
    # Restrict both sides to this exact match key (sport included) before the shared engine.
    same = [row for row in reference_rows if event_key(row) == key]
    later = [row for row in catalog.rows(prematch) if event_key(row) == key]
    result = compare_selection(reference, same, prematch, later, selection)
    if result["status"] != "COMPARED":
        return row | {"reason": f"COMPARISON_UNAVAILABLE:{result['status']}"}
    offers = _items(result["rows"])
    for offer in offers:
        observed = [
            _instant(offer.get(f"current_{name}"))
            for name in ("capture_time_utc", "source_timestamp_utc")
        ]
        if offer["status"] in _MATCHED and any(
            value is None or value >= kickoff for value in observed
        ):
            offer |= {"status": "EXCLUDED", "reason": "SOURCE_NOT_BEFORE_KICKOFF", "delta": None}
    paired = [offer for offer in offers if offer["status"] in _MATCHED]
    row |= {
        f"{name.lower()}_count": sum(offer["status"] == name for offer in paired)
        for name in ("UP", "DOWN", "UNCHANGED")
    }
    row |= {
        "paired_bookmakers": len(paired),
        "reference_only_count": sum(
            offer["status"] in {"NOT_OBSERVED", "EVENT_STARTED_BEFORE_CURRENT"} for offer in offers
        ),
        "last_prematch_only_count": sum(offer["status"] == "APPEARED" for offer in offers),
        "excluded_offer_count": sum(offer["status"] == "EXCLUDED" for offer in offers),
    }
    before = _median([_number(offer["previous_price"]) for offer in paired])
    after = _median([_number(offer["current_price"]) for offer in paired])
    if before is None or after is None:
        return row | {"reason": "NO_PAIRED_BOOKMAKER"}
    return row | {
        "status": "INCLUDED",
        "paired_median_at_reference": before,
        "paired_median_last_prematch": after,
        "median_delta": round(after - before, 6),
        "median_relative_change": round(after / before - 1, 6),
    }


def summarize_q1(rows: Sequence[Row]) -> dict[str, object]:
    """Summary of exactly the listed Q1 rows (the whole store, or a filtered subset)."""

    included = [row for row in rows if row["status"] == "INCLUDED"]
    deltas = [_number(row["median_delta"]) for row in included]
    reasons: dict[str, int] = defaultdict(int)
    for row in rows:
        if row["status"] == "EXCLUDED":
            reasons[str(row["reason"])] += 1
    return {
        "match_count": len(rows),
        "status_counts": _counts(
            rows, "status", ("INCLUDED", "EXCLUDED", "PENDING", "OUT_OF_STORE")
        ),
        "evaluable_count": sum(row["status"] in {"INCLUDED", "EXCLUDED"} for row in rows),
        "exclusion_reason_counts": dict(sorted(reasons.items())),
        "reference_class_counts": _counts(rows, "reference_class", ("J_MINUS_24H", "NEAR")),
        "last_prematch_class_counts": _counts(
            rows, "last_prematch_class", ("WITHIN_2H", "WITHIN_6H")
        ),
        "included_strict_windows": sum(row["strict_windows"] is True for row in included),
        "included_consensus_direction": {
            "DOWN": sum(delta < 0 for delta in deltas),
            "UP": sum(delta > 0 for delta in deltas),
            "UNCHANGED": sum(delta == 0 for delta in deltas),
        },
        "included_median_of_median_delta": _median(deltas),
    }


def answer_q1(catalog: AcquisitionCatalog) -> dict[str, object]:
    """Follow each stored match's favourite between the declared Q1 windows."""

    view = catalog.view()
    # Every listed match gets a row, so an unusable branch or market is reported, never dropped.
    listed: dict[EventKey, list[Acquisition]] = defaultdict(list)
    # Kickoff and teams: latest admissible listing in any market (Q1_RULES).
    anchors: dict[EventKey, list[tuple[datetime, Acquisition]]] = defaultdict(list)
    # Reference and last-prematch candidates: admissible listings with 1X2 rows.
    seen: dict[EventKey, list[tuple[datetime, Acquisition]]] = defaultdict(list)
    # PENDING and OUT_OF_STORE follow the whole store's observed span; a run with no observed
    # time never stands in for a capture, and a missing branch is an absence.
    store_times: list[datetime] = []
    for item in view.acquisitions:
        admissible = {}
        for sport, state in item.sports.items():
            if state.observed_at is not None:
                store_times.append(state.observed_at)
            if state.admissible and state.observed_at is not None:
                admissible[sport] = state.observed_at
        for key, event in item.events.items():
            listed[key].append(item)
            if key[2] in admissible:
                anchors[key].append((admissible[key[2]], item))
                if event.h2h_outcomes:
                    seen[key].append((admissible[key[2]], item))
    rows = []
    ready: list[tuple[dict[str, object], EventKey, Acquisition, Acquisition]] = []
    for key, listings in listed.items():
        values = sorted(seen.get(key, []), key=lambda pair: (pair[0], pair[1].run_id))
        anchored = sorted(anchors.get(key, []), key=lambda pair: (pair[0], pair[1].run_id))
        latest = (anchored[-1][1] if anchored else listings[-1]).events[key]
        bounds = (min(store_times), max(store_times)) if store_times else None
        row, pair = _q1_windows(view, key, latest, values, bounds)
        if pair is None:
            rows.append(row)
        else:
            ready.append((row, key, *pair))
    # Group by acquisition pair so each stored acquisition is parsed as few times as possible.
    ready.sort(key=lambda item: (item[2].slot_time, item[3].slot_time, repr(item[1])))
    for entry in ready:
        try:
            rows.append(_q1_movement(catalog, *entry))
        except QuestionError as exc:
            rows.append(entry[0] | {"reason": f"COMPARISON_UNAVAILABLE:{exc}"})
    rows.sort(
        key=lambda row: tuple(
            repr(row[name])
            for name in (
                "kickoff_utc",
                "sport_key",
                "event_id",
                "provider_key",
                "settlement_period_key",
            )
        )
    )
    return {
        "schema_version": "robin-explorer-q1-v1",
        "question": "Q1",
        "notice": NOTICE,
        "engine": ENGINE,
        "rules": Q1_RULES,
        # The span that decided PENDING and OUT_OF_STORE, next to the slot-based summary.
        "store": view.store_summary()
        | {
            "first_acquired_at_utc": _iso(min(store_times)) if store_times else None,
            "last_acquired_at_utc": _iso(max(store_times)) if store_times else None,
        },
        "summary": summarize_q1(rows),
        "rows": rows,
    }


Q3_FIELDS = (
    "previous_run_id current_run_id event_id sport_key match market_key outcome point "
    "settlement_period_key provider_key status reason side bookmaker_key bookmaker "
    "previous_price previous_capture_time_utc previous_source_timestamp_utc current_price "
    "current_capture_time_utc current_source_timestamp_utc delta other_points_observed"
).split()


def to_json_bytes(payload: Mapping[str, object]) -> bytes:
    """Canonical, wall-clock-free export: the same store and request give the same bytes."""

    text = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    )
    return (text + "\n").encode("utf-8")


def _cell(value: object) -> object:
    if isinstance(value, str) and value and value[0] in "=+-@\t\r":
        return f"'{value}"
    if isinstance(value, bool):
        return "true" if value else "false"
    return " ".join(repr(item) for item in value) if isinstance(value, list) else value


def to_csv_bytes(payload: Mapping[str, object]) -> bytes:
    """Spreadsheet-safe CSV holding the same rows as the JSON export."""

    shared: dict[str, object] = {}
    fields = Q1_FIELDS
    if payload.get("question") == "Q3":
        fields = Q3_FIELDS
        selection = payload.get("selection")
        acquisitions = payload.get("acquisitions")
        if not isinstance(selection, dict) or not isinstance(acquisitions, dict):
            raise QuestionError("EXPORT_PAYLOAD_INVALID")
        shared = {name: selection.get(name) for name in Q3_FIELDS[2:10]}
        shared |= {
            f"{side}_run_id": acquisitions[side]["run_id"] for side in ("previous", "current")
        }
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n", extrasaction="ignore")
    writer.writeheader()
    for row in _items(payload.get("rows")):
        writer.writerow({name: _cell((shared | row).get(name)) for name in fields})
    return stream.getvalue().encode("utf-8")


def acquisitions_payload(catalog: AcquisitionCatalog) -> dict[str, object]:
    view = catalog.view()
    rows = [
        item.provenance()
        | {
            "collection_health": item.collection_health,
            "row_count": item.row_count,
            "admissible_sports": sorted(
                name for name, state in item.sports.items() if state.admissible
            ),
        }
        for item in view.acquisitions
    ]
    return {
        "schema_version": "robin-explorer-acquisitions-v1",
        "question": "ACQUISITIONS",
        "notice": NOTICE,
        "store": view.store_summary(),
        "rows": rows,
    }


def run_question_command(
    store: AtomicExplorerStore, question: str, options: Mapping[str, str | None], output_format: str
) -> tuple[int, bytes]:
    """CLI entry point: exit 0 with the export, or 2 with a stable refusal code."""

    catalog = AcquisitionCatalog(store)
    try:
        if question == "q3":
            payload = answer_q3(catalog, options)
        elif question == "q1":
            payload = answer_q1(catalog)
        else:
            payload = acquisitions_payload(catalog)
        if output_format == "csv":
            if question not in {"q1", "q3"}:
                raise QuestionError("FORMAT_UNSUPPORTED")
            return 0, to_csv_bytes(payload)
        return 0, to_json_bytes(payload)
    except QuestionError as exc:
        return 2, f"{exc}\n".encode()


__all__ = [
    "Q1_RULES",
    "AcquisitionCatalog",
    "QuestionError",
    "Selection",
    "answer_q1",
    "answer_q3",
    "compare_selection",
    "list_selections",
    "resolve_selection",
    "run_question_command",
    "summarize_q1",
    "to_csv_bytes",
    "to_json_bytes",
]
