"""Deterministic normalization for synthetic and offline-replayed odds payloads."""

from __future__ import annotations

import json
import math
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from typing import Any, TypedDict, cast

from robin.capture.contracts import (
    FixtureMapping,
    JsonValue,
    MappingStatus,
    NormalizedMarketObservation,
    RawPayloadReceipt,
    SchemaFingerprint,
    canonical_json_bytes,
    canonical_sha256,
)


class CaptureValidationError(ValueError):
    """Fail-closed validation error carrying only a stable, non-sensitive code."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise CaptureValidationError("CAPTURE_JSON_DUPLICATE_KEY")
        result[key] = value
    return result


def decode_json_payload(payload: bytes) -> JsonValue:
    def reject_constant(_value: str) -> None:
        raise CaptureValidationError("CAPTURE_JSON_NON_FINITE_NUMBER")

    def parse_float(value: str) -> float:
        parsed = float(value)
        if not math.isfinite(parsed):
            raise CaptureValidationError("CAPTURE_JSON_NON_FINITE_NUMBER")
        return parsed

    def parse_int(value: str) -> int:
        if len(value.removeprefix("-")) > 19:
            raise CaptureValidationError("CAPTURE_JSON_INTEGER_OUT_OF_RANGE")
        parsed = int(value)
        if not -(2**63) <= parsed < 2**63:
            raise CaptureValidationError("CAPTURE_JSON_INTEGER_OUT_OF_RANGE")
        return parsed

    try:
        text = payload.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=reject_constant,
            parse_float=parse_float,
            parse_int=parse_int,
        )
    except CaptureValidationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise CaptureValidationError("CAPTURE_JSON_INVALID") from exc
    except RecursionError as exc:
        raise CaptureValidationError("CAPTURE_JSON_DEPTH_EXCEEDED") from exc
    stack: list[tuple[object, int]] = [(value, 0)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if depth > 64 or nodes > 100_000:
            raise CaptureValidationError("CAPTURE_JSON_COMPLEXITY_EXCEEDED")
        if isinstance(current, dict):
            if any(0xD800 <= ord(character) <= 0xDFFF for key in current for character in key):
                raise CaptureValidationError("CAPTURE_JSON_SURROGATE_FORBIDDEN")
            stack.extend((child, depth + 1) for child in current.values())
        elif isinstance(current, list):
            stack.extend((child, depth + 1) for child in current)
        elif isinstance(current, str) and any(
            0xD800 <= ord(character) <= 0xDFFF for character in current
        ):
            raise CaptureValidationError("CAPTURE_JSON_SURROGATE_FORBIDDEN")
    return cast(JsonValue, value)


def _json_type(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    raise CaptureValidationError("CAPTURE_JSON_TYPE_INVALID")


def schema_fingerprint(value: JsonValue) -> SchemaFingerprint:
    paths: set[str] = set()

    def visit(item: JsonValue, path: str) -> None:
        paths.add(f"{path}:{_json_type(item)}")
        if isinstance(item, dict):
            for key in sorted(item):
                visit(item[key], f"{path}.{key}")
        elif isinstance(item, list):
            for child in item:
                visit(child, f"{path}[]")

    visit(value, "$")
    ordered = tuple(sorted(paths))
    return SchemaFingerprint(
        schema_sha256=canonical_sha256(list(ordered)),
        paths_and_types=ordered,
    )


def _object(value: object, *, code: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CaptureValidationError(code)
    return cast(dict[str, Any], value)


def _array(value: object, *, code: str) -> list[Any]:
    if not isinstance(value, list):
        raise CaptureValidationError(code)
    return value


def _string(value: object, *, code: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CaptureValidationError(code)
    return value


def _timestamp(value: object, *, required: bool) -> datetime | None:
    if value is None and not required:
        return None
    if not isinstance(value, str):
        raise CaptureValidationError("CAPTURE_TIMESTAMP_INVALID")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CaptureValidationError("CAPTURE_TIMESTAMP_INVALID") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise CaptureValidationError("CAPTURE_TIMESTAMP_INVALID")
    return parsed.astimezone(UTC)


def _decimal(value: object, *, code: str) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        raise CaptureValidationError(code)
    try:
        parsed = Decimal(str(value))
    except InvalidOperation as exc:
        raise CaptureValidationError(code) from exc
    if not parsed.is_finite() or parsed <= 0:
        raise CaptureValidationError(code)
    return parsed


def _mapping_index(mappings: Iterable[FixtureMapping]) -> dict[str, FixtureMapping]:
    result: dict[str, FixtureMapping] = {}
    provider_event_by_fixture: dict[str, str] = {}
    for mapping in mappings:
        if mapping.provider_event_id in result:
            raise CaptureValidationError("CAPTURE_FIXTURE_MAPPING_DUPLICATED")
        if mapping.status is MappingStatus.AMBIGUOUS:
            raise CaptureValidationError("CAPTURE_FIXTURE_MAPPING_AMBIGUOUS")
        if mapping.status is not MappingStatus.MAPPED or mapping.fixture_id is None:
            raise CaptureValidationError("CAPTURE_FIXTURE_MAPPING_MISSING")
        if mapping.fixture_id in provider_event_by_fixture:
            raise CaptureValidationError("CAPTURE_FIXTURE_MAPPING_NOT_BIJECTIVE")
        provider_event_by_fixture[mapping.fixture_id] = mapping.provider_event_id
        result[mapping.provider_event_id] = mapping
    return result


def _complete_h2h(
    outcomes: list[Any],
    *,
    home_team: str,
    away_team: str,
) -> list[tuple[str, Decimal, Decimal | None]]:
    expected = {home_team, away_team, "Draw"}
    parsed: dict[str, Decimal] = {}
    for raw_outcome in outcomes:
        outcome = _object(raw_outcome, code="CAPTURE_OUTCOME_INVALID")
        name = _string(outcome.get("name"), code="CAPTURE_OUTCOME_NAME_INVALID")
        if name in parsed:
            raise CaptureValidationError("CAPTURE_OUTCOME_DUPLICATED")
        parsed[name] = _decimal(outcome.get("price"), code="CAPTURE_PRICE_INVALID")
    if set(parsed) != expected:
        return []
    return [(name, parsed[name], None) for name in sorted(parsed)]


def _complete_totals(outcomes: list[Any]) -> list[tuple[str, Decimal, Decimal | None]]:
    parsed: dict[str, tuple[Decimal, Decimal]] = {}
    for raw_outcome in outcomes:
        outcome = _object(raw_outcome, code="CAPTURE_OUTCOME_INVALID")
        name = _string(outcome.get("name"), code="CAPTURE_OUTCOME_NAME_INVALID")
        if name in parsed:
            raise CaptureValidationError("CAPTURE_OUTCOME_DUPLICATED")
        price = _decimal(outcome.get("price"), code="CAPTURE_PRICE_INVALID")
        point = _decimal(outcome.get("point"), code="CAPTURE_TOTALS_POINT_INVALID")
        parsed[name] = (price, point)
    if set(parsed) != {"Over", "Under"}:
        return []
    points = {point for _, point in parsed.values()}
    if len(points) != 1:
        return []
    return [(name, parsed[name][0], parsed[name][1]) for name in sorted(parsed)]


def normalized_jsonl_bytes(observations: Iterable[NormalizedMarketObservation]) -> bytes:
    lines = [
        canonical_json_bytes(item.model_dump(mode="json"))
        for item in sorted(
            observations,
            key=lambda row: (
                row.fixture_id,
                row.provider_event_id,
                row.bookmaker_key,
                row.market_key,
                row.outcome_name,
                str(row.point),
            ),
        )
    ]
    return b"".join(line + b"\n" for line in lines)


class _ObservationCore(TypedDict):
    fixture_id: str
    provider_event_id: str
    receipt_id: str
    payload_sha256: str
    bookmaker_key: str
    market_key: str
    market_last_update: datetime | None
    outcome_name: str
    price: Decimal
    point: Decimal | None
    available_at: datetime


def snapshot_id_for_observation_rows(
    *,
    receipt_id: str,
    schema_fingerprint_sha256: str,
    mappings: tuple[FixtureMapping, ...],
    observations: Iterable[Mapping[str, object]],
) -> str:
    canonical_rows = sorted(
        observations,
        key=lambda row: (
            str(row["fixture_id"]),
            str(row["provider_event_id"]),
            str(row["bookmaker_key"]),
            str(row["market_key"]),
            str(row["outcome_name"]),
            str(row["point"]),
        ),
    )
    return canonical_sha256(
        {
            "receipt_id": receipt_id,
            "schema_fingerprint_sha256": schema_fingerprint_sha256,
            "fixture_mappings": [
                mapping.model_dump(mode="json")
                for mapping in sorted(mappings, key=lambda item: item.provider_event_id)
            ],
            "observations": [
                {
                    key: (
                        value.isoformat().replace("+00:00", "Z")
                        if isinstance(value, datetime)
                        else str(value)
                        if isinstance(value, Decimal)
                        else value
                    )
                    for key, value in row.items()
                }
                for row in canonical_rows
            ],
        }
    )


def normalize_payload(
    value: JsonValue,
    *,
    receipt: RawPayloadReceipt,
    mappings: tuple[FixtureMapping, ...],
    allowed_markets: tuple[str, ...] | None = None,
    expected_sport_key: str | None = None,
) -> tuple[SchemaFingerprint, tuple[NormalizedMarketObservation, ...]]:
    if not isinstance(value, list):
        raise CaptureValidationError("CAPTURE_PAYLOAD_ROOT_NOT_ARRAY")
    schema = schema_fingerprint(value)
    mapping_by_event = _mapping_index(mappings)
    seen_event_ids: set[str] = set()
    rows: list[_ObservationCore] = []

    for raw_event in value:
        event = _object(raw_event, code="CAPTURE_EVENT_INVALID")
        if expected_sport_key is not None:
            event_sport_key = _string(
                event.get("sport_key"),
                code="CAPTURE_EVENT_SPORT_KEY_INVALID",
            )
            if event_sport_key != expected_sport_key:
                raise CaptureValidationError("CAPTURE_EVENT_SPORT_KEY_MISMATCH")
        event_id = _string(event.get("id"), code="CAPTURE_EVENT_ID_INVALID")
        if event_id in seen_event_ids:
            raise CaptureValidationError("CAPTURE_EVENT_DUPLICATED")
        seen_event_ids.add(event_id)
        mapping = mapping_by_event.get(event_id)
        if mapping is None or mapping.fixture_id is None:
            raise CaptureValidationError("CAPTURE_FIXTURE_MAPPING_MISSING")
        home_team = _string(event.get("home_team"), code="CAPTURE_HOME_TEAM_INVALID")
        away_team = _string(event.get("away_team"), code="CAPTURE_AWAY_TEAM_INVALID")
        _timestamp(event.get("commence_time"), required=True)
        bookmakers = _array(event.get("bookmakers"), code="CAPTURE_BOOKMAKERS_INVALID")

        seen_bookmakers: set[str] = set()
        for raw_bookmaker in bookmakers:
            bookmaker = _object(raw_bookmaker, code="CAPTURE_BOOKMAKER_INVALID")
            bookmaker_key = _string(bookmaker.get("key"), code="CAPTURE_BOOKMAKER_KEY_INVALID")
            if bookmaker_key in seen_bookmakers:
                raise CaptureValidationError("CAPTURE_BOOKMAKER_DUPLICATED")
            seen_bookmakers.add(bookmaker_key)
            markets = _array(bookmaker.get("markets"), code="CAPTURE_MARKETS_INVALID")
            seen_markets: set[str] = set()
            for raw_market in markets:
                market = _object(raw_market, code="CAPTURE_MARKET_INVALID")
                market_key = _string(market.get("key"), code="CAPTURE_MARKET_KEY_INVALID")
                if allowed_markets is not None and market_key not in allowed_markets:
                    raise CaptureValidationError("CAPTURE_UNREQUESTED_MARKET")
                if market_key not in {"h2h", "totals"}:
                    continue
                if market_key in seen_markets:
                    raise CaptureValidationError("CAPTURE_MARKET_DUPLICATED")
                seen_markets.add(market_key)
                updated = _timestamp(market.get("last_update"), required=False)
                available_at = receipt.robin_first_observed_at
                if updated is not None:
                    available_at = max(available_at, updated)
                outcomes = _array(market.get("outcomes"), code="CAPTURE_OUTCOMES_INVALID")
                if market_key == "h2h":
                    complete = _complete_h2h(
                        outcomes,
                        home_team=home_team,
                        away_team=away_team,
                    )
                else:
                    complete = _complete_totals(outcomes)
                if allowed_markets is not None and not complete:
                    raise CaptureValidationError("CAPTURE_REQUESTED_MARKET_INCOMPLETE")
                for outcome_name, price, point in complete:
                    rows.append(
                        _ObservationCore(
                            fixture_id=mapping.fixture_id,
                            provider_event_id=event_id,
                            receipt_id=receipt.receipt_id,
                            payload_sha256=receipt.payload_sha256,
                            bookmaker_key=bookmaker_key,
                            market_key=market_key,
                            market_last_update=updated,
                            outcome_name=outcome_name,
                            price=price,
                            point=point,
                            available_at=available_at,
                        )
                    )
            if allowed_markets is not None and seen_markets != set(allowed_markets):
                raise CaptureValidationError("CAPTURE_REQUESTED_MARKET_MISSING")

    if seen_event_ids != set(mapping_by_event):
        raise CaptureValidationError("CAPTURE_FIXTURE_MAPPING_UNUSED")
    canonical_rows = sorted(
        rows,
        key=lambda row: (
            str(row["fixture_id"]),
            str(row["provider_event_id"]),
            str(row["bookmaker_key"]),
            str(row["market_key"]),
            str(row["outcome_name"]),
            str(row["point"]),
        ),
    )
    snapshot_id = snapshot_id_for_observation_rows(
        receipt_id=receipt.receipt_id,
        schema_fingerprint_sha256=schema.schema_sha256,
        mappings=mappings,
        observations=canonical_rows,
    )
    observations = tuple(
        NormalizedMarketObservation(
            snapshot_id=snapshot_id,
            fixture_id=row["fixture_id"],
            provider_event_id=row["provider_event_id"],
            receipt_id=row["receipt_id"],
            payload_sha256=row["payload_sha256"],
            bookmaker_key=row["bookmaker_key"],
            market_key=cast(Any, row["market_key"]),
            market_last_update=row["market_last_update"],
            outcome_name=row["outcome_name"],
            price=row["price"],
            point=row["point"],
            available_at=row["available_at"],
        )
        for row in canonical_rows
    )
    return schema, observations


def normalize_payload_v2(
    value: JsonValue,
    *,
    receipt: RawPayloadReceipt,
    mapping_evidence: object,
    allowed_markets: tuple[str, ...] | None = None,
    expected_sport_key: str | None = None,
) -> tuple[SchemaFingerprint, tuple[NormalizedMarketObservation, ...], str]:
    """Project only proven mappings while preserving the full raw schema lineage.

    V2 mapping evidence is exhaustive for provider events, but ambiguous and
    unmapped events are deliberately excluded from the scientific projection.
    The raw payload, receipt and full mapping set remain evidence.
    """

    from robin.capture.fixture_mapping import PostCaptureFixtureMappingV1

    try:
        evidence = PostCaptureFixtureMappingV1.model_validate(
            cast(Any, mapping_evidence).model_dump(mode="json")
        )
    except (AttributeError, TypeError, ValueError):
        raise CaptureValidationError("CAPTURE_V2_MAPPING_BINDING_INVALID") from None
    mappings = evidence.mappings
    if not isinstance(value, list):
        raise CaptureValidationError("CAPTURE_PAYLOAD_ROOT_NOT_ARRAY")
    raw_schema = schema_fingerprint(value)
    mapping_by_event: dict[str, FixtureMapping] = {}
    for mapping in mappings:
        if mapping.provider_event_id in mapping_by_event:
            raise CaptureValidationError("CAPTURE_FIXTURE_MAPPING_DUPLICATED")
        mapping_by_event[mapping.provider_event_id] = mapping

    seen_event_ids: set[str] = set()
    admitted_payload: list[JsonValue] = []
    admitted_mappings: list[FixtureMapping] = []
    for raw_event in value:
        event = _object(raw_event, code="CAPTURE_EVENT_INVALID")
        event_id = _string(event.get("id"), code="CAPTURE_EVENT_ID_INVALID")
        if event_id in seen_event_ids:
            raise CaptureValidationError("CAPTURE_EVENT_DUPLICATED")
        seen_event_ids.add(event_id)
        candidate_mapping = mapping_by_event.get(event_id)
        if candidate_mapping is None:
            raise CaptureValidationError("CAPTURE_FIXTURE_MAPPING_MISSING")
        if candidate_mapping.status is MappingStatus.MAPPED:
            admitted_payload.append(raw_event)
            admitted_mappings.append(candidate_mapping)
    if seen_event_ids != set(mapping_by_event):
        raise CaptureValidationError("CAPTURE_FIXTURE_MAPPING_UNUSED")

    canonical_admitted_mappings = tuple(
        sorted(admitted_mappings, key=lambda item: item.provider_event_id)
    )
    _projected_schema, projected = normalize_payload(
        cast(JsonValue, admitted_payload),
        receipt=receipt,
        mappings=canonical_admitted_mappings,
        allowed_markets=allowed_markets,
        expected_sport_key=expected_sport_key,
    )
    row_material = [
        {
            "fixture_id": row.fixture_id,
            "provider_event_id": row.provider_event_id,
            "receipt_id": row.receipt_id,
            "payload_sha256": row.payload_sha256,
            "bookmaker_key": row.bookmaker_key,
            "market_key": row.market_key,
            "market_last_update": row.market_last_update,
            "outcome_name": row.outcome_name,
            "price": row.price,
            "point": row.point,
            "available_at": row.available_at,
        }
        for row in projected
    ]
    projected_snapshot_id = snapshot_id_for_observation_rows(
        receipt_id=receipt.receipt_id,
        schema_fingerprint_sha256=raw_schema.schema_sha256,
        mappings=mappings,
        observations=row_material,
    )
    snapshot_id = canonical_sha256(
        {
            "schema_version": "robin-scientific-projection-v2",
            "fixture_target_set_sha256": evidence.fixture_target_set_sha256,
            "post_capture_mapping_sha256": evidence.canonical_mapping_hash,
            "projected_snapshot_sha256": projected_snapshot_id,
        }
    )
    observations = tuple(
        NormalizedMarketObservation.model_validate(
            {**row.model_dump(mode="python"), "snapshot_id": snapshot_id}
        )
        for row in projected
    )
    return raw_schema, observations, snapshot_id
