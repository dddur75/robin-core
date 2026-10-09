"""Chronos Control Plane V2: DB-clocked authority and attributable effects."""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from threading import RLock
from typing import Protocol, cast, runtime_checkable

_HEX = frozenset("0123456789abcdef")
_FORBIDDEN_CLOCK_ARGUMENTS = frozenset(
    {"now", "--now", "injected_clock", "test_now", "fake_now"}
)
_EVENT_HASH_VERSION = "chronos-effect-event-v1"


class ChronosControlPlaneError(RuntimeError):
    """Fail-closed control-plane contract violation."""


class EffectEventType(StrEnum):
    AUTHORITY_GRANTED = "AUTHORITY_GRANTED"
    EFFECT_RESERVED = "EFFECT_RESERVED"
    PUT_DISPATCHED = "PUT_DISPATCHED"
    R2_GET_DISPATCHED = "R2_GET_DISPATCHED"
    CREATED_CONFIRMED = "CREATED_CONFIRMED"
    PREEXISTING_CONFIRMED = "PREEXISTING_CONFIRMED"
    PUT_COMMITTED_ACTUAL_PENDING = "PUT_COMMITTED_ACTUAL_PENDING"
    FAILED_BEFORE_DISPATCH = "FAILED_BEFORE_DISPATCH"
    FAILED_AFTER_DISPATCH = "FAILED_AFTER_DISPATCH"
    INTEGRITY_CONFLICT = "INTEGRITY_CONFLICT"
    RECOVERY_OBSERVED_MATCHING_OBJECT = "RECOVERY_OBSERVED_MATCHING_OBJECT"


class ConditionalPutOutcome(StrEnum):
    CREATED = "CREATED"
    PRECONDITION_FAILED = "PRECONDITION_FAILED"
    DEFINITE_FAILURE = "DEFINITE_FAILURE"
    AMBIGUOUS = "AMBIGUOUS"
    CONFLICT = "CONFLICT"


_ALLOWED_TRANSITIONS: Mapping[EffectEventType, frozenset[EffectEventType]] = {
    EffectEventType.AUTHORITY_GRANTED: frozenset(
        {EffectEventType.EFFECT_RESERVED}
    ),
    EffectEventType.EFFECT_RESERVED: frozenset(
        {
            EffectEventType.FAILED_BEFORE_DISPATCH,
            EffectEventType.PUT_DISPATCHED,
        }
    ),
    EffectEventType.PUT_DISPATCHED: frozenset(
        {
            EffectEventType.CREATED_CONFIRMED,
            EffectEventType.R2_GET_DISPATCHED,
            EffectEventType.PUT_COMMITTED_ACTUAL_PENDING,
            EffectEventType.FAILED_AFTER_DISPATCH,
        }
    ),
    EffectEventType.PUT_COMMITTED_ACTUAL_PENDING: frozenset(
        {EffectEventType.R2_GET_DISPATCHED}
    ),
    EffectEventType.R2_GET_DISPATCHED: frozenset(
        {
            EffectEventType.PREEXISTING_CONFIRMED,
            EffectEventType.PUT_COMMITTED_ACTUAL_PENDING,
            EffectEventType.RECOVERY_OBSERVED_MATCHING_OBJECT,
            EffectEventType.INTEGRITY_CONFLICT,
        }
    ),
}


def _require_text(value: str, *, field: str) -> str:
    if not value or value.strip() != value:
        raise ValueError(f"CHRONOS_{field.upper()}_INVALID")
    return value


def _require_sha(value: str, *, field: str, lengths: frozenset[int]) -> str:
    if len(value) not in lengths or any(character not in _HEX for character in value):
        raise ValueError(f"CHRONOS_{field.upper()}_INVALID")
    return value


def _utc(value: datetime, *, field: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"CHRONOS_{field.upper()}_MUST_BE_UTC")
    return value.astimezone(UTC)


def _timestamp(value: datetime) -> str:
    return _utc(value, field="timestamp").isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")


def _lp(value: object) -> bytes:
    text = str(value)
    encoded = text.encode("utf-8")
    return str(len(encoded)).encode("ascii") + b":" + encoded


def _hash_parts(*parts: object) -> str:
    digest = hashlib.sha256()
    for part in parts:
        digest.update(_lp(part))
    return digest.hexdigest()


def _generation_hash(token: str) -> str:
    _require_sha(token, field="generation_token", lengths=frozenset({64}))
    return hashlib.sha256(bytes.fromhex(token)).hexdigest()


@dataclass(frozen=True, slots=True)
class GitHubRunIdentity:
    github_run_id: int
    github_run_attempt: int
    github_sha: str
    github_workflow_ref: str
    github_workflow_sha: str
    github_repository: str
    github_ref: str

    def __post_init__(self) -> None:
        if self.github_run_id <= 0:
            raise ValueError("CHRONOS_GITHUB_RUN_ID_INVALID")
        if self.github_run_attempt <= 0:
            raise ValueError("CHRONOS_GITHUB_RUN_ATTEMPT_INVALID")
        _require_sha(
            self.github_sha,
            field="github_sha",
            lengths=frozenset({40, 64}),
        )
        _require_sha(
            self.github_workflow_sha,
            field="github_workflow_sha",
            lengths=frozenset({40, 64}),
        )
        _require_text(self.github_workflow_ref, field="github_workflow_ref")
        _require_text(self.github_repository, field="github_repository")
        _require_text(self.github_ref, field="github_ref")
        if "/" not in self.github_repository:
            raise ValueError("CHRONOS_GITHUB_REPOSITORY_INVALID")


@dataclass(frozen=True, slots=True)
class EffectOperation:
    mission_id: str
    identity: GitHubRunIdentity
    resource_kind: str
    canonical_key: str
    canonical_payload_hash: str
    code_revision: str

    def __post_init__(self) -> None:
        _require_text(self.mission_id, field="mission_id")
        _require_text(self.resource_kind, field="resource_kind")
        _require_text(self.canonical_key, field="canonical_key")
        _require_sha(
            self.canonical_payload_hash,
            field="canonical_payload_hash",
            lengths=frozenset({64}),
        )
        _require_sha(
            self.code_revision,
            field="code_revision",
            lengths=frozenset({40, 64}),
        )
        if self.code_revision != self.identity.github_sha:
            raise ValueError("CHRONOS_CODE_REVISION_MISMATCH")

    @property
    def operation_id(self) -> str:
        return derive_operation_id(
            mission_id=self.mission_id,
            github_run_id=self.identity.github_run_id,
            github_run_attempt=self.identity.github_run_attempt,
            resource_kind=self.resource_kind,
            canonical_key=self.canonical_key,
            canonical_payload_hash=self.canonical_payload_hash,
        )


def derive_operation_id(
    *,
    mission_id: str,
    github_run_id: int,
    github_run_attempt: int,
    resource_kind: str,
    canonical_key: str,
    canonical_payload_hash: str,
) -> str:
    _require_text(mission_id, field="mission_id")
    _require_text(resource_kind, field="resource_kind")
    _require_text(canonical_key, field="canonical_key")
    _require_sha(
        canonical_payload_hash,
        field="canonical_payload_hash",
        lengths=frozenset({64}),
    )
    if github_run_id <= 0 or github_run_attempt <= 0:
        raise ValueError("CHRONOS_GITHUB_RUN_IDENTITY_INVALID")
    return _hash_parts(
        mission_id,
        github_run_id,
        github_run_attempt,
        resource_kind,
        canonical_key,
        canonical_payload_hash,
    )


@dataclass(frozen=True, slots=True)
class AuthorityReceipt:
    authority_id: str
    db_authorized_at: datetime
    expires_at: datetime
    postgres_server_epoch: datetime
    authority_receipt_hash: str

    def __post_init__(self) -> None:
        _require_text(self.authority_id, field="authority_id")
        _utc(self.db_authorized_at, field="db_authorized_at")
        _utc(self.expires_at, field="expires_at")
        _utc(self.postgres_server_epoch, field="postgres_server_epoch")
        _require_sha(
            self.authority_receipt_hash,
            field="authority_receipt_hash",
            lengths=frozenset({64}),
        )


@dataclass(frozen=True, slots=True)
class EffectEvent:
    event_id: str
    event_seq: int
    operation_id: str
    authority_id: str
    event_type: EffectEventType
    resource_kind: str
    resource_key: str
    payload_hash: str
    db_recorded_at: datetime
    github_run_id: int
    github_run_attempt: int
    code_revision: str
    previous_event_hash: str | None
    event_hash: str

    def __post_init__(self) -> None:
        if self.event_seq < 0:
            raise ValueError("CHRONOS_EVENT_SEQUENCE_INVALID")
        _require_sha(
            self.operation_id,
            field="operation_id",
            lengths=frozenset({64}),
        )
        _require_sha(self.payload_hash, field="payload_hash", lengths=frozenset({64}))
        _require_sha(self.event_hash, field="event_hash", lengths=frozenset({64}))
        if self.previous_event_hash is not None:
            _require_sha(
                self.previous_event_hash,
                field="previous_event_hash",
                lengths=frozenset({64}),
            )
        _utc(self.db_recorded_at, field="db_recorded_at")


def derive_event_hash(
    *,
    event_seq: int,
    operation_id: str,
    authority_id: str,
    event_type: EffectEventType,
    resource_kind: str,
    resource_key: str,
    payload_hash: str,
    db_recorded_at: datetime,
    github_run_id: int,
    github_run_attempt: int,
    code_revision: str,
    previous_event_hash: str | None,
) -> str:
    return _hash_parts(
        _EVENT_HASH_VERSION,
        event_seq,
        operation_id,
        authority_id,
        event_type.value,
        resource_kind,
        resource_key,
        payload_hash,
        _timestamp(db_recorded_at),
        github_run_id,
        github_run_attempt,
        code_revision,
        previous_event_hash or "",
    )


@dataclass(frozen=True, slots=True)
class EffectCounters:
    r2_write_units_reserved: int
    r2_put_requests_dispatched: int
    r2_get_requests_dispatched: int
    r2_objects_created_confirmed: int
    r2_objects_preexisting_confirmed: int
    r2_write_outcomes_pending: int
    r2_integrity_conflicts: int


@dataclass(frozen=True, slots=True)
class ConditionalPutResult:
    outcome: ConditionalPutOutcome
    transport_attempts: int = 1
    automatic_retry_possible: bool = False
    request_id: str | None = None
    etag: str | None = None

    def __post_init__(self) -> None:
        if self.transport_attempts <= 0:
            raise ValueError("CHRONOS_R2_TRANSPORT_ATTEMPTS_INVALID")


@dataclass(frozen=True, slots=True)
class ObservedObject:
    data: bytes
    metadata: Mapping[str, str]


@runtime_checkable
class TestClock(Protocol):
    """Explicit test-only clock for Memory or SQLite adapters."""

    def now(self) -> datetime: ...


@runtime_checkable
class ConditionalObjectStore(Protocol):
    def put_if_absent(
        self,
        key: str,
        data: bytes,
        *,
        metadata: Mapping[str, str],
        on_dispatch: Callable[[], None],
    ) -> ConditionalPutResult: ...

    def get_object(self, key: str) -> ObservedObject | None: ...


@runtime_checkable
class PostgresFunctionClient(Protocol):
    """Protected DB-function surface that commits before returning a row."""

    def fetch_one(
        self,
        statement: str,
        parameters: Sequence[object],
    ) -> Mapping[str, object]: ...


@dataclass(frozen=True, slots=True)
class _AuthorityTicket:
    authority_id: str
    mission_id: str
    identity: GitHubRunIdentity
    planned_at: datetime
    expires_at: datetime
    issued_at: datetime
    postgres_server_epoch: datetime
    control_plane_generation_hash: str
    max_r2_put_requests: int
    code_revision: str


class MemoryChronosControlPlane:
    """Deterministic test adapter; never a production authority source."""

    def __init__(
        self,
        *,
        clock: TestClock,
        postgres_server_epoch: datetime,
    ) -> None:
        self._clock = clock
        self._server_epoch = _utc(
            postgres_server_epoch,
            field="postgres_server_epoch",
        )
        self._authorities: dict[str, _AuthorityTicket] = {}
        self._claims: dict[str, str] = {}
        self._receipts: dict[str, AuthorityReceipt] = {}
        self._operations: dict[str, EffectOperation] = {}
        self._events: dict[str, list[EffectEvent]] = {}
        self._authority_sequence = 0
        self._lock = RLock()

    def issue_authority(
        self,
        *,
        mission_id: str,
        identity: GitHubRunIdentity,
        generation_token: str,
        ttl_seconds: int,
        code_revision: str,
        max_r2_put_requests: int = 1,
    ) -> str:
        with self._lock:
            if not 1 <= ttl_seconds <= 1200:
                raise ChronosControlPlaneError("CHRONOS_AUTHORITY_TTL_INVALID")
            if max_r2_put_requests != 1:
                raise ChronosControlPlaneError(
                    "CHRONOS_AUTHORITY_EFFECT_LIMIT_INVALID"
                )
            if code_revision != identity.github_sha:
                raise ChronosControlPlaneError("CHRONOS_CODE_REVISION_MISMATCH")
            issued_at = _utc(self._clock.now(), field="test_clock")
            self._authority_sequence += 1
            authority_id = "chronos-authority:" + _hash_parts(
                mission_id,
                identity.github_run_id,
                identity.github_run_attempt,
                issued_at.isoformat(),
                self._authority_sequence,
            )
            self._authorities[authority_id] = _AuthorityTicket(
                authority_id=authority_id,
                mission_id=_require_text(mission_id, field="mission_id"),
                identity=identity,
                planned_at=issued_at,
                expires_at=issued_at + timedelta(seconds=ttl_seconds),
                issued_at=issued_at,
                postgres_server_epoch=self._server_epoch,
                control_plane_generation_hash=_generation_hash(generation_token),
                max_r2_put_requests=max_r2_put_requests,
                code_revision=code_revision,
            )
            return authority_id

    def _validate_authority(
        self,
        *,
        authority_id: str,
        operation: EffectOperation,
        generation_token: str,
        require_active: bool,
    ) -> tuple[_AuthorityTicket, datetime]:
        try:
            ticket = self._authorities[authority_id]
        except KeyError as error:
            raise ChronosControlPlaneError(
                "CHRONOS_AUTHORITY_NOT_FOUND"
            ) from error
        db_now = _utc(self._clock.now(), field="test_clock")
        if require_active and not ticket.planned_at <= db_now < ticket.expires_at:
            raise ChronosControlPlaneError("CHRONOS_AUTHORITY_NOT_ACTIVE")
        if ticket.postgres_server_epoch != self._server_epoch:
            raise ChronosControlPlaneError("CHRONOS_SERVER_EPOCH_MISMATCH")
        if not hmac.compare_digest(
            ticket.control_plane_generation_hash,
            _generation_hash(generation_token),
        ):
            raise ChronosControlPlaneError(
                "CHRONOS_CONTROL_PLANE_GENERATION_MISMATCH"
            )
        if ticket.identity != operation.identity:
            raise ChronosControlPlaneError(
                "CHRONOS_GITHUB_RUN_IDENTITY_MISMATCH"
            )
        if (
            ticket.mission_id != operation.mission_id
            or ticket.code_revision != operation.code_revision
        ):
            raise ChronosControlPlaneError("CHRONOS_AUTHORITY_SCOPE_MISMATCH")
        return ticket, db_now

    def claim_effect_authority(
        self,
        *,
        authority_id: str,
        operation: EffectOperation,
        generation_token: str,
    ) -> AuthorityReceipt:
        with self._lock:
            return self._claim_effect_authority(
                authority_id=authority_id,
                operation=operation,
                generation_token=generation_token,
            )

    def _claim_effect_authority(
        self,
        *,
        authority_id: str,
        operation: EffectOperation,
        generation_token: str,
    ) -> AuthorityReceipt:
        ticket, db_now = self._validate_authority(
            authority_id=authority_id,
            operation=operation,
            generation_token=generation_token,
            require_active=False,
        )
        claimed_operation = self._claims.get(authority_id)
        if claimed_operation is not None and claimed_operation != operation.operation_id:
            raise ChronosControlPlaneError("CHRONOS_AUTHORITY_ALREADY_CONSUMED")
        existing = self._receipts.get(authority_id)
        if existing is not None:
            return existing
        if not ticket.planned_at <= db_now < ticket.expires_at:
            raise ChronosControlPlaneError("CHRONOS_AUTHORITY_NOT_ACTIVE")

        receipt_hash = _hash_parts(
            authority_id,
            _timestamp(db_now),
            _timestamp(ticket.expires_at),
            _timestamp(ticket.postgres_server_epoch),
            operation.operation_id,
            ticket.control_plane_generation_hash,
            ticket.identity.github_run_id,
            ticket.identity.github_run_attempt,
            ticket.identity.github_sha,
            ticket.identity.github_workflow_ref,
            ticket.identity.github_workflow_sha,
            ticket.identity.github_repository,
            ticket.identity.github_ref,
        )
        receipt = AuthorityReceipt(
            authority_id=authority_id,
            db_authorized_at=db_now,
            expires_at=ticket.expires_at,
            postgres_server_epoch=ticket.postgres_server_epoch,
            authority_receipt_hash=receipt_hash,
        )
        granted = self._new_event(
            ticket=ticket,
            operation=operation,
            event_type=EffectEventType.AUTHORITY_GRANTED,
            recorded_at=db_now,
            previous=None,
        )
        reserved = self._new_event(
            ticket=ticket,
            operation=operation,
            event_type=EffectEventType.EFFECT_RESERVED,
            recorded_at=db_now,
            previous=granted,
        )
        # Claim, grant and reservation become visible together.
        self._claims[authority_id] = operation.operation_id
        self._receipts[authority_id] = receipt
        self._operations[operation.operation_id] = operation
        self._events[operation.operation_id] = [granted, reserved]
        return receipt

    @staticmethod
    def _new_event(
        *,
        ticket: _AuthorityTicket,
        operation: EffectOperation,
        event_type: EffectEventType,
        recorded_at: datetime,
        previous: EffectEvent | None,
    ) -> EffectEvent:
        sequence = 0 if previous is None else previous.event_seq + 1
        event_hash = derive_event_hash(
            event_seq=sequence,
            operation_id=operation.operation_id,
            authority_id=ticket.authority_id,
            event_type=event_type,
            resource_kind=operation.resource_kind,
            resource_key=operation.canonical_key,
            payload_hash=operation.canonical_payload_hash,
            db_recorded_at=recorded_at,
            github_run_id=operation.identity.github_run_id,
            github_run_attempt=operation.identity.github_run_attempt,
            code_revision=operation.code_revision,
            previous_event_hash=None if previous is None else previous.event_hash,
        )
        return EffectEvent(
            event_id="chronos-event:" + event_hash,
            event_seq=sequence,
            operation_id=operation.operation_id,
            authority_id=ticket.authority_id,
            event_type=event_type,
            resource_kind=operation.resource_kind,
            resource_key=operation.canonical_key,
            payload_hash=operation.canonical_payload_hash,
            db_recorded_at=recorded_at,
            github_run_id=operation.identity.github_run_id,
            github_run_attempt=operation.identity.github_run_attempt,
            code_revision=operation.code_revision,
            previous_event_hash=None if previous is None else previous.event_hash,
            event_hash=event_hash,
        )

    def append_event(
        self,
        *,
        authority_id: str,
        operation: EffectOperation,
        generation_token: str,
        event_type: EffectEventType,
    ) -> EffectEvent:
        with self._lock:
            return self._append_event(
                authority_id=authority_id,
                operation=operation,
                generation_token=generation_token,
                event_type=event_type,
            )

    def _append_event(
        self,
        *,
        authority_id: str,
        operation: EffectOperation,
        generation_token: str,
        event_type: EffectEventType,
    ) -> EffectEvent:
        ticket, db_now = self._validate_authority(
            authority_id=authority_id,
            operation=operation,
            generation_token=generation_token,
            # Expiry fences the physical effect.  A result for an already
            # dispatched PUT may still be journalled after the deadline.
            require_active=event_type is EffectEventType.PUT_DISPATCHED,
        )
        if self._claims.get(authority_id) != operation.operation_id:
            raise ChronosControlPlaneError("CHRONOS_AUTHORITY_NOT_CLAIMED")
        stored_operation = self._operations.get(operation.operation_id)
        if stored_operation != operation:
            raise ChronosControlPlaneError("CHRONOS_OPERATION_IDENTITY_MISMATCH")
        existing = next(
            (e for e in self._events[operation.operation_id] if e.event_type is event_type),
            None,
        )
        if existing is not None:
            if event_type is EffectEventType.PUT_DISPATCHED:
                raise ChronosControlPlaneError(
                    "CHRONOS_DISPATCH_PERMIT_ALREADY_EXISTS"
                )
            if event_type is EffectEventType.R2_GET_DISPATCHED:
                raise ChronosControlPlaneError(
                    "CHRONOS_R2_GET_PERMIT_ALREADY_EXISTS"
                )
            return existing
        previous = self.latest_event(operation.operation_id)
        if previous is None or event_type not in _ALLOWED_TRANSITIONS.get(
            previous.event_type, frozenset()
        ):
            raise ChronosControlPlaneError("CHRONOS_EFFECT_TRANSITION_FORBIDDEN")
        if event_type is EffectEventType.PUT_DISPATCHED:
            dispatched = sum(
                event.event_type is EffectEventType.PUT_DISPATCHED
                for event in self._events[operation.operation_id]
            )
            if dispatched >= ticket.max_r2_put_requests:
                raise ChronosControlPlaneError("CHRONOS_R2_DISPATCH_BUDGET_EXHAUSTED")
        event = self._new_event(
            ticket=ticket,
            operation=operation,
            event_type=event_type,
            recorded_at=db_now,
            previous=previous,
        )
        self._events[operation.operation_id].append(event)
        return event

    def latest_event(self, operation_id: str) -> EffectEvent | None:
        with self._lock:
            events = self._events.get(operation_id, ())
            return events[-1] if events else None

    def operation_events(self, operation_id: str) -> tuple[EffectEvent, ...]:
        with self._lock:
            return tuple(self._events.get(operation_id, ()))

    def accounting(self) -> EffectCounters:
        with self._lock:
            events = tuple(
                event
                for operation_events in self._events.values()
                for event in operation_events
            )
            latest = tuple(
                operation_events[-1]
                for operation_events in self._events.values()
                if operation_events
            )
        pending = {
            EffectEventType.PUT_DISPATCHED,
            EffectEventType.R2_GET_DISPATCHED,
            EffectEventType.PUT_COMMITTED_ACTUAL_PENDING,
            EffectEventType.RECOVERY_OBSERVED_MATCHING_OBJECT,
        }
        return EffectCounters(
            r2_write_units_reserved=sum(
                event.event_type is EffectEventType.EFFECT_RESERVED
                for event in events
            ),
            r2_put_requests_dispatched=sum(
                event.event_type is EffectEventType.PUT_DISPATCHED
                for event in events
            ),
            r2_get_requests_dispatched=sum(
                event.event_type is EffectEventType.R2_GET_DISPATCHED
                for event in events
            ),
            r2_objects_created_confirmed=sum(
                event.event_type is EffectEventType.CREATED_CONFIRMED
                for event in events
            ),
            r2_objects_preexisting_confirmed=sum(
                event.event_type is EffectEventType.PREEXISTING_CONFIRMED
                for event in events
            ),
            r2_write_outcomes_pending=sum(
                event.event_type in pending for event in latest
            ),
            r2_integrity_conflicts=sum(
                event.event_type is EffectEventType.INTEGRITY_CONFLICT
                for event in events
            ),
        )

    def restart_server_for_test(self, epoch: datetime) -> None:
        with self._lock:
            self._server_epoch = _utc(epoch, field="postgres_server_epoch")


def _reject_production_clock_options(options: Mapping[str, object]) -> None:
    if _FORBIDDEN_CLOCK_ARGUMENTS.intersection(options):
        raise ChronosControlPlaneError(
            "CHRONOS_PRODUCTION_CLOCK_INJECTION_FORBIDDEN"
        )
    if options:
        raise TypeError(f"unexpected PostgreSQL options: {sorted(options)}")


class PostgresAuthorityIssuer:
    """Authority-executor adapter; PostgreSQL supplies all production timestamps."""

    def __init__(
        self,
        client: PostgresFunctionClient,
        **options: object,
    ) -> None:
        _reject_production_clock_options(options)
        self._client = client

    def issue_authority(
        self,
        *,
        mission_id: str,
        identity: GitHubRunIdentity,
        generation_token: str,
        ttl_seconds: int,
        code_revision: str,
    ) -> str:
        _generation_hash(generation_token)
        if not 1 <= ttl_seconds <= 1200:
            raise ChronosControlPlaneError("CHRONOS_AUTHORITY_TTL_INVALID")
        if code_revision != identity.github_sha:
            raise ChronosControlPlaneError("CHRONOS_CODE_REVISION_MISMATCH")
        row = self._client.fetch_one(
            "SELECT public.chronos_issue_effect_authority("
            "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) AS authority_id",
            (
                mission_id,
                identity.github_run_id,
                identity.github_run_attempt,
                identity.github_sha,
                identity.github_workflow_ref,
                identity.github_workflow_sha,
                identity.github_repository,
                identity.github_ref,
                bytes.fromhex(generation_token),
                ttl_seconds,
                code_revision,
            ),
        )
        return cast(str, row["authority_id"])


class PostgresEffectLedger:
    """Runtime adapter backed only by reviewed PostgreSQL functions."""

    def __init__(
        self,
        client: PostgresFunctionClient,
        **options: object,
    ) -> None:
        _reject_production_clock_options(options)
        self._client = client

    @staticmethod
    def _receipt(row: Mapping[str, object]) -> AuthorityReceipt:
        return AuthorityReceipt(
            authority_id=cast(str, row["authority_id"]),
            db_authorized_at=cast(datetime, row["db_authorized_at"]),
            expires_at=cast(datetime, row["expires_at"]),
            postgres_server_epoch=cast(
                datetime,
                row["postgres_server_epoch"],
            ),
            authority_receipt_hash=cast(str, row["authority_receipt_hash"]),
        )

    @staticmethod
    def _event(row: Mapping[str, object]) -> EffectEvent:
        return EffectEvent(
            event_id=cast(str, row["event_id"]),
            event_seq=cast(int, row["event_seq"]),
            operation_id=cast(str, row["operation_id"]),
            authority_id=cast(str, row["authority_id"]),
            event_type=EffectEventType(cast(str, row["event_type"])),
            resource_kind=cast(str, row["resource_kind"]),
            resource_key=cast(str, row["resource_key"]),
            payload_hash=cast(str, row["payload_hash"]),
            db_recorded_at=cast(datetime, row["db_recorded_at"]),
            github_run_id=cast(int, row["github_run_id"]),
            github_run_attempt=cast(int, row["github_run_attempt"]),
            code_revision=cast(str, row["code_revision"]),
            previous_event_hash=cast(str | None, row["previous_event_hash"]),
            event_hash=cast(str, row["event_hash"]),
        )

    def claim_effect_authority(
        self,
        *,
        authority_id: str,
        operation: EffectOperation,
        generation_token: str,
    ) -> AuthorityReceipt:
        identity = operation.identity
        row = self._client.fetch_one(
            "SELECT * FROM public.chronos_claim_effect_authority("
            "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (
                authority_id,
                operation.mission_id,
                identity.github_run_id,
                identity.github_run_attempt,
                identity.github_sha,
                identity.github_workflow_ref,
                identity.github_workflow_sha,
                identity.github_repository,
                identity.github_ref,
                bytes.fromhex(generation_token),
                operation.operation_id,
                operation.resource_kind,
                operation.canonical_key,
                operation.canonical_payload_hash,
                operation.code_revision,
            ),
        )
        return self._receipt(row)

    def append_event(
        self,
        *,
        authority_id: str,
        operation: EffectOperation,
        generation_token: str,
        event_type: EffectEventType,
    ) -> EffectEvent:
        identity = operation.identity
        row = self._client.fetch_one(
            "SELECT * FROM public.chronos_append_effect_event("
            "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (
                authority_id,
                operation.operation_id,
                event_type.value,
                identity.github_run_id,
                identity.github_run_attempt,
                identity.github_sha,
                identity.github_workflow_ref,
                identity.github_workflow_sha,
                identity.github_repository,
                identity.github_ref,
                bytes.fromhex(generation_token),
                operation.code_revision,
            ),
        )
        return self._event(row)

    def latest_event(self, operation_id: str) -> EffectEvent | None:
        row = self._client.fetch_one(
            "SELECT * FROM public.chronos_get_effect_state(%s)",
            (operation_id,),
        )
        if not row:
            return None
        return self._event(row)


class EffectLedger(Protocol):
    def append_event(
        self,
        *,
        authority_id: str,
        operation: EffectOperation,
        generation_token: str,
        event_type: EffectEventType,
    ) -> EffectEvent: ...

    def latest_event(self, operation_id: str) -> EffectEvent | None: ...


@dataclass(frozen=True, slots=True)
class DispatchResult:
    event: EffectEvent
    put_permit_consumed: bool


class AttributableR2EffectExecutor:
    """Executes one conditional PUT without inventing physical attribution."""

    def __init__(
        self,
        *,
        ledger: EffectLedger,
        store: ConditionalObjectStore,
    ) -> None:
        self._ledger = ledger
        self._store = store

    def _append(
        self,
        *,
        authority_id: str,
        operation: EffectOperation,
        generation_token: str,
        event_type: EffectEventType,
    ) -> EffectEvent:
        return self._ledger.append_event(
            authority_id=authority_id,
            operation=operation,
            generation_token=generation_token,
            event_type=event_type,
        )

    def _append_outcome(
        self,
        *,
        authority_id: str,
        operation: EffectOperation,
        generation_token: str,
        event_type: EffectEventType,
    ) -> EffectEvent:
        try:
            return self._append(
                authority_id=authority_id,
                operation=operation,
                generation_token=generation_token,
                event_type=event_type,
            )
        except ChronosControlPlaneError as error:
            if str(error) != "CHRONOS_EFFECT_TRANSITION_FORBIDDEN":
                raise
            latest = self._ledger.latest_event(operation.operation_id)
            if latest is None:
                raise
            return latest

    def _observe_with_one_get(
        self,
        *,
        authority_id: str,
        operation: EffectOperation,
        generation_token: str,
        payload: bytes,
        recovery: bool,
    ) -> EffectEvent:
        try:
            permit = self._append(
                authority_id=authority_id,
                operation=operation,
                generation_token=generation_token,
                event_type=EffectEventType.R2_GET_DISPATCHED,
            )
        except Exception as error:
            if "CHRONOS_R2_GET_PERMIT_ALREADY_EXISTS" not in str(error):
                raise
            latest = self._ledger.latest_event(operation.operation_id)
            if latest is None:
                raise ChronosControlPlaneError("CHRONOS_EFFECT_NOT_RESERVED")
            return latest
        try:
            observed = self._store.get_object(operation.canonical_key)
        except Exception:
            observed = None
        if observed is None:
            if recovery:
                return permit
            return self._append_outcome(
                authority_id=authority_id,
                operation=operation,
                generation_token=generation_token,
                event_type=EffectEventType.PUT_COMMITTED_ACTUAL_PENDING,
            )
        event_type = (
            EffectEventType.RECOVERY_OBSERVED_MATCHING_OBJECT
            if recovery and observed.data == payload
            else EffectEventType.PREEXISTING_CONFIRMED
            if observed.data == payload
            else EffectEventType.INTEGRITY_CONFLICT
        )
        return self._append_outcome(
            authority_id=authority_id,
            operation=operation,
            generation_token=generation_token,
            event_type=event_type,
        )

    def dispatch_reserved(
        self,
        *,
        authority_id: str,
        authority_receipt_hash: str,
        operation: EffectOperation,
        generation_token: str,
        payload: bytes,
    ) -> DispatchResult:
        _require_sha(
            authority_receipt_hash,
            field="authority_receipt_hash",
            lengths=frozenset({64}),
        )
        actual_hash = hashlib.sha256(payload).hexdigest()
        if actual_hash != operation.canonical_payload_hash:
            raise ChronosControlPlaneError("CHRONOS_R2_PAYLOAD_HASH_MISMATCH")
        latest = self._ledger.latest_event(operation.operation_id)
        if latest is None:
            raise ChronosControlPlaneError("CHRONOS_EFFECT_NOT_RESERVED")
        if latest.event_type is EffectEventType.PUT_DISPATCHED:
            pending = self._append(
                authority_id=authority_id,
                operation=operation,
                generation_token=generation_token,
                event_type=EffectEventType.PUT_COMMITTED_ACTUAL_PENDING,
            )
            return DispatchResult(event=pending, put_permit_consumed=True)
        if latest.event_type is not EffectEventType.EFFECT_RESERVED:
            return DispatchResult(
                event=latest,
                put_permit_consumed=latest.event_type
                not in {
                    EffectEventType.AUTHORITY_GRANTED,
                    EffectEventType.EFFECT_RESERVED,
                    EffectEventType.FAILED_BEFORE_DISPATCH,
                },
            )

        dispatched = False

        def on_dispatch() -> None:
            nonlocal dispatched
            if dispatched:
                raise ChronosControlPlaneError("CHRONOS_DUPLICATE_DISPATCH_CALLBACK")
            self._append(
                authority_id=authority_id,
                operation=operation,
                generation_token=generation_token,
                event_type=EffectEventType.PUT_DISPATCHED,
            )
            dispatched = True

        try:
            result = self._store.put_if_absent(
                operation.canonical_key,
                payload,
                metadata={
                    "operation_id": operation.operation_id,
                    "authority_receipt_hash": authority_receipt_hash,
                    "payload_hash": operation.canonical_payload_hash,
                },
                on_dispatch=on_dispatch,
            )
        except Exception:
            durable = self._ledger.latest_event(operation.operation_id)
            if durable is None:
                raise ChronosControlPlaneError("CHRONOS_EFFECT_NOT_RESERVED")
            if durable.event_type is EffectEventType.PUT_DISPATCHED:
                event = self._append_outcome(
                    authority_id=authority_id,
                    operation=operation,
                    generation_token=generation_token,
                    event_type=EffectEventType.PUT_COMMITTED_ACTUAL_PENDING,
                )
                return DispatchResult(event=event, put_permit_consumed=True)
            if durable.event_type is EffectEventType.EFFECT_RESERVED:
                event = self._append_outcome(
                    authority_id=authority_id,
                    operation=operation,
                    generation_token=generation_token,
                    event_type=EffectEventType.FAILED_BEFORE_DISPATCH,
                )
                return DispatchResult(event=event, put_permit_consumed=False)
            return DispatchResult(event=durable, put_permit_consumed=dispatched)

        if not dispatched:
            failed = self._append(
                authority_id=authority_id,
                operation=operation,
                generation_token=generation_token,
                event_type=EffectEventType.FAILED_BEFORE_DISPATCH,
            )
            return DispatchResult(event=failed, put_permit_consumed=False)

        unambiguous_single_attempt = (
            result.transport_attempts == 1
            and not result.automatic_retry_possible
        )
        if (
            result.outcome is ConditionalPutOutcome.CREATED
            and unambiguous_single_attempt
        ):
            event_type = EffectEventType.CREATED_CONFIRMED
        elif (
            result.outcome is ConditionalPutOutcome.PRECONDITION_FAILED
            and unambiguous_single_attempt
        ):
            event = self._observe_with_one_get(
                authority_id=authority_id,
                operation=operation,
                generation_token=generation_token,
                payload=payload,
                recovery=False,
            )
            return DispatchResult(event=event, put_permit_consumed=True)
        elif (
            result.outcome is ConditionalPutOutcome.DEFINITE_FAILURE
            and unambiguous_single_attempt
        ):
            event_type = EffectEventType.FAILED_AFTER_DISPATCH
        else:
            event_type = EffectEventType.PUT_COMMITTED_ACTUAL_PENDING
        event = self._append_outcome(
            authority_id=authority_id,
            operation=operation,
            generation_token=generation_token,
            event_type=event_type,
        )
        return DispatchResult(event=event, put_permit_consumed=True)

    def observe_pending(
        self,
        *,
        authority_id: str,
        operation: EffectOperation,
        generation_token: str,
        payload: bytes,
    ) -> DispatchResult:
        if hashlib.sha256(payload).hexdigest() != operation.canonical_payload_hash:
            raise ChronosControlPlaneError("CHRONOS_R2_PAYLOAD_HASH_MISMATCH")
        latest = self._ledger.latest_event(operation.operation_id)
        if latest is None:
            raise ChronosControlPlaneError("CHRONOS_EFFECT_NOT_RESERVED")
        if latest.event_type is EffectEventType.PUT_DISPATCHED:
            latest = self._append(
                authority_id=authority_id,
                operation=operation,
                generation_token=generation_token,
                event_type=EffectEventType.PUT_COMMITTED_ACTUAL_PENDING,
            )
        if latest.event_type is EffectEventType.PUT_COMMITTED_ACTUAL_PENDING:
            event = self._observe_with_one_get(
                authority_id=authority_id,
                operation=operation,
                generation_token=generation_token,
                payload=payload,
                recovery=True,
            )
            return DispatchResult(event=event, put_permit_consumed=True)
        return DispatchResult(event=latest, put_permit_consumed=True)


__all__ = [
    "AttributableR2EffectExecutor", "AuthorityReceipt",
    "ChronosControlPlaneError", "ConditionalObjectStore",
    "ConditionalPutOutcome", "ConditionalPutResult", "DispatchResult",
    "EffectCounters", "EffectEvent", "EffectEventType", "EffectOperation",
    "GitHubRunIdentity", "MemoryChronosControlPlane", "ObservedObject",
    "PostgresAuthorityIssuer", "PostgresEffectLedger", "PostgresFunctionClient",
    "TestClock", "derive_event_hash", "derive_operation_id",
]
