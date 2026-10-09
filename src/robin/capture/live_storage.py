"""Durable authorization, lease, budget, and receipt state for live canaries."""

from __future__ import annotations

import hashlib
import os
import stat
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TypeAlias, cast

from robin.capture.bootstrap_contracts import (
    ActivationEnvelopeV2,
    LivePlanItemV2,
    LivePlanV2,
    OwnerAuthorizationV2,
)
from robin.capture.contracts import (
    AdmissionStatus,
    CaptureContractError,
    QuotaObservation,
    canonical_json_bytes,
    canonical_sha256,
    ensure_utc,
    strict_json_object,
)
from robin.capture.live_contracts import (
    ActivationEnvelopeV1,
    LiveAdmissionPermitV1,
    LiveExecutionAttemptReceiptV1,
    LiveExecutionReceiptV1,
    LiveLeaseV1,
    LivePlanItemV1,
    LivePlanV1,
    LiveResponseIntakeClaimV1,
    LiveTerminalDisposition,
    OwnerAuthorizationV1,
)
from robin.capture.storage import (
    _MAX_CONTRACT_BYTES,
    _MAX_LEDGER_BYTES,
    CaptureStorageError,
    CaptureStore,
    _exclusive_file_lock,
    _path_exists_no_follow,
    _reject_reparse_path,
    _repair_truncated_jsonl_tail,
    _safe_read_bounded,
    _safe_regular_file,
)

LiveAuthorization: TypeAlias = OwnerAuthorizationV1 | OwnerAuthorizationV2
LiveActivation: TypeAlias = ActivationEnvelopeV1 | ActivationEnvelopeV2
LivePlan: TypeAlias = LivePlanV1 | LivePlanV2
LivePlanItem: TypeAlias = LivePlanItemV1 | LivePlanItemV2


class LiveStorageError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class LiveBudgetReservation:
    entry_sha256: str
    reserved_requests: int
    reserved_credits: int
    maximum_requests: int
    maximum_credits: int


@dataclass(frozen=True, slots=True)
class LiveDispatchStartedState:
    admission_permit: LiveAdmissionPermitV1
    lease: LiveLeaseV1
    dispatch_started_at_utc: datetime
    marker_sha256: str


@dataclass(slots=True)
class _BudgetContext:
    authorization_id: str
    activation_id: str
    plan_id: str
    maximum_requests: int
    maximum_credits: int
    reserved_requests: int = 0
    reserved_credits: int = 0
    used_requests: int = 0
    used_credits: int = 0


@dataclass(slots=True)
class _BudgetItem:
    context_key: tuple[str, str, str]
    item_id: str
    credits: int
    reserved_at: datetime
    dispatched: bool = False
    reconciled: bool = False
    dispatch_at: datetime | None = None
    dispatch_entry_sha256: str | None = None


def _utc_text(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise LiveStorageError("LIVE_TIMESTAMP_UTC_REQUIRED")
    return value.isoformat().replace("+00:00", "Z")


def _fsync_parent(path: Path) -> None:
    if os.name == "nt":
        return
    _reject_reparse_path(path)
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        opened = os.fstat(descriptor)
        current = path.lstat()
        if (
            not os.path.samestat(opened, current)
            or not stat.S_ISDIR(opened.st_mode)
            or not stat.S_ISDIR(current.st_mode)
        ):
            raise LiveStorageError("LIVE_STORAGE_DIRECTORY_IDENTITY_CHANGED")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class LiveStateStore:
    """Pessimistic state store: existence never reopens a network attempt."""

    _BUDGET_KEYS = {
        "activation_id",
        "activation_hash",
        "authorization_id",
        "authorization_hash",
        "credits_delta",
        "entry_sha256",
        "event",
        "item_hash",
        "item_id",
        "maximum_credits",
        "maximum_requests",
        "plan_hash",
        "plan_id",
        "previous_entry_sha256",
        "quota_requests_last",
        "reserved_credits",
        "reserved_requests",
        "requests_delta",
        "timestamp_utc",
        "used_credits",
        "used_requests",
    }

    def __init__(
        self,
        capture_store: CaptureStore,
        *,
        failure_injector: Callable[[str], None] | None = None,
    ) -> None:
        self.capture_store = capture_store
        self.root = capture_store.root
        self.budget_ledger = self.root / "live-budget-ledger.jsonl"
        self._budget_lock = self.root / ".live-budget-ledger.lock"
        self.failure_injector = failure_injector

    def _crash_point(self, stage: str) -> None:
        if self.failure_injector is not None:
            self.failure_injector(stage)

    def assert_capture_root(self, expected_fingerprint: str) -> None:
        if self.capture_store.capture_root_fingerprint() != expected_fingerprint:
            raise LiveStorageError("LIVE_CAPTURE_ROOT_FINGERPRINT_MISMATCH")

    @contextmanager
    def item_execution_lock(self, item_hash: str) -> Iterator[None]:
        if len(item_hash) != 64 or any(value not in "0123456789abcdef" for value in item_hash):
            raise LiveStorageError("LIVE_ITEM_HASH_INVALID")
        self._directory("live/execution-locks")
        lock_path = self.capture_store._path(f"live/execution-locks/{item_hash}.lock")
        with _exclusive_file_lock(lock_path):
            yield

    def assert_item_not_previously_claimed(self, item_hash: str) -> None:
        if len(item_hash) != 64 or any(value not in "0123456789abcdef" for value in item_hash):
            raise LiveStorageError("LIVE_ITEM_HASH_INVALID")
        if _path_exists_no_follow(
            self.capture_store._path(f"live/leases/{item_hash}.json")
        ) or _path_exists_no_follow(self.capture_store._path(f"live/terminal/{item_hash}.json")):
            raise LiveStorageError("LIVE_ITEM_ALREADY_CLAIMED_TERMINAL_NO_RETRY")

    def _directory(self, logical: str) -> Path:
        directory = self.capture_store._directory(logical)
        self.capture_store.capture_root_fingerprint()
        return directory

    def _write_one_shot_marker_pair(
        self,
        *,
        primary_key: str,
        anchor_key: str,
        payload: bytes,
        exists_error: str,
        write_error: str,
    ) -> None:
        """Durably burn a transition twice before a later effect may proceed."""

        for key in (anchor_key, primary_key):
            path = self.capture_store._path(key)
            self._directory(str(Path(key).parent).replace("\\", "/"))
            try:
                with _safe_regular_file(
                    path,
                    flags=os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    mode="wb",
                ) as stream:
                    stream.write(payload)
                    stream.flush()
                    os.fsync(stream.fileno())
                _fsync_parent(path.parent)
            except FileExistsError:
                raise LiveStorageError(exists_error) from None
            except (CaptureStorageError, OSError):
                raise LiveStorageError(write_error) from None

    def _read_exact_marker_pair(
        self,
        *,
        primary_key: str,
        anchor_key: str,
        expected: bytes | None,
        missing_error: str,
        invalid_error: str,
    ) -> bytes:
        try:
            primary = _safe_read_bounded(
                self.capture_store._path(primary_key),
                maximum_bytes=_MAX_CONTRACT_BYTES,
            )
            anchor = _safe_read_bounded(
                self.capture_store._path(anchor_key),
                maximum_bytes=_MAX_CONTRACT_BYTES,
            )
        except FileNotFoundError:
            raise LiveStorageError(missing_error) from None
        except (CaptureStorageError, OSError):
            raise LiveStorageError(invalid_error) from None
        if primary != anchor or (expected is not None and primary != expected):
            raise LiveStorageError(invalid_error)
        return primary

    def _any_durable_marker(self, *keys: str) -> bool:
        try:
            return any(_path_exists_no_follow(self.capture_store._path(key)) for key in keys)
        except CaptureStorageError:
            raise LiveStorageError("LIVE_DURABLE_MARKER_IDENTITY_INVALID") from None

    @staticmethod
    def _validated_chain(
        authorization: LiveAuthorization,
        activation: LiveActivation,
        plan: LivePlan,
        item: LivePlanItem,
    ) -> tuple[LiveAuthorization, LiveActivation, LivePlan, LivePlanItem]:
        try:
            material = (
                authorization.model_dump(mode="json"),
                activation.model_dump(mode="json"),
                plan.model_dump(mode="json"),
                item.model_dump(mode="json"),
            )
            if material[0].get("schema_version") == "robin-owner-authorization-v2":
                if tuple(value.get("schema_version") for value in material[1:]) != (
                    "robin-live-activation-envelope-v2",
                    "robin-live-plan-v2",
                    "robin-live-plan-item-v2",
                ):
                    raise ValueError("LIVE_STORAGE_MIXED_CONTRACT_VERSION")
                return (
                    OwnerAuthorizationV2.model_validate(material[0]),
                    ActivationEnvelopeV2.model_validate(material[1]),
                    LivePlanV2.model_validate(material[2]),
                    LivePlanItemV2.model_validate(material[3]),
                )
            if tuple(value.get("schema_version") for value in material) != (
                "robin-owner-authorization-v1",
                "robin-live-activation-envelope-v1",
                "robin-live-plan-v1",
                "robin-live-plan-item-v1",
            ):
                raise ValueError("LIVE_STORAGE_MIXED_CONTRACT_VERSION")
            return (
                OwnerAuthorizationV1.model_validate(material[0]),
                ActivationEnvelopeV1.model_validate(material[1]),
                LivePlanV1.model_validate(material[2]),
                LivePlanItemV1.model_validate(material[3]),
            )
        except (AttributeError, CaptureContractError, TypeError, ValueError):
            raise LiveStorageError("LIVE_STORAGE_INPUT_CONTRACT_INVALID") from None

    @staticmethod
    def _binding_payload(
        *,
        authorization: LiveAuthorization,
        activation: LiveActivation,
        binding: str,
    ) -> bytes:
        material = {
            "schema_version": "robin-live-authority-binding-v1",
            "binding": binding,
            "authorization_id": authorization.authorization_id,
            "authorization_hash": authorization.canonical_authorization_hash,
            "activation_id": activation.activation_id,
            "activation_hash": activation.canonical_activation_hash,
            "authorization_nonce_sha256": canonical_sha256(
                {"nonce": authorization.authorization_nonce}
            ),
            "activation_nonce_sha256": canonical_sha256({"nonce": activation.activation_nonce}),
        }
        return canonical_json_bytes(material) + b"\n"

    def _bind_once_or_same(self, path: Path, payload: bytes) -> None:
        try:
            with _safe_regular_file(
                path,
                flags=os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                mode="wb",
            ) as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            _fsync_parent(path.parent)
        except FileExistsError:
            try:
                existing = _safe_read_bounded(
                    path,
                    maximum_bytes=_MAX_CONTRACT_BYTES,
                )
            except OSError:
                raise LiveStorageError("LIVE_AUTHORITY_BINDING_INVALID") from None
            if existing != payload:
                raise LiveStorageError("LIVE_AUTHORITY_ALREADY_BOUND") from None

    def acquire_lease(
        self,
        *,
        authorization: LiveAuthorization,
        activation: LiveActivation,
        plan: LivePlan,
        item: LivePlanItem,
        acquired_at: datetime,
    ) -> LiveLeaseV1:
        authorization, activation, plan, item = self._validated_chain(
            authorization, activation, plan, item
        )
        self._directory("live/authority-bindings")
        authorization_key = canonical_sha256(
            {"authorization_nonce": authorization.authorization_nonce}
        )
        activation_key = canonical_sha256({"activation_nonce": activation.activation_nonce})
        authorization_binding = self._binding_payload(
            authorization=authorization,
            activation=activation,
            binding="ONE_AUTHORIZATION_TO_ONE_ACTIVATION",
        )
        activation_binding = self._binding_payload(
            authorization=authorization,
            activation=activation,
            binding="ONE_ACTIVATION_NONCE_TO_ONE_ACTIVATION",
        )
        self._bind_once_or_same(
            self.capture_store._path(
                f"live/authority-bindings/authorization-{authorization_key}.json"
            ),
            authorization_binding,
        )
        self._bind_once_or_same(
            self.capture_store._path(f"live/authority-bindings/activation-{activation_key}.json"),
            activation_binding,
        )
        self._directory("live/leases")
        path = self.capture_store._path(f"live/leases/{item.canonical_item_hash}.json")
        try:
            _safe_read_bounded(path, maximum_bytes=_MAX_CONTRACT_BYTES)
        except FileNotFoundError:
            pass
        else:
            raise LiveStorageError("LIVE_ITEM_ALREADY_LEASED_TERMINAL_NO_RETRY")

        lease = LiveLeaseV1.issue(
            authorization_id=authorization.authorization_id,
            authorization_hash=authorization.canonical_authorization_hash,
            activation_id=activation.activation_id,
            activation_hash=activation.canonical_activation_hash,
            repository_sha=activation.repository_sha,
            plan_id=plan.plan_id,
            plan_hash=plan.canonical_plan_hash,
            item_id=item.item_id,
            item_hash=item.canonical_item_hash,
            request_fingerprint_sha256=item.provider_request_fingerprint,
            authorization_binding_key_sha256=authorization_key,
            authorization_binding_payload_sha256=hashlib.sha256(authorization_binding).hexdigest(),
            activation_binding_key_sha256=activation_key,
            activation_binding_payload_sha256=hashlib.sha256(activation_binding).hexdigest(),
            acquired_at_utc=acquired_at,
            expires_at_utc=item.expires_at_utc,
        )
        payload = canonical_json_bytes(lease.model_dump(mode="json")) + b"\n"
        try:
            with _safe_regular_file(
                path,
                flags=os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                mode="wb",
            ) as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            _fsync_parent(path.parent)
        except FileExistsError:
            raise LiveStorageError("LIVE_ITEM_ALREADY_LEASED_TERMINAL_NO_RETRY") from None
        except BaseException:
            # Never unlink: an empty/partial marker is a permanent no-retry tombstone.
            raise
        return lease

    def _assert_prior_plan_leases_are_budgeted(
        self,
        *,
        plan: LivePlan,
        current_item_hash: str,
        items: dict[str, _BudgetItem],
    ) -> None:
        """Treat any earlier lease missing from budget state as spent capacity.

        A lease is intentionally durable before reservation.  The current item's
        lease may therefore be the legitimate in-flight transition, but a lease
        for any other item in the same immutable plan cannot be ignored when a
        later item asks for capacity.  This pessimistic cross-check also catches
        deletion of both a JSONL suffix and its content-addressed event object.
        """

        for candidate in plan.items:
            if candidate.canonical_item_hash == current_item_hash:
                continue
            lease_path = self.capture_store._path(
                f"live/leases/{candidate.canonical_item_hash}.json"
            )
            if not _path_exists_no_follow(lease_path):
                continue
            try:
                lease = LiveLeaseV1.model_validate_json(
                    _safe_read_bounded(
                        lease_path,
                        maximum_bytes=_MAX_CONTRACT_BYTES,
                    )
                )
            except (CaptureContractError, CaptureStorageError, OSError, ValueError):
                raise LiveStorageError("LIVE_BUDGET_TOMBSTONE_INVALID") from None
            if (
                lease.plan_id != plan.plan_id
                or lease.plan_hash != plan.canonical_plan_hash
                or lease.item_id != candidate.item_id
                or lease.item_hash != candidate.canonical_item_hash
                or candidate.canonical_item_hash not in items
            ):
                raise LiveStorageError("LIVE_BUDGET_TOMBSTONE_UNACCOUNTED")

    def _load_budget(
        self,
    ) -> tuple[
        str | None,
        dict[tuple[str, str, str], _BudgetContext],
        dict[str, _BudgetItem],
    ]:
        previous: str | None = None
        contexts: dict[tuple[str, str, str], _BudgetContext] = {}
        items: dict[str, _BudgetItem] = {}
        previous_event_at: datetime | None = None
        try:
            recovery = _repair_truncated_jsonl_tail(
                self.budget_ledger,
                maximum_bytes=_MAX_LEDGER_BYTES,
            )
        except CaptureStorageError:
            raise LiveStorageError("LIVE_BUDGET_LEDGER_INVALID") from None
        if recovery is not None:
            recovery_record = {
                **recovery,
                "ledger": "live-budget-ledger-v1",
            }
            self.capture_store._write_immutable(
                f"live/budget-tail-recovery/{canonical_sha256(recovery_record)}.json",
                canonical_json_bytes(recovery_record) + b"\n",
            )
        try:
            entries = self.capture_store._load_anchored_jsonl_entries(
                ledger=self.budget_ledger,
                event_directory_key="live/budget-events",
                rollback_error="CAPTURE_LIVE_BUDGET_LEDGER_ROLLBACK_DETECTED",
            )
        except CaptureStorageError:
            raise LiveStorageError("LIVE_BUDGET_LEDGER_ROLLBACK_DETECTED") from None
        for entry in entries:
            if set(entry) != self._BUDGET_KEYS:
                raise LiveStorageError("LIVE_BUDGET_LEDGER_INVALID")
            entry_hash = entry.get("entry_sha256")
            identity = {key: value for key, value in entry.items() if key != "entry_sha256"}
            if (
                not isinstance(entry_hash, str)
                or canonical_sha256(identity) != entry_hash
                or entry.get("previous_entry_sha256") != previous
            ):
                raise LiveStorageError("LIVE_BUDGET_LEDGER_HASH_CHAIN_INVALID")
            strings = (
                entry.get("authorization_id"),
                entry.get("authorization_hash"),
                entry.get("activation_id"),
                entry.get("activation_hash"),
                entry.get("plan_id"),
                entry.get("plan_hash"),
                entry.get("item_id"),
                entry.get("item_hash"),
                entry.get("timestamp_utc"),
            )
            if any(not isinstance(value, str) for value in strings):
                raise LiveStorageError("LIVE_BUDGET_LEDGER_INVALID")
            authorization_id = cast(str, strings[0])
            context_key = cast(tuple[str, str, str], (strings[1], strings[3], strings[5]))
            activation_id = cast(str, strings[2])
            plan_id = cast(str, strings[4])
            item_id = cast(str, strings[6])
            item_hash = cast(str, strings[7])
            try:
                event_at = ensure_utc(
                    datetime.fromisoformat(cast(str, strings[8]).replace("Z", "+00:00")),
                    field="live_budget_event_at",
                )
            except (TypeError, ValueError):
                raise LiveStorageError("LIVE_BUDGET_LEDGER_INVALID") from None
            if previous_event_at is not None and event_at < previous_event_at:
                raise LiveStorageError("LIVE_BUDGET_TIMESTAMP_ORDER_INVALID")
            integer_names = (
                "maximum_requests",
                "maximum_credits",
                "requests_delta",
                "credits_delta",
                "reserved_requests",
                "reserved_credits",
                "used_requests",
                "used_credits",
            )
            if any(
                isinstance(entry.get(name), bool) or not isinstance(entry.get(name), int)
                for name in integer_names
            ):
                raise LiveStorageError("LIVE_BUDGET_LEDGER_INVALID")
            maximum_requests = cast(int, entry["maximum_requests"])
            maximum_credits = cast(int, entry["maximum_credits"])
            context = contexts.setdefault(
                context_key,
                _BudgetContext(
                    authorization_id=authorization_id,
                    activation_id=activation_id,
                    plan_id=plan_id,
                    maximum_requests=maximum_requests,
                    maximum_credits=maximum_credits,
                ),
            )
            if (
                context.authorization_id != authorization_id
                or context.activation_id != activation_id
                or context.plan_id != plan_id
                or context.maximum_requests != maximum_requests
                or context.maximum_credits != maximum_credits
            ):
                raise LiveStorageError("LIVE_BUDGET_CONFIGURATION_MISMATCH")
            event = entry.get("event")
            requests_delta = cast(int, entry["requests_delta"])
            credits_delta = cast(int, entry["credits_delta"])
            if event == "RESERVED":
                if (
                    item_hash in items
                    or requests_delta != 1
                    or credits_delta <= 0
                    or entry.get("quota_requests_last") is not None
                ):
                    raise LiveStorageError("LIVE_BUDGET_TRANSITION_INVALID")
                context.reserved_requests += 1
                context.reserved_credits += credits_delta
                items[item_hash] = _BudgetItem(
                    context_key,
                    item_id,
                    credits_delta,
                    event_at,
                )
            elif event == "DISPATCH_ARMED":
                item = items.get(item_hash)
                if (
                    item is None
                    or item.context_key != context_key
                    or item.item_id != item_id
                    or item.dispatched
                    or event_at < item.reserved_at
                    or requests_delta != -1
                    or credits_delta != -item.credits
                    or entry.get("quota_requests_last") is not None
                ):
                    raise LiveStorageError("LIVE_BUDGET_TRANSITION_INVALID")
                context.reserved_requests -= 1
                context.reserved_credits -= item.credits
                context.used_requests += 1
                context.used_credits += item.credits
                item.dispatched = True
                item.dispatch_at = event_at
                item.dispatch_entry_sha256 = entry_hash
            elif event == "RECONCILED":
                item = items.get(item_hash)
                quota_last = entry.get("quota_requests_last")
                if (
                    item is None
                    or item.context_key != context_key
                    or item.item_id != item_id
                    or not item.dispatched
                    or item.reconciled
                    or item.dispatch_at is None
                    or event_at < item.dispatch_at
                    or requests_delta != 0
                    or credits_delta != 0
                    or isinstance(quota_last, bool)
                    or not isinstance(quota_last, int)
                    or quota_last != item.credits
                ):
                    raise LiveStorageError("LIVE_BUDGET_TRANSITION_INVALID")
                item.reconciled = True
            else:
                raise LiveStorageError("LIVE_BUDGET_EVENT_INVALID")
            if (
                context.reserved_requests != entry.get("reserved_requests")
                or context.reserved_credits != entry.get("reserved_credits")
                or context.used_requests != entry.get("used_requests")
                or context.used_credits != entry.get("used_credits")
                or min(
                    context.reserved_requests,
                    context.reserved_credits,
                    context.used_requests,
                    context.used_credits,
                )
                < 0
                or context.reserved_requests + context.used_requests > context.maximum_requests
                or context.reserved_credits + context.used_credits > context.maximum_credits
            ):
                raise LiveStorageError("LIVE_BUDGET_STATE_INVALID")
            previous = entry_hash
            previous_event_at = event_at
        return previous, contexts, items

    def _append_budget_event(
        self,
        *,
        previous: str | None,
        context_key: tuple[str, str, str],
        item_id: str,
        item_hash: str,
        context: _BudgetContext,
        event: str,
        requests_delta: int,
        credits_delta: int,
        timestamp: datetime,
        quota_requests_last: int | None,
    ) -> str:
        identity = {
            "activation_id": context.activation_id,
            "activation_hash": context_key[1],
            "authorization_id": context.authorization_id,
            "authorization_hash": context_key[0],
            "credits_delta": credits_delta,
            "event": event,
            "item_id": item_id,
            "item_hash": item_hash,
            "maximum_credits": context.maximum_credits,
            "maximum_requests": context.maximum_requests,
            "plan_id": context.plan_id,
            "plan_hash": context_key[2],
            "previous_entry_sha256": previous,
            "quota_requests_last": quota_requests_last,
            "reserved_credits": context.reserved_credits,
            "reserved_requests": context.reserved_requests,
            "requests_delta": requests_delta,
            "timestamp_utc": _utc_text(timestamp),
            "used_credits": context.used_credits,
            "used_requests": context.used_requests,
        }
        entry_hash = canonical_sha256(identity)
        entry = {"entry_sha256": entry_hash, **identity}
        try:
            self.capture_store._append_anchored_jsonl_entry(
                ledger=self.budget_ledger,
                event_directory_key="live/budget-events",
                entry=entry,
            )
        except CaptureStorageError:
            raise LiveStorageError("LIVE_BUDGET_LEDGER_WRITE_FAILED") from None
        return entry_hash

    def reserve_budget(
        self,
        *,
        authorization: LiveAuthorization,
        activation: LiveActivation,
        plan: LivePlan,
        item: LivePlanItem,
        reserved_at: datetime,
    ) -> LiveBudgetReservation:
        authorization, activation, plan, item = self._validated_chain(
            authorization, activation, plan, item
        )
        if tuple(candidate for candidate in plan.items if candidate == item) != (item,):
            raise LiveStorageError("LIVE_BUDGET_ITEM_NOT_IN_PLAN")
        with _exclusive_file_lock(self._budget_lock):
            previous, contexts, items = self._load_budget()
            self._assert_prior_plan_leases_are_budgeted(
                plan=plan,
                current_item_hash=item.canonical_item_hash,
                items=items,
            )
            context_key = (
                authorization.canonical_authorization_hash,
                activation.canonical_activation_hash,
                plan.canonical_plan_hash,
            )
            if item.canonical_item_hash in items:
                raise LiveStorageError("LIVE_BUDGET_ITEM_ALREADY_RESERVED")
            context = contexts.setdefault(
                context_key,
                _BudgetContext(
                    authorization_id=authorization.authorization_id,
                    activation_id=activation.activation_id,
                    plan_id=plan.plan_id,
                    maximum_requests=plan.maximum_http_calls,
                    maximum_credits=plan.maximum_credits,
                ),
            )
            if (
                context.maximum_requests != plan.maximum_http_calls
                or context.maximum_credits != plan.maximum_credits
            ):
                raise LiveStorageError("LIVE_BUDGET_CONFIGURATION_MISMATCH")
            credits = item.maximum_credits
            if (
                context.reserved_requests + context.used_requests + 1 > context.maximum_requests
                or context.reserved_credits + context.used_credits + credits
                > context.maximum_credits
            ):
                raise LiveStorageError("LIVE_BUDGET_EXHAUSTED")
            context.reserved_requests += 1
            context.reserved_credits += credits
            entry_hash = self._append_budget_event(
                previous=previous,
                context_key=context_key,
                item_id=item.item_id,
                item_hash=item.canonical_item_hash,
                context=context,
                event="RESERVED",
                requests_delta=1,
                credits_delta=credits,
                timestamp=reserved_at,
                quota_requests_last=None,
            )
            return LiveBudgetReservation(
                entry_sha256=entry_hash,
                reserved_requests=1,
                reserved_credits=credits,
                maximum_requests=context.maximum_requests,
                maximum_credits=context.maximum_credits,
            )

    def arm_dispatch(
        self,
        *,
        authorization: LiveAuthorization,
        activation: LiveActivation,
        plan: LivePlan,
        item: LivePlanItem,
        lease: LiveLeaseV1,
        request_fingerprint_sha256: str,
        armed_at: datetime,
    ) -> LiveAdmissionPermitV1:
        authorization, activation, plan, item = self._validated_chain(
            authorization, activation, plan, item
        )
        try:
            durable_lease_bytes = _safe_read_bounded(
                self.capture_store._path(f"live/leases/{item.canonical_item_hash}.json"),
                maximum_bytes=_MAX_CONTRACT_BYTES,
            )
            durable_lease = LiveLeaseV1.model_validate_json(durable_lease_bytes)
        except (CaptureContractError, OSError, ValueError):
            raise LiveStorageError("LIVE_DURABLE_LEASE_INVALID") from None
        if (
            durable_lease != lease
            or durable_lease_bytes
            != canonical_json_bytes(durable_lease.model_dump(mode="json")) + b"\n"
            or lease.authorization_id != authorization.authorization_id
            or lease.authorization_hash != authorization.canonical_authorization_hash
            or lease.activation_id != activation.activation_id
            or lease.activation_hash != activation.canonical_activation_hash
            or lease.repository_sha != activation.repository_sha
            or lease.plan_id != plan.plan_id
            or lease.plan_hash != plan.canonical_plan_hash
            or lease.item_id != item.item_id
            or lease.item_hash != item.canonical_item_hash
        ):
            raise LiveStorageError("LIVE_DURABLE_LEASE_MISMATCH")
        marker = {
            "schema_version": "robin-live-dispatch-armed-v1",
            "authorization_hash": authorization.canonical_authorization_hash,
            "activation_hash": activation.canonical_activation_hash,
            "item_hash": item.canonical_item_hash,
            "lease_id": lease.lease_id,
            "plan_hash": plan.canonical_plan_hash,
            "request_fingerprint_sha256": request_fingerprint_sha256,
            "armed_at_utc": _utc_text(armed_at),
            "network_calls_claimed": 0,
        }
        self._directory("live/dispatch-armed")
        path = self.capture_store._path(f"live/dispatch-armed/{item.canonical_item_hash}.json")
        try:
            with _safe_regular_file(
                path,
                flags=os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                mode="wb",
            ) as stream:
                stream.write(canonical_json_bytes(marker) + b"\n")
                stream.flush()
                os.fsync(stream.fileno())
            _fsync_parent(path.parent)
        except FileExistsError:
            raise LiveStorageError("LIVE_DISPATCH_ALREADY_ARMED_NO_RETRY") from None
        with _exclusive_file_lock(self._budget_lock):
            previous, contexts, items = self._load_budget()
            context_key = (
                authorization.canonical_authorization_hash,
                activation.canonical_activation_hash,
                plan.canonical_plan_hash,
            )
            context = contexts.get(context_key)
            budget_item = items.get(item.canonical_item_hash)
            if context is None or budget_item is None or budget_item.dispatched:
                raise LiveStorageError("LIVE_BUDGET_DISPATCH_STATE_INVALID")
            context.reserved_requests -= 1
            context.reserved_credits -= budget_item.credits
            context.used_requests += 1
            context.used_credits += budget_item.credits
            dispatch_entry_sha256 = self._append_budget_event(
                previous=previous,
                context_key=context_key,
                item_id=item.item_id,
                item_hash=item.canonical_item_hash,
                context=context,
                event="DISPATCH_ARMED",
                requests_delta=-1,
                credits_delta=-budget_item.credits,
                timestamp=armed_at,
                quota_requests_last=None,
            )
        return LiveAdmissionPermitV1.issue(
            capture_root_fingerprint=self.capture_store.capture_root_fingerprint(),
            authorization_id=authorization.authorization_id,
            authorization_hash=authorization.canonical_authorization_hash,
            activation_id=activation.activation_id,
            activation_hash=activation.canonical_activation_hash,
            repository_sha=activation.repository_sha,
            plan_id=plan.plan_id,
            plan_hash=plan.canonical_plan_hash,
            item_id=item.item_id,
            item_hash=item.canonical_item_hash,
            lease_id=lease.lease_id,
            authorization_binding_key_sha256=lease.authorization_binding_key_sha256,
            authorization_binding_payload_sha256=(lease.authorization_binding_payload_sha256),
            activation_binding_key_sha256=lease.activation_binding_key_sha256,
            activation_binding_payload_sha256=lease.activation_binding_payload_sha256,
            request_fingerprint_sha256=request_fingerprint_sha256,
            reserved_credits=budget_item.credits,
            dispatch_armed_marker_sha256=canonical_sha256(marker),
            budget_dispatch_entry_sha256=dispatch_entry_sha256,
        )

    def verify_admission_permit(
        self,
        permit: LiveAdmissionPermitV1,
        *,
        consume: bool,
        require_consumed: bool = True,
    ) -> LiveAdmissionPermitV1:
        try:
            validated = LiveAdmissionPermitV1.model_validate(permit.model_dump(mode="json"))
            lease_bytes = _safe_read_bounded(
                self.capture_store._path(f"live/leases/{validated.item_hash}.json"),
                maximum_bytes=_MAX_CONTRACT_BYTES,
            )
            lease = LiveLeaseV1.model_validate_json(lease_bytes)
            marker_bytes = _safe_read_bounded(
                self.capture_store._path(f"live/dispatch-armed/{validated.item_hash}.json"),
                maximum_bytes=_MAX_CONTRACT_BYTES,
            )
            marker = strict_json_object(marker_bytes)
            authorization_binding = _safe_read_bounded(
                self.capture_store._path(
                    "live/authority-bindings/authorization-"
                    f"{validated.authorization_binding_key_sha256}.json"
                ),
                maximum_bytes=_MAX_CONTRACT_BYTES,
            )
            activation_binding = _safe_read_bounded(
                self.capture_store._path(
                    "live/authority-bindings/activation-"
                    f"{validated.activation_binding_key_sha256}.json"
                ),
                maximum_bytes=_MAX_CONTRACT_BYTES,
            )
            authorization_binding_record = strict_json_object(authorization_binding)
            activation_binding_record = strict_json_object(activation_binding)
        except (AttributeError, CaptureContractError, OSError, TypeError, ValueError):
            raise LiveStorageError("LIVE_ADMISSION_PERMIT_DURABLE_STATE_INVALID") from None
        try:
            armed_at = ensure_utc(
                datetime.fromisoformat(
                    cast(str, marker.get("armed_at_utc")).replace("Z", "+00:00")
                ),
                field="live_dispatch_armed_at",
            )
        except (AttributeError, TypeError, ValueError):
            raise LiveStorageError("LIVE_ADMISSION_PERMIT_DURABLE_STATE_INVALID") from None
        binding_keys = {
            "activation_hash",
            "activation_id",
            "activation_nonce_sha256",
            "authorization_hash",
            "authorization_id",
            "authorization_nonce_sha256",
            "binding",
            "schema_version",
        }
        binding_nonce_hashes = (
            authorization_binding_record.get("authorization_nonce_sha256"),
            authorization_binding_record.get("activation_nonce_sha256"),
        )
        if (
            validated.capture_root_fingerprint != self.capture_store.capture_root_fingerprint()
            or lease.lease_id != validated.lease_id
            or lease_bytes != canonical_json_bytes(lease.model_dump(mode="json")) + b"\n"
            or lease.authorization_id != validated.authorization_id
            or lease.authorization_hash != validated.authorization_hash
            or lease.activation_id != validated.activation_id
            or lease.activation_hash != validated.activation_hash
            or lease.repository_sha != validated.repository_sha
            or lease.plan_id != validated.plan_id
            or lease.plan_hash != validated.plan_hash
            or lease.item_id != validated.item_id
            or lease.item_hash != validated.item_hash
            or lease.request_fingerprint_sha256 != validated.request_fingerprint_sha256
            or lease.authorization_binding_key_sha256 != validated.authorization_binding_key_sha256
            or lease.authorization_binding_payload_sha256
            != validated.authorization_binding_payload_sha256
            or lease.activation_binding_key_sha256 != validated.activation_binding_key_sha256
            or lease.activation_binding_payload_sha256
            != validated.activation_binding_payload_sha256
            or not lease.acquired_at_utc <= armed_at < lease.expires_at_utc
            or hashlib.sha256(authorization_binding).hexdigest()
            != validated.authorization_binding_payload_sha256
            or hashlib.sha256(activation_binding).hexdigest()
            != validated.activation_binding_payload_sha256
            or authorization_binding != canonical_json_bytes(authorization_binding_record) + b"\n"
            or activation_binding != canonical_json_bytes(activation_binding_record) + b"\n"
            or set(authorization_binding_record) != binding_keys
            or set(activation_binding_record) != binding_keys
            or any(
                not isinstance(value, str)
                or len(value) != 64
                or any(character not in "0123456789abcdef" for character in value)
                for value in binding_nonce_hashes
            )
            or authorization_binding_record.get("schema_version")
            != "robin-live-authority-binding-v1"
            or authorization_binding_record.get("authorization_id") != validated.authorization_id
            or authorization_binding_record.get("authorization_hash")
            != validated.authorization_hash
            or authorization_binding_record.get("activation_id") != validated.activation_id
            or authorization_binding_record.get("activation_hash") != validated.activation_hash
            or authorization_binding_record.get("binding") != "ONE_AUTHORIZATION_TO_ONE_ACTIVATION"
            or activation_binding_record.get("binding") != "ONE_ACTIVATION_NONCE_TO_ONE_ACTIVATION"
            or any(
                activation_binding_record.get(key) != authorization_binding_record.get(key)
                for key in (
                    "activation_hash",
                    "activation_id",
                    "activation_nonce_sha256",
                    "authorization_hash",
                    "authorization_id",
                    "authorization_nonce_sha256",
                    "schema_version",
                )
            )
            or canonical_sha256(marker) != validated.dispatch_armed_marker_sha256
            or marker_bytes != canonical_json_bytes(marker) + b"\n"
            or marker
            != {
                "schema_version": "robin-live-dispatch-armed-v1",
                "authorization_hash": validated.authorization_hash,
                "activation_hash": validated.activation_hash,
                "item_hash": validated.item_hash,
                "lease_id": validated.lease_id,
                "plan_hash": validated.plan_hash,
                "request_fingerprint_sha256": validated.request_fingerprint_sha256,
                "armed_at_utc": marker.get("armed_at_utc"),
                "network_calls_claimed": 0,
            }
        ):
            raise LiveStorageError("LIVE_ADMISSION_PERMIT_DURABLE_STATE_MISMATCH")
        with _exclusive_file_lock(self._budget_lock):
            _previous, _contexts, items = self._load_budget()
            budget_item = items.get(validated.item_hash)
            if (
                budget_item is None
                or not budget_item.dispatched
                or budget_item.item_id != validated.item_id
                or budget_item.credits != validated.reserved_credits
                or budget_item.dispatch_entry_sha256 != validated.budget_dispatch_entry_sha256
                or budget_item.context_key
                != (
                    validated.authorization_hash,
                    validated.activation_hash,
                    validated.plan_hash,
                )
            ):
                raise LiveStorageError("LIVE_ADMISSION_PERMIT_BUDGET_STATE_MISMATCH")
        payload = (
            canonical_json_bytes(
                {
                    "schema_version": "robin-live-admission-consumed-v1",
                    "canonical_permit_sha256": validated.canonical_permit_sha256,
                    "item_hash": validated.item_hash,
                }
            )
            + b"\n"
        )
        primary_key = f"live/admission-consumed/{validated.item_hash}.json"
        anchor_key = f"live/admission-consumed-anchors/{validated.item_hash}.json"
        if consume:
            if self._any_durable_marker(
                f"live/dispatch-started/{validated.item_hash}.json",
                f"live/dispatch-started-anchors/{validated.item_hash}.json",
                f"live/response-intake-claimed/{validated.item_hash}.json",
                f"live/response-intake-anchors/{validated.item_hash}.json",
                f"live/terminal/{validated.item_hash}.json",
            ):
                raise LiveStorageError("LIVE_ADMISSION_ALREADY_CONSUMED_NO_RETRY")
            self._write_one_shot_marker_pair(
                primary_key=primary_key,
                anchor_key=anchor_key,
                payload=payload,
                exists_error="LIVE_ADMISSION_ALREADY_CONSUMED_NO_RETRY",
                write_error="LIVE_ADMISSION_CONSUMPTION_MARKER_WRITE_FAILED",
            )
        if consume or require_consumed:
            self._read_exact_marker_pair(
                primary_key=primary_key,
                anchor_key=anchor_key,
                expected=payload,
                missing_error="LIVE_ADMISSION_CONSUMPTION_MARKER_MISSING",
                invalid_error="LIVE_ADMISSION_CONSUMPTION_MARKER_MISMATCH",
            )
        return validated

    def _dispatch_armed_at(self, item_hash: str) -> datetime:
        try:
            marker = strict_json_object(
                _safe_read_bounded(
                    self.capture_store._path(f"live/dispatch-armed/{item_hash}.json"),
                    maximum_bytes=_MAX_CONTRACT_BYTES,
                )
            )
            return ensure_utc(
                datetime.fromisoformat(cast(str, marker["armed_at_utc"]).replace("Z", "+00:00")),
                field="live_dispatch_armed_at",
            )
        except (CaptureContractError, KeyError, OSError, TypeError, ValueError):
            raise LiveStorageError("LIVE_DISPATCH_ARMED_MARKER_INVALID") from None

    def verify_armed_permit(
        self,
        permit: LiveAdmissionPermitV1,
    ) -> LiveAdmissionPermitV1:
        validated = self.verify_admission_permit(
            permit,
            consume=False,
            require_consumed=False,
        )
        if self._any_durable_marker(
            f"live/admission-consumed/{validated.item_hash}.json",
            f"live/admission-consumed-anchors/{validated.item_hash}.json",
            f"live/dispatch-started/{validated.item_hash}.json",
            f"live/dispatch-started-anchors/{validated.item_hash}.json",
            f"live/response-intake-claimed/{validated.item_hash}.json",
            f"live/response-intake-anchors/{validated.item_hash}.json",
            f"live/terminal/{validated.item_hash}.json",
        ):
            raise LiveStorageError("LIVE_ADMISSION_ALREADY_CONSUMED_NO_RETRY")
        return validated

    def mark_dispatch_started(
        self,
        permit: LiveAdmissionPermitV1,
        *,
        dispatch_started_at: datetime,
    ) -> LiveDispatchStartedState:
        validated = self.verify_admission_permit(permit, consume=False)
        started = ensure_utc(dispatch_started_at, field="live_dispatch_started_at")
        lease = LiveLeaseV1.model_validate_json(
            _safe_read_bounded(
                self.capture_store._path(f"live/leases/{validated.item_hash}.json"),
                maximum_bytes=_MAX_CONTRACT_BYTES,
            )
        )
        armed_at = self._dispatch_armed_at(validated.item_hash)
        if not lease.acquired_at_utc <= armed_at <= started < lease.expires_at_utc:
            raise LiveStorageError("LIVE_DISPATCH_STARTED_TIMESTAMP_INVALID")
        if self._any_durable_marker(
            f"live/response-intake-claimed/{validated.item_hash}.json",
            f"live/response-intake-anchors/{validated.item_hash}.json",
            f"live/terminal/{validated.item_hash}.json",
        ):
            raise LiveStorageError("LIVE_DISPATCH_ALREADY_STARTED_NO_RETRY")
        single_effect_count = 1
        identity = {
            "schema_version": "robin-live-dispatch-started-v1",
            "admission_permit": validated.model_dump(mode="json"),
            "dispatch_started_at_utc": _utc_text(started),
            "network_calls_possible": single_effect_count,
            "provider_calls_possible": single_effect_count,
            "retries": 0,
            "secret_reads_count": single_effect_count,
        }
        marker = {
            "canonical_marker_sha256": canonical_sha256(identity),
            **identity,
        }
        payload = canonical_json_bytes(marker) + b"\n"
        self._write_one_shot_marker_pair(
            primary_key=f"live/dispatch-started/{validated.item_hash}.json",
            anchor_key=f"live/dispatch-started-anchors/{validated.item_hash}.json",
            payload=payload,
            exists_error="LIVE_DISPATCH_ALREADY_STARTED_NO_RETRY",
            write_error="LIVE_DISPATCH_STARTED_MARKER_WRITE_FAILED",
        )
        return self.load_dispatch_started(validated.item_hash)  # type: ignore[return-value]

    def load_dispatch_started(self, item_hash: str) -> LiveDispatchStartedState | None:
        primary_key = f"live/dispatch-started/{item_hash}.json"
        anchor_key = f"live/dispatch-started-anchors/{item_hash}.json"
        if not self._any_durable_marker(primary_key, anchor_key):
            return None
        marker_bytes = self._read_exact_marker_pair(
            primary_key=primary_key,
            anchor_key=anchor_key,
            expected=None,
            missing_error="LIVE_DISPATCH_STARTED_MARKER_INVALID",
            invalid_error="LIVE_DISPATCH_STARTED_MARKER_INVALID",
        )
        try:
            marker = strict_json_object(marker_bytes)
            if set(marker) != {
                "admission_permit",
                "canonical_marker_sha256",
                "dispatch_started_at_utc",
                "network_calls_possible",
                "provider_calls_possible",
                "retries",
                "schema_version",
                "secret_reads_count",
            }:
                raise ValueError
            identity = {
                key: value for key, value in marker.items() if key != "canonical_marker_sha256"
            }
            if (
                marker.get("schema_version") != "robin-live-dispatch-started-v1"
                or marker_bytes != canonical_json_bytes(marker) + b"\n"
                or marker.get("canonical_marker_sha256") != canonical_sha256(identity)
                or marker.get("network_calls_possible") != 1
                or marker.get("provider_calls_possible") != 1
                or marker.get("retries") != 0
                or marker.get("secret_reads_count") != 1
            ):
                raise ValueError
            permit = LiveAdmissionPermitV1.model_validate(marker["admission_permit"])
            if permit.item_hash != item_hash:
                raise ValueError
            permit = self.verify_admission_permit(permit, consume=False)
            lease = LiveLeaseV1.model_validate_json(
                _safe_read_bounded(
                    self.capture_store._path(f"live/leases/{item_hash}.json"),
                    maximum_bytes=_MAX_CONTRACT_BYTES,
                )
            )
            if lease.lease_id != permit.lease_id:
                raise ValueError
            started = ensure_utc(
                datetime.fromisoformat(
                    cast(str, marker["dispatch_started_at_utc"]).replace("Z", "+00:00")
                ),
                field="live_dispatch_started_at",
            )
            armed_at = self._dispatch_armed_at(item_hash)
            if not lease.acquired_at_utc <= armed_at <= started < lease.expires_at_utc:
                raise ValueError
        except (CaptureContractError, KeyError, OSError, TypeError, ValueError):
            raise LiveStorageError("LIVE_DISPATCH_STARTED_MARKER_INVALID") from None
        return LiveDispatchStartedState(
            admission_permit=permit,
            lease=lease,
            dispatch_started_at_utc=started,
            marker_sha256=cast(str, marker["canonical_marker_sha256"]),
        )

    def claim_live_response_intake(
        self,
        permit: LiveAdmissionPermitV1,
        *,
        payload_sha256: str,
        payload_byte_length: int,
        first_observed_at: datetime,
        ingested_at: datetime,
    ) -> LiveResponseIntakeClaimV1:
        if (
            len(payload_sha256) != 64
            or any(value not in "0123456789abcdef" for value in payload_sha256)
            or isinstance(payload_byte_length, bool)
            or not isinstance(payload_byte_length, int)
            or payload_byte_length < 0
        ):
            raise LiveStorageError("LIVE_RESPONSE_INTAKE_IDENTITY_INVALID")
        validated = self.verify_admission_permit(permit, consume=False)
        started = self.load_dispatch_started(validated.item_hash)
        observed = ensure_utc(first_observed_at, field="live_first_observed_at")
        ingested = ensure_utc(ingested_at, field="live_ingested_at")
        if (
            started is None
            or started.admission_permit != validated
            or started.lease.lease_id != validated.lease_id
            or observed < started.dispatch_started_at_utc
            or ingested < observed
        ):
            raise LiveStorageError("LIVE_RESPONSE_INTAKE_DISPATCH_MISMATCH")
        if _path_exists_no_follow(
            self.capture_store._path(f"live/terminal/{validated.item_hash}.json")
        ):
            raise LiveStorageError("LIVE_RESPONSE_INTAKE_ALREADY_TERMINAL_NO_RETRY")
        claim = LiveResponseIntakeClaimV1.issue(
            canonical_permit_sha256=validated.canonical_permit_sha256,
            dispatch_started_marker_sha256=started.marker_sha256,
            item_hash=validated.item_hash,
            payload_sha256=payload_sha256,
            payload_byte_length=payload_byte_length,
            first_observed_at_utc=observed,
            ingested_at_utc=ingested,
        )
        payload = canonical_json_bytes(claim.model_dump(mode="json")) + b"\n"
        self._write_one_shot_marker_pair(
            primary_key=f"live/response-intake-claimed/{validated.item_hash}.json",
            anchor_key=f"live/response-intake-anchors/{validated.item_hash}.json",
            payload=payload,
            exists_error="LIVE_RESPONSE_INTAKE_ALREADY_CLAIMED_NO_RETRY",
            write_error="LIVE_RESPONSE_INTAKE_CLAIM_WRITE_FAILED",
        )
        observed_claim = self.load_response_intake_claim(validated.item_hash)
        if observed_claim != claim:
            raise LiveStorageError("LIVE_RESPONSE_INTAKE_CLAIM_MISMATCH")
        return observed_claim

    def load_response_intake_claim(self, item_hash: str) -> LiveResponseIntakeClaimV1:
        if len(item_hash) != 64 or any(value not in "0123456789abcdef" for value in item_hash):
            raise LiveStorageError("LIVE_RESPONSE_INTAKE_IDENTITY_INVALID")
        try:
            claim_bytes = self._read_exact_marker_pair(
                primary_key=f"live/response-intake-claimed/{item_hash}.json",
                anchor_key=f"live/response-intake-anchors/{item_hash}.json",
                expected=None,
                missing_error="LIVE_RESPONSE_INTAKE_CLAIM_INVALID",
                invalid_error="LIVE_RESPONSE_INTAKE_CLAIM_INVALID",
            )
            claim = LiveResponseIntakeClaimV1.model_validate_json(claim_bytes)
            started = self.load_dispatch_started(item_hash)
            if (
                claim.item_hash != item_hash
                or claim_bytes != canonical_json_bytes(claim.model_dump(mode="json")) + b"\n"
                or started is None
                or claim.canonical_permit_sha256 != started.admission_permit.canonical_permit_sha256
                or claim.dispatch_started_marker_sha256 != started.marker_sha256
                or claim.first_observed_at_utc < started.dispatch_started_at_utc
            ):
                raise ValueError
        except (
            CaptureContractError,
            CaptureStorageError,
            OSError,
            TypeError,
            ValueError,
        ):
            raise LiveStorageError("LIVE_RESPONSE_INTAKE_CLAIM_INVALID") from None
        return claim

    def terminal_marker_exists(self, item_hash: str) -> bool:
        path = self.capture_store._path(f"live/terminal/{item_hash}.json")
        try:
            marker = strict_json_object(
                _safe_read_bounded(
                    path,
                    maximum_bytes=_MAX_CONTRACT_BYTES,
                )
            )
        except FileNotFoundError:
            return False
        except (CaptureContractError, UnicodeDecodeError, ValueError):
            return False
        return (
            set(marker)
            == {
                "execution_receipt_id",
                "item_hash",
                "retry_authorized",
                "schema_version",
                "terminal_at_utc",
                "terminal_disposition",
            }
            and marker.get("schema_version") == "robin-live-item-terminal-v1"
            and marker.get("item_hash") == item_hash
            and marker.get("retry_authorized") is False
            and marker.get("terminal_disposition")
            in {
                "DISPATCH_OUTCOME_UNKNOWN",
                "HTTP_REJECTED",
                "OFFLINE_REPLAY_FAILED",
                "PAYLOAD_REJECTED",
                "PRE_DISPATCH_REJECTED",
                "QUOTA_RECONCILIATION_FAILED",
                "SUCCESS",
            }
        )

    def load_unterminalized_receipt(
        self,
        item_hash: str,
    ) -> LiveExecutionReceiptV1 | None:
        matches: list[LiveExecutionReceiptV1] = []
        root = self._directory("live/execution-receipts")
        for path in sorted(root.glob("*.json")):
            try:
                candidate = LiveExecutionReceiptV1.model_validate_json(
                    _safe_read_bounded(
                        path,
                        maximum_bytes=_MAX_CONTRACT_BYTES,
                    )
                )
            except CaptureContractError:
                # A crash-partial immutable primary is a tombstone, not a valid
                # terminal receipt and not a reason to reopen a dispatch.
                continue
            except (OSError, ValueError):
                raise LiveStorageError("LIVE_TERMINAL_RECEIPT_INVALID") from None
            if path.stem != candidate.execution_receipt_id:
                raise LiveStorageError("LIVE_TERMINAL_RECEIPT_PATH_IDENTITY_MISMATCH")
            if candidate.item_hash == item_hash:
                matches.append(candidate)
        if len(matches) > 1:
            raise LiveStorageError("LIVE_MULTIPLE_TERMINAL_RECEIPTS_FOR_ITEM")
        return matches[0] if matches else None

    def reconcile_budget(
        self,
        *,
        authorization: LiveAuthorization,
        activation: LiveActivation,
        plan: LivePlan,
        item: LivePlanItem,
        quota: QuotaObservation,
        reconciled_at: datetime,
    ) -> None:
        authorization, activation, plan, item = self._validated_chain(
            authorization, activation, plan, item
        )
        try:
            quota_values = (
                quota.requests_remaining,
                quota.requests_used,
                quota.requests_last,
            )
            if any(
                value is not None and (isinstance(value, bool) or not isinstance(value, int))
                for value in quota_values
            ):
                raise ValueError
            quota = QuotaObservation.model_validate(quota.model_dump(mode="json"))
        except (AttributeError, CaptureContractError, TypeError, ValueError):
            raise LiveStorageError("LIVE_QUOTA_RECONCILIATION_INVALID") from None
        if quota.requests_last != item.maximum_credits:
            raise LiveStorageError("LIVE_QUOTA_RECONCILIATION_FAILED")
        with _exclusive_file_lock(self._budget_lock):
            previous, contexts, items = self._load_budget()
            context_key = (
                authorization.canonical_authorization_hash,
                activation.canonical_activation_hash,
                plan.canonical_plan_hash,
            )
            context = contexts.get(context_key)
            budget_item = items.get(item.canonical_item_hash)
            if (
                context is None
                or budget_item is None
                or not budget_item.dispatched
                or budget_item.reconciled
            ):
                raise LiveStorageError("LIVE_BUDGET_RECONCILIATION_STATE_INVALID")
            self._append_budget_event(
                previous=previous,
                context_key=context_key,
                item_id=item.item_id,
                item_hash=item.canonical_item_hash,
                context=context,
                event="RECONCILED",
                requests_delta=0,
                credits_delta=0,
                timestamp=reconciled_at,
                quota_requests_last=quota.requests_last,
            )

    def _load_lease(self, item_hash: str) -> LiveLeaseV1:
        if len(item_hash) != 64 or any(value not in "0123456789abcdef" for value in item_hash):
            raise LiveStorageError("LIVE_LEASE_INVALID")
        try:
            payload = _safe_read_bounded(
                self.capture_store._path(f"live/leases/{item_hash}.json"),
                maximum_bytes=_MAX_CONTRACT_BYTES,
            )
            lease = LiveLeaseV1.model_validate_json(payload)
        except (CaptureContractError, OSError, TypeError, ValueError):
            raise LiveStorageError("LIVE_LEASE_INVALID") from None
        if (
            lease.item_hash != item_hash
            or payload != canonical_json_bytes(lease.model_dump(mode="json")) + b"\n"
        ):
            raise LiveStorageError("LIVE_LEASE_INVALID")
        return lease

    @staticmethod
    def _terminal_matches_lease(
        receipt: LiveExecutionReceiptV1,
        lease: LiveLeaseV1,
    ) -> bool:
        return (
            receipt.authorization_id == lease.authorization_id
            and receipt.authorization_hash == lease.authorization_hash
            and receipt.activation_id == lease.activation_id
            and receipt.activation_hash == lease.activation_hash
            and receipt.repository_sha == lease.repository_sha
            and receipt.plan_id == lease.plan_id
            and receipt.plan_hash == lease.plan_hash
            and receipt.item_id == lease.item_id
            and receipt.item_hash == lease.item_hash
            and receipt.lease_id == lease.lease_id
            and receipt.lease_hash == lease.lease_id
            and receipt.request_fingerprint_sha256 == lease.request_fingerprint_sha256
        )

    def _validate_terminal_receipt_durable_lineage(
        self,
        receipt: LiveExecutionReceiptV1,
    ) -> None:
        lease = self._load_lease(receipt.item_hash)
        if not self._terminal_matches_lease(receipt, lease):
            raise LiveStorageError("LIVE_TERMINAL_RECEIPT_LEASE_MISMATCH")
        self.verify_terminal_budget_state(receipt)

        started = self.load_dispatch_started(receipt.item_hash)
        if receipt.terminal_disposition is LiveTerminalDisposition.PRE_DISPATCH_REJECTED:
            if started is not None:
                raise LiveStorageError("LIVE_TERMINAL_RECEIPT_DISPATCH_MISMATCH")
            return
        if started is None:
            raise LiveStorageError("LIVE_TERMINAL_RECEIPT_DISPATCH_MISSING")
        permit = self.verify_admission_permit(
            started.admission_permit,
            consume=False,
        )
        if (
            not self._terminal_matches_lease(receipt, started.lease)
            or permit.lease_id != lease.lease_id
            or permit.request_fingerprint_sha256 != receipt.request_fingerprint_sha256
            or permit.reserved_credits != receipt.reserved_credits
            or started.dispatch_started_at_utc != receipt.dispatch_started_at_utc
        ):
            raise LiveStorageError("LIVE_TERMINAL_RECEIPT_DISPATCH_MISMATCH")
        if receipt.terminal_disposition is LiveTerminalDisposition.DISPATCH_OUTCOME_UNKNOWN:
            return
        if receipt.execution_attempt_id is None or receipt.response_intake_claim_sha256 is None:
            raise LiveStorageError("LIVE_TERMINAL_RECEIPT_ATTEMPT_MISSING")
        attempt = self.load_execution_attempt(
            receipt.execution_attempt_id,
            manifest_id=receipt.manifest_id,
        )
        if (
            attempt.authorization_hash != receipt.authorization_hash
            or attempt.activation_hash != receipt.activation_hash
            or attempt.plan_hash != receipt.plan_hash
            or attempt.item_hash != receipt.item_hash
            or attempt.lease_id != receipt.lease_id
            or attempt.request_fingerprint_sha256 != receipt.request_fingerprint_sha256
            or attempt.response_intake_claim_sha256 != receipt.response_intake_claim_sha256
            or attempt.dispatch_started_at_utc != receipt.dispatch_started_at_utc
            or attempt.first_observed_at_utc != receipt.first_observed_at_utc
            or attempt.ingested_at_utc != receipt.ingested_at_utc
            or attempt.http_status != receipt.http_status
            or attempt.payload_sha256 != receipt.payload_sha256
            or attempt.payload_byte_length != receipt.payload_byte_length
            or attempt.capture_receipt_id != receipt.final_receipt_id
            or attempt.manifest_id != receipt.manifest_id
            or attempt.manifest_hash != receipt.manifest_hash
        ):
            raise LiveStorageError("LIVE_TERMINAL_RECEIPT_ATTEMPT_MISMATCH")
        claim = self.load_response_intake_claim(receipt.item_hash)
        if claim.canonical_intake_claim_sha256 != receipt.response_intake_claim_sha256:
            raise LiveStorageError("LIVE_TERMINAL_RECEIPT_INTAKE_UNBOUND")
        if receipt.final_receipt_id is not None:
            capture_receipt = self.capture_store.load_receipt(receipt.final_receipt_id)
            if (
                capture_receipt.request_fingerprint_sha256 != receipt.request_fingerprint_sha256
                or capture_receipt.payload_sha256 != receipt.payload_sha256
                or capture_receipt.payload_byte_length != receipt.payload_byte_length
                or capture_receipt.http_status != receipt.http_status
                or capture_receipt.robin_first_observed_at != receipt.first_observed_at_utc
                or capture_receipt.robin_ingested_at != receipt.ingested_at_utc
                or capture_receipt.intake_receipt_id != receipt.intake_receipt_id
                or capture_receipt.quota != receipt.observed_quota
            ):
                raise LiveStorageError("LIVE_TERMINAL_RECEIPT_CAPTURE_MISMATCH")
            code = capture_receipt.rejection_code or ""
            if (
                (
                    receipt.terminal_disposition is LiveTerminalDisposition.HTTP_REJECTED
                    and code not in {"CAPTURE_HTTP_STATUS_REJECTED", "CAPTURE_REDIRECT_FORBIDDEN"}
                )
                or (
                    receipt.terminal_disposition is LiveTerminalDisposition.PAYLOAD_REJECTED
                    and (
                        capture_receipt.admission_status is not AdmissionStatus.QUARANTINED
                        or not code
                        or code.startswith("CAPTURE_QUOTA")
                        or code in {"CAPTURE_HTTP_STATUS_REJECTED", "CAPTURE_REDIRECT_FORBIDDEN"}
                    )
                )
                or (
                    receipt.terminal_disposition
                    is LiveTerminalDisposition.QUOTA_RECONCILIATION_FAILED
                    and not code.startswith("CAPTURE_QUOTA")
                    and capture_receipt.admission_status is not AdmissionStatus.ADMITTED
                )
            ):
                raise LiveStorageError("LIVE_TERMINAL_RECEIPT_DISPOSITION_MISMATCH")
        if receipt.manifest_id is not None:
            try:
                replay = self.capture_store._replay_preterminal_live(receipt.manifest_id)
            except (CaptureStorageError, LiveStorageError, OSError, ValueError):
                if not (
                    receipt.terminal_disposition is LiveTerminalDisposition.OFFLINE_REPLAY_FAILED
                    and receipt.offline_replay_verdict == "FAILED"
                ):
                    raise LiveStorageError("LIVE_TERMINAL_RECEIPT_REPLAY_MISMATCH") from None
            else:
                if (
                    receipt.terminal_disposition is LiveTerminalDisposition.OFFLINE_REPLAY_FAILED
                    or replay.snapshot_id != receipt.manifest_id
                ):
                    raise LiveStorageError("LIVE_TERMINAL_RECEIPT_REPLAY_MISMATCH")

    def verify_terminal_budget_state(self, receipt: LiveExecutionReceiptV1) -> None:
        """Bind a terminal disposition to the immutable budget transition history."""

        try:
            receipt = LiveExecutionReceiptV1.model_validate(receipt.model_dump(mode="json"))
        except (AttributeError, CaptureContractError, TypeError, ValueError):
            raise LiveStorageError("LIVE_TERMINAL_RECEIPT_INVALID") from None
        with _exclusive_file_lock(self._budget_lock):
            _previous, _contexts, items = self._load_budget()
            budget_item = items.get(receipt.item_hash)
        expected_reserved_requests = 1 if budget_item is not None else 0
        expected_reserved_credits = budget_item.credits if budget_item is not None else 0
        if (
            receipt.reserved_requests != expected_reserved_requests
            or receipt.reserved_credits != expected_reserved_credits
            or (
                receipt.terminal_disposition is not LiveTerminalDisposition.PRE_DISPATCH_REJECTED
                and (budget_item is None or not budget_item.dispatched)
            )
        ):
            raise LiveStorageError("LIVE_TERMINAL_RECEIPT_BUDGET_MISMATCH")
        reconciliation_required = receipt.terminal_disposition in {
            LiveTerminalDisposition.SUCCESS,
            LiveTerminalDisposition.OFFLINE_REPLAY_FAILED,
        } or (
            receipt.terminal_disposition is LiveTerminalDisposition.PAYLOAD_REJECTED
            and receipt.observed_quota is not None
        )
        reconciled = budget_item.reconciled if budget_item is not None else False
        reconciliation_forbidden = (
            receipt.terminal_disposition is not LiveTerminalDisposition.DISPATCH_OUTCOME_UNKNOWN
            and not reconciliation_required
        )
        if (reconciliation_required and not reconciled) or (
            reconciliation_forbidden and reconciled
        ):
            raise LiveStorageError("LIVE_TERMINAL_RECEIPT_RECONCILIATION_MISMATCH")

    def store_terminal_receipt(self, receipt: LiveExecutionReceiptV1) -> None:
        try:
            receipt = LiveExecutionReceiptV1.model_validate(receipt.model_dump(mode="json"))
        except (AttributeError, CaptureContractError, TypeError, ValueError):
            raise LiveStorageError("LIVE_TERMINAL_RECEIPT_INVALID") from None
        self._validate_terminal_receipt_durable_lineage(receipt)
        if receipt.response_intake_claim_sha256 is not None:
            if receipt.execution_attempt_id is None:
                raise LiveStorageError("LIVE_TERMINAL_RECEIPT_INTAKE_UNBOUND")
            attempt = self.load_execution_attempt(
                receipt.execution_attempt_id,
                manifest_id=receipt.manifest_id,
            )
            if receipt.response_intake_claim_sha256 != attempt.response_intake_claim_sha256:
                raise LiveStorageError("LIVE_TERMINAL_RECEIPT_INTAKE_UNBOUND")
        elif receipt.execution_attempt_id is not None:
            raise LiveStorageError("LIVE_TERMINAL_RECEIPT_INTAKE_UNBOUND")
        receipt_key = f"live/execution-receipts/{receipt.execution_receipt_id}.json"
        self.capture_store._write_immutable(
            receipt_key,
            canonical_json_bytes(receipt.model_dump(mode="json")) + b"\n",
        )
        self._crash_point("AFTER_TERMINAL_RECEIPT_PRIMARY")
        if receipt.manifest_id is not None:
            self.capture_store._write_immutable(
                f"live/execution-receipts/by-manifest/{receipt.manifest_id}.json",
                canonical_json_bytes(receipt.model_dump(mode="json")) + b"\n",
            )
            self._crash_point("AFTER_TERMINAL_RECEIPT_ALIAS")
        terminal = {
            "schema_version": "robin-live-item-terminal-v1",
            "execution_receipt_id": receipt.execution_receipt_id,
            "item_hash": receipt.item_hash,
            "terminal_at_utc": _utc_text(receipt.terminal_at_utc),
            "terminal_disposition": receipt.terminal_disposition.value,
            "retry_authorized": False,
        }
        self._directory("live/terminal")
        terminal_payload = canonical_json_bytes(terminal) + b"\n"
        try:
            self.capture_store._write_immutable(
                f"live/terminal/{receipt.item_hash}.json",
                terminal_payload,
            )
            self._crash_point("AFTER_TERMINAL_MARKER")
        except Exception as error:
            if isinstance(error, LiveStorageError):
                raise
            raise LiveStorageError("LIVE_TERMINAL_MARKER_WRITE_FAILED") from None

    def store_execution_attempt(self, receipt: LiveExecutionAttemptReceiptV1) -> None:
        try:
            receipt = LiveExecutionAttemptReceiptV1.model_validate(receipt.model_dump(mode="json"))
        except (AttributeError, CaptureContractError, TypeError, ValueError):
            raise LiveStorageError("LIVE_EXECUTION_ATTEMPT_INVALID") from None
        claim = self.load_response_intake_claim(receipt.item_hash)
        if (
            claim.canonical_intake_claim_sha256 != receipt.response_intake_claim_sha256
            or claim.payload_sha256 != receipt.payload_sha256
            or claim.payload_byte_length != receipt.payload_byte_length
            or claim.first_observed_at_utc != receipt.first_observed_at_utc
            or claim.ingested_at_utc != receipt.ingested_at_utc
        ):
            raise LiveStorageError("LIVE_EXECUTION_ATTEMPT_INTAKE_UNBOUND")
        payload = canonical_json_bytes(receipt.model_dump(mode="json")) + b"\n"
        self.capture_store._write_immutable(
            f"live/execution-attempts/{receipt.execution_attempt_id}.json",
            payload,
        )
        self._crash_point("AFTER_EXECUTION_ATTEMPT_PRIMARY")
        if receipt.manifest_id is not None:
            self.capture_store._write_immutable(
                f"live/execution-attempts/by-manifest/{receipt.manifest_id}.json",
                payload,
            )
            self._crash_point("AFTER_EXECUTION_ATTEMPT_ALIAS")

    def load_execution_attempt(
        self,
        execution_attempt_id: str,
        *,
        manifest_id: str | None,
    ) -> LiveExecutionAttemptReceiptV1:
        if len(execution_attempt_id) != 64 or any(
            value not in "0123456789abcdef" for value in execution_attempt_id
        ):
            raise LiveStorageError("LIVE_EXECUTION_ATTEMPT_INVALID")
        try:
            primary = _safe_read_bounded(
                self.capture_store._path(f"live/execution-attempts/{execution_attempt_id}.json"),
                maximum_bytes=_MAX_CONTRACT_BYTES,
            )
            attempt = LiveExecutionAttemptReceiptV1.model_validate_json(primary)
            if attempt.execution_attempt_id != execution_attempt_id:
                raise ValueError
            if manifest_id is not None:
                alias = _safe_read_bounded(
                    self.capture_store._path(
                        f"live/execution-attempts/by-manifest/{manifest_id}.json"
                    ),
                    maximum_bytes=_MAX_CONTRACT_BYTES,
                )
                if alias != primary or attempt.manifest_id != manifest_id:
                    raise ValueError
            elif attempt.manifest_id is not None:
                raise ValueError
            claim = self.load_response_intake_claim(attempt.item_hash)
            if (
                claim.canonical_intake_claim_sha256 != attempt.response_intake_claim_sha256
                or claim.payload_sha256 != attempt.payload_sha256
                or claim.payload_byte_length != attempt.payload_byte_length
                or claim.first_observed_at_utc != attempt.first_observed_at_utc
                or claim.ingested_at_utc != attempt.ingested_at_utc
            ):
                raise ValueError
        except (CaptureContractError, CaptureStorageError, OSError, TypeError, ValueError):
            raise LiveStorageError("LIVE_EXECUTION_ATTEMPT_INVALID") from None
        return attempt
