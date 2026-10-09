"""Hard provider budgets and a bounded circuit breaker."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum

# Absolute append-only ledger guards. Operational admission is governed by
# the stricter run/day/week/competition/season ceilings in the central policy.
MAX_API_FOOTBALL_CALLS_TOTAL = 75_000
MAX_ODDS_API_CREDITS_TOTAL = 10_000
ODDS_API_INTERNAL_SAFETY_RESERVE = 2
API_FOOTBALL_PROVIDER_RESERVE = 5_000
ODDS_API_PROVIDER_RESERVE = 4_000
ODDS_NEAR_KICKOFF_RESERVE = 80


class ProviderKind(StrEnum):
    API_FOOTBALL = "API_FOOTBALL"
    ODDS_API = "ODDS_API"


class CircuitState(StrEnum):
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


@dataclass(frozen=True, slots=True)
class BudgetPolicy:
    api_football_limit: int = MAX_API_FOOTBALL_CALLS_TOTAL
    odds_api_limit: int = MAX_ODDS_API_CREDITS_TOTAL
    odds_api_internal_safety_reserve: int = ODDS_API_INTERNAL_SAFETY_RESERVE
    api_football_provider_reserve: int = API_FOOTBALL_PROVIDER_RESERVE
    odds_api_provider_reserve: int = ODDS_API_PROVIDER_RESERVE
    odds_near_kickoff_reserve: int = ODDS_NEAR_KICKOFF_RESERVE

    def __post_init__(self) -> None:
        if (
            self.api_football_limit != MAX_API_FOOTBALL_CALLS_TOTAL
            or self.odds_api_limit != MAX_ODDS_API_CREDITS_TOTAL
            or self.odds_api_internal_safety_reserve
            != ODDS_API_INTERNAL_SAFETY_RESERVE
        ):
            raise ValueError("JALON12_PROVIDER_HARD_LIMITS_IMMUTABLE")
        if (
            self.api_football_provider_reserve != API_FOOTBALL_PROVIDER_RESERVE
            or self.odds_api_provider_reserve != ODDS_API_PROVIDER_RESERVE
            or self.odds_near_kickoff_reserve != ODDS_NEAR_KICKOFF_RESERVE
        ):
            raise ValueError("PROVIDER_EXTERNAL_RESERVES_IMMUTABLE")


@dataclass(frozen=True, slots=True)
class BudgetEntry:
    idempotency_key: str
    provider: ProviderKind
    units: int
    recorded_at: datetime
    reason: str


@dataclass(frozen=True, slots=True)
class BudgetSnapshot:
    provider: ProviderKind
    limit: int
    reserve: int
    used: int
    remaining: int
    spendable: int


class BudgetExceeded(RuntimeError):
    pass


class BudgetLedger:
    """Append-only accounting; an idempotency key can never change meaning."""

    def __init__(self, policy: BudgetPolicy | None = None) -> None:
        self.policy = policy or BudgetPolicy()
        self._entries: dict[str, BudgetEntry] = {}

    @property
    def entries(self) -> tuple[BudgetEntry, ...]:
        return tuple(self._entries.values())

    def snapshot(self, provider: ProviderKind) -> BudgetSnapshot:
        if provider is ProviderKind.API_FOOTBALL:
            limit = self.policy.api_football_limit
        else:
            limit = self.policy.odds_api_limit
        # The provider-level reserves are enforced against provider_remaining,
        # not subtracted from the independent J12 pilot cap.
        reserve = (
            self.policy.odds_api_internal_safety_reserve
            if provider is ProviderKind.ODDS_API
            else 0
        )
        used = sum(entry.units for entry in self._entries.values() if entry.provider is provider)
        remaining = limit - used
        return BudgetSnapshot(
            provider=provider,
            limit=limit,
            reserve=reserve,
            used=used,
            remaining=remaining,
            spendable=max(remaining - reserve, 0),
        )

    def authorize(
        self,
        provider: ProviderKind,
        units: int,
        *,
        provider_remaining: int | None = None,
        provider_reserve: int | None = None,
        near_kickoff: bool = False,
    ) -> BudgetSnapshot:
        if units < 0:
            raise ValueError("PROVIDER_BUDGET_ESTIMATE_MUST_BE_NON_NEGATIVE")
        snapshot = self.snapshot(provider)
        if units > snapshot.spendable:
            raise BudgetExceeded(
                f"PROVIDER_BUDGET_OR_RESERVE_EXCEEDED:{provider.value}"
            )
        if provider_remaining is not None:
            if provider_reserve is None:
                provider_reserve = (
                    self.policy.api_football_provider_reserve
                    if provider is ProviderKind.API_FOOTBALL
                    else self.policy.odds_api_provider_reserve
                    + (
                        self.policy.odds_near_kickoff_reserve
                        if near_kickoff
                        else 0
                    )
                )
            if provider_remaining < 0 or provider_reserve < 0:
                raise ValueError("PROVIDER_QUOTA_STATE_INVALID")
            if provider_remaining - units < provider_reserve:
                raise BudgetExceeded(
                    f"PROVIDER_EXTERNAL_RESERVE_EXCEEDED:{provider.value}"
                )
        return snapshot

    def record(
        self,
        *,
        idempotency_key: str,
        provider: ProviderKind,
        units: int,
        recorded_at: datetime,
        reason: str,
    ) -> bool:
        if not idempotency_key or not reason:
            raise ValueError("PROVIDER_BUDGET_PROVENANCE_REQUIRED")
        if recorded_at.tzinfo is None or recorded_at.utcoffset() is None:
            raise ValueError("PROVIDER_BUDGET_TIMESTAMP_UTC_REQUIRED")
        entry = BudgetEntry(
            idempotency_key=idempotency_key,
            provider=provider,
            units=units,
            recorded_at=recorded_at.astimezone(UTC),
            reason=reason,
        )
        existing = self._entries.get(idempotency_key)
        if existing is not None:
            if existing != entry:
                raise ValueError("PROVIDER_BUDGET_IDEMPOTENCY_CONFLICT")
            return False
        self.authorize(provider, units)
        self._entries[idempotency_key] = entry
        return True


class CircuitBreaker:
    def __init__(
        self,
        *,
        failure_threshold: int = 3,
        cooldown: timedelta = timedelta(minutes=15),
    ) -> None:
        if failure_threshold < 1 or cooldown <= timedelta(0):
            raise ValueError("CIRCUIT_BREAKER_POLICY_INVALID")
        self.failure_threshold = failure_threshold
        self.cooldown = cooldown
        self.consecutive_failures = 0
        self.opened_at: datetime | None = None
        self._half_open_probe_used = False

    def state(self, *, now: datetime) -> CircuitState:
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("CIRCUIT_BREAKER_TIMESTAMP_UTC_REQUIRED")
        if self.opened_at is None:
            return CircuitState.CLOSED
        if now.astimezone(UTC) < self.opened_at + self.cooldown:
            return CircuitState.OPEN
        return CircuitState.HALF_OPEN

    def allow(self, *, now: datetime) -> bool:
        state = self.state(now=now)
        if state is CircuitState.CLOSED:
            return True
        if state is CircuitState.OPEN:
            return False
        if self._half_open_probe_used:
            return False
        self._half_open_probe_used = True
        return True

    def record_success(self) -> None:
        self.consecutive_failures = 0
        self.opened_at = None
        self._half_open_probe_used = False

    def record_failure(self, *, now: datetime) -> None:
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("CIRCUIT_BREAKER_TIMESTAMP_UTC_REQUIRED")
        self.consecutive_failures += 1
        if self.consecutive_failures >= self.failure_threshold:
            self.opened_at = now.astimezone(UTC)
            self._half_open_probe_used = False
