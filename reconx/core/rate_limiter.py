"""Async token bucket and sliding window rate limiter with injectable clock."""

from __future__ import annotations

import asyncio
import random
import time
from collections import deque
from collections.abc import Callable, Coroutine
from typing import Any


class FakeClock:
    """Simulated clock for high-speed, deterministic asynchronous tests."""

    def __init__(self, start_time: float = 0.0):
        self.current_time = start_time

    def now(self) -> float:
        return self.current_time

    async def sleep(self, seconds: float) -> None:
        if seconds > 0:
            self.current_time += seconds


class TokenBucket:
    """Token bucket algorithm implementation for rate control."""

    def __init__(
        self,
        rate_per_sec: float,
        capacity: float | None = None,
        clock: Callable[[], float] | None = None,
        sleep_func: Callable[[float], Coroutine[Any, Any, None]] | None = None,
    ):
        self.rate_per_sec = rate_per_sec
        # Default capacity to 1.0 so bursts don't violate windows
        self.capacity = capacity if capacity is not None else 1.0
        self.tokens = self.capacity
        self.clock = clock or time.monotonic
        self.sleep_func = sleep_func or asyncio.sleep
        self.last_update = self.clock()

    async def acquire(self, tokens_needed: float = 1.0) -> None:
        while True:
            now = self.clock()
            elapsed = now - self.last_update
            self.last_update = now

            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate_per_sec)

            if self.tokens >= tokens_needed - 1e-9:
                self.tokens = max(0.0, self.tokens - tokens_needed)
                return

            needed = tokens_needed - self.tokens
            wait_time = max(0.0, needed / self.rate_per_sec)
            await self.sleep_func(wait_time)


class SlidingWindowLimiter:
    """Sliding window log limiter to enforce per-minute or window caps."""

    def __init__(
        self,
        limit: int,
        window_seconds: float = 60.0,
        clock: Callable[[], float] | None = None,
        sleep_func: Callable[[float], Coroutine[Any, Any, None]] | None = None,
    ):
        self.limit = limit
        self.window_seconds = window_seconds
        self.clock = clock or time.monotonic
        self.sleep_func = sleep_func or asyncio.sleep
        self.history: deque[float] = deque()

    async def acquire(self) -> None:
        while True:
            now = self.clock()
            cutoff = now - self.window_seconds + 1e-9

            while self.history and self.history[0] <= cutoff:
                self.history.popleft()

            if len(self.history) < self.limit:
                self.history.append(now)
                return

            oldest = self.history[0]
            wait_time = (oldest + self.window_seconds) - now
            if wait_time > 1e-9:
                await self.sleep_func(wait_time)
            else:
                self.history.popleft()


class AsyncRateLimiter:
    """Central async rate limiter combining global limits, per-host limits,

    sliding minute windows, and jitter delays.
    """

    def __init__(
        self,
        requests_per_second: float = 1.0,
        requests_per_minute: int = 30,
        per_host_rps: float | None = None,
        per_host_rpm: int | None = None,
        min_delay: float = 1.0,
        max_delay: float = 2.0,
        clock: Callable[[], float] | None = None,
        sleep_func: Callable[[float], Coroutine[Any, Any, None]] | None = None,
        rng_func: Callable[[float, float], float] | None = None,
    ):
        self.clock = clock or time.monotonic
        self.sleep_func = sleep_func or asyncio.sleep
        self.rng_func = rng_func or random.uniform

        self.min_delay = min_delay
        self.max_delay = max_delay

        # Global rate limits
        self.global_rps = requests_per_second
        self.global_bucket = TokenBucket(
            rate_per_sec=requests_per_second,
            capacity=1.0,
            clock=self.clock,
            sleep_func=self.sleep_func,
        )
        self.global_window = SlidingWindowLimiter(
            limit=requests_per_minute,
            window_seconds=60.0,
            clock=self.clock,
            sleep_func=self.sleep_func,
        )

        # Per-host rate limits
        self.per_host_rps = per_host_rps or requests_per_second
        self.per_host_rpm = per_host_rpm or requests_per_minute
        self.host_buckets: dict[str, TokenBucket] = {}
        self.host_windows: dict[str, SlidingWindowLimiter] = {}

    def _get_host_limiters(self, host: str) -> tuple[TokenBucket, SlidingWindowLimiter]:
        host_key = host.lower().strip()
        if host_key not in self.host_buckets:
            self.host_buckets[host_key] = TokenBucket(
                rate_per_sec=self.per_host_rps,
                capacity=1.0,
                clock=self.clock,
                sleep_func=self.sleep_func,
            )
        if host_key not in self.host_windows:
            self.host_windows[host_key] = SlidingWindowLimiter(
                limit=self.per_host_rpm,
                window_seconds=60.0,
                clock=self.clock,
                sleep_func=self.sleep_func,
            )
        return self.host_buckets[host_key], self.host_windows[host_key]

    async def acquire(self, host: str) -> None:
        """Wait until global and per-host limits allow the request, and apply jitter delay."""
        # 1. Apply configured random delay if any
        if self.max_delay > 0:
            delay = self.rng_func(self.min_delay, self.max_delay)
            if delay > 0:
                await self.sleep_func(delay)

        # 2. Acquire per-host limiters
        host_bucket, host_window = self._get_host_limiters(host)
        await host_window.acquire()
        await host_bucket.acquire()

        # 3. Acquire global limiters
        await self.global_window.acquire()
        await self.global_bucket.acquire()
