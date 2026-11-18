"""Unit tests for the rate limiter with fake clock injection."""

import pytest

from reconx.core.rate_limiter import AsyncRateLimiter, FakeClock


@pytest.mark.asyncio
async def test_rate_limiter_100_acquisitions():
    clock = FakeClock()
    # 1 req/sec, per-minute cap 300, 0 delay for pure rate test
    limiter = AsyncRateLimiter(
        requests_per_second=1.0,
        requests_per_minute=300,
        min_delay=0.0,
        max_delay=0.0,
        clock=clock.now,
        sleep_func=clock.sleep,
    )

    for _ in range(100):
        await limiter.acquire("example.com")

    # 100 acquisitions at 1 rps starting at t=0 should take at least 99 simulated seconds
    assert clock.current_time >= 99.0


@pytest.mark.asyncio
async def test_rate_limiter_no_one_second_window_exceeds_limit():
    clock = FakeClock()
    rps = 2.0
    limiter = AsyncRateLimiter(
        requests_per_second=rps,
        requests_per_minute=600,
        min_delay=0.0,
        max_delay=0.0,
        clock=clock.now,
        sleep_func=clock.sleep,
    )

    timestamps = []
    for _ in range(50):
        await limiter.acquire("example.com")
        timestamps.append(clock.now())

    # Verify no 1.0 second sliding window has more than 2 requests (+ floating precision)
    for i, t in enumerate(timestamps):
        window_count = sum(1 for other in timestamps if t <= other < t + 1.0 - 1e-9)
        assert window_count <= int(rps)


@pytest.mark.asyncio
async def test_rate_limiter_per_minute_cap():
    clock = FakeClock()
    # 5 rps, but 30 rpm cap
    limiter = AsyncRateLimiter(
        requests_per_second=5.0,
        requests_per_minute=30,
        min_delay=0.0,
        max_delay=0.0,
        clock=clock.now,
        sleep_func=clock.sleep,
    )

    # Acquire 30 requests
    for _ in range(30):
        await limiter.acquire("example.com")

    # The 31st request must wait until the 60s window slides
    await limiter.acquire("example.com")
    assert clock.current_time >= 60.0


@pytest.mark.asyncio
async def test_rate_limiter_per_host_independent_and_global_bound():
    clock = FakeClock()
    # Global 2 rps, per-host 1 rps
    limiter = AsyncRateLimiter(
        requests_per_second=2.0,
        requests_per_minute=120,
        per_host_rps=1.0,
        per_host_rpm=60,
        min_delay=0.0,
        max_delay=0.0,
        clock=clock.now,
        sleep_func=clock.sleep,
    )

    # Alternating requests to host-a and host-b
    # Both can proceed concurrently up to global limit (2 rps)
    for _ in range(10):
        await limiter.acquire("host-a.com")
        await limiter.acquire("host-b.com")

    # 20 requests at global 2 rps takes at least 9.5s
    assert clock.current_time >= 9.5


@pytest.mark.asyncio
async def test_rate_limiter_delays_bounded():
    clock = FakeClock()
    limiter = AsyncRateLimiter(
        requests_per_second=100.0,
        requests_per_minute=6000,
        min_delay=1.0,
        max_delay=2.0,
        rng_func=lambda a, b: 1.5,  # Fixed injected RNG
        clock=clock.now,
        sleep_func=clock.sleep,
    )

    t0 = clock.now()
    await limiter.acquire("example.com")
    # First request applies jitter delay
    t1 = clock.now()
    assert (t1 - t0) == 1.5


@pytest.mark.asyncio
async def test_rate_limiter_simulation_gate():
    """Gate test: Across 1,000 simulated acquisitions, max requests in any 1-second window <= limit."""
    clock = FakeClock()
    rps = 5.0
    limiter = AsyncRateLimiter(
        requests_per_second=rps,
        requests_per_minute=10000,
        min_delay=0.0,
        max_delay=0.0,
        clock=clock.now,
        sleep_func=clock.sleep,
    )

    timestamps = []
    for _ in range(1000):
        await limiter.acquire("example.com")
        timestamps.append(clock.now())

    # Sample windows
    for i in range(0, len(timestamps) - 10, 10):
        t_start = timestamps[i]
        in_window = sum(1 for t in timestamps if t_start <= t < t_start + 1.0 - 1e-9)
        assert in_window <= int(rps)
