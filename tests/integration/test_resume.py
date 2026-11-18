"""Integration tests verifying scan task state, interrupt, resume, and dry-run."""

import httpx
import pytest

from reconx.core.config import (
    ScopeConfig,
    ScopeInScope,
    ScopeOutOfScope,
    ScopeRules,
    Settings,
)
from reconx.core.engine import ScanContext, ScanEngine
from reconx.core.rate_limiter import AsyncRateLimiter
from reconx.core.request_manager import RequestManager
from reconx.core.scheduler import Task, TaskScheduler
from reconx.core.scope import ScopeEngine
from reconx.database.storage import apply_migrations, create_scan, get_db, get_scan


class MockHttpModule:
    """Mock reconnaissance module that executes requests through ctx.requests."""
    name = "mock_http"

    def plan(self, ctx: ScanContext) -> list[Task]:
        return [
            Task(scan_id=ctx.scan_id, module=self.name, target=f"/item/{i}")
            for i in range(20)
        ]

    async def run(self, ctx: ScanContext, task: Task) -> list[dict]:
        url = f"http://127.0.0.1:8080{task.target}"
        resp = await ctx.requests.request("GET", url)
        return [{"status": resp.status_code, "target": task.target}]


@pytest.mark.integration
@pytest.mark.asyncio
async def test_scan_interrupt_and_resume(tmp_path):
    db = get_db(tmp_path / "resume.db")
    apply_migrations(db)

    scan_id = "RX-001"
    create_scan(db, scan_id, "test_resume", "cautious", 100)

    scope_cfg = ScopeConfig(
        program="test_resume",
        authorized_by="Self",
        in_scope=ScopeInScope(
            domains=["127.0.0.1"],
            ips=["127.0.0.1"],
            web_ports=[8080],
        ),
        out_of_scope=ScopeOutOfScope(),
        rules=ScopeRules(max_requests=100),
    )
    scope = ScopeEngine(scope_cfg)

    settings = Settings()
    settings.request_control.budget.max_requests = 100

    requests_sent = []

    def mock_handler(request: httpx.Request) -> httpx.Response:
        requests_sent.append(str(request.url))
        return httpx.Response(200, text="ok")

    transport = httpx.MockTransport(mock_handler)
    limiter = AsyncRateLimiter(
        requests_per_second=100.0,
        requests_per_minute=6000,
        min_delay=0.0,
        max_delay=0.0,
    )

    req_mgr = RequestManager(
        scan_id=scan_id,
        scope_engine=scope,
        settings=settings,
        db=db,
        rate_limiter=limiter,
        transport=transport,
    )

    ctx = ScanContext(
        scan_id=scan_id,
        program="test_resume",
        settings=settings,
        scope=scope,
        requests=req_mgr,
        db=db,
    )

    engine = ScanEngine([MockHttpModule()])
    tasks = engine.plan_scan(ctx)
    assert len(tasks) == 20

    # 1. Run first phase and simulate interrupt after 5 tasks
    status = await engine.run_scan(ctx, tasks=tasks, max_tasks=5)
    assert status == "stopped"

    # Verify exactly 5 requests sent and 5 tasks completed
    assert len(requests_sent) == 5
    stats = TaskScheduler.task_stats(db, scan_id)
    assert stats.get("completed", 0) == 5
    assert stats.get("pending", 0) == 15

    scan_row = get_scan(db, scan_id)
    assert scan_row["status"] == "stopped"
    assert scan_row["requests_used"] == 5

    # 2. Resume scan: should finish remaining 15 tasks without repeating first 5
    resume_status = await engine.resume_scan(scan_id=scan_id, ctx=ctx)
    assert resume_status == "completed"

    # Exactly 20 total requests sent across both phases
    assert len(requests_sent) == 20
    stats_after = TaskScheduler.task_stats(db, scan_id)
    assert stats_after.get("completed", 0) == 20
    assert stats_after.get("pending", 0) == 0

    scan_final = get_scan(db, scan_id)
    assert scan_final["status"] == "completed"
    assert scan_final["requests_used"] == 20


@pytest.mark.asyncio
async def test_dry_run_makes_zero_network_calls(tmp_path):
    db = get_db(tmp_path / "dryrun.db")
    apply_migrations(db)

    scan_id = "RX-002"
    create_scan(db, scan_id, "dry_prog", "cautious", 50)

    scope_cfg = ScopeConfig(
        program="dry_prog",
        authorized_by="Self",
        in_scope=ScopeInScope(domains=["127.0.0.1"]),
    )
    scope = ScopeEngine(scope_cfg)
    settings = Settings()

    network_called = False

    def explode_handler(request: httpx.Request) -> httpx.Response:
        nonlocal network_called
        network_called = True
        raise RuntimeError("Network call attempted during dry-run!")

    req_mgr = RequestManager(
        scan_id=scan_id,
        scope_engine=scope,
        settings=settings,
        db=db,
        rate_limiter=AsyncRateLimiter(),
        transport=httpx.MockTransport(explode_handler),
    )

    ctx = ScanContext(
        scan_id=scan_id,
        program="dry_prog",
        settings=settings,
        scope=scope,
        requests=req_mgr,
        db=db,
        dry_run=True,
    )

    engine = ScanEngine([MockHttpModule()])
    summary = engine.dry_run(ctx)

    assert summary["total_tasks"] == 20
    assert summary["estimated_requests"] == 20
    assert summary["tasks_by_module"]["mock_http"] == 20
    # Zero network calls were made
    assert network_called is False
