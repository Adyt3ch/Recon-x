"""Core execution engine orchestrating modules, task queues, interrupts, and resume."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from typing import Any, Protocol

from reconx.core.config import Settings
from reconx.core.request_manager import (
    BudgetExceeded,
    RequestManager,
    ScanPaused,
    ScopeDenied,
)
from reconx.core.scheduler import Task, TaskScheduler
from reconx.core.scope import ScopeEngine
from reconx.database.storage import (
    get_scan,
    insert_scan_event,
    update_scan_status,
    utc_now_iso,
)


@dataclass
class ScanContext:
    """Runtime context passed to all modules and tasks."""
    scan_id: str
    program: str
    settings: Settings
    scope: ScopeEngine
    requests: RequestManager
    db: sqlite3.Connection
    dry_run: bool = False
    is_interrupted: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


class Module(Protocol):
    """Protocol that every reconnaissance module must implement."""
    name: str

    def plan(self, ctx: ScanContext) -> list[Task]:
        """Return planned tasks with estimated request counts for dry-run."""
        ...

    async def run(self, ctx: ScanContext, task: Task) -> list[Any]:
        """Execute task work using ctx.requests. Never open raw sockets."""
        ...


class DryRunTransportError(Exception):
    """Raised if an active network call is attempted during --dry-run."""
    pass


class ScanEngine:
    """Orchestrates scan execution, task scheduling, resume, and graceful interrupt handling."""

    def __init__(self, modules: list[Module] | None = None):
        self.modules: dict[str, Module] = {}
        if modules:
            for m in modules:
                self.register_module(m)

    def register_module(self, module: Module) -> None:
        self.modules[module.name] = module

    def plan_scan(self, ctx: ScanContext) -> list[Task]:
        """Gather all planned tasks from registered modules."""
        all_tasks: list[Task] = []
        for mod in self.modules.values():
            planned = mod.plan(ctx)
            all_tasks.extend(planned)
        return all_tasks

    def dry_run(self, ctx: ScanContext) -> dict[str, Any]:
        """Simulate scan planning, returning task counts and estimated requests."""
        ctx.dry_run = True
        planned_tasks = self.plan_scan(ctx)
        total_estimated_requests = sum(t.estimated_requests for t in planned_tasks)

        summary = {
            "scan_id": ctx.scan_id,
            "program": ctx.program,
            "total_tasks": len(planned_tasks),
            "estimated_requests": total_estimated_requests,
            "budget": ctx.settings.request_control.budget.max_requests,
            "tasks_by_module": {},
        }
        for t in planned_tasks:
            summary["tasks_by_module"][t.module] = (
                summary["tasks_by_module"].get(t.module, 0) + 1
            )
        return summary

    async def run_scan(
        self,
        ctx: ScanContext,
        tasks: list[Task] | None = None,
        max_tasks: int | None = None,
    ) -> str:
        """Run tasks sequentially, committing progress and supporting graceful stop/pause."""
        db = ctx.db
        scan_id = ctx.scan_id

        # 1. Ensure tasks are enqueued if not already present
        if tasks:
            TaskScheduler.enqueue_tasks(db, tasks)

        # 2. Update scan status to running
        update_scan_status(db, scan_id, status="running")
        insert_scan_event(db, scan_id, "INFO", "Scan started")

        pending_tasks = TaskScheduler.get_pending_tasks(db, scan_id)
        executed_count = 0

        final_status = "completed"

        for task in pending_tasks:
            # Check interrupt
            if ctx.is_interrupted:
                final_status = "stopped"
                insert_scan_event(db, scan_id, "WARN", "Scan interrupted by user")
                break

            if max_tasks is not None and executed_count >= max_tasks:
                final_status = "stopped"
                break

            mod = self.modules.get(task.module)
            if not mod:
                TaskScheduler.mark_task(db, task.id, status="failed")
                continue

            TaskScheduler.mark_task(db, task.id, status="running")

            try:
                await mod.run(ctx, task)
                TaskScheduler.mark_task(db, task.id, status="completed")
                executed_count += 1
            except BudgetExceeded as e:
                TaskScheduler.mark_task(db, task.id, status="pending")
                final_status = "paused"
                insert_scan_event(db, scan_id, "WARN", f"Budget exceeded: {e}")
                break
            except ScanPaused as e:
                TaskScheduler.mark_task(db, task.id, status="pending")
                final_status = "paused"
                insert_scan_event(db, scan_id, "WARN", f"Scan paused: {e}")
                break
            except ScopeDenied:
                TaskScheduler.mark_task(db, task.id, status="skipped")
            except Exception as e:
                TaskScheduler.mark_task(db, task.id, status="failed")
                insert_scan_event(db, scan_id, "ERROR", f"Task error on {task.target}: {e}")

            # Keep scans.requests_used synchronized in DB
            update_scan_status(
                db,
                scan_id,
                status="running",
                requests_used=ctx.requests.requests_used,
            )

        # Update final scan state
        finished_at = utc_now_iso() if final_status in ("completed", "stopped") else None
        update_scan_status(
            db,
            scan_id,
            status=final_status,
            requests_used=ctx.requests.requests_used,
            finished_at=finished_at,
        )
        insert_scan_event(db, scan_id, "INFO", f"Scan finished with status: {final_status}")
        return final_status

    async def resume_scan(
        self,
        scan_id: str,
        ctx: ScanContext,
    ) -> str:
        """Resume an interrupted or paused scan, preserving request budget used."""
        db = ctx.db
        scan_data = get_scan(db, scan_id)
        if not scan_data:
            raise ValueError(f"Scan {scan_id} does not exist in database")

        # Sync used request count
        ctx.requests.requests_used = scan_data["requests_used"]
        insert_scan_event(db, scan_id, "INFO", "Scan resumed")

        # Run remaining pending tasks
        return await self.run_scan(ctx, tasks=None)
