"""Task queue management, scheduling, and dry-run execution planning."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from reconx.database.storage import utc_now_iso


@dataclass
class Task:
    """Represents a scheduled unit of reconnaissance work."""
    scan_id: str
    module: str
    target: str
    id: int | None = None
    status: str = "pending"
    attempts: int = 0
    estimated_requests: int = 1


class TaskScheduler:
    """Manages the database-backed task queue for durable pause and resume."""

    @staticmethod
    def enqueue_tasks(db: sqlite3.Connection, tasks: list[Task]) -> None:
        """Add a list of planned tasks to the scan_tasks table."""
        now = utc_now_iso()
        with db:
            for task in tasks:
                cursor = db.execute(
                    """
                    INSERT INTO scan_tasks (
                        scan_id, module, target, status, attempts, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        task.scan_id,
                        task.module,
                        task.target,
                        task.status,
                        task.attempts,
                        now,
                        now,
                    ),
                )
                task.id = cursor.lastrowid

    @staticmethod
    def get_pending_tasks(db: sqlite3.Connection, scan_id: str) -> list[Task]:
        """Fetch all incomplete tasks for a scan (pending, running, failed)."""
        cursor = db.execute(
            """
            SELECT id, scan_id, module, target, status, attempts
            FROM scan_tasks
            WHERE scan_id = ? AND status != 'completed' AND status != 'skipped'
            ORDER BY id ASC
            """,
            (scan_id,),
        )
        tasks = []
        for row in cursor.fetchall():
            tasks.append(
                Task(
                    id=row["id"],
                    scan_id=row["scan_id"],
                    module=row["module"],
                    target=row["target"],
                    status=row["status"],
                    attempts=row["attempts"],
                )
            )
        return tasks

    @staticmethod
    def mark_task(db: sqlite3.Connection, task_id: int, status: str) -> None:
        """Update a task's status and timestamp."""
        now = utc_now_iso()
        with db:
            db.execute(
                """
                UPDATE scan_tasks
                SET status = ?, attempts = attempts + 1, updated_at = ?
                WHERE id = ?
                """,
                (status, now, task_id),
            )

    @staticmethod
    def task_stats(db: sqlite3.Connection, scan_id: str) -> dict[str, int]:
        """Return counts of tasks grouped by status."""
        cursor = db.execute(
            """
            SELECT status, COUNT(*) as cnt
            FROM scan_tasks
            WHERE scan_id = ?
            GROUP BY status
            """,
            (scan_id,),
        )
        return {row["status"]: row["cnt"] for row in cursor.fetchall()}
