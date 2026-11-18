"""Data models for database entities in RECON-X."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ScanModel:
    id: str
    program: str
    profile: str
    status: str
    started_at: str
    request_budget: int
    requests_used: int = 0
    config_snapshot: str = ""
    scope_snapshot: str = ""
    finished_at: str | None = None


@dataclass
class AssetModel:
    id: int | None
    program: str
    hostname: str
    confidence: str
    first_seen: str
    last_seen: str


@dataclass
class RequestLogModel:
    id: int | None
    scan_id: str
    ts: str
    method: str
    url: str
    host: str
    status: int | None
    bytes: int | None
    duration_ms: int | None
    scope_decision: str
    prev_hash: str | None
    row_hash: str
