"""Unit tests for the DNS module with canned mock responses."""

import pytest

from reconx.core.config import ScopeConfig, ScopeInScope, ScopeRules, Settings
from reconx.core.engine import ScanContext
from reconx.core.rate_limiter import AsyncRateLimiter
from reconx.core.request_manager import RequestManager
from reconx.core.scheduler import Task
from reconx.core.scope import ScopeEngine
from reconx.database.storage import apply_migrations, create_scan, get_db, upsert_asset
from reconx.modules.dns import DnsModule


class MockDnsRequestManager(RequestManager):
    """Subclass of RequestManager that returns canned DNS answers."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.canned: dict[tuple[str, str], list[str]] = {}

    def set_canned(self, qname: str, rdtype: str, answers: list[str]):
        self.canned[(qname, rdtype)] = answers

    async def dns_query(self, qname: str, rdtype: str = "A") -> list[str]:
        # Handle wildcard checks
        if "reconx-wc-" in qname:
            if "wildcard.example.com" in qname or "example.com" in qname:
                return ["1.2.3.4"] if "wildcard.example.com" in qname else []
            return []
        return self.canned.get((qname, rdtype), [])


@pytest.fixture
def dns_env(tmp_path):
    db = get_db(tmp_path / "dns.db")
    apply_migrations(db)
    scan_id = "RX-DNS-01"
    create_scan(db, scan_id, "dns-test", "cautious", 100)

    scope_cfg = ScopeConfig(
        program="dns-test",
        authorized_by="Self",
        in_scope=ScopeInScope(
            domains=["example.com", "*.example.com"],
            ips=["93.184.216.34"],
        ),
        rules=ScopeRules(),
    )
    scope = ScopeEngine(scope_cfg)
    settings = Settings()

    req_mgr = MockDnsRequestManager(
        scan_id=scan_id,
        scope_engine=scope,
        settings=settings,
        db=db,
        rate_limiter=AsyncRateLimiter(),
    )

    ctx = ScanContext(
        scan_id=scan_id,
        program="dns-test",
        settings=settings,
        scope=scope,
        requests=req_mgr,
        db=db,
    )
    return ctx, req_mgr


@pytest.mark.asyncio
async def test_dns_records_and_confidence_upgrade(dns_env):
    ctx, req_mgr = dns_env
    upsert_asset(ctx.db, ctx.program, "app.example.com", confidence="low")

    # Set canned records
    req_mgr.set_canned("app.example.com", "A", ["93.184.216.34"])
    req_mgr.set_canned("app.example.com", "AAAA", ["2606:2800:220:1:248:1893:25c8:1946"])
    req_mgr.set_canned("app.example.com", "TXT", ["v=spf1 include:_spf.example.com ~all"])
    req_mgr.set_canned("_dmarc.app.example.com", "TXT", ["v=DMARC1; p=reject;"])
    req_mgr.set_canned("app.example.com", "CAA", ["0 issue letsencrypt.org"])

    dns_mod = DnsModule()
    res = await dns_mod.run(ctx, Task(scan_id=ctx.scan_id, module="dns", target="app.example.com"))

    assert "A" in res.records
    assert res.records["A"] == ["93.184.216.34"]
    assert "AAAA" in res.records

    # Check asset confidence upgraded to high in database
    cursor = ctx.db.execute("SELECT confidence FROM assets WHERE hostname = 'app.example.com'")
    assert cursor.fetchone()[0] == "high"


@pytest.mark.asyncio
async def test_dns_wildcard_detection(dns_env):
    ctx, req_mgr = dns_env
    upsert_asset(ctx.db, ctx.program, "sub.wildcard.example.com", confidence="low")

    # App matches wildcard answer 1.2.3.4
    req_mgr.set_canned("sub.wildcard.example.com", "A", ["1.2.3.4"])

    dns_mod = DnsModule()
    res = await dns_mod.run(ctx, Task(scan_id=ctx.scan_id, module="dns", target="sub.wildcard.example.com"))

    assert res.is_wildcard is True
    # Held at low confidence
    cursor = ctx.db.execute("SELECT confidence FROM assets WHERE hostname = 'sub.wildcard.example.com'")
    assert cursor.fetchone()[0] == "low"


@pytest.mark.asyncio
async def test_dns_observations_spf_dmarc_cname(dns_env):
    ctx, req_mgr = dns_env
    upsert_asset(ctx.db, ctx.program, "mail.example.com", confidence="low")

    req_mgr.set_canned("mail.example.com", "CNAME", ["dangling.unregistered.service.net."])
    req_mgr.set_canned("dangling.unregistered.service.net", "A", [])  # NXDOMAIN
    req_mgr.set_canned("mail.example.com", "TXT", [])  # missing SPF
    req_mgr.set_canned("_dmarc.mail.example.com", "TXT", ["v=DMARC1; p=none;"])  # DMARC p=none

    dns_mod = DnsModule()
    res = await dns_mod.run(ctx, Task(scan_id=ctx.scan_id, module="dns", target="mail.example.com"))

    assert any("Dangling CNAME" in obs for obs in res.observations)
    assert any("Missing SPF" in obs for obs in res.observations)
    assert any("p=none" in obs for obs in res.observations)

    # Check findings table populated
    cursor = ctx.db.execute("SELECT COUNT(*) FROM findings WHERE scan_id = ?", (ctx.scan_id,))
    assert cursor.fetchone()[0] >= 3
