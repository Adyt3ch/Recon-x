"""Self-contained HTML report generator for RECON-X assessments.

Enforces:
1. Strict Jinja2 autoescape enabled for all dynamic data (preventing XSS from hostile target titles/headers).
2. Zero external scripts, styles, or font fetches. 100% self-contained offline HTML.
"""

from __future__ import annotations

import sqlite3

from jinja2 import Environment, select_autoescape

from reconx.intelligence.correlation import calculate_leads
from reconx.reporting.json_report import generate_json_report

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RECON-X Assessment Report - {{ scan.id }}</title>
    <style>
        :root {
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --bg-tertiary: #334155;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --accent: #38bdf8;
            --border: #475569;
            --success: #22c55e;
            --warning: #eab308;
            --danger: #ef4444;
            --info: #0ea5e9;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 2rem;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        header {
            background-color: var(--bg-secondary);
            padding: 2rem;
            border-radius: 0.75rem;
            border: 1px solid var(--border);
            margin-bottom: 2rem;
        }
        h1 { color: var(--accent); font-size: 2rem; margin-bottom: 0.5rem; }
        .meta-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-top: 1.5rem;
        }
        .meta-card {
            background-color: var(--bg-tertiary);
            padding: 1rem;
            border-radius: 0.5rem;
        }
        .meta-label { font-size: 0.75rem; text-transform: uppercase; color: var(--text-secondary); }
        .meta-value { font-size: 1.25rem; font-weight: bold; margin-top: 0.25rem; }
        section {
            background-color: var(--bg-secondary);
            border-radius: 0.75rem;
            border: 1px solid var(--border);
            padding: 1.5rem;
            margin-bottom: 2rem;
        }
        h2 {
            font-size: 1.35rem;
            color: var(--accent);
            border-bottom: 1px solid var(--border);
            padding-bottom: 0.75rem;
            margin-bottom: 1rem;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9rem;
            margin-top: 0.5rem;
        }
        th, td {
            text-align: left;
            padding: 0.75rem 1rem;
            border-bottom: 1px solid var(--border);
        }
        th { background-color: var(--bg-tertiary); color: var(--text-secondary); font-weight: 600; }
        tr:hover { background-color: rgba(255, 255, 255, 0.02); }
        .badge {
            display: inline-block;
            padding: 0.2rem 0.6rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }
        .badge-verified { background-color: rgba(34, 197, 94, 0.2); color: var(--success); }
        .badge-high { background-color: rgba(14, 165, 233, 0.2); color: var(--info); }
        .badge-medium { background-color: rgba(234, 179, 8, 0.2); color: var(--warning); }
        .badge-low { background-color: rgba(148, 163, 184, 0.2); color: var(--text-secondary); }
        .badge-critical { background-color: rgba(239, 68, 68, 0.3); color: var(--danger); font-weight: bold; }
        .badge-danger { background-color: rgba(239, 68, 68, 0.2); color: var(--danger); }
        code {
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            background-color: var(--bg-tertiary);
            padding: 0.15rem 0.35rem;
            border-radius: 0.25rem;
            font-size: 0.85em;
        }
        .evidence-box {
            background-color: #0b0f19;
            border: 1px solid var(--border);
            padding: 1rem;
            border-radius: 0.5rem;
            font-family: ui-monospace, monospace;
            font-size: 0.8rem;
            white-space: pre-wrap;
            word-break: break-all;
            max-height: 250px;
            overflow-y: auto;
            color: #38bdf8;
        }
        footer {
            text-align: center;
            color: var(--text-secondary);
            font-size: 0.85rem;
            margin-top: 3rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>RECON-X Assessment Report</h1>
            <p style="color: var(--text-secondary);">Automated Security Reconnaissance & Intelligence Pipeline</p>
            <div class="meta-grid">
                <div class="meta-card">
                    <div class="meta-label">Scan ID</div>
                    <div class="meta-value">{{ scan.id }}</div>
                </div>
                <div class="meta-card">
                    <div class="meta-label">Program</div>
                    <div class="meta-value">{{ scan.program }}</div>
                </div>
                <div class="meta-card">
                    <div class="meta-label">Profile</div>
                    <div class="meta-value">{{ scan.profile }}</div>
                </div>
                <div class="meta-card">
                    <div class="meta-label">Requests Used</div>
                    <div class="meta-value">{{ scan.requests_used }} / {{ scan.request_budget }}</div>
                </div>
            </div>
        </header>

        {% if findings %}
        <section>
            <h2>Security Findings & Observations ({{ findings|length }})</h2>
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Target</th>
                        <th>Type</th>
                        <th>Title</th>
                        <th>Severity</th>
                        <th>Confidence</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    {% for f in findings %}
                    <tr>
                        <td><code>{{ f.id }}</code></td>
                        <td>{{ f.hostname or "N/A" }}</td>
                        <td>{{ f.type }}</td>
                        <td><strong>{{ f.title }}</strong></td>
                        <td><span class="badge badge-{{ f.severity_hint or 'low' }}">{{ f.severity_hint }}</span></td>
                        <td><span class="badge badge-{{ f.confidence }}">{{ f.confidence }}</span></td>
                        <td>{{ f.status }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </section>
        {% endif %}

        {% if leads %}
        <section>
            <h2>Top Prioritized Leads ({{ leads|length }})</h2>
            <table>
                <thead>
                    <tr>
                        <th>Target</th>
                        <th>Score</th>
                        <th>Suggested Test</th>
                        <th>Key Reasons</th>
                    </tr>
                </thead>
                <tbody>
                    {% for lead in leads %}
                    <tr>
                        <td><code>{{ lead.target }}</code></td>
                        <td><span class="badge badge-high">{{ lead.score }}</span></td>
                        <td>{{ lead.suggested_test }}</td>
                        <td>
                            <ul style="padding-left: 1rem;">
                            {% for r in lead.reasons[:3] %}
                                <li>{{ r }}</li>
                            {% endfor %}
                            </ul>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </section>
        {% endif %}

        <section>
            <h2>Live HTTP Services ({{ http_services|length }})</h2>
            {% if http_services %}
            <table>
                <thead>
                    <tr>
                        <th>URL</th>
                        <th>Status</th>
                        <th>Title</th>
                        <th>Server</th>
                        <th>CDN</th>
                    </tr>
                </thead>
                <tbody>
                    {% for h in http_services %}
                    <tr>
                        <td><a href="{{ h.url }}" style="color: var(--accent); text-decoration: none;" target="_blank">{{ h.url }}</a></td>
                        <td><span class="badge badge-{{ 'verified' if h.status_code == 200 else 'medium' }}">{{ h.status_code }}</span></td>
                        <td>{{ h.title or "(no title)" }}</td>
                        <td>{{ h.server or "-" }}</td>
                        <td>{{ "Yes" if h.is_cdn else "No" }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            {% else %}
            <p style="color: var(--text-secondary);">No active HTTP services discovered.</p>
            {% endif %}
        </section>

        <section>
            <h2>Discovered Assets ({{ assets|length }})</h2>
            <table>
                <thead>
                    <tr>
                        <th>Hostname</th>
                        <th>Confidence</th>
                        <th>Sources</th>
                        <th>First Seen</th>
                    </tr>
                </thead>
                <tbody>
                    {% for a in assets %}
                    <tr>
                        <td><code>{{ a.hostname }}</code></td>
                        <td><span class="badge badge-{{ a.confidence }}">{{ a.confidence }}</span></td>
                        <td>{{ a.sources|join(", ") }}</td>
                        <td>{{ a.first_seen[:19] }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </section>

        {% if technologies %}
        <section>
            <h2>Detected Technologies ({{ technologies|length }})</h2>
            <table>
                <thead>
                    <tr>
                        <th>Hostname</th>
                        <th>Technology</th>
                        <th>Version</th>
                        <th>Category</th>
                    </tr>
                </thead>
                <tbody>
                    {% for t in technologies %}
                    <tr>
                        <td><code>{{ t.hostname }}</code></td>
                        <td><strong>{{ t.name }}</strong></td>
                        <td>{{ t.version or "-" }}</td>
                        <td>{{ t.category or "-" }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </section>
        {% endif %}

        <footer>
            <p>Generated by <strong>RECON-X</strong> · Security Assessment Framework</p>
        </footer>
    </div>
</body>
</html>
"""


def generate_html_report(db: sqlite3.Connection, scan_id: str) -> str:
    """Generate offline, self-contained HTML assessment report with Jinja2 autoescape enabled."""
    data = generate_json_report(db, scan_id)
    leads = calculate_leads(db, scan_id)

    env = Environment(
        autoescape=select_autoescape(
            enabled_extensions=("html", "htm", "xml"),
            default_for_string=True,
        )
    )

    template = env.from_string(HTML_TEMPLATE)
    rendered = template.render(
        scan=data["scan"],
        assets=data["assets"],
        dns_records=data["dns_records"],
        http_services=data["http_services"],
        technologies=data.get("technologies", []),
        urls=data.get("urls", []),
        findings=data.get("findings", []),
        leads=leads[:15],
    )
    return rendered
