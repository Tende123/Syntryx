from pathlib import Path
from datetime import datetime
from jinja2 import Template
from rich.console import Console
from collections import Counter
import json

console = Console()

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Syntryx Scan Report</title>
    <style>
        :root {
            --bg: #0f172a;
            --card: #1e293b;
            --text: #e2e8f0;
            --accent: #38bdf8;
            --high: #ef4444;
            --medium: #f59e0b;
            --low: #22c55e;
            --info: #3b82f6;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
            padding: 30px 15px;
        }
        .container { max-width: 1100px; margin: 0 auto; }
        header {
            text-align: center;
            margin-bottom: 40px;
            padding-bottom: 20px;
            border-bottom: 1px solid #334155;
        }
        h1 {
            font-size: 2.5rem;
            color: var(--accent);
            margin-bottom: 8px;
        }
        .subtitle { color: #94a3b8; font-size: 1.1rem; }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-bottom: 40px;
        }
        .stat-card {
            background: var(--card);
            border-radius: 12px;
            padding: 20px;
            text-align: center;
            box-shadow: 0 4px 6px rgba(0,0,0,0.25);
        }
        .stat-card h3 { font-size: 2rem; margin-bottom: 4px; }
        .stat-card p { color: #94a3b8; font-size: 0.9rem; }
        .high { color: var(--high); }
        .medium { color: var(--medium); }
        .low { color: var(--low); }
        .info { color: var(--info); }
        .card {
            background: var(--card);
            border-radius: 12px;
            padding: 22px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.25);
            border-left: 6px solid #475569;
        }
        .card.high { border-left-color: var(--high); }
        .card.medium { border-left-color: var(--medium); }
        .card.low { border-left-color: var(--low); }
        .card.info { border-left-color: var(--info); }
        .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            margin-right: 10px;
        }
        .badge.high { background: var(--high); color: white; }
        .badge.medium { background: var(--medium); color: #000; }
        .badge.low { background: var(--low); color: #000; }
        .badge.info { background: var(--info); color: white; }
        .meta { color: #94a3b8; font-size: 0.9rem; margin: 8px 0 12px; }
        pre {
            background: #0f172a;
            padding: 14px;
            border-radius: 8px;
            overflow-x: auto;
            font-size: 0.85rem;
            margin-top: 12px;
            border: 1px solid #334155;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 12px;
            font-size: 0.9rem;
        }
        th, td {
            padding: 10px 12px;
            text-align: left;
            border-bottom: 1px solid #334155;
        }
        th { background: #334155; }
        footer {
            text-align: center;
            margin-top: 50px;
            color: #64748b;
            font-size: 0.9rem;
        }
    </style>
</head>
<body>
<div class="container">
    <header>
        <h1>Syntryx</h1>
        <p class="subtitle">Security Scan Report</p>
        <p style="margin-top:12px; color:#94a3b8;">
            Target: <strong style="color:#e2e8f0">{{ target }}</strong><br>
            Scan Date: {{ date }}
        </p>
    </header>

    <div class="summary">
        <div class="stat-card">
            <h3>{{ total }}</h3>
            <p>Total Findings</p>
        </div>
        <div class="stat-card">
            <h3 class="high">{{ high }}</h3>
            <p>High</p>
        </div>
        <div class="stat-card">
            <h3 class="medium">{{ medium }}</h3>
            <p>Medium</p>
        </div>
        <div class="stat-card">
            <h3 class="low">{{ low }}</h3>
            <p>Low</p>
        </div>
        <div class="stat-card">
            <h3 class="info">{{ info }}</h3>
            <p>Info</p>
        </div>
    </div>

    <h2 style="margin-bottom:20px; color:#94a3b8;">Findings</h2>

    {% for finding in findings %}
    <div class="card {{ finding.severity }}">
        <div>
            <span class="badge {{ finding.severity }}">{{ finding.severity }}</span>
            <strong style="font-size:1.15rem;">{{ finding.title }}</strong>
        </div>
        <div class="meta">
            Module: {{ finding.module }} &nbsp;•&nbsp; URL: {{ finding.url }}
        </div>
        <p>{{ finding.description }}</p>
        {% if finding.evidence %}
        <pre>{{ finding.evidence }}</pre>
        {% endif %}
    </div>
    {% else %}
    <div class="card info">
        <p>No security findings were detected in this scan.</p>
    </div>
    {% endfor %}

    <div class="card" style="margin-top:40px;">
        <h3 style="margin-bottom:12px;">Discovered URLs ({{ urls|length }})</h3>
        <table>
            <thead>
                <tr>
                    <th>URL</th>
                    <th>Status</th>
                    <th>Content-Type</th>
                </tr>
            </thead>
            <tbody>
                {% for u in urls %}
                <tr>
                    <td style="word-break:break-all;">{{ u.url }}</td>
                    <td>{{ u.status }}</td>
                    <td>{{ u.content_type }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>

    <footer>
        Generated by <strong>Syntryx</strong> — OWASP Top 10 Vulnerability Scanner
    </footer>
</div>
</body>
</html>
"""

class Reporter:
    def __init__(self, output_folder: str = "results"):
        self.output_folder = Path(output_folder)
        self.output_folder.mkdir(exist_ok=True)
        self.findings = []

    def add_finding(self, module: str, title: str, severity: str, url: str, description: str, evidence: str = ""):
        self.findings.append({
            "module": module,
            "title": title,
            "severity": severity.lower(),
            "url": url,
            "description": description,
            "evidence": evidence
        })

    def generate_report(self, target: str, urls: list):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        counts = Counter(f["severity"] for f in self.findings)

        # HTML Report
        html_path = self.output_folder / f"syntryx_report_{timestamp}.html"
        template = Template(HTML_TEMPLATE)
        html = template.render(
            target=target,
            date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            findings=self.findings,
            urls=urls,
            total=len(self.findings),
            high=counts.get("high", 0),
            medium=counts.get("medium", 0),
            low=counts.get("low", 0),
            info=counts.get("info", 0),
        )
        html_path.write_text(html, encoding="utf-8")

        # JSON Report
        json_path = self.output_folder / f"syntryx_report_{timestamp}.json"
        report_data = {
            "scanner": "Syntryx",
            "target": target,
            "scan_date": datetime.now().isoformat(),
            "summary": {
                "total": len(self.findings),
                "high": counts.get("high", 0),
                "medium": counts.get("medium", 0),
                "low": counts.get("low", 0),
                "info": counts.get("info", 0)
            },
            "findings": self.findings,
            "urls": urls
        }
        json_path.write_text(json.dumps(report_data, indent=2), encoding="utf-8")

        console.print(f"[bold green]HTML Report:[/bold green] {html_path}")
        console.print(f"[bold green]JSON Report:[/bold green] {json_path}")
        return str(html_path)
