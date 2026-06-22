"""
Trend Analytics
Tracks vulnerability trends across scans over time.
Stores scan history in SQLite, provides statistics and visualizations.
"""

import json
import sqlite3
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict, Any
import logging

logger = logging.getLogger(__name__)


class TrendTracker:
    """
    Persistent trend analysis across multiple scans.

    Stores: scan results, findings counts per severity,
    top recurring CWEs, fix rates, and scanner performance.
    """

    def __init__(self, db_path: str = "./data/trends.db"):
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_path TEXT,
                    scan_timestamp TEXT,
                    total_findings INTEGER,
                    critical_count INTEGER,
                    high_count INTEGER,
                    medium_count INTEGER,
                    low_count INTEGER,
                    info_count INTEGER,
                    validated_patches INTEGER,
                    duration_seconds REAL,
                    scanner_results TEXT
                )""")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER,
                    rule_name TEXT,
                    severity TEXT,
                    cwe_id TEXT,
                    file_path TEXT,
                    patch_generated INTEGER,
                    patch_validated INTEGER,
                    FOREIGN KEY(scan_id) REFERENCES scans(id)
                )""")
            conn.commit()

    def record_scan(self, scan_result) -> int:
        """Save a scan result to the database. Returns scan_id."""
        stats = scan_result.statistics
        dist = stats.get("severity_distribution", {})

        with sqlite3.connect(self.db_path) as conn:
            cur = conn.execute("""
                INSERT INTO scans (target_path, scan_timestamp, total_findings,
                    critical_count, high_count, medium_count, low_count, info_count,
                    validated_patches, duration_seconds, scanner_results)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)""", (
                scan_result.target_path,
                scan_result.scan_timestamp,
                stats.get("total_findings", 0),
                dist.get("CRITICAL", 0), dist.get("HIGH", 0),
                dist.get("MEDIUM", 0), dist.get("LOW", 0), dist.get("INFO", 0),
                stats.get("validated_patches", 0),
                scan_result.duration_seconds,
                json.dumps(stats.get("raw_scanner_results", {}))
            ))
            scan_id = cur.lastrowid

            for f in scan_result.findings:
                conn.execute("""
                    INSERT INTO findings (scan_id, rule_name, severity, cwe_id,
                        file_path, patch_generated, patch_validated)
                    VALUES (?,?,?,?,?,?,?)""", (
                    scan_id, f.rule_name, f.severity, f.cwe_id or "",
                    f.file_path, 1 if f.ai_patch else 0, 1 if f.patch_validated else 0
                ))
            conn.commit()
        return scan_id

    def get_trend(self, days: int = 30) -> Dict[str, Any]:
        """Get vulnerability trend for the last N days."""
        since = (datetime.now() - timedelta(days=days)).isoformat()

        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute("""
                SELECT scan_timestamp, total_findings, critical_count,
                       high_count, medium_count, low_count, validated_patches
                FROM scans WHERE scan_timestamp >= ?
                ORDER BY scan_timestamp ASC""", (since,)).fetchall()

        if not rows:
            return {"period_days": days, "scans": 0, "trend": "no_data"}

        total_scans = len(rows)
        first = rows[0]
        last = rows[-1]

        trend_direction = "stable"
        if last[1] < first[1] * 0.8:
            trend_direction = "improving"
        elif last[1] > first[1] * 1.2:
            trend_direction = "worsening"

        return {
            "period_days": days,
            "scans": total_scans,
            "trend_direction": trend_direction,
            "avg_findings_per_scan": sum(r[1] for r in rows) / total_scans,
            "total_critical": sum(r[2] for r in rows),
            "total_high": sum(r[3] for r in rows),
            "patch_success_rate": sum(r[6] for r in rows) / max(sum(r[1] for r in rows), 1),
            "timeline": [
                {"timestamp": r[0], "total": r[1], "critical": r[2], "high": r[3]}
                for r in rows
            ]
        }

    def get_top_cwe(self, limit: int = 10) -> List[Dict]:
        """Get most frequently found CWEs."""
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute("""
                SELECT cwe_id, COUNT(*) as count, severity
                FROM findings WHERE cwe_id != ''
                GROUP BY cwe_id ORDER BY count DESC LIMIT ?""", (limit,)).fetchall()
        return [{"cwe_id": r[0], "count": r[1], "severity": r[2]} for r in rows]

    def get_fix_rate_by_severity(self) -> Dict[str, float]:
        """Calculate patch success rate per severity level."""
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute("""
                SELECT severity,
                    SUM(patch_generated) as generated,
                    SUM(patch_validated) as validated,
                    COUNT(*) as total
                FROM findings GROUP BY severity""").fetchall()
        return {
            r[0]: {
                "patch_rate": r[1] / max(r[3], 1),
                "validation_rate": r[2] / max(r[1], 1),
                "total": r[3]
            }
            for r in rows
        }

    def generate_plotly_chart(self) -> str:
        """Generate Plotly timeline chart as HTML."""
        try:
            import plotly.graph_objects as go
            trend = self.get_trend(days=90)
            timeline = trend.get("timeline", [])
            if not timeline:
                return "<p>No scan data available yet.</p>"

            dates = [t["timestamp"][:10] for t in timeline]
            totals = [t["total"] for t in timeline]
            criticals = [t["critical"] for t in timeline]

            fig = go.Figure()
            fig.add_trace(go.Scatter(x=dates, y=totals, name="Total", line=dict(color="#58a6ff")))
            fig.add_trace(go.Scatter(x=dates, y=criticals, name="Critical", line=dict(color="#f85149")))
            fig.update_layout(
                title="Vulnerability Trend (90 days)",
                template="plotly_dark",
                height=300
            )
            return fig.to_html(full_html=False, include_plotlyjs="cdn")
        except Exception as e:
            return f"<p>Chart error: {e}</p>"
