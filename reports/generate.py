"""
generate.py — Produces a PDF security/traffic report from traffic.db.
Can be run standalone or called from the dashboard.
"""

import sqlite3
import time
import argparse
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

DB_PATH = "db/traffic.db"


def get_connection():
    return sqlite3.connect(DB_PATH)


def fetch_summary(conn, window_seconds):
    cutoff = time.time() - window_seconds
    cur = conn.execute(
        "SELECT COUNT(*), COALESCE(SUM(length),0) FROM packets WHERE timestamp >= ?",
        (cutoff,),
    )
    total_packets, total_bytes = cur.fetchone()

    cur = conn.execute(
        """SELECT protocol, COUNT(*) FROM packets WHERE timestamp >= ?
           GROUP BY protocol ORDER BY COUNT(*) DESC""",
        (cutoff,),
    )
    protocol_breakdown = cur.fetchall()

    cur = conn.execute(
        """SELECT COUNT(DISTINCT src_ip || '-' || dst_ip)
           FROM packets WHERE timestamp >= ?""",
        (cutoff,),
    )
    unique_connections = cur.fetchone()[0]

    return {
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "unique_connections": unique_connections,
        "protocol_breakdown": protocol_breakdown,
    }


def fetch_alerts(conn, window_seconds):
    cutoff = time.time() - window_seconds
    cur = conn.execute(
        """SELECT timestamp, alert_type, source_ip, details, severity
           FROM alerts WHERE timestamp >= ? ORDER BY timestamp DESC""",
        (cutoff,),
    )
    return cur.fetchall()


def build_pdf(output_path, summary, alerts, window_seconds):
    doc = SimpleDocTemplate(output_path, pagesize=A4,
                             topMargin=20*mm, bottomMargin=20*mm)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("TitleCustom", parent=styles["Title"], fontSize=18)
    heading_style = styles["Heading2"]
    normal_style = styles["Normal"]

    elements = []

    elements.append(Paragraph("Network Traffic Analyzer — Security Report", title_style))
    elements.append(Paragraph(
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | "
        f"Window: last {window_seconds} seconds", normal_style
    ))
    elements.append(Spacer(1, 10*mm))

    # Traffic Summary
    elements.append(Paragraph("Traffic Summary", heading_style))
    summary_data = [
        ["Metric", "Value"],
        ["Total Packets", str(summary["total_packets"])],
        ["Total Bytes", str(summary["total_bytes"])],
        ["Unique Connections", str(summary["unique_connections"])],
    ]
    summary_table = Table(summary_data, colWidths=[80*mm, 80*mm])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 8*mm))

    # Protocol Breakdown
    elements.append(Paragraph("Protocol Breakdown", heading_style))
    proto_data = [["Protocol", "Packet Count"]] + [
        [p, str(c)] for p, c in summary["protocol_breakdown"]
    ]
    proto_table = Table(proto_data, colWidths=[80*mm, 80*mm])
    proto_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    elements.append(proto_table)
    elements.append(Spacer(1, 8*mm))

    # Suspicious Activity Log
    elements.append(Paragraph("Suspicious Activity Log", heading_style))
    if alerts:
        severity_colors = {
            "low": colors.HexColor("#27ae60"),
            "medium": colors.HexColor("#f39c12"),
            "high": colors.HexColor("#c0392b"),
        }
        alert_data = [["Time", "Type", "Source IP", "Details", "Severity"]]
        for ts, atype, src, details, sev in alerts:
            time_str = datetime.fromtimestamp(ts).strftime("%H:%M:%S")
            alert_data.append([time_str, atype, src or "-", details, sev])

        alert_table = Table(alert_data, colWidths=[20*mm, 28*mm, 28*mm, 70*mm, 18*mm])
        style_cmds = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]
        for i, (_, _, _, _, sev) in enumerate(alerts, start=1):
            style_cmds.append(("TEXTCOLOR", (4, i), (4, i), severity_colors.get(sev, colors.black)))
        alert_table.setStyle(TableStyle(style_cmds))
        elements.append(alert_table)
    else:
        elements.append(Paragraph("No suspicious activity detected in this window.", normal_style))

    doc.build(elements)


def main():
    parser = argparse.ArgumentParser(description="Generate PDF security report")
    parser.add_argument("--window", type=int, default=3600,
                         help="Time window in seconds to include (default: last hour)")
    parser.add_argument("--output", default="reports/security_report.pdf")
    args = parser.parse_args()

    conn = get_connection()
    summary = fetch_summary(conn, args.window)
    alerts = fetch_alerts(conn, args.window)
    conn.close()

    build_pdf(args.output, summary, alerts, args.window)
    print(f"[report] PDF saved to {args.output}")


if __name__ == "__main__":
    main()
