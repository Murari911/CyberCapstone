"""
app.py — Streamlit dashboard for the Network Traffic Analyzer.
Polls traffic.db and displays live stats, protocol breakdown,
connections, and suspicious activity alerts.
"""

import sqlite3
import time
import pandas as pd
import plotly.express as px
import streamlit as st

DB_PATH = "db/traffic.db"
REFRESH_SECONDS = 5

st.set_page_config(page_title="Network Traffic Analyzer", layout="wide")

st.markdown("""
<style>
    .block-container {
        padding-top: 2rem;
        padding-bottom: 2rem;
        max-width: 1200px;
    }
    h1, h2, h3 {
        font-weight: 600;
        letter-spacing: -0.02em;
    }
    [data-testid="stMetric"] {
        background: rgba(255, 255, 255, 0.03);
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 12px;
        padding: 16px 20px;
        transition: transform 0.15s ease, box-shadow 0.15s ease;
    }
    [data-testid="stMetric"]:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 16px rgba(37, 99, 235, 0.15);
        border-color: rgba(37, 99, 235, 0.4);
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 4px;
    }
    .stTabs [data-baseweb="tab"] {
        border-radius: 8px 8px 0 0;
        padding: 10px 18px;
        font-weight: 500;
    }
    .stButton button, .stDownloadButton button {
        border-radius: 8px;
        font-weight: 500;
        transition: all 0.15s ease;
        border: 1px solid rgba(37, 99, 235, 0.3);
    }
    .stButton button:hover, .stDownloadButton button:hover {
        border-color: #2563eb;
        box-shadow: 0 2px 8px rgba(37, 99, 235, 0.25);
    }
    [data-testid="stDataFrame"] {
        border-radius: 10px;
        overflow: hidden;
        border: 1px solid rgba(255, 255, 255, 0.08);
    }
    .stAlert {
        border-radius: 10px;
    }
    @media (max-width: 768px) {
        [data-testid="column"] {
            width: 100% !important;
            flex: 1 1 100% !important;
            min-width: 100% !important;
        }
    }
</style>
""", unsafe_allow_html=True)


def get_connection():
    return sqlite3.connect(DB_PATH, check_same_thread=False)


def load_recent_packets(conn, seconds=60):
    cutoff = time.time() - seconds
    return pd.read_sql_query(
        "SELECT * FROM packets WHERE timestamp >= ? ORDER BY timestamp DESC",
        conn, params=(cutoff,),
    )


def load_recent_stats(conn, limit=50):
    return pd.read_sql_query(
        "SELECT * FROM traffic_stats ORDER BY id DESC LIMIT ?",
        conn, params=(limit,),
    ).iloc[::-1]


def load_alerts(conn, limit=100):
    return pd.read_sql_query(
        "SELECT * FROM alerts ORDER BY id DESC LIMIT ?",
        conn, params=(limit,),
    )


def tab_overview(conn):
    stats_df = load_recent_stats(conn)
    packets_df = load_recent_packets(conn)

    # Compute live metrics directly from packets (last 10s), matching the charts below
    live_window = packets_df[packets_df["timestamp"] >= time.time() - 10]
    live_packet_count = len(live_window)
    live_bytes = int(live_window["length"].sum()) if not live_window.empty else 0
    live_connections = (
        live_window[["src_ip", "dst_ip"]].drop_duplicates().shape[0]
        if not live_window.empty else 0
    )

    col1, col2, col3 = st.columns(3)
    col1.metric("Packets (last 10s)", live_packet_count)
    col2.metric("Bytes (last 10s)", live_bytes)
    col3.metric("Active Connections (last 10s)", live_connections)

    if not stats_df.empty:
        stats_df["time"] = pd.to_datetime(stats_df["window_end"], unit="s")
        fig = px.line(stats_df, x="time", y="packet_count", title="Packets per Window", template="plotly_dark")
        st.plotly_chart(fig, use_container_width=True)

        fig2 = px.line(stats_df, x="time", y="total_bytes", title="Bandwidth (bytes per Window)", template="plotly_dark")
        st.plotly_chart(fig2, use_container_width=True)

    if not packets_df.empty:
        proto_counts = packets_df["protocol"].value_counts().reset_index()
        proto_counts.columns = ["protocol", "count"]
        fig3 = px.pie(proto_counts, names="protocol", values="count", title="Protocol Distribution (last 60s)", template="plotly_dark", hole=0.4)
        st.plotly_chart(fig3, use_container_width=True)
    else:
        st.info("No packets captured yet. Make sure sniffer.py is running.")


def tab_connections(conn):
    packets_df = load_recent_packets(conn)
    if packets_df.empty:
        st.info("No recent connections.")
        return

    conn_summary = (
        packets_df.groupby(["src_ip", "dst_ip"])
        .agg(packets=("id", "count"), bytes=("length", "sum"))
        .reset_index()
        .sort_values("packets", ascending=False)
    )
    st.subheader("Active Connections (last 60s)")
    st.dataframe(conn_summary, use_container_width=True)

    top_talkers = (
        packets_df.groupby("src_ip")
        .agg(packets=("id", "count"), bytes=("length", "sum"))
        .reset_index()
        .sort_values("bytes", ascending=False)
        .head(10)
    )
    st.subheader("Top Talkers")
    fig = px.bar(top_talkers, x="src_ip", y="bytes", title="Bytes Sent by Source IP", template="plotly_dark", color_discrete_sequence=["#2563eb"])
    st.plotly_chart(fig, use_container_width=True)


def tab_alerts(conn):
    alerts_df = load_alerts(conn)
    if alerts_df.empty:
        st.success("No suspicious activity detected.")
        return

    severity_filter = st.multiselect(
        "Filter by severity", options=["low", "medium", "high"],
        default=["low", "medium", "high"],
    )
    filtered = alerts_df[alerts_df["severity"].isin(severity_filter)]

    severity_icons = {"low": "🟢 low", "medium": "🟡 medium", "high": "🔴 high"}
    display_df = filtered.copy()
    display_df["severity"] = display_df["severity"].map(severity_icons).fillna(display_df["severity"])

    st.subheader(f"Suspicious Activity ({len(filtered)} alerts)")
    st.dataframe(display_df, use_container_width=True, hide_index=True)

    severity_counts = alerts_df["severity"].value_counts().reset_index()
    severity_counts.columns = ["severity", "count"]
    fig = px.bar(severity_counts, x="severity", y="count", title="Alerts by Severity", template="plotly_dark",
                 color="severity", color_discrete_map={"low": "#22c55e", "medium": "#f59e0b", "high": "#ef4444"})
    st.plotly_chart(fig, use_container_width=True)


def tab_reports(conn):
    st.subheader("Generate Reports")
    st.write("Export current traffic and alert data for the project report.")

    # Traffic summary CSV — direct in-browser download, works even when deployed
    stats_df = load_recent_stats(conn, limit=1000)
    st.download_button(
        "Download Traffic Summary (CSV)",
        data=stats_df.to_csv(index=False),
        file_name="traffic_summary.csv",
        mime="text/csv",
    )

    # Alerts log CSV
    alerts_df = load_alerts(conn, limit=1000)
    st.download_button(
        "Download Alerts Log (CSV)",
        data=alerts_df.to_csv(index=False),
        file_name="alerts_log.csv",
        mime="text/csv",
    )

    # Security report PDF — generate on click, then offer direct download
    if st.button("Generate Security Report (PDF)"):
        import sys
        sys.path.insert(0, "reports")
        from generate import fetch_summary, fetch_alerts, build_pdf

        window = 3600
        summary = fetch_summary(conn, window)
        alerts = fetch_alerts(conn, window)
        pdf_path = "reports/security_report.pdf"
        build_pdf(pdf_path, summary, alerts, window)

        with open(pdf_path, "rb") as f:
            pdf_bytes = f.read()

        st.success("Report generated.")
        st.download_button(
            "Download Security Report (PDF)",
            data=pdf_bytes,
            file_name="security_report.pdf",
            mime="application/pdf",
        )


def main():
    with st.sidebar:
        st.markdown("### System Status")
        conn_check = get_connection()
        try:
            recent = conn_check.execute(
                "SELECT COUNT(*) FROM packets WHERE timestamp >= ?", (time.time() - 15,)
            ).fetchone()[0]
            if recent > 0:
                st.success("Capture: Active")
            else:
                st.warning("Capture: No recent packets")
        except Exception:
            st.error("Capture: Unreachable")

        total_alerts = conn_check.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        st.metric("Total Alerts Logged", total_alerts)

        st.markdown("---")
        st.caption("Network Traffic Analyzer")
        st.caption("Scapy · SQLite · Streamlit")

    st.markdown("""
    <div style="margin-bottom: 0.5rem;">
        <h1 style="margin-bottom: 0;">🛡️ Network Traffic Analyzer</h1>
        <p style="color: #94a3b8; font-size: 0.95rem; margin-top: 4px;">
            Real-time packet capture, traffic monitoring, and threat detection
        </p>
    </div>
    """, unsafe_allow_html=True)
    conn = get_connection()

    tabs = st.tabs(["Overview", "Connections", "Alerts", "Reports"])
    with tabs[0]:
        tab_overview(conn)
    with tabs[1]:
        tab_connections(conn)
    with tabs[2]:
        tab_alerts(conn)
    with tabs[3]:
        tab_reports(conn)

    st.caption(f"Auto-refreshing every {REFRESH_SECONDS}s")
    time.sleep(REFRESH_SECONDS)
    st.rerun()


if __name__ == "__main__":
    main()
