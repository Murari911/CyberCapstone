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
        fig = px.line(stats_df, x="time", y="packet_count", title="Packets per Window")
        st.plotly_chart(fig, use_container_width=True)

        fig2 = px.line(stats_df, x="time", y="total_bytes", title="Bandwidth (bytes per Window)")
        st.plotly_chart(fig2, use_container_width=True)

    if not packets_df.empty:
        proto_counts = packets_df["protocol"].value_counts().reset_index()
        proto_counts.columns = ["protocol", "count"]
        fig3 = px.pie(proto_counts, names="protocol", values="count", title="Protocol Distribution (last 60s)")
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
    fig = px.bar(top_talkers, x="src_ip", y="bytes", title="Bytes Sent by Source IP")
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

    st.subheader(f"Suspicious Activity ({len(filtered)} alerts)")
    st.dataframe(filtered, use_container_width=True)

    severity_counts = alerts_df["severity"].value_counts().reset_index()
    severity_counts.columns = ["severity", "count"]
    fig = px.bar(severity_counts, x="severity", y="count", title="Alerts by Severity",
                 color="severity", color_discrete_map={"low": "green", "medium": "orange", "high": "red"})
    st.plotly_chart(fig, use_container_width=True)


def tab_reports(conn):
    st.subheader("Generate Reports")
    st.write("Export current traffic and alert data for the project report.")

    if st.button("Export Traffic Summary (CSV)"):
        df = load_recent_stats(conn, limit=1000)
        df.to_csv("reports/traffic_summary.csv", index=False)
        st.success("Saved to reports/traffic_summary.csv")

    if st.button("Export Alerts Log (CSV)"):
        df = load_alerts(conn, limit=1000)
        df.to_csv("reports/alerts_log.csv", index=False)
        st.success("Saved to reports/alerts_log.csv")


def main():
    st.title("🛡️ Network Traffic Analyzer")
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
