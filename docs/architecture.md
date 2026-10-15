# Architecture

## Overview

The system is split into independent, loosely-coupled components that communicate only through a shared SQLite database. This keeps capture (which needs root) separate from analysis and presentation (which don't), and lets each piece be tested, restarted, or demoed on its own.

## Data Flow

1. capture/sniffer.py captures live packets on the network interface using Scapy, parses each into (timestamp, src_ip, dst_ip, protocol, src_port, dst_port, length), batches them, and writes to the packets table in SQLite.

2. monitor/stats.py runs on a loop, reading recent rows from packets and computing per-window bandwidth, active connection count, and protocol distribution. Writes a summary row to traffic_stats.

3. detector/rules.py runs on a loop, reading recent packets and checking them against four threshold-based rules defined in config.yaml. Matches are written to the alerts table.

4. dashboard/app.py (Streamlit) polls the database every few seconds and renders four tabs: Overview, Connections, Alerts, Reports.

5. reports/generate.py reads traffic_stats and alerts and produces a formatted PDF, or the dashboard exports CSVs directly.

## Database Schema

Table: packets
- id, timestamp, src_ip, dst_ip, protocol, src_port, dst_port, length

Table: traffic_stats
- id, window_start, window_end, total_bytes, packet_count, active_connections, top_protocol

Table: alerts
- id, timestamp, alert_type, source_ip, details, severity

Table: known_devices
- ip, label, first_seen

Indexes on packets(timestamp) and packets(src_ip) for fast windowed queries.

## Detection Logic

Four rules, all configurable via detector/config.yaml:

1. Traffic spike: packets/sec in a window exceeds pps_threshold
2. Unknown IP: source or destination IP is not in a trusted/private range
3. Repeated connection attempts: same source IP hits the same destination port N+ times within a window
4. Port scan: same source IP contacts N+ distinct destination ports within a window

Each rule reads directly from the packets table and writes matches to alerts with a severity level (low/medium/high). Rules are independent functions, so each can be tested, disabled, or tuned separately.

## Design Decisions

- Capture and dashboard are decoupled via SQLite rather than one combined live-updating script. This means the dashboard can be restarted without losing capture, and capture doesn't need to run with Streamlit's permissions.
- Detection thresholds are configurable rather than hardcoded so they can be tuned without code changes, and so the choice of threshold can be explained and justified.
- The detector does not exclude the host's own IP from checks, so detection reacts to traffic patterns rather than assumptions about which source is "safe."
- All testing traffic is self-generated (ping, curl, nmap against an authorized test target) to stay within the project's scope limitation of no unauthorized network access.

## Technology Stack

- Python 3.13
- Scapy -- packet capture and parsing
- SQLite -- storage
- Pandas -- data aggregation in the dashboard
- Plotly -- charts
- Streamlit -- dashboard UI
- ReportLab -- PDF report generation
- PyYAML -- configuration
- pytest -- automated testing

