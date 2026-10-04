"""
rules.py — Threshold-based suspicious activity detection.
Reads recent packets from SQLite, checks them against config.yaml rules,
writes matches to the alerts table.
"""

import sqlite3
import time
import argparse
import ipaddress
import yaml

DB_PATH = "db/traffic.db"
CONFIG_PATH = "detector/config.yaml"


def load_config():
    with open(CONFIG_PATH) as f:
        return yaml.safe_load(f)


def get_connection():
    return sqlite3.connect(DB_PATH)


def save_alert(conn, alert_type, source_ip, details, severity):
    conn.execute(
        """INSERT INTO alerts (timestamp, alert_type, source_ip, details, severity)
           VALUES (?, ?, ?, ?, ?)""",
        (time.time(), alert_type, source_ip, details, severity),
    )
    conn.commit()
    print(f"[ALERT] {severity.upper()} | {alert_type} | {source_ip} | {details}")


def check_spike(conn, config):
    cfg = config["spike"]
    if not cfg["enabled"]:
        return
    window_start = time.time() - cfg["window_seconds"]
    cur = conn.execute(
        "SELECT COUNT(*) FROM packets WHERE timestamp >= ?", (window_start,)
    )
    count = cur.fetchone()[0]
    pps = count / cfg["window_seconds"]
    if pps > cfg["pps_threshold"]:
        save_alert(
            conn, "traffic_spike", None,
            f"{pps:.1f} packets/sec over last {cfg['window_seconds']}s "
            f"(threshold: {cfg['pps_threshold']})",
            "medium",
        )


def is_trusted(ip, trusted_ranges):
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in ipaddress.ip_network(r) for r in trusted_ranges)
    except ValueError:
        return False


def check_unknown_ip(conn, config):
    cfg = config["unknown_ip"]
    if not cfg["enabled"]:
        return
    window_start = time.time() - 10
    cur = conn.execute(
        "SELECT DISTINCT src_ip FROM packets WHERE timestamp >= ?", (window_start,)
    )
    for (ip,) in cur.fetchall():
        if not is_trusted(ip, cfg["trusted_ranges"]):
            save_alert(
                conn, "unknown_ip", ip,
                f"Traffic from non-private IP {ip}",
                "low",
            )


def check_repeated_attempts(conn, config):
    cfg = config["repeated_attempts"]
    if not cfg["enabled"]:
        return
    window_start = time.time() - cfg["window_seconds"]
    cur = conn.execute(
        """SELECT src_ip, dst_port, COUNT(*) as cnt
           FROM packets
           WHERE timestamp >= ? AND dst_port IS NOT NULL
           GROUP BY src_ip, dst_port
           HAVING cnt >= ?""",
        (window_start, cfg["attempt_threshold"]),
    )
    for src_ip, dst_port, cnt in cur.fetchall():
        save_alert(
            conn, "repeated_attempts", src_ip,
            f"{cnt} connection attempts to port {dst_port} "
            f"in {cfg['window_seconds']}s",
            "medium",
        )


def check_port_scan(conn, config):
    cfg = config["port_scan"]
    if not cfg["enabled"]:
        return
    window_start = time.time() - cfg["window_seconds"]
    cur = conn.execute(
        """SELECT src_ip, COUNT(DISTINCT dst_port) as distinct_ports
           FROM packets
           WHERE timestamp >= ? AND dst_port IS NOT NULL
           GROUP BY src_ip
           HAVING distinct_ports >= ?""",
        (window_start, cfg["distinct_port_threshold"]),
    )
    for src_ip, distinct_ports in cur.fetchall():
        save_alert(
            conn, "port_scan", src_ip,
            f"{distinct_ports} distinct ports contacted "
            f"in {cfg['window_seconds']}s",
            "high",
        )


def run_once(conn, config):
    check_spike(conn, config)
    check_unknown_ip(conn, config)
    check_repeated_attempts(conn, config)
    check_port_scan(conn, config)


def main():
    parser = argparse.ArgumentParser(description="Suspicious activity detector")
    parser.add_argument("--interval", type=int, default=5)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()

    config = load_config()
    conn = get_connection()

    try:
        if args.once:
            run_once(conn, config)
        else:
            print(f"[detector] Running every {args.interval}s (Ctrl+C to stop)")
            while True:
                run_once(conn, config)
                time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n[detector] Stopped.")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
