"""
stats.py — Aggregates recent packets into traffic_stats summaries.
Run independently of sniffer.py; polls the packets table on a loop.
"""

import sqlite3
import time
import argparse

DB_PATH = "db/traffic.db"
WINDOW_SECONDS = 5  # how much history each summary covers


def get_connection():
    return sqlite3.connect(DB_PATH)


def compute_window_stats(conn, window_start, window_end):
    cur = conn.cursor()

    cur.execute(
        """SELECT COUNT(*), COALESCE(SUM(length), 0)
           FROM packets WHERE timestamp >= ? AND timestamp < ?""",
        (window_start, window_end),
    )
    packet_count, total_bytes = cur.fetchone()

    cur.execute(
        """SELECT COUNT(DISTINCT src_ip || '-' || dst_ip)
           FROM packets WHERE timestamp >= ? AND timestamp < ?""",
        (window_start, window_end),
    )
    active_connections = cur.fetchone()[0]

    cur.execute(
        """SELECT protocol, COUNT(*) as cnt
           FROM packets WHERE timestamp >= ? AND timestamp < ?
           GROUP BY protocol ORDER BY cnt DESC LIMIT 1""",
        (window_start, window_end),
    )
    row = cur.fetchone()
    top_protocol = row[0] if row else None

    return {
        "window_start": window_start,
        "window_end": window_end,
        "total_bytes": total_bytes,
        "packet_count": packet_count,
        "active_connections": active_connections,
        "top_protocol": top_protocol,
    }


def save_stats(conn, stats):
    conn.execute(
        """INSERT INTO traffic_stats
           (window_start, window_end, total_bytes, packet_count,
            active_connections, top_protocol)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (
            stats["window_start"],
            stats["window_end"],
            stats["total_bytes"],
            stats["packet_count"],
            stats["active_connections"],
            stats["top_protocol"],
        ),
    )
    conn.commit()


def run_once(conn):
    now = time.time()
    window_start = now - WINDOW_SECONDS
    stats = compute_window_stats(conn, window_start, now)
    save_stats(conn, stats)
    print(
        f"[stats] {stats['packet_count']} pkts | "
        f"{stats['total_bytes']} bytes | "
        f"{stats['active_connections']} connections | "
        f"top proto: {stats['top_protocol']}"
    )
    return stats


def main():
    parser = argparse.ArgumentParser(description="Traffic stats aggregator")
    parser.add_argument("--interval", type=int, default=5,
                         help="Seconds between stat computations")
    parser.add_argument("--once", action="store_true",
                         help="Run a single computation and exit")
    args = parser.parse_args()

    conn = get_connection()
    try:
        if args.once:
            run_once(conn)
        else:
            print(f"[stats] Running every {args.interval}s (Ctrl+C to stop)")
            while True:
                run_once(conn)
                time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n[stats] Stopped.")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
