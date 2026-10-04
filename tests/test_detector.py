"""
test_detector.py — Unit tests for detector/rules.py using a throwaway in-memory DB.
Run with: pytest tests/test_detector.py -v
"""

import sys
import os
import sqlite3
import time
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from detector import rules


@pytest.fixture
def test_db():
    conn = sqlite3.connect(":memory:")
    conn.executescript("""
        CREATE TABLE packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL NOT NULL,
            src_ip TEXT NOT NULL,
            dst_ip TEXT NOT NULL,
            protocol TEXT NOT NULL,
            src_port INTEGER,
            dst_port INTEGER,
            length INTEGER NOT NULL
        );
        CREATE TABLE alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL NOT NULL,
            alert_type TEXT NOT NULL,
            source_ip TEXT,
            details TEXT,
            severity TEXT
        );
    """)
    yield conn
    conn.close()


@pytest.fixture
def config():
    return {
        "spike": {"enabled": True, "pps_threshold": 10, "window_seconds": 5},
        "unknown_ip": {
            "enabled": True,
            "trusted_ranges": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"],
        },
        "repeated_attempts": {"enabled": True, "attempt_threshold": 5, "window_seconds": 10},
        "port_scan": {"enabled": True, "distinct_port_threshold": 5, "window_seconds": 10},
    }


def insert_packets(conn, rows):
    conn.executemany(
        """INSERT INTO packets (timestamp, src_ip, dst_ip, protocol, src_port, dst_port, length)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        rows,
    )
    conn.commit()


def get_alerts(conn, alert_type=None):
    cur = conn.execute("SELECT alert_type, source_ip FROM alerts")
    rows = cur.fetchall()
    if alert_type:
        return [r for r in rows if r[0] == alert_type]
    return rows


def test_spike_detection_triggers_above_threshold(test_db, config):
    now = time.time()
    # 20 packets in the window, threshold is 10 pps over 5s (=50 total) — should NOT trigger with 20
    rows = [(now, "192.168.1.5", "8.8.8.8", "TCP", 1234, 80, 100) for _ in range(60)]
    insert_packets(test_db, rows)
    rules.check_spike(test_db, config)
    alerts = get_alerts(test_db, "traffic_spike")
    assert len(alerts) == 1, "Spike should trigger when packet rate exceeds threshold"


def test_spike_detection_does_not_trigger_below_threshold(test_db, config):
    now = time.time()
    rows = [(now, "192.168.1.5", "8.8.8.8", "TCP", 1234, 80, 100) for _ in range(5)]
    insert_packets(test_db, rows)
    rules.check_spike(test_db, config)
    alerts = get_alerts(test_db, "traffic_spike")
    assert len(alerts) == 0, "Spike should NOT trigger for normal traffic volume"


def test_unknown_ip_flags_public_ip(test_db, config):
    now = time.time()
    insert_packets(test_db, [(now, "45.33.32.156", "192.168.1.5", "TCP", 80, 1234, 60)])
    rules.check_unknown_ip(test_db, config)
    alerts = get_alerts(test_db, "unknown_ip")
    assert len(alerts) == 1
    assert alerts[0][1] == "45.33.32.156"


def test_unknown_ip_ignores_private_ip(test_db, config):
    now = time.time()
    insert_packets(test_db, [(now, "192.168.1.10", "192.168.1.5", "TCP", 80, 1234, 60)])
    rules.check_unknown_ip(test_db, config)
    alerts = get_alerts(test_db, "unknown_ip")
    assert len(alerts) == 0, "Private IPs should never be flagged as unknown"


def test_repeated_attempts_triggers_on_threshold(test_db, config):
    now = time.time()
    rows = [(now, "1.2.3.4", "192.168.1.5", "TCP", 5000 + i, 22, 60) for i in range(6)]
    insert_packets(test_db, rows)
    rules.check_repeated_attempts(test_db, config)
    alerts = get_alerts(test_db, "repeated_attempts")
    assert len(alerts) == 1


def test_port_scan_triggers_on_distinct_ports(test_db, config):
    now = time.time()
    rows = [(now, "1.2.3.4", "192.168.1.5", "TCP", 5000, 1000 + i, 60) for i in range(6)]
    insert_packets(test_db, rows)
    rules.check_port_scan(test_db, config)
    alerts = get_alerts(test_db, "port_scan")
    assert len(alerts) == 1


def test_disabled_rule_does_not_run(test_db, config):
    config["spike"]["enabled"] = False
    now = time.time()
    rows = [(now, "192.168.1.5", "8.8.8.8", "TCP", 1234, 80, 100) for _ in range(100)]
    insert_packets(test_db, rows)
    rules.check_spike(test_db, config)
    alerts = get_alerts(test_db, "traffic_spike")
    assert len(alerts) == 0, "Disabled rule should never fire"
