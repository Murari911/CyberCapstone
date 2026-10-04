CREATE TABLE IF NOT EXISTS packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    protocol TEXT NOT NULL,
    src_port INTEGER,
    dst_port INTEGER,
    length INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS traffic_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    window_start REAL NOT NULL,
    window_end REAL NOT NULL,
    total_bytes INTEGER,
    packet_count INTEGER,
    active_connections INTEGER,
    top_protocol TEXT
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    alert_type TEXT NOT NULL,
    source_ip TEXT,
    details TEXT,
    severity TEXT
);

CREATE TABLE IF NOT EXISTS known_devices (
    ip TEXT PRIMARY KEY,
    label TEXT,
    first_seen REAL
);

CREATE INDEX IF NOT EXISTS idx_packets_ts ON packets(timestamp);
CREATE INDEX IF NOT EXISTS idx_packets_src ON packets(src_ip);
