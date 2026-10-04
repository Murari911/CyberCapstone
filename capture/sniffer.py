"""
sniffer.py — Captures live network packets and writes them to SQLite.
Run with sudo (raw socket access required).
"""

import sqlite3
import time
import signal
import sys
import argparse
from scapy.all import sniff, IP, TCP, UDP, ICMP

DB_PATH = "db/traffic.db"
INTERFACE = "eth0"
BATCH_SIZE = 50
BATCH_INTERVAL = 2.0  # seconds

buffer = []
last_flush = time.time()
conn = None
running = True


def get_protocol(pkt):
    if pkt.haslayer(TCP):
        return "TCP"
    elif pkt.haslayer(UDP):
        return "UDP"
    elif pkt.haslayer(ICMP):
        return "ICMP"
    return "OTHER"


def parse_packet(pkt):
    if not pkt.haslayer(IP):
        return None  # skip non-IP packets (e.g. ARP)

    ip_layer = pkt[IP]
    proto = get_protocol(pkt)
    src_port = dst_port = None

    if pkt.haslayer(TCP):
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
    elif pkt.haslayer(UDP):
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport

    return (
        time.time(),
        ip_layer.src,
        ip_layer.dst,
        proto,
        src_port,
        dst_port,
        len(pkt),
    )


def flush_buffer():
    global buffer
    if not buffer:
        return
    conn.executemany(
        """INSERT INTO packets
           (timestamp, src_ip, dst_ip, protocol, src_port, dst_port, length)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        buffer,
    )
    conn.commit()
    print(f"[sniffer] Flushed {len(buffer)} packets to DB")
    buffer = []


def packet_callback(pkt):
    global buffer, last_flush
    row = parse_packet(pkt)
    if row:
        buffer.append(row)

    now = time.time()
    if len(buffer) >= BATCH_SIZE or (now - last_flush) >= BATCH_INTERVAL:
        flush_buffer()
        last_flush = now


def handle_shutdown(sig, frame):
    global running
    print("\n[sniffer] Stopping, flushing remaining packets...")
    flush_buffer()
    running = False
    conn.close()
    sys.exit(0)


def main():
    global conn
    parser = argparse.ArgumentParser(description="Network packet sniffer")
    parser.add_argument("--count", type=int, default=0,
                         help="Stop after N packets (0 = run forever)")
    parser.add_argument("--duration", type=int, default=0,
                         help="Stop after N seconds (0 = run forever)")
    args = parser.parse_args()

    conn = sqlite3.connect(DB_PATH)
    signal.signal(signal.SIGINT, handle_shutdown)

    print(f"[sniffer] Starting capture on {INTERFACE}... (Ctrl+C to stop)")
    sniff(
        iface=INTERFACE,
        prn=packet_callback,
        store=False,
        count=args.count if args.count > 0 else 0,
        timeout=args.duration if args.duration > 0 else None,
    )

    flush_buffer()
    conn.close()


if __name__ == "__main__":
    main()
