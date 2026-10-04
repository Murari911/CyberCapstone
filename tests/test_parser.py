"""
test_parser.py — Unit tests for capture/sniffer.py packet parsing.
Uses Scapy's own packet-building to create synthetic packets (no live capture needed).
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scapy.all import IP, TCP, UDP, ICMP, Ether
from capture.sniffer import parse_packet, get_protocol


def test_parse_tcp_packet():
    pkt = Ether() / IP(src="192.168.1.5", dst="8.8.8.8") / TCP(sport=1234, dport=443)
    result = parse_packet(pkt)
    assert result is not None
    _, src, dst, proto, sport, dport, length = result
    assert src == "192.168.1.5"
    assert dst == "8.8.8.8"
    assert proto == "TCP"
    assert sport == 1234
    assert dport == 443


def test_parse_udp_packet():
    pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=5353, dport=53)
    result = parse_packet(pkt)
    assert result is not None
    assert result[3] == "UDP"
    assert result[4] == 5353
    assert result[5] == 53


def test_parse_icmp_packet():
    pkt = Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / ICMP()
    result = parse_packet(pkt)
    assert result is not None
    assert result[3] == "ICMP"
    assert result[4] is None
    assert result[5] is None


def test_parse_non_ip_packet_returns_none():
    pkt = Ether()
    result = parse_packet(pkt)
    assert result is None, "Non-IP packets (e.g. ARP) should be skipped"


def test_get_protocol_defaults_to_other():
    pkt = Ether() / IP(src="1.1.1.1", dst="2.2.2.2")
    assert get_protocol(pkt) == "OTHER"
