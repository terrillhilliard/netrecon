"""Core unit tests — pure logic, no network or admin required (CI-safe)."""

import socket
import struct

from netrecon import enrich, monitor, net, scanner


def _dns_packet(name, src="192.168.1.50", dst="8.8.8.8"):
    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    dns = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + labels + struct.pack("!HH", 1, 1)
    udp = struct.pack("!HHHH", 51000, 53, 8 + len(dns), 0) + dns
    total = 20 + len(udp)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, 17, 0,
                     socket.inet_aton(src), socket.inet_aton(dst))
    return ip + udp


def test_parse_ipv4_udp_dns():
    pkt = _dns_packet("example.com")
    proto, src, dst, ihl, _ = monitor.parse_ipv4(pkt)
    assert proto == 17 and src == "192.168.1.50" and dst == "8.8.8.8" and ihl == 20
    assert monitor.parse_ports(proto, pkt, ihl) == (51000, 53)
    assert monitor.parse_dns_qname(pkt, ihl) == "example.com"


def test_parse_ipv4_rejects_short_and_nonv4():
    assert monitor.parse_ipv4(b"\x45" * 5) is None
    assert monitor.parse_ipv4(b"\x60" + b"\x00" * 40) is None  # IPv6 nibble


def test_proto_name():
    assert monitor.proto_name(6) == "tcp"
    assert monitor.proto_name(17) == "udp"
    assert monitor.proto_name(99) == "99"


def test_expand_targets_cidr():
    assert net.expand_targets("192.168.1.0/30") == ["192.168.1.1", "192.168.1.2"]


def test_expand_targets_last_octet_range():
    assert net.expand_targets("10.0.0.5-7") == ["10.0.0.5", "10.0.0.6", "10.0.0.7"]


def test_expand_targets_full_range_and_single():
    assert net.expand_targets("10.0.0.1-10.0.0.2") == ["10.0.0.1", "10.0.0.2"]
    assert net.expand_targets("10.0.0.9") == ["10.0.0.9"]


def test_subnet_for():
    assert net.subnet_for("192.168.88.145") == "192.168.88.0/24"


def test_sort_ips():
    assert net.sort_ips(["10.0.0.9", "10.0.0.10", "10.0.0.2"]) == \
        ["10.0.0.2", "10.0.0.9", "10.0.0.10"]


def test_service_name():
    assert enrich.service_name(22) == "ssh"
    assert enrich.service_name(443) == "https"


def test_top_ports():
    assert 80 in scanner.TOP_PORTS and 443 in scanner.TOP_PORTS and 22 in scanner.TOP_PORTS
