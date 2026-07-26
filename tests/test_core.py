"""Core unit tests — pure logic, no network or admin required (CI-safe)."""

import socket
import struct

from netrecon import enrich, ingest, monitor, net, scanner, watch


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


def test_ntfy_url():
    assert watch.ntfy_url("my-topic") == "https://ntfy.sh/my-topic"
    assert watch.ntfy_url("https://ntfy.example.com/t") == "https://ntfy.example.com/t"


def test_host_key():
    assert watch._host_key("aa:bb:cc:dd:ee:ff", "1.2.3.4") == "aa:bb:cc:dd:ee:ff"
    assert watch._host_key("", "1.2.3.4") == "ip:1.2.3.4"


def test_suricata_alert():
    line = ('{"timestamp":"2026-07-26T04:00:00Z","event_type":"alert","src_ip":"10.0.0.5",'
            '"src_port":51000,"dest_ip":"93.184.216.34","dest_port":443,"proto":"TCP",'
            '"alert":{"signature":"ET MALWARE Test","category":"A Network Trojan","severity":1}}')
    r = ingest.parse_suricata_line(line)
    assert r["kind"] == "alert" and r["signature"] == "ET MALWARE Test"
    assert r["severity"] == 1 and r["dst"] == "93.184.216.34" and r["source"] == "suricata"


def test_suricata_dns_and_flow():
    dns = ingest.parse_suricata_line('{"event_type":"dns","src_ip":"10.0.0.5","dns":{"rrname":"evil.example.com"}}')
    assert dns["kind"] == "dns" and dns["qname"] == "evil.example.com"
    flow = ingest.parse_suricata_line('{"event_type":"flow","src_ip":"10.0.0.5","dest_ip":"1.1.1.1",'
                                      '"proto":"UDP","dest_port":53,"flow":{"pkts_toserver":2,"pkts_toclient":1,'
                                      '"bytes_toserver":120,"bytes_toclient":300}}')
    assert flow["kind"] == "flow" and flow["packets"] == 3 and flow["bytes"] == 420


def test_suricata_ignores_junk():
    assert ingest.parse_suricata_line("not json") is None
    assert ingest.parse_suricata_line('{"event_type":"stats"}') is None


def test_zeek_conn_and_dns():
    conn = ingest.parse_zeek_conn({"id.orig_h": "10.0.0.5", "id.resp_h": "1.1.1.1", "proto": "tcp",
                                   "id.resp_p": 443, "orig_pkts": 5, "resp_pkts": 4,
                                   "orig_ip_bytes": 500, "resp_ip_bytes": 4000})
    assert conn["kind"] == "flow" and conn["dport"] == 443 and conn["bytes"] == 4500
    dns = ingest.parse_zeek_dns({"id.orig_h": "10.0.0.5", "query": "example.com"})
    assert dns["kind"] == "dns" and dns["qname"] == "example.com"


def test_detect_format():
    assert ingest.detect_format("/logs/eve.json") == "suricata"
    assert ingest.detect_format("/logs/conn.log") == "zeek-conn"
    assert ingest.detect_format("/logs/dns.log") == "zeek-dns"
