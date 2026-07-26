"""Passive traffic monitor.

Captures IP/TCP/UDP traffic with a raw socket and extracts flows + DNS query
names — no third-party dependencies. On Windows it uses ``SIO_RCVALL`` to put a
raw socket into promiscuous-ish mode (requires Administrator). The header
parsers are pure functions so they can be unit-tested without capturing.
"""

from __future__ import annotations

import platform
import socket
import struct
from typing import Callable, Optional, Tuple

from . import net

_IS_WIN = platform.system().lower().startswith("win")

_PROTO = {1: "icmp", 6: "tcp", 17: "udp"}


def proto_name(proto: int) -> str:
    return _PROTO.get(proto, str(proto))


def parse_ipv4(data: bytes) -> Optional[Tuple[int, str, str, int, int]]:
    """Return (proto, src, dst, header_len, total_len) or None."""
    if len(data) < 20 or (data[0] >> 4) != 4:
        return None
    ihl = (data[0] & 0x0F) * 4
    total_len = struct.unpack("!H", data[2:4])[0]
    proto = data[9]
    src = socket.inet_ntoa(data[12:16])
    dst = socket.inet_ntoa(data[16:20])
    return proto, src, dst, ihl, total_len


def parse_ports(proto: int, data: bytes, off: int) -> Tuple[Optional[int], Optional[int]]:
    if proto in (6, 17) and len(data) >= off + 4:
        sport, dport = struct.unpack("!HH", data[off:off + 4])
        return sport, dport
    return None, None


def parse_dns_qname(data: bytes, ip_hdr_len: int) -> Optional[str]:
    """Parse the first DNS question name from a UDP/53 packet (best effort)."""
    dns = data[ip_hdr_len + 8:]  # skip IP + 8-byte UDP header
    if len(dns) < 13:
        return None
    i, labels = 12, []
    while i < len(dns):
        ln = dns[i]
        if ln == 0:
            break
        if ln & 0xC0:  # compression pointer — bail
            break
        i += 1
        labels.append(dns[i:i + ln].decode("latin-1", "replace"))
        i += ln
        if len(labels) > 12:
            break
    return ".".join(labels) if labels else None


def open_capture(iface_ip: Optional[str] = None) -> socket.socket:
    """Open a raw capture socket on the given interface IP (Windows)."""
    if not _IS_WIN:
        raise RuntimeError(
            "netrecon monitor currently supports Windows raw sockets only "
            "(Linux AF_PACKET support is on the roadmap)."
        )
    host = iface_ip or net.local_ipv4()
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    s.bind((host, 0))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)  # type: ignore[attr-defined]
    return s


def capture(
    on_packet: Callable[[int, str, str, Optional[int], Optional[int], int], None],
    on_dns: Optional[Callable[[str, str, str], None]] = None,
    duration: Optional[float] = None,
    iface_ip: Optional[str] = None,
    should_stop: Optional[Callable[[], bool]] = None,
) -> None:
    """Capture loop. Calls on_packet(proto, src, dst, sport, dport, length)
    for every IPv4 packet and on_dns(client, server, qname) for DNS queries."""
    import time

    s = open_capture(iface_ip)
    s.settimeout(1.0)
    start = time.time()
    try:
        while True:
            if duration is not None and (time.time() - start) > duration:
                break
            if should_stop is not None and should_stop():
                break
            try:
                data, _ = s.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                continue
            info = parse_ipv4(data)
            if not info:
                continue
            proto, src, dst, ihl, total_len = info
            sport, dport = parse_ports(proto, data, ihl)
            on_packet(proto, src, dst, sport, dport, total_len)
            if on_dns and proto == 17 and (sport == 53 or dport == 53):
                name = parse_dns_qname(data, ihl)
                if name:
                    on_dns(src, dst, name)
    finally:
        try:
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)  # type: ignore[attr-defined]
        except Exception:
            pass
        s.close()
