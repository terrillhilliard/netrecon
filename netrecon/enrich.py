"""Enrichment: OUI vendor, reverse-DNS hostname, service names, banners."""

from __future__ import annotations

import socket
from typing import Optional

# Curated service map (supplements socket.getservbyport, which is spotty on Windows).
_SERVICES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain",
    67: "dhcp", 68: "dhcp", 69: "tftp", 80: "http", 88: "kerberos", 110: "pop3",
    111: "rpcbind", 123: "ntp", 135: "msrpc", 137: "netbios-ns", 138: "netbios-dgm",
    139: "netbios-ssn", 143: "imap", 161: "snmp", 389: "ldap", 443: "https",
    445: "microsoft-ds", 465: "smtps", 514: "syslog", 587: "submission", 631: "ipp",
    636: "ldaps", 993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
    1723: "pptp", 1883: "mqtt", 2049: "nfs", 3306: "mysql", 3389: "rdp", 5060: "sip",
    5432: "postgres", 5900: "vnc", 5985: "winrm", 6379: "redis", 8080: "http-alt",
    8443: "https-alt", 9100: "jetdirect", 9200: "elasticsearch", 11211: "memcached",
    27017: "mongodb", 32400: "plex",
}

_mac_lookup = None


def service_name(port: int) -> str:
    if port in _SERVICES:
        return _SERVICES[port]
    try:
        return socket.getservbyport(port)
    except OSError:
        return ""


def vendor(mac: str) -> str:
    """OUI -> vendor name (best effort; empty if the OUI DB is unavailable)."""
    global _mac_lookup
    if not mac:
        return ""
    try:
        if _mac_lookup is None:
            from mac_vendor_lookup import MacLookup

            _mac_lookup = MacLookup()
        return _mac_lookup.lookup(mac)
    except Exception:
        return ""


def hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return ""


_HTTP_PORTS = {80, 591, 8000, 8008, 8080, 8081, 8088, 8888, 9000, 9090}


def banner(ip: str, port: int, timeout: float = 1.5) -> str:
    """Grab a service banner / version string from an open port (best effort).

    For HTTP ports it returns the Server header (e.g. 'nginx/1.24'); for other
    services it returns the greeting line (e.g. 'SSH-2.0-OpenSSH_8.4', FTP/SMTP
    banners). HTTPS/TLS ports return '' (no plaintext banner)."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            if port in _HTTP_PORTS:
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: %b\r\nUser-Agent: netrecon\r\n\r\n" % ip.encode())
            data = b""
            try:
                while len(data) < 2048:
                    chunk = s.recv(512)
                    if not chunk:
                        break
                    data += chunk
            except OSError:
                pass
            text = data.decode("latin-1", "replace")
            for line in text.split("\r\n"):  # prefer the HTTP Server header
                if line.lower().startswith("server:"):
                    return line.split(":", 1)[1].strip()[:120]
            for line in text.splitlines():   # else first meaningful line
                line = line.strip()
                if line:
                    return line[:120]
            return ""
    except OSError:
        return ""
