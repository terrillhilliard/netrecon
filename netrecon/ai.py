"""Optional AI analysis via the Anthropic Messages API (stdlib only).

Turns the live network state into context and asks Claude the operator's
question. Enabled by setting ANTHROPIC_API_KEY (or `netrecon serve --ai-key`).
No SDK dependency — a plain urllib call.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Optional

API_URL = "https://api.anthropic.com/v1/messages"
DEFAULT_MODEL = "claude-sonnet-5"

SYSTEM = (
    "You are a senior offensive+defensive security analyst embedded in 'netrecon', a LAN "
    "reconnaissance and monitoring tool. Answer the operator's question using the provided "
    "live network data plus your security knowledge. Be accurate, concise, and practical; "
    "name the specific host/IP and port when flagging anything.\n\n"
    "VULNERABILITY FOCUS: the data includes detected service banners/versions (e.g. "
    "'OpenSSH 8.4', 'nginx/1.24', 'vsftpd 2.3.4'). For each notable service, identify:\n"
    "  - likely KNOWN VULNERABILITIES (name CVE IDs and severity when reasonably confident);\n"
    "  - whether PUBLIC EXPLOITS exist (Metasploit module path, Exploit-DB, or 'PoC only'), "
    "without providing weaponized exploit code;\n"
    "  - the FIXED/updated version and the concrete remediation ('upgrade X to >= Y').\n"
    "Rank findings by exploitability and impact. When a 'LIVE NVD CVE DATA' block is present, "
    "treat those CVEs as authoritative and CURRENT (pulled live from NVD): cite their exact CVE "
    "IDs, CVSS severity/score, and published dates, and prioritize them over your training "
    "knowledge. A '⚔ ACTIVELY-EXPLOITED (in CISA KEV)' marker means the CVE is being exploited in "
    "the wild RIGHT NOW — flag these as top priority; 'PUBLIC-EXPLOIT: <url>' means a public "
    "exploit/PoC (Exploit-DB/Metasploit/etc.) exists. Use your own knowledge to add remediation "
    "context. "
    "Suggest netrecon next steps (`netrecon scan <ip>`, `netrecon vulns \"<service> <ver>\"`, "
    "`netrecon flows`) and, only for authorized testing, the relevant tool/technique names. "
    "If data is insufficient, say so rather than guessing."
)


def api_key() -> str:
    return os.environ.get("ANTHROPIC_API_KEY", "").strip()


def build_context(session: dict, events: Optional[list] = None) -> str:
    itf = session.get("interface", {}) or {}
    gw = session.get("gateway", {}) or {}
    lines = [
        f"Interface: {itf.get('ipv4', '?')} ({itf.get('hostname', '')})",
        f"Gateway: {gw.get('ipv4', '?')}",
    ]
    hosts = (session.get("lan", {}) or {}).get("hosts", [])
    lines.append(f"{len(hosts)} hosts discovered:")
    for h in hosts[:50]:
        pmap = ((h.get("meta", {}) or {}).get("values", {}) or {}).get("ports", {}) or {}
        pstrs = []
        for k, v in pmap.items():
            s = f"{v.get('port', k)}/{v.get('service', '') or 'tcp'}"
            if v.get("banner"):
                s += f" [{v['banner']}]"
            pstrs.append(s)
        lines.append(f"  - {h.get('ipv4', '')}  {h.get('hostname', '') or '-'}  "
                     f"[{h.get('vendor', '') or 'unknown'}]  ports: {', '.join(pstrs) or 'none'}")
    pkts = session.get("packets", {}) or {}
    stats = pkts.get("stats", {}) or {}
    if stats.get("pkts_received"):
        lines.append(f"Captured packets: {stats.get('pkts_received')} "
                     f"(protocols: {', '.join(f'{k}={v}' for k, v in (pkts.get('protos') or {}).items())})")
    dns_http = [e for e in (events or []) if e.get("tag") in ("dns", "http")][-30:]
    if dns_http:
        lines.append("Recent DNS/HTTP from monitored devices:")
        for e in dns_http:
            d = e.get("data", {})
            lines.append(f"  {d.get('ipv4', '')} -> {d.get('hostname', '')} ({e.get('tag')})")
    return "\n".join(lines)


def ask(question: str, context: str, model: Optional[str] = None,
        key: Optional[str] = None, max_tokens: int = 1024) -> str:
    key = key or api_key()
    if not key:
        raise RuntimeError("no ANTHROPIC_API_KEY set - export it (or use --ai-key) to enable AI analysis")
    body = json.dumps({
        "model": model or DEFAULT_MODEL,
        "max_tokens": max_tokens,
        "system": SYSTEM,
        "messages": [{"role": "user",
                      "content": f"LIVE NETWORK DATA:\n{context}\n\nQUESTION: {question}"}],
    }).encode("utf-8")
    req = urllib.request.Request(API_URL, data=body, headers={
        "x-api-key": key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            data = json.loads(r.read())
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:300]
        raise RuntimeError(f"AI API error {e.code}: {detail}")
    parts = [b.get("text", "") for b in data.get("content", []) if b.get("type") == "text"]
    return "".join(parts).strip() or "(no response)"
