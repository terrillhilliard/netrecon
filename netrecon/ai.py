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
    "You are a senior network security analyst embedded in 'netrecon', a LAN "
    "reconnaissance and monitoring tool. Answer the operator's question using the "
    "provided live network data plus your security knowledge. Be accurate, concise, "
    "and practical. When flagging risk, name the specific host/IP and port. Suggest "
    "concrete next steps (including netrecon commands like `netrecon scan <ip>`, "
    "`netrecon mitm <ip>`, `netrecon monitor`) where useful. If the data is "
    "insufficient to answer, say so rather than guessing."
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
        ports = list(((h.get("meta", {}) or {}).get("values", {}) or {}).get("ports", {}).keys())
        lines.append(f"  - {h.get('ipv4', '')}  {h.get('hostname', '') or '-'}  "
                     f"[{h.get('vendor', '') or 'unknown'}]  ports: {', '.join(ports) or 'none'}")
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
