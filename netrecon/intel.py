"""Threat-intel lookups + pivot links (VirusTotal + Hybrid Analysis + ANY.RUN).

Classify an indicator (IP / domain / URL / file hash) and check its reputation.
API keys are optional: without them you still get one-click pivot links to all
three services. With VT_API_KEY / HYBRID_ANALYSIS_KEY (or serve --vt-key /
--ha-key) you also get inline verdicts. Files are hashed client-side in the
browser, so only the hash is ever sent.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional

_HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-zA-Z0-9_-]{1,63}\.)+[a-zA-Z]{2,}$")


def classify(indicator: str) -> str:
    ind = (indicator or "").strip()
    if not ind:
        return "unknown"
    if ind.startswith("http://") or ind.startswith("https://"):
        return "url"
    if _HASH_RE.match(ind):
        return "hash"
    try:
        ipaddress.ip_address(ind)
        return "ip"
    except ValueError:
        pass
    if _DOMAIN_RE.match(ind):
        return "domain"
    return "unknown"


def links(indicator: str, kind: str) -> dict:
    q = urllib.parse.quote(indicator, safe="")
    out = {
        "virustotal": f"https://www.virustotal.com/gui/search/{q}",
        "hybrid": f"https://www.hybrid-analysis.com/search?query={q}",
        "anyrun": "https://app.any.run/submissions",
    }
    if kind == "hash":
        out["anyrun"] = f"https://any.run/report/{indicator}"
    return out


def _vt_path(indicator: str, kind: str) -> Optional[str]:
    if kind == "ip":
        return f"ip_addresses/{indicator}"
    if kind == "domain":
        return f"domains/{indicator}"
    if kind == "hash":
        return f"files/{indicator}"
    if kind == "url":
        uid = base64.urlsafe_b64encode(indicator.encode()).decode().strip("=")
        return f"urls/{uid}"
    return None


def virustotal(indicator: str, kind: str, key: Optional[str] = None) -> dict:
    key = key or os.environ.get("VT_API_KEY", "").strip()
    if not key:
        return {"error": "no VT_API_KEY set"}
    path = _vt_path(indicator, kind)
    if not path:
        return {"error": "unsupported indicator for VirusTotal"}
    req = urllib.request.Request(f"https://www.virustotal.com/api/v3/{path}",
                                 headers={"x-apikey": key})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            data = json.loads(r.read())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"stats": None, "note": "not found in VirusTotal"}
        return {"error": f"VirusTotal HTTP {e.code}"}
    except Exception as e:
        return {"error": f"VirusTotal: {e}"}
    attr = (data.get("data", {}) or {}).get("attributes", {}) or {}
    return {
        "stats": attr.get("last_analysis_stats"),
        "reputation": attr.get("reputation"),
        "name": attr.get("meaningful_name") or (attr.get("names") or [None])[0],
    }


def hybrid_analysis(file_hash: str, key: Optional[str] = None) -> dict:
    key = key or os.environ.get("HYBRID_ANALYSIS_KEY", "").strip()
    if not key:
        return {"error": "no HYBRID_ANALYSIS_KEY set"}
    body = urllib.parse.urlencode({"hash": file_hash}).encode()
    req = urllib.request.Request(
        "https://www.hybrid-analysis.com/api/v2/search/hash", data=body,
        headers={"api-key": key, "user-agent": "Falcon Sandbox", "accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            arr = json.loads(r.read())
    except Exception as e:
        return {"error": f"Hybrid Analysis: {e}"}
    if not arr:
        return {"verdict": None, "note": "not found in Hybrid Analysis"}
    first = arr[0]
    return {"verdict": first.get("verdict"), "threat_score": first.get("threat_score"),
            "type": first.get("type_short")}


def lookup(indicator: str, vt_key: Optional[str] = None, ha_key: Optional[str] = None) -> dict:
    kind = classify(indicator)
    out = {"indicator": indicator, "kind": kind, "links": links(indicator, kind)}
    if kind == "unknown":
        out["error"] = "could not classify - expected an IP, domain, URL, or file hash"
        return out
    out["virustotal"] = virustotal(indicator, kind, vt_key)
    if kind == "hash":
        out["hybrid"] = hybrid_analysis(indicator, ha_key)
    return out
