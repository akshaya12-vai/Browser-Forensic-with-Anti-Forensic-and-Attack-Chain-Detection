"""Transparent domain / text heuristics used by Modules 6 and 7."""
from __future__ import annotations

import math
import re
from pathlib import Path

from .schema import is_ip, registrable

SUSPICIOUS_TLDS = {"xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "work", "zip", "mov",
                   "icu", "buzz", "cyou", "rest", "monster", "su"}
TRUSTED_DOMAINS = {"python.org", "microsoft.com", "google.com", "gstatic.com", "mozilla.org",
                   "mozilla.net", "github.com", "githubusercontent.com", "apple.com",
                   "ubuntu.com", "videolan.org", "7-zip.org", "visualstudio.com", "live.com",
                   "bing.com", "wikipedia.org", "stackoverflow.com", "duckduckgo.com"}
SUSPICIOUS_TERMS = ("crack", "keygen", "nulled", "warez", "activator", "serial key", "cracked",
                    "loader")


def entropy(s: str) -> float:
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)


def load_ioc(path: str | Path | None) -> frozenset:
    if not path or not Path(path).exists():
        return frozenset()
    return frozenset(l.strip().lower() for l in Path(path).read_text().splitlines()
                     if l.strip() and not l.startswith("#"))


def domain_flags(domain: str | None, ioc: frozenset = frozenset()) -> list[str]:
    """Reasons a domain looks suspicious (empty list = nothing unusual)."""
    if not domain:
        return []
    d = domain.lower()
    reg = registrable(d)
    reasons: list[str] = []
    if is_ip(d):
        return ["IP address used instead of a domain name"]
    labels = reg.split(".")
    tld, sld = labels[-1], labels[0]
    if tld in SUSPICIOUS_TLDS:
        reasons.append(f"commonly abused TLD .{tld}")
    if d.startswith("xn--") or ".xn--" in d:
        reasons.append("punycode (possible look-alike) domain")
    if len(sld) >= 10 and entropy(sld) > 3.6:
        reasons.append("random-looking (high-entropy) name")
    if len(sld) >= 8 and sum(c.isdigit() for c in sld) / len(sld) > 0.3:
        reasons.append("digit-heavy name")
    if sld.count("-") >= 3:
        reasons.append("many hyphens in name")
    if d in ioc or reg in ioc:
        reasons.append("listed in IOC file")
    return reasons


def is_trusted(domain: str | None) -> bool:
    return registrable(domain) in TRUSTED_DOMAINS if domain else False


def suspicious_terms(text: str | None) -> list[str]:
    t = (text or "").lower()
    return [w for w in SUSPICIOUS_TERMS if re.search(r"\b" + re.escape(w), t)]
