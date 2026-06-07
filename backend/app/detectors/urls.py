"""URL detectors: malicious URL and unreachable / non-routable URL.

Network egress is intentionally avoided so detection is deterministic and
hot-path-safe. ``unreachable_url`` therefore flags *structurally*
non-routable destinations (reserved/private/loopback/reserved-TLD). A
deployment can layer live DNS/threat-intel resolution on top via the
``extra`` context bag without changing this contract.
"""

from __future__ import annotations

import ipaddress
import re

from app.detectors.base import DetectorContext, DetectorResult, Direction
from app.detectors import util

_URL_RE = re.compile(r"\b(?:https?://|www\.)[^\s<>\"')]+", re.I)
_HOST_RE = re.compile(r"https?://([^/:\s]+)", re.I)

_SUSPICIOUS_TLDS = {
    "zip",
    "mov",
    "xyz",
    "top",
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "click",
    "country",
    "kim",
    "work",
    "loan",
}
_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "t.co",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "rebrand.ly",
    "cutt.ly",
}
_RESERVED_TLDS = {"invalid", "test", "example", "localhost", "local", "internal", "home", "lan"}
_BAD_KEYWORDS = (
    "login",
    "verify",
    "account",
    "secure",
    "update",
    "confirm",
    "webscr",
    "wallet",
    "airdrop",
    "metamask",
)


def _host(url: str) -> str:
    m = _HOST_RE.search(url if url.startswith("http") else "http://" + url)
    return (m.group(1) if m else "").lower()


class MaliciousURLDetector:
    name = "malicious_url"
    category = "malicious_url"
    default_threshold = 0.5
    severity = "high"
    directions = (Direction.BOTH,)

    def detect(self, text: str, ctx: DetectorContext) -> DetectorResult:
        urls = _URL_RE.findall(text)
        if not urls:
            return DetectorResult(self.name, self.category, 0.0, "info", {})
        worst = 0.0
        worst_url = ""
        reasons: list[str] = []
        allow = set(ctx.extra.get("url_allowlist", ()))
        for url in urls:
            host = _host(url)
            if host in allow:
                continue
            s = 0.0
            r: list[str] = []
            # IP-literal host
            try:
                ip = ipaddress.ip_address(host.split(":")[0])
                s = max(s, 0.6)
                r.append("ip_host")
                if ip.is_private or ip.is_loopback:
                    s = max(s, 0.7)
                    r.append("private_ip")
            except ValueError:
                pass
            tld = host.rsplit(".", 1)[-1] if "." in host else ""
            if tld in _SUSPICIOUS_TLDS:
                s = max(s, 0.65)
                r.append(f"suspicious_tld:{tld}")
            if host in _SHORTENERS:
                s = max(s, 0.55)
                r.append("shortener")
            if host.startswith("xn--") or "xn--" in host:
                s = max(s, 0.7)
                r.append("punycode")
            if any(k in url.lower() for k in _BAD_KEYWORDS) and ("@" in url or s > 0):
                s = max(s, 0.6)
                r.append("phishing_keyword")
            if "@" in url.split("//", 1)[-1].split("/", 1)[0]:
                s = max(s, 0.75)
                r.append("userinfo_obfuscation")
            if host.count("-") >= 3 or len(host) > 40:
                s = max(s, 0.4)
                r.append("suspicious_host_shape")
            if util.shannon_entropy(host.replace(".", "")) > 4.0 and len(host) > 15:
                s = max(s, 0.45)
                r.append("high_entropy_host")
            if s > worst:
                worst, worst_url, reasons = s, url, r
        return DetectorResult(
            self.name,
            self.category,
            worst,
            "high" if worst >= 0.6 else "medium",
            {"url": worst_url[:200], "reasons": reasons, "url_count": len(urls)},
        ).clamp()


class UnreachableURLDetector:
    name = "unreachable_url"
    category = "unreachable_url"
    default_threshold = 0.5
    severity = "low"
    directions = (Direction.BOTH,)

    def detect(self, text: str, ctx: DetectorContext) -> DetectorResult:
        urls = _URL_RE.findall(text)
        if not urls:
            return DetectorResult(self.name, self.category, 0.0, "info", {})
        worst = 0.0
        reasons: list[str] = []
        bad_url = ""
        for url in urls:
            host = _host(url)
            s = 0.0
            r: list[str] = []
            tld = host.rsplit(".", 1)[-1] if "." in host else host
            if tld in _RESERVED_TLDS or host in _RESERVED_TLDS:
                s = max(s, 0.85)
                r.append(f"reserved_tld:{tld}")
            try:
                ip = ipaddress.ip_address(host.split(":")[0])
                if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local:
                    s = max(s, 0.8)
                    r.append("non_routable_ip")
            except ValueError:
                pass
            if "." not in host and host not in _RESERVED_TLDS:
                s = max(s, 0.6)
                r.append("no_tld")
            if re.search(r"\s", url) or url.endswith((".", ",")):
                s = max(s, 0.4)
                r.append("malformed")
            if s > worst:
                worst, reasons, bad_url = s, r, url
        return DetectorResult(
            self.name,
            self.category,
            worst,
            "low",
            {"url": bad_url[:200], "reasons": reasons},
        ).clamp()
