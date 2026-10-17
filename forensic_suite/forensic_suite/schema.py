"""Common event schema and small helpers shared by every module."""
from __future__ import annotations

import ipaddress
import ntpath
from urllib.parse import parse_qs, urlparse

EVENT_FIELDS = [
    "ts", "ts_tz", "source", "browser", "artifact_type", "url", "referrer",
    "title", "detail", "file_name", "file_path", "process", "source_file",
]

BROWSER_EXES = {"chrome.exe": "chrome", "msedge.exe": "edge", "firefox.exe": "firefox",
                "brave.exe": "brave"}

SEARCH_ENGINES = {"google.com", "bing.com", "duckduckgo.com", "yahoo.com", "yandex.com",
                  "ecosia.org", "search.brave.com"}
_SEARCH_PARAM = {"google.com": "q", "bing.com": "q", "duckduckgo.com": "q", "yahoo.com": "p",
                 "yandex.com": "text", "ecosia.org": "q", "brave.com": "q"}

EXECUTABLE_EXTS = (".exe", ".msi", ".bat", ".cmd", ".ps1", ".scr", ".vbs", ".js", ".jar",
                   ".dll", ".iso", ".lnk", ".hta")

# Tools that wipe traces. Value = how strongly their use suggests evidence removal (0-1).
CLEANUP_TOOLS = {"ccleaner.exe": 0.7, "ccleaner64.exe": 0.7, "bleachbit.exe": 0.8,
                 "sdelete.exe": 0.8, "sdelete64.exe": 0.8, "eraser.exe": 0.8,
                 "privazer.exe": 0.8, "cipher.exe": 0.4, "wevtutil.exe": 0.5}

KNOWN_BENIGN_EXES = {"chrome.exe", "msedge.exe", "firefox.exe", "explorer.exe", "notepad.exe",
                     "svchost.exe", "cmd.exe", "powershell.exe", "taskmgr.exe", "mspaint.exe",
                     "calc.exe", "winword.exe", "excel.exe", "code.exe", "onedrive.exe"}

USER_SPACE_MARKERS = ("\\downloads\\", "\\temp\\", "\\appdata\\", "\\desktop\\", "\\users\\public\\")

_TWO_PART_SUFFIXES = {"co.uk", "org.uk", "ac.uk", "com.au", "co.in", "ac.in", "co.jp", "com.br"}


def new_event(**kw) -> dict:
    e = {k: None for k in EVENT_FIELDS}
    e["ts_tz"] = "UTC"
    e.update(kw)
    return e


def host_of(url: str | None) -> str:
    if not url or not isinstance(url, str):
        return ""
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def registrable(host: str | None) -> str:
    """Naive registrable domain (no public-suffix list needed for this project)."""
    if not host:
        return ""
    host = host.lower().strip(".")
    if is_ip(host):
        return host
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if ".".join(labels[-2:]) in _TWO_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def basename(path: str | None) -> str:
    if not path or not isinstance(path, str):
        return ""
    return ntpath.basename(str(path).replace("/", "\\"))


def parse_search_url(url: str) -> str | None:
    """Return the search term if the URL is a web-search results page."""
    reg = registrable(host_of(url))
    param = _SEARCH_PARAM.get(reg)
    if not param:
        return None
    vals = parse_qs(urlparse(url).query).get(param)
    return vals[0] if vals else None
