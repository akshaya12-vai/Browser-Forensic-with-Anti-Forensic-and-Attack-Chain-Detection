"""MODULE 1 - Evidence Collection.

Reads Chrome / Edge / Brave (Chromium), Firefox, Windows Timeline (ActivitiesCache.db),
Prefetch (PECmd-style CSV) and DNS logs (CSV).  Every source is hashed, copied and read
from the COPY, then re-hashed so you can prove the original was not altered.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import unquote

import pandas as pd

from .schema import (BROWSER_EXES, basename, host_of, new_event, parse_search_url)

UTC = timezone.utc
_WEBKIT_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)
_UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


# ----------------------------------------------------------------- time helpers
def webkit_to_dt(us):
    return _WEBKIT_EPOCH + timedelta(microseconds=int(us)) if us else None


def prtime_to_dt(us):
    return _UNIX_EPOCH + timedelta(microseconds=int(us)) if us else None


def unix_to_dt(sec):
    return _UNIX_EPOCH + timedelta(seconds=int(sec)) if sec else None


# ------------------------------------------------------------ chain of custody
def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def acquire(src: Path, work: Path, kind: str) -> tuple[Path, dict]:
    """Hash -> copy (with -wal/-shm sidecars) -> hash copy -> re-hash original."""
    work.mkdir(parents=True, exist_ok=True)
    before = sha256_file(src)
    tag = hashlib.sha1(str(src.resolve()).encode()).hexdigest()[:8]
    dst = work / f"{tag}_{src.name}"
    shutil.copy2(src, dst)
    for ext in ("-wal", "-shm"):
        side = src.with_name(src.name + ext)
        if side.exists():
            shutil.copy2(side, dst.with_name(dst.name + ext))
    copy_hash = sha256_file(dst)
    after = sha256_file(src)
    entry = {"kind": kind, "source_path": str(src), "working_copy": str(dst),
             "size_bytes": src.stat().st_size, "sha256": before, "copy_sha256": copy_hash,
             "verified": before == copy_hash == after,
             "acquired_utc": datetime.now(UTC).isoformat(timespec="seconds")}
    return dst, entry


# ---------------------------------------------------------------- discovery
def discover(evidence_dir: Path) -> list[tuple[str, str | None, Path]]:
    """Return (kind, browser, path) for every recognised artifact under evidence_dir."""
    found = []
    for p in sorted(evidence_dir.rglob("*")):
        if not p.is_file():
            continue
        name, parts = p.name.lower(), [x.lower() for x in p.parts]
        if name == "history" and not p.suffix:
            browser = next((b for b in ("chrome", "edge", "brave") if any(b in x for x in parts)), "chromium")
            found.append(("chromium", browser, p))
        elif name == "places.sqlite":
            found.append(("firefox", "firefox", p))
        elif name == "activitiescache.db":
            found.append(("timeline", None, p))
        elif name.endswith(".csv") and "prefetch" in name:
            found.append(("prefetch", None, p))
        elif name.endswith(".csv") and "dns" in name:
            found.append(("dns", None, p))
    return found


def live_windows_paths() -> list[tuple[str, str | None, Path]]:
    """Default artifact locations on a live Windows machine (browsers should be closed)."""
    local = Path(os.environ.get("LOCALAPPDATA", ""))
    roam = Path(os.environ.get("APPDATA", ""))
    out = []
    for browser, rel in (("chrome", "Google/Chrome/User Data/Default/History"),
                         ("edge", "Microsoft/Edge/User Data/Default/History"),
                         ("brave", "BraveSoftware/Brave-Browser/User Data/Default/History")):
        if (local / rel).exists():
            out.append(("chromium", browser, local / rel))
    for prof in (roam / "Mozilla/Firefox/Profiles").glob("*/places.sqlite"):
        out.append(("firefox", "firefox", prof))
    for cache in (local / "ConnectedDevicesPlatform").glob("*/ActivitiesCache.db"):
        out.append(("timeline", None, cache))
    return out


# ----------------------------------------------------------------- sqlite utils
def _connect(db: Path) -> sqlite3.Connection:
    con = sqlite3.connect(db.resolve().as_uri() + "?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    return con


def _id_meta(con, browser: str, table: str) -> dict | None:
    """Row-id statistics: used by Module 4 to spot deleted history rows."""
    try:
        cnt, mn, mx = con.execute(f"SELECT COUNT(*), MIN(id), MAX(id) FROM {table}").fetchone()
    except sqlite3.Error:
        return None
    seq = None
    try:
        r = con.execute("SELECT seq FROM sqlite_sequence WHERE name=?", (table,)).fetchone()
        seq = r[0] if r else None
    except sqlite3.Error:
        pass
    return {"browser": browser, "table": table, "count": cnt, "min_id": mn, "max_id": mx, "seq": seq}


# ----------------------------------------------------------------- collectors
def collect_chromium(db: Path, browser: str, label: str):
    events, meta = [], []
    con = _connect(db)
    for r in con.execute("SELECT v.visit_time, u.url, u.title FROM visits v "
                         "JOIN urls u ON u.id = v.url"):
        events.append(new_event(ts=webkit_to_dt(r["visit_time"]), source=browser, browser=browser,
                                artifact_type="visit", url=r["url"], title=r["title"],
                                source_file=label))
    try:
        for r in con.execute("SELECT k.term, u.url, v.visit_time FROM keyword_search_terms k "
                             "JOIN urls u ON u.id = k.url_id JOIN visits v ON v.url = u.id"):
            events.append(new_event(ts=webkit_to_dt(r["visit_time"]), source=browser, browser=browser,
                                    artifact_type="search", url=r["url"], detail=r["term"],
                                    source_file=label))
    except sqlite3.Error:
        pass
    try:
        for r in con.execute("SELECT * FROM downloads"):
            d = dict(r)
            final_url = None
            try:
                row = con.execute("SELECT url FROM downloads_url_chains WHERE id=? "
                                  "ORDER BY chain_index DESC LIMIT 1", (d["id"],)).fetchone()
                final_url = row["url"] if row else None
            except sqlite3.Error:
                pass
            path = d.get("target_path") or d.get("current_path")
            events.append(new_event(ts=webkit_to_dt(d.get("start_time")), source=browser,
                                    browser=browser, artifact_type="download", url=final_url,
                                    referrer=d.get("referrer") or d.get("tab_url"),
                                    file_path=path, file_name=basename(path),
                                    detail=f"{d.get('total_bytes', '?')} bytes", source_file=label))
    except sqlite3.Error:
        pass
    for t in ("visits", "urls", "downloads"):
        m = _id_meta(con, browser, t)
        if m:
            meta.append(m)
    con.close()
    return events, meta


def _file_uri_to_path(uri: str) -> str:
    p = unquote(uri)
    if p.startswith("file:///"):
        p = p[8:]
    return p.replace("/", "\\")


def collect_firefox(db: Path, label: str):
    events, meta = [], []
    con = _connect(db)
    dl_path = {}
    try:
        for r in con.execute("SELECT a.place_id, a.content FROM moz_annos a JOIN moz_anno_attributes n "
                             "ON n.id = a.anno_attribute_id WHERE n.name = 'downloads/destinationFileURI'"):
            dl_path[r["place_id"]] = _file_uri_to_path(r["content"])
    except sqlite3.Error:
        pass
    for r in con.execute("SELECT h.visit_date, h.visit_type, p.id AS pid, p.url, p.title "
                         "FROM moz_historyvisits h JOIN moz_places p ON p.id = h.place_id"):
        ts = prtime_to_dt(r["visit_date"])
        if r["visit_type"] == 7:                                   # TRANSITION_DOWNLOAD
            path = dl_path.get(r["pid"])
            events.append(new_event(ts=ts, source="firefox", browser="firefox",
                                    artifact_type="download", url=r["url"], file_path=path,
                                    file_name=basename(path) or basename(r["url"].split("?")[0]),
                                    source_file=label))
            continue
        events.append(new_event(ts=ts, source="firefox", browser="firefox", artifact_type="visit",
                                url=r["url"], title=r["title"], source_file=label))
        term = parse_search_url(r["url"])
        if term:
            events.append(new_event(ts=ts, source="firefox", browser="firefox",
                                    artifact_type="search", url=r["url"], detail=term,
                                    source_file=label))
    m = _id_meta(con, "firefox", "moz_historyvisits")
    if m:
        meta.append(m)
    con.close()
    return events, meta


def collect_timeline(db: Path, label: str):
    """Windows 10 Timeline: which application was in focus, and when."""
    events = []
    con = _connect(db)
    for r in con.execute("SELECT AppId, Payload, StartTime, ActivityType FROM Activity"):
        try:
            apps = json.loads(r["AppId"])
            app = next((a["application"] for a in apps if a.get("platform") == "windows_win32"),
                       apps[0]["application"])
        except (ValueError, KeyError, IndexError, TypeError):
            continue
        text = None
        try:
            payload = r["Payload"]
            payload = payload.decode("utf-8", "ignore") if isinstance(payload, bytes) else payload
            text = json.loads(payload).get("displayText")
        except (ValueError, AttributeError, TypeError):
            pass
        exe = basename(app).lower()
        events.append(new_event(ts=unix_to_dt(r["StartTime"]), source="timeline", artifact_type="activity",
                                process=exe, file_path=app, file_name=exe, detail=text,
                                source_file=label))
    con.close()
    return events


def collect_prefetch_csv(path: Path, label: str):
    """PECmd-style CSV: ExecutableName, RunCount, LastRun, PreviousRun0..6, FilesLoaded."""
    df = pd.read_csv(path, dtype=str).fillna("")
    cols = {c.lower(): c for c in df.columns}
    exe_c, last_c = cols.get("executablename"), cols.get("lastrun")
    if not exe_c or not last_c:
        raise ValueError(f"{path.name}: needs ExecutableName and LastRun columns")
    prev_cols = [c for c in df.columns if c.lower().startswith("previousrun")]
    events = []
    for _, row in df.iterrows():
        exe = row[exe_c].strip()
        exe_path = None
        for f in str(row.get(cols.get("filesloaded", ""), "")).split(","):
            if basename(f).lower() == exe.lower():
                exe_path = f.strip()
                break
        for c in [last_c] + prev_cols:
            if row[c].strip():
                events.append(new_event(ts=pd.to_datetime(row[c]).to_pydatetime(),
                                        ts_tz="UTC" if pd.to_datetime(row[c]).tzinfo else "LOCAL",
                                        source="prefetch", artifact_type="execution", process=exe.lower(),
                                        file_name=exe, file_path=exe_path,
                                        detail=f"run count {row.get(cols.get('runcount', ''), '?')}",
                                        source_file=label))
    return events


def collect_dns_csv(path: Path, label: str):
    """DNS client log export (e.g. Sysmon event 22): timestamp, domain, [qtype], [process]."""
    df = pd.read_csv(path, dtype=str).fillna("")
    cols = {c.lower(): c for c in df.columns}
    t = next((cols[c] for c in cols if "time" in c), None)
    d = next((cols[c] for c in cols if c in ("domain", "queryname", "name", "query")), None)
    p = next((cols[c] for c in cols if c in ("process", "image", "processname")), None)
    if not t or not d:
        raise ValueError(f"{path.name}: needs a timestamp column and a domain column")
    events = []
    for _, row in df.iterrows():
        ts = pd.to_datetime(row[t])
        proc = basename(row[p]).lower() if p else None
        events.append(new_event(ts=ts.to_pydatetime(), ts_tz="UTC" if ts.tzinfo else "LOCAL",
                                source="dns", artifact_type="dns", process=proc or None,
                                browser=BROWSER_EXES.get(proc or ""), url=None,
                                detail=row[d].strip().lower(), source_file=label))
    return events


# --------------------------------------------------------------------- driver
def collect_all(evidence_dir: str | Path, work_dir: str | Path, items=None):
    """Acquire + parse everything. Returns (events DataFrame, custody manifest, id-meta list)."""
    evidence_dir, work_dir = Path(evidence_dir), Path(work_dir)
    items = items if items is not None else discover(evidence_dir)
    events, manifest, meta, errors = [], [], [], []
    for kind, browser, src in items:
        try:
            copy, entry = acquire(src, work_dir, kind)
            manifest.append(entry)
            if kind == "chromium":
                ev, m = collect_chromium(copy, browser, src.name)
                meta += m
            elif kind == "firefox":
                ev, m = collect_firefox(copy, src.name)
                meta += m
            elif kind == "timeline":
                ev = collect_timeline(copy, src.name)
            elif kind == "prefetch":
                ev = collect_prefetch_csv(copy, src.name)
            else:
                ev = collect_dns_csv(copy, src.name)
            entry["events_extracted"] = len(ev)
            events += ev
        except Exception as exc:                                  # keep going on a bad source
            errors.append({"kind": kind, "source_path": str(src), "error": str(exc)})
    df = pd.DataFrame(events)
    df.attrs["errors"] = errors
    return df, manifest + [{"kind": "error", **e} for e in errors], meta
