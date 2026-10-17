"""MODULE 4 - Anti-Forensic Detection.

Compares what the browsers still say with what the rest of Windows says.
Every finding lists the evidence it rests on and why it might be innocent.
"""
from __future__ import annotations

import pandas as pd

from .m3_correlate import history_gap_windows, interesting_execs
from .schema import BROWSER_EXES, CLEANUP_TOOLS


def _finding(kind, ts, severity, title, desc, evidence, caveat, ts_end=None):
    return {"kind": kind, "ts": ts, "ts_end": ts_end or ts, "severity": round(severity, 2),
            "title": title, "description": desc, "evidence": evidence, "caveat": caveat,
            "technique": "T1070"}


def detect(tl: pd.DataFrame, meta: list[dict]) -> list[dict]:
    out: list[dict] = []
    t0 = tl.ts.min() if not tl.empty else pd.Timestamp.now(tz="UTC")

    # A. Missing database rows (SQLite auto-increment ids that no longer exist)
    for m in meta:
        if m["table"] not in ("visits", "moz_historyvisits") or not m["count"]:
            continue
        interior = (m["max_id"] - m["min_id"] + 1) - m["count"]
        tail = (m["seq"] - m["max_id"]) if m["seq"] else 0
        if interior > 0 or tail > 0:
            ratio = (interior + tail) / max(m["seq"] or m["max_id"], 1)
            sev = 0.9 if ratio > 0.25 else 0.6 if ratio > 0.05 else 0.35
            out.append(_finding(
                "deleted_records", t0, sev, f"{m['browser']}: history rows deleted",
                f"{m['table']} ids run {m['min_id']}..{m['max_id']} but only {m['count']} rows remain: "
                f"{interior} missing inside the range (selective deletion), {tail} missing at the end.",
                [], "Chrome also expires visits older than ~90 days from the START of the table; "
                    "only interior/tail gaps point to selective deletion."))

    # B. Browser DNS lookups with no matching history  -> history cleared for that window
    for w in history_gap_windows(tl):
        out.append(_finding(
            "history_gap", w["start"], 0.8, f"{w['browser']}: activity with no history",
            f"{w['browser']} resolved {', '.join(w['domains'])} between {w['start']:%H:%M:%S} and "
            f"{w['end']:%H:%M:%S} UTC, but no history row exists within 10 minutes.",
            w["dns_ids"], "Private/incognito browsing leaves DNS traces but no history.", ts_end=w["end"]))

    # C. Trace-wiping tools executed
    for _, c in tl[tl.category == "cleanup"].iterrows():
        sev = CLEANUP_TOOLS.get((c["file_name"] or "").lower(), 0.5)
        out.append(_finding("cleanup_tool", c["ts"], sev, f"{c['file_name']} executed",
                            f"Trace-cleaning tool {c['file_name']} ran at {c['ts']:%Y-%m-%d %H:%M:%S} UTC ({c['detail']}).", [c["event_id"]],
                            "Cleanup tools are also used for legitimate disk maintenance."))

    # D. Program launched from Downloads/Temp with no browser download record
    dl_names = set(tl[tl.category == "download"]["file_name"].dropna().str.lower())
    for _, e in interesting_execs(tl).iterrows():
        if (e["file_name"] or "").lower() not in dl_names and e["user_space"]:
            out.append(_finding("download_record_missing", e["ts"], 0.7,
                                f"{e['file_name']} has no download record",
                                f"{e['file_name']} ran from {e['file_path']} but no browser recorded downloading it.",
                                [e["event_id"]], "File may have arrived via USB, e-mail or another browser profile."))

    # E. Browser was in use before its oldest remaining history row
    for exe, browser in BROWSER_EXES.items():
        sys_ev = tl[(tl["process"] == exe) & tl.category.isin(["dns", "activity", "execution"])]
        hist = tl[(tl.browser == browser) & tl.category.isin(["visit", "search", "download"])]
        if sys_ev.empty or hist.empty:
            continue
        if (hist.ts.min() - sys_ev.ts.min()) > pd.Timedelta(hours=24):
            out.append(_finding("history_truncated_before", sys_ev.ts.min(), 0.5,
                                f"{browser}: history starts late",
                                f"System evidence shows {browser} in use from {sys_ev.ts.min():%Y-%m-%d %H:%M} UTC but "
                                f"the oldest history row is {hist.ts.min():%Y-%m-%d %H:%M} UTC.",
                                list(sys_ev.event_id.head(5)), "Normal if history was auto-expired or the profile is new."))
    for i, f in enumerate(sorted(out, key=lambda x: x["ts"]), 1):
        f["finding_id"] = f"F{i:02d}"
    return sorted(out, key=lambda x: x["ts"])
