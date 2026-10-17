"""MODULE 3 - Cross-Source Correlation.

Links events that share a domain, URL, file name, process or a tight time window.
Output is an edge list; every edge says WHY two events are linked and how strongly.
"""
from __future__ import annotations

import pandas as pd

from .schema import BROWSER_EXES, KNOWN_BENIGN_EXES, SEARCH_ENGINES, registrable

SEARCH_TO_VISIT_S = 300
VISIT_TO_DOWNLOAD_S = 900
DOWNLOAD_TO_EXEC_S = 7 * 86400
CLEANUP_AFTER_EXEC_S = 2 * 3600
GAP_CONTEXT_S = 600          # DNS counts as "explained" if history exists within +/- 10 min
GAP_MERGE_S = 600
DELIVERY_TO_EXEC_S = 900


def history_gap_windows(tl: pd.DataFrame) -> list[dict]:
    """Browser DNS lookups with NO browser-history row nearby = possible deleted history.

    Using a time window (not per-domain matching) avoids flagging ads/CDN lookups that
    pages trigger but that never appear as separate history rows.
    """
    if tl.empty:
        return []
    hist = tl[tl.category.isin(["visit", "search", "download"])]
    hist_ts = {b: g["ts"].tolist() for b, g in hist.groupby("browser")}
    dns = tl[(tl.category == "dns") & tl["process"].isin(BROWSER_EXES)]
    flagged = []
    for _, r in dns.iterrows():
        near = hist_ts.get(r["browser"], [])
        if not any(abs((t - r["ts"]).total_seconds()) <= GAP_CONTEXT_S for t in near):
            flagged.append(r)
    windows: list[dict] = []
    for r in sorted(flagged, key=lambda x: x["ts"]):
        w = windows[-1] if windows else None
        if w and w["browser"] == r["browser"] and (r["ts"] - w["end"]).total_seconds() <= GAP_MERGE_S:
            w["end"] = r["ts"]
            w["dns_ids"].append(r["event_id"])
            w["domains"].append(r["domain"])
        else:
            windows.append({"browser": r["browser"], "start": r["ts"], "end": r["ts"],
                            "dns_ids": [r["event_id"]], "domains": [r["domain"]]})
    for w in windows:
        w["domains"] = sorted(set(w["domains"]))
    return windows


def interesting_execs(tl: pd.DataFrame) -> pd.DataFrame:
    """Executions worth chaining: matched to a download, or launched from a user-writable folder."""
    ex = tl[tl.category == "execution"]
    dl_names = set(tl[tl.category == "download"]["file_name"].dropna().str.lower())
    keep = [(r["file_name"] or "").lower() not in KNOWN_BENIGN_EXES and
            ((r["file_name"] or "").lower() in dl_names or bool(r["user_space"]))
            for _, r in ex.iterrows()]
    return ex[keep]


def correlate(tl: pd.DataFrame) -> pd.DataFrame:
    edges: list[dict] = []

    def link(a, b, rule, reason, strength):
        edges.append({"src": a, "dst": b, "rule": rule, "reason": reason, "strength": strength})

    if tl.empty:
        return pd.DataFrame(columns=["src", "dst", "rule", "reason", "strength"])
    sec = lambda a, b: (b - a).total_seconds()

    # R1 search -> first non-search-engine visit shortly after, same browser
    visits = tl[tl.category == "visit"]
    for _, s in tl[tl.category == "search"].iterrows():
        nxt = visits[(visits.browser == s["browser"]) & (visits.ts > s["ts"]) &
                     (~visits.registrable.isin(SEARCH_ENGINES))]
        nxt = nxt[(nxt.ts - s["ts"]).dt.total_seconds() <= SEARCH_TO_VISIT_S].head(1)
        for _, v in nxt.iterrows():
            link(s["event_id"], v["event_id"], "search_to_visit",
                 f"visited {v['domain']} {sec(s['ts'], v['ts']):.0f}s after the search", 0.6)

    # R2 visit -> download (download came from the page just visited)
    downloads = tl[tl.category == "download"]
    for _, d in downloads.iterrows():
        dom = {registrable(x) for x in (d["domain"], registrable_from_ref(d["referrer"])) if x}
        cand = visits[(visits.browser == d["browser"]) & (visits.ts <= d["ts"]) &
                      visits.registrable.isin(dom)]
        cand = cand[(d["ts"] - cand.ts).dt.total_seconds() <= VISIT_TO_DOWNLOAD_S].tail(1)
        for _, v in cand.iterrows():
            link(v["event_id"], d["event_id"], "visit_to_download",
                 f"download from {v['registrable']} within {sec(v['ts'], d['ts']):.0f}s of the visit", 0.8)

    # R3 download -> execution (same file name, execution after download)
    execs = tl[tl.category == "execution"]
    for _, d in downloads.iterrows():
        name = (d["file_name"] or "").lower()
        if not name:
            continue
        m = execs[(execs.file_name.str.lower() == name) & (execs.ts >= d["ts"] - pd.Timedelta(seconds=60))]
        m = m[(m.ts - d["ts"]).dt.total_seconds() <= DOWNLOAD_TO_EXEC_S]
        for _, e in m.iterrows():
            link(d["event_id"], e["event_id"], "download_to_execution",
                 f"{d['file_name']} downloaded, then executed (Prefetch)", 0.9)

    inter = interesting_execs(tl)
    dns = tl[tl.category == "dns"]
    act = tl[tl.category == "activity"]
    cleanup = tl[tl.category == "cleanup"]
    for _, e in inter.iterrows():
        name = (e["file_name"] or "").lower()
        # R4 execution -> DNS lookups made BY that process
        for _, q in dns[(dns["process"] == name) & (dns.ts >= e["ts"] - pd.Timedelta(seconds=5))].iterrows():
            link(e["event_id"], q["event_id"], "exec_to_dns",
                 f"{name} itself resolved {q['domain']}", 0.9)
        # R4b execution -> Windows Timeline focus on same program
        for _, a in act[(act["process"] == name) & ((act.ts - e["ts"]).dt.total_seconds().between(-60, 3600))].iterrows():
            link(e["event_id"], a["event_id"], "exec_to_activity", "program in focus (Windows Timeline)", 0.7)
        # R5 execution -> cleanup tool run within 2 h
        for _, c in cleanup[((cleanup.ts - e["ts"]).dt.total_seconds().between(0, CLEANUP_AFTER_EXEC_S))].iterrows():
            link(e["event_id"], c["event_id"], "exec_to_cleanup",
                 f"{c['file_name']} ran {sec(e['ts'], c['ts']) / 60:.0f} min after execution", 0.5)

    # R6 browser DNS with no history (deleted visit) -> execution shortly after
    for w in history_gap_windows(tl):
        for _, e in inter[((inter.ts - w["end"]).dt.total_seconds().between(0, DELIVERY_TO_EXEC_S))].iterrows():
            for qid in w["dns_ids"]:
                link(qid, e["event_id"], "reconstructed_delivery",
                     "browser lookup with no history row, followed by this execution", 0.5)
    return pd.DataFrame(edges, columns=["src", "dst", "rule", "reason", "strength"]).drop_duplicates()


def registrable_from_ref(ref):
    from .schema import host_of
    return registrable(host_of(ref)) if ref else ""
