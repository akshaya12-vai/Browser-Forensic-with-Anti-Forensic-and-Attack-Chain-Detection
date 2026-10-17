"""MODULE 5 - Attack-Chain Reconstruction.

Groups correlated events (connected components of the Module-3 edge graph) into ordered
chains:  Search -> Visit/Delivery -> Download -> Execution -> Network -> Cleanup.
"""
from __future__ import annotations

import pandas as pd

from .schema import BROWSER_EXES

STAGE_ORDER = ["Search", "Visit", "Delivery (from DNS)", "Download", "Execution", "Network",
               "Cleanup"]
FINDING_MARGIN = pd.Timedelta(minutes=15)


def stage_of(row, gap_dns_ids: set) -> str | None:
    c = row["category"]
    if c == "search":
        return "Search"
    if c == "visit":
        return "Visit"
    if c == "download":
        return "Download"
    if c == "execution":
        return "Execution"
    if c == "cleanup":
        return "Cleanup"
    if c == "dns":
        return "Delivery (from DNS)" if row["event_id"] in gap_dns_ids else "Network"
    return None                                  # 'activity' rows only support other stages


def build_chains(tl: pd.DataFrame, edges: pd.DataFrame, findings: list[dict],
                 gap_windows: list[dict]) -> list[dict]:
    if edges.empty:
        return []
    parent: dict[str, str] = {}

    def find(x):
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for a, b in zip(edges.src, edges.dst):
        parent[find(a)] = find(b)
    groups: dict[str, set] = {}
    for n in list(parent):
        groups.setdefault(find(n), set()).add(n)

    gap_ids = {i for w in gap_windows for i in w["dns_ids"]}
    by_id = tl.set_index("event_id", drop=False)
    chains = []
    for members in groups.values():
        ev = by_id.loc[sorted(members)].sort_values("ts")
        if not ev.category.isin(["execution", "download"]).any() or len(ev) < 2:
            continue
        stages = [stage_of(r, gap_ids) for _, r in ev.iterrows()]
        ev = ev.assign(stage=stages)
        path = [s for s in STAGE_ORDER if s in set(stages)]
        start, end = ev.ts.min(), ev.ts.max()
        ids = set(ev.event_id)
        attached = [f["finding_id"] for f in findings
                    if set(f["evidence"]) & ids or (start - FINDING_MARGIN <= f["ts"] <= end + FINDING_MARGIN
                                                    and f["kind"] != "deleted_records")]
        # deleted_records has no timestamp of its own: attach it when a history_gap is attached
        gap_f = {f["finding_id"] for f in findings if f["kind"] == "history_gap"}
        if gap_f & set(attached):
            attached += [f["finding_id"] for f in findings if f["kind"] == "deleted_records"
                         and f["finding_id"] not in attached]
        chain_edges = edges[edges.src.isin(ids) & edges.dst.isin(ids)]
        chains.append({"event_ids": list(ev.event_id), "stages": list(stages), "stage_path": path,
                       "start": start, "end": end, "finding_ids": attached,
                       "edges": chain_edges.to_dict("records")})
    chains.sort(key=lambda c: c["start"])
    for i, c in enumerate(chains, 1):
        c["chain_id"] = f"C{i:02d}"
        c["summary"] = " \u2192 ".join(c["stage_path"])
    return chains
