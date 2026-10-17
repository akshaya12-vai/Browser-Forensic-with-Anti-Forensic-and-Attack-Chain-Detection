"""MODULE 6 - MITRE ATT&CK Mapping (indicative; the investigator validates every tag)."""
from __future__ import annotations

import pandas as pd

from .heuristics import domain_flags, is_trusted
from .schema import BROWSER_EXES

TECHNIQUES = {
    "T1189": ("Drive-by Compromise", "Initial Access"),
    "T1105": ("Ingress Tool Transfer", "Command and Control"),
    "T1204.002": ("User Execution: Malicious File", "Execution"),
    "T1071.001": ("Application Layer Protocol: Web Protocols", "Command and Control"),
    "T1070": ("Indicator Removal", "Defense Evasion"),
}


def _step(stage, row, tid, why, confidence):
    name, tactic = TECHNIQUES[tid]
    return {"stage": stage, "event_id": row["event_id"], "ts": row["ts"], "technique_id": tid,
            "technique": name, "tactic": tactic, "rationale": why, "confidence": confidence}


def map_chain(chain: dict, tl: pd.DataFrame, findings: list[dict], ioc=frozenset()) -> list[dict]:
    ev = tl[tl.event_id.isin(chain["event_ids"])].copy()
    stage_by_id = dict(zip(chain["event_ids"], chain["stages"]))
    exec_to_dns = {e["dst"] for e in chain["edges"] if e["rule"] == "exec_to_dns"}
    steps = []
    for _, r in ev.iterrows():
        st = stage_by_id.get(r["event_id"])
        flags = domain_flags(r["domain"], ioc) if r["domain"] and not is_trusted(r["domain"]) else []
        if st == "Download" and r["is_executable"]:
            steps.append(_step(st, r, "T1105", f"executable {r['file_name']} downloaded", "high"))
        if st == "Visit" and flags:
            steps.append(_step(st, r, "T1189", f"visited {r['domain']} ({'; '.join(flags)})", "low"))
        if st == "Delivery (from DNS)" and flags:
            steps.append(_step(st, r, "T1189", f"browser resolved {r['domain']} ({'; '.join(flags)}); "
                                               "visit reconstructed from DNS", "low"))
        if st == "Execution":
            steps.append(_step(st, r, "T1204.002", f"{r['file_name']} executed (Prefetch)", "medium"))
        if st == "Network" and r["event_id"] in exec_to_dns:
            steps.append(_step(st, r, "T1071.001", f"{r['process']} resolved {r['domain']}"
                                                   " - confirm with traffic capture", "low"))
        if st == "Cleanup":
            steps.append(_step(st, r, "T1070", f"{r['file_name']} executed after the program", "medium"))
    for f in findings:
        if f["finding_id"] in chain["finding_ids"] and f["kind"] in ("deleted_records", "history_gap"):
            anchor = ev.iloc[-1]
            steps.append({"stage": "Cleanup (inferred)", "event_id": f["evidence"][0] if f["evidence"] else anchor["event_id"],
                          "ts": f["ts"], "technique_id": "T1070", "technique": TECHNIQUES["T1070"][0],
                          "tactic": TECHNIQUES["T1070"][1], "rationale": f["title"], "confidence": "medium"})
    return sorted(steps, key=lambda s: s["ts"])
