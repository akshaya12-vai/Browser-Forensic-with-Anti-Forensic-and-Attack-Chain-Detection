"""Runs Modules 1-8 end to end."""
from __future__ import annotations

from pathlib import Path

from . import (m1_collect, m2_timeline, m3_correlate, m4_antiforensic, m5_chains, m6_mitre,
               m7_risk, m8_report)
from .heuristics import load_ioc


def run(evidence_dir, out_dir, tz_offset_minutes: int = 0, ioc_file=None, live: bool = False) -> dict:
    out_dir = Path(out_dir)
    items = m1_collect.live_windows_paths() if live else None
    raw, manifest, meta = m1_collect.collect_all(evidence_dir or ".", out_dir / "working_copies", items)   # M1
    tl = m2_timeline.build_timeline(raw, tz_offset_minutes)                                               # M2
    edges = m3_correlate.correlate(tl)                                                                    # M3
    findings = m4_antiforensic.detect(tl, meta) if len(tl) else []                                        # M4
    gaps = m3_correlate.history_gap_windows(tl)
    chains = m5_chains.build_chains(tl, edges, findings, gaps)                                            # M5
    ioc = load_ioc(ioc_file)
    anomalies = m7_risk.anomalous_events(tl) if len(tl) else {}
    for c in chains:
        c["attack_steps"] = m6_mitre.map_chain(c, tl, findings, ioc)                                      # M6
        c["risk"] = m7_risk.score_chain(c, tl, findings, anomalies, ioc)                                  # M7
    m8_report.write_outputs(out_dir, tl, edges, findings, chains, manifest, meta)                         # M8
    return {"timeline": tl, "edges": edges, "findings": findings, "chains": chains,
            "manifest": manifest, "meta": meta, "out_dir": out_dir}
