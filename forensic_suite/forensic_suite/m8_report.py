"""MODULE 8 - Report & Investigator Dashboard data layer.

Writes machine-readable outputs, an evidence-linked HTML report, and stores the
investigator's accept / reject / note decisions (the human stays in control).
"""
from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

DECISIONS_FILE = "decisions.json"


def _json(obj):
    return json.dumps(obj, indent=2, default=lambda o: o.isoformat() if hasattr(o, "isoformat") else str(o))


def load_decisions(out_dir: Path) -> dict:
    p = Path(out_dir) / DECISIONS_FILE
    return json.loads(p.read_text()) if p.exists() else {}


def save_decision(out_dir: Path, chain_id: str, decision: str, note: str, analyst: str = "") -> None:
    d = load_decisions(out_dir)
    d[chain_id] = {"decision": decision, "note": note, "analyst": analyst,
                   "decided_utc": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    (Path(out_dir) / DECISIONS_FILE).write_text(_json(d))


def write_outputs(out_dir: Path, tl, edges, findings, chains, manifest, meta) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    tl.to_csv(out_dir / "timeline.csv", index=False)
    edges.to_csv(out_dir / "correlations.csv", index=False)
    (out_dir / "findings.json").write_text(_json(findings))
    (out_dir / "chains.json").write_text(_json(chains))
    (out_dir / "custody_manifest.json").write_text(_json(manifest))
    (out_dir / "id_meta.json").write_text(_json(meta))
    write_html_report(out_dir, tl, findings, chains, manifest)


def _e(x) -> str:
    return html.escape("" if x is None else str(x))


def write_html_report(out_dir: Path, tl, findings, chains, manifest) -> Path:
    decisions = load_decisions(out_dir)
    ev = tl.set_index("event_id", drop=False)
    fmap = {f["finding_id"]: f for f in findings}
    css = ("body{font-family:Segoe UI,Arial,sans-serif;margin:32px;color:#1c1c1c;max-width:1100px}"
           "table{border-collapse:collapse;width:100%;margin:8px 0 18px;font-size:13px}"
           "th,td{border:1px solid #ccc;padding:5px 8px;text-align:left;vertical-align:top}"
           "th{background:#f0f2f5}.High{background:#c0392b}.Medium{background:#d68910}.Low{background:#2e8b57}"
           ".badge{color:#fff;padding:2px 10px;border-radius:10px;font-weight:600}"
           ".note{background:#fff8e1;border-left:4px solid #d68910;padding:8px 12px;margin:12px 0}"
           "h2{border-bottom:2px solid #1f3a5f;padding-bottom:4px;margin-top:34px}code{font-size:12px}")
    p = [f"<html><head><meta charset='utf-8'><title>Browser Forensic Report</title><style>{css}</style></head><body>",
         "<h1>Browser Forensic Report</h1>",
         f"<p>Generated {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC &middot; {len(tl)} events from "
         f"{tl.source.nunique() if len(tl) else 0} source types &middot; {len(chains)} attack chain(s) &middot; "
         f"{len(findings)} anti-forensic finding(s)</p>",
         "<div class='note'><b>Important:</b> scores, ATT&amp;CK tags and findings are automated leads. "
         "The investigator makes the final decision on every chain.</div>",
         "<h2>1. Summary</h2><table><tr><th>Chain</th><th>Score</th><th>Stages</th><th>Window (UTC)</th>"
         "<th>Investigator decision</th></tr>"]
    for c in sorted(chains, key=lambda c: -c["risk"]["score"]):
        d = decisions.get(c["chain_id"], {})
        p.append(f"<tr><td>{c['chain_id']}</td><td><span class='badge {c['risk']['level']}'>{c['risk']['score']} "
                 f"{c['risk']['level']}</span></td><td>{_e(c['summary'])}</td><td>{c['start']:%Y-%m-%d %H:%M} &rarr; "
                 f"{c['end']:%H:%M}</td><td>{_e(d.get('decision', 'pending'))}</td></tr>")
    p.append("</table>")
    for c in sorted(chains, key=lambda c: -c["risk"]["score"]):
        d = decisions.get(c["chain_id"], {})
        p.append(f"<h2>Chain {c['chain_id']} &mdash; <span class='badge {c['risk']['level']}'>{c['risk']['score']}/100 "
                 f"{c['risk']['level']}</span></h2><p><b>{_e(c['summary'])}</b></p>")
        p.append("<h3>Why this score</h3><table><tr><th>Points</th><th>Reason</th><th>Evidence</th></tr>")
        for s in c["risk"]["signals"]:
            p.append(f"<tr><td>{s['points']:+d}</td><td>{_e(s['reason'])}</td><td>{_e(', '.join(s['evidence']))}</td></tr>")
        p.append(f"</table><p>Raw total {c['risk']['raw_points']}, capped to 0&ndash;100.</p>")
        p.append("<h3>ATT&amp;CK mapping (indicative)</h3><table><tr><th>Time (UTC)</th><th>Stage</th><th>Technique</th>"
                 "<th>Tactic</th><th>Basis</th><th>Confidence</th></tr>")
        for s in c["attack_steps"]:
            p.append(f"<tr><td>{s['ts']:%H:%M:%S}</td><td>{_e(s['stage'])}</td><td>{s['technique_id']} {_e(s['technique'])}</td>"
                     f"<td>{_e(s['tactic'])}</td><td>{_e(s['rationale'])}</td><td>{s['confidence']}</td></tr>")
        p.append("</table><h3>Evidence timeline</h3><table><tr><th>ID</th><th>Time (UTC)</th><th>Stage</th><th>Source</th>"
                 "<th>Event</th><th>Source file</th></tr>")
        for eid, st in zip(c["event_ids"], c["stages"]):
            r = ev.loc[eid]
            p.append(f"<tr><td>{eid}</td><td>{r['ts']:%Y-%m-%d %H:%M:%S}</td><td>{_e(st or 'supporting')}</td>"
                     f"<td>{_e(r['source'])}</td><td>{_e(r['summary'])}</td><td>{_e(r['source_file'])}</td></tr>")
        p.append("</table>")
        for fid in c["finding_ids"]:
            f = fmap[fid]
            p.append(f"<p><b>{fid} {_e(f['title'])}</b> (severity {f['severity']}): {_e(f['description'])}<br>"
                     f"<i>Could also be innocent: {_e(f['caveat'])}</i></p>")
        p.append(f"<p><b>Investigator decision:</b> {_e(d.get('decision', 'pending'))} "
                 f"{('&mdash; ' + _e(d['note'])) if d.get('note') else ''} "
                 f"{('(' + _e(d['analyst']) + ', ' + _e(d['decided_utc']) + ')') if d.get('analyst') else ''}</p>")
    p.append("<h2>Anti-forensic findings</h2><table><tr><th>ID</th><th>Kind</th><th>Severity</th><th>Detail</th></tr>")
    for f in findings:
        p.append(f"<tr><td>{f['finding_id']}</td><td>{f['kind']}</td><td>{f['severity']}</td><td>{_e(f['description'])}</td></tr>")
    p.append("</table><h2>Chain of custody</h2><table><tr><th>Source</th><th>SHA-256 (original)</th><th>Copy matches</th></tr>")
    for m in manifest:
        if m.get("kind") == "error":
            p.append(f"<tr><td>{_e(m['source_path'])}</td><td colspan=2>ERROR: {_e(m['error'])}</td></tr>")
        else:
            p.append(f"<tr><td>{_e(m['source_path'])}</td><td><code>{m['sha256']}</code></td>"
                     f"<td>{'yes' if m['verified'] else 'NO'}</td></tr>")
    p.append("</table><h2>Method &amp; limitations</h2><ul>"
             "<li>All sources were hashed, copied and parsed from the copy; the original hash was re-checked afterwards.</li>"
             "<li>Deleted-row detection relies on SQLite row ids; VACUUM or profile reset can hide deletions.</li>"
             "<li>DNS evidence needs a DNS log that records the querying process (e.g. Sysmon event 22).</li>"
             "<li>Risk scoring is rule-weighted; the Isolation Forest only adds a small, labelled signal.</li>"
             "<li>ATT&amp;CK tags are indicative and must be validated with other evidence.</li></ul></body></html>")
    path = out_dir / "report.html"
    path.write_text("\n".join(p), encoding="utf-8")
    return path
