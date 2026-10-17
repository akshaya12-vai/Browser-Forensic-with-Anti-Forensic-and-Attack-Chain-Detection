"""MODULE 8 - Investigator dashboard.   Run:  streamlit run dashboard.py"""
import json
import tempfile
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

from forensic_suite import m8_report
from forensic_suite.pipeline import run
from forensic_suite.sample_data import make_sample

st.set_page_config(page_title="Browser Forensics", layout="wide")
st.title("AI-assisted multi-browser forensic dashboard")
st.caption("Scores and tags are leads. The investigator makes the final decision.")

out = Path(st.sidebar.text_input("Output folder", "output"))
st.sidebar.subheader("Run analysis")
evidence = st.sidebar.text_input("Evidence folder", "sample_evidence")
tz = st.sidebar.number_input("Local-time CSV offset from UTC (minutes)", value=0, step=30)
if st.sidebar.button("Use synthetic sample evidence"):
    make_sample(evidence)
    st.sidebar.success(f"Sample evidence written to {evidence}")
if st.sidebar.button("Run Modules 1-8", type="primary"):
    with st.spinner("Analysing..."):
        run(evidence, out, int(tz))
    st.sidebar.success("Done")
analyst = st.sidebar.text_input("Analyst name")

if not (out / "chains.json").exists():
    st.info("No results yet. Use the sidebar: create sample evidence (or point to your own), then run.")
    st.stop()

tl = pd.read_csv(out / "timeline.csv", parse_dates=["ts"])
chains = json.loads((out / "chains.json").read_text())
findings = json.loads((out / "findings.json").read_text())
manifest = json.loads((out / "custody_manifest.json").read_text())
decisions = m8_report.load_decisions(out)

c1, c2, c3, c4 = st.columns(4)
c1.metric("Events", len(tl))
c2.metric("Attack chains", len(chains))
c3.metric("Anti-forensic findings", len(findings))
c4.metric("Highest score", max((c["risk"]["score"] for c in chains), default=0))

t_time, t_chain, t_find, t_cust, t_rep = st.tabs(
    ["Unified timeline", "Attack chains", "Anti-forensic findings", "Chain of custody", "Report"])

with t_time:
    srcs = st.multiselect("Sources", sorted(tl.source.unique()), default=sorted(tl.source.unique()))
    cats = st.multiselect("Categories", sorted(tl.category.unique()), default=sorted(tl.category.unique()))
    view = tl[tl.source.isin(srcs) & tl.category.isin(cats)]
    st.altair_chart(alt.Chart(view).mark_circle(size=90).encode(
        x="ts:T", y="source:N", color="category:N", tooltip=["event_id", "ts", "summary", "source_file"]
    ).properties(height=260).interactive(), width="stretch")
    st.dataframe(view[["event_id", "ts", "source", "category", "summary", "source_file"]], width="stretch")

with t_chain:
    for c in sorted(chains, key=lambda c: -c["risk"]["score"]):
        d = decisions.get(c["chain_id"], {})
        icon = {"High": "\U0001F534", "Medium": "\U0001F7E0", "Low": "\U0001F7E2"}[c["risk"]["level"]]
        with st.expander(f"{icon} {c['chain_id']}  |  score {c['risk']['score']}  |  {c['summary']}  |  "
                         f"decision: {d.get('decision', 'pending')}", expanded=c["risk"]["level"] == "High"):
            st.markdown("**Why this score**")
            st.dataframe(pd.DataFrame([{"points": f"{s['points']:+d}", "reason": s["reason"],
                                        "evidence": ", ".join(s["evidence"])} for s in c["risk"]["signals"]]),
                         width="stretch", hide_index=True)
            st.markdown("**ATT&CK mapping (indicative)**")
            st.dataframe(pd.DataFrame([{"time": s["ts"][11:19], "stage": s["stage"],
                                        "technique": f"{s['technique_id']} {s['technique']}",
                                        "basis": s["rationale"], "confidence": s["confidence"]}
                                       for s in c["attack_steps"]]), width="stretch", hide_index=True)
            st.markdown("**Evidence**")
            st.dataframe(tl[tl.event_id.isin(c["event_ids"])][["event_id", "ts", "source", "summary", "source_file"]],
                         width="stretch", hide_index=True)
            st.markdown("**Investigator decision**")
            choice = st.selectbox("Decision", ["accepted", "rejected", "needs more evidence"], key=f"d{c['chain_id']}",
                                  index=["accepted", "rejected", "needs more evidence"].index(d["decision"]) if d.get("decision") in
                                  ["accepted", "rejected", "needs more evidence"] else 2)
            note = st.text_area("Note", d.get("note", ""), key=f"n{c['chain_id']}")
            if st.button("Save decision", key=f"s{c['chain_id']}"):
                m8_report.save_decision(out, c["chain_id"], choice, note, analyst)
                st.success("Saved. Regenerate the report to include it.")

with t_find:
    for f in findings:
        st.markdown(f"**{f['finding_id']} - {f['title']}** (severity {f['severity']}, {f['technique']})")
        st.write(f["description"])
        st.caption(f"Could also be innocent: {f['caveat']}")

with t_cust:
    st.dataframe(pd.DataFrame([m for m in manifest if m.get("kind") != "error"])[
        ["kind", "source_path", "sha256", "verified", "events_extracted"]], width="stretch")
    for m in manifest:
        if m.get("kind") == "error":
            st.error(f"{m['source_path']}: {m['error']}")

with t_rep:
    if st.button("Regenerate report with decisions"):
        m8_report.write_html_report(out, tl.assign(ts=pd.to_datetime(tl.ts)), findings,
                                    [dict(c, start=pd.Timestamp(c["start"]), end=pd.Timestamp(c["end"]),
                                          attack_steps=[dict(s, ts=pd.Timestamp(s["ts"])) for s in c["attack_steps"]])
                                     for c in chains], manifest)
    rp = out / "report.html"
    if rp.exists():
        st.download_button("Download report.html", rp.read_bytes(), "forensic_report.html", "text/html")
