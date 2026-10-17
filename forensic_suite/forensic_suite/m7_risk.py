"""MODULE 7 - Explainable Risk Scoring.

Core score = transparent weighted signals (every point is traceable to evidence).
An Isolation Forest adds a small, separately-labelled 'unusual behaviour' signal.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from .heuristics import domain_flags, entropy, is_trusted, suspicious_terms

MIN_EVENTS_FOR_ML = 100
WEIGHTS = {
    "executable_download": 10, "execution_of_downloaded_file": 10, "execution_user_space": 10,
    "network_after_exec": 10, "suspicious_c2_domain": 15, "suspicious_delivery_domain": 15,
    "cleanup_after_exec": 15, "history_deleted": 15, "suspicious_search_terms": 10,
    "anomalous_behaviour": 5, "multi_source": 5, "trusted_delivery": -20,
}


def anomalous_events(tl: pd.DataFrame, top_frac: float = 0.1) -> dict[str, str]:
    """event_id -> reason, for events an Isolation Forest finds unusual. {} if scikit-learn is absent."""
    try:
        from sklearn.ensemble import IsolationForest
    except ImportError:
        return {}
    if len(tl) < MIN_EVENTS_FOR_ML:      # too little data: "unusual" would just be noise
        return {}
    d = tl.copy()
    freq = d.groupby("registrable")["event_id"].transform("count").clip(lower=1)
    X = pd.DataFrame({
        "off_hours": d.ts.dt.hour.isin([0, 1, 2, 3, 4, 5]).astype(float),
        "rare_domain": 1.0 / freq,
        "long_url": np.log1p(d["url"].fillna("").str.len()),
        "name_entropy": d["registrable"].map(entropy),
        "is_exec": d.category.isin(["execution", "cleanup"]).astype(float),
        "is_download": (d.category == "download").astype(float),
    })
    model = IsolationForest(n_estimators=200, random_state=0).fit(X)
    score = model.decision_function(X)
    cut = np.quantile(score, top_frac)
    z = (X - X.median()) / (X.std().replace(0, 1))
    out = {}
    for i in np.where((score <= cut) & (score < 0))[0]:
        top = z.iloc[i].abs().sort_values(ascending=False).head(2).index
        out[d.event_id.iloc[i]] = "unusual " + " + ".join(c.replace("_", " ") for c in top)
    return out


def score_chain(chain: dict, tl: pd.DataFrame, findings: list[dict], anomalies: dict,
                ioc=frozenset()) -> dict:
    ev = tl[tl.event_id.isin(chain["event_ids"])]
    stage = dict(zip(chain["event_ids"], chain["stages"]))
    rules = {}
    for e in chain["edges"]:
        rules.setdefault(e["rule"], set()).update([e["src"], e["dst"]])
    signals = []

    def add(key, reason, ids):
        signals.append({"signal": key, "points": WEIGHTS[key], "reason": reason, "evidence": sorted(set(ids))})

    dl = ev[(ev.category == "download") & ev.is_executable]
    if len(dl):
        add("executable_download", f"executable downloaded: {', '.join(dl.file_name)}", dl.event_id)
    if "download_to_execution" in rules:
        ids = [i for i in rules["download_to_execution"]]
        add("execution_of_downloaded_file", "a downloaded file was later executed", ids)
    ex = ev[(ev.category == "execution") & ev.user_space]
    if len(ex):
        add("execution_user_space", f"ran from a user-writable folder: {ex.file_path.iloc[0]}", ex.event_id)
    if "exec_to_dns" in rules:
        q = ev[ev.event_id.isin(rules["exec_to_dns"]) & (ev.category == "dns")]
        add("network_after_exec", f"the program itself made {len(q)} DNS lookup(s)", q.event_id)
        for dom, g in q.groupby("domain"):
            f = domain_flags(dom, ioc)
            if f:
                add("suspicious_c2_domain", f"program contacted {dom}: {'; '.join(f)}", g.event_id)
    delivery = ev[ev.event_id.map(stage).isin(["Visit", "Delivery (from DNS)", "Download"]) & (ev.domain != "")]
    flagged = delivery[[bool(domain_flags(d, ioc)) and not is_trusted(d) for d in delivery.domain]]
    if len(flagged):
        doms = sorted(set(flagged.domain))
        add("suspicious_delivery_domain", f"delivery site(s): {', '.join(doms)} "
            f"({'; '.join(domain_flags(doms[0], ioc))})", flagged.event_id)
    cl = ev[ev.category == "cleanup"]
    if len(cl):
        add("cleanup_after_exec", f"{', '.join(cl.file_name)} ran after the program", cl.event_id)
    fs = [f for f in findings if f["finding_id"] in chain["finding_ids"]
          and f["kind"] in ("deleted_records", "history_gap", "download_record_missing")]
    if fs:
        add("history_deleted", "; ".join(f["title"] for f in fs), [i for f in fs for i in f["evidence"]])
    sr = ev[ev.category == "search"]
    hits = [(r.event_id, w) for r in sr.itertuples() for w in suspicious_terms(r.detail)]
    if hits:
        add("suspicious_search_terms", f"search terms: {', '.join(sorted({w for _, w in hits}))}", [i for i, _ in hits])
    an = {i: anomalies[i] for i in ev.event_id if i in anomalies}
    if an:
        add("anomalous_behaviour", "ML flagged: " + "; ".join(sorted(set(an.values()))), an)
    if ev.source.nunique() >= 3:
        add("multi_source", f"evidence agrees across {ev.source.nunique()} sources ({', '.join(sorted(ev.source.unique()))})", ev.event_id)
    web = ev[ev.event_id.map(stage).isin(["Visit", "Download"]) & (ev.domain != "")]
    if len(web) and all(is_trusted(d) for d in web.domain) and not len(flagged):
        add("trusted_delivery", f"all delivery sites are well-known: {', '.join(sorted(set(web.domain)))}", web.event_id)

    raw = sum(s["points"] for s in signals)
    score = int(max(0, min(100, raw)))
    level = "High" if score >= 70 else "Medium" if score >= 40 else "Low"
    return {"score": score, "raw_points": raw, "level": level,
            "signals": sorted(signals, key=lambda s: -abs(s["points"]))}
