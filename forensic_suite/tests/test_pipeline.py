import json
from pathlib import Path

import pytest

from forensic_suite.pipeline import run
from forensic_suite.sample_data import make_sample
from forensic_suite import m1_collect, m2_timeline, m8_report


@pytest.fixture(scope="module")
def result(tmp_path_factory):
    root = tmp_path_factory.mktemp("case")
    ev = make_sample(root / "evidence")
    return run(ev, root / "out"), ev


def _chain(res, needle):
    return next(c for c in res["chains"] if needle in " ".join(c["stage_path"]) or needle in c["summary"])


def test_module1_hashes_verify_and_originals_untouched(result):
    res, ev = result
    srcs = [m for m in res["manifest"] if m.get("kind") != "error"]
    assert len(srcs) == 6 and all(m["verified"] for m in srcs)
    assert all(m["sha256"] == m1_collect.sha256_file(Path(m["source_path"])) for m in srcs)


def test_module2_unified_utc_sorted_timeline(result):
    tl = result[0]["timeline"]
    assert set(tl.source) >= {"chrome", "edge", "firefox", "timeline", "prefetch", "dns"}
    assert tl.ts.is_monotonic_increasing and str(tl.ts.dt.tz) == "UTC"
    assert tl.event_id.is_unique and tl.source_file.notna().all()


def test_local_time_csv_is_shifted_to_utc(tmp_path):
    (tmp_path / "dns.csv").write_text("timestamp,domain,process\n2026-10-12 19:30:00,a.example,chrome.exe\n")
    raw, _, _ = m1_collect.collect_all(tmp_path, tmp_path / "w")
    tl = m2_timeline.build_timeline(raw, local_utc_offset_minutes=330)     # IST -> UTC
    assert str(tl.ts.iloc[0]) == "2026-10-12 14:00:00+00:00"


def test_module4_detects_antiforensics(result):
    kinds = [f["kind"] for f in result[0]["findings"]]
    for k in ("deleted_records", "history_gap", "cleanup_tool", "download_record_missing"):
        assert k in kinds


def test_module5_two_chains_with_expected_stages(result):
    res = result[0]
    assert len(res["chains"]) == 2
    bad = _chain(res, "Cleanup")
    assert bad["stage_path"] == ["Delivery (from DNS)", "Execution", "Network", "Cleanup"]
    good = _chain(res, "Download")
    assert good["stage_path"] == ["Search", "Visit", "Download", "Execution"]


def test_module6_mitre_tags(result):
    bad = _chain(result[0], "Cleanup")
    ids = {s["technique_id"] for s in bad["attack_steps"]}
    assert {"T1204.002", "T1071.001", "T1070", "T1189"} <= ids
    assert "T1105" in {s["technique_id"] for s in _chain(result[0], "Download")["attack_steps"]}


def test_module7_scores_separate_malicious_from_benign(result):
    bad, good = _chain(result[0], "Cleanup"), _chain(result[0], "Download")
    assert bad["risk"]["level"] == "High" and bad["risk"]["score"] >= 70
    assert good["risk"]["level"] == "Low" and good["risk"]["score"] < 40
    assert all(s["reason"] and s["evidence"] for s in bad["risk"]["signals"])      # explainable


def test_module8_report_and_decisions(result):
    res = result[0]
    out = res["out_dir"]
    m8_report.save_decision(out, "C02", "accepted", "matches CCleaner + DNS beacon", "Akshaya")
    m8_report.write_html_report(out, res["timeline"], res["findings"], res["chains"], res["manifest"])
    html = (out / "report.html").read_text()
    assert "accepted" in html and "T1204.002" in html and "final decision" in html
    assert json.loads((out / "decisions.json").read_text())["C02"]["analyst"] == "Akshaya"
