# AI-Assisted Multi-Browser Forensic Suite

Browser Forensics with Anti-Forensic and Attack-Chain Detection. Eight modules, one pipeline,
and a human investigator who makes every final decision.

## Quick start
```bash
pip install -r requirements.txt
python -c "from forensic_suite.sample_data import make_sample; make_sample('sample_evidence')"
python -m forensic_suite --evidence sample_evidence --out output     # Modules 1-8, writes output/report.html
streamlit run dashboard.py                                           # investigator dashboard
python -m pytest -q                                                  # 8 tests
```

## Modules
| # | Module | File | What it does |
|---|--------|------|--------------|
| 1 | Evidence Collection | `m1_collect.py` | Chrome/Edge/Brave `History`, Firefox `places.sqlite`, Windows Timeline `ActivitiesCache.db`, Prefetch CSV, DNS CSV. Hash, copy, parse the copy, re-hash the original. |
| 2 | Normalization & Unified Timeline | `m2_timeline.py` | One schema, UTC timestamps (local-time CSVs shifted with `--tz-offset-minutes`), one sorted table, every row tied to its source file. |
| 3 | Cross-Source Correlation | `m3_correlate.py` | Edge list: search→visit, visit→download, download→execution, execution→DNS, execution→cleanup, history-gap→execution. Each edge states its reason and strength. |
| 4 | Anti-Forensic Detection | `m4_antiforensic.py` | Missing SQLite row ids, browser DNS with no history nearby, trace-wiping tools, programs run from Downloads with no download record, history that starts late. Every finding carries a "could be innocent because…" note. |
| 5 | Attack-Chain Reconstruction | `m5_chains.py` | Connected components of the edge graph, ordered into Search → Visit → Delivery → Download → Execution → Network → Cleanup. |
| 6 | MITRE ATT&CK Mapping | `m6_mitre.py` | T1189, T1105, T1204.002, T1071.001, T1070, each with the evidence it rests on and a confidence level. |
| 7 | Explainable Risk Scoring | `m7_risk.py` | 0-100 from weighted signals (see `WEIGHTS`), every point linked to event ids. Isolation Forest adds a small, separately labelled "unusual behaviour" signal when there are ≥100 events. |
| 8 | Report & Dashboard | `m8_report.py`, `dashboard.py` | Timeline, chains, findings, custody table, accept/reject/note per chain, HTML report. |

Shared helpers: `schema.py` (event schema, constants), `heuristics.py` (domain/search-term checks), `pipeline.py`.

## Evidence folder layout
```
evidence/
  chrome/History          edge/History          firefox/places.sqlite
  windows/ActivitiesCache.db
  windows/prefetch.csv    (name must contain "prefetch")
  windows/dns.csv         (name must contain "dns")
```
Collecting real evidence (use a VM or your own test machine, close the browsers first):
* Chrome: `%LOCALAPPDATA%\Google\Chrome\User Data\Default\History`; Edge: `...\Microsoft\Edge\User Data\Default\History`
* Firefox: `%APPDATA%\Mozilla\Firefox\Profiles\<profile>\places.sqlite`
* Timeline: `%LOCALAPPDATA%\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`
* Prefetch: run Eric Zimmerman's PECmd (`PECmd.exe -d C:\Windows\Prefetch --csv out`) and use the main CSV
* DNS with process names: Sysmon event 22 exported to CSV with columns `timestamp,domain,process`
  (`ipconfig /displaydns` has no timestamps, so it is not enough)
* `--live` collects the default browser and Timeline paths on the current Windows machine

## Limitations (say these in your viva)
* The sample data is synthetic. Results on real machines depend on what logging was enabled.
* Deleted-row detection uses SQLite row ids; VACUUM or deleting the profile hides it. Chrome also
  expires visits older than ~90 days, which is why only gaps inside the range or at the end are flagged.
* "Browser DNS with no history" uses a ±10 minute window so ad/CDN lookups don't trigger it; private browsing
  looks the same, so it is reported as a lead, not proof.
* Prefetch is read from PECmd CSV output; compressed `.pf` files are not parsed directly.
* ATT&CK tags are indicative. The T1071.001 tag from DNS alone needs traffic evidence to confirm.
* Domain checks (abused TLDs, entropy, trusted list) are heuristics. Add known-bad domains with `--ioc file.txt`.
