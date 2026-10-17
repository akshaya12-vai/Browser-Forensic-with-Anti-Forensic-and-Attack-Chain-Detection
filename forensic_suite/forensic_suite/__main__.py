import argparse

from .pipeline import run


def main():
    ap = argparse.ArgumentParser(prog="forensic_suite",
                                 description="AI-assisted multi-browser forensic analysis (Modules 1-8)")
    ap.add_argument("--evidence", help="folder holding the evidence files (see README for layout)")
    ap.add_argument("--live", action="store_true", help="collect from this Windows machine's default profiles")
    ap.add_argument("--out", default="output", help="output folder (default: output)")
    ap.add_argument("--tz-offset-minutes", type=int, default=0,
                    help="UTC offset of LOCAL-time CSVs, e.g. 330 for India (default 0)")
    ap.add_argument("--ioc", help="optional text file of known-bad domains, one per line")
    a = ap.parse_args()
    if not a.evidence and not a.live:
        ap.error("give --evidence FOLDER or --live")
    r = run(a.evidence, a.out, a.tz_offset_minutes, a.ioc, a.live)
    print(f"{len(r['timeline'])} events | {len(r['findings'])} anti-forensic findings | {len(r['chains'])} chains")
    for c in sorted(r["chains"], key=lambda c: -c["risk"]["score"]):
        print(f"  {c['chain_id']}  {c['risk']['score']:3d} {c['risk']['level']:6s}  {c['summary']}")
    print(f"report: {r['out_dir'] / 'report.html'}")


if __name__ == "__main__":
    main()
