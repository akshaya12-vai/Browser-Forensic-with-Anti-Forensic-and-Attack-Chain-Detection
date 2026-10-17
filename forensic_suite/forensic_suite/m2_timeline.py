"""MODULE 2 - Normalization & Unified Timeline."""
from __future__ import annotations

from datetime import timedelta, timezone

import pandas as pd

from .schema import (CLEANUP_TOOLS, EXECUTABLE_EXTS, USER_SPACE_MARKERS, basename, host_of,
                     registrable)

UTC = timezone.utc


def _to_utc(ts, tz_flag: str, local_offset_min: int):
    if ts is None or pd.isna(ts):
        return pd.NaT
    ts = pd.Timestamp(ts)
    if ts.tzinfo is None:
        if tz_flag == "LOCAL":
            ts = ts - timedelta(minutes=local_offset_min)      # local time -> UTC
        return ts.tz_localize(UTC)
    return ts.tz_convert(UTC)


def build_timeline(raw: pd.DataFrame, local_utc_offset_minutes: int = 0) -> pd.DataFrame:
    """One schema, UTC timestamps, one time-ordered table, every row tied to its source file."""
    cols = ["event_id", "ts", "source", "browser", "artifact_type", "category", "url", "domain",
            "registrable", "referrer", "title", "detail", "file_name", "file_path", "process",
            "is_executable", "user_space", "source_file", "summary"]
    if raw is None or raw.empty:
        return pd.DataFrame(columns=cols)
    df = raw.copy()
    df["ts"] = [_to_utc(t, f, local_utc_offset_minutes) for t, f in zip(df["ts"], df["ts_tz"])]
    df = df.dropna(subset=["ts"])
    for c in ("url", "referrer", "title", "detail", "file_name", "file_path", "process", "browser"):
        df[c] = df[c].astype(object).where(df[c].notna(), None)

    # domain: URL host for web events, queried name for DNS events
    df["domain"] = [d if a == "dns" and d else host_of(u)
                    for u, d, a in zip(df["url"], df["detail"], df["artifact_type"])]
    df["registrable"] = df["domain"].map(registrable)
    names = [fn if isinstance(fn, str) and fn else (basename(fp) or None)
             for fn, fp in zip(df["file_name"], df["file_path"])]
    df["file_name"] = pd.Series(names, index=df.index, dtype=object)
    df["is_executable"] = [bool(fn) and fn.lower().endswith(EXECUTABLE_EXTS) for fn in names]
    df["user_space"] = [isinstance(fp, str) and any(m in fp.lower().replace("/", "\\") for m in USER_SPACE_MARKERS)
                        for fp in df["file_path"]]

    def category(r):
        if r["artifact_type"] == "execution" and (r["file_name"] if isinstance(r["file_name"], str) else "").lower() in CLEANUP_TOOLS:
            return "cleanup"
        return r["artifact_type"]

    df["category"] = df.apply(category, axis=1)
    df = df.drop_duplicates(subset=["ts", "source", "artifact_type", "url", "file_name", "process", "detail"])
    df = df.sort_values("ts", kind="stable").reset_index(drop=True)
    df["event_id"] = [f"E{i + 1:04d}" for i in range(len(df))]
    df["summary"] = [f"{c}: {u or fn or dt or p or ''}" for c, u, fn, dt, p in
                     zip(df["category"], df["url"], df["file_name"], df["detail"], df["process"])]
    return df[cols]
