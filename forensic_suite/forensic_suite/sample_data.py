"""Builds a realistic, SYNTHETIC evidence folder for demos and tests.

Scenario (all times UTC, 2026-10-12):
  14:00  user searches "free pdf converter crack", opens freepdf-tools.xyz, downloads and runs
         PDFConverter_Setup.exe; the program beacons to update-cdn-x7q.top
  14:48  CCleaner is run, and Chrome history for 13:55-14:50 (visits, searches, download) is deleted
  Also: an innocent Python installer download in Edge (2026-10-11) and ordinary browsing.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

UTC = timezone.utc
D = lambda s: datetime.fromisoformat(s).replace(tzinfo=UTC)
WK = lambda dt: int((dt - datetime(1601, 1, 1, tzinfo=UTC)).total_seconds() * 1_000_000)
PR = lambda dt: int(dt.timestamp() * 1_000_000)

CHROMIUM_SCHEMA = """
CREATE TABLE urls(id INTEGER PRIMARY KEY AUTOINCREMENT, url LONGVARCHAR, title LONGVARCHAR,
  visit_count INTEGER DEFAULT 0, typed_count INTEGER DEFAULT 0, last_visit_time INTEGER NOT NULL, hidden INTEGER DEFAULT 0);
CREATE TABLE visits(id INTEGER PRIMARY KEY AUTOINCREMENT, url INTEGER NOT NULL, visit_time INTEGER NOT NULL,
  from_visit INTEGER, transition INTEGER DEFAULT 0);
CREATE TABLE keyword_search_terms(keyword_id INTEGER NOT NULL, url_id INTEGER NOT NULL, term LONGVARCHAR NOT NULL,
  normalized_term LONGVARCHAR NOT NULL);
CREATE TABLE downloads(id INTEGER PRIMARY KEY, guid VARCHAR, current_path LONGVARCHAR, target_path LONGVARCHAR,
  start_time INTEGER, received_bytes INTEGER, total_bytes INTEGER, state INTEGER, danger_type INTEGER,
  end_time INTEGER, opened INTEGER, referrer VARCHAR, tab_url VARCHAR, tab_referrer_url VARCHAR);
CREATE TABLE downloads_url_chains(id INTEGER, chain_index INTEGER, url LONGVARCHAR);
"""


def _chromium(path: Path, visits, searches, downloads, wipe=None):
    """visits: (dt,url,title); searches: (dt,url,term); downloads: (dt,url,target,referrer,bytes)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.unlink(missing_ok=True)
    con = sqlite3.connect(path)
    con.executescript(CHROMIUM_SCHEMA)
    rows = [(dt, "v", url, title) for dt, url, title in visits] + [(dt, "s", url, term) for dt, url, term in searches]
    for dt, kind, url, extra in sorted(rows, key=lambda r: r[0]):
        r = con.execute("SELECT id FROM urls WHERE url=?", (url,)).fetchone()
        uid = r[0] if r else con.execute("INSERT INTO urls(url,title,last_visit_time) VALUES(?,?,?)",
                                         (url, extra if kind == "v" else "", WK(dt))).lastrowid
        con.execute("INSERT INTO visits(url,visit_time) VALUES(?,?)", (uid, WK(dt)))
        if kind == "s":
            con.execute("INSERT INTO keyword_search_terms VALUES(2,?,?,?)", (uid, extra, extra.lower()))
    for i, (dt, url, target, ref, size) in enumerate(downloads, 1):
        con.execute("INSERT INTO downloads(id,guid,current_path,target_path,start_time,total_bytes,referrer,tab_url)"
                    " VALUES(?,?,?,?,?,?,?,?)", (i, f"g{i}", target, target, WK(dt), size, ref, ref))
        con.execute("INSERT INTO downloads_url_chains VALUES(?,0,?)", (i, url))
    if wipe:                                   # emulate "clear browsing data" for a time range
        lo, hi = WK(wipe[0]), WK(wipe[1])
        gone = [r[0] for r in con.execute("SELECT DISTINCT url FROM visits WHERE visit_time BETWEEN ? AND ?", (lo, hi))]
        con.execute("DELETE FROM visits WHERE visit_time BETWEEN ? AND ?", (lo, hi))
        for u in gone:
            con.execute("DELETE FROM keyword_search_terms WHERE url_id=?", (u,))
            con.execute("DELETE FROM urls WHERE id=? AND id NOT IN (SELECT url FROM visits)", (u,))
        ids = [r[0] for r in con.execute("SELECT id FROM downloads WHERE start_time BETWEEN ? AND ?", (lo, hi))]
        for i in ids:
            con.execute("DELETE FROM downloads WHERE id=?", (i,))
            con.execute("DELETE FROM downloads_url_chains WHERE id=?", (i,))
    con.commit()
    con.close()


def make_sample(evidence_dir) -> Path:
    root = Path(evidence_dir)
    g = lambda q: f"https://www.google.com/search?q={q.replace(' ', '+')}"
    b = lambda q: f"https://www.bing.com/search?q={q.replace(' ', '+')}"

    # ---- Chrome: ordinary browsing + the attack, then a selective wipe 13:55-14:50
    chrome_v = [(D("2026-10-09T09:00:00"), "https://github.com/", "GitHub"),
                (D("2026-10-09T09:05:00"), "https://stackoverflow.com/questions/1", "Question"),
                (D("2026-10-10T11:00:00"), "https://en.wikipedia.org/wiki/SQLite", "SQLite - Wikipedia"),
                (D("2026-10-10T11:08:00"), "https://www.w3schools.com/sql/", "SQL Tutorial"),
                (D("2026-10-11T18:20:00"), "https://github.com/pandas-dev/pandas", "pandas"),
                (D("2026-10-12T09:04:00"), "https://github.com/streamlit/streamlit", "streamlit"),
                (D("2026-10-12T09:12:00"), "https://stackoverflow.com/questions/2", "Question 2"),
                (D("2026-10-12T13:56:00"), "https://stackoverflow.com/questions/3", "Question 3"),  # wiped
                (D("2026-10-12T14:00:05"), g("free pdf converter crack"), "Google Search"),
                (D("2026-10-12T14:01:10"), "https://freepdf-tools.xyz/download", "Free PDF Converter"),
                (D("2026-10-12T14:20:00"), "https://mail.example.org/inbox", "Inbox"),
                (D("2026-10-12T15:30:00"), "https://stackoverflow.com/questions/4", "Question 4"),
                (D("2026-10-12T15:42:00"), "https://github.com/pallets/flask", "flask")]
    _chromium(root / "chrome" / "History", chrome_v, [(D("2026-10-12T14:00:05"), g("free pdf converter crack"), "free pdf converter crack")],
              [(D("2026-10-12T14:03:20"), "https://freepdf-tools.xyz/dl/PDFConverter_Setup.exe",
                r"C:\Users\Kumar\Downloads\PDFConverter_Setup.exe", "https://freepdf-tools.xyz/download", 3_200_000)],
              wipe=(D("2026-10-12T13:55:00"), D("2026-10-12T14:50:00")))

    # ---- Edge: an innocent installer download
    py = "https://www.python.org/ftp/python/3.12.0/python-3.12.0-amd64.exe"
    _chromium(root / "edge" / "History",
              [(D("2026-10-11T10:10:00"), "https://www.microsoft.com/en-us/", "Microsoft"),
               (D("2026-10-11T10:17:30"), b("python 3.12 download"), "Bing Search"),
               (D("2026-10-11T10:18:00"), "https://www.python.org/downloads/", "Download Python"),
               (D("2026-10-11T12:00:00"), "https://learn.microsoft.com/en-us/", "Microsoft Learn")],
              [(D("2026-10-11T10:17:30"), b("python 3.12 download"), "python 3.12 download")],
              [(D("2026-10-11T10:19:00"), py, r"C:\Users\Kumar\Downloads\python-3.12.0-amd64.exe",
                "https://www.python.org/downloads/", 26_000_000)])

    # ---- Firefox
    p = root / "firefox" / "places.sqlite"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.unlink(missing_ok=True)
    con = sqlite3.connect(p)
    con.executescript("""
      CREATE TABLE moz_places(id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT, title TEXT, visit_count INTEGER, last_visit_date INTEGER);
      CREATE TABLE moz_historyvisits(id INTEGER PRIMARY KEY AUTOINCREMENT, from_visit INTEGER, place_id INTEGER, visit_date INTEGER, visit_type INTEGER);
      CREATE TABLE moz_anno_attributes(id INTEGER PRIMARY KEY, name TEXT);
      CREATE TABLE moz_annos(id INTEGER PRIMARY KEY, place_id INTEGER, anno_attribute_id INTEGER, content TEXT);
      INSERT INTO moz_anno_attributes VALUES(1,'downloads/destinationFileURI');""")
    ff = [(D("2026-10-10T16:00:00"), "https://www.mozilla.org/en-US/", "Mozilla", 1),
          (D("2026-10-10T16:05:00"), "https://duckduckgo.com/?q=sqlite+wal+forensics", "DuckDuckGo", 1),
          (D("2026-10-10T16:07:00"), "https://www.sqlite.org/wal.html", "WAL", 1),
          (D("2026-10-11T16:30:00"), "https://example.edu/notes.pdf", "notes.pdf", 7)]
    for i, (dt, url, title, vt) in enumerate(ff, 1):
        con.execute("INSERT INTO moz_places(id,url,title,visit_count,last_visit_date) VALUES(?,?,?,1,?)", (i, url, title, PR(dt)))
        con.execute("INSERT INTO moz_historyvisits(place_id,visit_date,visit_type) VALUES(?,?,?)", (i, PR(dt), vt))
    con.execute("INSERT INTO moz_annos VALUES(1,4,1,'file:///C:/Users/Kumar/Downloads/notes.pdf')")
    con.commit()
    con.close()

    # ---- Windows Timeline
    t = root / "windows" / "ActivitiesCache.db"
    t.parent.mkdir(parents=True, exist_ok=True)
    t.unlink(missing_ok=True)
    con = sqlite3.connect(t)
    con.execute("CREATE TABLE Activity(Id BLOB, AppId TEXT, ActivityType INTEGER, Payload BLOB, StartTime INTEGER, EndTime INTEGER, LastModifiedTime INTEGER)")
    def act(dt, path, text):
        app = json.dumps([{"application": path, "platform": "windows_win32"}])
        con.execute("INSERT INTO Activity VALUES(randomblob(8),?,5,?,?,?,?)",
                    (app, json.dumps({"displayText": text}).encode(), int(dt.timestamp()), int(dt.timestamp()) + 600, int(dt.timestamp())))
    act(D("2026-10-12T09:03:00"), r"C:\Program Files\Google\Chrome\Application\chrome.exe", "Chrome")
    act(D("2026-10-11T10:21:30"), r"C:\Users\Kumar\Downloads\python-3.12.0-amd64.exe", "Python 3.12.0 Setup")
    act(D("2026-10-12T14:05:30"), r"C:\Users\Kumar\Downloads\PDFConverter_Setup.exe", "PDF Converter Setup")
    act(D("2026-10-12T15:29:30"), r"C:\Program Files\Google\Chrome\Application\chrome.exe", "Chrome")
    con.commit()
    con.close()

    # ---- Prefetch (PECmd-style CSV)
    pf = ("ExecutableName,RunCount,LastRun,PreviousRun0,FilesLoaded\n"
          'PDFCONVERTER_SETUP.EXE,1,2026-10-12 14:05:02,,"\\VOLUME{x}\\USERS\\KUMAR\\DOWNLOADS\\PDFCONVERTER_SETUP.EXE,\\WINDOWS\\SYSTEM32\\NTDLL.DLL"\n'
          'CCLEANER64.EXE,3,2026-10-12 14:48:10,2026-10-05 18:00:00,"\\VOLUME{x}\\PROGRAM FILES\\CCLEANER\\CCLEANER64.EXE"\n'
          'PYTHON-3.12.0-AMD64.EXE,1,2026-10-11 10:21:05,,"\\VOLUME{x}\\USERS\\KUMAR\\DOWNLOADS\\PYTHON-3.12.0-AMD64.EXE"\n'
          'CHROME.EXE,40,2026-10-12 15:29:00,2026-10-12 09:03:00,"\\VOLUME{x}\\PROGRAM FILES\\GOOGLE\\CHROME\\APPLICATION\\CHROME.EXE"\n'
          'NOTEPAD.EXE,9,2026-10-12 08:50:00,,"\\VOLUME{x}\\WINDOWS\\SYSTEM32\\NOTEPAD.EXE"\n')
    (root / "windows" / "prefetch.csv").write_text(pf)

    # ---- DNS log (Sysmon event 22 style: records the querying process)
    dns = ["timestamp,domain,qtype,process",
           "2026-10-09 09:00:01,github.com,A,chrome.exe", "2026-10-10 11:00:01,en.wikipedia.org,A,chrome.exe",
           "2026-10-12 09:04:01,github.com,A,chrome.exe", "2026-10-12 09:04:02,avatars.githubusercontent.com,A,chrome.exe",
           "2026-10-12 14:00:40,www.google.com,A,chrome.exe", "2026-10-12 14:01:05,freepdf-tools.xyz,A,chrome.exe",
           "2026-10-12 14:01:06,cdn.freepdf-tools.xyz,A,chrome.exe",
           "2026-10-12 14:05:10,update-cdn-x7q.top,A,pdfconverter_setup.exe",
           "2026-10-12 14:35:10,update-cdn-x7q.top,A,pdfconverter_setup.exe",
           "2026-10-12 15:30:01,stackoverflow.com,A,chrome.exe",
           "2026-10-11 10:18:01,www.python.org,A,msedge.exe", "2026-10-11 10:19:01,www.python.org,A,msedge.exe"]
    (root / "windows" / "dns.csv").write_text("\n".join(dns) + "\n")
    return root
