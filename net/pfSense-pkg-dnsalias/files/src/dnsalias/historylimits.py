"""Storage budgets for the reporting database. Active DNS leases use a separate store."""
import os
from pathlib import Path
import sqlite3
import stat

DEFAULT_EVENTS = 20_000
# Event count -> (maximum database MiB, hourly groups). Typed answers have their own
# equally sized row budget because one DNS event can contain several addresses.
PROFILES = {20_000: (64, 20_000), 100_000: (256, 60_000),
            500_000: (1024, 160_000), 1_250_000: (3072, 250_000)}
MAX_BYTES = max(size for size, _ in PROFILES.values()) * 1024**2
TABLE = "CREATE TABLE IF NOT EXISTS history_retention (id INTEGER PRIMARY KEY CHECK(id=1), events INTEGER NOT NULL, peak_events INTEGER NOT NULL)"

def read_limits(db):
    row = db.execute("SELECT events,peak_events FROM history_retention WHERE id=1").fetchone()
    events, peak = row or (DEFAULT_EVENTS, DEFAULT_EVENTS)
    if events not in PROFILES or peak not in PROFILES or peak < events:
        raise ValueError("Invalid saved history budget")
    return events, peak

def existing_limits(db):
    exists = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='history_retention'").fetchone()
    return read_limits(db) if exists else (DEFAULT_EVENTS, DEFAULT_EVENTS)

def settings(path, events=None):
    if events is not None and (type(events) is not int or events not in PROFILES):
        raise ValueError("Choose a supported history size")
    path = Path(path)
    if events is not None and not path.exists():
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(fd)
    try:
        info = path.lstat()
    except FileNotFoundError:
        if events is not None:
            raise
        return DEFAULT_EVENTS
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_BYTES:
        raise ValueError("Owned statistics database required")
    if os.name == "posix" and (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600):
        raise ValueError("Unexpected statistics database ownership")
    mode = "ro" if events is None else "rw"
    db = sqlite3.connect(path.resolve().as_uri() + "?mode=" + mode, uri=True, timeout=1)
    try:
        current, peak = existing_limits(db)
        if info.st_size > PROFILES[peak][0] * 1024**2:
            raise ValueError("Database exceeds its saved history budget")
        if events is None:
            return current
        if db.execute("PRAGMA journal_mode=TRUNCATE").fetchone()[0] != "truncate":
            raise ValueError("Statistics journal mode unavailable")
        with db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(TABLE)
            _, peak = read_limits(db)
            db.execute("INSERT OR REPLACE INTO history_retention VALUES(1,?,?)", (events, max(peak, events)))
        return events
    finally:
        db.close()

if __name__ == "__main__":
    import json
    import sys
    args = sys.argv[1:]
    if args == ["get"]:
        selected = None
    elif len(args) == 2 and args[0] == "set" and args[1] in {str(n) for n in PROFILES}:
        selected = int(args[1])
    else:
        raise SystemExit("Expected get or set with a supported budget")
    print(json.dumps(dict(events=settings("/var/db/dnsalias/events.sqlite", selected), profiles=PROFILES)))
