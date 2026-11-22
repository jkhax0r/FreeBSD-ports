"""Observation collector, with a separately approved on-demand trial launcher.

Run as a bounded trial before enabling service startup. Existing resolver and
filter logs and optional existing pfBlockerNG reply/policy logs are the event
sources. None of these text logs can supply trusted enforcement mappings.
Optional bounded local metadata uses Kea's read-only Unix control socket.
An explicit native-UI request can prepare a separately approved inactive trial;
the collector never sends Start, writes a rule or changes a DNS hook itself.
"""
import argparse
from collections import Counter
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import time
from . import __version__
from .rollups import HourlyCounts

MAX_DB_BYTES = 64 * 1024 * 1024
MAX_EVENTS = 20000
MAX_AGE_SECONDS = 86400
MAX_BATCH_EVENTS = 2000
DNS_HISTORY_KINDS = frozenset(('dns_query','dns_reply_log','dns_policy_log','dns_reply'))
DNS_HISTORY_SQL = "kind IN ('dns_query','dns_reply_log','dns_policy_log','dns_reply')"

# Matches the read-only client view's scope. The partial index lets SQLite count
# eligible events without decoding every retained JSON body on each refresh.
# Keep id before the counters so the time/id pagination order remains available.
CLIENT_VISIBLE_SQL = ("kind='dns_query' OR (kind='firewall_packet' "
                      "AND action IN ('pass','block') "
                      "AND json_extract(body,'$.destination_port') IN (80,443) "
                      "AND json_extract(body,'$.protocol') IN ('tcp','udp'))")


def write_json(path, value):
    data = json.dumps(value, separators=(",",":"), ensure_ascii=True).encode()
    if len(data) > 4*1024*1024:
        raise ValueError("status size limit")
    temp = path.with_suffix(".tmp")
    with temp.open("wb") as f:
        f.write(data)
    os.chmod(temp, 0o600)
    os.replace(temp, path)


class EventStore:
    def __init__(self, path, session, max_events=MAX_EVENTS, max_db_bytes=MAX_DB_BYTES, max_hourly_groups=20000, busy_timeout_ms=1000, reply_details=False):
        self.path, self.session = Path(path), session
        if type(max_events) is not int or not 1 <= max_events <= MAX_EVENTS:
            raise ValueError("invalid event cap")
        if type(max_db_bytes) is not int or not 32768 <= max_db_bytes <= MAX_DB_BYTES:
            raise ValueError("invalid database cap")
        if type(busy_timeout_ms) is not int or not 0 <= busy_timeout_ms <= 1000:
            raise ValueError("bounded database wait required")
        if type(reply_details) is not bool:raise ValueError('explicit reply history mode required')
        self.answer_history=None
        if self.path.is_symlink() or (self.path.exists() and self.path.stat().st_size > max_db_bytes):
            raise ValueError("database is a symlink or already exceeds storage cap")
        self.max_events, self.max_db_bytes = max_events, max_db_bytes
        # Protect a bounded part of the existing row budget from packet floods.
        # Always leave room for a full accepted batch before inserting, so the
        # database does not need a temporary over-cap allocation. Small test
        # stores retain their original FIFO behavior when no such room exists.
        self.dns_reserved_events=min(5000,max_events//4,max(0,max_events-MAX_BATCH_EVENTS))
        self.db = sqlite3.connect(self.path, timeout=1)
        try:
            self.page_size = self.db.execute("PRAGMA page_size").fetchone()[0]
            self.max_pages = max_db_bytes // self.page_size
            actual = self.db.execute(f"PRAGMA max_page_count={self.max_pages}").fetchone()[0]
            if actual != self.max_pages:
                raise ValueError("existing database exceeds page budget")
            if self.db.execute("PRAGMA journal_mode=TRUNCATE").fetchone()[0] != "truncate":
                raise RuntimeError("bounded rollback-journal mode unavailable")
            self.db.execute("PRAGMA cache_size=-8192")
            self.db.execute(f"PRAGMA busy_timeout={busy_timeout_ms}")
            self.db.execute('BEGIN IMMEDIATE')
            self.db.execute("CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, session TEXT NOT NULL, time REAL NOT NULL, kind TEXT NOT NULL, client TEXT, domain TEXT, tracker TEXT, action TEXT, body TEXT NOT NULL)")
            self.db.execute("CREATE INDEX IF NOT EXISTS event_time ON events(time)")
            self.db.execute("CREATE INDEX IF NOT EXISTS event_client ON events(client,time)")
            self.db.execute("CREATE INDEX IF NOT EXISTS event_client_web ON events(client,time,id,kind,action) WHERE " + CLIENT_VISIBLE_SQL)
            self.db.execute("CREATE INDEX IF NOT EXISTS event_domain_evidence ON events(domain,time,id,kind,client) WHERE kind IN ('dns_query','dns_reply_log','dns_policy_log','dns_reply')")
            self.db.execute("CREATE INDEX IF NOT EXISTS event_destination_web ON events(json_extract(body,'$.destination'),time,id,client,action) WHERE kind='firewall_packet' AND json_extract(body,'$.destination_port') IN (80,443) AND json_extract(body,'$.protocol') IN ('tcp','udp')")
            self.db.execute("CREATE INDEX IF NOT EXISTS event_reply_address ON events(json_extract(body,'$.logged_answer'),time,id,domain,client) WHERE kind='dns_reply_log'")
            self.db.execute("CREATE INDEX IF NOT EXISTS event_client_dnsevidence ON events(client,time,id,kind,json_extract(body,'$.answer_kind')) WHERE kind IN ('dns_reply_log','dns_policy_log','dns_reply')")
            # Separate covering ID streams keep full-store eviction from
            # scanning large JSON-bearing rows or rebuilding a5000-ID set.
            # Both indexes join the same atomic schema transaction; an
            # allocation failure retains the existing rows and schema.
            self.db.execute("CREATE INDEX IF NOT EXISTS event_retention_dns ON events(id) WHERE "+DNS_HISTORY_SQL)
            self.db.execute("CREATE INDEX IF NOT EXISTS event_retention_other ON events(id) WHERE NOT ("+DNS_HISTORY_SQL+")")
            # Publish both replacements before removing legacy indexes, in the
            # same schema transaction. A capacity failure retains old indexes
            # and observations. These two replacements keep their index count;
            # the independent retention indexes above are additional.
            self.db.execute('DROP INDEX IF EXISTS event_domain')
            self.db.execute('DROP INDEX IF EXISTS event_client_dnslog')
            self.hourly=HourlyCounts(self.db,max_hourly_groups)
            if reply_details:
                from .answerhistory import AnswerHistory
                self.answer_history=AnswerHistory(self.db)
            self.db.commit()
            self._prepare_packet_address_index()
            os.chmod(self.path,0o600)
        except Exception:
            self.db.close()
            raise

    def _prepare_packet_address_index(self):
        """Index the remaining logged ports for the on-demand alias member counts."""
        if self.db.execute("SELECT 1 FROM sqlite_master WHERE type='index' AND name='event_packet_nonweb_counts'").fetchone():
            return
        pages = self.db.execute("PRAGMA page_count").fetchone()[0]
        free = self.db.execute("PRAGMA freelist_count").fetchone()[0]
        # Leave working space for collection in a small or nearly full database.
        # A member page can always use the original time-range query.
        if (self.max_pages - pages + free) * self.page_size < max(1048576, self.max_events * 256):
            return
        try:
            with self.db:
                self.db.execute("BEGIN IMMEDIATE")
                self.db.execute("""
                    CREATE INDEX IF NOT EXISTS event_packet_nonweb_counts
                    ON events(json_extract(body,'$.destination'),time,action='pass',action='block')
                    WHERE kind='firewall_packet'
                    AND (json_extract(body,'$.destination_port') IN (80,443)
                         AND json_extract(body,'$.protocol') IN ('tcp','udp')) IS NOT 1
                    AND json_type(body,'$.destination')='text'
                    AND length(CAST(json_extract(body,'$.destination') AS BLOB)) BETWEEN 2 AND 45
                """)
        except sqlite3.OperationalError as error:
            if (error.sqlite_errorcode & 255) not in (sqlite3.SQLITE_FULL, sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED):
                raise

    def insert(self, events, now=None):
        if len(events) > min(MAX_BATCH_EVENTS,self.max_events):
            raise ValueError("batch limit")
        now = time.time() if now is None else now
        eligible=[e for e in events if e['time']>=now-MAX_AGE_SECONDS]
        rows = [(self.session,e["time"],e["kind"],e.get("client",e.get("source")),e.get("name"),
                 e.get("tracker"),e.get("action"),json.dumps(e,separators=(",",":"))) for e in eligible]
        answers,total=self.answer_history.prepare(eligible) if self.answer_history is not None else (None,0)
        # Eviction and insertion share one transaction. SQLITE_FULL or any other
        # write failure rolls both back; old rows are not lost by a failed batch.
        with self.db:
            incoming_dns=sum(e['kind'] in DNS_HISTORY_KINDS for e in eligible)
            self._trim(now, self.max_events-len(rows),max(0,self.dns_reserved_events-incoming_dns))
            insert="INSERT INTO events(session,time,kind,client,domain,tracker,action,body) VALUES (?,?,?,?,?,?,?,?)"
            if self.answer_history is None:self.db.executemany(insert,rows)
            else:
                self.answer_history.reserve(total)
                for row,detail in zip(rows,answers):
                    event_id=self.db.execute(insert,row).lastrowid
                    self.answer_history.insert(event_id,detail)
            self.hourly.insert(eligible,now)
        return len(rows)

    def _trim(self, now, keep, reserve=None):
        self.db.execute("DELETE FROM events WHERE time < ?",(now-MAX_AGE_SECONDS,))
        count = self.db.execute("SELECT count(*) FROM events").fetchone()[0]
        excess = max(0,count-keep)
        if excess:
            reserve=self.dns_reserved_events if reserve is None else reserve
            if reserve:
                # The Rth newest DNS ID is an inclusive protection boundary.
                # If fewer than R DNS rows exist, NULL protects all of them.
                # Merge older DNS with all other kinds in global FIFO order.
                # These disjoint covering streams preserve the old NOT IN
                # semantics without materializing the full protected ID set.
                # The preceding DELETE has already opened the write transaction;
                # another collector cannot change the boundary before eviction.
                cutoff=self.db.execute("SELECT id FROM events WHERE "+DNS_HISTORY_SQL+
                    " ORDER BY id DESC LIMIT 1 OFFSET ?",(reserve-1,)).fetchone()
                self.db.execute("DELETE FROM events WHERE id IN (SELECT id FROM events WHERE "+DNS_HISTORY_SQL+
                    " AND id < ? UNION ALL SELECT id FROM events WHERE NOT ("+DNS_HISTORY_SQL+
                    ") ORDER BY id LIMIT ?)",(None if cutoff is None else cutoff[0],excess))
            else:
                self.db.execute("DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY id LIMIT ?)",(excess,))

    def prune(self, now):
        with self.db:
            self._trim(now,self.max_events)
            self.hourly.prune(now)
        if self.path.stat().st_size > self.max_db_bytes:
            raise RuntimeError("database storage cap reached; collector stopped")

    def storage(self):
        return {"rows":self.db.execute("SELECT count(*) FROM events").fetchone()[0],
                "page_count":self.db.execute("PRAGMA page_count").fetchone()[0],
                "page_size":self.page_size,"writer_page_limit":self.max_pages,
                "journal_mode":self.db.execute("PRAGMA journal_mode").fetchone()[0],
                "event_limit":self.max_events,"database_byte_limit":self.max_db_bytes,"hourly":self.hourly.summary(),
                "dns_reserved_events":self.dns_reserved_events,
                "raw_by_kind":[{"kind":kind,"rows":count,"oldest":oldest,"newest":newest} for kind,count,oldest,newest in
                    self.db.execute("SELECT kind,count(*),min(time),max(time) FROM events GROUP BY kind")],
                "retention_policy":"Latest collected DNS evidence protected within shared row/24-hour limits; unused reserve is available to other logs. Missing records do not prove zero traffic."}

    def summary(self):
        rows=self.db.execute("SELECT kind,action,count(*) FROM events WHERE session=? GROUP BY kind,action",(self.session,)).fetchall()
        return [{"kind":k,"action":a,"retained_events":c} for k,a,c in rows]

    def close(self):
        self.db.close()


def prepare_trial_request(data_dir,now):
    # The observer's normal import/start path stays independent of enforcement
    # helpers. Import them only for an actual private queued preparation.
    operation=None
    for name,kind in (('trial-prepare-request','block'),('observation-prepare-request','observe')):
        try:(Path(data_dir)/name).lstat();operation=kind;break
        except FileNotFoundError:pass
    if operation is None:return None
    from .triallaunch import consume_request
    root=Path(__file__).resolve().parents[1]
    return consume_request(root,data_dir,now=now,operation='observe') if operation=='observe' else consume_request(root,data_dir,now=now)


def collect_rules(tracker):
    from .telemetry import parse_rules
    # No user-controlled command, shell, table operation, reload or state removal.
    result=subprocess.run(["/sbin/pfctl","-vvsr"],stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                          text=True,timeout=3,check=False)
    if result.returncode != 0 or len(result.stdout) > 2*1024*1024:
        raise RuntimeError("read-only PF counter query failed or exceeded limit")
    return tracker.update(parse_rules(result.stdout))


def resource_limits():
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CORE,(0,0))
        resource.setrlimit(resource.RLIMIT_NOFILE,(64,64))
        resource.setrlimit(resource.RLIMIT_AS,(192*1024*1024,192*1024*1024))
        os.nice(10)
    except (ImportError, AttributeError):
        pass


def run(data_dir, duration, resolver_log="/var/log/resolver.log", filter_log="/var/log/filter.log", rules_enabled=True):
    import uuid
    from .telemetry import TailReader, parse_dns, parse_filter, CounterTracker
    from .policylog import parse_policy_log
    from .clientidentity import collect_identity,consume_identity_request
    data_dir=Path(data_dir)
    if not data_dir.is_dir() or data_dir.is_symlink():
        raise ValueError("pre-created owned data directory required")
    session=uuid.uuid4().hex
    status={"version":__version__,"mode":"observation_only","session":session,"pid":os.getpid(),
            "started_utc":time.time(),"enforcement_enabled":False,"pf_writes":0,
            "production_hook_installed":False,"reply_mapping_coverage":False,
            "limitations":["Query logs plus optional pfBlockerNG reply/policy logs; complete trusted reply mappings remain unavailable",
                            "pfBlockerNG reply text may show only one answer or an inferred status; never used for leases",
                            "Firewall log events are packets, not HTTP requests or guaranteed unique connections",
                            "Only existing logged rules are visible; client/NAT attribution is not yet normalized",
                            "Rule bytes are aggregate counters; logged packet bytes are not connection bytes",
                            "Collection starts at EOF; rotations, truncation and overflow are recorded as gaps"],
            "limits":{"max_database_bytes":MAX_DB_BYTES,"max_retained_events":MAX_EVENTS,
                      "max_age_seconds":MAX_AGE_SECONDS,"log_read_bytes_per_second":524288},
            "counts":{},"gaps":[],"rules":[],"state":"starting"}
    # Fixed total remains 512KiB per polling cycle. Missing optional logs are
    # inert; no package, logging configuration or DNS hook is enabled here.
    readers=[(TailReader(resolver_log,131072),parse_dns),(TailReader(filter_log,262144),parse_filter),
             (TailReader('/var/log/pfblockerng/dns_reply.log',65536),parse_policy_log),
             (TailReader('/var/log/pfblockerng/dnsbl.log',65536),parse_policy_log)]
    store=None
    tracker=CounterTracker()
    stopped=False
    def stop(signum, frame):
        nonlocal stopped
        stopped=True
    signal.signal(signal.SIGTERM,stop)
    signal.signal(signal.SIGINT,stop)
    counts=Counter()
    started=time.monotonic()
    next_rules=next_status=0
    last_identity_sample=None
    pending=[]
    try:
        store=EventStore(data_dir/"events.sqlite",session)
        store.prune(time.time())
        while not stopped and (duration == 0 or time.monotonic()-started < duration):
            now=time.time()
            for reader, parser in readers:
                try:
                    lines=reader.read()
                except OSError as exc:
                    lines=[]
                    status["gaps"].append({"time":now,"source":str(reader.path),"reason":type(exc).__name__})
                counts["input_lines"]+=len(lines)
                for line in lines:
                    event=parser(line)
                    if event:
                        counts[event["kind"]]+=1
                        if len(pending)<2000:
                            pending.append(event)
                        else:
                            counts["events_dropped_batch_limit"]+=1
                status["gaps"].extend({"time":now,"source":str(reader.path),"reason":gap} for gap in reader.gaps)
                reader.gaps.clear()
            if pending:
                inserted=store.insert(pending,now=now)
                counts["events_expired_on_insert"]+=len(pending)-inserted
                pending.clear()
            if consume_identity_request(data_dir,now=time.time()):
                sample_clock=time.monotonic()
                if last_identity_sample is None or sample_clock-last_identity_sample>=60:
                    status['client_identity']=collect_identity(time.time())
                    last_identity_sample=sample_clock;next_status=0
            preparation=prepare_trial_request(data_dir,time.time())
            if preparation is not None:
                status['trial_preparation']=preparation;next_status=0
            if rules_enabled and time.monotonic()>=next_rules:
                try:
                    status["rules"]=collect_rules(tracker)
                    status["rules_observed_utc"]=now
                    counts["rule_samples"]+=1
                except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
                    status["gaps"].append({"time":now,"source":"pf_counters","reason":type(exc).__name__})
                next_rules=time.monotonic()+60
            if time.monotonic()>=next_status:
                store.prune(now)
                status.update(state="running",updated_utc=now,counts=dict(counts),retained=store.summary(),storage=store.storage())
                status['log_readers']=[{'source':str(reader.path),**reader.status()} for reader,_ in readers]
                status["gaps"]=status["gaps"][-100:]
                write_json(data_dir/"status.json",status)
                next_status=time.monotonic()+10
            time.sleep(1)
        status["state"]="stopped"
        status["stop_reason"]="signal" if stopped else "bounded_trial_completed"
    except Exception as exc:
        status["state"]="failed"
        status["error"]=type(exc).__name__+": "+str(exc)[:200]
        raise
    finally:
        for reader, _ in readers: reader.close()
        try:
            status.update(updated_utc=time.time(),counts=dict(counts),retained=[])
            if store is not None:
                try:
                    status.update(retained=store.summary(),storage=store.storage())
                except sqlite3.Error as exc:
                    status["summary_error"]=type(exc).__name__
            write_json(data_dir/"status.json",status)
        finally:
            if store is not None: store.close()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--data-dir",required=True)
    p.add_argument("--duration",type=int,default=0,help="seconds; 0 for supervised continuous observation")
    args=p.parse_args()
    if args.duration<0 or args.duration>86400:
        p.error("duration must be 0..86400")
    from .lifecycle import current
    root=Path(__file__).resolve().parents[1]
    if current(root,Path(args.data_dir)) is None:
        os.execv('/usr/local/bin/python3.11',['/usr/local/bin/python3.11','-B',str(root/'dnsalias/lifecycle.py'),'collector','--data-dir',args.data_dir,'--duration',str(args.duration)])
    resource_limits()
    run(args.data_dir,args.duration)


if __name__ == "__main__": main()
