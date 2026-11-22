"""Parsers and bounded log reader; none of these functions alter the firewall."""
import datetime
import hashlib
import ipaddress
import math
import os
import re
import stat
import time
from .leases import dns_name

HEADER = re.compile(r"^<\d+>1 (\S+) \S+ (\S+) \S+ - - (.*)$")
QUERY = re.compile(r"(?:^|\s)info: (?:query: )?([^ ]+) ([^ ]+) ([A-Z0-9]+) (IN|CH|HS)$")


def envelope(line):
    match = HEADER.match(line.rstrip("\r\n"))
    if not match:
        return None
    stamp, app, message = match.groups()
    try:
        dt = datetime.datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            return None
        return dt.timestamp(), app, message
    except ValueError:
        return None


def parse_dns(line):
    env = envelope(line)
    if not env or env[1] != "unbound":
        return None
    match = QUERY.search(env[2])
    if not match:
        return None
    client, name, kind, klass = match.groups()
    try:
        return {"kind":"dns_query", "time":env[0], "client":str(ipaddress.ip_address(client)),
                "name":"." if name == "." else dns_name(name), "qtype":kind, "qclass":klass,
                "source":"unbound_query_log", "result":"unknown", "mapping":None}
    except ValueError:
        return None


def parse_filter(line):
    env = envelope(line)
    if not env or env[1] != "filterlog":
        return None
    parts = env[2].split(",")
    try:
        version = int(parts[8])
        if version == 4:
            proto, length, si, ports = parts[16], int(parts[17]), 18, 20
        elif version == 6:
            proto, length, si, ports = parts[12], int(parts[14]), 15, 17
        else:
            return None
        source, dest = ipaddress.ip_address(parts[si]), ipaddress.ip_address(parts[si+1])
        if source.version != version or dest.version != version or length < 0:
            return None
        event = {"kind":"firewall_packet", "time":env[0], "tracker":parts[3] or None,
                 "rule_number":parts[0], "interface":parts[4], "reason":parts[5],
                 "action":parts[6], "direction":parts[7], "family":version,
                 "protocol":proto, "source":str(source), "destination":str(dest),
                 "packet_bytes":length, "source_port":None, "destination_port":None,
                 "domains":[], "attribution":"unknown_no_reply_mapping"}
        if event["action"] not in ("pass","block","match") or event["direction"] not in ("in","out"):
            return None
        if proto in ("tcp","udp") and len(parts) > ports+1:
            sport, dport = int(parts[ports]), int(parts[ports+1])
            if not 0 <= sport <= 65535 or not 0 <= dport <= 65535:
                return None
            event.update(source_port=sport, destination_port=dport)
        return event
    except (ValueError, IndexError):
        return None


def parse_rules(text):
    rules, current = [], None
    for line in text.splitlines():
        if line.startswith("@"):
            tracker = re.search(r"\bridentifier (\d+)", line)
            current = None
            if tracker:
                label = re.search(r'label "descr=([^"\n]*)"', line)
                generation = re.search(r"tags=ruleset:([a-zA-Z0-9]+)", line)
                identity = re.sub(r"(<[^<>:]+):\d+>", r"\1>", line)
                current = {"tracker":tracker[1], "description":label[1] if label else "",
                           "rule":line, "fingerprint":hashlib.sha256(identity.encode()).hexdigest()[:24],
                           "generation":generation[1] if generation else None}
                rules.append(current)
        elif current is not None:
            for field, value in re.findall(r"(Evaluations|Packets|Bytes|States|State Creations):\s*(\d+)", line):
                current[field.lower().replace(" ","_")] = int(value)
    return [r for r in rules if "packets" in r and "bytes" in r]


class CounterTracker:
    def __init__(self):
        self.previous = {}
        self.generation = None

    def update(self, rules):
        generation=hashlib.sha256(repr([(r['fingerprint'],r.get('generation')) for r in rules]).encode()).hexdigest()[:24]
        if self.generation!=generation:
            self.previous={}
        self.generation=generation
        next_previous = {}
        for rule in rules:
            key = rule["fingerprint"]
            previous = self.previous.get(key)
            fields = ("packets", "bytes", "state_creations")
            reset = previous is None or any(rule.get(f,0) < previous.get(f,0) for f in fields)
            rule["interval_delta"] = None if reset else {f:rule.get(f,0)-previous.get(f,0) for f in fields}
            rule["counter_epoch"] = "baseline_or_reset" if reset else "no_reset_observed"
            rule["ruleset_epoch"] = generation
            next_previous[key] = rule.copy()
        self.previous = next_previous
        return rules


class TailReader:
    """Bounded overlapping drain of current and recently rotated log files.

    Read at most max_bytes per call across at most three regular descriptors.
    Retired files remain open for three idle seconds, at most ten seconds total.
    Late writers beyond that window, intermediate rotations between polls and
    copy/truncate regrowth cannot be proved absent: continuity stays uncertain.
    Every descriptor has its own partial-line buffer. Startup resumes at EOF.
    """
    def __init__(self, path, max_bytes=262144):
        if type(max_bytes) is not int or not 1 <= max_bytes <= 262144:
            raise ValueError('bounded log read size required')
        self.path, self.max_bytes = path, max_bytes
        self.streams = []
        self.current = None
        self.started = False
        self.gaps = []
        self.last_clock = None
        self.counters = dict.fromkeys(('rotations', 'bytes_read', 'late_rotation_bytes',
            'late_rotation_lines', 'retired_closed', 'descriptor_limit', 'drain_timeout'), 0)

    def count(self, key, amount=1):
        self.counters[key] = min(2**63-1, self.counters[key]+amount)

    def gap(self, reason):
        self.gaps.append(reason)

    def _close(self, stream):
        if stream['pending'] or stream['discard']:
            self.gap('log_partial_line_discarded_on_close')
        stream['handle'].close()
        self.streams.remove(stream)
        if stream['retired_at'] is not None: self.count('retired_closed')

    def _open_current(self, now):
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            return
        identity = (st.st_dev, st.st_ino)
        if self.current is not None and identity == self.current['identity']:
            return
        flags = os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0)
        fd = os.open(self.path, flags)
        try:
            own = os.fstat(fd)
            if not stat.S_ISREG(own.st_mode): raise OSError('regular log file required')
            actual = (own.st_dev, own.st_ino)
            if actual != identity: self.gap('log_path_changed_during_open')
            existing = next((s for s in self.streams if s['identity'] == actual), None)
            if existing is not None:
                os.close(fd);fd = None
                stream = existing
                stream['retired_at'] = None
            else:
                stream = {'handle':os.fdopen(fd, 'rb', buffering=0), 'identity':actual,
                          'pending':b'', 'discard':False, 'retired_at':None, 'last_activity':now}
                fd = None
                self.streams.append(stream)
            if not self.started:
                stream['handle'].seek(0,2)
                self.started = True
            if self.current is not None and self.current is not stream:
                self.current['retired_at'] = self.current['last_activity'] = now
                self.gap('log_rotation_continuity_unverified')
                self.count('rotations')
            self.current = stream
            while len(self.streams) > 3:
                retired = next(s for s in self.streams if s is not self.current)
                self.gap('log_rotation_descriptor_limit')
                self.count('descriptor_limit');self._close(retired)
        finally:
            if fd is not None: os.close(fd)

    def _read_stream(self, stream, budget, now):
        handle = stream['handle']
        own = os.fstat(handle.fileno())
        if own.st_size < handle.tell():
            self.gap('log_truncated')
            handle.seek(0)
            stream['pending'] = b''
            stream['discard'] = False
        available = own.st_size-handle.tell()
        if available > self.max_bytes:
            self.gap('backlog_limit_dropped_bytes')
            handle.seek(-self.max_bytes,2)
            stream['pending'] = b''
            stream['discard'] = True
        chunk = handle.read(budget)
        self.count('bytes_read', len(chunk))
        if chunk: stream['last_activity'] = now
        data = stream['pending'] + chunk
        pieces = data.split(b"\n")
        stream['pending'] = pieces.pop()
        # Consume a pre-existing partial discard before handling a newly
        # oversized trailing line; never discard an unrelated complete line.
        if stream['discard'] and pieces:
            pieces.pop(0)
            stream['discard'] = False
        if len(stream['pending']) > 16384:
            self.gap('oversized_log_line')
            stream['pending'] = b''
            stream['discard'] = True
        if any(len(x) > 16384 for x in pieces): self.gap('oversized_log_line')
        lines = [x.decode("utf-8",errors="replace") for x in pieces if len(x) <= 16384]
        if stream is not self.current:
            self.count('late_rotation_bytes', len(chunk));self.count('late_rotation_lines', len(lines))
        return lines, len(chunk)

    def read(self, *, now=None):
        now = time.monotonic() if now is None else now
        if type(now) not in (int,float) or not math.isfinite(now) or now < 0:
            raise ValueError('valid drain clock required')
        if self.last_clock is not None and now < self.last_clock:
            self.gap('log_drain_clock_regressed');now = self.last_clock
        self.last_clock = now
        self._open_current(now)
        rows=[];budget=self.max_bytes
        streams=list(self.streams)
        for index,stream in enumerate(streams):
            # Split remaining capacity fairly so a busy retired writer cannot
            # starve the current log. Unused capacity flows to later streams.
            share=budget//(len(streams)-index)
            if share:
                lines,used=self._read_stream(stream,share,now)
                rows.extend(lines);budget-=used
            if stream is self.current: continue
            at_eof=stream['handle'].tell() >= os.fstat(stream['handle'].fileno()).st_size
            if now-stream['retired_at'] >= 10:
                self.gap('log_rotation_drain_timeout');self.count('drain_timeout');self._close(stream)
            elif at_eof and now-stream['last_activity'] >= 3:
                self._close(stream)
        return rows

    def status(self):
        return {'open_descriptors':len(self.streams), 'descriptor_limit':3,
                'read_byte_limit_per_poll':self.max_bytes, 'retired_idle_seconds':3,
                'retired_max_seconds':10, 'counters':dict(self.counters),
                'coverage':'Bounded overlap drain; rotation continuity is not guaranteed.'}

    def close(self):
        for stream in list(self.streams): self._close(stream)
        self.current = None
