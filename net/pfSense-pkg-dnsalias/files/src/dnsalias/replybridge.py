"""Inactive bounded authenticated-reply to telemetry bridge.

Caller owns the receiver, data files, event-loop scheduling and native deployment
audits. This module cannot bind a socket, install a hook, start a process or write
PF. Never run it inside a DNS callback. Successful persistence is observation,
not proof that a client received a reply or that a firewall allowed a connection.
"""
from collections import deque
import json
import math
import sqlite3
import time

from .collector import EventStore
from .observationpump import ReplyObservationPump


class ReplyTelemetryBridge:
    MAX_EVENTS=512
    MAX_BYTES=512*1024
    MAX_EVENT_BYTES=3072
    BATCH=128
    FLUSH_SECONDS=.1
    MAX_WAIT_SECONDS=1.0
    RETRY_SECONDS=.05

    def __init__(self,pump,store):
        if (not isinstance(pump,ReplyObservationPump) or pump.session.deployment_guard is None
            or pump.session.deployment_guard.generation is None):
            raise ValueError('receiver with explicit deployment and generation enrollment required')
        if not isinstance(store,EventStore) or store.max_events<self.BATCH:
            raise ValueError('bounded telemetry store required')
        if store.db.execute('PRAGMA busy_timeout').fetchone()[0]>25:
            raise ValueError('reply writer must not wait more than25ms for a database lock')
        self.pump,self.store=pump,store
        self.queue=deque();self.bytes=0
        self.state='ready';self.reason=None;self.last_step=None;self.next_flush=None
        self.counters={k:0 for k in ('observed','staged','persisted','expired_on_insert',
            'dropped_capacity','dropped_storage_wait','dropped_suspension','dropped_invalid',
            'dropped_storage_failure','busy_retries','storage_failures','flushes')}

    def _count(self,name,n=1): self.counters[name]=min(2**63-1,self.counters[name]+n)

    def _pop(self,n):
        for _ in range(n): self.bytes-=self.queue.popleft()[1]

    def _drop(self,n,reason):
        if n:
            self._count(reason,n);self._pop(n);self.pump.session.receiver_gap()

    def _suspend(self,reason):
        self.state='suspended';self.reason=reason
        self._drop(len(self.queue),'dropped_suspension')
        self.pump.session.receiver_gap()

    def step(self,*,now=None,utc_now=None):
        """At most one bounded receive poll and one128-event database batch.

        SQLite's lock timeout is bounded, but disk scheduling is not a hard
        latency guarantee. Busy transactions are retried only after rollback;
        any other storage failure stops this bridge without replaying an
        uncertain commit. Queue delay/capacity loss permanently marks coverage.
        """
        if self.state not in ('ready','running'): return
        now=time.monotonic() if now is None else now
        utc_now=time.time() if utc_now is None else utc_now
        if any(type(v) not in (int,float) or not math.isfinite(v) or v<0 for v in (now,utc_now)):
            self._suspend('invalid_clock');return
        if self.last_step is not None and now<self.last_step:
            self._suspend('clock_regressed');return
        self.last_step=now
        qualification=self.pump.session.deployment_guard.check(now=now)
        if qualification!='qualified':
            self._suspend(qualification);return
        self.state='running'
        while self.queue and now-self.queue[0][2]>=self.MAX_WAIT_SECONDS:
            self._drop(1,'dropped_storage_wait')
        outcomes=self.pump.poll()
        if self.pump.stopped_reason is not None:
            self._suspend(self.pump.stopped_reason);return
        # A same-PID reload may be detected by a reply during this poll. Drop
        # both queued and just-received records before any database write.
        qualification=self.pump.session.deployment_guard.suspended_reason
        if qualification is not None:
            self._suspend(qualification);return
        for result in outcomes:
            self._count('observed')
            event=result.get('telemetry')
            if event is None: continue
            try:
                encoded=json.dumps(event,separators=(',',':'),allow_nan=False)
                size=len(encoded.encode())
                if type(event) is not dict or event.get('kind')!='dns_reply' or 'records' in event or not 0<size<=self.MAX_EVENT_BYTES:
                    raise ValueError('unexpected compact reply')
                # Decouple queued events from any later caller mutation.
                event=json.loads(encoded)
            except (ValueError,TypeError):
                self._count('dropped_invalid');self.pump.session.receiver_gap();continue
            if len(self.queue)>=self.MAX_EVENTS or self.bytes+size>self.MAX_BYTES:
                self._count('dropped_capacity');self.pump.session.receiver_gap();continue
            self.queue.append((event,size,now));self.bytes+=size;self._count('staged')
            if self.next_flush is None: self.next_flush=now+self.FLUSH_SECONDS
        if not self.queue:
            self.next_flush=None;return
        if now<self.next_flush: return
        batch=[row[0] for row in list(self.queue)[:self.BATCH]]
        # An overflow since staging invalidates coverage for these records too.
        if self.pump.session.mapping_incomplete:
            batch=[event|{'mapping_coverage_incomplete':True} for event in batch]
        try:
            inserted=self.store.insert(batch,now=utc_now)
        except sqlite3.Error as exc:
            code=getattr(exc,'sqlite_errorcode',None)
            if code is not None and code&255 in (sqlite3.SQLITE_BUSY,sqlite3.SQLITE_LOCKED) and not self.store.db.in_transaction:
                self._count('busy_retries');self.next_flush=now+self.RETRY_SECONDS;return
            self._count('storage_failures');self.state='failed'
            self.reason='storage_commit_unqualified:'+type(exc).__name__
            self._drop(len(self.queue),'dropped_storage_failure')
            self.pump.session.receiver_gap();return
        self._pop(len(batch));self._count('persisted',inserted)
        self._count('expired_on_insert',len(batch)-inserted);self._count('flushes')
        if inserted<len(batch): self.pump.session.receiver_gap()
        self.next_flush=now+self.FLUSH_SECONDS if self.queue else None

    def close(self):
        """No implicit final write, socket close or file deletion; caller owns them."""
        if self.state in ('ready','running'):
            self._suspend(self.pump.session.deployment_guard.suspended_reason or 'caller_closed')

    def status(self,*,now=None):
        return {'state':self.state,'reason':self.reason,'counters':dict(self.counters),
                'pending_events':len(self.queue),'pending_bytes':self.bytes,
                'limits':{'events':self.MAX_EVENTS,'bytes':self.MAX_BYTES,'batch':self.BATCH,
                    'max_wait_seconds':self.MAX_WAIT_SECONDS,'flush_seconds':self.FLUSH_SECONDS},
                'receiver':self.pump.status(now_monotonic=now),'enforcement_applied':False}
