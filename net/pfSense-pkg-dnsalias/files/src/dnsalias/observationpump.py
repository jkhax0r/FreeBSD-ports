"""Inactive bounded receiver for an already-owned local reply socket.

No binding, file creation, background process, hooks, PF or telemetry writes.
Caller must qualify socket-path ownership and actual producer/profile before
constructing this adapter. It returns compact observation outcomes; callers
must not infer DNS policy success/failure from mapping acceptance/rejection.
"""
import math
import time
from collections import deque
from .ipc import configure_receiver,receive,RejectedMessage,IncompleteMessage,MessageAssembler
from .observation import ReplyObservationSession
from .replyendpoint import ReplyEndpoint
from .replystartup import ReplyStartup


class ReplyObservationPump:
    def __init__(self,sock,session,*,max_datagrams=64,budget_seconds=.002,endpoint=None,startup=None):
        if not isinstance(session,ReplyObservationSession): raise ValueError('qualified observation session required')
        if type(max_datagrams) is not int or not 1<=max_datagrams<=64: raise ValueError('bounded datagram budget required')
        if type(budget_seconds) not in (int,float) or not math.isfinite(budget_seconds) or not 0<budget_seconds<=.01:
            raise ValueError('bounded processing budget required')
        if endpoint is not None and (not isinstance(endpoint,ReplyEndpoint) or endpoint.socket is not sock or not endpoint.healthy()):
            raise ValueError('receiver must match a healthy owned endpoint')
        if startup is not None and (not isinstance(startup,ReplyStartup) or startup.endpoint is not endpoint):
            raise ValueError('startup must own this exact endpoint')
        configure_receiver(sock)
        self.endpoint=endpoint;self.stopped_reason=None
        self.socket,self.session=sock,session
        self.max_datagrams,self.budget=max_datagrams,budget_seconds
        self.assembler=MessageAssembler();self.seen_discards=0
        self.startup=deque()
        if startup is not None:self.startup,self.assembler=startup.take(session.deployment_guard)
        self.counters={key:0 for key in ('fragments','complete_replies','startup_replies','transport_rejected','transport_errors','budget_yields')}

    def count(self,key): self.counters[key]=min(2**63-1,self.counters[key]+1)

    def _gaps(self):
        if self.assembler.discarded>self.seen_discards:
            self.session.receiver_gap();self.seen_discards=self.assembler.discarded

    def poll(self):
        """Soft time budget checked between bounded messages; never waits on I/O.

        The caller schedules readiness/polls. This is not a thread or an event
        loop, and must not be called synchronously from a DNS reply callback.
        """
        outcomes=[];start=time.monotonic()
        if self.stopped_reason is not None: return outcomes
        if self.endpoint is not None and not self.endpoint.healthy():
            self.stopped_reason='receiver_endpoint_changed';self.session.receiver_gap();return outcomes
        try: self.assembler.advance(start)
        except RejectedMessage:
            self.session.receiver_gap();self.count('transport_errors');return outcomes
        self._gaps()
        for _ in range(self.max_datagrams):
            if time.monotonic()-start>=self.budget:
                self.count('budget_yields');break
            if self.startup:
                reply,credentials=self.startup.popleft()
                self.count('startup_replies');self.count('complete_replies')
                outcome=self.session.observe(reply,credentials,received_monotonic=time.monotonic(),received_utc=time.time())
                if 'telemetry' not in outcome:self.session.receiver_gap()
                outcomes.append(outcome);continue
            try:
                reply,credentials=receive(self.socket,expected_uid=self.session.uid,expected_pid=self.session.pid,assembler=self.assembler)
            except IncompleteMessage:
                self.count('fragments');self._gaps();continue
            except BlockingIOError: break
            except InterruptedError: continue
            except RejectedMessage:
                # Conservative coverage loss, not a firewall/DNS block. A new
                # explicitly qualified session is required to restore coverage.
                self.count('transport_rejected');self.session.receiver_gap();self._gaps();continue
            except OSError:
                self.count('transport_errors');self.session.receiver_gap();break
            self.count('fragments');self.count('complete_replies');self._gaps()
            outcomes.append(self.session.observe(reply,credentials,received_monotonic=time.monotonic(),received_utc=time.time()))
        else: self.count('budget_yields')
        return outcomes

    def status(self,*,now_monotonic=None):
        return {'mode':'observation_only','counters':dict(self.counters),
                'stopped_reason':self.stopped_reason,'endpoint':self.endpoint.status() if self.endpoint is not None else None,
                'pending_messages':len(self.assembler.pending),'pending_bytes':self.assembler.bytes,
                'pending_startup_replies':len(self.startup),
                'discarded_messages':self.assembler.discarded,'max_datagrams_per_poll':self.max_datagrams,
                'soft_budget_seconds':self.budget,'observation':self.session.status(now_monotonic=now_monotonic)}
