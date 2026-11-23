"""Inactive bounded reply staging during an explicitly controlled hook load.

The caller owns the load window, source checks and independent post-load audit.
This adapter never loads a hook, sends a DNS query, starts a thread, writes a
file or touches PF. Only an already-owned credential socket can be used. It
retains original reply timestamps/TTLs; the normal pump revalidates replies at
processing time after a fresh audit. Pending fragments transfer with the queue.
Any observed gap, changed generation, timeout or overflow refuses enrollment.
"""
from collections import deque
import json
import re
import time

from .deployment import DeploymentFingerprint,ProducerIdentity,DeploymentGuard,GenerationEnrollment
from .ipc import receive,RejectedMessage,IncompleteMessage,RetiredMessage,MessageAssembler,MAX_MESSAGE,Credentials
from .replyendpoint import ReplyEndpoint
from .replygate import clock


class ReplyStartup:
    MAX_EVENTS=256
    MAX_BYTES=512*1024
    MAX_SECONDS=8.0
    # An ordinary persistent service start reloads the already verified
    # resolver. Loading its policy can briefly delay its control and DNS ports.
    INITIAL_SERVICE_SECONDS=15.0
    # A newly qualified replacement process may still be loading its policy.
    # This is a service enrollment budget, independent of client DNS deadlines.
    REPLACEMENT_SECONDS=15.0
    MAX_DATAGRAMS=64
    BUDGET_SECONDS=.002

    def __init__(self,endpoint,*,expected,producer,load_open,retired_generation=None,discard_before_load=False,required_generation=None,persistent_start=False):
        if not isinstance(endpoint,ReplyEndpoint) or not endpoint.healthy():
            raise ValueError('explicit healthy owned endpoint required')
        if not isinstance(expected,DeploymentFingerprint) or not isinstance(producer,ProducerIdentity):
            raise ValueError('qualified deployment and producer required')
        clock(load_open)
        if retired_generation is not None and (not isinstance(retired_generation,GenerationEnrollment)
            or retired_generation.profile_id!=expected.identifier or retired_generation.producer.uid!=producer.uid
            or retired_generation.producer.boot_id!=producer.boot_id or retired_generation.load_close>load_open
            or retired_generation.started_monotonic>=load_open):
            raise ValueError('one prior same-boot qualified generation required')
        self.retired=retired_generation
        if required_generation is not None and (type(required_generation) is not str or not re.fullmatch('[a-f0-9]{32}',required_generation)
            or retired_generation is None or required_generation==retired_generation.generation):
            raise ValueError('fresh announced generation and retired enrollment required')
        self.required_generation=required_generation
        if type(discard_before_load) is not bool or discard_before_load and retired_generation is None:
            raise ValueError('pre-load discard requires an explicit retired generation')
        self.discard_before_load=discard_before_load
        if type(persistent_start) is not bool or persistent_start and (retired_generation is not None or discard_before_load or required_generation is not None):
            raise ValueError('initial service enrollment requires a new session')
        self.wait_seconds = self.INITIAL_SERVICE_SECONDS if persistent_start else self.MAX_SECONDS
        if discard_before_load and retired_generation.producer.pid != producer.pid:
            self.wait_seconds = self.REPLACEMENT_SECONDS
        if not 0 <= time.monotonic()-load_open < self.wait_seconds:
            raise ValueError('recent caller-controlled load window required')
        self.endpoint,self.expected,self.producer=endpoint,expected,producer
        self.load_open=load_open;self.last_poll=load_open
        self.assembler=MessageAssembler();self.queue=deque();self.bytes=0
        self.enrollment=None;self.state='collecting';self.reason=None
        self.counters={k:0 for k in ('datagrams','complete_replies','budget_yields','retired_datagrams','retired_replies','preload_replies')}

    def _fail(self,reason):
        if self.state=='collecting':
            self.state='failed';self.reason=reason;self.queue.clear();self.bytes=0

    def _healthy(self,now):
        if self.state!='collecting':return False
        try:
            clock(now)
            if now<self.last_poll or not 0<=now-self.load_open<self.wait_seconds:
                self._fail('startup_clock_or_deadline');return False
            self.last_poll=now
            if not self.endpoint.healthy():
                self._fail('startup_endpoint_changed');return False
            self.assembler.advance(now)
            if self.assembler.discarded:
                self._fail('startup_fragment_gap');return False
        except (ValueError,OSError):
            self._fail('startup_transport_unqualified');return False
        return True

    def poll(self,*,on_staged=None):
        """Nonblocking staged receive: at most64 datagrams and a2ms soft budget.

        An optional bounded nonblocking callback sees each successfully staged
        reply once. Its caller may send a warming/ignored ACK, never an applied
        ACK. This is only for startup before traffic rules are armed. Failure
        discards the queue and refuses enrollment; it is never retried here.
        """
        if on_staged is not None and not callable(on_staged):raise ValueError('explicit staged-reply callback required')
        start=time.monotonic()
        if not self._healthy(start):return self.state
        for _ in range(self.MAX_DATAGRAMS):
            if time.monotonic()-start>=self.BUDGET_SECONDS:
                self.counters['budget_yields']+=1;break
            try:
                options={}
                if self.retired is not None and self.retired.producer.pid!=self.producer.pid:
                    options['retired_pid']=self.retired.producer.pid
                reply,credentials=receive(self.endpoint.socket,expected_uid=self.producer.uid,
                    expected_pid=self.producer.pid,assembler=self.assembler,**options)
            except RetiredMessage:
                self.counters['datagrams']+=1;self.counters['retired_datagrams']+=1
                if not self._healthy(time.monotonic()):break
                continue
            except IncompleteMessage:
                self.counters['datagrams']+=1
                if not self._healthy(time.monotonic()):break
                continue
            except BlockingIOError:break
            except InterruptedError:continue
            except (RejectedMessage,OSError):
                self._fail('startup_transport_unqualified');break
            self.counters['datagrams']+=1
            now,utc_now=time.monotonic(),time.time()
            if not self._healthy(now):break
            if (self.retired is not None and isinstance(credentials,Credentials)
                and (credentials.pid,credentials.uid,credentials.euid)==(self.retired.producer.pid,self.retired.producer.uid,self.retired.producer.uid)
                and reply.get('profile_id')==self.retired.profile_id
                and (reply.get('resolver_generation'),reply.get('generation_started_monotonic'))==
                    (self.retired.generation,self.retired.started_monotonic)):
                # No queue, mapping, fresh enrollment or ACK candidate is
                # produced for an already-retired generation.
                self.counters['retired_replies']+=1;continue
            if self.discard_before_load and reply.get('profile_id')==self.expected.identifier:
                try:started=clock(reply.get('generation_started_monotonic'))
                except ValueError:started=None
                if started is not None and started<self.load_open:
                    # The native receiver authenticated the replacement PID.
                    # Its pre-reload generation is not admitted, staged or ACKed.
                    self.counters['preload_replies']+=1;continue
            try:
                candidate=GenerationEnrollment.from_reply(reply,credentials,expected=self.expected,producer=self.producer,
                    load_open=self.load_open,load_close=now,received_monotonic=now,received_utc=utc_now)
                if self.required_generation is not None and candidate.generation!=self.required_generation:
                    raise ValueError('reply differs from the authenticated reader announcement')
                if self.enrollment is not None and (candidate.generation,candidate.started_monotonic)!=(self.enrollment.generation,self.enrollment.started_monotonic):
                    raise ValueError('generation changed inside controlled startup')
                raw=json.dumps(reply,separators=(',',':'),allow_nan=False).encode()
                if len(raw)>MAX_MESSAGE or len(self.queue)>=self.MAX_EVENTS or self.bytes+len(raw)>self.MAX_BYTES:
                    self._fail('startup_capacity');break
                copied=json.loads(raw)
            except (ValueError,TypeError,KeyError,RecursionError):
                self._fail('startup_reply_unqualified');break
            if self.enrollment is None:self.enrollment=candidate
            self.queue.append((copied,credentials));self.bytes+=len(raw)
            self.counters['complete_replies']+=1
            if on_staged is not None:
                try:
                    if on_staged(reply,credentials) is not True:raise ValueError('startup acknowledgement not confirmed')
                except Exception:
                    self._fail('startup_acknowledgement_failed');break
        else:self.counters['budget_yields']+=1
        return self.state

    def take(self,guard):
        """One handoff after a matching independent post-load audit; never retry.

        The audit must START after the first authenticated reply closes the
        controlled load window. Queue ownership and pending assembler ownership
        transfer together. Disk hashes alone cannot supply this load evidence.
        """
        now=time.monotonic()
        if not self._healthy(now) or self.enrollment is None:
            raise ValueError('complete recent startup evidence required')
        if (not isinstance(guard,DeploymentGuard) or guard.expected!=self.expected or guard.producer!=self.producer):
            self._fail('startup_guard_mismatch');raise ValueError('matching independently audited guard required')
        try:guard.enroll_generation(self.enrollment,now=now)
        except ValueError:
            self._fail('startup_audit_unqualified');raise
        queued,assembler=self.queue,self.assembler
        self.queue=deque();self.assembler=None;self.bytes=0;self.state='transferred'
        return queued,assembler

    def close(self):self._fail('startup_caller_closed')

    def status(self):
        return {'state':self.state,'reason':self.reason,'queued_replies':len(self.queue),'queued_bytes':self.bytes,
            'counters':dict(self.counters),'generation_seen':self.enrollment is not None,
            'limits':{'events':self.MAX_EVENTS,'bytes':self.MAX_BYTES,'seconds':self.wait_seconds},
            'enforcement_applied':False}
