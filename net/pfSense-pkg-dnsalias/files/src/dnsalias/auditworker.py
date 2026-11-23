"""Inactive bounded off-path audit scheduler; no default capture or live wiring.

One caller-supplied capture runs at a time, outside DNS callbacks and receiver
polling. It must own its I/O resources and return independently qualified,
immutable deployment/producer identities. This class supplies no attestation.
Only one receipt is retained. Capture failures and late results stop the worker;
they are not retried. The consumer never waits for capture or takes a blocking
lock. Audit freshness starts at capture start, not when its result is consumed.

A callback blocked in filesystem I/O cannot be forcibly canceled by a thread.
The caller must enforce I/O bounds, retain ownership until stop completes, and
let the deployment guard expire meanwhile. close() reports pending cleanup;
it never claims that a still-running capture was stopped or closes its resources
underneath it. No subprocess, network call, file write or restart is built in.
"""
from dataclasses import dataclass
import math
import threading
import time

from .deployment import DeploymentFingerprint,DeploymentGuard,ProducerIdentity


class InitialAuditTimeout(TimeoutError):
    """A persistent service's first settings read timed out before any receipt."""


@dataclass(frozen=True)
class AuditReceipt:
    sequence: int
    started: float
    finished: float
    deployment: object
    producer: object
    error: object


class AuditWorker:
    def __init__(self,capture,*,interval_seconds=2,budget_seconds=1):
        if not callable(capture): raise ValueError('explicit independent capture required')
        if (type(interval_seconds) not in (int,float) or not math.isfinite(interval_seconds)
            or not 1<=interval_seconds<=3): raise ValueError('audit interval must be1..3seconds')
        if (type(budget_seconds) not in (int,float) or not math.isfinite(budget_seconds)
            or not 0<budget_seconds<=1): raise ValueError('capture budget must be0..1second')
        self.capture=capture;self.interval=interval_seconds;self.budget=budget_seconds
        self.stop=threading.Event();self.lock=threading.Lock();self.thread=None
        self.latest=None;self.sequence=0;self.delivered=0;self.failure=None
        self.initial_retry=False

    def start(self):
        if self.thread is not None or self.stop.is_set(): raise ValueError('worker cannot be restarted')
        self.thread=threading.Thread(target=self._run,name='dnsalias-audit',daemon=True)
        try:self.thread.start()
        except Exception:
            self.failure='audit_worker_start_failed';self.stop.set();raise

    def _run(self):
        while not self.stop.is_set():
            started=time.monotonic();deployment=producer=None;error=None
            try:
                result=self.capture()
                if (type(result) is not tuple or len(result)!=2
                    or not isinstance(result[0],DeploymentFingerprint) or not isinstance(result[1],ProducerIdentity)):
                    raise ValueError('bounded immutable audit identities required')
                deployment,producer=result
            except InitialAuditTimeout:
                elapsed=time.monotonic()-started
                if self.sequence==0 and not self.initial_retry and 0<=elapsed<=self.budget:
                    # No receipt has qualified this session. Retry one complete
                    # capture on the worker, within the original enrollment window.
                    self.initial_retry=True
                    if self.stop.wait(.1):break
                    continue
                error='audit_initial_read_timed_out'
            except Exception as exc:
                # Do not publish exception messages, which may contain file
                # contents, credentials or an unbounded remote response.
                error='audit_capture_failed:'+type(exc).__name__[:60]
            finished=time.monotonic()
            if not 0<=finished-started<=self.budget:error='audit_capture_deadline'
            if self.stop.is_set():break
            with self.lock:
                self.sequence+=1
                self.latest=AuditReceipt(self.sequence,started,finished,
                    None if error else deployment,None if error else producer,error)
                if error:self.failure=error
            if error:break
            # Never catch up a missed schedule with a burst of repeated reads.
            if self.stop.wait(max(0,self.interval-(finished-started))):break

    def apply(self,guard,*,now=None):
        """Main-loop call: apply at most one receipt without waiting for work."""
        if not isinstance(guard,DeploymentGuard):raise ValueError('explicit deployment guard required')
        now=time.monotonic() if now is None else now
        if self.stop.is_set():guard.suspend('audit_worker_stopped')
        elif self.thread is None:guard.suspend('audit_worker_not_started')
        elif self.failure is not None:guard.suspend(self.failure)
        elif not self.thread.is_alive():guard.suspend('audit_worker_ended')
        elif self.lock.acquire(blocking=False):
            try:
                receipt=self.latest
                if receipt is not None and receipt.sequence>self.delivered:
                    self.delivered=receipt.sequence
                else:receipt=None
            finally:self.lock.release()
            if receipt is not None:
                if receipt.error:guard.suspend(receipt.error)
                else:guard.audit(receipt.deployment,receipt.producer,now=now,captured_monotonic=receipt.started)
        return guard.check(now=now)

    def close(self,*,wait_seconds=.1):
        if (type(wait_seconds) not in (int,float) or not math.isfinite(wait_seconds)
            or not 0<=wait_seconds<=.1):raise ValueError('bounded worker stop wait required')
        self.stop.set()
        if self.thread is not None and self.thread.ident is not None:
            self.thread.join(wait_seconds)
            return not self.thread.is_alive()
        return True

    def status(self):
        alive=self.thread is not None and self.thread.is_alive()
        return {'state':('stopping' if alive else 'stopped') if self.stop.is_set() else
            'failed' if self.failure else 'running' if alive else 'not_started',
            'error':self.failure,'published':self.sequence,'delivered':self.delivered,
            'interval_seconds':self.interval,'capture_budget_seconds':self.budget,
            'retained_receipt_limit':1,'enforcement_qualified':False}
