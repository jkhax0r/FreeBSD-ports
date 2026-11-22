"""One demand-driven, read-only settings lookup outside the DNS receiver.

The caller supplies bounded capture and config identity functions, retains
source ownership during capture, and applies accepted results on its own loop.
No timer, policy/PF mutation, process discovery or repeated action lives here.
"""
import threading
import time


class PolicyRefresh:
    def __init__(self,capture,identity):
        if not callable(capture) or not callable(identity):raise ValueError('explicit read-only callbacks required')
        self.capture,self.identity=capture,identity
        self.thread=None;self.result=None;self.closed=False;self.pending_apply=None
        self.reads=0;self.discarded=0;self.last_ms=None;self.apply_deferrals=0

    def request(self,stamp):
        if self.closed:raise ValueError('settings reader is closed')
        if self.thread is not None or self.pending_apply is not None:return False
        self.result=None;self.reads+=1
        def read():
            started=time.monotonic();value=error=None;stable=False
            try:
                if self.identity()==stamp:
                    value=self.capture();stable=self.identity()==stamp
            except Exception as exc:error=exc
            self.result=(stamp,value,error,stable,(time.monotonic()-started)*1000)
        self.thread=threading.Thread(target=read,name='dnsalias-settings-reader',daemon=False)
        self.thread.start();return True

    def take(self,current):
        if self.closed:raise ValueError('settings reader is closed')
        if self.pending_apply is not None:
            result,self.pending_apply=self.pending_apply,None
            if result[0]!=current:
                self.discarded+=1;return None
            return result
        if self.thread is None or self.thread.is_alive():return None
        self.thread.join();self.thread=None
        result,self.result=self.result,None
        if result is None:raise RuntimeError('settings reader ended without a result')
        stamp,value,error,stable,self.last_ms=result
        if current!=stamp:
            self.discarded+=1;return None
        if error is not None:raise error
        if not stable:
            self.discarded+=1;return None
        return stamp,value

    def defer_apply(self,result):
        """Keep one accepted snapshot after a known-unexecuted lock refusal.

        This stores data only. The owner must establish that no uncertain
        processing occurred, and take() rechecks the current config identity.
        A waiting snapshot never starts another settings read or worker.
        """
        if self.closed:raise ValueError('settings reader is closed')
        if self.thread is not None or self.pending_apply is not None:
            raise ValueError('pending settings work must not be overwritten')
        if type(result) is not tuple or len(result)!=2:raise ValueError('accepted settings snapshot required')
        self.pending_apply=result;self.apply_deferrals+=1

    def close(self,wait_seconds=3):
        self.closed=True;self.pending_apply=None
        if self.thread is not None:self.thread.join(timeout=wait_seconds)
        return self.thread is None or not self.thread.is_alive()

    def status(self):
        return {'running':bool(self.thread and self.thread.is_alive()),'reads':self.reads,
                'discarded_changed_snapshots':self.discarded,'last_read_ms':self.last_ms,
                'application_pending':self.pending_apply is not None,'application_deferrals':self.apply_deferrals,
                'dns_waits_for_settings_read':False}
