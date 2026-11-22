"""Inactive FreeBSD process lifetime watch using the installed Python API.

No signals, process launches, ABI casts, ps parsing or package dependencies.
An enrollment ID is fresh for every watch, including reattachment to the same
PID. It is not a kernel start timestamp or proof of loaded code/credentials.
The supervisor must separately qualify those facts and poll this watch before
auditing the deployment guard. Exit, errors and closure cannot recover silently.
"""
import hashlib
import select
import sys
import uuid


class ProcessLifetimeWatch:
    def __init__(self,pid):
        if type(pid) is not int or not 0<pid<2**31:
            raise ValueError('explicit producer PID required')
        if not sys.platform.startswith('freebsd') or not all(hasattr(select,n) for n in
                ('kqueue','kevent','KQ_FILTER_PROC','KQ_EV_ADD','KQ_EV_ONESHOT','KQ_EV_ERROR','KQ_NOTE_EXIT','KQ_NOTE_EXEC')):
            raise RuntimeError('qualified FreeBSD process watch unavailable')
        self.pid=pid;self.state='enrolling';self.reason=None;self.queue=None
        self.lifetime_id=hashlib.sha256(('dnsalias-process-watch-1:'+str(pid)+':'+uuid.uuid4().hex).encode()).hexdigest()
        try:
            self.queue=select.kqueue()
            event=select.kevent(pid,filter=select.KQ_FILTER_PROC,
                flags=select.KQ_EV_ADD|select.KQ_EV_ONESHOT,fflags=select.KQ_NOTE_EXIT|select.KQ_NOTE_EXEC)
            self.queue.control([event],0,0)
            self.state='watching'
            if not self.alive(): raise RuntimeError('producer ended during enrollment')
        except Exception:
            self._stop('failed','enrollment_failed');raise

    def _stop(self,state,reason):
        self.state=state;self.reason=reason
        if self.queue is not None:
            queue,self.queue=self.queue,None
            try: queue.close()
            except OSError: pass

    def alive(self):
        if self.state!='watching': return False
        try: events=self.queue.control(None,1,0)
        except OSError:
            self._stop('failed','watch_read_failed');return False
        if not events: return True
        event=events[0]
        if event.ident!=self.pid or event.filter!=select.KQ_FILTER_PROC or event.flags&select.KQ_EV_ERROR:
            self._stop('failed','watch_event_unqualified')
        elif event.fflags&select.KQ_NOTE_EXIT:
            self._stop('exited','producer_exited')
        elif event.fflags&select.KQ_NOTE_EXEC:
            self._stop('changed','producer_executed')
        else: self._stop('failed','watch_event_unqualified')
        return False

    def close(self):
        if self.state=='watching': self._stop('closed','caller_closed')

    def status(self):
        self.alive()
        return {'pid':self.pid,'state':self.state,'reason':self.reason,
                'lifetime_id':self.lifetime_id,
                'identity_basis':'fresh_kernel_process_watch_enrollment',
                'loaded_code_verified':False,'credentials_verified':False}

    def __enter__(self): return self
    def __exit__(self,*args): self.close()
