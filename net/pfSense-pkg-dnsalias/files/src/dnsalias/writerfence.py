"""Stop an exclusively owned child writer before independent table cleanup.

No PID attachment, process discovery, launches, table operations or retries.
The caller creates the child with Popen and transfers exclusive wait/signal
ownership here. No other thread, handler or code may poll/wait/reap that child.
This parent supervisor must remain single-threaded. The controlled writer must
not fork descendants holding PF descriptors. Namespace ownership and cleanup
remain separate requirements; stopped=True only fences this owned child.

The deployed CPython Popen signal path is pinned and inspected. Keeping wait
and signal operations on one owner avoids its documented concurrent-reap race.
Only confirmed child exit permits cleanup; a timeout/error permits inspection,
not a second signal. Never use this component for Unbound or another daemon.
"""
import hashlib
import inspect
import signal
import subprocess
import sys
import threading


SIGNAL_SOURCE_SHA256='4d9a77155fddf56437eaf76ba686ff074d32045519ee3f36b1629d36ea765212'


class UnqualifiedWriterChild(RuntimeError):pass


class OwnedWriterFence:
    def __init__(self,child):
        if (not sys.platform.startswith('freebsd') or sys.version_info[:2]!=(3,11)
            or hashlib.sha256(inspect.getsource(subprocess.Popen.send_signal).encode()).hexdigest()!=SIGNAL_SOURCE_SHA256):
            raise UnqualifiedWriterChild('unqualified native child signal implementation')
        if (not isinstance(child,subprocess.Popen) or not child._child_created
            or type(child.pid) is not int or child.pid<=0):raise ValueError('directly created owned Popen child required')
        self.child=child;self.pid=child.pid;self.owner=threading.get_ident()
        self.state='watching';self.reason=None;self.signal_attempted=False;self.exit_code=None
        self._check_owner()
        self.inspect()

    def _check_owner(self):
        if (threading.get_ident()!=self.owner or threading.current_thread() is not threading.main_thread()
            or threading.active_count()!=1 or signal.getsignal(signal.SIGCHLD)!=signal.SIG_DFL
            or self.child.pid!=self.pid):
            raise UnqualifiedWriterChild('exclusive single-threaded child ownership is required')

    def inspect(self):
        self._check_owner()
        if self.state=='stopped':return self.status()
        try:code=self.child.poll()
        except Exception as exc:
            self.state='uncertain';self.reason='child_inspection_failed:'+type(exc).__name__
            return self.status()
        if code is not None:
            if type(code) is not int:raise UnqualifiedWriterChild('invalid native child exit status')
            self.state='stopped';self.exit_code=code
        return self.status()

    def stop(self,*,wait_seconds=.5):
        self._check_owner()
        if type(wait_seconds) not in (int,float) or not 0<=wait_seconds<=1:raise ValueError('bounded child-exit wait required')
        if self.state!='watching':return self.inspect()
        if self.inspect()['stopped']:return self.status()
        if self.state!='watching':return self.status()
        self.state='stopping';self.signal_attempted=True
        try:
            # SIGKILL targets only this unreaped child. No global signal or
            # numeric PID supplied by configuration is ever accepted.
            self.child.kill()
            self.exit_code=self.child.wait(timeout=wait_seconds)
            if type(self.exit_code) is not int:raise UnqualifiedWriterChild('invalid native child exit status')
            self.state='stopped';self.reason='owned_writer_stopped'
        except subprocess.TimeoutExpired:
            self.state='stop_pending';self.reason='owned_writer_exit_not_yet_confirmed'
        except Exception as exc:
            self.state='uncertain';self.reason='owned_writer_stop_uncertain:'+type(exc).__name__
        return self.status()

    def status(self):
        return {'state':self.state,'pid':self.pid,'stopped':self.state=='stopped',
            'exit_code':self.exit_code,'signal_attempted':self.signal_attempted,'reason':self.reason,
            'automatic_signal_retry':False,'namespace_cleanup_authorized':False}
