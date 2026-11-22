"""Bounded background enrollment after a source or firewall change.

The shared proof lock coordinates enrollment across resolver workers. A
worker waits for its exact ACK outside that lock. The enrollment thread only
obtains fresh watch capabilities and never reads a DNS ACK socket.
"""
import threading
import uuid
from .confirmationtransport import ConfirmationTransport
from .watchstartup import FilterWatchEnrollment


class RefreshingTransport:
    def __init__(self,transport,notice,*,native_watch):
        if type(transport) is not ConfirmationTransport or type(notice) is not FilterWatchEnrollment:
            raise ValueError('exact enrolled transport and source notice required')
        if notice.state!='ready' or not notice.value.get('source_watches') or not notice.manifest_digest:
            raise ValueError('committed source watch required')
        self.current=transport;self.notice=notice;self.native=native_watch
        self.lock=transport.lock
        self.original_token=notice.value['token'];self.sequence=0
        self.thread=None;self.candidate=None;self.failure=None;self.closed=False
        self.completed=0;self.retired_reused=0;self.retired_scope_reused=0;self.retired_synchronous=0

    def _begin(self):
        self.sequence+=1
        current=self.current;value=dict(self.notice.value)
        value['token']=uuid.uuid4().hex+uuid.uuid4().hex
        request={'watch_refresh':self.original_token,'nonce':value['token'],'sequence':self.sequence,
                 'profile_id':current.profile_id,'resolver_generation':current.generation,
                 'source_manifest':self.notice.manifest_digest}
        def enroll():
            try:
                candidate=FilterWatchEnrollment(value,helper_pid=current.helper_pid,
                    profile_id=current.profile_id,generation=current.generation,
                    native_watch=self.native,refresh_request=request)
                with self.lock:
                    if self.closed:candidate.close()
                    else:self.candidate=candidate
            except Exception as exc:
                with self.lock:self.failure='refresh_failed:'+type(exc).__name__
        self.thread=threading.Thread(target=enroll,name='dnsalias-reader-refresh',daemon=True)
        self.thread.start()

    def _finish(self):
        old=self.current;candidate=self.candidate
        if not old.refreshable or not old.alive() or not candidate.unchanged():
            candidate.close();self.candidate=None;self.failure='refresh_no_longer_qualified';return
        fresh=ConfirmationTransport(helper_pid=old.helper_pid,profile_id=old.profile_id,
            generation=old.generation,started=old.started,lookup=old.lookup,
            alive=old.alive,key=old.key,unchanged=candidate.unchanged,socket_count=old.socket_count,scope_absent=old.scope_absent)
        # Keep clock-regression history; fresh capabilities are not a new DNS
        # generation and cannot erase a previous reply's clock evidence.
        fresh.gate=old.gate;fresh.clients=old.clients;fresh.lock=self.lock
        self.retired_reused+=old.reused;self.retired_synchronous+=old.synchronous
        self.retired_scope_reused+=old.scope_reused
        old.close();self.notice.close()
        self.current=fresh;self.notice=candidate;self.candidate=None;self.thread=None
        self.completed+=1

    def exchange(self,client,event,deadline):
        with self.lock:
            if self.closed:return 'unavailable'
            current=self.current
            prepared=current._prepare(client,event,deadline)
        result=current._complete(client,prepared,deadline)
        with self.lock:
            if self.closed or current is not self.current:return result
            self._consider_refresh(current,result)
        return result

    def _consider_refresh(self,current,result):
        # Complete one ordinary exact ACK before starting or installing a
        # replacement. _drain/_wait account for previous asynchronous ACKs.
        if (result=='applied' and current.state=='disabled' and current.refreshable
            and not current.pending and not current.inflight and not self.failure):
            try:
                if self.thread is None:
                    # A delivered error can also come from taking the reload
                    # lock without modifying its file. This later exact ACK,
                    # empty ACK ledger and NEW root-side table/source audit
                    # qualify a replacement; the old reader never resumes.
                    changed=not self.notice.unchanged() and self.notice.state=='changed'
                    if changed or current.reason in ('current_ack_not_applied','prior_ack_not_applied'):
                        self._begin()
                elif not self.thread.is_alive() and self.candidate is not None:self._finish()
            except Exception as exc:
                self.failure='refresh_completion_failed:'+type(exc).__name__
    def close(self):
        with self.lock:self.closed=True
        if self.thread is not None:self.thread.join(timeout=1.2)
        if self.thread is not None and self.thread.is_alive():
            raise RuntimeError('reader enrollment still active; retain notice resources')
        if self.candidate is not None:self.candidate.close();self.candidate=None
        self.current.close();self.notice.close()

    def status(self):
        with self.lock:
            result=self.current.status()
            result['reused']+=self.retired_reused;result['synchronous']+=self.retired_synchronous
            result['scope_reused']+=self.retired_scope_reused
            result['refresh']={'completed':self.completed,'sequence':self.sequence,'failure':self.failure,
                               'pending':bool(self.thread and self.thread.is_alive())}
            return result
