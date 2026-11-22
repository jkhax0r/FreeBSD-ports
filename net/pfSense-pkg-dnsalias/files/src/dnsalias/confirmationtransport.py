"""Bounded confirmed-reply transport enrolled by the normal alias service.

Caller supplies an owned native reader and enrolled helper lifetime check.
Each ACK socket has its own request lock. A common lock protects proof and
clock state, and is released before waiting for an ACK on any socket.
Every query still sends its full fresh observation. A receipt only avoids the
wait for an identical already-committed answer; it is not a firewall decision.
"""
import re
import select
import threading
import time
from .confirmationkey import confirmation_key,key_with_loss_counter,scope_reply_keys
from .ipc import RejectedMessage,receive,send_observation
from .replygate import ReplyGate,RejectedEpoch,clock


class ConfirmationTransport:
    MAX_PENDING=8
    MAX_RECEIVES=16
    ACK_STATUSES=('applied','ignored','helper_error')

    def __init__(self,*,helper_pid,profile_id,generation,started,lookup,alive,key=None,unchanged=None,socket_count=1,scope_absent=None):
        if (type(helper_pid) is not int or not 0<helper_pid<2**31
            or type(profile_id) is not str or not re.fullmatch('[a-f0-9]{64}',profile_id)
            or type(generation) is not str or not re.fullmatch('[a-f0-9]{32}',generation)
            or not callable(lookup) or not callable(alive) or (key is not None and not callable(key))
            or (unchanged is not None and not callable(unchanged))
            or (scope_absent is not None and not callable(scope_absent))
            or type(socket_count) is not int or not 1<=socket_count<=16):
            raise ValueError('explicit owned reader, helper lifetime and source generation required')
        self.gate=ReplyGate(max_delivery_age=.04)
        # Reuse the gate's clock validation; first exchange also checks the
        # exact controlled generation start supplied by the startup owner.
        self.started=clock(started)
        self.helper_pid,self.profile_id,self.generation=helper_pid,profile_id,generation
        self.lookup,self.alive=lookup,alive
        self.scope_absent=scope_absent
        self.unchanged=unchanged
        self.key=confirmation_key if key is None else key
        self.socket_count=socket_count
        self.lock=threading.RLock()
        self.pending={};self.clients={};self.inflight=0;self.state='ready';self.reason=None
        self.reused=0;self.scope_reused=0;self.synchronous=0;self.closed=False
        self.refreshable=True

    def disable(self,reason):
        # A new failure during qualification must prevent installing the
        # replacement even though the original disable reason stays sticky.
        with self.lock:
            if reason not in ('source_or_reload_changed','current_ack_not_applied','prior_ack_not_applied'):
                self.refreshable=False
            if self.state=='ready':self.state='disabled';self.reason=reason

    def _expire_pending(self,now):
        for token in [token for token, (deadline,slot) in self.pending.items() if deadline <= now]:
            del self.pending[token]

    def _alive(self):
        if self.state!='ready':return False
        try:
            live=self.alive()
        except Exception:pass
        else:
            if live:
                # Optional startup-enrolled native notice. Any failure is
                # permanent for this reader. Never rely on a quiet interval
                # or a subsequent clean poll to reactivate old receipts.
                if self.unchanged is None:return True
                try:stable=self.unchanged()
                except Exception:
                    self.disable('change_watch_failed');return False
                if stable is True:return True
                self.disable('source_or_reload_changed');return False
        self.disable('helper_lifetime_ended');return False

    def _previous(self,client,reply):
        token=reply.get('request_id')
        if (set(reply)!={'request_id','status'} or reply['status'] not in self.ACK_STATUSES
                or type(token) is not str or not re.fullmatch('[a-f0-9]{32}',token)):
            self.disable('prior_ack_unqualified');return
        # A well-formed ACK for an expired or untracked request cannot
        # authorize this reply. The helper independently revokes shared
        # confirmations before any invalidating table or source change.
        with self.lock:
            pending=self.pending.get(token)
            if pending is not None and pending[1]==client.slot:
                del self.pending[token]
                if reply['status']=='helper_error' and time.monotonic()<pending[0]:
                    self.disable('prior_ack_not_applied')

    def _drain(self,client):
        if self.pending:self._expire_pending(time.monotonic())
        for unused in range(self.MAX_RECEIVES):
            if not select.select([client.socket],[],[],0)[0]:break
            reply,_=receive(client.socket,expected_uid=0,expected_pid=self.helper_pid)
            self._previous(client,reply)

    def _wait(self,client,token,deadline):
        for unused in range(self.MAX_RECEIVES):
            remaining=deadline-time.monotonic()
            if remaining<=0:break
            try:
                if not select.select([client.socket],[],[],remaining)[0]:break
                reply,_=receive(client.socket,expected_uid=0,expected_pid=self.helper_pid)
            except RejectedMessage:
                with self.lock:self.refreshable=False
                continue
            except (BlockingIOError,InterruptedError):continue
            except OSError:self.disable('receive_failed');return 'unavailable'
            if time.monotonic()>=deadline:break
            if reply.get('request_id')==token:
                if set(reply)=={'request_id','status'} and reply['status'] in self.ACK_STATUSES:
                    if reply['status']=='helper_error':self.disable('current_ack_not_applied')
                    return reply['status']
                self.disable('current_ack_invalid');return 'invalid_ack'
            self._previous(client,reply)
        if time.monotonic()>=deadline:return 'ack_expired'
        self.disable('current_ack_receive_limit')
        return 'receive_limit'

    def _send(self,client,event):
        token=client.request_id()
        result=send_observation(client.socket,client.destination,event|{'request_id':token})
        if result!='queued':self.disable('send_failed')
        return token,result

    def _prepare(self,client,event,deadline):
        """Run under the common proof lock. Return a token only for an exact wait."""
        if self.closed:return None,'unavailable'
        slot=client.slot
        valid_slot=slot is None if self.socket_count==1 else type(slot) is int and 0<=slot<self.socket_count
        if client.helper_pid!=self.helper_pid or not valid_slot:
            raise ValueError('reader/helper or ACK slot differs')
        if self.clients.setdefault(slot,client) is not client:
            raise ValueError('reader cannot move to a different ACK socket')
        try:
            self._drain(client)
            now,utc=time.monotonic(),time.time()
            if now>=deadline:return None,'ack_expired'
            digest=None
            if self.state=='ready':
                if (event.get('profile_id')!=self.profile_id or event.get('resolver_generation')!=self.generation
                    or event.get('generation_started_monotonic')!=self.started):
                    self.disable('source_or_generation_changed')
                else:
                    try:
                        if now-clock(event['monotonic'])>=self.gate.max_age:return None,'ack_expired'
                        self.gate.accept(event,received_monotonic=now,received_utc=utc)
                    except (RejectedEpoch,KeyError):self.disable('reply_clock_unqualified')
                if self._alive():digest=key_with_loss_counter(event,self.key)
            receipt=self.lookup(digest) if digest is not None else None
            reuse=receipt is not None and self._alive()
            scope_keys=scope_receipt=None
            if not reuse and self.scope_absent is not None and self._alive():
                scope_keys=scope_reply_keys(event)
                if scope_keys is not None:scope_receipt=self.scope_absent(scope_keys)
            if not reuse:
                if time.monotonic()>=deadline:return None,'ack_expired'
            token,result=self._send(client,event)
            if result!='queued':return None,result
            again=self.lookup(digest) if reuse else None
            scoped=(scope_receipt is not None and self.scope_absent(scope_keys)==scope_receipt)
            if ((again is not None and again[0]==receipt[0]) or scoped) and time.monotonic()<deadline and self._alive():
                # Bound bookkeeping without waiting for other requests. Every
                # admitted observation still goes to the bounded kernel queue.
                if len(self.pending)>=self.MAX_PENDING*self.socket_count:del self.pending[next(iter(self.pending))]
                self.pending[token]=(deadline,slot)
                self.reused+=1
                if scoped:self.scope_reused+=1
                return None,'applied'
            # The observation is already sent; consume its exact ACK once.
            self.synchronous+=1
            self.inflight+=1
            return token,'queued'
        except Exception:
            # A send may have happened. Never retransmit an uncertain action.
            self.disable('transport_uncertain');return None,'unavailable'

    def _complete(self,client,prepared,deadline):
        token,result=prepared
        if token is None:return result
        try:
            return self._wait(client,token,deadline)
        except Exception:
            self.disable('transport_uncertain')
            return 'unavailable'
        finally:
            with self.lock:self.inflight-=1

    def exchange(self,client,event,deadline):
        """Call only while holding this client's existing request/ACK lock."""
        with self.lock:prepared=self._prepare(client,event,deadline)
        return self._complete(client,prepared,deadline)

    def close(self):
        with self.lock:
            self.disable('reader_closed');self.closed=True
        # Reader/watch ownership remains with the startup owner. Closing this
        # transport never drains sockets, sends requests, or deletes paths.

    def status(self):
        with self.lock:
            return {'state':'closed' if self.closed else self.state,'reason':self.reason,
                    'pending':len(self.pending),'reused':self.reused,'scope_reused':self.scope_reused,'synchronous':self.synchronous}
