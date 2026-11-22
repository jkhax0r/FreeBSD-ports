"""Bounded request/ack transport; inactive until a qualified helper is wired.

One configured root helper PID may acknowledge a request. This transport alone
does not prove PF correctness, serialize filter reloads or enforce DNS policy.
"""
import math
import select
import threading
import time
import uuid

from .ipc import RejectedMessage,receive,send_observation


class ReplyAcknowledger:
    def __init__(self,sock,destination,*,helper_pid,timeout=.05,cooldown=.5,confirmation=None,slot=None):
        if type(helper_pid) is not int or helper_pid<=0:
            raise ValueError('explicit helper PID required')
        if type(timeout) not in (int,float) or not math.isfinite(timeout) or not 0<timeout<=.1:
            raise ValueError('acknowledgement budget must be at most 100 ms')
        if type(cooldown) not in (int,float) or not math.isfinite(cooldown) or not .1<=cooldown<=5:
            raise ValueError('helper retry cooldown must be 0.1 to 5 seconds')
        self.socket,self.destination=sock,destination
        self.helper_pid,self.timeout=helper_pid,timeout
        self.cooldown,self.retry_after=cooldown,0
        if confirmation is not None and not callable(getattr(confirmation,'exchange',None)):
            raise ValueError('explicit confirmation transport required')
        if slot is not None and (type(slot) is not int or not 0<=slot<16):
            raise ValueError('bounded ACK slot required')
        self.slot=slot
        self.confirmation=confirmation
        self.lock=threading.Lock()

    def request_id(self):
        token=uuid.uuid4().hex
        return token if self.slot is None else f'e{self.slot:x}'+token[2:]

    def exchange(self,event):
        if not isinstance(event,dict): raise ValueError('reply event required')
        started=time.monotonic()
        if started<self.retry_after: return 'cooldown'
        deadline=started+self.timeout
        if not self.lock.acquire(timeout=self.timeout): return 'busy'
        try:
            # Another worker may have detected failure while this one waited.
            if time.monotonic()<self.retry_after: return 'cooldown'
            result=self._exchange_locked(event,deadline)
            # A matching authenticated negative ACK proves delivery, even
            # though PF synchronization failed. It is not a transport outage;
            # keep reporting later observations without manufacturing a gap.
            # An individual confirmation deadline is not a socket outage.
            if result not in ('applied','ignored','helper_error','ack_expired'):
                self.retry_after=time.monotonic()+self.cooldown
            return result
        finally:
            self.lock.release()

    def _exchange_locked(self,event,deadline):
        if self.confirmation is not None:return self.confirmation.exchange(self,event,deadline)
        # Cooldown skips transmission; it never claims a mapping was installed.
        # A caller enabling enforcement must choose an explicit failure policy.
        # Only a fresh matching authenticated ACK can recover this transport.
        try:
            if time.monotonic()>=deadline: return 'timeout'
            token=self.request_id()
            sent=send_observation(self.socket,self.destination,event|{'request_id':token})
            if sent!='queued': return sent
            for _ in range(16):
                remaining=deadline-time.monotonic()
                if remaining<=0: return 'timeout'
                try:
                    ready,_,_=select.select([self.socket],[],[],remaining)
                    if not ready: return 'timeout'
                    reply,_=receive(self.socket,expected_uid=0,expected_pid=self.helper_pid)
                except (BlockingIOError,InterruptedError,RejectedMessage):
                    continue
                except OSError: return 'unavailable'
                if time.monotonic()>=deadline: return 'timeout'
                if reply.get('request_id')!=token: continue
                if set(reply)!={'request_id','status'} or reply['status'] not in ('applied','ignored','helper_error'):
                    return 'invalid_ack'
                return reply['status']
            return 'receive_limit'
        except OSError: return 'unavailable'
