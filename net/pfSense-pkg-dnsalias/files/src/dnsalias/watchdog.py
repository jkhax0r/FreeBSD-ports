"""Pure helper-liveness guard; no PF access or process control.

The caller must authenticate every heartbeat's kernel PID/UID and independently
verify ownership before clearing any table. This guard never revives after an
expiry; a fresh ownership/profile qualification must create a new guard.
"""
import math
import re

from .replygate import clock


class HelperWatchdog:
    def __init__(self,epoch,*,armed_monotonic,timeout=2.0):
        if not isinstance(epoch,str) or not re.fullmatch('[a-f0-9]{32}',epoch): raise ValueError('helper epoch required')
        if type(timeout) not in (int,float) or not math.isfinite(timeout) or not .1<=timeout<=3:
            raise ValueError('helper timeout must be 0.1 to 3 seconds')
        self.epoch,self.timeout=epoch,timeout
        self.last_poll=clock(armed_monotonic)
        self.deadline=self.last_poll+timeout
        self.last_sent=None;self.sequence=-1;self.reason=None

    def expired(self,now,*,helper_alive=True):
        if self.reason is not None: return True
        try: now=clock(now)
        except ValueError:
            self.reason='invalid_monotonic_clock';return True
        if now<self.last_poll: self.reason='monotonic_clock_reversed'
        elif helper_alive is not True: self.reason='helper_dead_or_identity_unknown'
        elif now>=self.deadline: self.reason='helper_heartbeat_expired'
        self.last_poll=now
        return self.reason is not None

    def heartbeat(self,event,*,received_monotonic):
        if self.expired(received_monotonic): return False
        if not isinstance(event,dict) or set(event)!={'format','epoch','sequence','sent_monotonic'}:
            return False
        if event['format']!='dnsalias-helper-heartbeat-1' or event['epoch']!=self.epoch: return False
        sequence=event['sequence']
        if type(sequence) is not int or not self.sequence<sequence<2**63: return False
        try: sent=clock(event['sent_monotonic'])
        except ValueError: return False
        if not 0<=received_monotonic-sent<self.timeout or self.last_sent is not None and sent<=self.last_sent:
            return False
        self.last_sent,self.sequence=sent,sequence
        # A delayed heartbeat may only renew from its actual send time.
        self.deadline=sent+self.timeout
        return True
