"""Pure clock/reload checks after kernel producer authentication, before leases."""
import math
import re


class RejectedEpoch(ValueError): pass


def clock(value):
    if type(value) not in (int,float) or not math.isfinite(value) or value<0:
        raise RejectedEpoch('invalid clock')
    return value


class ReplyGate:
    def __init__(self, max_delivery_age=5.0, clock_tolerance=.25):
        if not 0<max_delivery_age<=5 or not 0<clock_tolerance<=1:
            raise ValueError('unsafe clock bounds')
        self.max_age,self.tolerance=max_delivery_age,clock_tolerance
        self.active=None
        self.received=None
        self.clock_blocked=False

    def accept(self, event, *, received_monotonic, received_utc):
        if self.clock_blocked: raise RejectedEpoch('clock requires explicit requalification')
        mono,utc=clock(received_monotonic),clock(received_utc)
        observed_mono,observed_utc=clock(event['monotonic']),clock(event['time'])
        started=clock(event['generation_started_monotonic'])
        generation=event['resolver_generation']
        if not isinstance(generation,str) or not re.fullmatch('[a-f0-9]{32}',generation):
            raise RejectedEpoch('invalid resolver generation')
        if self.received is not None:
            prior_mono,prior_utc=self.received
            if mono<prior_mono or abs((utc-prior_utc)-(mono-prior_mono))>self.tolerance:
                self.clock_blocked=True
                raise RejectedEpoch('receiver clock discontinuity')
        age=mono-observed_mono
        if not 0<=age<=self.max_age or started>observed_mono:
            raise RejectedEpoch('stale, future or invalid generation time')
        if abs((utc-observed_utc)-age)>self.tolerance:
            self.clock_blocked=True
            raise RejectedEpoch('sender/receiver clocks disagree')
        changed=self.active is None or self.active!=(started,generation)
        if changed and self.active is not None and (started<=self.active[0] or generation==self.active[1]):
            raise RejectedEpoch('retired or ambiguous resolver generation')
        # Rejected input never advances a generation or trusted receive clock.
        self.active=(started,generation)
        self.received=(mono,utc)
        return {'generation':generation,'generation_changed':changed,'delivery_age':age}
