"""Inactive reply-to-statistics composition; no sockets, PF, files or DNS hooks.

The service must qualify the deployed resolver profile and supply Credentials
obtained from ipc.receive, not fields claimed by the sender. This in-process
composition is not a substitute for kernel authentication or hook ownership.
It observes all authenticated client replies, independently of alias policies.
No result means that a firewall table was updated or traffic was permitted.
"""
from copy import copy
import ipaddress

from .attribution import MappingHistory
from .ipc import Credentials
from .deployment import DeploymentGuard
from .replygate import ReplyGate,RejectedEpoch
from .replynormalize import ReplyProfile,UnqualifiedReply,normalize
from .replytelemetry import summarize


class ReplyObservationSession:
    def __init__(self, *, profile, producer_uid, producer_pid,
                 max_mappings=20000, history_seconds=86400, deployment_guard=None):
        if not isinstance(profile,ReplyProfile): raise ValueError('qualified profile required')
        if type(producer_uid) is not int or not 0<=producer_uid<2**32 or type(producer_pid) is not int or not 0<producer_pid<2**31:
            raise ValueError('explicit qualified producer identity required')
        self.profile,self.uid,self.pid=profile,producer_uid,producer_pid
        if deployment_guard is not None:
            if (not isinstance(deployment_guard,DeploymentGuard)
                or deployment_guard.expected.identifier!=profile.identifier
                or deployment_guard.expected.excluded_addresses!=profile.excluded_addresses
                or (deployment_guard.producer.pid,deployment_guard.producer.uid)!=(producer_pid,producer_uid)):
                raise ValueError('deployment guard must match profile and producer')
        self.deployment_guard=deployment_guard
        self.gate=ReplyGate()
        self.history=MappingHistory(max_mappings=max_mappings,history_seconds=history_seconds)
        self.counters={key:0 for key in ('mapped','no_live_mapping','untrusted_producer','profile_mismatch',
                                       'invalid_client','clock_or_epoch_rejected','unqualified_reply','capacity_gap',
                                       'invalid_transport_health','transport_gap_reports','receiver_gap_reports','deployment_unqualified')}
        self.mapping_incomplete=False
        self.last_reply_utc=None

    def receiver_gap(self):
        """Local receiver reports rejected, lost or expired input; never clear it implicitly."""
        self.mapping_incomplete=True
        self.counters['receiver_gap_reports']=min(2**63-1,self.counters['receiver_gap_reports']+1)

    def _result(self,reason,**values):
        self.counters[reason]=min(2**63-1,self.counters[reason]+1)
        return {'result':reason,'enforcement_applied':False}|values

    def observe(self,reply,credentials,*,received_monotonic,received_utc):
        """Validate first; never let rejected reply data retire a valid epoch."""
        if (not isinstance(credentials,Credentials)
            or any(type(n) is not int for n in (credentials.pid,credentials.uid,credentials.euid))
            or (credentials.pid,credentials.uid,credentials.euid)!=(self.pid,self.uid,self.uid)):
            return self._result('untrusted_producer')
        if type(reply) is not dict or reply.get('profile_id')!=self.profile.identifier:
            # Authenticated data from an unexpected profile can indicate a
            # same-PID hook change before the next source audit. Unguarded
            # offline sessions still reject it without advancing their clock.
            if self.deployment_guard is not None:
                self.deployment_guard.suspend('reply_profile_changed')
                self.mapping_incomplete=True
            return self._result('profile_mismatch')
        if self.deployment_guard is not None:
            reason=self.deployment_guard.check(now=received_monotonic)
            if reason=='qualified': reason=self.deployment_guard.check_generation(reply)
            if reason!='qualified':
                self.mapping_incomplete=True
                return self._result('deployment_unqualified',qualification_reason=reason)
        dropped=reply.get('transport_dropped_before')
        if type(dropped) is not int or not 0<=dropped<=2**63-1:
            return self._result('invalid_transport_health')
        client=reply.get('client')
        try:
            if type(client) is not str or len(client)>45 or '%' in client: raise ValueError('no qualified client')
            client=ipaddress.ip_address(client)
            if client.is_unspecified or client.is_multicast: raise ValueError('not a client address')
            client=str(client)
        except ValueError:
            return self._result('invalid_client')
        staged_gate=copy(self.gate)
        try:
            epoch=staged_gate.accept(reply,received_monotonic=received_monotonic,received_utc=received_utc)
        except (RejectedEpoch,KeyError,TypeError,ValueError):
            # A trusted producer's clock discontinuity is sticky. A malformed
            # packet, foreign PID or wrong profile cannot advance receive time.
            if staged_gate.clock_blocked: self.gate.clock_blocked=True
            return self._result('clock_or_epoch_rejected')
        if dropped:
            self.mapping_incomplete=True
            self.counters['transport_gap_reports']=min(2**63-1,self.counters['transport_gap_reports']+1)
        # Keep authentic negative/failure replies useful for statistics without
        # promoting their DNS rcode or mapping rejection into a policy decision.
        try: telemetry=summarize(reply,client=client,profile_id=self.profile.identifier)
        except (ValueError,TypeError,KeyError): telemetry=None
        def observed_result(reason,**values):
            result=self._result(reason,**values)
            if telemetry is not None:
                result['telemetry']=telemetry|{'mapping_status':reason,
                    'mapping_count':values.get('reply_mapping_count',0),
                    'mapping_coverage_incomplete':self.mapping_incomplete}
            return result
        try:
            event=normalize(reply,profile=self.profile,resolver_epoch=epoch['generation'])
            count=self.history.observe(client,event,received_utc=received_utc)
        except OverflowError:
            # Old mappings remain intact, but can no longer be presented as an
            # adequately observed candidate set. Explicit requalification/new
            # session is needed to recover coverage; do not silently evict.
            self.mapping_incomplete=True
            self.gate=staged_gate
            return observed_result('capacity_gap')
        except (UnqualifiedReply,ValueError,KeyError,TypeError):
            return observed_result('unqualified_reply')
        self.gate=staged_gate
        self.last_reply_utc=event['observed_utc']
        return observed_result('mapped' if count else 'no_live_mapping',client=client,name=event['qname'],
                            reply_mapping_count=count,observed_utc=event['observed_utc'],
                            evidence_basis='resolver_reply_for_client_not_wire_delivery')

    def annotate_firewall(self,event,*,client=None,client_identity_verified=False,now_monotonic=None):
        result=self.history.annotate_firewall(event,client=client,client_identity_verified=client_identity_verified)
        if self.deployment_guard is not None and self.deployment_guard.check(now=now_monotonic)!='qualified':
            result.update(domain_attribution='unknown',domain_candidates=[],attribution_reason='deployment_unqualified')
            return result
        if self.gate.clock_blocked or self.mapping_incomplete:
            result.update(domain_attribution='unknown',domain_candidates=[],
                          attribution_reason='mapping_clock_unqualified' if self.gate.clock_blocked else 'mapping_coverage_incomplete')
        return result

    def status(self,*,now_monotonic=None):
        return {'mode':'observation_only','producer_pid':self.pid,'producer_uid':self.uid,
                'profile_id':self.profile.identifier,'resolver_epoch':self.gate.active[1] if self.gate.active else None,
                'last_reply_utc':self.last_reply_utc,'mapping_rows':len(self.history.mappings),
                'mapping_limit':self.history.max_mappings,'history_seconds':self.history.history_seconds,
                'clock_blocked':self.gate.clock_blocked,'mapping_incomplete':self.mapping_incomplete,
                'counters':dict(self.counters),'enforcement_applied':False,
                'deployment':self.deployment_guard.status(now=now_monotonic) if self.deployment_guard is not None else {'state':'external_qualification_required'}}
