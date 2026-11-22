"""A bounded, explicitly started observation session; no rule permissions.

The socket owner supplies the independently qualified table and exact names.
Client requests contain only status/start/stop and the fresh preview token.
"""
import hmac
import secrets
import time

from .leases import dns_name
from .trialtable import validate_scope


class PreparedObservation:
    def __init__(self,scope,names,*,duration_seconds,preview_seconds=60):
        if type(scope) is not dict or set(scope)!={'token','table','anchor'}:
            raise ValueError('table-only namespace required; no traffic-rule scope')
        self.scope=validate_scope(scope)
        if type(names) not in (list,tuple) or not 1<=len(names)<=8:raise ValueError('one to eight exact names required')
        self.names=tuple(dns_name(name) for name in names)
        if len(set(self.names))!=len(self.names):raise ValueError('distinct exact names required')
        if type(duration_seconds) is not int or not 15<=duration_seconds<=120:raise ValueError('qualified bounded observation duration required')
        if type(preview_seconds) is not int or not 1<=preview_seconds<=120:raise ValueError('bounded preview duration required')
        self.duration=duration_seconds;self.token=secrets.token_hex(16)
        self.deadline=time.monotonic()+preview_seconds;self.expires_utc=time.time()+preview_seconds
        self.state='prepared';self.started=self.cancelled=self.restored=self.released=self.ready=False
        self.last_event=self.error=self.trial_id=None

    def _expire(self):
        if self.state in ('prepared','queued') and time.monotonic()>=self.deadline:self.state='expired'

    def snapshot(self):
        self._expire()
        return {'format':'dnsalias-observation-control-1','token':self.token,'state':self.state,
            'table':self.scope['table'],'names':list(self.names),'duration_seconds':self.duration,
            'preview_expires_utc':self.expires_utc,'started':self.started,'cancel_requested':self.cancelled,
            'feed_ready':self.ready,'restoration_verified':self.restored,'resources_released':self.released,
            'last_event':self.last_event,'error':self.error,'trial_id':self.trial_id,'enforcement_applied':False,
            'rule_created':False,'shared_destination_table':True,'client_scope':'any_trusted_reply'}

    def request(self,value):
        if type(value) is not dict:raise ValueError('request object required')
        if value=={'op':'status'}:return self.snapshot()
        if (set(value)!={'op','token'} or value['op'] not in ('start','stop')
            or type(value['token']) is not str or len(value['token'])!=32 or not value['token'].isascii()
            or not hmac.compare_digest(value['token'],self.token)):
            raise ValueError('exact prepared observation request required')
        self._expire()
        if value['op']=='start':
            if self.state=='expired':raise ValueError('preview expired')
            if self.state=='prepared':self.state='queued'
        elif self.state in ('prepared','queued'):
            self.cancelled=True;self.state='cancelled'
        elif self.state in ('running','cancelling'):
            self.cancelled=True;self.state='cancelling'
        return self.snapshot()

    def begin(self):
        self._expire()
        if self.state!='queued' or self.started:return False
        self.started=True;self.state='running';return True

    def event(self,value):
        if not self.started or self.state not in ('running','cancelling'):raise ValueError('running observation required')
        name=value.get('event') if type(value) is dict else None
        if name not in ('rollback_ready','trial_phase','observing','observation_stop_requested'):
            raise ValueError('known observation event required')
        if name=='rollback_ready':
            identity=value.get('trial_id')
            if (self.trial_id is not None or type(identity) is not str or len(identity)!=32
                or any(c not in '0123456789abcdef' for c in identity)):
                raise ValueError('single independent rollback identity required')
            self.trial_id=identity
        self.last_event=name
        if name=='observing':self.ready=True
        if name=='observation_stop_requested':self.cancelled=True;self.state='cancelling'

    def finish(self,result):
        if not self.started or self.state not in ('running','cancelling'):raise ValueError('single running observation required')
        if (type(result) is not dict or result.get('format')!='dnsalias-observation-trial-result-1'
            or result.get('enforcement_applied') is not False
            or self.trial_id is None or result.get('trial_id')!=self.trial_id):
            raise ValueError('matching non-enforcing observation result required')
        self.restored=result.get('restoration_verified') is True
        self.released=result.get('resources_released') is True
        cleanup=(result.get('feed') or {}).get('cleanup') or {}
        retirement=(result.get('feed') or {}).get('retirement') or {}
        rollback=result.get('rollback') or {}
        good=(result.get('state') in ('complete','cancelled') and result.get('error') is None
            and self.restored and self.released and cleanup.get('owned_resources_removed') is True
            and cleanup.get('telemetry_closed') is True and cleanup.get('error') is None
            and retirement.get('tables_verified_empty') is True
            and rollback.get('worker_exited') is True and rollback.get('worker_exit_code')==0)
        self.state=result['state'] if good else 'inspection_required'
        self.error=None if good else 'Observation requires inspection'
        return self.snapshot()
