"""Small forward-only policy identity history; no DNS/PF or periodic work."""
import ipaddress
import json
import math
import re
import time
from .checkpointfile import CheckpointFile
from .leases import Policy
from .policystats import rule_ids

FORMAT='dnsalias-policy-history-1'
MAX_SESSIONS=64
MAX_BYTES=262144


def _stamp(value):
    if type(value) not in (int,float) or not math.isfinite(value) or value<=0:raise ValueError('finite policy timestamp required')
    return value


def validate(value):
    if type(value) is not dict or set(value)!={'format','sessions'} or value['format']!=FORMAT or type(value['sessions']) is not list or len(value['sessions'])>MAX_SESSIONS:
        raise ValueError('bounded policy history required')
    seen=set()
    for s in value['sessions']:
        if type(s) is not dict or set(s)!={'token','name','client','interface','port','names','rule_trackers','started_utc','until_utc','ended_utc','counters'}:
            raise ValueError('complete policy identity required')
        if type(s['token']) is not str or not re.fullmatch('[a-f0-9]{16}',s['token']) or s['token'] in seen:raise ValueError('distinct policy session required')
        seen.add(s['token']);_stamp(s['started_utc']);_stamp(s['until_utc'])
        if not 1<=s['until_utc']-s['started_utc']<=3630:raise ValueError('bounded identity observation window required')
        if s['ended_utc'] is not None and not s['started_utc']<=_stamp(s['ended_utc'])<=s['until_utc']:
            raise ValueError('policy end outside original window')
        if type(s['names']) is not list or not 1<=len(s['names'])<=8 or list(Policy(s['name'],tuple(s['names'])).patterns)!=s['names']:
            raise ValueError('normalized policy names required')
        if type(s['client']) is not str or str(ipaddress.ip_address(s['client']))!=s['client'] or type(s['interface']) is not str or not re.fullmatch('[A-Za-z][A-Za-z0-9_.]{0,15}',s['interface']):
            raise ValueError('exact recorded source required')
        if not (type(s['port']) is int and s['port'] in (80,443) or s['port']=='web') or s['rule_trackers']!=rule_ids({'policy_name':s['name'],'token':s['token'],'port':s['port']}):
            raise ValueError('exact recorded rule identities required')
        c=s['counters']
        if c is not None and (type(c) is not dict or set(c)!={'rule_trackers','packets','bytes','observed_utc'}
            or c['rule_trackers']!=s['rule_trackers'] or any(type(c[k]) is not int or not 0<=c[k]<2**65 for k in ('packets','bytes'))
            or not s['started_utc']<=_stamp(c['observed_utc'])<=s['until_utc']):raise ValueError('qualified recorded counters required')
    if len(json.dumps(value,separators=(',',':'),allow_nan=False).encode())>MAX_BYTES:raise ValueError('policy history size cap')
    return value


class PolicyHistoryFile(CheckpointFile):
    NAME='policy-history.json';PENDING='policy-history.pending';LOCK='policy-history.lock'
    ENVELOPE_FORMAT='dnsalias-policy-history-envelope-1';PAYLOAD_FORMAT=FORMAT

    def read(self):
        record=super().read()
        if record is not None:validate(record['checkpoint'])
        return record

    def save(self,value,*,expected_digest):return super().save(validate(value),expected_digest=expected_digest)


def started(directory,rule,names,seconds,*,expected_uid=0,now=None):
    now=time.time() if now is None else _stamp(now)
    if 'policy_name' not in rule or type(seconds) is not int or not 60<=seconds<=3600:raise ValueError('bounded named policy required')
    with PolicyHistoryFile(directory,expected_uid=expected_uid) as store:
        old=store.read();sessions=old['checkpoint']['sessions'] if old else []
        if any(s['token']==rule['token'] for s in sessions):raise ValueError('policy session was already recorded')
        sessions=[s for s in sessions if s['until_utc']>=now-86400]
        session={'token':rule['token'],'name':rule['policy_name'],'client':rule['client'],'interface':rule['interface'],
                 'port':rule['port'],'names':list(names),'rule_trackers':rule_ids(rule),'started_utc':now,'until_utc':now+seconds+30,'ended_utc':None,'counters':None}
        store.save({'format':FORMAT,'sessions':(sessions+[session])[-MAX_SESSIONS:]},expected_digest=old['file_sha256'] if old else None)


def ended(directory,token,*,expected_uid=0,now=None,counters=None):
    now=time.time() if now is None else _stamp(now)
    with PolicyHistoryFile(directory,expected_uid=expected_uid) as store:
        old=store.read()
        if old is None:raise ValueError('recorded start required')
        sessions=old['checkpoint']['sessions'];matches=[s for s in sessions if s['token']==token]
        if len(matches)!=1 or matches[0]['ended_utc'] is not None:raise ValueError('one unfinished recorded policy required')
        # A delayed cleanup cannot widen the original attribution window.
        matches[0]['ended_utc']=min(max(now,matches[0]['started_utc']),matches[0]['until_utc'])
        matches[0]['counters']=counters
        store.save(old['checkpoint'],expected_digest=old['file_sha256'])
