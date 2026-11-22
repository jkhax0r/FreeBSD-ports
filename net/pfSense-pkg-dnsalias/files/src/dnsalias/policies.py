"""Saved alias policies; configuration only, never DNS leases or activation.

Normal firewall rules live in pfSense configuration. Optional tracker/hash
bindings identify exactly generated rules for later review; editing a native
rule does not grant permission to silently replace it. Reading or saving this
file starts no process and changes no firewall, hook, service or TTL.
"""
import json
import re
from .checkpointfile import CheckpointFile
from .leases import Policy

FORMAT='dnsalias-policies-1'
MAX_POLICIES=128
MAX_BYTES=262144


def validate(value):
    if type(value) is not dict or set(value)!={'format','policies'} or value['format']!=FORMAT:
        raise ValueError('complete saved policy configuration required')
    policies=value['policies']
    if type(policies) is not list or len(policies)>MAX_POLICIES:
        raise ValueError('bounded saved policy list required')
    names=set();trackers=set()
    for policy in policies:
        if type(policy) is not dict or set(policy)!={'name','table','names','enabled','rules'}:
            raise ValueError('complete saved alias policy required')
        name=policy['name']
        if (type(name) is not str or not re.fullmatch('[a-z][a-z0-9_]{0,22}',name)
            or name.startswith(('mvp_','seed')) or name in names or policy['table']!='da_'+name
            or type(policy['enabled']) is not bool):
            raise ValueError('distinct explicit policy and table identity required')
        names.add(name)
        patterns=policy['names']
        if (type(patterns) is not list or not 1<=len(patterns)<=256
            or any(type(p) is not str for p in patterns)
            or list(Policy(name,tuple(patterns)).patterns)!=patterns or len(set(patterns))!=len(patterns)):
            raise ValueError('normalized distinct saved names or patterns required')
        rules=policy['rules']
        if type(rules) is not list or len(rules)>16:raise ValueError('bounded exact native rule bindings required')
        for rule in rules:
            if (type(rule) is not dict or set(rule)!={'tracker','sha256'}
                or type(rule['tracker']) is not str or not re.fullmatch('[1-9][0-9]{0,9}',rule['tracker'])
                or int(rule['tracker'])>4294967295 or rule['tracker'] in trackers
                or type(rule['sha256']) is not str or not re.fullmatch('[a-f0-9]{64}',rule['sha256'])):
                raise ValueError('distinct native rule identity and digest required')
            trackers.add(rule['tracker'])
    raw=json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)
    if len(raw.encode('utf-8'))>MAX_BYTES:raise ValueError('saved policy size limit')
    return json.loads(raw)


class PolicyFile(CheckpointFile):
    NAME='policies.json';PENDING='policies.pending';LOCK='policies.lock'
    ENVELOPE_FORMAT='dnsalias-owned-policies-1';PAYLOAD_FORMAT=FORMAT

    def read(self):
        value=super().read()
        if value is not None:validate(value['checkpoint'])
        return value

    def save(self,value,*,expected_digest):
        return super().save(validate(value),expected_digest=expected_digest)
