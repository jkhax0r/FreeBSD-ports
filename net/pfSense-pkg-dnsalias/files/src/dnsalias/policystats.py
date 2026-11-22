"""Bounded rule identities and exact-set counters, outside the DNS reply path."""
import hashlib
import re
from .telemetry import parse_rules


def rule_ids(rule):
    if 'policy_name' not in rule:return []
    token=rule['token']
    if type(token) is not str or not re.fullmatch('[a-f0-9]{16}',token):raise ValueError('explicit rule identity required')
    # Four adjacent high IDs; the creator still checks the complete live PF
    # inventory for collision. The random session token is not a policy name.
    base=0x80000000 | (int(hashlib.sha256(token.encode('ascii')).hexdigest()[:8],16)&0x7ffffffc)
    return [str(base+i) for i in range(4 if rule['port']=='web' else 1)]


def counters(text,expected,identifiers):
    """Return only counters for the exact canonical owned rule set.

    A missing set is an explicit None, never a fabricated zero or permission
    to reinstall. Changed content is refused; old counts are not attributed to
    its replacement. Native verbose table member counts are not rule changes.
    """
    if type(text) is not str or len(text)>65536:raise ValueError('bounded rule counter text required')
    if not text.strip():return None
    headers=[re.sub(r'^@[0-9]+\s+','',line) for line in text.splitlines() if line.startswith('@')]
    headers=[re.sub(r'(<[^<>:]+):\d+>',r'\1>',line) for line in headers]
    if headers!=expected.splitlines():raise ValueError('owned rule set changed')
    rows=parse_rules(text)
    if len(rows)!=len(identifiers) or [r['tracker'] for r in rows]!=identifiers:
        raise ValueError('rule counter identities changed')
    if any(type(r.get(key)) is not int or not 0<=r[key]<2**63 for r in rows for key in ('packets','bytes')):
        raise ValueError('bounded packet and byte counters required')
    return {'rule_trackers':list(identifiers),'packets':sum(r['packets'] for r in rows),'bytes':sum(r['bytes'] for r in rows)}
