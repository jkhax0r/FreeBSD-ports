"""Bounded, indexed answer evidence owned by the statistics transaction.

No backfill, DNS lookups, PF membership or recovery. A trigger follows event
deletion even when an older log collector shares or reopens the database.
"""
import ipaddress
import math
from functools import lru_cache
from .leases import dns_name

MAX_RECORDS=20000
MAX_BATCH_RECORDS=8192


@lru_cache(maxsize=8192)
def _parsed_address(value):
    address=ipaddress.ip_address(value)
    return address.version,str(address)


def _address(value):
    # Cache only bounded immutable text parsing. Family, expiry and evidence
    # checks still run for every row; sinkholes remain visible in statistics.
    parse=_parsed_address if type(value) is str and len(value)<=128 else _parsed_address.__wrapped__
    return parse(value)


def records(event):
    raw=event.get('answer_records',[])
    if not raw:return []
    if (event.get('kind')!='dns_reply' or event.get('answer_details_version')!=1
        or event.get('answer_detail_status')!='recorded' or type(raw) is not list or len(raw)>256):
        raise ValueError('typed callback answer details required')
    query=dns_name(event['name']);client=_address(event['client'])[1];stamp=event['time']
    if type(stamp) not in (int,float) or not math.isfinite(stamp):raise ValueError('finite observation clock required')
    rows=[]
    for index,row in enumerate(raw):
        if type(row) is not dict:raise ValueError('typed answer row required')
        owner=dns_name(row['name']);kind=row['type'];value=row['value'];expiry=row['expires_utc']
        if kind=='CNAME':value=dns_name(value)
        elif kind in ('A','AAAA'):
            version,value=_address(value)
            if version!=(4 if kind=='A' else 6):raise ValueError('answer family mismatch')
        else:raise ValueError('unsupported answer type')
        if expiry is None:
            if row['expiry_basis']!='unavailable':raise ValueError('missing expiry must stay unavailable')
        elif (type(expiry) not in (int,float) or not math.isfinite(expiry) or not 0<=expiry-stamp<=604800
              or row['expiry_basis']!='qualified_remaining'):
            raise ValueError('qualified remaining expiry required')
        category=row.get('address_kind')
        if category not in (None,'sinkhole','configured_exclusion','loopback','multicast','address'):
            raise ValueError('known answer category required')
        rows.append((index,stamp,client,query,owner,kind,value,expiry,category))
    return rows


class AnswerHistory:
    def __init__(self,db,limit=MAX_RECORDS):
        if type(limit) is not int or not 1<=limit<=MAX_RECORDS:raise ValueError('bounded answer history required')
        self.db,self.limit=db,limit
        db.execute('CREATE TABLE IF NOT EXISTS reply_answers (event_id INTEGER NOT NULL,ordinal INTEGER NOT NULL,time REAL NOT NULL,client TEXT NOT NULL,query TEXT NOT NULL,owner TEXT NOT NULL,rrtype TEXT NOT NULL,value TEXT NOT NULL,expires_utc REAL,address_kind TEXT,PRIMARY KEY(event_id,ordinal)) WITHOUT ROWID')
        db.execute('CREATE INDEX IF NOT EXISTS reply_answer_value ON reply_answers(value,time,event_id,query,client)')
        db.execute('CREATE INDEX IF NOT EXISTS reply_answer_query ON reply_answers(query,time,event_id,value,client)')
        db.execute('CREATE TRIGGER IF NOT EXISTS event_answer_cleanup AFTER DELETE ON events BEGIN DELETE FROM reply_answers WHERE event_id=OLD.id; END')

    def prepare(self,events):
        rows=[records(event) for event in events];total=sum(map(len,rows))
        if total>min(self.limit,MAX_BATCH_RECORDS):raise ValueError('answer batch limit')
        return rows,total

    def reserve(self,incoming):
        count=self.db.execute('SELECT count(*) FROM reply_answers').fetchone()[0]
        excess=max(0,count+incoming-self.limit)
        if excess:
            self.db.execute('DELETE FROM reply_answers WHERE (event_id,ordinal) IN (SELECT event_id,ordinal FROM reply_answers ORDER BY event_id,ordinal LIMIT ?)',(excess,))

    def insert(self,event_id,rows):
        if rows:
            self.db.executemany('INSERT INTO reply_answers(event_id,ordinal,time,client,query,owner,rrtype,value,expires_utc,address_kind) VALUES (?,?,?,?,?,?,?,?,?,?)',
                                [(event_id,*row) for row in rows])

    def status(self):
        return {'rows':self.db.execute('SELECT count(*) FROM reply_answers').fetchone()[0],'record_limit':self.limit,
                'scope':'Typed callback evidence only; historical records may be expired or independently pruned; not PF leases or exact HTTPS use'}
