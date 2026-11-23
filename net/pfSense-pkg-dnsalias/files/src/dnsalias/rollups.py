"""Bounded hourly observation counts, committed with their raw source events."""
import math

MAX_GROUPS=20000
DIMENSIONS=('bucket','kind','client','domain','tracker','action','destination','port','protocol','interface','direction')


class HourlyCounts:
    def __init__(self,db,max_groups=MAX_GROUPS):
        if type(max_groups) is not int or not 1<=max_groups<=MAX_GROUPS: raise ValueError('invalid hourly group cap')
        self.db,self.max_groups=db,max_groups
        db.execute('CREATE TABLE IF NOT EXISTS hourly_counts (id INTEGER PRIMARY KEY,bucket INTEGER NOT NULL,kind TEXT NOT NULL,client TEXT NOT NULL,domain TEXT NOT NULL,tracker TEXT NOT NULL,action TEXT NOT NULL,destination TEXT NOT NULL,port INTEGER NOT NULL,protocol TEXT NOT NULL,interface TEXT NOT NULL,direction TEXT NOT NULL,n INTEGER NOT NULL,first_seen REAL NOT NULL,last_seen REAL NOT NULL)')
        db.execute('CREATE UNIQUE INDEX IF NOT EXISTS hourly_identity ON hourly_counts ('+','.join(DIMENSIONS)+')')
        db.execute('CREATE TABLE IF NOT EXISTS hourly_coverage (id INTEGER PRIMARY KEY CHECK(id=1),first_event REAL,capacity_groups_removed INTEGER NOT NULL,capacity_observations_removed INTEGER NOT NULL)')
        db.execute('INSERT OR IGNORE INTO hourly_coverage VALUES(1,NULL,0,0)')

    @staticmethod
    def floor(now):
        if type(now) not in (int,float) or not math.isfinite(now): raise ValueError('invalid rollup clock')
        return (math.floor(now/3600)-23)*3600

    def insert(self,events,now):
        # Caller owns the transaction, so raw insertion, counts and cap eviction
        # either all commit or all roll back. Never commit from this class.
        grouped={};oldest=self.floor(now)
        for event in events:
            stamp=event['time']
            if type(stamp) not in (int,float) or not math.isfinite(stamp): raise ValueError('invalid event time')
            bucket=math.floor(stamp/3600)*3600
            if bucket<oldest or stamp>now+5 or event['kind'] not in ('dns_query','firewall_packet'): continue
            dns=event['kind']=='dns_query'
            values=[bucket,event['kind'],event.get('client',event.get('source')) or '',event.get('name') or '' if dns else '',
                    '' if dns else event.get('tracker') or '', '' if dns else event.get('action') or '',
                    '' if dns else event.get('destination') or '',-1 if dns else event.get('destination_port') if event.get('destination_port') is not None else -1,
                    '' if dns else event.get('protocol') or '', '' if dns else event.get('interface') or '', '' if dns else event.get('direction') or '']
            if any(not isinstance(value,str) or len(value)>253 for i,value in enumerate(values) if i not in (0,7)):
                raise ValueError('invalid hourly dimensions')
            if type(values[7]) is not int or not -1<=values[7]<=65535: raise ValueError('invalid hourly port')
            key=tuple(values)
            prior=grouped.get(key)
            grouped[key]=(prior[0]+1,min(prior[1],stamp),max(prior[2],stamp)) if prior else (1,stamp,stamp)
        if grouped:
            first=min(value[1] for value in grouped.values())
            self.db.execute('UPDATE hourly_coverage SET first_event=CASE WHEN first_event IS NULL THEN ? ELSE MIN(first_event,?) END WHERE id=1',(first,first))
            columns=','.join(DIMENSIONS)
            sql='INSERT INTO hourly_counts ('+columns+',n,first_seen,last_seen) VALUES ('+','.join('?' for _ in range(14))+') ON CONFLICT('+columns+') DO UPDATE SET n=hourly_counts.n+excluded.n,first_seen=MIN(hourly_counts.first_seen,excluded.first_seen),last_seen=MAX(hourly_counts.last_seen,excluded.last_seen)'
            self.db.executemany(sql,[(*key,*value) for key,value in grouped.items()])
        self.prune(now,len(grouped))

    def prune(self,now,incoming=0):
        batch=512+incoming
        self.db.execute('DELETE FROM hourly_counts WHERE id IN (SELECT id FROM hourly_counts WHERE bucket < ? ORDER BY bucket LIMIT ?)',(self.floor(now),batch))
        count=self.db.execute('SELECT count(*) FROM hourly_counts').fetchone()[0]
        excess=min(max(0,count-self.max_groups),batch)
        if excess:
            ids=self.db.execute('SELECT id,n FROM hourly_counts ORDER BY bucket,last_seen,id LIMIT ?',(excess,)).fetchall()
            self.db.executemany('DELETE FROM hourly_counts WHERE id=?',[(row[0],) for row in ids])
            self.db.execute('UPDATE hourly_coverage SET capacity_groups_removed=capacity_groups_removed+?,capacity_observations_removed=capacity_observations_removed+? WHERE id=1',(len(ids),sum(row[1] for row in ids)))

    def summary(self):
        count,total,oldest,newest=self.db.execute('SELECT count(*),COALESCE(sum(n),0),min(bucket),max(bucket) FROM hourly_counts').fetchone()
        first,groups_lost,observations_lost=self.db.execute('SELECT first_event,capacity_groups_removed,capacity_observations_removed FROM hourly_coverage WHERE id=1').fetchone()
        return {'groups':count,'observations':total,'oldest_hour':oldest,'newest_hour':newest,'first_observed_event':first,
                'capacity_groups_removed':groups_lost,'capacity_observations_removed':observations_lost,
                'group_limit':self.max_groups,'hour_buckets':24,'coverage':'Observed log records only; absent hours and logging gaps are not zero traffic.'}
