"""Owned optional domain annotations, independent of statistics and enforcement.

Normal removal retains the sibling label store. Explicit --purge-data removes
only a complete, validated store. Unknown/partial/foreign content is preserved.
This module is never imported by the DNS reply or PF membership paths.
"""
import hashlib
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import stat

FORMAT='dnsalias-domain-labels-1'
APPLICATION=0x44414c31
MAX_BYTES=16*1024*1024
SCHEMA={
    'domain_labels':"CREATE TABLE domain_labels(domain TEXT PRIMARY KEY,review TEXT NOT NULL CHECK(review IN ('','good','bad','investigate')),updated_utc INTEGER NOT NULL)",
    'domain_tags':'CREATE TABLE domain_tags(domain TEXT NOT NULL,tag TEXT NOT NULL,PRIMARY KEY(domain,tag),FOREIGN KEY(domain) REFERENCES domain_labels(domain) ON DELETE CASCADE)',
    'domain_labels_review':'CREATE INDEX domain_labels_review ON domain_labels(review,domain)',
    'domain_tags_tag':'CREATE INDEX domain_tags_tag ON domain_tags(tag,domain)',
}
FILES={'OWNER.json':2048,'labels.lock':0,'labels.sqlite':MAX_BYTES}


def store_path(data):return Path(str(Path(data))+'-labels')


def _identity(info):
    return tuple(getattr(info,name) for name in (
        'st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))


def _file(path,limit):
    info=path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_nlink!=1
        or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>limit):
        raise ValueError('Domain label file ownership or size changed')
    return info


def _directory(data,path):
    if os.name!='posix' or not path.is_absolute() or path.resolve(strict=True)!=path:
        raise ValueError('Canonical native domain label store required')
    info=path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:
        raise ValueError('Domain label directory ownership changed')
    if {p.name for p in path.iterdir()}!=set(FILES):
        raise ValueError('Partial or unexpected domain label data; retain for inspection')
    for name,limit in FILES.items():_file(path/name,limit)
    if json.loads((path/'OWNER.json').read_text())!={'format':FORMAT,'data':str(Path(data))}:
        raise ValueError('Domain label store identity changed')
    return info


def _inspect(data,path):
    directory=_directory(data,path)
    identities={n:_identity(_file(path/n,limit)) for n,limit in FILES.items()}
    with closing(sqlite3.connect((path/'labels.sqlite').as_uri()+'?mode=ro',uri=True,timeout=.25)) as db:
        if (db.execute('PRAGMA application_id').fetchone()[0]!=APPLICATION
            or db.execute('PRAGMA user_version').fetchone()[0]!=1
            or db.execute('PRAGMA journal_mode').fetchone()[0].lower()!='delete'
            or dict(db.execute('SELECT name,sql FROM sqlite_master WHERE sql IS NOT NULL'))!=SCHEMA):
            raise ValueError('Domain label database schema or identity changed')
    result={'directory':str(path),'directory_identity':_identity(directory),
            'identities':identities,'sha256':{n:hashlib.sha256((path/n).read_bytes()).hexdigest() for n in FILES}}
    _directory(data,path)
    if identities!={n:_identity(_file(path/n,limit)) for n,limit in FILES.items()}:
        raise ValueError('Domain label data changed during inspection')
    return result


def _locked(data,path,operation):
    import fcntl
    _directory(data,path);before=_file(path/'labels.lock',0)
    fd=os.open(path/'labels.lock',os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        if _identity(before)!=_identity(os.fstat(fd)):raise ValueError('Domain label lock changed')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        try:return operation()
        finally:fcntl.flock(fd,fcntl.LOCK_UN)
    finally:os.close(fd)


def inspect(data):
    path=store_path(data)
    if not os.path.lexists(path):return None
    return _locked(data,path,lambda:_inspect(data,path))


def purge(data,expected):
    path=store_path(data)
    if expected is None:
        if os.path.lexists(path):raise ValueError('Domain label store appeared after removal review')
        return False
    def remove():
        if _inspect(data,path)!=expected:raise ValueError('Domain labels changed after removal review')
        for name in ('labels.sqlite','OWNER.json','labels.lock'):(path/name).unlink()
        path.rmdir()
        return True
    return _locked(data,path,remove)
