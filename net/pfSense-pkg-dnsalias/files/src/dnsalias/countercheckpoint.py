"""Bounded SQLite snapshot primitive for a caller-owned counter RAM store.

This module grants no mount/path ownership and never activates RAM storage.
The caller must qualify its exact mounted views and quiescent setup/removal.
Only data is copied: this is unrelated to resolver-hook/source recovery.
"""
import hashlib
import os
from pathlib import Path
import re
import sqlite3
import stat
import time

MAX_BYTES=1048576
SCHEMA={
 'resolver':'CREATE TABLE resolver(row INTEGER,totalqueries INTEGER,queries INTEGER)',
 'lastclear':'CREATE TABLE lastclear(row INTEGER,lastipclear TEXT,lastdnsblclear TEXT)',
 'lastevent':'CREATE TABLE lastevent(row INTEGER,groupname TEXT,entry TEXT,details TEXT)',
}

def identity(info):
    return tuple(getattr(info,name)for name in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink'))

def _path(value):
    path=Path(value)
    if not path.is_absolute()or not re.fullmatch(r'/[A-Za-z0-9_./-]{1,511}',str(path))or'..'in path.parts:
        raise ValueError('Canonical counter path required')
    if path.parent.resolve(strict=True)!=path.parent:raise ValueError('Counter parent symlink refused')
    return path

def _file(path,uid,gid,modes):
    info=path.lstat()
    if not stat.S_ISREG(info.st_mode)or info.st_uid!=uid or info.st_gid!=gid or stat.S_IMODE(info.st_mode)not in modes or info.st_nlink!=1 or not 0<info.st_size<=MAX_BYTES:
        raise ValueError('Counter data identity or size changed')
    return info

def _connection(path,*,read_only,deadline):
    db=sqlite3.connect(':memory:')if path is None else sqlite3.connect('file:'+str(path)+'?mode='+('ro'if read_only else'rw'),uri=True,timeout=0)
    try:
        db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH,MAX_BYTES)
        db.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH,8192)
        db.setlimit(sqlite3.SQLITE_LIMIT_COLUMN,16)
        db.setlimit(sqlite3.SQLITE_LIMIT_ATTACHED,0)
        db.set_progress_handler(lambda:int(time.monotonic()>=deadline),1000)
        db.execute('PRAGMA trusted_schema=OFF')
        if read_only:db.execute('PRAGMA query_only=ON')
        else:db.execute('PRAGMA synchronous=FULL')
        return db
    except BaseException:db.close();raise

def validate_database(db):
    if db.execute('PRAGMA quick_check').fetchall()!=[('ok',)]:raise ValueError('Counter database check failed')
    rows=db.execute('SELECT type,name,sql FROM sqlite_schema ORDER BY name').fetchall()
    names=set()
    normalized=lambda text:re.sub(r'\s+','',text).lower()
    for kind,name,sql in rows:
        if kind!='table'or name not in SCHEMA or not isinstance(sql,str)or normalized(sql)!=normalized(SCHEMA[name]):
            raise ValueError('Unqualified counter schema; no source or extension import')
        names.add(name)
    if 'resolver'not in names:raise ValueError('Counter resolver table required')
    rows=db.execute('SELECT row,totalqueries,queries FROM resolver LIMIT 2').fetchall()
    if len(rows)!=1 or rows[0][0]!=0 or any(type(value)is not int or not 0<=value<=9223372036854775807 for value in rows[0]):
        raise ValueError('One bounded native counter row required')
    return {'totalqueries':rows[0][1],'queries':rows[0][2],'tables':sorted(names)}

def snapshot(source,target,*,uid,gid,guard,budget_seconds=.25):
    """Publish one consistent snapshot, preserving the previous file on failure.

    guard is the caller's independent current mount/ownership proof. It must
    not authorize a foreign store merely because its paths or bytes match.
    A busy source aborts within the budget; no live DNS thread waits here.
    Counter resets may decrease values. The full qualified database is copied.
    """
    if type(uid)is not int or type(gid)is not int or uid<0 or gid<0 or not callable(guard):raise ValueError('Explicit counter ownership proof required')
    if type(budget_seconds)not in(int,float)or not 0<budget_seconds<=2:raise ValueError('Bounded snapshot budget required')
    source,target=_path(source),_path(target)
    if source==target:raise ValueError('Independent RAM and disk paths required')
    deadline=time.monotonic()+budget_seconds;guard()
    before_source=_file(source,uid,gid,(0o600,0o644));before_target=_file(target,uid,gid,(0o600,0o644))
    if(before_source.st_dev,before_source.st_ino)==(before_target.st_dev,before_target.st_ino):raise ValueError('Independent RAM and disk inodes required')
    parents={path:identity(path.stat())for path in(source.parent,target.parent)}
    pending=target.with_name(target.name+'.checkpoint.pending')
    if os.path.lexists(pending)or any(os.path.lexists(str(pending)+suffix)for suffix in('-journal','-wal','-shm')):
        raise ValueError('Pending counter snapshot requires inspection')
    opened=os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    src=dst=memory=None;fd=None;pending_identity=None;published=False
    try:
        if identity(os.fstat(opened))!=identity(before_source):raise ValueError('Counter source changed before open')
        src=_connection(source,read_only=True,deadline=deadline)
        memory=_connection(None,read_only=False,deadline=deadline)
        def progress(status,remaining,total):
            if time.monotonic()>=deadline:raise TimeoutError('Counter checkpoint busy or deadline exceeded')
        # Release the live RAM database before a disk commit or source/mount
        # audit. The consistent in-memory image keeps disk latency away from
        # the original writer's read/commit locks.
        src.backup(memory,pages=16,progress=progress,sleep=.005)
        captured_utc=time.time();src.close();src=None
        summary=validate_database(memory)
        if memory.execute('PRAGMA page_count').fetchone()[0]*memory.execute('PRAGMA page_size').fetchone()[0]>MAX_BYTES:
            raise ValueError('Counter memory snapshot capacity exceeded')
        fd=os.open(pending,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        os.fchmod(fd,0o600);pending_identity=identity(os.fstat(fd))
        dst=_connection(pending,read_only=False,deadline=deadline)
        memory.backup(dst,pages=16,progress=progress,sleep=.005)
        if validate_database(dst)!=summary:raise ValueError('Counter disk snapshot differs')
        dst.close();dst=None;memory.close();memory=None
        if time.monotonic()>=deadline:raise TimeoutError('Counter checkpoint deadline exceeded')
        if identity(_file(source,uid,gid,(0o600,0o644)))!=identity(before_source)or identity(os.fstat(opened))!=identity(before_source):
            raise ValueError('Counter source replaced during snapshot')
        if identity(_file(target,uid,gid,(0o600,0o644)))!=identity(before_target):raise ValueError('Counter checkpoint replaced during snapshot')
        for path,expected in parents.items():
            if identity(path.stat())!=expected:raise ValueError('Counter mounted view changed')
        guard()
        if identity(_file(source,uid,gid,(0o600,0o644)))!=identity(before_source)or identity(_file(target,uid,gid,(0o600,0o644)))!=identity(before_target):
            raise ValueError('Counter data changed during final ownership proof')
        if identity(pending.lstat())!=pending_identity or identity(os.fstat(fd))!=pending_identity:raise ValueError('Counter snapshot staging file changed')
        info=os.fstat(fd)
        if not 0<info.st_size<=MAX_BYTES:raise ValueError('Counter snapshot capacity exceeded')
        os.fchown(fd,uid,gid);os.fchmod(fd,stat.S_IMODE(before_target.st_mode));os.fsync(fd)
        os.lseek(fd,0,os.SEEK_SET);raw=os.read(fd,MAX_BYTES+1)
        if len(raw)!=info.st_size:raise ValueError('Counter snapshot size changed')
        result=summary|{'bytes':info.st_size,'sha256':hashlib.sha256(raw).hexdigest()}
        os.replace(pending,target);published=True
        directory=os.open(target.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:os.fsync(directory)
        finally:os.close(directory)
        result.update(complete=True,elapsed_seconds=budget_seconds-(deadline-time.monotonic()),captured_utc=captured_utc,published_utc=time.time())
        return result
    finally:
        if dst is not None:dst.close()
        if src is not None:src.close()
        if memory is not None:memory.close()
        if fd is not None:os.close(fd)
        os.close(opened)
        if not published and pending_identity is not None and os.path.lexists(pending):
            # Only our untouched staging inode is disposable. Unknown files or
            # surviving journals remain for inspection, never auto-replayed.
            if identity(pending.lstat())==pending_identity and not any(os.path.lexists(str(pending)+suffix)for suffix in('-journal','-wal','-shm')):
                pending.unlink()
