"""Bounded optional local name metadata. Informational, never policy identity.

No DNS requests, arbitrary commands, configuration writes or lease mutations.
Kea uses the same fixed read-only command as the deployed native lease page.
Missing/unsupported sources are explicit coverage gaps; snapshots expire in UI.
"""
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import stat
import time
import xml.etree.ElementTree as ET

MAX_CLIENTS=512
MAX_CLAIMS=6
MAX_LEASE_BYTES=1048576
REQUEST_NAME='identity-request'
SOURCE_PRIORITY={'DHCP reservation':0,'Active DHCP lease (Kea)':1,'DNS host override':2,
                 'DNS override alias':3,'Router interface':4,'Reservation label':5,'Firewall host alias':6}

def claim_priority(item):
    return SOURCE_PRIORITY.get(item['source'],9),item.get('alias_members',0),item['name']

def consume_identity_request(directory,*,now):
    """Consume one empty UI request, never create one or adopt unknown files.

    Only a recently opened authenticated page requests work. No timer refreshes
    labels in the absence of requests. Caller separately limits refresh rate.
    """
    path=Path(directory)/REQUEST_NAME
    try:
        info=path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or
            stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1 or info.st_size!=0):return False
        again=path.lstat()
        if (again.st_dev,again.st_ino,again.st_mtime_ns)!=(info.st_dev,info.st_ino,info.st_mtime_ns):return False
        path.unlink()
        return 0<=now-info.st_mtime<=30
    except FileNotFoundError:return False
    except OSError:return False

def name_text(value):
    if not isinstance(value,str):return None
    value=value.strip().rstrip('.')
    if not value or len(value)>253 or any(ord(c)<32 or ord(c)==127 for c in value):return None
    return value

def add(clients,address,name,source,**details):
    if not isinstance(address,str):return
    try:ip=ipaddress.ip_address(address)
    except ValueError:return
    name=name_text(name)
    if not name or ip.is_unspecified or ip.is_multicast or ip.is_loopback:return
    address=str(ip)
    if address not in clients and len(clients)>=MAX_CLIENTS:return
    claims=clients.setdefault(address,[])
    item={'name':name,'source':source,**details}
    if item not in claims:
        claims.append(item);claims.sort(key=claim_priority);del claims[MAX_CLAIMS:]

def config_names(body):
    if len(body)>8388608 or b'<!DOCTYPE' in body.upper() or b'<!ENTITY' in body.upper():raise ValueError('config bounds')
    root=ET.fromstring(body);clients={}
    for interface in root.findall('./dhcpd/*'):
        for node in interface.findall('./staticmap'):
            extras={'interface':interface.tag}
            mac=node.findtext('mac','')
            if re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}',mac):extras['mac']=mac.lower()
            add(clients,node.findtext('ipaddr',''),node.findtext('hostname',''),'DHCP reservation',**extras)
            add(clients,node.findtext('ipaddr',''),node.findtext('descr',''),'Reservation label',**extras)
    for path in ('./unbound/hosts','./dnsmasq/hosts'):
        for node in root.findall(path):
            host=node.findtext('host','');domain=node.findtext('domain','')
            name=host+'.'+domain if domain else host
            for address in node.findtext('ip','').split(','):add(clients,address.strip(),name,'DNS host override')
            for alias in node.findall('./aliases/item'):
                alias_name=alias.findtext('host','')+'.'+alias.findtext('domain','')
                for address in node.findtext('ip','').split(','):add(clients,address.strip(),alias_name,'DNS override alias')
    router=root.findtext('./system/hostname','')+'.'+root.findtext('./system/domain','')
    for interface in root.findall('./interfaces/*'):
        for key in ('ipaddr','ipaddrv6'):add(clients,interface.findtext(key,''),router,'Router interface',interface=interface.findtext('descr',interface.tag))
    for alias in root.findall('./aliases/alias'):
        if alias.findtext('type')=='host':
            members=alias.findtext('address','').split()
            for address in members:
                # A group label, not a DNS hostname or device identity. Never
                # expand network aliases or resolve configured FQDNs here.
                add(clients,address,alias.findtext('name',''),'Firewall host alias',alias_members=len(members))
    return clients,root.findtext('./dhcpbackend','unknown')

def kea_names(payload,clients,now):
    if not isinstance(payload,dict) or payload.get('result')!=0:raise ValueError('Kea response')
    arguments=payload.get('arguments')
    if not isinstance(arguments,dict):raise ValueError('Kea arguments')
    leases=arguments.get('leases')
    if not isinstance(leases,list) or len(leases)>8192:raise ValueError('Kea lease bounds')
    for lease in leases:
        if not isinstance(lease,dict):continue
        cltt=lease.get('cltt');valid=lease.get('valid-lft');state=lease.get('state')
        if type(cltt) is not int or type(valid) is not int or type(state) is not int or state!=0 or cltt>now+2 or cltt<0 or valid<=0:continue
        expiry=cltt+valid
        if expiry<=now:continue
        extras={'expires':expiry}
        mac=lease.get('hw-address','')
        if isinstance(mac,str) and re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}',mac):extras['mac']=mac.lower()
        add(clients,lease.get('ip-address',''),lease.get('hostname',''),'Active DHCP lease (Kea)',**extras)

def read_kea(version):
    if version not in (4,6):raise ValueError('Kea version')
    path=Path('/var/run/kea/kea%d-ctrl-socket'%version)
    item=path.lstat()
    if not stat.S_ISSOCK(item.st_mode) or item.st_uid!=0:raise ValueError('Kea socket ownership')
    deadline=time.monotonic()+.2
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as conn:
        conn.settimeout(.2);conn.connect(str(path))
        conn.sendall(json.dumps({'command':'lease%d-get-all'%version}).encode())
        body=bytearray()
        while True:
            remaining=min(.2,deadline-time.monotonic())
            if remaining<=0:raise TimeoutError('Kea deadline')
            conn.settimeout(remaining);part=conn.recv(min(65536,MAX_LEASE_BYTES+1-len(body)))
            if not part:break
            body.extend(part)
            if len(body)>MAX_LEASE_BYTES:raise ValueError('Kea response cap')
        return json.loads(body)

def collect_identity(now):
    started=time.monotonic();clients={};coverage={}
    try:
        path=Path('/cf/conf/config.xml')
        if path.is_symlink():raise ValueError('config link')
        with path.open('rb') as f:body=f.read(8388609)
        clients,backend=config_names(body);coverage['configuration']='Read local DHCP reservations and DNS overrides'
    except (OSError,ValueError,ET.ParseError) as exc:
        backend='unknown';coverage['configuration']='Unavailable: '+type(exc).__name__
    if backend=='kea':
        for version in (4,6):
            try:kea_names(read_kea(version),clients,now);coverage['dhcp'+str(version)]='Active leases read'
            except (OSError,ValueError) as exc:coverage['dhcp'+str(version)]='Unavailable: '+type(exc).__name__
    else:coverage['dynamic_dhcp']='Backend not yet supported: '+backend
    return {'observed_utc':now,'clients':clients,'coverage':coverage,'elapsed_ms':round((time.monotonic()-started)*1000,3),
            'bounded':True,'client_cap':MAX_CLIENTS,'claims_per_client_cap':MAX_CLAIMS,'network_dns_requests':0,
            'at_capacity':len(clients)>=MAX_CLIENTS or any(len(c)>=MAX_CLAIMS for c in clients.values())}
