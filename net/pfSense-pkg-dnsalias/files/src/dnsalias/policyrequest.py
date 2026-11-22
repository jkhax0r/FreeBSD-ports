"""Bounded explicit MVP policy input; no paths, source scope or commands."""
import re
import hashlib
import ipaddress
import xml.etree.ElementTree as ET
from .leases import Policy


def validate(value):
    fields={'format','alias','names','port','block_seconds'}
    if type(value) is not dict or set(value) not in (fields,fields|{'client'}) or value['format']!='dnsalias-mvp-policy-1':
        raise ValueError('complete named policy request required')
    name=value['alias']
    if type(name) is not str or not re.fullmatch('[a-z][a-z0-9_]{0,22}',name) or name.startswith(('mvp_','seed')):
        raise ValueError('distinct bounded alias name required')
    names=value['names']
    if type(names) is not list or not 1<=len(names)<=8 or any(type(n) is not str for n in names):
        raise ValueError('one to eight names or suffix patterns required')
    names=Policy(name,tuple(names)).patterns
    if len(set(names))!=len(names):raise ValueError('distinct names required')
    if not (type(value['port']) is int and value['port'] in (80,443) or value['port']=='web'):
        raise ValueError('one explicit web port or bounded web traffic scope required')
    if value['block_seconds'] is not None and (type(value['block_seconds']) is not int or value['block_seconds'] not in (60,300,900,3600)):
        raise ValueError('explicit policy duration or until-stopped operation required')
    if 'client' in value:client_address(value['client'])
    return value|{'names':list(names)}


def bind(request,policy):
    """Bind editable fields to a freshly admitted, fixed-client request."""
    policy=validate(policy)
    if policy.get('client',request['rule']['client'])!=request['rule']['client']:
        raise ValueError('selected client requires fresh native interface admission')
    rule=request['rule']|{'policy_name':policy['alias'],'table':'da_'+policy['alias'],'port':policy['port']}
    return request|{'rule':rule,'names':policy['names'],'block_seconds':policy['block_seconds'],
                    'target':request['target']|{'duration_seconds':None if policy['block_seconds'] is None else policy['block_seconds']+15}}


def client_address(value):
    if type(value) is not str:raise ValueError('one exact source IP required')
    address=ipaddress.ip_address(value)
    if (str(address)!=value or address.is_unspecified or address.is_multicast or address.is_loopback
        or address.is_link_local or getattr(address,'scope_id',None) is not None):
        raise ValueError('canonical nonlocal unicast client required')
    return address


def compatible_profile(profile,xml,*,client=None):
    """Permit unrelated config revisions only while the admitted LAN holds.

    The caller must bind these bytes to a fresh root-owned source audit and
    still run the normal complete source/runtime/memory/baseline admission.
    No client, interface, resolver setting or credential is changed here.
    """
    if type(xml) is not bytes or not 0<len(xml)<=2*1024**2:raise ValueError('bounded native configuration required')
    digest=hashlib.sha256(xml).hexdigest()
    if client is not None:
        address=client_address(client)
        if client!=profile['scope']['client']:
            root=ET.fromstring(xml);candidates=[];router_addresses=set();wan_networks=[]
            for node in root.findall('./interfaces/*'):
                suffix='v6' if address.version==6 else ''
                try:network=ipaddress.ip_interface(node.findtext('ipaddr'+suffix)+'/'+node.findtext('subnet'+suffix))
                except (TypeError,ValueError):continue
                router_addresses.add(network.ip)
                if node.tag=='wan':wan_networks.append(network.network)
                if node.tag=='wan' or node.find('disable') is not None or network.version!=address.version:continue
                iface=node.findtext('if')
                if (not iface or not re.fullmatch('[A-Za-z][A-Za-z0-9_.]{0,15}',iface) or iface.startswith('lo')):continue
                if address in network.network and (address.version==6 or address not in (network.network.network_address,network.network.broadcast_address)):
                    candidates.append(iface)
            for node in root.findall('./virtualip/vip/subnet'):
                try:router_addresses.add(ipaddress.ip_address(node.text))
                except ValueError:continue
            if address in router_addresses or any(address in net for net in wan_networks) or len(candidates)!=1:
                raise ValueError('selected client needs one enabled static non-WAN source network; router/ambiguous sources refused')
            return profile|{'native_config_sha256':digest,'scope':profile['scope']|{'client':client,'interface':candidates[0]}}
    if digest==profile['native_config_sha256']:return profile
    source=ipaddress.ip_address(profile['scope']['client']);iface=profile['scope']['interface']
    root=ET.fromstring(xml)
    matches=[node for node in root.findall('./interfaces/*') if node.findtext('if')==iface]
    if len(matches)!=1 or matches[0].tag=='wan' or matches[0].find('disable') is not None:
        raise ValueError('admitted ingress interface changed')
    node=matches[0];suffix='v6' if source.version==6 else ''
    try:network=ipaddress.ip_interface(node.findtext('ipaddr'+suffix)+'/'+node.findtext('subnet'+suffix))
    except (TypeError,ValueError):raise ValueError('admitted source network is no longer static') from None
    if network.version!=source.version or source not in network.network or source==network.ip:
        raise ValueError('admitted client no longer belongs to this ingress')
    return profile|{'native_config_sha256':digest}
