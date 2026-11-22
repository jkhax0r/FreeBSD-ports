"""Pure standalone observation-hook builder. Nothing is installed or activated.

Use the installed package's inspected source text as inputs. The caller pins
the returned component hashes in its deployment descriptor, qualifies isolated
behavior and native lifecycle, and separately owns any future installation.
"""
import ast
import hashlib
import json
import re


MAX_OBSERVER_SOURCE_BYTES = 144 * 1024


def render_plain(observer_source,dispatcher_source):
    """Self-contained selected script for plain Unbound's single Python module."""
    for source,limit in ((observer_source,256*1024),(dispatcher_source,64*1024)):
        if type(source) is not str or not 1<=len(source.encode())<=limit:
            raise ValueError('bounded companion source required')
        ast.parse(source)
    output=('_dnsalias_dispatch_scope={}\nexec('+repr(dispatcher_source)+',_dnsalias_dispatch_scope)\n'
            'globals().update(_dnsalias_dispatch_scope["compose"](_dnsalias_dispatch_scope["runtime_api"](globals()),'+repr(observer_source)+'))\n')
    ast.parse(output)
    return output,{'format':'dnsalias-plain-hook-1',
                   'observer_sha256':hashlib.sha256(observer_source.encode()).hexdigest(),
                   'dispatcher_sha256':hashlib.sha256(dispatcher_source.encode()).hexdigest(),
                   'generated_sha256':hashlib.sha256(output.encode()).hexdigest(),
                   'enforcement_capable':False}


def _configuration(destination,policy_mode,max_events_per_second,burst,synchronous_mapping=False):
    if (type(destination) is not str or not re.fullmatch(r'/[A-Za-z0-9_./-]{1,89}', destination)
        or any(part in ('', '.', '..') for part in destination.split('/')[1:])):
        raise ValueError('fixed absolute local socket path required')
    if type(policy_mode) is not str or policy_mode not in ('plain', 'pfblockerng'): raise ValueError('explicit policy mode required')
    if type(max_events_per_second) is not int or not 1 <= max_events_per_second <= 2000:
        raise ValueError('bounded event rate required')
    if type(burst) is not int or not 1 <= burst <= 128: raise ValueError('bounded burst required')
    if type(synchronous_mapping) is not bool:raise ValueError('explicit synchronous mapping mode required')
    config={'destination':destination,'policy_mode':policy_mode,
            'max_events_per_second':max_events_per_second,'burst':burst}
    if synchronous_mapping:config['synchronous_mapping']=True
    return config


def configuration_fingerprint(*,destination,policy_mode,max_events_per_second=500,burst=64,synchronous_mapping=False):
    """Pin fixed sender settings before computing its embedded profile ID."""
    config=_configuration(destination,policy_mode,max_events_per_second,burst,synchronous_mapping)
    return hashlib.sha256(json.dumps(config,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def render_observer(*, observer_source, extractor_source, transport_source,
                    profile_id, destination, policy_mode, max_events_per_second=500, burst=64,synchronous_mapping=False):
    if type(profile_id) is not str or not re.fullmatch('[a-f0-9]{64}', profile_id):
        raise ValueError('explicit qualified profile required')
    fixed=_configuration(destination,policy_mode,max_events_per_second,burst,synchronous_mapping)
    sources = {'observer_source': observer_source, 'extractor_source': extractor_source, 'transport_source': transport_source}
    for name, source in sources.items():
        limit = MAX_OBSERVER_SOURCE_BYTES if name == 'observer_source' else 128 * 1024
        if type(source) is not str or not 1 <= len(source.encode()) <= limit:
            raise ValueError('bounded source text required')
        ast.parse(source)
    # Ship the same tested sender implementation without receive-side imports
    # or package installation inside the Unbound chroot.
    tree = ast.parse(transport_source)
    funcs = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
    names = ('configure_sender', 'wire_datagrams', '_rr_metadata', '_rr_datum',
             '_rr_repeated_bound', '_rr_envelope', '_encode_ack', 'send_observation')
    constants = ('MAX_MESSAGE', 'SENDER_BUFFER_BYTES', 'CHUNK_BYTES', 'RR_FORMAT',
                 'RR_FIELDS', 'RR_MAX_GROUPS', 'RR_MAX_RECORDS', 'ACK_MAGIC', 'ACK_STATUSES', 'ACK_TOKEN', '_NATIVE_WIRE')
    assignments = {target.id: node for node in tree.body if isinstance(node, ast.Assign)
                   for target in node.targets if isinstance(target, ast.Name)}
    if not set(names) <= funcs.keys() or not set(constants) <= assignments.keys():
        raise ValueError('incompatible sender source')
    sender = 'import json, socket, errno, os, base64, hashlib, zlib, re\n' + '\n'.join(
        ast.get_source_segment(transport_source, node) for node in
        [*(assignments[n] for n in constants), *(funcs[n] for n in names)])
    config = {'profile_id':profile_id,**fixed}
    output = ('_dnsalias_observer_config=' + repr(config) + '\n'
        '_dnsalias_sender_scope={}\nexec(' + repr(sender) + ',_dnsalias_sender_scope)\n'
        '_dnsalias_send_observation=_dnsalias_sender_scope["send_observation"]\n'
        '_dnsalias_configure_sender=_dnsalias_sender_scope["configure_sender"]\n'
        '_dnsalias_extract_scope={}\nexec(' + repr(extractor_source) + ',_dnsalias_extract_scope)\n'
        '_dnsalias_extract_reply=_dnsalias_extract_scope["extract_reply"]\n') + observer_source
    if len(output.encode()) > 256*1024: raise ValueError('generated source size cap')
    ast.parse(output)
    hashes = {name: hashlib.sha256(source.encode()).hexdigest() for name,source in sources.items()}
    return output, {'format': 'dnsalias-observer-build-1', 'config': config, 'sources': hashes,
                    'configuration_sha256':configuration_fingerprint(**fixed),
                    'generated_sha256': hashlib.sha256(output.encode()).hexdigest(),
                    'enforcement_capable': False}
