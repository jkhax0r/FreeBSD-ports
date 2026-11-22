"""Pure, hash-pinned hook-overlay candidate. No filesystem or live installer.

The original policy remains a byte-for-byte prefix. Only its entry functions
are delegated through the observation dispatcher. A single self-contained file
survives pfSense's basename-only test copy. Regeneration/upgrades are detected;
unknown content is never overwritten or treated as ours.
"""
import ast
import hashlib

MARKER=b'\n# DNSALIAS OBSERVATION OVERLAY v1 BEGIN\n'
END=b'# DNSALIAS OBSERVATION OVERLAY v1 END\n'
LIMIT=1024*1024


def digest(data): return hashlib.sha256(data).hexdigest()


def render(original, observer_source, dispatcher_source, *, expected_sha256):
    if not isinstance(original,bytes) or not 1<=len(original)<=512*1024:
        raise ValueError('invalid policy size')
    if MARKER in original or digest(original)!=expected_sha256:
        raise ValueError('policy is changed or already wrapped')
    policy_tree=ast.parse(original)
    functions={n.name for n in policy_tree.body if isinstance(n,ast.FunctionDef)}
    if not {'init_standard','deinit','operate','inform_super'}<=functions:
        raise ValueError('unqualified policy entry points')
    for source,limit in ((observer_source,256*1024),(dispatcher_source,64*1024)):
        if not isinstance(source,str) or not 1<=len(source.encode())<=limit:
            raise ValueError('invalid companion source size')
        ast.parse(source)
    # Preserve policy globals and original function references. Do not execute
    # the policy a second time, import a companion path or modify its config.
    suffix=(
        'try:\n'
        '    _dnsalias_dispatch_scope = {}\n'
        '    exec(compile('+repr(dispatcher_source)+', "dnsalias_dispatch", "exec"), _dnsalias_dispatch_scope)\n'
        '    _dnsalias_entrypoints = _dnsalias_dispatch_scope["compose"](_dnsalias_dispatch_scope["runtime_api"](globals()), '+repr(observer_source)+', existing_policy=globals())\n'
        '    globals().update(_dnsalias_entrypoints)\n'
        'except Exception as _dnsalias_overlay_error:\n'
        '    try: log_err("DNS Alias overlay disabled: " + type(_dnsalias_overlay_error).__name__)\n'
        '    except Exception: pass\n'
    ).encode()
    installed=original+MARKER+suffix+END
    if len(installed)>LIMIT: raise ValueError('overlay size cap')
    ast.parse(installed)
    manifest={'format':'dnsalias-hook-overlay-1','original_size':len(original),
              'original_sha256':digest(original),'installed_sha256':digest(installed),
              'observer_sha256':digest(observer_source.encode()),'dispatcher_sha256':digest(dispatcher_source.encode())}
    return installed,manifest


def state(current, manifest):
    if manifest.get('format')!='dnsalias-hook-overlay-1': raise ValueError('unrecognized ownership record')
    if current is None: return 'missing'
    if not isinstance(current,bytes) or len(current)>LIMIT: return 'foreign_changed'
    sha=digest(current)
    if sha==manifest['installed_sha256']: return 'owned_overlay'
    if sha==manifest['original_sha256']: return 'original_restored'
    return 'foreign_changed'


def restore(current, manifest):
    status=state(current,manifest)
    if status=='original_restored': return current
    if status!='owned_overlay': raise ValueError('refuse to overwrite missing or changed hook')
    size=manifest['original_size']
    if type(size) is not int or not 1<=size<=512*1024: raise ValueError('invalid original length')
    original=current[:size]
    if digest(original)!=manifest['original_sha256'] or current[size:size+len(MARKER)]!=MARKER:
        raise ValueError('ownership record does not match original prefix')
    return original
