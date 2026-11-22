"""Build an inactive, fixed native parse-config registration fragment.

Pure bytes only: no files, registration, config writes, PF, network or commands.
An owning installer must qualify lifetime, paths, source and removal first.
The generated file declares request-local table identities; no traffic rules,
memberships or service startup. It is not installed by the observer package.
"""
import base64
import hashlib
import json
import re


NATIVE_SOURCES={
    '/etc/inc/globals.inc':'327bc946a5cae05aa9d0b8167ea0ccdfe23807d88073328a7aae3f4da5c28171',
    '/etc/inc/config.inc':'f6141dffbb81f7b2fbb15e305bb343963665fe7775e27506a4aeb5c782b27282',
    '/etc/inc/util.inc':'d8e7ac31116da5024835036ab16e4e67d85f28ebfeeb2d838c1226636419ff61',
    '/etc/inc/filter.inc':'23e022dda78b622ecdfbab67cc78df4ab57d3ded4419b2477907054af131518f',
}

def build(*,root,tables,alias_source,filter_source,expected_uid=0):
    """Return a source-bound one-request registration fragment and its digest.

    A nonroot UID is solely for private unprivileged fixture ownership. Caller
    must not use this descriptor alone as evidence of deployment qualification.
    """
    if type(root) is not str or len(root)>256 or not re.fullmatch(r'/(?:[A-Za-z0-9_-][A-Za-z0-9_.-]*/)*[A-Za-z0-9_-][A-Za-z0-9_.-]*',root):
        raise ValueError('canonical absolute package directory required')
    if type(expected_uid) is not int or not 0<=expected_uid<=2**31-1:
        raise ValueError('explicit native file owner required')
    if type(tables) is not list or not 1<=len(tables)<=128:
        raise ValueError('bounded nonempty policy table list required')
    seen=set()
    for table in tables:
        if type(table) is not dict or set(table)!={'name','description'}:
            raise ValueError('explicit table identity and description required')
        name,description=table['name'],table['description']
        if type(name) is not str or not re.fullmatch(r'da_[a-z][a-z0-9_]{0,22}',name) or name in seen:
            raise ValueError('invalid or duplicate owned alias')
        if type(description) is not str or len(description.encode('utf-8'))>160 or re.search(r'[\x00-\x1f\x7f]',description):
            raise ValueError('bounded plain description required')
        seen.add(name)
    sources={}
    for name,body in (('aliases.php',alias_source),('filterhook.php',filter_source)):
        if type(body) is not bytes or not 1<=len(body)<=65536 or not body.startswith(b'<?php'):
            raise ValueError('bounded reviewed native source bytes required')
        sources[root+'/native/'+name]={'sha256':hashlib.sha256(body).hexdigest(),'size':len(body)}
    config={'format':'dnsalias-native-registration-1','root':root,'tables':tables,
            'owner':expected_uid,'sources':sources,'native_sources':dict(NATIVE_SOURCES)}
    encoded=base64.b64encode(json.dumps(config,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()).decode()
    source=PHP.replace('CONFIGURATION_BASE64',encoded).encode()
    return {'source':source,'sha256':hashlib.sha256(source).hexdigest(),'configuration':config}


PHP=r'''<?php
/* Generated DNS Alias request-local registration. No commands or PF writes.
 * Not an activation mechanism: installation/removal is independently owned.
 */
(static function(): void {
    $GLOBALS['dnsalias_native_bootstrap']=['state'=>'checking'];
    try {
        $config=json_decode(base64_decode('CONFIGURATION_BASE64',true),true,16,JSON_THROW_ON_ERROR);
        $paths=[$config['root'],$config['root'].'/native'];
        foreach($paths as $path) {
            clearstatcache(true,$path);$st=@lstat($path);
            if(!$st || ($st['mode']&0170000)!==0040000 || $st['uid']!==$config['owner'] ||
               ($st['mode']&0022)!==0 || realpath($path)!==$path)throw new RuntimeException('Package directory ownership changed');
        }
        foreach($config['sources'] as $path=>$want) {
            clearstatcache(true,$path);$st=@lstat($path);
            if(!$st || ($st['mode']&0170000)!==0100000 || $st['nlink']!==1 ||
               $st['uid']!==$config['owner'] || ($st['mode']&0022)!==0 || $st['size']!==$want['size'] ||
               @hash_file('sha256',$path)!==$want['sha256'])throw new RuntimeException('Package source changed');
        }
        foreach($config['native_sources'] as $path=>$digest) {
            clearstatcache(true,$path);$st=@lstat($path);
            if(!$st || ($st['mode']&0170000)!==0100000 || $st['uid']!==0 || ($st['mode']&0022)!==0 ||
               $st['size']>1000000 || @hash_file('sha256',$path)!==$digest)throw new RuntimeException('Qualified native source changed');
        }
        require_once $config['root'].'/native/filterhook.php';
        $definitions=dnsalias_native_register_dynamic_tables($config['tables']);
        $GLOBALS['dnsalias_native_bootstrap']=['state'=>'registered','tables'=>array_keys($definitions),
            'scope'=>'request-local identities only','enforcement_applied'=>false];
    } catch (Throwable $error) {
        // An optional package must not make every native page fatal. The
        // supervisor must treat this as an unavailable registration, not ready.
        $GLOBALS['dnsalias_native_bootstrap']=['state'=>'unavailable','reason'=>$error->getMessage(),
            'enforcement_applied'=>false];
    }
})();
'''
