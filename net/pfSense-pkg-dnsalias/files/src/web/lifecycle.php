<?php
/* Shared with Python's source lifetime: held until the authenticated request
 * ends, before loading view/control modules or touching plugin settings. */
function da_lifetime_identity(array $info): array {
    return array_intersect_key($info,array_flip(['dev','ino','uid','gid','mode','nlink','size','mtime','ctime']));
}
function da_lifetime_directory(string $path, int $uid): array {
    clearstatcache(true,$path);$info=@lstat($path);
    if($info===false || ($info['mode']&0170000)!==0040000 || $info['uid']!==$uid || ($info['mode']&07777)!==0700)
        throw new RuntimeException('Private source lifetime directory required');
    // The data directory changes while workers publish status snapshots.
    return array_intersect_key($info,array_flip(['dev','ino','uid','gid','mode']));
}
function da_lifetime_regular(string $path, int $uid, int $limit): array {
    clearstatcache(true,$path);$info=@lstat($path);
    if($info===false || ($info['mode']&0170000)!==0100000 || $info['uid']!==$uid || ($info['mode']&07777)!==0600 || $info['nlink']!==1 || $info['size']>$limit)
        throw new RuntimeException('Owned source lifetime file required');
    return da_lifetime_identity($info);
}
function da_lifetime_json(string $path, int $uid, int $limit): array {
    $before=da_lifetime_regular($path,$uid,$limit);
    if($before['size']===0)throw new RuntimeException('Source lifetime authority missing');
    $file=@fopen($path,'rbe');if($file===false)throw new RuntimeException('Source lifetime authority unavailable');
    try {
        if(da_lifetime_identity(fstat($file))!==$before)throw new RuntimeException('Source lifetime authority replaced');
        $raw=stream_get_contents($file,$limit+1);
        if($raw===false || strlen($raw)!==$before['size'] || da_lifetime_identity(fstat($file))!==$before || da_lifetime_regular($path,$uid,$limit)!==$before)
            throw new RuntimeException('Source lifetime authority changed');
    } finally {fclose($file);}
    $value=json_decode($raw,true,32,JSON_THROW_ON_ERROR);
    if(!is_array($value))throw new RuntimeException('Invalid source lifetime authority');
    return $value;
}
function da_source_lifetime(string $root, string $data) {
    foreach([$root,$data] as $path)if(!preg_match('~^/[A-Za-z0-9_./-]{1,511}$~D',$path) || in_array('..',explode('/',$path),true))
        throw new RuntimeException('Canonical source lifetime paths required');
    $uid=posix_geteuid();$directories=[];
    foreach([$root,$data] as $path)$directories[$path]=da_lifetime_directory($path,$uid);
    $lock=$data.'-lifetime.lock';$identity=da_lifetime_regular($lock,$uid,0);
    $file=@fopen($lock,'rbe');if($file===false)throw new RuntimeException('Source lifetime lock unavailable');
    try {
        if(da_lifetime_identity(fstat($file))!==$identity || !flock($file,LOCK_SH|LOCK_NB))
            throw new RuntimeException('DNS Alias update or removal is in progress');
        if(da_lifetime_identity(fstat($file))!==$identity || da_lifetime_regular($lock,$uid,0)!==$identity)
            throw new RuntimeException('Source lifetime lock replaced');
        foreach($directories as $path=>$before)if(da_lifetime_directory($path,$uid)!==$before)
            throw new RuntimeException('Source lifetime directory replaced');
        $owner=da_lifetime_json($data.'/OWNER.json',$uid,4096);
        if(count($owner)!==2 || ($owner['owner']??null)!=='dnsalias-observation-v1' || ($owner['root']??null)!==$root)
            throw new RuntimeException('Source lifetime owner differs');
        $manifest=da_lifetime_json($root.'/MANIFEST.json',$uid,1048576);
        if(($manifest['format']??null)!==1 || ($manifest['owner']??null)!=='dnsalias-observation-v1')
            throw new RuntimeException('Owned source manifest required');
        return $file;
    } catch(Throwable $error) {fclose($file);throw $error;}
}
