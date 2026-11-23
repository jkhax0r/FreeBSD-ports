<?php
/* On-demand status metadata only; no commands, PF, DNS, database or writes. */
function da_reply_health(array $status,float $now,string $availability='reported'): array {
    $stamp=$status['updated_utc']??null;
    $valid=(is_int($stamp)||is_float($stamp))&&is_finite((float)$stamp)&&$stamp>0&&floor((float)$stamp)<=$now;
    $fresh=$valid&&$now-floor((float)$stamp)<15;
    $state=is_string($status['state']??null)?$status['state']:'unknown';
    $telemetry=is_array($status['telemetry']??null)?$status['telemetry']:[];
    $error=is_string($telemetry['error']??null)?substr($telemetry['error'],0,120):null;
    // The on-disk report has no PID; the process-checking control API adds it.
    // Describe the report's freshness/state here, never process liveness.
    $running=$fresh&&$state==='running'&&array_key_exists('error',$status)&&$status['error']===null;
    $storage=$running&&($telemetry['thread_alive']??null)===true&&($telemetry['error']??null)===null&&array_key_exists('error',$telemetry);
    $counts=[];
    foreach(['offered','persisted','dropped','invalid','queued'] as $key){
        $value=$telemetry[$key]??null;$counts[$key]=is_int($value)&&$value>=0?$value:null;
    }
    $reasons=da_reply_reason_counts($telemetry['excluded_by_reason']??null,['request_deadline','helper_outcome','reply_metadata'],$counts['invalid']);
    $drops=da_reply_reason_counts($telemetry['dropped_by_reason']??null,['queue_full','worker_unavailable','database_busy'],$counts['dropped']);
    $loss=$status['reply_loss']['dropped']??null;
    $counts['resolver_loss']=is_int($loss)&&$loss>=0?$loss:null;
    $warning=null;
    if($availability==='unavailable'){$label='Reply status unavailable';$warning='DNS reply-feed status could not be read. Reply statistics coverage is unknown.';}
    elseif($availability!=='reported')$label='No reply-feed report';
    elseif(!$valid){$label='Reply status unavailable';$warning='DNS reply-feed status has no usable timestamp. Reply statistics coverage is unknown.';}
    elseif($state==='running'&&!$fresh){$label='Reply status stale';$warning='DNS reply-feed status is stale. Query and firewall logs may still be current.';}
    elseif($state==='failed'||!empty($status['error'])){$label='Reply feed reports failure';$warning='The last DNS reply-feed report records a failure. Reply statistics coverage is uncertain.';}
    elseif($state==='running'&&!$running){$label='Reply status unavailable';$warning='The DNS reply-feed report is incomplete. Reply statistics coverage is unknown.';}
    elseif($running&&!$storage){$label='Reply storage needs attention';$warning='DNS reply statistics storage is unavailable or uncertain'.($error!==null&&$error!==''?' ('.$error.')':'').'. Query and firewall logs may continue.';}
    elseif($running){
        $label='Reply feed reports running';
        if(($counts['resolver_loss']??0)>0)$warning='The resolver reported missing reply observations. The feed continues to process fresh replies. See the feed counters in Coverage.';
        elseif(($counts['dropped']??0)>0||($counts['invalid']??0)>0)$warning='Some DNS reply observations were dropped or excluded from trusted statistics. See the feed counters in Coverage.';
    }else $label=match($state){'stopped'=>'Reply feed reports stopped','starting'=>'Reply feed reports starting','stopping'=>'Reply feed reports stopping',default=>'Reply feed not reporting running'};
    return ['label'=>$label,'warning'=>$warning,'observed'=>$valid?$stamp:null,'fresh'=>$fresh,'reported_running'=>$running,
        'storage_reported_active'=>$storage,'error'=>$error,'counts'=>$counts,'excluded_by_reason'=>$reasons,'dropped_by_reason'=>$drops];
}
function da_reply_reason_counts($values,array $keys,?int $total): ?array {
    if(!is_array($values)||$total===null)return null;
    $counts=[];
    foreach($keys as $key){
        $value=$values[$key]??null;
        if(!is_int($value)||$value<0)return null;
        $counts[$key]=$value;
    }
    return array_sum($counts)===$total?$counts:null;
}
function da_reply_health_read(string $directory,float $now): array {
    $path=$directory.'/alias-status.json';clearstatcache(true,$path);clearstatcache(true,$directory);$before=@lstat($path);
    if($before===false)return da_reply_health([],$now,'missing');
    $unavailable=static fn()=>da_reply_health([],$now,'unavailable');
    $parent=@lstat($directory);
    if(!is_array($parent)||($parent['mode']&0170000)!==0040000||($parent['mode']&0022)!==0||
       ($before['mode']&0170000)!==0100000||($before['mode']&0777)!==0600||$before['nlink']!==1||
       $before['uid']!==$parent['uid']||$before['size']<=0||$before['size']>1048576)return $unavailable();
    $raw=@file_get_contents($path,false,null,0,1048577);clearstatcache(true,$path);$after=@lstat($path);
    if(!is_string($raw)||strlen($raw)!==$before['size']||!is_array($after))return $unavailable();
    foreach(['dev','ino','mode','nlink','uid','gid','size','mtime','ctime'] as $key)if($before[$key]!==$after[$key])return $unavailable();
    try{$value=json_decode($raw,true,64,JSON_THROW_ON_ERROR);}
    catch(Throwable $e){return $unavailable();}
    if(!is_array($value)||array_is_list($value))return $unavailable();
    return da_reply_health($value,$now);
}
function da_reply_health_warning(array $health): void {
    if($health['warning']===null)return;
    echo '<div class="da-panel da-reply-warning" role="status"><strong>DNS reply coverage</strong><p>'.da_h($health['warning']).'</p><p class="da-footnote">Feed/storage health applies to all observed clients. Last report '.da_h(da_when($health['observed'])).'. Table synchronization does not wait for statistics storage. <a href="dnsalias_status.php?view=coverage">Coverage details ↗</a></p></div>';
}
function da_reply_health_render(array $health): void {
    echo '<div class="da-panel" id="da-reply-health"><div class="da-panel-title"><h2>DNS reply feed and storage</h2><span class="da-pill da-neutral">'.da_h($health['label']).'</span></div>';
    $c=$health['counts'];
    da_table(['Reported offered','Confirmed stored','Storage drops','Excluded / unqualified','Queued','Resolver-reported misses'],[[da_num($c['offered']),da_num($c['persisted']),da_num($c['dropped']),da_num($c['invalid']),da_num($c['queued']),da_num($c['resolver_loss'])]]);
    $drops=$health['dropped_by_reason']??null;
    if(is_array($drops)&&($c['dropped']??0)>0){
        da_table(['Statistics queue full','Storage worker unavailable','Database busy'],[[
            da_num($drops['queue_full']),da_num($drops['worker_unavailable']),da_num($drops['database_busy'])]]);
    }
    $reasons=$health['excluded_by_reason']??null;
    if(is_array($reasons)&&($c['invalid']??0)>0){
        da_table(['Helper deadline expired','Other helper refusal','Invalid reply metadata'],[[
            da_num($reasons['request_deadline']),da_num($reasons['helper_outcome']),da_num($reasons['reply_metadata'])]]);
    }
    echo '<p class="da-footnote">Last feed report '.da_h(da_when($health['observed'])).'. Read when this page loads; no extra collection or process check. Counters are cumulative for the reported feed session, not the selected time window or retained-row totals. They cover all observed clients, independent of page filters. A storage error can leave a write outcome unknown; it is not automatically replayed. DNS queries, client delivery and firewall decisions are separate evidence.</p></div>';
}
