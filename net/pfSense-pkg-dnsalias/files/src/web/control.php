<?php
require_once(__DIR__."/observation.php");
require_once(__DIR__."/capacity.php");
/* Authentication, firewall-page privilege and native CSRF validation must
 * precede changes. The endpoint accepts one previously prepared scope only. */
function da_trial_request($op,$token=null) {
    if (in_array($op,['status','prepare','prepare_observation','prepare_policy'],true) && $token===null) {return ['op'=>$op];}
    if (!in_array($op,['start','undo','stop'],true) || !is_string($token) || !preg_match('/^[a-f0-9]{32}$/D',$token)) {
        throw new RuntimeException('Invalid trial request');
    }
    return ['op'=>$op,'token'=>$token];
}
function da_trial_snapshot($v) {
    $named=is_array($v) && is_string($v['policy_name']??null) && preg_match('/^[a-z][a-z0-9_]{0,22}$/D',$v['policy_name']);
    $seconds=$v['block_seconds']??null;
    $web=$named && ($v['port']??null)==='web';
    if (!is_array($v) || ($v['format']??null)!=='dnsalias-trial-control-1' ||
        !in_array($v['state']??null,['prepared','queued','running','cancelling','cancelled','expired','complete','inspection_required'],true) ||
        !is_string($v['token']??null) || !preg_match('/^[a-f0-9]{32}$/D',$v['token']) ||
        !is_string($v['client']??null) || !filter_var($v['client'],FILTER_VALIDATE_IP) ||
        !is_string($v['interface']??null) || !preg_match('/^[a-zA-Z0-9_.]{1,32}$/D',$v['interface']) ||
        (!$web && !in_array($v['port']??null,[80,443],true)) || ($v['protocol']??null)!==($web?'tcp/udp':'tcp') ||
        (!is_int($seconds) || ($named?!in_array($seconds,[60,300,900,3600],true):$seconds!==5)) || ($v['independent_rule_seconds']??null)!==$seconds+5 ||
        !is_array($v['names']??null) || count($v['names'])<1 || count($v['names'])>8 ||
        !is_numeric($v['preview_expires_utc']??null)) {throw new RuntimeException('Invalid trial status');}
    foreach ($v['names'] as $name) {
        if (!is_string($name) || strlen($name)>253 || !preg_match($named?'/^(?:\*\.)?[a-z0-9_.-]+$/D':'/^[a-z0-9_.-]+$/D',$name)) {throw new RuntimeException('Invalid trial name');}
    }
    foreach (['started','cancel_requested','rule_activated','rule_removed','restoration_verified','resources_released','traffic_verified','shared_ip_impact','include_subdomains'] as $key) {
        if (!is_bool($v[$key]??null)) {throw new RuntimeException('Invalid trial evidence');}
    }
    $wildcard=count(array_filter($v['names'],fn($name)=>str_starts_with($name,'*.')))>0;
    if ($v['traffic_verified'] || !$v['shared_ip_impact'] || $v['include_subdomains']!==($named && $wildcard)) {throw new RuntimeException('Unqualified trial scope');}
    if (isset($v['table'])) {
        if (!is_string($v['table']) || ($named?$v['table']!=='da_'.$v['policy_name']:!preg_match('/^da_mvp_[a-f0-9]{12}$/D',$v['table'])) ||
            !is_array($v['members']??null) || count($v['members'])>128 || !is_int($v['members_count']??null) ||
            $v['members_count']<count($v['members']) || $v['members_count']>100000 || !is_bool($v['no_matching_address']??null)) {throw new RuntimeException('Invalid alias status');}
        foreach($v['members'] as $ip) {if(!is_string($ip)||!filter_var($ip,FILTER_VALIDATE_IP)){throw new RuntimeException('Invalid alias member');}}
    }
    if(isset($v['rule_trackers'])) {
        if(!is_array($v['rule_trackers']) || !array_is_list($v['rule_trackers']) || count($v['rule_trackers'])!==($named?($web?4:1):0) || count(array_unique($v['rule_trackers']))!==count($v['rule_trackers'])) {throw new RuntimeException('Invalid policy rule identities');}
        foreach($v['rule_trackers'] as $id){if(!is_string($id)||!ctype_digit($id)||strlen($id)>10||(int)$id<2147483648||(int)$id>4294967295){throw new RuntimeException('Invalid policy tracker');}}
    }
    if(isset($v['rule_counters'])) {
        $c=$v['rule_counters'];
        if(!is_array($c)||($c['rule_trackers']??null)!==($v['rule_trackers']??null)||!is_int($c['packets']??null)||$c['packets']<0||!is_int($c['bytes']??null)||$c['bytes']<0||!is_numeric($c['observed_utc']??null)){throw new RuntimeException('Invalid policy counters');}
    }
    if(array_key_exists('names_revision',$v)) {
        if(!is_int($v['names_revision']) || $v['names_revision']<0 || $v['names_revision']>16 || !array_key_exists('names_pending',$v)) {throw new RuntimeException('Invalid name edit revision');}
        if($v['names_pending']!==null && (!is_array($v['names_pending']) || !array_is_list($v['names_pending']) || $v['names_pending']!==da_policy_names(implode("\n",$v['names_pending'])))) {throw new RuntimeException('Invalid pending names');}
    }
    if(array_key_exists('registered_alias',$v) && !is_bool($v['registered_alias'])) {throw new RuntimeException('Invalid saved alias status');}
    return $v;
}
function da_trial_progress($directory) {
    // Read only. Owners publish a bounded atomic checkpoint before each phase.
    // A slow source audit/reload must not make a status read wait on its socket.
    for ($attempt=0;$attempt<2;$attempt++) {
        $before=da_trial_owned_file($directory,'runtime.json',65536);
        if ($before===null) {return null;}
        $parent=@lstat($directory);$stream=@fopen($directory.'/runtime.json','rb');
        if ($stream===false) {throw new RuntimeException('Progress unavailable');}
        try {$opened=fstat($stream);$raw=stream_get_contents($stream,65537);$after=fstat($stream);}
        finally {fclose($stream);}
        clearstatcache(true,$directory);clearstatcache(true,$directory.'/runtime.json');
        $named=@lstat($directory.'/runtime.json');$parentAfter=@lstat($directory);
        $changed=!$named || !$parent || !$parentAfter || $parent['dev']!==$parentAfter['dev'] || $parent['ino']!==$parentAfter['ino'];
        foreach (['mode','uid','gid'] as $key) {if (!$parent || !$parentAfter || $parent[$key]!==$parentAfter[$key]) {$changed=true;}}
        foreach (['dev','ino','mode','uid','gid','size','mtime','ctime','nlink'] as $key) {
            if (!$opened || !$after || $before[$key]!==$opened[$key] || $opened[$key]!==$after[$key] || !$named || $after[$key]!==$named[$key]) {$changed=true;}
        }
        if ($changed) {if ($attempt===0) {continue;}throw new RuntimeException('Progress changed during read');}
        if (!is_string($raw) || strlen($raw)!==$opened['size'] || strlen($raw)>65536) {throw new RuntimeException('Invalid progress size');}
        // CheckpointFile emits this exact envelope. Hash the original payload
        // bytes so PHP and Python floating-point encoders need not agree.
        if (!preg_match('/^\{"checkpoint":(\{.*\}),"format":"([^"]+)","sha256":"([a-f0-9]{64})"\}$/sD',$raw,$m) || !hash_equals($m[3],hash('sha256',$m[1]))) {
            throw new RuntimeException('Progress integrity unavailable');
        }
        $v=json_decode($raw,true,32,JSON_THROW_ON_ERROR);$c=$v['checkpoint']??null;
        $types=['dnsalias-short-runtime-envelope-1'=>['dnsalias-short-runtime-1','trial'],
            'dnsalias-observation-runtime-envelope-1'=>['dnsalias-observation-runtime-1','observation']];
        $type=$types[$v['format']??'']??null;
        if ($type===null || !is_array($c) || ($c['format']??null)!==$type[0] || ($c['root']??null)!==dirname(__DIR__) ||
            !in_array($c['phase']??null,['prepared','start_consumed','table_created','running','feed_finished','supervisor_finished','complete'],true)) {
            throw new RuntimeException('Progress scope unavailable');
        }
        $snapshot=da_control_snapshot($c[$type[1]]??null);
        if (($type[1]==='observation')!==($snapshot['format']==='dnsalias-observation-control-1')) {throw new RuntimeException('Progress operation changed');}
        $age=time()-$opened['mtime'];$snapshot['progress_age_seconds']=max(0,$age);
        if (in_array($snapshot['state'],['prepared','queued'],true) && time()>=$snapshot['preview_expires_utc']) {$snapshot['state']='expired';}
        $maxAge=!empty($snapshot['policy_name'])&&in_array($snapshot['state'],['queued','running','cancelling'],true)?25:($snapshot['duration_seconds']??30)+60;
        if (!in_array($snapshot['state'],['complete','cancelled','expired','inspection_required'],true) && ($age< -2 || $age>$maxAge)) {
            $snapshot['state']='inspection_required';$snapshot['error']='Progress is stale; local inspection required';
        }
        return $snapshot;
    }
    throw new RuntimeException('Progress unavailable');
}
function da_trial_exchange($directory,$request) {
    if ($request===['op'=>'status']) {
        $progress=da_trial_progress($directory);
        if ($progress!==null) {return $progress;}
    }
    // The installed page supplies a fixed directory, never a request parameter.
    $path=$directory.'/control.sock';$uid=fileowner(__FILE__);
    clearstatcache(true,$directory);clearstatcache(true,$path);
    if (!file_exists($directory) && !is_link($directory)) {return null;}
    $parent=@lstat($directory);$socket=@lstat($path);
    if (!$parent || ($parent['mode']&0170000)!==0040000 || $parent['uid']!==$uid || ($parent['mode']&0777)!==0700 ||
        !$socket || ($socket['mode']&0170000)!==0140000 || $socket['uid']!==$uid || ($socket['mode']&0777)!==0600 || $socket['nlink']!==1) {
        throw new RuntimeException('Control ownership unavailable');
    }
    $body=json_encode($request,JSON_THROW_ON_ERROR)."\n";
    if (strlen($body)>4096) {throw new RuntimeException('Trial request too large');}
    $stream=@stream_socket_client('unix://'.$path,$errno,$error,.25,STREAM_CLIENT_CONNECT);
    if ($stream===false) {throw new RuntimeException('Control unavailable');}
    try {
        stream_set_timeout($stream,0,250000);
        clearstatcache(true,$path);$after=@lstat($path);
        if (!$after || $after['dev']!==$socket['dev'] || $after['ino']!==$socket['ino'] || $after['mode']!==$socket['mode'] || $after['uid']!==$uid) {
            throw new RuntimeException('Control changed');
        }
        if (@fwrite($stream,$body)!==strlen($body)) {throw new RuntimeException('Request outcome unavailable');}
        $raw=@fgets($stream,16386);
        if (!is_string($raw) || strlen($raw)>16384 || !str_ends_with($raw,"\n")) {throw new RuntimeException('Request outcome unavailable');}
        $response=json_decode($raw,true,32,JSON_THROW_ON_ERROR);
        if (!is_array($response) || ($response['ok']??false)!==true) {throw new RuntimeException('Trial request refused');}
        return da_control_snapshot($response['trial']??null);
    } finally {fclose($stream);}
}
function da_trial_render($trial,$canControl,$error='') {
    if (($trial['format']??null)==='dnsalias-observation-control-1') {da_observation_render($trial,$canControl,$error);return;}
    if ($trial===null && $error==='') {return;}
    $named=!empty($trial['policy_name']);
    echo '<div class="da-panel" id="da-trial-control" data-state="'.da_h($trial['state']??'unavailable').'"><div class="da-panel-title"><h2>'.($named?'DNS alias block policy':'Prepared block trial').'</h2></div>';
    if ($error!=='') {echo '<p class="da-notice da-danger">'.da_h($error).'</p>';}
    if ($trial!==null) {
        $labels=['prepared'=>'Ready for review','queued'=>'Start requested','running'=>'Trial running','cancelling'=>'Undo requested; cleanup pending','cancelled'=>'Cancelled','expired'=>'Preview expired; fresh checks required','complete'=>'Trial complete','inspection_required'=>'Inspection required'];
        if($named){$labels=array_replace($labels,['prepared'=>'Review alias and blocking','queued'=>'Enable requested','running'=>!empty($trial['rule_activated'])&&!$trial['rule_removed']?'Blocking enabled':'Starting alias policy','cancelling'=>'Undo requested; restoration pending','cancelled'=>'Blocking disabled','complete'=>'Policy expired']);}
        if(($trial['end_reason']??null)==='rule_absent'){$labels['complete']='Stopped: firewall rule removed';}
        if($trial['state']==='cancelled' && !$trial['started']){$labels['cancelled']='Preview cancelled';}
        $state=$trial['state'];
        echo '<p><strong>'.da_h($labels[$state]).'</strong> · '.da_h($trial['client']).' on '.da_h($trial['interface']).' · '.da_h(da_policy_scope_label($trial['port'])).'</p>';
        echo '<p>'.($named?'Names / patterns':'Exact names').': <strong>'.da_h(implode(', ',$trial['names'])).'</strong>. '.($named?'Blocks for up to '.da_h($trial['block_seconds']).' seconds; Undo stops it early. Independent rule expiry: '.da_h($trial['independent_rule_seconds']).' seconds.':'Five-second block, with independent ten-second rule expiry.').'</p>';
        if (!empty($trial['no_matching_address'])) {echo '<p class="da-notice">No matching destination address was received. The test finished without activating a block.</p>';}
        echo '<p class="da-footnote">Other names sharing these destination IPs can be affected. Existing connections are not killed. Rule activation does not prove which hostname was used.</p>';
        echo '<p>Rule removal: <strong>'.($trial['rule_removed']?'verified':($trial['rule_activated']?'pending':'no activation reported')).'</strong> · DNS restoration: <strong>'.($trial['restoration_verified']?'verified':(!$trial['started']?'not started':'not yet verified')).'</strong></p>';
        if (isset($trial['progress_age_seconds'])) {echo '<p class="da-footnote">Last progress update: '.da_h($trial['progress_age_seconds']).' seconds ago.</p>';}
        if ($canControl && in_array($state,['prepared','queued','running','cancelling'],true)) {
            echo '<form method="post" action="dnsalias_status.php?view=aliases"><input type="hidden" name="trial_token" value="'.da_h($trial['token']).'">';
            if ($state==='prepared') {echo '<button class="da-primary" name="trial_op" value="start" type="submit">'.($named?'Enable blocking':'Start five-second test').'</button> ';}
            echo '<button name="trial_op" value="undo" type="submit">'.($state==='prepared'?'Cancel trial':'Undo now').'</button></form>';
        }
        if (!$canControl) {echo '<p class="da-footnote">Firewall rule editing privilege is required for trial controls.</p>';}
        if($canControl && $named && $state==='running' && $trial['rule_activated'] && !$trial['rule_removed'] && isset($trial['names_revision']) && $trial['names_revision']<16) {
            if($trial['names_pending']!==null) {
                echo '<p class="da-notice">Name edit pending: '.da_h(implode(', ',$trial['names_pending'])).'. Refresh to confirm; queue acceptance does not mean the table changed.</p>';
            } else {
                echo '<details><summary>Edit this alias’s names without reloading DNS</summary><form method="post" action="dnsalias_status.php?view=aliases"><input type="hidden" name="trial_token" value="'.da_h($trial['token']).'"><input type="hidden" name="names_revision" value="'.da_h($trial['names_revision']).'"><p><label>Names or *.suffix patterns<br><textarea name="policy_names" rows="3" cols="50" maxlength="2048" required>'.da_h(implode("\n",$trial['names'])).'</textarea></label></p><button class="da-primary" name="trial_op" value="names" type="submit">Apply names</button><p class="da-footnote">Keeps the same client, ports, rule IDs and original expiry. Removed names lose only their own leases. New exact names get a bounded lookup; suffixes learn subsequent queries. Existing states remain. At most 16 edits per session.</p></form></details>';
            }
        }
    }
    echo '<p><a class="da-detail" href="dnsalias_status.php?view=aliases">Refresh trial status</a></p></div>';
}

function da_trial_alias_render($trial) {
    if (!is_array($trial) || ($trial['format']??null)!=='dnsalias-trial-control-1' || !isset($trial['table'])) {return false;}
    $trial=da_trial_snapshot($trial);
    $unused=!$trial['started'] && in_array($trial['state'],['cancelled','expired'],true);
    $removed=$unused || (($trial['resources_released']??false) && ($trial['restoration_verified']??false));
    $named=!empty($trial['policy_name']);
    $registered=!empty($trial['registered_alias']);
    echo '<div class="da-panel"><div class="da-panel-title"><div><h2>'.da_h($trial['policy_name']??implode(', ',$trial['names'])).'</h2><p>'.($registered?'Saved pfSense destination alias':'Temporary DNS-fed alias').' · '.da_h($trial['table']).'</p></div><span class="da-pill '.($removed?'da-neutral':(!empty($trial['rule_activated'])&&!$trial['rule_removed']?'da-block':'da-warn')).'">'.($removed?'Session ended':(!empty($trial['rule_activated'])&&!$trial['rule_removed']?'Blocking':'Waiting / preparing')).'</span></div>';
    if($named){echo '<p>Names / patterns: <strong>'.da_h(implode(', ',$trial['names'])).'</strong></p>';}
    if($registered){echo '<p class="da-notice">Ordinary firewall rules using this saved alias also use its shared destination IPs. A verified clean stop clears memberships and retains the empty alias. Failed cleanup requires inspection. No automatic reboot startup is enabled.</p>';}
    else{echo '<p class="da-footnote">Session-only policy: this alias is not saved in Firewall &gt; Aliases. Its temporary table and rule end with this session.</p>';}
    if(isset($trial['rule_counters'])) {
        $c=$trial['rule_counters'];echo '<p><strong>'.da_h(da_number($c['packets'])).' blocked packets</strong> · '.da_h(da_bytes($c['bytes'])).' · counters sampled '.da_h(da_when($c['observed_utc'])).'</p><p class="da-footnote">Counters belong to this exact policy rule set. Packets include retransmissions; these are not HTTP request or exact hostname counts.</p>';
    }
    echo '<p>Rule source <strong>'.da_h($trial['client']).'</strong> · '.da_h(da_policy_scope_label($trial['port'])).' · '.da_h($trial['interface']).'. Any trusted client’s matching DNS reply can populate the shared table.</p>';
    $rows=[];foreach($trial['members']??[] as $ip){$rows[]=[['text'=>$ip,'url'=>'dnsalias_status.php?view=ip&destination='.rawurlencode($ip)],$removed?($registered?'Recorded before release':'Recorded before removal'):($named?'Latest membership snapshot':'Recorded at block activation')];}
    da_table(['Destination IP','Membership evidence'],$rows);
    echo '<p class="da-footnote">'.da_h($trial['members_count']??0).' addresses'.(($trial['members_count']??0)>count($rows)?'; first 128 shown':'').'. '.($named?'Latest owner snapshot: '.da_h(da_when($trial['members_observed_utc']??null)).'. Membership samples do not renew DNS TTLs.':'This is a bounded activation snapshot, not a current membership or TTL readback.').' DNS leases expire independently; established states are not killed. No automatic reboot startup is enabled.</p></div>';
    return true;
}

function da_trial_owned_file($directory,$name,$maximum) {
    $path=$directory.'/'.$name;$uid=fileowner(__FILE__);
    clearstatcache(true,$directory);clearstatcache(true,$path);
    if (!file_exists($path) && !is_link($path)) {return null;}
    $parent=@lstat($directory);$item=@lstat($path);
    if (!$parent || ($parent['mode']&0170000)!==0040000 || $parent['uid']!==$uid || ($parent['mode']&0777)!==0700 ||
        !$item || ($item['mode']&0170000)!==0100000 || $item['uid']!==$uid || ($item['mode']&0777)!==0600 || $item['nlink']!==1 || $item['size']>$maximum) {
        throw new RuntimeException('Preparation file ownership unavailable');
    }
    return $item;
}
function da_trial_preparation($directory) {
    $out=['available'=>false,'busy'=>false,'state'=>'unconfigured','last'=>null,'profile'=>null,'last_refused'=>false,'refusal_reason'=>null,'capacity'=>null];
    if (!da_trial_owned_file($directory,'trial-profile.json',32768)) {return $out;}
    $p=json_decode(file_get_contents($directory.'/trial-profile.json'),true,32,JSON_THROW_ON_ERROR);
    if (($p['format']??null)!=='dnsalias-approved-trial-1' || ($p['target']['root']??null)!==dirname(__DIR__) || ($p['target']['data']??null)!==$directory ||
        !is_string($p['scope']['client']??null) || !filter_var($p['scope']['client'],FILTER_VALIDATE_IP) || !in_array($p['scope']['port']??null,[80,443],true) ||
        !is_array($p['names']??null) || count($p['names'])<1 || count($p['names'])>8) {throw new RuntimeException('Approved preparation scope unavailable');}
    foreach($p['names'] as $name){if(!is_string($name)||strlen($name)>253||!preg_match('/^[a-z0-9_.-]+$/D',$name)){throw new RuntimeException('Approved name unavailable');}}
    $out['available']=true;$out['state']='ready';$out['profile']=['client'=>$p['scope']['client'],'port'=>$p['scope']['port'],'names'=>$p['names']];
    $out['capacity']=da_policy_capacity($p['target']['mode']??null,$p['max_policy_bytes']??null,$p['target']['control_directory']??null);
    $claim=null;
    if (da_trial_owned_file($directory,'trial-launch.json',4096)) {
        $claim=json_decode(file_get_contents($directory.'/trial-launch.json'),true,16,JSON_THROW_ON_ERROR);
        if ((!in_array($claim['format']??null,['dnsalias-launch-claim-1','dnsalias-launch-claim-2'],true) || (($claim['format']??null)==='dnsalias-launch-claim-2' && !in_array($claim['operation']??null,['block','observe'],true))) || !is_string($claim['token']??null) || !preg_match('/^[a-f0-9]{32}$/D',$claim['token'])) {throw new RuntimeException('Launch claim unavailable');}
        $out['busy']=true;$out['state']='preparing';
    }
    $observeRequest=da_trial_owned_file($directory,'observation-prepare-request',0);
    $blockRequest=da_trial_owned_file($directory,'trial-prepare-request',4096);
    if ($observeRequest || $blockRequest) {$out['busy']=true;$out['state']=$observeRequest && $blockRequest?'inspection_required':'queued';}
    if (da_trial_owned_file($directory,'trial-prepare-pending',4096)) {$out['busy']=true;$out['state']='inspection_required';}
    if (da_trial_owned_file($directory,'trial-last.pending',65536)) {$out['busy']=true;$out['state']='inspection_required';}
    if (da_trial_owned_file($directory,'trial-last.json',65536)) {
        $envelope=json_decode(file_get_contents($directory.'/trial-last.json'),true,32,JSON_THROW_ON_ERROR);$last=$envelope['checkpoint']??null;
        if (($envelope['format']??null)!=='dnsalias-last-trial-envelope-1' || !is_array($last) || ($last['format']??null)!=='dnsalias-last-trial-1') {throw new RuntimeException('Last trial result unavailable');}
        $out['last_refused']=!$out['busy']&&($last['state']??null)==='refused'&&($last['inspection_required']??true)===false;
        if($out['last_refused']&&($last['refusal_reason']??null)==='policy_capacity'){$out['refusal_reason']='policy_capacity';}
        if ($claim!==null && ($last['token']??null)===$claim['token'] && ($last['inspection_required']??false)===true) {$out['state']='inspection_required';}
        if ((!$out['busy'] || ($out['state']==='inspection_required' && ($last['token']??null)===($claim['token']??null))) && is_array($last['trial']??null)) {
            if (!in_array($last['trial']['state']??null,['complete','cancelled','expired','inspection_required'],true)) {throw new RuntimeException('Last result is not terminal');}
            $out['last']=da_control_snapshot($last['trial']);
        }
    }
    return $out;
}
function da_policy_history_read($directory,$now=null) {
    if(!da_trial_owned_file($directory,'policy-history.json',270336)){return [];}
    $raw=file_get_contents($directory.'/policy-history.json');
    if(!is_string($raw)||strlen($raw)>270336||!preg_match('/^\{"checkpoint":(\{.*\}),"format":"dnsalias-policy-history-envelope-1","sha256":"([a-f0-9]{64})"\}$/sD',$raw,$m)||!hash_equals($m[2],hash('sha256',$m[1]))){throw new RuntimeException('Policy history integrity unavailable');}
    $body=json_decode($m[1],true,16,JSON_THROW_ON_ERROR);
    if(($body['format']??null)!=='dnsalias-policy-history-1'||!is_array($body['sessions']??null)||!array_is_list($body['sessions'])||count($body['sessions'])>64){throw new RuntimeException('Policy history unavailable');}
    foreach($body['sessions'] as $s){
        if(!is_array($s)||!is_string($s['name']??null)||!preg_match('/^[a-z][a-z0-9_]{0,22}$/D',$s['name'])||!filter_var($s['client']??'',FILTER_VALIDATE_IP)||!is_array($s['rule_trackers']??null)||!array_is_list($s['rule_trackers'])||count($s['rule_trackers'])!==(($s['port']??null)==='web'?4:1)||!is_array($s['names']??null)||count($s['names'])<1||count($s['names'])>8||!is_numeric($s['started_utc']??null)||!is_numeric($s['until_utc']??null)||$s['until_utc']<$s['started_utc']||$s['until_utc']-$s['started_utc']>3630){throw new RuntimeException('Invalid recorded policy');}
        foreach($s['rule_trackers'] as $id){if(!is_string($id)||!ctype_digit($id)||strlen($id)>10||(int)$id<2147483648||(int)$id>4294967295){throw new RuntimeException('Invalid recorded rule ID');}}
        foreach($s['names'] as $name){if(!is_string($name)||strlen($name)>253||!preg_match('/^(?:\*\.)?[a-z0-9_.-]+$/D',$name)){throw new RuntimeException('Invalid recorded name');}}
        if(($s['ended_utc']??null)!==null&&(!is_numeric($s['ended_utc'])||$s['ended_utc']<$s['started_utc']||$s['ended_utc']>$s['until_utc'])){throw new RuntimeException('Invalid policy end');}
        if(isset($s['counters'])){$c=$s['counters'];if(!is_array($c)||($c['rule_trackers']??null)!==$s['rule_trackers']||!is_int($c['packets']??null)||$c['packets']<0||!is_int($c['bytes']??null)||$c['bytes']<0||!is_numeric($c['observed_utc']??null)){throw new RuntimeException('Invalid recorded counters');}}
    }
    $now=$now??time();return array_values(array_filter($body['sessions'],fn($s)=>$s['until_utc']>=$now-86400));
}
function da_policy_history_render($v) {
    $rows=[];
    if(!empty($v['policy_history_error'])){echo '<p class="da-notice">Policy history is unavailable; recorded firewall events remain visible without those labels.</p>';}
    foreach(array_reverse($v['policy_history']??[]) as $s){
        $c=$s['counters']??null;
        $rows[]=[$s['name'],implode(', ',$s['names']),['text'=>da_client_label($v,$s['client']),'url'=>'dnsalias_status.php?view=client&client='.rawurlencode($s['client'])],da_policy_scope_label($s['port']),da_num($c['packets']??null),$c?da_bytes($c['bytes']):'Not sampled',da_time($s['ended_utc']??$s['started_utc']),['detail'=>['Client'=>$s['client'],'Interface'=>$s['interface'],'Started'=>da_when($s['started_utc']),'Ended'=>isset($s['ended_utc'])?da_when($s['ended_utc']):'No end record','Rule IDs'=>implode(', ',$s['rule_trackers']),'Counters sampled'=>da_when($c['observed_utc']??null)],'label'=>'Recorded scope']];
    }
    echo '<div class="da-panel"><div class="da-panel-title"><h2>Recent policy sessions</h2></div>';
    da_table(['Policy','Names at activation','Source','Ports','Block packets','Bytes','Last record','Details'],$rows);
    echo '<p class="da-footnote">Up to 64 starts recorded by this version, within 24 hours. Previews never replace this history. Counters are the owner’s final available sample, not HTTP requests. A recorded start alone does not prove a rule is still enabled. Older activity is not reconstructed.</p></div>';
}
function da_policy_scope_label($port) {return $port==='web'?'TCP/UDP 80 and 443 (HTTP, HTTPS and QUIC)':'TCP '.$port;}
function da_policy_prefill($query) {
    $name=$query['block_name']??null;
    if(!is_string($name)||strlen($name)>2048||preg_match('/[\x00-\x1f\x7f]/',$name)){return null;}
    try {
        $input=['policy_alias'=>'selected_name','policy_names'=>$name,'policy_port'=>'web','policy_seconds'=>'900'];
        if(isset($query['block_client'])){$input['policy_client']=$query['block_client'];}
        $policy=da_policy_input($input);
        if(count($policy['names'])!==1 || str_starts_with($policy['names'][0],'*.')) {return null;}
        $policy['alias']=substr('block_'.preg_replace('/[^a-z0-9_]/','_',$policy['names'][0]),0,23);
        return $policy;
    } catch(Throwable $e) {return null;}
}
function da_block_review_link($v,$client,$name) {
    if(function_exists('da_saved_aliases_render')) {
        if(empty($v['can_control']))return null;
        $prefill=da_policy_prefill(['block_name'=>$name]);
        if($prefill===null)return null;
        // Shared table edits do not select a source client or create rules.
        return ['url'=>'dnsalias_status.php?view=aliases&block_name='.rawurlencode($prefill['names'][0]),'text'=>'Add to DNS alias'];
    }
    if (empty($v['can_control']) || (!function_exists('da_saved_aliases_render') && empty($v['preparation']['available'])) ||
        !is_string($client) || !filter_var($client,FILTER_VALIDATE_IP) || da_loopback($client)) {return null;}
    $prefill=da_policy_prefill(['block_name'=>$name,'block_client'=>$client]);
    if($prefill===null) {return null;}
    return ['url'=>'dnsalias_status.php?view=aliases&block_name='.rawurlencode($prefill['names'][0]).'&block_client='.rawurlencode($prefill['client']),'text'=>function_exists('da_saved_aliases_render')?'Add to DNS alias':'Review block'];
}
function da_policy_names($raw) {
    if(!is_string($raw) || strlen($raw)>2048){throw new RuntimeException('Bounded names required');}
    $names=preg_split('/[\s,]+/',strtolower(trim($raw)),-1,PREG_SPLIT_NO_EMPTY);
    if(count($names)<1||count($names)>8||count(array_unique($names))!==count($names)){throw new RuntimeException('One to eight distinct names required');}
    foreach($names as &$domain){$domain=rtrim($domain,'.');$plain=str_starts_with($domain,'*.')?substr($domain,2):$domain;
        if(strlen($domain)>253||!preg_match('/^[a-z0-9_-]+(?:\.[a-z0-9_-]+)*$/D',$plain)){throw new RuntimeException('DNS names required; omit URLs and paths');}
        foreach(explode('.',$plain) as $label){if(strlen($label)>63){throw new RuntimeException('DNS label too long');}}
    }unset($domain);
    if(count(array_unique($names))!==count($names)){throw new RuntimeException('Distinct normalized names required');}
    return $names;
}
function da_policy_names_request($post) {
    $token=da_trial_request('start',$post['trial_token']??null)['token'];
    $revision=$post['names_revision']??null;
    if(!is_string($revision)||!ctype_digit($revision)||strlen($revision)>2||(int)$revision>15){throw new RuntimeException('Current name-list revision required');}
    return ['op'=>'names','token'=>$token,'revision'=>(int)$revision,'names'=>da_policy_names($post['policy_names']??null)];
}
function da_policy_input($post) {
    if (!is_string($post['policy_alias']??null) || !is_string($post['policy_port']??null) || !is_string($post['policy_seconds']??null)) {throw new RuntimeException('Complete policy fields required');}
    $name=strtolower(trim($post['policy_alias']));
    if(!preg_match('/^[a-z][a-z0-9_]{0,22}$/D',$name)||str_starts_with($name,'mvp_')||str_starts_with($name,'seed')){throw new RuntimeException('Bounded distinct alias name required');}
    $names=da_policy_names($post['policy_names']??null);
    if(!in_array($post['policy_port'],['80','443','web'],true)||!in_array($post['policy_seconds'],['60','300','900','3600'],true)){throw new RuntimeException('Explicit port and expiry required');}
    $value=['format'=>'dnsalias-mvp-policy-1','alias'=>$name,'names'=>$names,'port'=>$post['policy_port']==='web'?'web':(int)$post['policy_port'],'block_seconds'=>(int)$post['policy_seconds']];
    if(isset($post['policy_client'])) {
        if(!is_string($post['policy_client']) || !filter_var(trim($post['policy_client']),FILTER_VALIDATE_IP)){throw new RuntimeException('One exact client IP required');}
        $client=inet_ntop(inet_pton(trim($post['policy_client'])));
        if(da_loopback($client) || in_array($client,['0.0.0.0','::'],true)){throw new RuntimeException('A LAN client is required');}
        $value['client']=$client;
    }
    return $value;
}
function da_queue_trial_preparation($directory,$status,$now,$operation='block',$policy=null) {
    if (!in_array($operation,['block','observe'],true)) {throw new RuntimeException('Invalid preparation operation');}
    $requestFile=$operation==='observe'?'observation-prepare-request':'trial-prepare-request';
    $p=da_trial_preparation($directory);
    if (!$p['available'] || $p['busy']) {throw new RuntimeException('Fresh preparation unavailable');}
    if(($p['capacity']['state']??null)==='exceeded'){throw new RuntimeException('DNS policy capacity review required before preparation');}
    $stamp=$status['updated_utc']??0;
    if (($status['state']??null)!=='running' || !is_numeric($stamp) || $now-$stamp>30 || $stamp>$now+2) {throw new RuntimeException('Active collector required');}
    if (!da_trial_owned_file($directory,'OWNER.json',2048)) {throw new RuntimeException('Owned data required');}
    $owner=json_decode(file_get_contents($directory.'/OWNER.json'),true,8,JSON_THROW_ON_ERROR);
    if (($owner['owner']??null)!=='dnsalias-observation-v1' || ($owner['root']??null)!==dirname(__DIR__)) {throw new RuntimeException('Owned data required');}
    $mask=umask(0077);
    try {
        $pending=$policy!==null?$directory.'/trial-prepare-pending':$directory.'/'.$requestFile;
        if($policy!==null&&$operation!=='block'){throw new RuntimeException('Named policy requires block preparation');}
        $stream=@fopen($pending,'x');
        if ($stream===false) {throw new RuntimeException('Preparation outcome unavailable');}
        if($policy!==null){$raw=json_encode($policy,JSON_THROW_ON_ERROR|JSON_UNESCAPED_SLASHES);if(strlen($raw)>4096||fwrite($stream,$raw)!==strlen($raw)||!fflush($stream)||(function_exists('fsync')&&!fsync($stream))){fclose($stream);throw new RuntimeException('Policy publication requires inspection');}}
        fclose($stream);
        if($policy!==null){if(!link($pending,$directory.'/'.$requestFile)){throw new RuntimeException('Policy queue outcome requires inspection');}if(!unlink($pending)){throw new RuntimeException('Policy publication requires inspection');}}
    } finally {umask($mask);}
    return da_trial_preparation($directory);
}
function da_preparation_render($p,$canControl,$active,$prefill=null) {
    if (!$p || !$p['available'] || $active) {return;}
    echo '<div class="da-panel" id="da-preparation-control" data-state="'.da_h($p['state']).'"><div class="da-panel-title"><h2>Alias policies</h2></div><p>'.da_h($p['profile']['client']).' · TCP '.da_h($p['profile']['port']).' · '.da_h(implode(', ',$p['profile']['names'])).'</p>';
    da_policy_capacity_render($p['capacity']??null);
    if(!empty($p['last_refused'])){
        $reason=($p['refusal_reason']??null)==='policy_capacity'
            ?'DNS policy data grew beyond the verified capacity. A local capacity check is required before retrying.'
            :'Check the alias name and current source/configuration, then review again.';
        echo '<p class="da-notice">The previous preparation was refused before any rule or DNS hook was changed. '.da_h($reason).'</p>';
    }
    if ($p['busy']) {
        echo '<p>'.($p['state']==='inspection_required'?'Preparation requires local inspection. No automatic retry.':'Preparing the preview. Refresh shortly to check its status.').'</p>';
    } elseif (($p['capacity']['state']??null)==='exceeded') {
        echo '<p class="da-notice">DNS policy data exceeds the reviewed size cap. Preparation is unavailable until a local capacity check updates the owned profile. No blocking has started.</p>';
    } elseif ($canControl) {
        $alias=$prefill['alias']??'example_sites';$names=$prefill['names']??['example.com'];$client=$prefill['client']??$p['profile']['client'];
        echo '<form method="post" action="dnsalias_status.php?view=aliases"><h3>Create an alias and block policy</h3><label>Source client IP <input name="policy_client" value="'.da_h($client).'" maxlength="45" required></label><p class="da-footnote">One exact LAN address. The helper verifies its current interface before the preview. Router, WAN and ambiguous sources are refused. IPv4 and IPv6 addresses are separate rule sources.</p><label>Alias name <input name="policy_alias" value="'.da_h($alias).'" maxlength="23" required></label><label>DNS names / patterns <textarea name="policy_names" maxlength="2048" rows="3" required>'.da_h(implode("\n",$names)).'</textarea></label><label>Port <select name="policy_port"><option value="web" selected>Web: TCP/UDP 80 and 443 (includes QUIC)</option><option value="80">TCP 80 only</option><option value="443">TCP 443 only</option></select></label><label>Automatic expiry <select name="policy_seconds"><option value="60">1 minute</option><option value="300">5 minutes</option><option value="900" selected>15 minutes</option><option value="3600">1 hour</option></select></label><button class="da-primary" name="trial_op" value="prepare_policy" type="submit">Review alias and blocking</button><p class="da-footnote">One active policy at a time in this MVP. Up to eight exact names or *.example.com patterns. Shared CDN IPs can affect other names. Uses ordinary source/port firewall matching; no exact HTTPS hostname inspection.</p></form>';
        echo '<form method="post" action="dnsalias_status.php?view=aliases"><button class="da-primary" name="trial_op" value="prepare" type="submit">Prepare test</button> <button name="trial_op" value="prepare_observation" type="submit">Prepare DNS observation</button></form><p class="da-footnote">Checks the approved scope and current router state. Preparation does not block traffic; review the preview and press Start separately. DNS observation collects replies from all observed clients and attaches no traffic rule.</p>';
    } else {echo '<p class="da-footnote">Firewall rule editing privilege is required to prepare a test.</p>';}
    echo '<a href="dnsalias_status.php?view=aliases">Refresh test status</a></div>';
}
