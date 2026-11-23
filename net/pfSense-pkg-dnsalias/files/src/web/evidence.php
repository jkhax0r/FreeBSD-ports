<?php
/* Presentation of incomplete log evidence, including records collected before
 * the parser learned these distinctions. Never a policy or lease input. */
function da_identity_snapshot($directory) {
    $path=$directory.'/status.json';
    if(is_link($path)||!is_file($path)||filesize($path)>4194304){return [];}
    $value=json_decode(file_get_contents($path),true,64);
    return is_array($value)?$value:[];
}
function da_queue_identity($directory,$status,$now) {
    $stamp=$status['client_identity']['observed_utc']??0;
    if(is_numeric($stamp) && $stamp<=$now+2 && $now-$stamp<60){return false;}
    $updated=$status['updated_utc']??0;
    if(($status['state']??'')!=='running' || !is_numeric($updated) || $now-$updated>30 || $updated>$now+2){return false;}
    // This path is fixed by the authenticated native page, never URL input.
    // A single empty owned marker coalesces every tab's request. No commands.
    if(is_link($directory)||!is_dir($directory)||fileowner($directory)!==fileowner(__FILE__) || (fileperms($directory)&0777)!==0700){return false;}
    $marker=$directory.'/OWNER.json';
    if(is_link($marker)||!is_file($marker)||filesize($marker)>2048){return false;}
    $owner=json_decode(file_get_contents($marker),true);
    if(($owner['owner']??'')!=='dnsalias-observation-v1' || ($owner['root']??'')!==dirname(__DIR__)){return false;}
    $path=$directory.'/identity-request';
    if(file_exists($path)||is_link($path)){return !is_link($path)&&is_file($path)&&filesize($path)===0&&fileowner($path)===fileowner(__FILE__)&&(fileperms($path)&0777)===0600;}
    $mask=umask(0077);
    try{$file=@fopen($path,'x');if($file===false){return false;}fclose($file);return true;}
    finally{umask($mask);}
}
function da_identity_payload($status,$now,?string $selected=null) {
    $v=['now'=>$now,'status'=>$status];$clients=[];
    $observed=array_slice($status['client_identity']['clients']??[],0,512,true);
    if($selected!==null)$observed=array_intersect_key($observed,[$selected=>true]);
    foreach($observed as $client=>$unused){
        if(filter_var($client,FILTER_VALIDATE_IP)){$claims=da_client_claims($v,$client);if($claims){$clients[$client]=$claims;}}
    }
    $payload=['format'=>'dnsalias-client-names-1','observed_utc'=>$status['client_identity']['observed_utc']??0,'clients'=>(object)$clients,'at_capacity'=>$status['client_identity']['at_capacity']??false];
    if($selected!==null)$payload['client']=$selected;
    return $payload;
}
function da_loopback($client) {
    $b=@inet_pton($client);
    return $b!==false && ((strlen($b)===4 && ord($b[0])===127) ||
        $b===inet_pton('::1') || (strlen($b)===16 && substr($b,0,12)===hex2bin('00000000000000000000ffff') && ord($b[12])===127));
}
function da_logged_answer($b) {
    $answer=$b['logged_answer']??'Not recorded';
    if (!is_string($answer)) { return 'Not recorded'; }
    if (!filter_var($answer,FILTER_VALIDATE_IP) && (in_array(strtoupper($b['qtype']??''),['HTTPS','SVCB','TYPE64','TYPE65','64','65'],true) || in_array(strtoupper($b['reported_answer_type']??''),['HTTPS','SVCB','TYPE64','TYPE65','64','65'],true))) {
        return 'Service parameters unavailable in text log';
    }
    return $answer;
}
function da_client_name_attributes(string $ip): string {
    return 'data-client-ip="'.da_h($ip).'"'.(da_loopback($ip)?' data-client-loopback':'');
}
function da_client_basis($r) {
    if (!da_loopback($r['client']??'')) { return 'Logged source address; original device may be hidden by forwarding/NAT'; }
    if ($r['kind']==='dns_query') { return 'Verified loopback peer on this router; originating process or forwarded client is not recorded'; }
    if (in_array($r['kind'],['dns_reply_log','dns_policy_log'],true) && $r['client']==='127.0.0.1') { return 'Loopback or unavailable client: pfBlockerNG uses 127.0.0.1 for both; origin cannot be recovered from this record'; }
    return 'Loopback source on this router; originating process or forwarded client is not recorded';
}
function da_client_label($v,$client) {
    if (da_loopback($client)) { return $client.' · router loopback / unknown origin'; }
    $names=da_client_claims($v,$client);
    if (!$names) { return $client; }
    $name=$names[0];
    $interface=$name['source']==='Router interface' && !empty($name['interface'])?' · '.$name['interface']:'';
    return $name['name'].$interface.' · '.$client;
}
function da_client_claims($v,$client) {
    $snapshot=$v['status']['client_identity']??[];
    $stamp=$snapshot['observed_utc']??0;
    if (!is_numeric($stamp) || $v['now']-$stamp>180 || $stamp>$v['now']+2) { return []; }
    $claims=$snapshot['clients'][$client]??[];
    if (!is_array($claims)) { return []; }
    $claims=array_values(array_filter(array_slice($claims,0,6),fn($r)=>is_array($r) && is_string($r['name']??null) && is_string($r['source']??null) && (!isset($r['expires']) || (is_numeric($r['expires']) && $r['expires']>$v['now']))));
    $priority=['DHCP reservation'=>0,'Active DHCP lease (Kea)'=>1,'DNS host override'=>2,'DNS override alias'=>3,'Router interface'=>4,'Reservation label'=>5,'Firewall host alias'=>6];
    usort($claims,fn($a,$b)=>(($priority[$a['source']]??9)<=>($priority[$b['source']]??9)) ?: (($a['alias_members']??0)<=>($b['alias_members']??0)) ?: strcmp($a['name'],$b['name']));
    return $claims;
}
function da_client_identity_render($v,$client) {
    $claims=da_client_claims($v,$client);$rows=[];
    echo '<div data-client-claims>';
    foreach($claims as $r) { $rows[]=[$r['name'],$r['source'].(isset($r['alias_members'])?' · '.da_number($r['alias_members']).' configured entries':''),$r['interface']??'',$r['mac']??'',isset($r['expires'])?da_time($r['expires']):'Configured']; }
    if ($rows) { da_table(['Name / label','Source','Interface','MAC','Lease expiry'],$rows,'da-identity-table'); }
    else { echo '<p class="da-footnote">'.da_h(da_loopback($client)?'Router loopback / unknown origin. Query records prove a loopback peer; pfBlockerNG reply logs may also use this address when the client is unavailable.':'No recent local name metadata available for this address.').'</p>'; }
    if($rows){echo '<p class="da-footnote">Current local metadata; DHCP names are client supplied and firewall aliases can group multiple devices. Address reuse or forwarding can change the device behind historical events. No automatic reverse-DNS requests.</p>';}
    if(array_filter($claims,fn($r)=>$r['source']==='Router interface')) { echo '<p class="da-footnote"><strong>Router interface address.</strong> Outbound logs can show translated traffic from other devices. This source alone does not identify the original LAN client or prove that pfSense generated the traffic.</p>'; }
    if(($v['status']['client_identity']['at_capacity']??false)===true){echo '<p class="da-footnote">Name metadata reached a collection limit; some labels may be absent.</p>';}
    echo '</div>';
    if($client==='127.0.0.1') { echo '<p class="da-footnote"><strong>'.da_h(da_number($v['counts']['dns']??0)).' query records with a verified loopback peer</strong> · '.da_h(da_number(($v['dns_outcomes']['replies']??0)+($v['dns_outcomes']['dnsbl']??0))).' pfBlockerNG reply/policy records with ambiguous origin. These sources can overlap; the originating process is not logged.</p>'; }
}
