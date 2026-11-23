<?php
/* Display context only: bounded indexed history, never policy or DNS queries. */
function da_destination_grouping($sqlite_version) {
    // Older libraries keep the equivalent existing query. This hint prevents
    // validation from being pushed into each source record and repeating its
    // normalization, while retaining every grouped name and client timestamp.
    return is_int($sqlite_version) && $sqlite_version>=3035000?' MATERIALIZED':'';
}
function da_destination_load($db, &$v) {
    $v['destination_names']=[];$ips=[];
    foreach (['destinations','blocks','traffic','client_events'] as $key) {
        foreach ($v[$key]??[] as $r) {
            if (isset($r['kind']) && $r['kind']!=='firewall_packet') { continue; }
            $b=isset($r['body'])?json_decode($r['body'],true):$r;
            $ip=$b['destination']??'';
            if (!is_string($ip) || !filter_var($ip,FILTER_VALIDATE_IP) || da_loopback($ip) || in_array($ip,['0.0.0.0','::'],true)) { continue; }
            $ips[$ip]=true;
        }
    }
    if (!$ips) { return; }
    // Two visible lists can contain 100 different destinations each. No work
    // for other views; all visible addresses share this one read query.
    $ips=array_slice(array_keys($ips),0,200);$slots=[];
    $until=(int)($v['asof']?:$v['now']);
    $params=[':since'=>$until-$v['window']*60,':until'=>$until,':client'=>$v['client']];
    foreach ($ips as $i=>$ip) { $slots[]=':ip'.$i;$params[':ip'.$i]=$ip; }
    $list=implode(',',$slots);
    $source="SELECT json_extract(body,'$.logged_answer') AS ip,domain AS name,time,client FROM events WHERE kind='dns_reply_log' AND json_extract(body,'$.logged_answer') IN ($list) AND time>=:since AND time<=:until";
    if ((bool)da_rows($db,"SELECT 1 FROM sqlite_master WHERE type='table' AND name='reply_answers'",[])) {
        $source.=" UNION ALL SELECT value AS ip,query AS name,time,client FROM reply_answers WHERE value IN ($list) AND rrtype IN ('A','AAAA') AND time>=:since AND time<=:until";
    }
    $valid="length(name) BETWEEN 1 AND 253 AND name NOT GLOB '*[^a-z0-9_.-]*' AND substr(name,1,1) GLOB '[a-z0-9_]' AND substr(name,-1,1) GLOB '[a-z0-9_]'";
    $grouping=da_destination_grouping(SQLite3::version()['versionNumber']??null);
    $sql="WITH grouped AS$grouping (SELECT ip,lower(rtrim(name,'.')) AS name,max(time) AS latest,max(CASE WHEN client=:client AND :client<>'' THEN time END) AS client_latest FROM ($source) GROUP BY ip,lower(rtrim(name,'.'))), ranked AS (SELECT *,row_number() OVER (PARTITION BY ip ORDER BY latest DESC,name) AS rank FROM grouped WHERE $valid) SELECT * FROM ranked WHERE rank<=9 ORDER BY ip,rank";
    foreach (da_rows($db,$sql,$params) as $r) {
        $name=$r['name'];
        if (!is_string($name) || strlen($name)>253 || !preg_match('/^[a-z0-9_](?:[a-z0-9_.-]{0,251}[a-z0-9_])?$/D',$name) || filter_var($name,FILTER_VALIDATE_IP)) { continue; }
        $v['destination_names'][$r['ip']][]=$r;
    }
}
function da_destination($v,$ip,$port=null) {
    $label=$ip;
    if ($port!==null) { $label=(str_contains($ip,':')?'['.$ip.']':$ip).':'.$port; }
    $cell=da_link($v,$label,['destination'=>$ip,'view'=>'ip']);
    $names=$v['destination_names'][$ip]??[];
    if (!$names) { return $cell+['destination_context'=>[]]; }
    $details=[];
    foreach (array_slice($names,0,8) as $r) {
        $scope=$v['client']===''?'all observed clients':($r['client_latest']!==null?'also seen for this client':'other observed clients');
        $details[]=da_link($v,$r['name'],['domain'=>$r['name']])+['latest'=>$r['latest'],'scope'=>$scope];
    }
    return $cell+['destination_context'=>$details,'names_more'=>count($names)>8];
}
function da_destination_render($cell) {
    $names=$cell['destination_context'];
    echo '<div class="da-destination">';
    if ($names) { echo '<a class="da-destination-name" href="'.da_h($names[0]['url']).'">'.da_h($names[0]['text']).'</a>'; }
    echo '<a class="da-destination-ip" href="'.da_h($cell['url']).'">'.da_h($cell['text']).'</a>';
    if ($names) {
        $title=implode("\n",array_map(fn($r)=>$r['text'].' · '.da_when($r['latest']).' · '.$r['scope'],$names));
        $count=count($names).(!empty($cell['names_more'])?'+':'');
        echo '<details class="da-destination-history"><summary title="'.da_h($title).'">Recent DNS · ('.$count.' '.(count($names)===1?'name':'names').') · '.da_h($names[0]['scope']).'</summary><div>';
        foreach ($names as $r) { echo '<p><a href="'.da_h($r['url']).'">'.da_h($r['text']).'</a><br><small>'.da_h(da_when($r['latest']).' · '.$r['scope']).'</small></p>'; }
        echo '<p class="da-footnote">Latest names in the selected window, possibly after this packet. DNS context, not the HTTPS hostname used or a current TTL lease.'.(!empty($cell['names_more'])?' Showing the newest 8 names; inspect the IP for more.':'').'</p></div></details>';
    } else { echo '<small class="da-muted">No recent DNS name recorded</small>'; }
    echo '</div>';
}
