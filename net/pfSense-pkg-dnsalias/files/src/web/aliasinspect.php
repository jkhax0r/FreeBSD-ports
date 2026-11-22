<?php
/* On-demand read-only alias evidence. No DNS queries, PF writes or actions. */
function da_alias_popup_payload(string $name,array $policies,array $service,int $now): array {
    if(!preg_match('/^[a-z][a-z0-9_]{0,22}$/D',$name))throw new InvalidArgumentException('Saved DNS alias required');
    $policy=null;foreach($policies as $p)if(($p['name']??null)===$name)$policy=$p;
    if($policy===null)throw new OutOfBoundsException('Saved DNS alias not found');
    $health=da_alias_health($service,(float)$now);$count=da_alias_live_count('da_'.$name,$service,$health);$members=[];
    if($count!==null)foreach(array_slice($service['tables']['da_'.$name]??[],0,100)as $ip)
        if(is_string($ip)&&filter_var($ip,FILTER_VALIDATE_IP))$members[da_ip_canonical($ip)]=true;
    return ['format'=>'dnsalias-popup-1','name'=>$name,'names'=>array_slice($policy['names'],0,16),'name_count'=>count($policy['names']),
        'state'=>da_alias_row_status($policy,$service,$health),'current'=>$count!==null,'member_count'=>$count,
        'members'=>array_slice(array_keys($members),0,32),'observed_utc'=>$count!==null?$service['membership_observed_utc']:null];
}
function da_alias_pattern_sql(array $patterns,string $field,array &$params): string {
    if(!in_array($field,['domain','query'],true)||!array_is_list($patterns)||count($patterns)<1||count($patterns)>2048)
        throw new InvalidArgumentException('Bounded saved DNS patterns required');
    $exact=[];$suffixes=[];
    foreach($patterns as $pattern){
        if(!is_string($pattern)||strlen($pattern)>255||!preg_match('/^(?:\*\.)?[a-z0-9_-]+(?:\.[a-z0-9_-]+)*$/D',$pattern))
            throw new InvalidArgumentException('Invalid saved DNS pattern');
        if(str_starts_with($pattern,'*.')){
            $suffix=substr($pattern,1);
            $suffixes[strlen($suffix)][]=$suffix;
        }else $exact[]=$pattern;
    }
    // SQLite builds an uncorrelated membership set once per suffix length.
    // JSON array bindings also bound the number of SQL variables for large lists.
    $membership=static function(string $column,string $slot,array $values)use(&$params):string{
        if(count($values)===1){$params[$slot]=$values[0];return "$column=$slot";}
        $params[$slot]=json_encode($values,JSON_THROW_ON_ERROR);
        return "$column IN (SELECT value FROM json_each($slot))";
    };
    $parts=[];
    if($exact)$parts[]=$membership($field,':pattern_exact',$exact);
    foreach($suffixes as $length=>$values){
        $test=$membership("substr($field,-$length)",':pattern_suffix_'.$length,$values);
        $parts[]="(length($field)>$length AND $test)";
    }
    return '('.implode(' OR ',$parts).')';
}
function da_alias_members_model(string $directory,array $policy,array $service,int $now,int $window): array {
    $table='da_'.$policy['name'];$health=da_alias_health($service,(float)$now);
    $v=['table'=>$table,'policy'=>$policy,'current'=>da_alias_live_count($table,$service,$health)!==null,
        'member_count'=>da_alias_live_count($table,$service,$health),'members'=>[],'domains'=>[],
        'answers'=>[],'packets'=>[],'statistics_available'=>false,'answer_history_available'=>false,
        'error'=>'','now'=>$now,'window'=>in_array($window,[15,60,1440],true)?$window:60];
    $members=$service['tables'][$table]??[];
    foreach(array_slice(is_array($members)?$members:[],0,100) as $ip)
        if(is_string($ip)&&filter_var($ip,FILTER_VALIDATE_IP))$v['members'][da_ip_canonical($ip)]=true;
    $v['members']=array_keys($v['members']);$db=null;
    try{
        $path=$directory.'/events.sqlite';
        if(is_link($path)||!is_file($path)||filesize($path)>67108864)throw new RuntimeException('Telemetry unavailable');
        $db=new SQLite3($path,SQLITE3_OPEN_READONLY);$db->enableExceptions(true);$db->busyTimeout(250);
        $params=[':since'=>$now-$v['window']*60,':until'=>$now];
        $where=da_alias_pattern_sql($policy['names'],'domain',$params);
        $v['domains']=da_rows($db,"SELECT domain,sum(kind='dns_query') AS queries,sum(kind='dns_reply') AS replies,sum(kind='dns_reply_log') AS reply_logs,sum(kind='dns_policy_log') AS policy_logs,max(time) AS latest FROM events WHERE kind IN ('dns_query','dns_reply','dns_reply_log','dns_policy_log') AND time>=:since AND time<=:until AND $where GROUP BY domain ORDER BY replies DESC,queries DESC,domain LIMIT 101",$params);
        $v['statistics_available']=true;
        if($v['members']){
            $slots=[];$ips=[':since'=>$params[':since'],':until'=>$now];
            foreach($v['members'] as $i=>$ip){$slot=':ip'.$i;$slots[]=$slot;$ips[$slot]=$ip;}
            $list=implode(',',$slots);
            foreach(da_rows($db,"SELECT json_extract(body,'$.destination') AS ip,sum(action='pass') AS pass,sum(action='block') AS block,count(*) AS n FROM events WHERE kind='firewall_packet' AND time>=:since AND time<=:until AND json_extract(body,'$.destination') IN ($list) GROUP BY ip",$ips) as $r)$v['packets'][$r['ip']]=$r;
            $v['answer_history_available']=(int)$db->querySingle("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='reply_answers'")===1;
            if($v['answer_history_available']){
                $matching=da_alias_pattern_sql($policy['names'],'query',$ips);
                $v['answers']=da_rows($db,"SELECT query,value,count(*) AS records,max(time) AS latest,max(expires_utc) AS expiry FROM reply_answers WHERE rrtype IN ('A','AAAA') AND time>=:since AND time<=:until AND value IN ($list) AND $matching GROUP BY query,value ORDER BY latest DESC,query,value LIMIT 501",$ips);
            }
        }
    }catch(Throwable $e){
        // Never turn a failed or partial query into zero observed traffic.
        $v['statistics_available']=false;$v['domains']=[];$v['packets']=[];$v['answers']=[];
        $v['error']='Statistics unavailable. Current membership and saved names are shown separately.';
    }finally{if($db!==null)$db->close();}
    return $v;
}
function da_alias_preview(array $policy,int $window=60): void {
    $window=in_array($window,[15,60,1440],true)?$window:60;
    $table='da_'.$policy['name'];$url='dnsalias_status.php?view=aliases&window='.$window.'&inspect_members='.rawurlencode($policy['name']).'#da-alias-members';
    $id='da-preview-'.$policy['name'];$shown=array_slice($policy['names'],0,12);
    echo '<span class="da-alias-preview"><a href="'.da_h($url).'" aria-describedby="'.da_h($id).'"><strong>'.da_h($table).'</strong></a><span class="da-alias-tooltip" role="tooltip" id="'.da_h($id).'"><b>DNS names and patterns</b>';
    foreach($shown as $name)echo '<span>'.da_h($name).'</span>';
    if(count($policy['names'])>count($shown))echo '<small>+'.da_h(count($policy['names'])-count($shown)).' more</small>';
    echo '<small>Click the alias for IPs and observed counts.</small></span></span>';
}
function da_alias_members_render(?array $v,bool $can=false): void {
    $window=$v['window']??60;
    echo '<p class="da-alias-back"><a href="dnsalias_status.php?view=aliases&amp;window='.da_h($window).'">← Back to DNS aliases</a></p><div class="da-panel" id="da-alias-members">';
    if($v===null){echo '<h2>DNS alias not found</h2></div>';return;}
    echo '<div class="da-panel-title"><div><h2>Destinations for '.da_h($v['table']).'</h2><p>All observed clients · last '.da_h($v['window']).' minutes · '.($v['current']?'current PF members':'recorded addresses; current membership unknown').'</p></div>';
    if($can)echo '<a href="dnsalias_status.php?view=aliases&amp;window='.da_h($window).'&amp;edit_alias='.rawurlencode($v['policy']['name']).'#da-alias-editor">Edit alias ↗</a>';
    echo '</div>';
    if($v['error']!=='')echo '<p class="da-error">'.da_h($v['error']).'</p>';
    echo '<details class="da-domain-aliases"><summary>Saved names and patterns · '.da_h(count($v['policy']['names'])).'</summary><p>'.da_h(implode(', ',$v['policy']['names'])).'</p></details>';
    $by=[];foreach(array_slice($v['answers'],0,500) as $r)$by[$r['value']][]=$r;
    $rows=[];
    foreach($v['members'] as $ip){
        $answers=$by[$ip]??[];$names=[];
        foreach(array_slice($answers,0,8) as $r)$names[]=$r['query'];
        $count=$v['statistics_available']?($v['packets'][$ip]??['pass'=>0,'block'=>0]):[];
        $rows[]=[['text'=>$ip,'url'=>'dnsalias_status.php?view=ip&destination='.rawurlencode($ip).'&window='.$window],
            ['text'=>$names?implode(', ',$names):'No matching answer evidence retained','hint'=>implode("\n",array_map(fn($r)=>$r['query'].' · '.$r['records'].' answer records · recorded RR expiry '.da_when($r['expiry']),array_slice($answers,0,8)))],
            da_num($count['pass']??null),da_num($count['block']??null)];
    }
    da_table(['Address','Recent matching DNS names','Logged pass packets','Logged block packets'],$rows,'da-alias-members-table');
    echo '<p class="da-footnote">Up to100 addresses and500 name/address evidence groups shown. '.($v['member_count']!==null?'The current table contains '.da_h($v['member_count']).' addresses. ':''). 'Hover a name for recorded answer counts and RR expiry; this history is not the current CNAME-chain lease. Select an IP for individual packet and DNS evidence. Packet counts cover all collected ports to that IP, including other rules and shared domains; they are not alias hits, visits or connections.</p>';
    $rows=[];foreach(array_slice($v['domains'],0,100) as $r)$rows[]=[['text'=>$r['domain'],'url'=>'dnsalias_status.php?view=domain&domain='.rawurlencode($r['domain']).'&window='.$window],da_num($r['queries']),da_num($r['replies']),da_num($r['reply_logs']),da_num($r['policy_logs'])];
    echo '<h3>Observed domains matching the saved patterns</h3>';
    if($v['statistics_available'])da_table(['Domain','Query logs','Resolver replies','Reply logs','DNSBL policy logs'],$rows);
    else echo '<p class="da-footnote">Domain counts unavailable.</p>';
    echo '<p class="da-footnote">These are retained observations in the selected time window, matched against today’s saved patterns. Sources can overlap and logging may have gaps; missing records do not mean no traffic. Wildcards match observed subdomains, not their base name. No DNS lookup is made when this view opens.</p></div>';
}
