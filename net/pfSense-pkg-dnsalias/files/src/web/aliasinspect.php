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
function da_alias_check_pattern($pattern): void {
    if(!is_string($pattern)||strlen($pattern)>255||!preg_match('/^(?:\*\.)?[a-z0-9_-]+(?:\.[a-z0-9_-]+)*$/D',$pattern))
        throw new InvalidArgumentException('Invalid saved DNS pattern');
}
function da_alias_report_patterns(array $patterns): array {
    if(count($patterns)<128||count($patterns)>2048||!array_is_list($patterns))return $patterns;
    $wildcards=[];
    foreach($patterns as $pattern){
        da_alias_check_pattern($pattern);
        if(str_starts_with($pattern,'*.'))$wildcards[substr($pattern,1)]=true;
    }
    if(!$wildcards)return $patterns;
    // An ancestor wildcard covers every strict subdomain, including another
    // wildcard below it. An exact apex remains independently matchable.
    $kept=[];
    foreach($patterns as $pattern){
        $base=str_starts_with($pattern,'*.')?substr($pattern,2):$pattern;
        for($dot=strpos($base,'.');$dot!==false;$dot=strpos($base,'.',$dot+1)){
            if(isset($wildcards[substr($base,$dot)]))continue 2;
        }
        $kept[]=$pattern;
    }
    return $kept;
}
function da_alias_pattern_sql(array $patterns,string $field,array &$params): string {
    if(!in_array($field,['domain','query'],true)||!array_is_list($patterns)||count($patterns)<1||count($patterns)>2048)
        throw new InvalidArgumentException('Bounded saved DNS patterns required');
    $exact=[];$suffixes=[];
    foreach($patterns as $pattern){
        da_alias_check_pattern($pattern);
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
// For long pattern lists, match each distinct recorded domain at most once.
// Bound both the name count and the memory used for this per-request projection.
function da_alias_observed_matches(SQLite3 $db,array $patterns,string $dns_scope,array $window): ?string {
    $recent=false;
    if(isset($window[':since'],$window[':until']) &&
        $db->querySingle("SELECT 1 FROM sqlite_master WHERE type='index' AND name='event_time'")){
        $recent=!da_rows($db,"SELECT 1 FROM events WHERE time BETWEEN :since AND :until LIMIT 1 OFFSET 1024",$window);
    }
    $range=$recent?' AND time BETWEEN :since AND :until':'';
    $sql="WITH sampled AS (
        SELECT DISTINCT domain FROM events WHERE $dns_scope AND domain IS NOT NULL $range LIMIT 8193
    ), observed AS MATERIALIZED (
        SELECT CASE WHEN typeof(domain)='text' AND length(CAST(domain AS BLOB))<=253 THEN domain END AS name FROM sampled
    ) SELECT CASE WHEN count(*)<=8192 AND count(*)=count(name)
        AND coalesce(sum(length(CAST(name AS BLOB))),0)<=1048576
        THEN (SELECT json_group_array(name) FROM observed) END AS names FROM observed";
    $serialized=da_rows($db,$sql,$recent?$window:[])[0]['names'];
    if($serialized===null)return null;
    $names=json_decode($serialized,true);
    if(!is_array($names))return null;
    $exact=[];$suffix=[];
    foreach($patterns as $pattern){
        if(str_starts_with($pattern,'*.'))$suffix[substr($pattern,1)]=true;
        else $exact[$pattern]=true;
    }
    $matches=[];
    foreach($names as $name){
        // Older or malformed rows keep the original SQLite comparison semantics.
        if(!is_string($name)||strlen($name)>253 || !preg_match('/^[a-z0-9_-]+(?:\.[a-z0-9_-]+)*$/D',$name))return null;
        if(isset($exact[$name])){$matches[]=$name;continue;}
        for($dot=strpos($name,'.');$dot!==false;$dot=strpos($name,'.',$dot+1)){
            if(isset($suffix[substr($name,$dot)])){$matches[]=$name;break;}
        }
    }
    return json_encode($matches,JSON_THROW_ON_ERROR);
}

function da_alias_domain_filter(SQLite3 $db,array $patterns,string $dns_scope,array &$params): string {
    $bindings=[];
    $predicate=da_alias_pattern_sql($patterns,'domain',$bindings);
    foreach($patterns as $pattern){
        if(!str_starts_with($pattern,'*.'))continue;
        // Check each retained name once when the covering index yields a small set.
        // A large history or an older schema keeps the ordinary event query.
        if(SQLite3::version()['versionNumber']>=3035000 &&
            $db->querySingle("SELECT 1 FROM sqlite_master WHERE type='index' AND name='event_domain_evidence'")){
            if(count($patterns)>=128){
                $names=da_alias_observed_matches($db,$patterns,$dns_scope,$params);
                if($names!==null){
                    $params[':observed_domains']=$names;
                    return 'domain IN (SELECT value FROM json_each(:observed_domains))';
                }
                $params+=$bindings;
                return $predicate;
            }
            $sql="WITH observed AS MATERIALIZED (
                SELECT DISTINCT domain FROM events WHERE $dns_scope AND domain IS NOT NULL LIMIT 513
            ) SELECT CASE WHEN count(*)<=512 AND coalesce(sum(length(CAST(domain AS BLOB))),0)<=131072
                THEN (SELECT json_group_array(domain) FROM observed WHERE $predicate) END AS names FROM observed";
            $names=da_rows($db,$sql,$bindings)[0]['names'];
            if($names!==null){
                $params[':observed_domains']=$names;
                return 'domain IN (SELECT value FROM json_each(:observed_domains))';
            }
        }
        break;
    }
    $params+=$bindings;
    return $predicate;
}
function da_alias_packet_counts(SQLite3 $db,string $list,array $params): array {
    $select="SELECT json_extract(body,'$.destination') AS ip,sum(action='pass') AS pass,
        sum(action='block') AS block,count(*) AS n FROM events WHERE kind='firewall_packet'
        AND time>=:since AND time<=:until AND json_extract(body,'$.destination') IN ($list)";
    if(!$db->querySingle("SELECT 1 FROM sqlite_master WHERE type='index' AND name='event_packet_nonweb_counts'"))
        return da_rows($db,$select.' GROUP BY ip',$params);
    // The web index covers TCP/UDP 80 and 443. The complementary index includes
    // every other logged port/protocol, including records with an unknown value.
    $web="json_extract(body,'$.destination_port') IN (80,443) AND json_extract(body,'$.protocol') IN ('tcp','udp')";
    $other="($web) IS NOT 1 AND json_type(body,'$.destination')='text'
        AND length(CAST(json_extract(body,'$.destination') AS BLOB)) BETWEEN 2 AND 45";
    return da_rows($db,"SELECT ip,sum(pass) AS pass,sum(block) AS block,sum(n) AS n FROM (
        $select AND $web GROUP BY ip UNION ALL $select AND $other GROUP BY ip
    ) GROUP BY ip",$params);
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
        $file_bytes=da_history_file_size($path);
        $db=new SQLite3($path,SQLITE3_OPEN_READONLY);$db->enableExceptions(true);$db->busyTimeout(250);
        da_check_large_history($db,$file_bytes);
        $patterns=da_alias_report_patterns($policy['names']);
        // Retention may run between name discovery and the domain totals.
        $db->exec('BEGIN');
        $params=[':since'=>$now-$v['window']*60,':until'=>$now];
        $dns_scope="kind IN ('dns_query','dns_reply_log','dns_policy_log','dns_reply')";
        $where=da_alias_domain_filter($db,$patterns,$dns_scope,$params);
        // Match the EventStore partial index predicate so exact names can seek by domain and time.
        $v['domains']=da_rows($db,"SELECT domain,sum(kind='dns_query') AS queries,sum(kind='dns_reply') AS replies,sum(kind='dns_reply_log') AS reply_logs,sum(kind='dns_policy_log') AS policy_logs,max(time) AS latest FROM events WHERE $dns_scope AND time>=:since AND time<=:until AND $where GROUP BY domain ORDER BY replies DESC,queries DESC,domain LIMIT 101",$params);
        $db->exec('COMMIT');
        $v['statistics_available']=true;
        if($v['members']){
            $slots=[];$ips=[':since'=>$params[':since'],':until'=>$now];
            foreach($v['members'] as $i=>$ip){$slot=':ip'.$i;$slots[]=$slot;$ips[$slot]=$ip;}
            $list=implode(',',$slots);
            foreach(da_alias_packet_counts($db,$list,$ips) as $r)$v['packets'][$r['ip']]=$r;
            $v['answer_history_available']=(int)$db->querySingle("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='reply_answers'")===1;
            if($v['answer_history_available']){
                $matching=da_alias_pattern_sql($patterns,'query',$ips);
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
function da_alias_members_render(?array $v,bool $can=false,bool $show_names=false): void {
    $window=$v['window']??60;
    echo '<p class="da-alias-back"><a href="dnsalias_status.php?view=aliases&amp;window='.da_h($window).'">← Back to DNS aliases</a></p><div class="da-panel" id="da-alias-members">';
    if($v===null){echo '<h2>DNS alias not found</h2></div>';return;}
    echo '<div class="da-panel-title"><div><h2>Destinations for '.da_h($v['table']).'</h2><p>All observed clients · last '.da_h($v['window']).' minutes · '.($v['current']?'current PF members':'recorded addresses; current membership unknown').'</p></div>';
    if($can)echo '<a href="dnsalias_status.php?view=aliases&amp;window='.da_h($window).'&amp;edit_alias='.rawurlencode($v['policy']['name']).'#da-alias-editor">Edit alias ↗</a>';
    echo '</div>';
    if($v['error']!=='')echo '<p class="da-error">'.da_h($v['error']).'</p>';
    $names=$v['policy']['names'];
    $preview=count($names)>64&&!$show_names;
    echo '<details class="da-domain-aliases" id="da-saved-names"'.($show_names?' open':'').'><summary>Saved names and patterns · '.da_h(count($names)).'</summary><p>'.da_h(implode(', ',$preview?array_slice($names,0,16):$names)).'</p>';
    if($preview){
        $url='dnsalias_status.php?view=aliases&inspect_members='.rawurlencode($v['policy']['name']).'&window='.$window.'&show_names=1#da-saved-names';
        echo '<a href="'.da_h($url).'">Show all '.da_h(count($names)).' saved names and patterns</a>';
    }
    echo '</details>';
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
