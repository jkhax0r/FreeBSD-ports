<?php
/* Presentation and bounded SQLite reads only. No commands or configuration IO. */
function da_h($value) {
    return htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}
// A single-quoted attribute lets JSON retain its structural double quotes.
// Escape HTML metacharacters and encode apostrophes inside JSON strings.
function da_json_attr($value): string {
    $json=json_encode($value, JSON_HEX_APOS | JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR);
    return "'" . htmlspecialchars($json, ENT_NOQUOTES | ENT_SUBSTITUTE, 'UTF-8') . "'";
}
function da_ip_canonical(string $value): string {
    // Match the packaged Python3.11 collectors' text. Native inet_ntop can
    // retain a dotted IPv4 tail in IPv6; that spelling misses exact SQL keys.
    // Preserve address families and the producer's IPv4-mapped mixed notation.
    if(strlen($value)>45||!filter_var($value,FILTER_VALIDATE_IP))throw new InvalidArgumentException('Numeric IP address required');
    $packed=inet_pton($value);
    if(strlen($packed)===4)return inet_ntop($packed);
    if(strlen($packed)!==16)throw new InvalidArgumentException('Numeric IP address required');
    if(substr($packed,0,12)===(str_repeat("\0",10)."\xff\xff"))return '::ffff:'.inet_ntop(substr($packed,12));
    $words=array_values(unpack('n8',$packed));$parts=array_map('dechex',$words);
    $bestStart=-1;$bestLength=0;$start=-1;
    for($i=0;$i<=8;$i++){
        if($i<8&&$words[$i]===0){if($start<0)$start=$i;}
        elseif($start>=0){
            $length=$i-$start;
            if($length>$bestLength){$bestStart=$start;$bestLength=$length;}
            $start=-1;
        }
    }
    if($bestLength<2)return implode(':',$parts);
    return implode(':',array_slice($parts,0,$bestStart)).'::'.implode(':',array_slice($parts,$bestStart+$bestLength));
}
function da_when($value) {
    return is_numeric($value) ? gmdate('Y-m-d H:i:s', (int)$value) . ' UTC' : 'Unknown';
}
function da_number($value) {
    return is_numeric($value) ? number_format((float)$value, 0) : 'Unknown';
}
function da_rows($db, $sql, $values) {
    $stmt = $db->prepare($sql);
    if (!$stmt) { throw new RuntimeException('Query unavailable'); }
    foreach ($values as $key => $value) {
        $stmt->bindValue($key, $value, is_int($value) ? SQLITE3_INTEGER : SQLITE3_TEXT);
    }
    $result = $stmt->execute();
    if (!$result) { throw new RuntimeException('Query unavailable'); }
    $rows = [];
    while ($row = $result->fetchArray(SQLITE3_ASSOC)) { $rows[] = $row; }
    $result->finalize();
    $stmt->close();
    return $rows;
}
function da_load($directory, $query, $now) {
    $v = ['now'=>$now, 'status'=>[], 'errors'=>[], 'dns'=>[], 'dns_top'=>[], 'traffic'=>[], 'flows'=>[], 'counts'=>[], 'rules'=>[], 'hourly'=>[], 'hourly_ready'=>false, 'hourly_coverage'=>[], 'clients'=>[], 'domains'=>[], 'destinations'=>[], 'blocks'=>[], 'client_events'=>[], 'next_cursor'=>null, 'feed'=>'all', 'before'=>'', 'asof'=>''];
    $v['data_directory']=$directory;
    $v['labels']=['available'=>true,'exists'=>false,'labels'=>[],'tags'=>[]];$v['labels_joined']=false;$v['labels_error']='';
    $v+=['review'=>'','tag'=>'','hide_tag'=>''];
    try{$v=array_replace($v,da_labels_query($query));}catch(InvalidArgumentException $e){$v['errors'][]=$e->getMessage();}
    $window = is_string($query['window'] ?? null) ? $query['window'] : '60';
    $v['window'] = in_array($window, ['15','60','1440'], true) ? (int)$window : 60;
    // An omitted choice keeps existing Client inspect links at 100 events.
    $v['rows'] = in_array($query['rows'] ?? null, ['25','50','100'], true) ? $query['rows'] : '';
    $v['client'] = is_string($query['client'] ?? null) ? trim($query['client']) : '';
    $v['domain'] = is_string($query['domain'] ?? null) ? strtolower(trim($query['domain'])) : '';
    $v['tracker'] = is_string($query['tracker'] ?? null) ? trim($query['tracker']) : '';
    $v['destination'] = is_string($query['destination'] ?? null) ? trim($query['destination']) : '';
    $v['action'] = is_string($query['action'] ?? null) && in_array($query['action'], ['pass','block'], true) ? $query['action'] : '';
    $v['view'] = is_string($query['view'] ?? null) && in_array($query['view'], ['overview','clients','client','domains','domain','ip','activity','blocks','rules','aliases','coverage'], true) ? $query['view'] : 'overview';
    if (in_array($v['view'],['domain','ip'],true)) { $v['tracker']='';$v['action']=''; }
    if ($v['view']==='ip') { $v['client']=''; }
    if ($v['view']==='domain' && $v['domain']!=='.') { $v['domain']=rtrim($v['domain'],'.'); }
    if ($v['client'] !== '' && !filter_var($v['client'], FILTER_VALIDATE_IP)) { $v['errors'][]='Client/source must be an IP address.'; }
    if (strlen($v['domain']) > 253 || preg_match('/[\x00-\x1f\x7f]/', $v['domain'])) { $v['errors'][]='Domain filter is invalid.'; }
    if ($v['tracker'] !== '' && !preg_match('/^[0-9]{1,20}$/D', $v['tracker'])) { $v['errors'][]='Tracker must be numeric.'; }
    if ($v['destination'] !== '' && !filter_var($v['destination'], FILTER_VALIDATE_IP)) { $v['errors'][]='Destination must be an IP address.'; }
    if (!$v['errors']) {
        foreach(['client','destination'] as $field)if($v[$field]!=='')$v[$field]=da_ip_canonical($v[$field]);
        if($v['view']==='ip'&&$v['destination']!=='')$v['domain']='';
    }
    $path = $directory . '/status.json';
    if (!is_link($path) && is_file($path) && filesize($path) <= 4194304) {
        $parsed = json_decode(file_get_contents($path), true, 64);
        if (is_array($parsed)) { $v['status'] = $parsed; }
    }
    // PHP time() is whole seconds; the writer records fractional seconds.
    // Compare at the same resolution so a status from this second is not future.
    $updated=$v['status']['updated_utc']??null;
    $v['status_age']=is_numeric($updated)?$now-floor((float)$updated):null;
    $v['fresh'] = $v['status_age']!==null && $v['status_age']>=0 && $v['status_age']<30;
    $v['reply_health']=da_reply_health_read($directory,(float)$now);
    $v['rules'] = is_array($v['status']['rules'] ?? null) ? $v['status']['rules'] : [];
    $v['rule_labels'] = [];
    foreach ($v['rules'] as $rule) { if (!empty($rule['tracker'])) { $v['rule_labels'][(string)$rule['tracker']] = $rule['description'] ?? ''; } }
    if ($v['tracker'] !== '') { $v['rules'] = array_values(array_filter($v['rules'], fn($r) => ($r['tracker'] ?? '') === $v['tracker'])); }
    usort($v['rules'], fn($a, $b) => ($b['interval_delta']['bytes'] ?? 0) <=> ($a['interval_delta']['bytes'] ?? 0));
    $v['rules_total'] = count($v['rules']);
    $v['rules'] = array_slice($v['rules'], 0, 100);
    if ($v['errors']) { return $v; }
    // These views need only the status snapshot, never the traffic database.
    if (in_array($v['view'],['rules','aliases'],true)) { return $v; }
    $db = null;
    try {
        $path = $directory . '/events.sqlite';
        if (is_link($path) || !is_file($path) || filesize($path) > 67108864) { throw new RuntimeException('Telemetry unavailable'); }
        $db = new SQLite3($path, SQLITE3_OPEN_READONLY);
        $db->enableExceptions(true);
        $db->busyTimeout(250);
        if(in_array($v['view'],['overview','clients','client','domains','domain'],true)){
            try{
                if(da_labels_filter_active($v)&&in_array($v['view'],['overview','client','domains'],true))$v['labels_joined']=da_labels_attach($db,$directory);
            }catch(Throwable $e){$v['labels']['available']=false;$v['labels_error']='Domain labels are unavailable. Review/tag filters are not applied.';}
        }
        if (in_array($v['view'],['domain','ip'],true)) {
            $db->exec('BEGIN');da_inspect_load($db,$v,$query);$db->exec('COMMIT');da_labels_load_visible($v);return $v;
        }
        if ($v['view']==='client') {
            $db->exec('BEGIN');
            da_client_load($db,$v,$query);
            da_destination_load($db,$v);
            $db->exec('COMMIT');
            da_labels_load_visible($v);
            return $v;
        }
        // One read snapshot for the selected view's related aggregates.
        $db->exec('BEGIN');
        $where = 'time >= :since AND time <= :until';
        $params = [':since'=>(int)($now-$v['window']*60), ':until'=>(int)$now];
        if ($v['client'] !== '') { $where .= ' AND client = :client'; $params[':client'] = $v['client']; }
        $dnswhere = $where . " AND kind = 'dns_query'";
        $dnsparams = $params;
        if ($v['domain'] !== '') { $dnswhere .= ' AND instr(lower(domain), :domain) > 0'; $dnsparams[':domain'] = $v['domain']; }
        $webwhere = $where . " AND kind = 'firewall_packet' AND json_extract(body,'$.destination_port') IN (80,443) AND json_extract(body,'$.protocol') IN ('tcp','udp')";
        $webparams = $params;
        if ($v['tracker'] !== '') { $webwhere .= ' AND tracker = :tracker'; $webparams[':tracker'] = $v['tracker']; }
        if ($v['destination'] !== '') { $webwhere .= " AND json_extract(body,'$.destination') = :destination"; $webparams[':destination'] = $v['destination']; }
        if ($v['action'] !== '') { $webwhere .= ' AND action = :action'; $webparams[':action'] = $v['action']; }
        if ($v['view']==='domains') {
            $dnswhere.=da_labels_clause($v,$dnsparams);
            $v['dns'] = da_rows($db, 'SELECT time,client,domain,body FROM events WHERE '.$dnswhere.' ORDER BY time DESC,id DESC LIMIT 100', $dnsparams);
        }
        if (in_array($v['view'],['overview','domains'],true)) {
            $limit=$v['view']==='overview'?6:100;
            $rankWhere=$dnswhere;$rankParams=$dnsparams;
            if($v['view']==='overview')$rankWhere.=da_labels_clause($v,$rankParams);
            $v['domains'] = da_rows($db, 'SELECT domain,count(*) AS n,count(DISTINCT client) AS clients,max(time) AS latest FROM events WHERE '.$rankWhere.' GROUP BY domain ORDER BY n DESC,domain LIMIT '.$limit, $rankParams);
        }
        if (in_array($v['view'],['overview','clients'],true)) {
        $clientRows = []; $v['counts']['dns']=0;
        foreach (da_rows($db, 'SELECT client,count(*) AS dns,max(time) AS latest FROM events WHERE '.$dnswhere.' GROUP BY client', $dnsparams) as $r) {
            $clientRows[$r['client']] = ['client'=>$r['client'],'dns'=>$r['dns'],'pass'=>0,'block'=>0,'latest'=>$r['latest']];
            $v['counts']['dns']+=$r['dns'];
        }
        foreach (da_rows($db, 'SELECT client,action,count(*) AS n,max(time) AS latest FROM events WHERE '.$webwhere." AND action IN ('pass','block') GROUP BY client,action", $webparams) as $r) {
            if (!isset($clientRows[$r['client']])) { $clientRows[$r['client']] = ['client'=>$r['client'],'dns'=>0,'pass'=>0,'block'=>0,'latest'=>$r['latest']]; }
            $clientRows[$r['client']][$r['action']] = $r['n'];
            $clientRows[$r['client']]['latest'] = max($clientRows[$r['client']]['latest'], $r['latest']);
            $v['counts'][$r['action']]=($v['counts'][$r['action']]??0)+$r['n'];
        }
        $evidenceWhere=$where." AND kind IN ('dns_reply_log','dns_policy_log','dns_reply')";$evidenceParams=$params;
        if($v['domain']!==''){$evidenceWhere.=' AND instr(lower(domain),:domain)>0';$evidenceParams[':domain']=$v['domain'];}
        foreach(da_rows($db,'SELECT client,count(*) AS n,max(time) AS latest FROM events WHERE '.$evidenceWhere.' GROUP BY client',$evidenceParams) as $r){
            if(!isset($clientRows[$r['client']])){$clientRows[$r['client']]=['client'=>$r['client'],'dns'=>0,'pass'=>0,'block'=>0,'latest'=>$r['latest']];}
            $clientRows[$r['client']]['other_dns']=$r['n'];
            $clientRows[$r['client']]['latest']=max($clientRows[$r['client']]['latest'],$r['latest']);
        }
        $v['counts']['clients'] = count($clientRows);
        if ($v['view']==='overview') { usort($clientRows, fn($a,$b) => ($b['dns']<=>$a['dns']) ?: strcmp($a['client'],$b['client'])); }
        else { usort($clientRows, fn($a,$b) => (($b['dns']+$b['pass']+$b['block']+($b['other_dns']??0)) <=> ($a['dns']+$a['pass']+$a['block']+($a['other_dns']??0))) ?: strcmp($a['client'],$b['client'])); }
        $v['clients'] = array_slice(array_values($clientRows),0,$v['view']==='overview'?6:100);
        }
        if ($v['view']==='activity') {
            // The existing time index can stop at the latest eligible rows.
            // Insertion order would sort the entire retained time range and
            // promote delayed log records above newer observed traffic.
            $v['traffic'] = da_rows($db, 'SELECT body FROM events WHERE '.$webwhere.' ORDER BY time DESC,id DESC LIMIT 100', $webparams);
            $v['destinations'] = da_rows($db, "SELECT json_extract(body,'$.destination') AS destination,json_extract(body,'$.destination_port') AS port,json_extract(body,'$.protocol') AS protocol,sum(action='pass') AS pass,sum(action='block') AS block,count(*) AS n,count(DISTINCT client) AS clients FROM events WHERE ".$webwhere.' GROUP BY destination,port,protocol ORDER BY n DESC LIMIT 100', $webparams);
        }
        if (in_array($v['view'],['overview','blocks'],true)) {
            $limit=$v['view']==='overview'?5:100;
            $v['blocks'] = da_rows($db, "SELECT json_extract(body,'$.destination') AS destination,tracker,count(*) AS n,count(DISTINCT client) AS clients,max(time) AS latest FROM events WHERE ".$webwhere." AND action='block' GROUP BY destination,tracker ORDER BY n DESC,destination,tracker LIMIT ".$limit, $webparams);
        }
        // Independent aggregates let SQLite seek the endpoints of the time index.
        $v['retention'] = da_rows($db, 'SELECT (SELECT min(time) FROM events) AS oldest,(SELECT max(time) FROM events) AS newest,(SELECT count(*) FROM events) AS n', [])[0];
        if (in_array($v['view'],['overview','coverage'],true)) {
        $available=da_rows($db, "SELECT count(*) AS n FROM sqlite_master WHERE type='table' AND name IN ('hourly_counts','hourly_coverage')",[])[0]['n'];
        if ($available===2) {
            $v['hourly_coverage']=da_rows($db,'SELECT first_event,capacity_groups_removed,capacity_observations_removed FROM hourly_coverage WHERE id=1',[])[0]??[];
            $v['hourly_ready']=true;
            if ($v['view']==='overview') {
            $hwhere='bucket >= :since AND bucket <= :until';
            $hp=[':since'=>((int)floor($now/3600)-23)*3600,':until'=>(int)floor($now/3600)*3600];
            if ($v['client']!=='') { $hwhere.=' AND client=:client';$hp[':client']=$v['client']; }
            $hd=$hwhere." AND kind='dns_query'";$dp=$hp;
            if ($v['domain']!=='') { $hd.=' AND instr(lower(domain),:domain)>0';$dp[':domain']=$v['domain']; }
            $hw=$hwhere." AND kind='firewall_packet' AND port IN (80,443) AND protocol IN ('tcp','udp') AND action IN ('pass','block')";$wp=$hp;
            if ($v['tracker']!=='') { $hw.=' AND tracker=:tracker';$wp[':tracker']=$v['tracker']; }
            if ($v['destination']!=='') { $hw.=' AND destination=:destination';$wp[':destination']=$v['destination']; }
            if ($v['action']!=='') { $hw.=' AND action=:action';$wp[':action']=$v['action']; }
            $hours=[];
            foreach (da_rows($db,'SELECT bucket,sum(n) AS n FROM hourly_counts WHERE '.$hd.' GROUP BY bucket ORDER BY bucket DESC LIMIT 24',$dp) as $row) {
                $hours[$row['bucket']]=['bucket'=>$row['bucket'],'dns'=>$row['n'],'pass'=>0,'block'=>0];
            }
            foreach (da_rows($db,'SELECT bucket,action,sum(n) AS n FROM hourly_counts WHERE '.$hw.' GROUP BY bucket,action ORDER BY bucket DESC LIMIT 48',$wp) as $row) {
                if (!isset($hours[$row['bucket']])) { $hours[$row['bucket']]=['bucket'=>$row['bucket'],'dns'=>0,'pass'=>0,'block'=>0]; }
                $hours[$row['bucket']][$row['action']]=$row['n'];
            }
            krsort($hours,SORT_NUMERIC);$v['hourly']=array_values($hours);
            }
        }
        }
        da_destination_load($db,$v);
        $db->exec('COMMIT');
    } catch (Throwable $e) {
        // Do not expose database paths, SQL, PHP internals or partial aggregates.
        $v['errors'][]=$e instanceof InvalidArgumentException?$e->getMessage():'Telemetry is unavailable or busy. Refresh to try again.';
        foreach (['dns','dns_top','traffic','flows','counts','hourly','hourly_coverage','clients','domains','destinations','blocks','client_events','inspect_events','inspect_clients','inspect_counts','inspect_names','callback_answers'] as $key) { $v[$key]=[]; }
        $v['next_cursor']=null;$v['dns_outcomes']=[];$v['destination_names']=[];
        $v['hourly_ready']=false;
    } finally {
        if ($db !== null) { $db->close(); }
    }
    da_labels_load_visible($v);
    return $v;
}
require_once __DIR__ . '/replyhealth.php';
require_once __DIR__ . '/domainlabels.php';
require_once __DIR__ . '/console.php';
require_once __DIR__ . '/evidence.php';
require_once __DIR__ . '/clientview.php';
require_once __DIR__ . '/inspectview.php';
require_once __DIR__ . '/destination.php';
