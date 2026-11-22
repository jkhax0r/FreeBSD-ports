<?php
require_once __DIR__.'/aliasinspect.php';
require_once __DIR__.'/../native/policies.php';
function da_alias_health(array $service,?float $now=null): array {
    $now=$now??microtime(true);
    $age=static function($stamp)use($now){
        return (is_int($stamp)||is_float($stamp))&&is_finite((float)$stamp)?$now-floor((float)$stamp):null;
    };
    $updated=$service['updated_utc']??null;$elapsed=$age($updated);
    $fresh=$elapsed!==null&&$elapsed>=0&&$elapsed<15;
    $state=$service['state']??null;
    $running=$fresh&&$state==='running'&&is_int($service['pid']??null)&&$service['pid']>1&&empty($service['error']);
    $readAge=$age($service['membership_observed_utc']??null);
    $members=$readAge!==null&&$readAge>=0&&$readAge<15&&empty($service['membership_error']);
    if(!empty($service['error']))$label='Feed needs attention';
    elseif($state==='running'&&!$fresh)$label='Feed status stale';
    elseif($running)$label='Learning';
    else $label=match($state){
        'starting'=>'Starting','stopping'=>'Stopping','stopped'=>'Stopped',
        'waiting_for_resolver'=>'Waiting for resolver','stopped unexpectedly'=>'Stopped unexpectedly',
        default=>'Feed unavailable'};
    return ['label'=>$label,'class'=>$running&&empty($service['membership_error'])?'da-live':'da-warn',
        'running'=>$running,'fresh'=>$fresh,'members_current'=>$members,'updated'=>$updated];
}
function da_alias_row_status(array $policy,array $service,array $health): string {
    $applied=null;
    foreach($service['policies']??[] as $p)if(is_array($p)&&($p['name']??null)===$policy['name'])$applied=$p;
    if(!$policy['enabled']){
        if(!$health['running'])return 'Disabled in settings';
        return $applied!==null&&($applied['enabled']??null)===false?'Disabled':'Disable pending';
    }
    if(!$health['running'])return 'Enabled in settings';
    return $applied!==null&&($applied['enabled']??null)===true&&($applied['names']??null)===$policy['names']?'Learning':'Update pending';
}
function da_alias_live_count(string $table,array $service,array $health): ?int {
    $count=$service['table_counts'][$table]??null;
    return $health['members_current']&&is_int($count)&&$count>=0?$count:null;
}
function da_domain_alias_matches(string $domain,array $policies): ?array {
    // Saved configuration matching only. Never resolve DNS, inspect PF, infer
    // a traffic action or mutate an alias while rendering a domain page.
    $domain=strtolower(rtrim($domain,'.'));
    if(strlen($domain)>253||!preg_match('/^[a-z0-9_-]+(?:\.[a-z0-9_-]+)*$/D',$domain))return null;
    foreach(explode('.',$domain) as $label)if(strlen($label)>63)return null;
    if(!array_is_list($policies)||count($policies)>127)throw new InvalidArgumentException('Invalid saved alias list');
    $out=[];
    foreach($policies as $policy){
        if(!is_array($policy)||!is_string($policy['name']??null)||!preg_match('/^[a-z][a-z0-9_]{0,22}$/D',$policy['name'])||
           !is_bool($policy['enabled']??null)||!is_array($policy['names']??null)||!array_is_list($policy['names'])||count($policy['names'])>2048)
            throw new InvalidArgumentException('Invalid saved alias');
        $patterns=[];
        foreach($policy['names'] as $pattern){
            if(!is_string($pattern)||strlen($pattern)>255||!preg_match('/^(?:\*\.)?[a-z0-9_-]+(?:\.[a-z0-9_-]+)*$/D',$pattern))
                throw new InvalidArgumentException('Invalid saved DNS pattern');
            if($domain===$pattern||(str_starts_with($pattern,'*.')&&str_ends_with($domain,substr($pattern,1))))$patterns[]=$pattern;
        }
        if($patterns)$out[]=['name'=>$policy['name'],'enabled'=>$policy['enabled'],'patterns'=>$patterns];
    }
    return $out;
}
function da_domain_aliases_render(array $view,string $domain): void {
    if(!array_key_exists('domain_aliases',$view))return; // Legacy/private views may not load configuration.
    if(!is_array($view['domain_aliases'])){
        echo '<p class="da-footnote">Saved alias configuration is unavailable. No matching decision can be shown.</p>';return;
    }
    try{$matches=da_domain_alias_matches($domain,$view['domain_aliases']);}
    catch(Throwable $e){echo '<p class="da-footnote">Saved alias configuration is unavailable. No matching decision can be shown.</p>';return;}
    if($matches===null){echo '<p class="da-footnote">Choose a supported DNS name to inspect configured alias matches.</p>';return;}
    echo '<details class="da-domain-aliases"><summary>Configured DNS aliases matching this name · '.da_h(count($matches)).'</summary>';
    if(!$matches)echo '<p class="da-footnote">No saved exact name or wildcard pattern matches this domain.</p>';
    else {
        $rows=[];foreach($matches as $match)$rows[]=[
            ['text'=>'da_'.$match['name'],'url'=>'dnsalias_status.php?view=aliases&edit_alias='.rawurlencode($match['name']).'#da-alias-editor'],
            $match['enabled']?'Enabled in settings':'Disabled in settings',implode(', ',$match['patterns'])];
        da_table(['Saved alias','Configured state','Matching names and patterns'],$rows);
    }
    echo '<p class="da-footnote">Current saved-name matches; the selected history window does not apply. Ordinary firewall rules and live IP membership determine pass or block. CNAME-related mappings and other names sharing an IP can also affect membership.</p></details>';
}
function da_alias_save_identity(string $input,?string $original,array $policies): string {
    if($original!==null){
        $found=false;foreach($policies as $p)if(($p['name']??null)===$original)$found=true;
        if(!$found||$input!==$original)throw new RuntimeException('Alias identity changed. Open Edit again; renaming requires a separate alias.');
        return $original; // Existing da_-prefixed identities remain owned and deletable.
    }
    if(strlen($input)>26)throw new RuntimeException('Use an alias name up to 23 characters, without the automatic da_ prefix.');
    $name=$input;while(str_starts_with($name,'da_'))$name=substr($name,3);
    if(!preg_match('/^[a-z][a-z0-9_]{0,22}$/D',$name)||str_starts_with($name,'seed')||str_starts_with($name,'mvp_'))
        throw new RuntimeException('Use a lowercase alias name up to 23 characters; da_ is added automatically.');
    foreach($policies as $p)if(($p['name']??null)===$name)
        throw new RuntimeException('DNS alias da_'.$name.' already exists. Use Edit to change it.');
    return $name;
}
function da_alias_delete_command(string $action,string $name): array {
    if(!in_array($action,['review','remove'],true)||!preg_match('/^[a-z][a-z0-9_]{0,22}$/D',$name))throw new RuntimeException('Invalid alias deletion');
    $p=proc_open(['/usr/local/bin/python3.11','-B','-m','dnsalias.policydelete',$action,$name],[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes,'/usr/local/libexec/dnsalias');
    if(!is_resource($p))throw new RuntimeException('Alias deletion unavailable');
    fclose($pipes[0]);$out=stream_get_contents($pipes[1],8193);$err=stream_get_contents($pipes[2],4097);fclose($pipes[1]);fclose($pipes[2]);$code=proc_close($p);
    if($code!==0||strlen($out)>8192)throw new RuntimeException('Delete: '.substr(trim($err),0,500));
    return json_decode($out,true,16,JSON_THROW_ON_ERROR);
}
function da_alias_delete(string $name): void {
    // Review before changing anything; a referenced alias stays fully intact.
    da_alias_delete_command('review',$name);
    $selected=null;foreach(dnsalias_policies_read() as $p)if($p['name']===$name)$selected=$p;
    if($selected===null)throw new RuntimeException('Saved DNS alias not found');
    dnsalias_policies_save($name,$selected['names'],false);
    $until=microtime(true)+4;$drained=false;
    do {
        $s=da_alias_service('status');$ack=false;
        foreach($s['policies']??[] as $p)if($p['name']===$name&&!$p['enabled'])$ack=true;
        if(($s['pid']??null)===null||($ack&&($s['table_counts']['da_'.$name]??-1)===0)){$drained=true;break;}
        usleep(100000);
    }while(microtime(true)<$until);
    if(!$drained)throw new RuntimeException('Alias disabled; still waiting for empty table acknowledgement. Inspect service status before deleting again.');
    // Recheck complete live references and native membership inside the final transaction.
    da_alias_delete_command('remove',$name);
}
function da_alias_service(string $op): array {
    if(!in_array($op,['start','stop','status','boot_enable','boot_disable','service_start','service_stop'],true))throw new RuntimeException('Invalid service action');
    $boot=str_starts_with($op,'boot_');
    $native=str_starts_with($op,'service_');
    $p=proc_open(['/usr/local/bin/python3.11','-B','-m',($boot||$native)?'dnsalias.serviceboot':'dnsalias.aliasservice',($boot?substr($op,5):($native?substr($op,8):$op))],
        [0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes,'/usr/local/libexec/dnsalias');
    if(!is_resource($p))throw new RuntimeException('Service control unavailable');
    // Status includes applied names, PF members and service health.
    $limit=$op==='status'?1048576:262144;
    fclose($pipes[0]);$out=stream_get_contents($pipes[1],$limit+1);$err=stream_get_contents($pipes[2],4097);
    fclose($pipes[1]);fclose($pipes[2]);$code=proc_close($p);
    if($code!==0||strlen($out)>$limit)throw new RuntimeException('Alias service: '.substr($err,0,200));
    return json_decode($out,true,32,JSON_THROW_ON_ERROR);
}
function da_alias_rule_index(array $rules): array {
    $index=[];
    // Reuse the collector's bounded snapshot; no PF query or database work.
    foreach(array_slice($rules,0,10000) as $r){
        $raw=$r['rule']??null;$tracker=$r['tracker']??null;
        if(!is_string($raw)||strlen($raw)>8192||!is_string($tracker)||!preg_match('/^[0-9]{1,20}$/D',$tracker))continue;
        // Descriptive labels can contain arbitrary text, including <names>.
        // Native PF prints table operands before label options.
        $scope=preg_split('/\blabel\s+"/',$raw,2)[0];
        preg_match_all('/<(da_[a-z][a-z0-9_]{0,22})(?::[0-9]+)?>/',$scope,$matches);
        foreach(array_unique($matches[1]) as $name)$index[$name][]=$r;
    }
    return $index;
}
function da_alias_rule_snapshot($observed,?float $now=null): array {
    $now=$now??microtime(true);
    $known=(is_int($observed)||is_float($observed))&&is_finite((float)$observed)&&$observed>0&&floor((float)$observed)<=$now;
    return ['known'=>$known,'observed'=>$known?$observed:null,
        'stale'=>$known&&$now-floor((float)$observed)>=150];
}
function da_alias_rule_count(array $rules,array $snapshot): string {
    if(!$snapshot['known'])return 'Unknown';
    return count(array_unique(array_column($rules,'tracker'))).' rules · '.count($rules).' PF entries'.($snapshot['stale']?' · Stale snapshot':'');
}
function da_alias_rule_references(array $policies,array $index,$observed): void {
    $selected=$_GET['inspect_alias']??($_GET['edit_alias']??(count($policies)===1?$policies[0]['name']:null));
    $policy=null;foreach($policies as $p)if($p['name']===$selected)$policy=$p;
    if($policy===null)return;
    $table='da_'.$policy['name'];$rules=$index[$table]??[];$rows=[];
    $snapshot=da_alias_rule_snapshot($observed);
    echo '<div class="da-panel" id="da-alias-rule-details"><div class="da-panel-title"><div><h2>Rules referencing '.da_h($table).'</h2><p>Main ruleset snapshot · '.da_h(da_when($snapshot['observed'])).'</p></div><span class="da-pill da-neutral">'.da_h($snapshot['known']?da_alias_rule_count($rules,$snapshot):'Reference counts unknown').'</span></div>';
    if(!$snapshot['known'])echo '<p class="da-footnote">Reference snapshot unavailable. Reference counts and counter freshness are unknown; any retained rows remain visible below.</p>';
    elseif($snapshot['stale'])echo '<p class="da-footnote">Stale snapshot: more than two counter-sampling intervals have elapsed. Retained rows and counters remain visible; the current ruleset may differ.</p>';
    echo '<p class="da-footnote">TCP and UDP are separate PF entries even when they come from one saved firewall rule. <a href="firewall_rules.php">Open Firewall → Rules ↗</a></p>';
    foreach(array_slice($rules,0,50) as $r){
        preg_match('/^@[0-9]+\s+(pass|block|match)\b/',$r['rule'],$action);
        $rows[]=[['text'=>strtoupper($action[1]??'unknown'),'badge'=>in_array($action[1]??'',['pass','block'],true)?$action[1]:'neutral'],
            ['text'=>($r['description']??'').' · '.$r['tracker'],'url'=>'dnsalias_status.php?view=activity&tracker='.rawurlencode($r['tracker'])],
            da_num($r['packets']??null),da_bytes($r['bytes']??null),
            ['detail'=>['PF rule in snapshot'=>$r['rule'],'States in snapshot'=>$r['states']??'Not recorded','Scope'=>'Whole-rule counters since reset; not alias-only hits'],'label'=>'Source / ports / scope']];
    }
    da_table(['Decision','Recorded label / logged activity','Packets since reset','Bytes since reset','Rule scope'],$rows);
    echo '<p class="da-footnote">Up to50 entries shown. Only tracked main-ruleset entries with counters are included. These rules reference the table; their counters are for the entire rule, including any negated or broader matching scope. They are not exact alias hits, unique connections or HTTP requests. TCP/UDP entries may share a tracker. Client/domain filters do not narrow these counters. Anchors are not included; no references shown is not proof that the alias is unused.</p></div>';
}
function da_saved_aliases_render(array $policies,array $service,bool $can,string $error='',array $rule_snapshot=[],$rules_observed=null,?array $member_view=null,int $window=60): void {
    $rule_index=da_alias_rule_index($rule_snapshot);
    $reference_snapshot=da_alias_rule_snapshot($rules_observed);
    if(isset($_GET['inspect_members'])){da_alias_members_render($member_view,$can);return;}
    if(isset($_GET['inspect_alias'])){
        echo '<p class="da-alias-back"><a href="dnsalias_status.php?view=aliases">← Back to DNS aliases</a></p>';
        $found=false;foreach($policies as $p)if($p['name']===($_GET['inspect_alias']??null))$found=true;
        if($found)da_alias_rule_references($policies,$rule_index,$rules_observed);
        else echo '<div class="da-panel"><h2>DNS alias not found</h2></div>';
        return;
    }
    if(($_GET['settings']??null)==='1'){
        echo '<p class="da-alias-back"><a href="dnsalias_status.php?view=aliases">← Back to DNS aliases</a></p><div class="da-panel"><h2>DNS Alias settings</h2>';
        if($error!=='')echo '<p class="da-error">'.da_h($error).'</p>';
        if($can)echo '<form class="da-alias-form" method="post" action="dnsalias_status.php?view=aliases&amp;settings=1"><label class="da-check"><input type="checkbox" name="service_enabled" value="1" '.(dnsalias_service_enabled()?'checked':'').'> Enable DNS Alias</label><p class="da-help">Run the service now and after reboot. Disabling empties DNS alias tables; ordinary firewall rules stay saved.</p><div class="da-form-actions"><button class="da-primary" name="alias_op" value="settings">Save settings</button><a href="status_services.php">Status → Services ↗</a></div></form>';
        echo '<p class="da-footnote">Use Status → Services for start, stop and restart. Alias names and patterns are managed separately.</p>';
        echo '<details class="da-domain-aliases"><summary>Preferences backup</summary><p>Download saved alias names and all domain reviews/tags. Firewall rules are included in pfSense’s configuration backup. Logs and learned IPs are excluded.</p><p><a href="dnsalias_status.php?preferences_export=1">Download preferences backup</a></p></details></div>';return;
    }
    $health=da_alias_health($service);
    echo '<div class="da-panel"><div class="da-panel-title"><div><h2>DNS aliases</h2><p>Saved names → trusted DNS replies → separate PF tables → ordinary firewall rules.</p></div><span class="da-pill '.$health['class'].'">'.da_h($health['label']).'</span></div>';
    if($error!=='')echo '<p class="da-error">'.da_h($error).'</p>';
    if(!empty($service['error']))echo '<p class="da-error">Feed: '.da_h($service['error']).'</p>';
    if(!empty($service['result']['source_error']))echo '<p class="da-error">'.da_h($service['result']['source_error']).'</p>';
    if(!empty($service['membership_error']))echo '<p class="da-error">Current PF membership could not be read: '.da_h($service['membership_error']).'. Live counts are unavailable; recorded values are not treated as current.</p>';
    echo '<p class="da-footnote">Feed updated '.da_h(da_when($health['updated'])).'. PF membership checked '.da_h(da_when($service['membership_observed_utc']??null)).'.</p>';
    if(!$health['running'])echo '<p class="da-footnote">Saved enable settings do not prove that replies are currently updating tables. Live membership and feed status are separate observations.</p>';
    if(!empty($service['telemetry']['dropped']))echo '<p class="da-footnote">DNS statistics missed '.da_h($service['telemetry']['dropped']).' observations. Table synchronization does not wait for statistics storage.</p>';
    echo '<p class="da-alias-toolbar"><a href="dnsalias_status.php?view=aliases&amp;settings=1">Service settings</a> · <a href="status_services.php">Status → Services ↗</a></p>';
    $members=$service['tables']??[];
    echo '<table class="da-table"><thead><tr><th>Alias / PF table</th><th>Names and patterns</th><th>State</th><th>Live IPs</th><th>Rule references</th><th></th></tr></thead><tbody>';
    foreach($policies as $p){
        $table='da_'.$p['name'];$entries=$rule_index[$table]??[];
        $count=da_alias_live_count($table,$service,$health);$status=da_alias_row_status($p,$service,$health);
        echo '<tr><td>';da_alias_preview($p,$window);
        echo '</td><td>'.da_h(implode(', ',array_slice($p['names'],0,3))).(count($p['names'])>3?' <small>+'.da_h(count($p['names'])-3).' more</small>':'').'</td><td>'.da_h($status).'</td><td>'.($count===null?'Unknown':da_h($count));
        if($count===0&&$status==='Learning')echo '<small class="da-alias-empty">No unexpired addresses; matching replies can populate this table.</small>';
        echo '</td><td><a href="dnsalias_status.php?view=aliases&amp;inspect_alias='.rawurlencode($p['name']).'#da-alias-rule-details">'.da_h(da_alias_rule_count($entries,$reference_snapshot)).' ↗</a></td><td>';
        if($can)echo '<div class="da-form-actions"><a href="dnsalias_status.php?view=aliases&amp;edit_alias='.rawurlencode($p['name']).'#da-alias-editor">Edit</a><form method="post" action="dnsalias_status.php?view=aliases"><input type="hidden" name="alias_name" value="'.da_h($p['name']).'"><button class="da-delete" name="alias_op" value="delete">Delete</button></form></div>';
        echo '</td></tr>';
    }
    if(!$policies)echo '<tr><td colspan="6">Create your first DNS alias below.</td></tr>';
    echo '</tbody></table>';
    foreach($members as $name=>$ips)if(is_array($ips)&&$ips){
        $count=da_alias_live_count((string)$name,$service,$health);
        $destinations=[];
        foreach(array_slice($ips,0,100) as $ip){
            if(!is_string($ip))continue;
            $label=da_h($ip);
            $destinations[]=filter_var($ip,FILTER_VALIDATE_IP)?'<a href="dnsalias_status.php?view=ip&amp;destination='.rawurlencode($ip).'">'.$label.'</a>':$label;
        }
        echo '<details><summary>'.da_h($name).' · '.($count===null?'Recorded destinations (current membership unknown)':da_h($count).' live destinations').'</summary><p>'.implode(', ',$destinations).'</p><p class="da-footnote">'.($count===null?'Up to 100 recorded addresses; this is not a current PF membership check.':'Up to 100 current members shown, read when this page opens.').' Select an IP to inspect recent DNS names and observed traffic.</p></details>';
    }
    echo '<p class="da-footnote">Rule references use the main ruleset snapshot from '.da_h(da_when($reference_snapshot['observed'])).'. '.(!$reference_snapshot['known']?'Reference snapshot unavailable. ':''). 'No references shown does not prove the alias is unused.</p>';
    if($can){
        $prefill=function_exists('da_policy_prefill')?da_policy_prefill($_GET):null;
        if($prefill!==null && $policies){
            echo '<form method="post" action="dnsalias_status.php?view=aliases"><h3>Add '.da_h($prefill['names'][0]).' to an alias</h3><input type="hidden" name="alias_domain" value="'.da_h($prefill['names'][0]).'"><select name="alias_name">';
            foreach($policies as $p)echo '<option value="'.da_h($p['name']).'">'.da_h('da_'.$p['name']).($p['enabled']?'':' (disabled)').'</option>';
            echo '</select> <button class="da-primary" name="alias_op" value="add_name">Add domain</button><p class="da-footnote">The ordinary rules using this shared table determine which clients pass or block. This action adds no firewall rule.</p></form>';
        }
        $edit=null;foreach($policies as $p)if($p['name']===($_GET['edit_alias']??''))$edit=$p;
        $editor_names=$edit!==null?$edit['names']:($prefill['names']??[]);
        echo '<form class="da-alias-form" id="da-alias-editor" method="post" action="dnsalias_status.php?view=aliases"><h3>'.($edit?'Edit DNS alias':'Create DNS alias').'</h3>';
        echo '<input type="hidden" name="alias_editor_mode" value="'.($edit?'edit':'create').'">';
        if($edit)echo '<input type="hidden" name="alias_original_name" value="'.da_h($edit['name']).'">';
        echo '<label>Alias name<input name="alias_name" pattern="(?:da_)?[a-z][a-z0-9_]{0,22}" maxlength="26" value="'.da_h($edit['name']??'').'" required '.($edit?'readonly':'').'></label><p class="da-help">'.($edit?'Firewall alias: <strong>'.da_h('da_'.$edit['name']).'</strong>.':'The <strong>da_</strong> prefix is added automatically. Enter <strong>example</strong> or <strong>da_example</strong> to create <strong>da_example</strong>.').'</p><label>DNS names and patterns<textarea name="alias_names" rows="4" maxlength="65536" required placeholder="example.com&#10;*.example.com">'.da_h(implode("\n",$editor_names)).'</textarea></label><p class="da-help">Up to 2,048 names or wildcard patterns per alias. *.example.com matches subdomains; add example.com separately for the base name.</p><label class="da-check"><input type="checkbox" name="alias_enabled" value="1" '.(!$edit||$edit['enabled']?'checked':'').'> Enable this alias</label><div class="da-form-actions"><button class="da-primary" name="alias_op" value="save">Save alias</button>';
        if($edit)echo '<button class="da-delete" name="alias_op" value="delete" formnovalidate>Delete</button><a href="dnsalias_status.php?view=aliases">Cancel</a>';
        echo '</div></form>';
    }
    echo '<p class="da-footnote">No session expiry. Each DNS mapping keeps its remaining TTL; shared IPs stay until their final mapping expires. Any trusted client can populate a table. Choose source/VLAN, ports and pass/block in <a href="firewall_rules.php">Firewall → Rules</a>; destination is the alias above. A *.example.com pattern matches subdomains, not example.com itself. Shared CDN IPs cannot distinguish HTTPS hostnames. Existing firewall states normally survive membership removal.</p></div>';
}
