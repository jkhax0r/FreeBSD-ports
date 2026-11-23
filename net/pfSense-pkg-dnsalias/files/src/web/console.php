<?php
require_once __DIR__.'/replyhealth.php';
require_once __DIR__.'/domainlabels.php';
/* All data text is escaped. Investigation links are explicit and opt-in. */
function da_recorded_rule_label($v,$tracker,$stamp) {
    foreach($v['policy_history']??[] as $s){
        if(is_numeric($stamp)&&in_array((string)$tracker,$s['rule_trackers'],true)&&$stamp>=$s['started_utc']&&$stamp<=($s['ended_utc']??$s['until_utc'])){return 'DNS Alias / '.$s['name'].' / block';}
    }
    return $v['rule_labels'][$tracker]??'Unavailable';
}
function da_url($v, $changes=[]) {
    $q=[];
    foreach (['window','client','domain','tracker','destination','action','view','feed','before','asof','review','tag','hide_tag','rows'] as $k) { $q[$k]=$v[$k]??''; }
    foreach ($changes as $k=>$value) { if (array_key_exists($k,$q)) { $q[$k]=$value; } }
    // Either way back to Domains restores the filter that opened the detail.
    if ($q['view']==='domain') {
        $q['list_domain']=($v['view']??'')==='domains'?($v['domain']??''):($v['list_domain']??'');
    } elseif ($q['view']==='domains' && ($v['view']??'')==='domain' && !array_key_exists('domain',$changes)) {
        $q['domain']=$v['list_domain']??'';
    }
    return '?'.http_build_query(array_filter($q,fn($value)=>$value!==''), '', '&', PHP_QUERY_RFC3986);
}
function da_address_order($ip,$port=null) {
    $packed=@inet_pton((string)$ip);
    if ($packed===false) return [];
    // Fixed-width network byte order also sorts compressed IPv6 correctly.
    $key=(strlen($packed)===4?'4':'6').bin2hex($packed);
    if (is_numeric($port)) $key.=':'.sprintf('%05d',(int)$port);
    return ['ip_order'=>$key];
}
function da_link($v,$text,$changes) {
    $client_label=isset($changes['client']) && $changes['client']!=='' && $text===$changes['client'];
    if (isset($changes['client']) && !isset($changes['action'])) { $changes=array_merge(['domain'=>'','tracker'=>'','destination'=>'','action'=>'','feed'=>'all','before'=>'','asof'=>''],$changes,['view'=>'client']); }
    elseif (!empty($changes['domain'])) { $changes=array_merge($changes,['view'=>'domain','client'=>$v['client']??'','tracker'=>'','destination'=>'','action'=>'','before'=>'','asof'=>'']); }
    elseif (!empty($changes['destination'])) { $changes=array_merge($changes,['view'=>'ip','client'=>'','tracker'=>'','domain'=>'','action'=>'','before'=>'','asof'=>'']); }
    if ($client_label) {
        return ['text'=>da_client_label($v,$text),'url'=>da_url($v,$changes),'client_ip'=>$text]+da_address_order($text);
    }
    return ['text'=>$text,'url'=>da_url($v,$changes)];
}
function da_time($stamp) { return ['text'=>da_when($stamp),'time'=>$stamp]; }
function da_context_client($v) {
    if (($v['client']??'')==='') { echo '<span class="da-muted">All observed clients</span>';return; }
    $clear=da_url($v,['client'=>'','view'=>$v['view']==='client'?'overview':$v['view'],'before'=>'','asof'=>'','feed'=>'all']);
    $applied=!in_array($v['view'],['rules','aliases','coverage'],true);
    echo '<span class="da-scope-filter"><strong>'.($applied?'Client filter:':'Client selection:').'</strong> <span '.da_client_name_attributes($v['client']).'>'.da_h(da_client_label($v,$v['client'])).'</span>'.($applied?'':' <small>(not applied here)</small>').' <a href="'.da_h($clear).'" aria-label="Clear client filter">Clear ×</a></span>';
}
function da_num($n) { return ['text'=>da_number($n),'order'=>is_numeric($n)?$n:-1]; }
function da_bytes($n) {
    if (!is_numeric($n)) { return '—'; }
    $i=0; while ($n>=1024 && $i<4) { $n/=1024; $i++; }
    return number_format($n,$i?1:0).' '.['B','KiB','MiB','GiB','TiB'][$i];
}
function da_event_detail_attr(array $detail,bool $compact,?array &$first): string {
    if (!$compact) return 'data-detail='.da_json_attr($detail);
    if ($first===null) {
        $first=$detail;
        return 'data-detail-base data-detail='.da_json_attr($detail);
    }
    // Only reuse an identical ordered field list. Mixed event types may carry
    // extra answer records or different attribution and retain their full data.
    if (array_keys($detail)===array_keys($first)) {
        $changes=array_filter($detail,static fn($value,$key)=>$value!==$first[$key],ARRAY_FILTER_USE_BOTH);
        // Shared descriptions can outweigh several changing packet fields.
        if (count($changes)<count($detail)) return 'data-detail-delta='.da_json_attr($changes);
    }
    return 'data-detail='.da_json_attr($detail);
}
function da_table($headers,$rows,$class='',$compact_events=false,$default_desc=null) {
    $first_detail=null;
    if ($class==='da-client-timeline') {
        echo '<div class="da-card-sort"><label>Sort by <select>';
        foreach ($headers as $i=>$label) {
            echo '<option value="'.$i.'"'.($i===$default_desc?' selected':'').'>'.da_h($label).'</option>';
        }
        echo '</select></label><button type="button" title="Reverse sort direction">Descending ↓</button></div>';
    }
    echo '<div class="da-table-wrap"><table class="da-table '.da_h($class).'"><thead><tr>';
    foreach ($headers as $i=>$header) {
        echo '<th scope="col"'.($class==='da-client-timeline'?' aria-label="'.da_h($header).'"':'').($i===$default_desc?' aria-sort="descending"':'').'><button type="button" class="da-sort">'.da_h($header).'<span aria-hidden="true"></span></button></th>';
    }
    echo '</tr></thead><tbody>';
    foreach ($rows as $row) {
        echo '<tr data-row>';
        foreach ($row as $index=>$cell) {
            $c=is_array($cell)?$cell:['text'=>$cell];
            echo '<td';
            // The timeline uses named cells when it becomes a stack of cards.
            if ($class==='da-client-timeline') echo ' data-label="'.da_h($headers[$index]??'').'"';
            if (isset($c['ip_order'])) echo ' data-ip-order="'.da_h($c['ip_order']).'"';
            if (isset($c['order'])) echo ' data-order="'.da_h($c['order']).'"';
            if ($compact_events && isset($c['review'])) echo ' data-review-context='.da_json_attr($c['review']);
            echo '>';
            if (isset($c['destination_context'])) { da_destination_render($c); }
            elseif (isset($c['domain_label'])) { da_labels_cell_render($c); }
            elseif (isset($c['url'])) { echo '<a href="'.da_h($c['url']).'"'.(isset($c['client_ip'])?' '.da_client_name_attributes($c['client_ip']):'').'>'.da_h($c['text']).'</a>'; }
            elseif (isset($c['badge'])) { echo '<span class="da-pill da-'.(in_array($c['badge'],['pass','block'],true)?$c['badge']:'neutral').'">'.da_h($c['text']).'</span>'; }
            elseif (isset($c['detail'])) { echo '<button type="button" class="da-detail" ' . da_event_detail_attr($c['detail'],$compact_events,$first_detail) . '>'.da_h($c['label']??'Details').' <span aria-hidden="true">↗</span></button>'; }
            elseif (isset($c['review'])) {
                foreach (['allow'=>'Review allow','block'=>'Review block'] as $intent=>$label) {
                    $attribute=$compact_events?'data-review-intent="'.da_h($intent).'"':'data-review='.da_json_attr($c['review']+['intent'=>$intent]);
                    echo '<button type="button" class="da-review" '.$attribute.'>'.da_h($label).'</button> ';
                }
            }
            elseif (isset($c['hint'])) { echo '<span tabindex="0" title="'.da_h($c['hint']).'">'.da_h($c['text']).'</span>'; }
            elseif (isset($c['time']) && is_numeric($c['time'])) { echo '<time datetime="'.gmdate('c',(int)$c['time']).'" data-utc="'.da_h($c['time']).'">'.da_h($c['text']).'</time>'; }
            else { echo da_h($c['text']??''); }
            echo '</td>';
        }
        echo '</tr>';
    }
    if (!$rows) { echo '<tr><td class="da-empty" colspan="'.count($headers).'">No matching observations in retained data.</td></tr>'; }
    echo '</tbody></table></div><p class="da-search-empty" hidden>No rows match this table search.</p>';
}
function da_rank($v,$rows,$field,$target,$metric) {
    $max=max([1,...array_map(fn($r)=>(int)$r[$metric],$rows)]);
    if (!$rows) { echo '<p class="da-empty">No matching observations yet.</p>'; }
    foreach (array_slice($rows,0,6) as $r) {
        $link=da_link($v,$r[$field],[$target=>$r[$field],'view'=>$target==='client'?'client':'domain']);
        echo '<a class="da-rank" href="'.da_h($link['url']).'"><span'.($target==='client'?' '.da_client_name_attributes($r[$field]):'').'>'.da_h($target==='client'?da_client_label($v,$r[$field]):$r[$field]).'</span><strong>'.da_h(da_number($r[$metric])).'</strong><i style="width:'.round(100*$r[$metric]/$max,2).'%"></i></a>';
    }
}
function da_chart($v,$kind) {
    $hours=[];foreach ($v['hourly'] as $r) { $hours[$r['bucket']]=$r; }
    $top=max([1,...array_map(fn($r)=>$kind==='dns'?$r['dns']:$r['pass']+$r['block'],$v['hourly'])]);
    echo '<svg class="da-chart" viewBox="0 0 720 165" role="img" aria-label="'.($kind==='dns'?'Observed DNS queries':'Logged pass and block packets').' by UTC hour"><text x="0" y="12" class="da-axis">'.da_h(da_number($top)).'</text><line x1="0" y1="133" x2="720" y2="133" class="da-grid"/>';
    $start=((int)floor($v['now']/3600)-23)*3600;
    for ($i=0;$i<24;$i++) {
        $stamp=$start+$i*3600;$r=$hours[$stamp]??null;$x=$i*30+4;
        $title=gmdate('H:i',$stamp).' UTC · '.($r?('DNS '.$r['dns'].' / pass '.$r['pass'].' / block '.$r['block']):'No retained observations; traffic unknown');
        echo '<g><title>'.da_h($title).'</title>';
        if ($r) {
            $values=$kind==='dns'?['dns'=>$r['dns']]:['pass'=>$r['pass'],'block'=>$r['block']];$y=132;
            foreach ($values as $k=>$value) { $h=112*$value/$top; $y-=$h; echo '<rect x="'.$x.'" y="'.round($y,2).'" width="20" height="'.round($h,2).'" rx="2" class="da-bar-'.$k.'"/>'; }
        } else { echo '<rect x="'.$x.'" y="128" width="20" height="4" class="da-bar-missing"/>'; }
        echo '</g>';
        if ($i%6===0 || $i===23) { echo '<text x="'.$x.'" y="155" class="da-axis">'.gmdate('H:i',$stamp).'</text>'; }
    }
    echo '</svg>';
}
function da_retention($status) {
    $counts=$status['counts']??[];
    if(isset($status['storage_busy_since'])&&($status['state']??'')==='running'){
        echo '<p class="da-footnote"><strong>Log storage busy.</strong> At the last check, '.da_h(da_number($status['pending_log_events']??null)).' log records were waiting to be stored. ';
        echo isset($status['storage_observed_utc'])?'The collector last verified retention totals at '.da_h(da_when($status['storage_observed_utc'])).'.':'The first retention totals are pending.';
        echo '</p>';
    }
    if(($counts['events_dropped_batch_limit']??0)>0)
        echo '<p class="da-footnote">The collector discarded '.da_h(da_number($counts['events_dropped_batch_limit'])).' log records at its batch limit.</p>';
    if(($counts['events_unconfirmed_at_exit']??0)>0)
        echo '<p class="da-footnote">The collector exited with '.da_h(da_number($counts['events_unconfirmed_at_exit'])).' unconfirmed log records.</p>';
    $storage=is_array($status['storage']??null)?$status['storage']:[];
    $history=is_array($storage['raw_by_kind']??null)?$storage['raw_by_kind']:[];
    if (!$history) { return; }
    $labels=['dns_query'=>'DNS queries','dns_reply_log'=>'Recorded DNS replies','dns_policy_log'=>'Recorded DNS policy decisions','dns_reply'=>'Trusted reply observations','firewall_packet'=>'Firewall packets (all collected ports)'];
    echo '<div class="da-panel"><div class="da-panel-title"><h2>Retained detail by log type</h2><span class="da-muted">Latest collector snapshot</span></div>';
    $rows=[];
    foreach (array_slice($history,0,16) as $row) {
        if (!is_array($row)) { continue; }
        $rows[]=[$labels[$row['kind']??'']??($row['kind']??'Unknown'),da_num($row['rows']??null),da_time($row['oldest']??null),da_time($row['newest']??null)];
    }
    da_table(['Log type','Records','Oldest retained','Newest retained'],$rows);
    if (($storage['dns_reserved_events']??0)>0) {
        echo '<p>Under capacity pressure, up to '.da_h(da_number($storage['dns_reserved_events'])).' most recently collected DNS records are protected from eviction by other logs. This reservation shares the existing '.da_h(da_number($storage['event_limit']??null)).'-record limit. Unused space remains available to other logs.</p>';
    }
    echo '<p class="da-footnote">All collected sources are included; page filters do not narrow these counts. Reports cover the most recent 24 hours. The collector removes expired records in batches. Each log type can cover a different time range; the oldest record does not prove continuous coverage. Missing records are unknown, not zero traffic. Previously removed records are not recovered.</p></div>';
}
function da_console_open($v,$fresh) {
    $s=$v['status'];
    ?><section id="da-console" data-identity-pending="<?=!empty($v['identity_pending'])?'1':'0'?>" data-identity-observed="<?=da_h($s['client_identity']['observed_utc']??0)?>" data-view="<?=da_h($v['view'])?>" data-status-time="<?=da_h($s['updated_utc']??0)?>" data-status-age="<?=da_h($v['status_age']??30)?>" data-running="<?=$fresh?'1':'0'?>"><?php
}
function da_health_badge($v,$fresh) {
    ?><a href="<?=da_h(da_url($v,['view'=>'coverage','before'=>'','asof'=>'']))?>" data-nav="coverage" class="da-pill <?=$fresh?'da-live':'da-warn'?>" id="da-health-badge"><span aria-hidden="true">●</span> <?=$fresh?'Collector live':'Collector stale / unavailable'?></a><?php
}
function da_render_errors($v) {
    $s=$v['status'];
    ?><?php foreach ($v['errors'] as $error): ?><div class="da-notice da-danger"><?=da_h($error)?></div><?php endforeach; ?>
      <?php if (!empty($s['error'])): ?><div class="da-notice da-danger">Collector: <?=da_h($s['error'])?></div><?php endif; ?><?php
}
function da_render($v, $fragment=false) {
    if(function_exists('da_policy_history_read')){
        try{$v['policy_history']=da_policy_history_read($v['data_directory']??'/var/db/dnsalias',$v['now']);}
        catch(Throwable $e){$v['policy_history']=[];$v['policy_history_error']=true;}
    }
    $trialPresent=!empty($v['trial']) || !empty($v['trial_error']);
    $observationSession=($v['trial']['format']??null)==='dnsalias-observation-control-1';
    $namedPolicy=!empty($v['trial']['policy_name']);
    $s=$v['status'];$fresh=$v['fresh'] && ($s['state']??'')==='running';
    $reply_health=$v['reply_health']??da_reply_health([],(float)$v['now'],'missing');
    if ($fragment && $v['view']==='client') {
        // Return everything the current filter and Back handlers consume.
        da_console_open($v,$fresh);
        da_health_badge($v,$fresh);
        da_render_errors($v);
        da_reply_health_warning($reply_health);
        da_labels_context_render($v);
        da_client_render($v,$fragment==='client-v2');
        da_labels_dialog_render($v);
        echo '</section>';
        return;
    }
    $views=['aliases'=>'Aliases','overview'=>'Overview','clients'=>'Clients','client'=>'Client inspect','domains'=>'Domains','domain'=>'Domain inspect','ip'=>'IP inspect','activity'=>'Activity','blocks'=>'Blocked','rules'=>'Rules','coverage'=>'Coverage'];
    $window=[15=>'Last 15 minutes',60=>'Last hour',1440=>'Last 24 hours'][$v['window']];
    if(!$fragment)require __DIR__.'/style.php';
    ?>
    <?php da_console_open($v,$fresh); ?>
      <header class="da-header"><div><div class="da-eyebrow">NETWORK VISIBILITY</div><h1>DNS Alias <span>Activity console</span></h1></div><div class="da-status"><?php da_health_badge($v,$fresh); ?><a href="<?=da_h(da_url($v,['view'=>'aliases','before'=>'','asof'=>'']))?>" data-nav="aliases" class="da-pill da-neutral"><?=function_exists('da_saved_aliases_render')?'DNS aliases':($namedPolicy?'Alias block policy':($observationSession?'DNS reply session':($trialPresent?'Short block trial':'Observation only')))?></a></div></header>
      <?php da_render_errors($v); ?>
      <?php if ($v['view']==='aliases' && !function_exists('da_saved_aliases_render') && function_exists('da_trial_render')) {da_trial_render($v['trial']??null,$v['can_control']??false,$v['trial_error']??'');} ?>
      <?php if ($v['view']==='aliases' && !function_exists('da_saved_aliases_render') && function_exists('da_preparation_render')) {da_preparation_render($v['preparation']??null,$v['can_control']??false,in_array($v['trial']['state']??'',['prepared','queued','running','cancelling'],true),$v['policy_prefill']??null);} ?>
      <div class="da-shell"><nav class="da-nav" aria-label="DNS Alias views">
        <?php foreach ($views as $key=>$label): if ($key==='overview'): ?><div class="da-nav-label">Diagnostics</div><?php endif; ?><a href="<?=da_h(da_url($v,['view'=>$key,'before'=>'','asof'=>'']))?>" data-nav="<?=$key?>" <?=$key===$v['view']?'aria-current="page"':''?>><span class="da-nav-icon" aria-hidden="true"><?= ['overview'=>'▦','clients'=>'◉','client'=>'↳','domains'=>'◎','domain'=>'↳','ip'=>'↳','activity'=>'≋','blocks'=>'⊘','rules'=>'☷','aliases'=>'◇','coverage'=>'ⓘ'][$key]?></span><?=da_h($label)?><?php if ($key==='blocks' && isset($v['counts']['block'])): ?><span class="da-nav-count"><?=da_h(da_number($v['counts']['block']))?></span><?php endif; ?></a><?php endforeach; ?>
        <div class="da-nav-footer">DNS Alias<br><strong><?=da_h($s['version']??'Unavailable')?></strong><br><?=function_exists('da_saved_aliases_render')?'Ordinary firewall rules':($trialPresent?'See prepared trial status':'Enforcement inactive')?></div>
      </nav><main class="da-main">
        <form class="da-filters" method="get" action="dnsalias_status.php">
          <input type="hidden" name="view" value="<?=da_h($v['view'])?>">
          <?php if (($v['list_domain']??'')!==''): ?><input type="hidden" name="list_domain" value="<?=da_h($v['list_domain'])?>"><?php endif; ?>
          <input type="hidden" name="rows" value="<?=da_h($v['rows']??'')?>" <?=empty($v['rows'])?'disabled':''?>>
          <?php if($v['view']==='client'): ?><input type="hidden" name="feed" value="<?=da_h($v['feed']??'all')?>"><?php endif; ?>
          <label>Event window<select name="window"><?php foreach ([15=>'15 minutes',60=>'1 hour',1440=>'24 hours'] as $n=>$label): ?><option value="<?=$n?>" <?=$v['window']===$n?'selected':''?>><?=$label?></option><?php endforeach; ?></select></label>
          <label>Client / source IP<input name="client" value="<?=da_h($v['client'])?>" placeholder="All observed clients" maxlength="45"></label>
          <label><?= $v['view']==='domain'?'Exact DNS name':'DNS name contains' ?><input name="domain" value="<?=da_h($v['domain'])?>" placeholder="Search DNS names" maxlength="253"></label>
          <button class="da-primary" type="submit">Apply filters</button><a class="da-reset" href="?view=<?=da_h($v['view'])?>">Reset</a>
          <?php da_labels_filters_render($v); ?>
          <details class="da-advanced" <?=($v['tracker']!==''||$v['destination']!==''||$v['action']!=='')?'open':''?>><summary>Firewall filters<?=($v['tracker']!==''||$v['destination']!==''||$v['action']!=='')?' · active':''?></summary><div><label>Destination IP<input name="destination" value="<?=da_h($v['destination'])?>" maxlength="45" placeholder="Any destination"></label><label>Rule tracker<input name="tracker" value="<?=da_h($v['tracker'])?>" maxlength="20" placeholder="Any rule"></label><label>Decision<select name="action"><option value="">Pass and block</option><?php foreach (['pass','block'] as $a): ?><option <?=$v['action']===$a?'selected':''?> value="<?=$a?>"><?=ucfirst($a)?></option><?php endforeach; ?></select></label><p>DNS-name filters affect DNS data. Firewall filters affect logged traffic. These are separate observations until reply mapping is connected.</p></div></details>
        </form>
        <div class="da-context"><span><strong id="da-view-name"><?=da_h($views[$v['view']])?></strong> <span class="da-muted">/ <?=da_h($window)?> · </span><?php da_context_client($v); ?></span><div><label class="da-compact">Times <select id="da-time-mode"><option value="local">Local</option><option value="utc">UTC</option></select></label><label class="da-compact">Refresh <select id="da-refresh"<?=($_SERVER['REQUEST_METHOD']??'GET')==='POST'?' disabled title="Automatic refresh is paused after submitting a form."':''?>><option value="0">Manual</option><option value="30">30 sec</option><option value="60">60 sec</option></select></label><a class="da-detail" href="<?=da_h(da_url($v))?>" id="da-refresh-now">Refresh now</a></div></div>
        <div class="da-retained"><?php if (in_array($v['view'],['rules','aliases'],true)): ?>This view uses the latest collector status snapshot. <?php else: ?>Metrics below count retained log observations, not connections or HTTP requests. Oldest retained record <?=da_h(da_when($v['retention']['oldest']??null))?>. <?php endif; ?><a href="<?=da_h(da_url($v,['view'=>'coverage','before'=>'','asof'=>'']))?>" data-nav="coverage">Coverage details ↗</a></div>

        <?php da_reply_health_warning($reply_health); ?>
        <?php da_labels_context_render($v); ?>
        <div class="da-table-tools" hidden><label>Search visible tables <input id="da-table-search" type="search" placeholder="Type to narrow rows…"></label><span>Click a heading to sort · click a name or IP to filter</span></div>
        <?php if ($v['view']==='client'): da_client_render($v); elseif (in_array($v['view'],['domain','ip'],true)): da_inspect_render($v); else: ?>
        <?php if ($v['view']==='overview'): ?><section class="da-view" id="da-overview" data-panel="overview" aria-label="Overview">
          <div class="da-cards"><?php foreach ([['dns','DNS queries','Observed lookups','domains','dns'],['pass','Pass packets','Logged to ports 80 / 443','activity','pass'],['block','Block packets','Logged to ports 80 / 443','blocks','block'],['clients','Clients / sources','Addresses in retained events','clients','clients']] as [$key,$label,$note,$target,$tone]): ?><a class="da-card da-card-<?=$tone?>" href="<?=da_h(in_array($key,['pass','block'],true)?da_url($v,['action'=>$key,'view'=>$target]):da_url($v,['view'=>$target]))?>" <?=in_array($key,['pass','block'],true)?'':'data-nav="'.$target.'"'?>><span><?=$label?></span><strong><?=da_h($v['errors']?'—':da_number($v['counts'][$key]??0))?></strong><small><?=$note?> <span aria-hidden="true">↗</span></small></a><?php endforeach; ?></div>
          <div class="da-panel"><div class="da-panel-title"><div><h2>Activity over time</h2><p>Latest 24 UTC hour buckets · current hour is partial · independent of the event window</p></div><span class="da-pill da-neutral">Hourly summaries</span></div>
            <?php if (!$v['hourly_ready']): ?><div class="da-empty">Hourly summaries are not available yet.</div><?php else: ?>
            <div class="da-charts"><div><h3><i class="da-dot da-dns"></i> DNS queries</h3><?php da_chart($v,'dns'); ?></div><div><h3><i class="da-dot da-pass"></i> Pass <i class="da-dot da-block"></i> Block <small>logged packets</small></h3><?php da_chart($v,'firewall'); ?></div></div><p class="da-footnote">Gray marks mean no retained observations. Missing hours are not zero traffic. Hover over a bar for counts.</p><?php endif; ?>
          </div>
          <div class="da-two"><div class="da-panel"><div class="da-panel-title"><h2>Most queried domains</h2><a href="<?=da_h(da_url($v,['view'=>'domains','before'=>'','asof'=>'']))?>" data-nav="domains">View all ↗</a></div><?php da_rank($v,$v['domains'],'domain','domain','n'); ?><p class="da-footnote">Query counts show DNS lookups, not HTTP requests or firewall decisions. Select a domain for recorded DNS outcomes and recent IP evidence.</p></div><div class="da-panel"><div class="da-panel-title"><h2>Active DNS clients</h2><a href="<?=da_h(da_url($v,['view'=>'clients','before'=>'','asof'=>'']))?>" data-nav="clients">View all ↗</a></div><?php $top=$v['clients'];usort($top,fn($a,$b)=>$b['dns']<=>$a['dns']);da_rank($v,array_values(array_filter($top,fn($r)=>$r['dns']>0)),'client','client','dns'); ?><p class="da-footnote">Select a client to inspect its observations.</p></div></div>
          <div class="da-panel"><div class="da-panel-title"><div><h2>Top blocked destinations</h2><p>Grouped by destination and the actual logged rule</p></div><a href="<?=da_h(da_url($v,['view'=>'blocks','before'=>'','asof'=>'']))?>" data-nav="blocks">Inspect blocks ↗</a></div><?php $rows=[];foreach(array_slice($v['blocks'],0,5) as $r){$rows[]=[da_destination($v,$r['destination']),da_link($v,$r['tracker']?:'Unknown',['tracker'=>$r['tracker'],'view'=>'rules']),da_num($r['clients']),da_num($r['n'])];}da_table(['Destination / recent DNS','Actual tracker','Sources','Logged packets'],$rows,default_desc:3); ?></div>
        </section>


        <?php endif; ?><?php if ($v['view']==='clients'): ?><section class="da-view" id="da-clients" data-panel="clients" aria-label="Clients"><div class="da-panel"><div class="da-panel-title"><div><h2>Client activity</h2><p>Top 100 logged source addresses · DNS and firewall columns are independently filtered</p></div></div><?php $rows=[];foreach($v['clients'] as $r){$rows[]=[da_link($v,$r['client'],['client'=>$r['client'],'view'=>'overview']),da_num($r['dns']),da_num($r['other_dns']??0),da_link($v,da_number($r['pass']),['client'=>$r['client'],'action'=>'','feed'=>'pass','view'=>'client'])+['order'=>$r['pass']],da_link($v,da_number($r['block']),['client'=>$r['client'],'action'=>'','feed'=>'block','view'=>'client'])+['order'=>$r['block']],da_time($r['latest'])];}da_table(['Client / source IP','DNS queries','Other DNS records','Pass packets','Block packets','Last observed'],$rows); ?><p class="da-footnote">Other DNS records are separate resolver reply, reply-log or policy-log observations; overlapping sources are not deduplicated. Source addresses remain as logged; NAT is not normalized. Friendly names use current local metadata and do not verify the device behind historical events.</p></div></section>
        <?php endif; ?><?php if ($v['view']==='domains'): ?><section class="da-view" id="da-domains" data-panel="domains" aria-label="Domains"><div class="da-panel"><div class="da-panel-title"><div><h2>DNS domains</h2><p>Top 100 names by observed query count</p></div><span class="da-pill da-neutral">Query visibility</span></div><?php $rows=[];foreach($v['domains'] as $r){$rows[]=[da_link($v,$r['domain'],['domain'=>$r['domain'],'view'=>'domains']),da_labels_cell($v,$r['domain']),da_num($r['n']),da_num($r['clients']),da_time($r['latest'])];}da_table(['DNS name','Review / tags','Queries','Clients','Last observed'],$rows,default_desc:2); ?><p class="da-footnote"><strong>DNS query totals.</strong> Click a name to inspect recorded DNS outcomes while retaining the client filter. Recent IP/name evidence does not prove an HTTPS hostname, a firewall decision or current table membership.</p></div><div class="da-panel"><div class="da-panel-title"><h2>Latest DNS queries</h2><span class="da-muted">Latest 100 retained records</span></div><?php $rows=[];foreach($v['dns'] as $r){$b=json_decode($r['body'],true);$rows[]=[da_time($r['time']),da_link($v,$r['client'],['client'=>$r['client'],'view'=>'domains']),da_link($v,$r['domain'],['domain'=>$r['domain'],'view'=>'domains']),$b['qtype']??'Unknown'];}da_table(['Time','Client','DNS name','Type'],$rows,default_desc:0); ?></div></section>
        <?php endif; ?><?php if ($v['view']==='activity'): ?><section class="da-view" id="da-activity" data-panel="activity" aria-label="Activity"><div class="da-panel"><div class="da-panel-title"><div><h2>Destination activity</h2><p>Top 100 destination / port / protocol groups</p></div></div><?php $rows=[];foreach($v['destinations'] as $r){$rows[]=[da_destination($v,$r['destination']),$r['port'],$r['protocol'],da_num($r['clients']),da_num($r['pass']),da_num($r['block'])];}da_table(['Destination / recent DNS','Port','Protocol','Sources','Pass packets','Block packets'],$rows); ?></div><div class="da-panel"><div class="da-panel-title"><h2>Latest firewall events</h2><span class="da-muted">Latest 100 retained records</span></div><?php $rows=[];foreach($v['traffic'] as $r){$b=json_decode($r['body'],true);$tracker=$b['tracker']??'';$detail=['Observed UTC'=>da_when($b['time']??null),'Logged source'=>$b['source']??'Unknown','Destination'=>$b['destination']??'Unknown','Port'=>$b['destination_port']??'Unknown','Protocol'=>$b['protocol']??'Unknown','Actual action'=>$b['action']??'Unknown','Actual tracker'=>$tracker?:'Unknown','Current rule label'=>da_recorded_rule_label($v,$tracker,$b['time']??null),'Interface / direction'=>($b['interface']??'').' '.($b['direction']??''),'Domain attribution'=>'Recent DNS names are destination context; the HTTPS hostname and the domain that caused this decision are unverified.','Meaning'=>'One logged packet, not a connection or an HTTP request. Current labels are not historical decision evidence.'];$rows[]=[da_time($b['time']??null),da_link($v,$b['source']??'Unknown',['client'=>$b['source']??'','view'=>'activity']),da_destination($v,$b['destination']??'',$b['destination_port']??null),['text'=>$b['action']??'Unknown','badge'=>$b['action']??''],da_link($v,$tracker?:'Unknown',['tracker'=>$tracker,'view'=>'rules']),['text'=>'Details','detail'=>$detail]];}da_table(['Time','Logged source','Destination / port','Decision','Actual tracker','Inspect'],$rows,compact_events:true,default_desc:0); ?></div></section>
        <?php endif; ?><?php if ($v['view']==='blocks'): ?><section class="da-view" id="da-blocks" data-panel="blocks" aria-label="Blocked"><div class="da-panel"><div class="da-panel-title"><div><h2>Blocked summary</h2><p>Top 100 destination / rule groups · includes logged fallback denies outside aliases</p></div><span class="da-pill da-block">Logged blocks</span></div><?php $rows=[];foreach($v['blocks'] as $r){$rows[]=[da_destination($v,$r['destination']),da_link($v,$r['tracker']?:'Unknown',['tracker'=>$r['tracker'],'view'=>'rules']),da_recorded_rule_label($v,$r['tracker'],$r['latest']),da_num($r['clients']),da_num($r['n']),da_time($r['latest'])];}da_table(['Destination / recent DNS','Actual tracker','Current rule label','Sources','Block packets','Last observed'],$rows,default_desc:4); ?><p class="da-footnote">A rule can block repeated packets for the same attempt. These counts are not unique connection attempts. Domain grouping requires trusted reply history.</p></div></section>
        <?php endif; ?><?php if ($v['view']==='rules'): ?><section class="da-view" id="da-rules" data-panel="rules" aria-label="Rules"><div class="da-panel"><div class="da-panel-title"><div><h2>Firewall rule counters</h2><p>Top <?=count($v['rules'])?> of <?=da_h($v['rules_total'])?> entries by bytes in the latest sample · whole-rule scope</p></div><span class="da-pill da-neutral">PF counters</span></div><p class="da-footnote">Sample <?=da_h(da_when($s['rules_observed_utc']??null))?>. Client, domain, destination, decision and event-window filters do not narrow these counters. Tracker applies.</p><?php $rows=[];foreach($v['rules'] as $r){$d=$r['interval_delta']??null;$rows[]=[da_link($v,$r['tracker']??'Unknown',['tracker'=>$r['tracker']??'','view'=>'activity']),$r['description']??'',da_num($r['packets']??null),['text'=>da_bytes($r['bytes']??null),'order'=>$r['bytes']??-1],['text'=>is_array($d)?da_bytes($d['bytes']??null):'New baseline','order'=>$d['bytes']??-1],da_num($r['states']??null)];}da_table(['Tracker','Current rule label','Packets since reset','Bytes since reset','Interval bytes','Current states'],$rows,default_desc:4); ?><p class="da-footnote">Reloads and detected resets establish a new baseline. Totals can overlap interfaces; adding them does not yield unique client traffic. Labels describe current rules, not historical labels.</p></div></section>
        <?php endif; ?><?php if ($v['view']==='aliases'): ?><section class="da-view" id="da-aliases" data-panel="aliases" aria-label="Aliases"><?php $aliasShown=false;if(function_exists('da_saved_aliases_render')){da_saved_aliases_render($v['saved_aliases']??[],$v['alias_service']??[],$v['can_control']??false,$v['alias_error']??'',$v['status']['rules']??[],$v['status']['rules_observed_utc']??null,$v['alias_members']??null,$v['window']??60);$aliasShown=true;}else $aliasShown=function_exists('da_trial_alias_render') && da_trial_alias_render($v['trial']??null);if(!$aliasShown): ?><div class="da-panel da-coming"><div class="da-symbol">◇</div><h2>DNS-fed alias test</h2><p>Use Prepare test above to review the approved names, source and port, then Start. One initial A/AAAA lookup per name seeds the alias through the trusted reply hook; later matching replies update it with their remaining TTLs.</p><p>Alias addresses and the block outcome appear here when a session runs. Continuous operation and saved ordinary aliases remain in development.</p></div><?php endif; ?><?php if(function_exists('da_policy_history_render') && !isset($_GET['block_name']) && !isset($_GET['edit_alias']) && !isset($_GET['inspect_alias']) && !isset($_GET['inspect_members']) && ($_GET['settings']??'')!=='1'){echo '<details class="da-alias-history"><summary>Earlier test sessions</summary>';da_policy_history_render($v);echo '</details>';} ?></section>
        <?php endif; ?><?php if ($v['view']==='coverage'): ?><section class="da-view" id="da-coverage" data-panel="coverage" aria-label="Coverage"><div class="da-panel"><div class="da-panel-title"><h2>Data coverage</h2><span class="da-pill <?=$fresh?'da-live':'da-warn'?>"><?=$fresh?'Recent status':'Stale / unavailable'?></span></div><div class="da-coverage-grid"><div><h3>DNS</h3><p>Trusted Unbound callbacks record typed replies while the feed runs. Existing query logs and optional pfBlockerNG reply/DNSBL logs supplement that history. A query log alone has no resolution outcome.</p></div><div><h3>Firewall</h3><p>Existing logged packets to TCP/UDP ports 80 and 443, plus separate whole-rule counters. Port numbers alone do not prove HTTP/HTTPS.</p></div><div><h3>Attribution</h3><p>Source addresses remain as logged; NAT is not normalized. Friendly names use current local metadata. DNS correlation is inferred. Shared CDN IPs cannot independently enforce hostnames.</p></div><div><h3>Retention</h3><p><?=da_h(da_number($v['retention']['n']??null))?> raw rows. Reporting limits from the collector: <?=da_h(da_number($s['storage']['event_limit']??null))?> events, <?=da_h(da_number($s['storage']['hourly']['group_limit']??null))?> hourly groups and <?=da_h(da_number(isset($s['storage']['database_byte_limit'])?$s['storage']['database_byte_limit']/1048576:null))?> MiB. Reports cover up to 24 hours.</p></div></div><p>Hourly summaries began <?=da_h(da_when($v['hourly_coverage']['first_event']??null))?>. Older events were not backfilled. Capacity removals: <?=da_h(da_number($v['hourly_coverage']['capacity_groups_removed']??null))?> groups / <?=da_h(da_number($v['hourly_coverage']['capacity_observations_removed']??null))?> observations.</p><p>Collection resumes at the ends of existing logs after restart. Existing logging determines coverage; absent records do not prove zero traffic. Packet counts and whole-rule bytes do not identify per-client connection totals or prove an alias caused a decision.</p><p class="da-footnote">Status updated <?=da_h(da_when($s['updated_utc']??null))?>. Statistics do not change traffic. Alias edits require firewall-editing access through the existing webConfigurator login.</p></div><?php da_reply_health_render($reply_health);da_retention($s); ?><div class="da-panel"><div class="da-panel-title"><h2>Recent continuity notices</h2><span class="da-muted">Latest 20 of up to 100 retained notices</span></div><?php $rows=[];foreach(array_slice(array_reverse($s['gaps']??[]),0,20) as $r){$rows[]=[da_time($r['time']??null),$r['source']??'',$r['reason']??''];}da_table(['Time','Source','Notice'],$rows); ?><p class="da-footnote">A continuity warning is uncertainty, not proof of lost events. Absence of warnings does not prove complete coverage.</p></div></section>
      <?php endif; ?><?php endif; ?></main></div>
      <dialog id="da-event-dialog"><div class="da-dialog-header"><div><div class="da-eyebrow">OBSERVATION DETAILS</div><h2>Event details</h2></div><button type="button" id="da-close-dialog" aria-label="Close event details">✕</button></div><dl id="da-event-fields"></dl><p class="da-footnote">Rule and source evidence stays separate from inferred domain attribution.</p></dialog>
      <?php da_labels_dialog_render($v); ?>
      <dialog id="da-policy-dialog" aria-labelledby="da-policy-title"><div class="da-dialog-header"><div><div class="da-eyebrow">CLIENT POLICY REVIEW</div><h2 id="da-policy-title">Review policy draft</h2></div><button type="button" id="da-close-policy" aria-label="Close policy review">✕</button></div><dl id="da-policy-fields"></dl><p class="da-notice" id="da-policy-impact"></p><p class="da-footnote">The selected source is a logged address; verify the device/interface before applying. Existing rule order, earlier denies and live states must be checked. Removing a name from an allowlist does not guarantee a block if another valid name still permits the same IP. Shared destination tables may be populated by any trusted client; the firewall rule limits the source.</p><div class="da-policy-buttons"><button type="button" class="da-primary" id="da-download-draft">Download draft</button><button type="button" disabled title="This draft action is outside the admitted named block controls">Apply unavailable</button></div><p class="da-footnote">This draft is saved only to your browser’s downloads and is not installed. Add DNS names through Aliases. Ordinary firewall rules decide sources, ports and pass/block. This IP-only draft is not applied.</p></dialog>
      <noscript><div class="da-notice">Navigation and filters work without JavaScript. Enable JavaScript for sorting, local timestamps and event details.</div></noscript>
    </section>
    <?php if(!$fragment)require __DIR__.'/client.php';
}
