<?php
/* Bounded client-first event reads; separate display-only DNS context. */
function da_client_load($db, &$v, $query) {
    $v['client_events']=[];$v['client_domains']=[];$v['dns_outcomes']=[];$v['next_cursor']=null;
    if ($v['client']==='') { return; }
    $v['client']=da_ip_canonical($v['client']);
    $v['feed']=is_string($query['feed']??null) && in_array($query['feed'],['all','pass','block','dns','dns_reply','dns_block'],true)?$query['feed']:'all';
    $v['asof']=$v['now'];
    if (isset($query['asof'])) {
        if (!is_string($query['asof']) || !ctype_digit($query['asof']) || strlen($query['asof'])>10 || (int)$query['asof']>$v['now'] || (int)$query['asof']<$v['now']-86400) { throw new InvalidArgumentException('Refresh this client view; its time cursor is invalid or expired.'); }
        $v['asof']=(int)$query['asof'];
    }
    $params=[':client'=>$v['client'],':since'=>(int)($v['asof']-$v['window']*60),':until'=>(int)$v['asof']];
    $base='client=:client AND time>=:since AND time<=:until';
    $dns="kind='dns_query'";
    $web="kind='firewall_packet' AND action IN ('pass','block') AND json_extract(body,'$.destination_port') IN (80,443) AND json_extract(body,'$.protocol') IN ('tcp','udp')";
    // Retain the constant scope for the optional partial index even when a
    // source-specific search narrows it. Legacy databases use the same results.
    $eligible='(('.$dns.') OR ('.$web.'))';
    // Filters belong to each source. A DNS-name search never hides unknown-IP blocks.
    if ($v['domain']!=='') { $dns.=' AND instr(lower(domain),:domain)>0';$params[':domain']=$v['domain']; }
    if ($v['tracker']!=='') { $web.=' AND tracker=:tracker';$params[':tracker']=$v['tracker']; }
    if ($v['destination']!=='') { $web.=" AND json_extract(body,'$.destination')=:destination";$params[':destination']=$v['destination']; }
    if ($v['action']!=='') { $web.=' AND action=:action';$params[':action']=$v['action']; }
    $visible=$eligible.' AND (('.$dns.') OR ('.$web.'))';
    $counts=da_rows($db,"SELECT COALESCE(sum(kind='dns_query'),0) AS dns,COALESCE(sum(kind='firewall_packet' AND action='pass'),0) AS pass,COALESCE(sum(kind='firewall_packet' AND action='block'),0) AS block,min(time) AS oldest,max(time) AS newest,count(*) AS n FROM events WHERE ".$base.' AND '.$visible,$params)[0];
    $v['counts']=['dns'=>$counts['dns'],'pass'=>$counts['pass'],'block'=>$counts['block'],'clients'=>$counts['n']?1:0];
    $v['retention']=['oldest'=>$counts['oldest'],'newest'=>$counts['newest'],'n'=>$counts['n']];
    $logParams=[':client'=>$v['client'],':since'=>$params[':since'],':until'=>$params[':until']];
    $logWhere=$base." AND kind IN ('dns_reply_log','dns_policy_log','dns_reply')";
    if($v['domain']!==''){$logWhere.=' AND instr(lower(domain),:domain)>0';$logParams[':domain']=$v['domain'];}
    $logCounts=da_rows($db,"SELECT sum(kind='dns_reply_log') AS replies,sum(kind='dns_reply') AS resolver_replies,sum(kind='dns_reply' AND json_extract(body,'$.answer_kind')='sinkhole') AS resolver_sinkholes,sum(kind='dns_policy_log') AS dnsbl,sum(kind='dns_reply_log' AND json_extract(body,'$.answer_kind')='sinkhole') AS sinkholes,min(time) AS oldest,max(time) AS newest,count(*) AS n FROM events WHERE ".$logWhere,$logParams)[0];
    $v['dns_outcomes']=$logCounts;
    if($logCounts['n']) {
        $v['counts']['clients']=1;$v['retention']['n']+=$logCounts['n'];
        $v['retention']['oldest']=$counts['oldest']===null?$logCounts['oldest']:min($counts['oldest'],$logCounts['oldest']);
        $v['retention']['newest']=$counts['newest']===null?$logCounts['newest']:max($counts['newest'],$logCounts['newest']);
    }
    // Annotated names narrow only visible DNS rows, never firewall events or totals.
    $labelParams=[];$labelClause=da_labels_clause($v,$labelParams);
    if($labelClause!==''){$visible.=" AND (kind='firewall_packet' OR (1".$labelClause.'))';$params+=$labelParams;$logWhere.=$labelClause;$logParams+=$labelParams;}
    if ($v['feed']==='dns') { $visible.=" AND kind='dns_query'"; }
    elseif ($v['feed']==='dns_reply') { $visible.=' AND 0'; }
    elseif ($v['feed']==='dns_block') { $visible.=' AND 0';$logWhere.=" AND (kind='dns_policy_log' OR json_extract(body,'$.answer_kind')='sinkhole')"; }
    elseif (in_array($v['feed'],['pass','block'],true)) { $visible.=" AND kind='firewall_packet' AND action=:feed";$params[':feed']=$v['feed']; }
    if (isset($query['before'])) {
        if (!is_string($query['before']) || !preg_match('/^([0-9]{1,10}(?:\.[0-9]{1,17})?):([1-9][0-9]{0,17})$/D',$query['before'],$m) || (float)$m[1]>$v['asof']) { throw new InvalidArgumentException('Refresh this client view; its event cursor is invalid.'); }
        $visible.=' AND (time,id)<(:before_time,:before_id)';
        $params[':before_time']=$m[1];$params[':before_id']=(int)$m[2];
        $logWhere.=' AND (time,id)<(:before_time,:before_id)';$logParams[':before_time']=$m[1];$logParams[':before_id']=(int)$m[2];
    }
    $rows=da_rows($db,'SELECT id,time,kind,client,domain,tracker,action,body FROM events WHERE '.$base.' AND '.$visible.' ORDER BY time DESC,id DESC LIMIT 101',$params);
    // Merge two independently indexed, bounded streams. Keeping the existing
    // web/query index avoids decoding all client packets to count DNS outcomes.
    if(in_array($v['feed'],['all','dns','dns_reply','dns_block'],true)) {
        $logs=da_rows($db,'SELECT id,time,kind,client,domain,tracker,action,body FROM events WHERE '.$logWhere.' ORDER BY time DESC,id DESC LIMIT 101',$logParams);
        $rows=array_merge($rows,$logs);usort($rows,fn($a,$b)=>($b['time']<=>$a['time'])?:($b['id']<=>$a['id']));$rows=array_slice($rows,0,101);
    }
    if (count($rows)>100) {
        array_pop($rows);$last=$rows[count($rows)-1];
        $v['next_cursor']=sprintf('%.17g',$last['time']).':'.$last['id'];
    }
    $v['client_events']=$rows;
    // No aggregate scan of every client, destination, rule or hourly bucket on this path.
}
function da_policy_review($client,$kind,$target,$tracker='',$port=null,$protocol=null,$view=[]) {
    // A shared destination alias has no source-client scope. Use the existing
    // exact-name prefill validator, including supported local/service names;
    // an inert editor link neither creates a rule nor attributes a DNS source.
    if($kind==='domain'&&function_exists('da_saved_aliases_render')&&function_exists('da_block_review_link')){
        if(!empty($view['can_control'])&&(!is_string($target)||preg_match('/[\x00-\x1f\x7f]/',$target)))return ['text'=>'No exact DNS name'];
        $link=da_block_review_link($view,$client,$target);
        return $link??['text'=>empty($view['can_control'])?'Read-only access':'No exact DNS name'];
    }
    if (!filter_var($client,FILTER_VALIDATE_IP)) { return ['text'=>'Select one client']; }
    if (da_loopback($client)) { return ['text'=>'Origin unverified; policy unavailable']; }
    if ($kind==='domain') {
        $target=strtolower(rtrim($target,'.'));
        if (strlen($target)>253 || !preg_match('/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/D',$target) || filter_var($target,FILTER_VALIDATE_IP)) { return ['text'=>'No valid policy name']; }
    } elseif ($kind==='ip') {
        if (!filter_var($target,FILTER_VALIDATE_IP) || !in_array($port,[80,443],true) || !in_array($protocol,['tcp','udp'],true)) { return ['text'=>'No qualified destination']; }
    } else { return ['text'=>'Unknown target']; }
    if($kind==='domain' && function_exists('da_block_review_link')) {
        $link=da_block_review_link($view,$client,$target);
        if($link!==null) {return $link;}
    }
    return ['review'=>['client'=>$client,'target_type'=>$kind,'target'=>$target,'tracker'=>$tracker,'port'=>$port,'protocol'=>$protocol]];
}
function da_client_render($v,$compact_events=true) {
    ?>
    <section class="da-view da-visible" id="da-client" data-client="<?=da_h($v['client'])?>" data-panel="client" aria-label="Client inspect">
      <div class="da-panel"><div class="da-panel-title"><div><div class="da-eyebrow">CLIENT INSPECT</div><h2 data-client-ip="<?=da_h($v['client'])?>"><?=da_h($v['client']?da_client_label($v,$v['client']):'Choose a client')?></h2><p>Recent DNS evidence and logged web traffic in one timeline</p></div><a href="<?=da_h(da_url($v,['client'=>'','view'=>'clients','before'=>'','asof'=>'','domain'=>'','tracker'=>'','destination'=>'','action'=>'']))?>">Choose another client ↗</a></div>
      <?php if ($v['client']===''): ?><p>Select a client from Clients or enter its IP above.</p><?php else: ?>
      <div id="da-client-identity" data-client="<?=da_h($v['client'])?>"><?php da_client_identity_render($v,$v['client']); ?></div>
      <div class="da-cards da-client-cards"><?php foreach (['dns'=>'DNS queries','pass'=>'Passed packets','block'=>'Blocked packets'] as $key=>$label): ?><a class="da-card da-card-<?=$key?>" href="<?=da_h(da_url($v,['view'=>'client','feed'=>$key,'before'=>'','asof'=>'']))?>"><span><?=$label?></span><strong><?=da_h($v['errors']?'—':da_number($v['counts'][$key]??0))?></strong><small>Selected client and time window</small></a><?php endforeach; ?></div>
      <p class="da-footnote">Recorded DNS outcomes: <?=da_h(da_number($v['dns_outcomes']['resolver_replies']??0))?> resolver replies (<?=da_h(da_number($v['dns_outcomes']['resolver_sinkholes']??0))?> with sinkholes) · <?=da_h(da_number($v['dns_outcomes']['replies']??0))?> reply logs · <?=da_h(da_number($v['dns_outcomes']['sinkholes']??0))?> logged sinkholes · <?=da_h(da_number($v['dns_outcomes']['dnsbl']??0))?> DNSBL blocks. Sources may observe the same reply; these counts are separate and do not increase query or firewall packet counts.</p>
      <div class="da-feed-filters" aria-label="Client timeline decision"><?php foreach (['all'=>'All activity','block'=>'Firewall blocked','pass'=>'Firewall passed','dns'=>'DNS evidence','dns_reply'=>'Answers / DNSBL','dns_block'=>'DNS blocked / sinkhole'] as $key=>$label): ?><a class="da-feed-link" <?=($v['feed']??'all')===$key?'aria-current="true"':''?> href="<?=da_h(da_url($v,['view'=>'client','feed'=>$key,'before'=>'','asof'=>'']))?>"><?=$label?></a><?php endforeach; ?><span class="da-muted">Newest first · up to 100 records</span></div><p class="da-feed-status" role="status" aria-live="polite"></p>
      <p class="da-footnote">DNS queries are shown separately from firewall decisions. Click a name for DNS evidence while retaining the selected client. Clear the client filter to inspect all clients. Resolver replies do not prove delivery or firewall permission; an IP block is never assigned to a nearby query just because their times match. Add to DNS alias opens the shared alias editor with this exact name. Existing ordinary firewall rules decide which sources pass or block; adding a name does not create a rule. IP-only actions remain unapplied drafts.</p>
      </div><div class="da-panel"><?php
      $rows=[];
      foreach ($v['client_events'] as $r) {
          $b=json_decode($r['body'],true);$dns=$r['kind']!=='firewall_packet';$reply=$r['kind']==='dns_reply_log';$callback=$r['kind']==='dns_reply';$policy=$r['kind']==='dns_policy_log';$tracker=$r['tracker']??'';
          $meaning=$policy?'Explicit DNSBL log decision; not a firewall block':($callback?'Resolver reply callback; client delivery and HTTPS use unverified. DNS return codes are not policy decisions.':($reply?'Selected logged answer; not a complete RRset or verified rcode':($dns?'Query observed; this log has no answer field. See Answers / DNSBL for separately recorded outcomes':'Logged firewall packet; recent DNS names are context, not a verified hostname')));
          $detail=['Observed UTC'=>da_when($r['time']),'Client / logged source'=>$r['client'],'Client evidence'=>da_client_basis($r),'Evidence'=>$meaning,'Source'=>$b['source']??($dns?'unbound_query_log':'filterlog'),'Logged answer'=>$reply?da_logged_answer($b):'Not attached','DNSBL policy'=>$policy?($b['policy_group']??'').' / '.($b['policy_feed']??''):'Unknown','Actual tracker'=>$tracker?:'Not recorded','Current rule label'=>da_recorded_rule_label($v,$tracker,$r['time']),'Interface / direction'=>($b['interface']??'').' '.($b['direction']??''),'Policy status'=>'Observation only; drafts do not change traffic'];
          $target=$dns?($r['domain']??''):($b['destination']??'');
          if($callback){$detail+=da_callback_detail($b);}
          $result=$policy?'DNSBL blocked':($callback?da_callback_result_label($b):($reply?($b['result']??'Logged reply'):($dns?'DNS query':ucfirst($r['action']??'Unknown'))));
          $type=$policy?'Policy log':($dns?($b['qtype']??'Unknown'):strtoupper($b['protocol']??'').' / '.($b['destination_port']??''));
          if($reply){$type.=' → '.da_logged_answer($b);}
          if($callback){$type=da_callback_answer_cell($b,true);}
          $rows[]=[da_time($r['time']),['text'=>$result,'badge'=>$policy?'block':($dns?'neutral':($r['action']??'neutral'))],($dns?da_link($v,$target,['domain'=>$target,'view'=>'domain']):da_destination($v,$target)),$type,$dns?'No rule attached':((($ruleLabel=da_recorded_rule_label($v,$tracker,$r['time']))!=='Unavailable'?$ruleLabel.' / ':'').($tracker?:'Unknown')),['detail'=>$detail,'label'=>$dns?'DNS evidence':'Rule / evidence'],$dns?da_labels_cell($v,$target):['text'=>''],da_policy_review($r['client'],$dns?'domain':'ip',$target,$tracker,$b['destination_port']??null,$b['protocol']??null,$v)];
      }
      da_table(['Time','Result','DNS name / destination IP','Type / port','Actual rule','Attribution','Review / tags','Quick action'],$rows,'da-client-timeline',$compact_events);
      ?><div class="da-pagination"><a href="<?=da_h(da_url($v,['before'=>'','asof'=>'']))?>">Latest activity</a><?php if ($v['next_cursor']!==null): ?><a class="da-feed-link" href="<?=da_h(da_url($v,['before'=>$v['next_cursor'],'asof'=>(string)$v['asof']]))?>">Older activity →</a><?php endif; ?></div><p class="da-footnote">Includes logged fallback blocks outside alias rules. Recent DNS names are context from retained answers, not a hostname verdict. A shared CDN IP may serve many names; an IP policy affects all of them. Packet counts are not HTTP requests or connections.</p>
      <?php endif; ?></div>
    </section>
    <?php
}
