<?php
/* Exact domain/IP inspection. Read-only bounded SQL; external links are opt-in. */
function da_callback_detail($b) {
    return ['Reply callback'=>$b['callback']??'Unknown','DNS return code'=>$b['result']??'UNKNOWN',
        'Code evidence'=>$b['rcode_basis']??'Unknown','Mapping status'=>$b['mapping_status']??'Unknown',
        'Qualified address mappings'=>isset($b['mapping_count'])?(string)$b['mapping_count']:'Not recorded',
        'Mapping coverage'=>($b['mapping_coverage_incomplete']??null)===true?'Incomplete':(($b['mapping_coverage_incomplete']??null)===false?'No gap reported for this observation':'Unknown'),
        'Answer detail status'=>$b['answer_detail_status']??'Not captured by this version',
        'Typed answer records'=>da_callback_answers($b),
        'Answer coverage'=>'Selected A/AAAA/CNAME before reply encoding; not proven client delivery or table leases',
        'Optional policy signal'=>$b['policy_signal']??'Unavailable',
        'Policy interpretation'=>'Neither a return code nor a registry match proves a DNS/firewall block or pass',
        'Profile'=>$b['profile_id']??'Unknown','Resolver generation'=>$b['resolver_generation']??'Unknown'];
}
function da_callback_answers($b,$limit=256) {
    $records=$b['answer_records']??[];
    if (!is_array($records) || count($records)>256) {return 'Unavailable';}
    $parts=[];
    foreach(array_slice($records,0,$limit) as $r) {
        if (!is_array($r) || !is_string($r['name']??null) || !is_string($r['value']??null) ||
            strlen($r['name'])>253 || strlen($r['value'])>253 || !in_array($r['type']??null,['A','AAAA','CNAME'],true)) {continue;}
        $parts[]=$r['type'].' '.$r['name'].' → '.$r['value'].' · RR expiry '.da_when($r['expires_utc']??null);
    }
    if(count($records)>$limit){$parts[]='+'.(count($records)-$limit).' records in DNS evidence';}
    return $parts?implode('; ',$parts):'No supported answer values captured';
}
function da_callback_result_label($b) {
    $code=$b['result']??'UNKNOWN';
    return $code==='NOERROR'?'DNS reply':'DNS reply · '.$code;
}
function da_callback_answer_cell($b,$include_query_type=false) {
    $records=$b['answer_records']??null;$addresses=[];$aliases=[];
    if(is_array($records)&&count($records)<=256)foreach($records as $r){
        if(!is_array($r)||!is_string($r['name']??null)||!is_string($r['value']??null)||
           strlen($r['name'])>253||strlen($r['value'])>253)continue;
        if(in_array($r['type']??null,['A','AAAA'],true))$addresses[$r['value']]=true;
        elseif(($r['type']??null)==='CNAME')$aliases[$r['name'].' '.$r['value']]=true;
    }
    $parts=[];$n=count($addresses);$a=count($aliases);
    if($n)$parts[]=$n.' '.($n===1?'address':'addresses');
    if($a)$parts[]=$a.' '.($a===1?'alias':'aliases');
    $text=$parts?implode(' · ',$parts):(($b['answer_detail_status']??null)==='no_supported_records_captured'?'No captured answers':'Answers unavailable');
    if($include_query_type)$text=($b['qtype']??'Unknown').' · '.$text;
    return ['text'=>$text,'hint'=>'DNS result: '.($b['result']??'UNKNOWN')."\n".da_callback_answers($b,4)."\nFull details: DNS evidence."];
}
function da_inspect_load($db,&$v,$query) {
    $v['inspect_events']=[];$v['inspect_clients']=[];$v['inspect_names']=[];$v['inspect_counts']=[];$v['next_cursor']=null;
    $v['callback_answers']=[];$v['callback_answers_ready']=false;
    $v['asof']=$v['now'];
    if (isset($query['asof'])) {
        if (!is_string($query['asof']) || !ctype_digit($query['asof']) || strlen($query['asof'])>10 || (int)$query['asof']>$v['now'] || (int)$query['asof']<$v['now']-86400) { throw new InvalidArgumentException('Refresh this inspection; its time cursor expired.'); }
        $v['asof']=(int)$query['asof'];
    }
    $domain=$v['view']==='domain';$target=$domain?$v['domain']:$v['destination'];
    if ($target==='') { return; }
    if ($domain && $target!=='.' && !preg_match('/^[a-z0-9_](?:[a-z0-9_.-]{0,251}[a-z0-9_])?$/D',$target)) { throw new InvalidArgumentException('Choose a valid exact DNS name.'); }
    $params=[':since'=>(int)($v['asof']-$v['window']*60),':until'=>(int)$v['asof'],':target'=>$target];
    $where='time>=:since AND time<=:until AND '.($domain?"domain=:target AND kind IN ('dns_query','dns_reply_log','dns_policy_log','dns_reply')":"kind='firewall_packet' AND json_extract(body,'$.destination')=:target AND json_extract(body,'$.destination_port') IN (80,443) AND json_extract(body,'$.protocol') IN ('tcp','udp')");
    // Domain navigation retains its explicit client filter. IP inspection
    // remains an all-client view; firewall trackers/actions do not scope DNS.
    $clientWhere=$domain&&($v['client']??'')!==''?' AND client=:client':'';
    if($clientWhere!==''){$where.=$clientWhere;$params[':client']=$v['client'];}
    $count=$domain?"sum(kind='dns_query') AS queries,sum(kind='dns_reply_log') AS replies,sum(kind='dns_reply') AS resolver_replies,sum(kind='dns_reply' AND json_extract(body,'$.answer_kind')='sinkhole') AS resolver_sinkholes,sum(kind='dns_policy_log') AS dnsbl,sum(kind='dns_reply_log' AND json_extract(body,'$.answer_kind')='sinkhole') AS sinkholes":"sum(action='pass') AS pass,sum(action='block') AS block";
    $counts=da_rows($db,'SELECT '.$count.',count(DISTINCT client) AS clients,count(*) AS n,min(time) AS oldest,max(time) AS newest FROM events WHERE '.$where,$params)[0];
    $v['inspect_counts']=$counts;$v['retention']=['oldest'=>$counts['oldest'],'newest'=>$counts['newest'],'n'=>$counts['n']];
    $v['inspect_clients']=da_rows($db,'SELECT client,'.$count.',max(time) AS latest FROM events WHERE '.$where.' GROUP BY client ORDER BY latest DESC,client LIMIT 100',$params);
    $v['callback_answers_ready']=(bool)da_rows($db,"SELECT 1 FROM sqlite_master WHERE type='table' AND name='reply_answers'",[]);
    if($v['callback_answers_ready']) {
        $v['callback_answers']=da_rows($db,'SELECT query,owner,rrtype,value,client,count(*) AS records,max(time) AS latest,max(expires_utc) AS furthest_expiry FROM reply_answers WHERE time>=:since AND time<=:until AND '.($domain?'query':'value').'=:target'.$clientWhere.' GROUP BY query,owner,rrtype,value,client ORDER BY latest DESC,query,owner,value,client LIMIT 50',$params);
    }
    if ($domain) {
        $v['inspect_names']=da_rows($db,"SELECT json_extract(body,'$.logged_answer') AS answer,json_extract(body,'$.qtype') AS qtype,json_extract(body,'$.reported_answer_type') AS reported_answer_type,count(*) AS records,count(DISTINCT client) AS clients,max(time) AS latest FROM events WHERE time>=:since AND time<=:until AND domain=:target AND kind IN ('dns_query','dns_reply_log','dns_policy_log','dns_reply') AND kind='dns_reply_log'".$clientWhere." GROUP BY answer,qtype,reported_answer_type ORDER BY latest DESC,answer LIMIT 50",$params);
    }
    $page=$where;
    if (isset($query['before'])) {
        if (!is_string($query['before']) || !preg_match('/^([0-9]{1,10}(?:\.[0-9]{1,17})?):([1-9][0-9]{0,17})$/D',$query['before'],$m) || (float)$m[1]>$v['asof']) { throw new InvalidArgumentException('Refresh this inspection; its event cursor is invalid.'); }
        $page.=' AND (time,id)<(:bt,:bi)';$params[':bt']=$m[1];$params[':bi']=(int)$m[2];
    }
    $rows=da_rows($db,'SELECT id,time,kind,client,domain,tracker,action,body FROM events WHERE '.$page.' ORDER BY time DESC,id DESC LIMIT 101',$params);
    if (count($rows)>100) { array_pop($rows);$last=$rows[count($rows)-1];$v['next_cursor']=sprintf('%.17g',$last['time']).':'.$last['id']; }
    $v['inspect_events']=$rows;
    if (!$domain) {
        $v['inspect_names']=da_rows($db,"SELECT domain,client,max(time) AS latest FROM events WHERE time>=:since AND time<=:until AND kind='dns_reply_log' AND json_extract(body,'$.logged_answer')=:target GROUP BY domain,client ORDER BY latest DESC LIMIT 50",array_intersect_key($params,array_flip([':since',':until',':target'])));
    }
}
function da_investigation_links($target,$kind) {
    if ($kind==='ip') {
        if (!filter_var($target,FILTER_VALIDATE_IP,FILTER_FLAG_NO_PRIV_RANGE|FILTER_FLAG_NO_RES_RANGE)) { return []; }
        $ip=inet_pton($target);
        // PHP's filters do not classify every non-global IPv4 range.
        if (strlen($ip)===4 && (ord($ip[0])===0 || ord($ip[0])>=224 || (ord($ip[0])===100 && (ord($ip[1])&192)===64))) { return []; }
        if (strlen($ip)===16 && (ord($ip[0])&224)!==32) { return []; }
        $encoded=rawurlencode($target);
        return ['Location / ASN · IPinfo'=>'https://ipinfo.io/'.$encoded,'Reputation · VirusTotal'=>'https://www.virustotal.com/gui/ip-address/'.$encoded,'Existing host report · Shodan'=>'https://www.shodan.io/host/'.$encoded];
    }
    if (!preg_match('/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/D',$target) || filter_var($target,FILTER_VALIDATE_IP)) { return []; }
    return ['Domain report · VirusTotal'=>'https://www.virustotal.com/gui/domain/'.rawurlencode($target)];
}
function da_inspect_render($v) {
    $domain=$v['view']==='domain';$target=$domain?$v['domain']:$v['destination'];$counts=$v['inspect_counts']??[];
    $scope=$domain&&($v['client']??'')!==''?'CLIENT '.da_client_label($v,$v['client']):'ALL OBSERVED CLIENTS';
    if($domain)$counts['sinkhole_records']=(int)($counts['resolver_sinkholes']??0)+(int)($counts['sinkholes']??0);
    ?>
    <section class="da-view da-visible da-inspect" data-panel="<?=da_h($v['view'])?>" aria-label="<?= $domain?'Domain':'IP' ?> inspect">
    <div class="da-panel"><div class="da-panel-title"><div><div class="da-eyebrow"><?= $domain?'DOMAIN':'DESTINATION IP' ?> INSPECT · <?=da_h($scope)?></div><h2><?=da_h($target?:'Choose a '.($domain?'DNS name':'destination IP'))?></h2><?php if($domain&&$target!=='')da_labels_cell_render(da_labels_cell($v,$target)); ?><p><?= $domain?'Exact name · queries and recorded DNS outcomes':'Logged TCP/UDP traffic on ports 80 and 443' ?></p></div><a href="<?=da_h(da_url($v,['view'=>$domain?'domains':'activity','domain'=>$domain?($v['list_domain']??''):'','destination'=>'','before'=>'','asof'=>'']))?>">Back to <?= $domain?'domains':'activity' ?> ↗</a></div>
    <?php if ($target===''): ?><p>Click a <?= $domain?'DNS name':'destination IP' ?> in an activity table to inspect it.</p></div><?php else: ?>
      <div class="da-cards da-client-cards"><?php foreach (($domain?['clients'=>'Observed clients','queries'=>'Query records','sinkhole_records'=>'Sinkhole reply records','dnsbl'=>'DNSBL block records']:['clients'=>'Observed clients','pass'=>'Passed packets','block'=>'Blocked packets']) as $key=>$label): ?><div class="da-card"><span><?=da_h($label)?></span><strong><?=da_h($v['errors']?'—':da_number($counts[$key]??0))?></strong><small>Retained records in this time window</small></div><?php endforeach; ?></div>
      <p class="da-footnote"><?= $domain?'A sinkhole means a recorded reply contained 0.0.0.0 or ::. DNSBL decisions are separate policy evidence. Missing reply records mean the outcome is unknown, not allowed. Reply records do not increase query counts.':'These are logged packets, not unique connections or HTTP requests. IP location is an estimate and does not identify the person or hostname using it.' ?></p>
      <?php if($domain): ?><p class="da-footnote">Sinkhole sources · Resolver callback records: <?=da_h(da_number($counts['resolver_sinkholes']??0))?> · Reply-log records: <?=da_h(da_number($counts['sinkholes']??0))?>. Sources may overlap; these are records, not unique queries or firewall blocks.</p><?php endif; ?>
      <?php $blockLink=$domain && function_exists('da_block_review_link')?da_block_review_link($v,$v['preparation']['profile']['client']??'',$target):null;
      if($blockLink!==null): ?><p><a class="da-detail" href="<?=da_h($blockLink['url'])?>"><?=da_h($blockLink['text'])?> &rarr;</a></p><?php endif; ?>
      <?php if($domain && function_exists('da_domain_aliases_render'))da_domain_aliases_render($v,$target); ?>
      <?php $links=da_investigation_links($target,$domain?'domain':'ip');if ($links): ?><div class="da-investigate"><?php foreach($links as $label=>$url): ?><a class="da-detail" href="<?=da_h($url)?>" target="_blank" rel="noopener noreferrer" referrerpolicy="no-referrer"><?=da_h($label)?> ↗</a><?php endforeach; ?></div><p class="da-footnote">External lookup opens only when clicked and sends this <?= $domain?'name':'IP' ?> to the selected provider. No automatic lookup, scan or submission is performed.</p><?php elseif (!$domain): ?><p class="da-footnote">Private, reserved and sinkhole addresses have no external location lookup.</p><?php endif; ?>
    </div><?php da_recent_names_render($v); ?><div class="da-panel"><div class="da-panel-title"><h2><?= $domain?'Who requested':'Who sent traffic to' ?> <?=da_h($target)?></h2><span class="da-muted">Up to 100 of <?=da_h(da_number($counts['clients']??0))?> observed clients</span></div><?php
      $rows=[];foreach($v['inspect_clients']??[] as $r) {
          $cells=[da_link($v,$r['client'],['client'=>$r['client'],'view'=>'client'])];
          foreach($domain?['queries','resolver_replies','resolver_sinkholes','replies','sinkholes','dnsbl']:['pass','block'] as $key) { $cells[]=da_num($r[$key]??0); }
          $cells[]=da_time($r['latest']);$rows[]=$cells;
      }
      da_table($domain?['Client','Queries','Resolver replies','Resolver sinkholes','Reply logs','Logged sinkholes','DNSBL blocks','Latest']:['Client','Pass packets','Block packets','Latest'],$rows,'da-inspect-table');
      ?></div><div class="da-panel"><div class="da-panel-title"><h2>Recent <?= $domain?'DNS':'firewall' ?> evidence</h2><span class="da-muted">Latest 100 · newest first</span></div><?php
      $rows=[];foreach($v['inspect_events']??[] as $r) {
          $b=json_decode($r['body'],true);$kind=$r['kind'];
          if ($domain) {
              $reply=$kind==='dns_reply_log';$callback=$kind==='dns_reply';$policy=$kind==='dns_policy_log';
              $result=$policy?'DNSBL blocked':($callback?da_callback_result_label($b):($reply?($b['result']??'Logged reply'):'Query observed'));
              $answer=$reply?da_logged_answer($b):($callback?da_callback_answer_cell($b):($policy?($b['policy_group']??'').' / '.($b['policy_feed']??''):'See separate answer records'));
              $detail=['Evidence source'=>$b['source']??'unbound_query_log','Client evidence'=>da_client_basis($r),'Meaning'=>$policy?'Policy log says blocked; no firewall decision or complete DNS reply is implied':($reply?'Selected answer text from pfBlockerNG log; not complete RRsets or verified rcode':'Query log has no answer field. Answers are separate records; no guessed query/reply pairing'),'Time basis'=>$b['time_basis']??(($reply||$policy)?'Year inferred from router local log time':'Timestamped query log'),'Lease source'=>'No; these records cannot populate PF tables'];
              if($callback){$detail['Meaning']='Resolver reply callback; client delivery and HTTPS hostname use unverified';$detail['Time basis']='Resolver callback UTC, qualified against monotonic receipt time';$detail+=da_callback_detail($b);}
              $rows[]=[da_time($r['time']),da_link($v,$r['client'],['client'=>$r['client'],'view'=>'client']),$b['qtype']??'Not recorded',['text'=>$result,'badge'=>$policy?'block':'neutral'],is_string($answer)&&filter_var($answer,FILTER_VALIDATE_IP)?da_link($v,$answer,['destination'=>$answer,'view'=>'ip']):$answer,['detail'=>$detail,'label'=>$callback?'DNS evidence':'Source']];
          } else {
              $rows[]=[da_time($r['time']),da_link($v,$r['client'],['client'=>$r['client'],'view'=>'client']),['text'=>$r['action']??'Unknown','badge'=>$r['action']??'neutral'],strtoupper($b['protocol']??'').' / '.($b['destination_port']??''),da_link($v,$r['tracker']?:'Unknown',['tracker'=>$r['tracker'],'view'=>'rules']),$b['interface']??''];
          }
      }
      da_table($domain?['Time','Client','Query type','Recorded result','Logged answer / policy','Evidence']:['Time','Client','Decision','Traffic','Actual tracker','Interface'],$rows,'da-inspect-table');
      ?><div class="da-pagination"><span><?=count($v['inspect_events']??[])?> shown</span><?php if($v['next_cursor']): ?><a href="<?=da_h(da_url($v,['before'=>$v['next_cursor'],'asof'=>(string)$v['asof']]))?>">Older evidence →</a><?php endif; ?></div>
      <p class="da-footnote">Collection starts at EOF; only retained observations are shown. No record does not prove no request. Optional pfBlockerNG logs may be absent or incomplete, and their yearless local timestamps are inferred conservatively.</p>
    </div>
    <?php endif; ?></section>
    <?php
}

function da_recent_names_render($v) {
    $domain=$v['view']==='domain';$rows=[];
    if($v['callback_answers_ready']??false) {
        echo '<div class="da-panel da-recent-mappings"><div class="da-panel-title"><h2>Resolver answer history</h2><span class="da-muted">Latest 50 groups · all observed clients</span></div>';
        foreach($v['callback_answers']??[] as $r) {
            $answer=filter_var($r['value'],FILTER_VALIDATE_IP)?da_link($v,$r['value'],['destination'=>$r['value'],'view'=>'ip']):da_link($v,$r['value'],['domain'=>$r['value'],'view'=>'domain']);
            $rows[]=[da_link($v,$r['query'],['domain'=>$r['query'],'view'=>'domain']),$r['owner'],$r['rrtype'],$answer,
                     da_link($v,$r['client'],['client'=>$r['client'],'view'=>'client']),da_num($r['records']),da_time($r['latest']),
                     is_numeric($r['furthest_expiry'])?da_time($r['furthest_expiry']):'Unavailable'];
        }
        da_table(['Query name','Answer owner','Type','Address / name','Client','Records','Latest','Furthest recorded RR expiry'],$rows,'da-inspect-table');
        echo '<p class="da-footnote">Typed A/AAAA/CNAME from trusted resolver callbacks before encoding; not proof of client delivery. Each record keeps its remaining expiry where qualified. These are historical RR observations, not current PF membership or CNAME-chain leases. Shared IPs do not prove HTTPS hostname use. The reporting history setting limits saved answer records. Older evidence can expire or be evicted.</p></div>';
        $rows=[];
    }
    echo '<div class="da-panel da-recent-mappings"><div class="da-panel-title"><h2>'.($domain?'Recent answers / names':'Recently resolved from these names').'</h2><span class="da-muted">Latest 50 groups · selected time window</span></div>';
    foreach($v['inspect_names']??[] as $r) {
        if($domain) {
            $answer=da_logged_answer(['logged_answer'=>$r['answer'],'qtype'=>$r['qtype'],'reported_answer_type'=>$r['reported_answer_type']]);
            $cell=filter_var($answer,FILTER_VALIDATE_IP)?da_link($v,$answer,['destination'=>$answer,'view'=>'ip']):$answer;
            if(!filter_var($answer,FILTER_VALIDATE_IP) && strtoupper($r['reported_answer_type']??'')==='CNAME' && preg_match('/^[a-z0-9_.-]+$/iD',$answer)){$cell=da_link($v,$answer,['domain'=>strtolower(rtrim($answer,'.')),'view'=>'domain']);}
            $rows[]=[$cell,$r['qtype']??'Unknown',$r['reported_answer_type']??'Unknown',da_num($r['clients']),da_num($r['records']),da_time($r['latest'])];
        } else {$rows[]=[da_link($v,$r['domain'],['domain'=>$r['domain'],'view'=>'domain']),da_link($v,$r['client'],['client'=>$r['client'],'view'=>'client']),da_time($r['latest'])];}
    }
    da_table($domain?['Logged address / name','Query type','Logged answer type','Clients','Records','Latest']:['DNS name','Logged client','Latest'],$rows,'da-inspect-table');
    echo '<p class="da-footnote">Selected reply-log evidence only, not a complete answer or CNAME chain. Historical mappings may have expired; these names are not assigned to the firewall events and do not prove HTTPS hostname usage. A sinkhole address is recorded as returned, not as a server contacted.</p></div>';
}
