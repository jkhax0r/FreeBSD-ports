<?php
/* Ordinary saved pfSense block rules. Pure construction; no configuration or PF
 * reads/writes, activation, commands or timer. The caller supplies a freshly
 * admitted native interface, registered alias and collision-checked trackers.
 * These rules are normal user configuration and remain editable in the GUI.
 */
function dnsalias_native_block_rules(array $policy,array $trackers,array $occupied_trackers): array {
    $fields=['name','alias','client','interface','port'];$keys=array_keys($policy);sort($fields);sort($keys);
    if($fields!==$keys || !is_string($policy['name']) || !preg_match('/^[a-z][a-z0-9_]{0,22}$/D',$policy['name']) ||
       $policy['alias']!=='da_'.$policy['name'] || !is_string($policy['client']) ||
       !filter_var($policy['client'],FILTER_VALIDATE_IP) || inet_ntop(inet_pton($policy['client']))!==$policy['client'] ||
       !is_string($policy['interface']) || !preg_match('/^[a-z][a-z0-9_]{0,31}$/D',$policy['interface']) ||
       !in_array($policy['port'],[80,443,'web'],true)) {
        throw new InvalidArgumentException('Exact registered alias, canonical source and native interface required');
    }
    $ports=$policy['port']==='web'?[80,443]:[$policy['port']];
    if(!array_is_list($trackers) || count($trackers)!==count($ports) || count(array_unique($trackers))!==count($trackers) ||
       !array_is_list($occupied_trackers) || count($occupied_trackers)>10000) {
        throw new InvalidArgumentException('Distinct explicit native rule identities required');
    }
    foreach([...$trackers,...$occupied_trackers] as $tracker) {
        if(!is_string($tracker) || !preg_match('/^[1-9][0-9]{0,9}$/D',$tracker) || (int)$tracker>4294967295) {
            throw new InvalidArgumentException('Canonical native tracker required');
        }
    }
    if(array_intersect($trackers,$occupied_trackers)) {throw new InvalidArgumentException('Existing tracker collision; no overwrite');}
    $rules=[];
    foreach($ports as $i=>$port) {
        $rules[]=['type'=>'block','interface'=>$policy['interface'],
            'ipprotocol'=>str_contains($policy['client'],':')?'inet6':'inet','protocol'=>'tcp/udp',
            'source'=>['address'=>$policy['client']],'destination'=>['address'=>$policy['alias'],'port'=>(string)$port],
            'log'=>'','descr'=>'DNS Alias / '.$policy['name'].' / '.($port===80?'HTTP':'HTTPS'),
            'tracker'=>$trackers[$i]];
    }
    return $rules;
}
