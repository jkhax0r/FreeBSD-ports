<?php
/* Saved DNS alias configuration. Called by the authenticated page or local CLI.
 * Alias creation never adds a firewall rule. Native rules reference da_<name>.
 * Names live in config.xml; no IPs or DNS leases are saved in configuration.
 */
require_once __DIR__.'/aliases.php';
const DNSALIAS_SEED='da_dnsalias_seed';
function dnsalias_seed_definition(): array {
    return ['name'=>DNSALIAS_SEED,'type'=>'host','descr'=>'DNS Alias internal empty definition; never populate','address'=>'','detail'=>''];
}
function dnsalias_seed_owner(): ?array {
    $raw=config_get_path('installedpackages/dnsalias/seed_json','');
    if($raw==='')return null;
    if(!is_string($raw)||strlen($raw)>4096)throw new RuntimeException('Invalid seed ownership record');
    $v=json_decode($raw,true,8,JSON_THROW_ON_ERROR);
    if($v!==['format'=>'dnsalias-native-seed-1','alias'=>dnsalias_seed_definition()])throw new RuntimeException('Seed ownership record changed');
    return $v['alias'];
}
function dnsalias_seed_record(): void {
    config_set_path('installedpackages/dnsalias/seed_json',json_encode(['format'=>'dnsalias-native-seed-1','alias'=>dnsalias_seed_definition()],JSON_THROW_ON_ERROR));
}
function dnsalias_seed_register_legacy(): bool {
    $p=dnsalias_policies_read();dnsalias_policies_check($p);
    if(dnsalias_seed_owner()!==null)return false;
    if(!$p)throw new RuntimeException('Existing saved DNS aliases required for explicit legacy seed registration');
    $expected=[DNSALIAS_SEED=>dnsalias_seed_definition()];foreach($p as $v)$expected['da_'.$v['name']]=dnsalias_policies_expected($v);
    foreach(config_get_path('aliases/alias',[]) as $a)if(isset($expected[$a['name']??''])){
        if($a!==$expected[$a['name']])throw new RuntimeException('Legacy alias definition changed');unset($expected[$a['name']]);
    }
    if($expected)throw new RuntimeException('Incomplete legacy alias set');
    dnsalias_seed_record();$written=write_config('DNS Alias: register legacy seed ownership -NoReMoTeBaCkUp',true,true);
    if($written===false||$written===-1)throw new RuntimeException('Seed ownership save failed; inspect before retrying');
    return true;
}
function dnsalias_service_enabled(): bool {
    return config_get_path('installedpackages/dnsalias/config/0/enable','on')==='on';
}
function dnsalias_service_definition(): array {
    return ['name'=>'dnsalias','description'=>'DNS Alias: trusted DNS destination tables and activity',
        'rcfile'=>'dnsalias.sh','executable'=>'',
        'custom_php_service_status_command'=>"isvalidpid('/var/db/dnsalias/collector.pid') && (config_get_path('installedpackages/dnsalias/policy_json','[]') === '[]' || isvalidpid('/var/db/dnsalias/alias-service.pid'))"];
}
function dnsalias_service_save(bool $enabled): void {
    $services=config_get_path('installedpackages/service',[]);$expected=dnsalias_service_definition();$found=false;
    foreach($services as $s)if(strcasecmp($s['name']??'','dnsalias')===0){
        if($s!=$expected||$found)throw new RuntimeException('DNS Alias service registration changed; inspect before saving');$found=true;
    }
    if(!$found)$services[]=$expected;
    config_set_path('installedpackages/service',$services);
    config_set_path('installedpackages/dnsalias/config/0/enable',$enabled?'on':'off');
    $written=write_config('DNS Alias: service settings -NoReMoTeBaCkUp',true,true);
    if($written===false||$written===-1)throw new RuntimeException('Service settings save failed; inspect before retrying');
}
function dnsalias_service_remove(): bool {
    if(dnsalias_policies_read())throw new RuntimeException('Delete saved DNS aliases before uninstalling; firewall references must be removed by their owner');
    if(dnsalias_seed_owner()!==null)throw new RuntimeException('Remove the owned unused seed before unregistering this service');
    $services=config_get_path('installedpackages/service',[]);$kept=[];$found=false;
    foreach($services as $s){
        if(strcasecmp($s['name']??'','dnsalias')!==0){$kept[]=$s;continue;}
        if($s!=dnsalias_service_definition()||$found)throw new RuntimeException('DNS Alias service registration changed; inspect before uninstalling');
        $found=true;
    }
    if(!$found)return false;
    config_set_path('installedpackages/service',$kept);
    $written=write_config('DNS Alias: unregister service -NoReMoTeBaCkUp',true,true);
    if($written===false||$written===-1)throw new RuntimeException('Service removal save failed; inspect before retrying');
    return true;
}
function dnsalias_policies_read(): array {
    $raw=config_get_path('installedpackages/dnsalias/policy_json','');
    if($raw==='')return [];
    if(!is_string($raw)||strlen($raw)>262144||!str_starts_with(ltrim($raw),'['))throw new RuntimeException('Saved policy list or size invalid');
    static $lastRaw=null,$lastPolicies=[];
    if($raw===$lastRaw)return $lastPolicies;
    $v=json_decode($raw,true,16,JSON_THROW_ON_ERROR);
    if(!is_array($v)||!array_is_list($v)||count($v)>127)throw new RuntimeException('Invalid saved policy list');
    $seen=[];
    foreach($v as $p){
        if(!is_array($p)||array_diff(array_keys($p),['name','names','enabled'])||count($p)!==3||
           !is_string($p['name'])||!preg_match('/^[a-z][a-z0-9_]{0,22}$/D',$p['name'])||
           str_starts_with($p['name'],'seed')||str_starts_with($p['name'],'mvp_')||isset($seen[$p['name']])||
           !is_bool($p['enabled'])||!is_array($p['names'])||!array_is_list($p['names'])||count($p['names'])<1||count($p['names'])>2048)
            throw new RuntimeException('Invalid saved alias policy');
        $seen[$p['name']]=true;$patterns=[];
        foreach($p['names'] as $n){
            if(!is_string($n)||strlen($n)>255||!preg_match('/^(?:\*\.)?[a-z0-9_-]+(?:\.[a-z0-9_-]+)*$/D',$n)||isset($patterns[$n]))throw new RuntimeException('Invalid or duplicate DNS pattern');
            $domain=str_starts_with($n,'*.')?substr($n,2):$n;
            if(strlen($domain)>253)throw new RuntimeException('DNS name too long');
            foreach(explode('.',$domain) as $label)if(strlen($label)>63)throw new RuntimeException('DNS label too long');
            $patterns[$n]=true;
        }
    }
    $lastRaw=$raw;$lastPolicies=$v;
    return $v;
}
function dnsalias_policies_expected(array $p): array {
    return ['name'=>'da_'.$p['name'],'type'=>'host','descr'=>'DNS Alias: '.$p['name'],'address'=>DNSALIAS_SEED,'detail'=>''];
}
function dnsalias_registered_mode(): bool {
    $mode=config_get_path('installedpackages/dnsalias/native_alias_mode','legacy');
    if(!in_array($mode,['legacy','registered-v1'],true))throw new RuntimeException('Unknown native alias mode');
    return $mode==='registered-v1';
}
function dnsalias_registry_check(array $policies): void {
    $state=$GLOBALS['dnsalias_registry_status']??null;
    if(($state['state']??null)!=='registered'||($state['format']??null)!=='dnsalias-native-registry-status-1'||
       ($state['root']??null)!==dirname(__DIR__)||($state['data']??null)!=='/var/db/dnsalias'||
       ($state['entry_module_sha256']??null)!==hash_file('sha256',__DIR__.'/registry.php')||
       !function_exists('dnsalias_registry_definitions')||!function_exists('get_reserved_table_names'))
        throw new RuntimeException('Owned native DNS registry is unavailable or differs from source');
    $definitions=dnsalias_registry_definitions($policies);$reserved=get_reserved_table_names();
    if($state['definitions']!==$definitions||$state['policies']!==$policies)throw new RuntimeException('Native DNS registry policy snapshot changed');
    foreach($definitions as $name=>$definition)if(($reserved[$name]??null)!==$definition)throw new RuntimeException('Native DNS registry definition changed');
    foreach(config_get_path('aliases/alias',[]) as $alias)
        if(isset($definitions[strtolower($alias['name']??'')])||strtolower($alias['name']??'')===DNSALIAS_SEED)
            throw new RuntimeException('Registered DNS aliases have conflicting saved native definitions');
    if(config_get_path('installedpackages/dnsalias/seed_json','')!=='')throw new RuntimeException('Registered DNS aliases retain legacy seed metadata');
}
function dnsalias_policies_check(array $policies): void {
    if(dnsalias_registered_mode()){dnsalias_registry_check($policies);return;}
    $aliases=config_get_path('aliases/alias',[]);$by=[];
    foreach($aliases as $a){if(isset($by[strtolower($a['name'])]))throw new RuntimeException('Duplicate native alias');$by[strtolower($a['name'])]=$a;}
    $seed_owner=dnsalias_seed_owner();
    if($seed_owner!==null&&($by[DNSALIAS_SEED]??null)!==$seed_owner)throw new RuntimeException('Owned native seed changed');
    if($policies && (($by[DNSALIAS_SEED]['type']??null)!=='host'||($by[DNSALIAS_SEED]['address']??null)!==''))throw new RuntimeException('DNS Alias seed changed');
    foreach($policies as $p){$a=$by['da_'.$p['name']]??null;
        if(!is_array($a)||($a['type']??null)!=='host'||($a['address']??null)!==DNSALIAS_SEED)throw new RuntimeException('Native alias changed: da_'.$p['name']);
    }
}
function dnsalias_policies_save(string $name,array $names,bool $enabled): void {
    if(!preg_match('/^[a-z][a-z0-9_]{0,22}$/D',$name)||str_starts_with($name,'seed')||str_starts_with($name,'mvp_'))throw new RuntimeException('Use a lowercase alias identifier, up to 23 characters');
    $normalized=[];
    foreach($names as $n){if(!is_string($n))throw new RuntimeException('DNS name required');$n=strtolower(rtrim(trim($n),'.'));if($n!=='')$normalized[$n]=true;}
    $names=array_keys($normalized);
    if(count($names)>2048)throw new RuntimeException('An alias accepts up to 2,048 distinct names or wildcard patterns');
    $policies=dnsalias_policies_read();dnsalias_policies_check($policies);
    $index=null;foreach($policies as $i=>$p)if($p['name']===$name)$index=$i;
    $new=['name'=>$name,'names'=>$names,'enabled'=>$enabled];
    if($index===null)$policies[]=$new;else $policies[$index]=$new;
    // Validate the complete candidate before mutating native configuration.
    $old=config_get_path('installedpackages/dnsalias/policy_json','');
    config_set_path('installedpackages/dnsalias/policy_json',json_encode($policies,JSON_THROW_ON_ERROR));
    try{dnsalias_policies_read();}finally{config_set_path('installedpackages/dnsalias/policy_json',$old);}
    if(dnsalias_registered_mode()){
        $occupied=[];foreach(get_reserved_table_names() as $a)$occupied[strtolower($a['name'])]=true;
        foreach(config_get_path('aliases/alias',[]) as $a)$occupied[strtolower($a['name'])]=true;
        if($index===null&&isset($occupied['da_'.$name]))throw new RuntimeException('Native alias namespace already in use');
        config_set_path('installedpackages/dnsalias/policy_json',json_encode($policies,JSON_THROW_ON_ERROR));
        $written=write_config('DNS Alias: save da_'.$name.' -NoReMoTeBaCkUp',true,true);
        if($written===false||$written===-1)throw new RuntimeException('Native configuration save failed; inspect before retrying');
        dnsalias_registry_update_after_save($policies);return;
    }
    $aliases=config_get_path('aliases/alias',[]);$found=false;$seed=false;$seed_owner=dnsalias_seed_owner();
    foreach($aliases as $a){
        if(strcasecmp($a['name'],'da_'.$name)===0){
            if(($a['type']??null)!=='host'||($a['address']??null)!==DNSALIAS_SEED)throw new RuntimeException('Alias name already in use');
            if($index===null)throw new RuntimeException('Native alias already exists outside saved DNS aliases');
            $found=true;
        }
        if(strcasecmp($a['name'],DNSALIAS_SEED)===0){
            if($seed_owner===null)throw new RuntimeException('Existing seed has no ownership record; inspect or explicitly register the legacy set');
            if($a!==$seed_owner)throw new RuntimeException('Seed name already in use');$seed=true;
        }
    }
    if(!$seed){if($seed_owner!==null)throw new RuntimeException('Owned seed missing; inspect before saving');$aliases[]=dnsalias_seed_definition();}
    if(!$found)$aliases[]=dnsalias_policies_expected($new);
    config_set_path('aliases/alias',$aliases);
    if(!$seed)dnsalias_seed_record();
    config_set_path('installedpackages/dnsalias/policy_json',json_encode($policies,JSON_THROW_ON_ERROR));
    $written=write_config('DNS Alias: save da_'.$name.' -NoReMoTeBaCkUp',true,true);
    if($written===false||$written===-1)throw new RuntimeException('Native configuration save failed; inspect before retrying');
}
function dnsalias_policies_snapshot(): array {
    $p=dnsalias_policies_read();dnsalias_policies_check($p);
    return ['format'=>'dnsalias-saved-aliases-1','policies'=>$p];
}
if(PHP_SAPI==='cli' && realpath($_SERVER['SCRIPT_FILENAME']??'')===__FILE__){
    require_once '/etc/inc/globals.inc';require_once '/etc/inc/config.inc';
    try{
        if(($argv[1]??'')==='register-service'){dnsalias_service_save(dnsalias_service_enabled());echo json_encode(['registered'=>true]);}
        elseif(($argv[1]??'')==='register-seed-legacy')echo json_encode(['registered'=>dnsalias_seed_register_legacy()]);
        elseif(($argv[1]??'')==='unregister-service')echo json_encode(['removed'=>dnsalias_service_remove()]);
        elseif(($argv[1]??'')==='service-enabled')echo json_encode(dnsalias_service_enabled());
        elseif(($argv[1]??'')==='plain-first-apply'){
            // Called once after the owned first selection by the root service.
            // Suppress the unrelated DHCP restart; create no firewall rule.
            if(!config_path_enabled('unbound','python')||config_get_path('unbound/python_script')!=='dnsalias_unbound')throw new RuntimeException('Owned plain selection required');
            if(file_exists('/var/unbound/dnsalias_unbound_include.inc')||is_link('/var/unbound/dnsalias_unbound_include.inc'))throw new RuntimeException('Unowned native include requires inspection');
            require_once '/etc/inc/functions.inc';require_once '/etc/inc/services.inc';require_once '/etc/inc/system.inc';
            $r=services_unbound_configure(false);echo json_encode(['return'=>$r],JSON_THROW_ON_ERROR);exit($r===0?0:1);
        }
        else echo json_encode(dnsalias_policies_snapshot(),JSON_THROW_ON_ERROR);
    }catch(Throwable $e){fwrite(STDERR,$e->getMessage());exit(1);}
}
