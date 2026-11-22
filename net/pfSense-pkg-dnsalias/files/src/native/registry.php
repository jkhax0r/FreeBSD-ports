<?php
/* Inactive until an owned parse_config entry explicitly selects registered-v1.
 * Uses native request-local reserved tables. No core patches, config writes,
 * commands, address files, PF writes, service operations or DNS callbacks.
 *
 * The fixed ASCII-space value selects this native version's persistent empty
 * table branch without queuing a later flush. It exists only in this request;
 * it is neither a user-saved value nor a learned address. The compatibility
 * contract must be requalified when native alias generation changes.
 */
function dnsalias_registry_policies($raw): array {
    if(!is_string($raw)||strlen($raw)>262144||!str_starts_with(ltrim($raw),'['))throw new RuntimeException('Bounded saved DNS policy list required');
    // A request may parse the same saved configuration several times. Retain
    // only a completely validated value and compare its exact source bytes.
    static $lastRaw=null,$lastPolicies=[];
    if($raw===$lastRaw)return $lastPolicies;
    $policies=json_decode($raw,true,16,JSON_THROW_ON_ERROR);
    if(!is_array($policies)||!array_is_list($policies)||count($policies)>127)throw new RuntimeException('Invalid saved DNS policies');
    $seen=[];
    foreach($policies as $policy){
        if(!is_array($policy)||array_diff(array_keys($policy),['name','names','enabled'])||count($policy)!==3||
           !is_string($policy['name'])||!preg_match('/^[a-z][a-z0-9_]{0,22}$/D',$policy['name'])||
           str_starts_with($policy['name'],'seed')||str_starts_with($policy['name'],'mvp_')||isset($seen[$policy['name']])||
           !is_bool($policy['enabled'])||!is_array($policy['names'])||!array_is_list($policy['names'])||
           count($policy['names'])<1||count($policy['names'])>2048)throw new RuntimeException('Invalid saved DNS policy');
        $seen[$policy['name']]=true;$names=[];
        foreach($policy['names'] as $name){
            if(!is_string($name)||strlen($name)>255||!preg_match('/^(?:\*\.)?[a-z0-9_-]+(?:\.[a-z0-9_-]+)*$/D',$name)||isset($names[$name]))throw new RuntimeException('Invalid DNS pattern');
            $domain=str_starts_with($name,'*.')?substr($name,2):$name;
            if(strlen($domain)>253)throw new RuntimeException('DNS name too long');
            foreach(explode('.',$domain) as $part)if(strlen($part)>63)throw new RuntimeException('DNS label too long');
            $names[$name]=true;
        }
    }
    $lastRaw=$raw;$lastPolicies=$policies;
    return $policies;
}
function dnsalias_registry_definitions(array $policies): array {
    $definitions=[];
    // The native host popup splits the single space into two empty tokens.
    // Supply both detail slots and the ordinary optional display fields so
    // it does not emit undefined-key warnings. Keep the PF marker unchanged.
    foreach($policies as $policy){
        // Saved patterns already belong to this native configuration snapshot.
        // A bounded preview needs no live status read, PF query or DNS lookup.
        $preview=[];$bytes=0;
        foreach($policy['names'] as $pattern){
            $extra=strlen($pattern)+(count($preview)?2:0);
            if(count($preview)>=6||$bytes+$extra>512)break;
            $preview[]=$pattern;$bytes+=$extra;
        }
        $remaining=count($policy['names'])-count($preview);
        $detail='Saved DNS names: '.implode(', ',$preview).($remaining?' (+'.$remaining.' more)':'').
            '||Live IPs and edit: Firewall > DNS Aliases.';
        $name='da_'.$policy['name'];$definitions[$name]=['name'=>$name,'type'=>'host','descr'=>'DNS Alias: '.$policy['name'],
            'address'=>' ','detail'=>$detail,'url'=>'','aliasurl'=>[]];
    }
    return $definitions;
}
function dnsalias_registry_bootstrap(): array {
    foreach(['config_get_path','get_reserved_table_names','add_reserved_table','alias_make_table'] as $function)
        if(!function_exists($function))throw new RuntimeException('Qualified native registry API required');
    $mode=config_get_path('installedpackages/dnsalias/native_alias_mode','legacy');
    if($mode==='legacy')return ['state'=>'inactive','mode'=>'legacy'];
    if($mode!=='registered-v1')throw new RuntimeException('Unknown native DNS alias mode');
    $policies=dnsalias_registry_policies(config_get_path('installedpackages/dnsalias/policy_json','[]'));
    $definitions=dnsalias_registry_definitions($policies);
    $reserved=get_reserved_table_names();$aliases=config_get_path('aliases/alias',[]);
    if(!is_array($reserved)||!is_array($aliases)||count($reserved)+count($aliases)>10000)throw new RuntimeException('Bounded native alias inventory required');
    $old=$GLOBALS['dnsalias_registry_registration']??null;
    if($old!==null){
        if($old['definitions']!==$definitions||$old['policies']!==$policies)throw new RuntimeException('DNS policies changed within native request');
        foreach($definitions as $name=>$definition)if(($reserved[$name]??null)!==$definition)throw new RuntimeException('Registered native DNS alias changed');
        return $old;
    }
    $occupied=[];
    foreach(array_keys($reserved) as $name)$occupied[strtolower($name)]=true;
    foreach($aliases as $alias){
        if(!is_array($alias)||!is_string($alias['name']??null))throw new RuntimeException('Native alias inventory changed');
        $occupied[strtolower($alias['name'])]=true;
    }
    // Validate the whole namespace before changing any request-local globals.
    foreach($definitions as $name=>$ignored)if(isset($occupied[$name]))throw new RuntimeException('Native alias namespace collision');
    foreach($definitions as $definition)add_reserved_table($definition,[' '=>$definition['detail']]);
    alias_make_table();
    dnsalias_registry_rules_register($policies);
    return $GLOBALS['dnsalias_registry_registration']=['state'=>'registered','mode'=>$mode,'definitions'=>$definitions,'policies'=>$policies];
}
function dnsalias_registry_update_after_save(array $policies): void {
    $old=$GLOBALS['dnsalias_registry_registration']??null;
    if(($old['state']??null)!=='registered'||config_get_path('installedpackages/dnsalias/native_alias_mode','legacy')!=='registered-v1'||
       dnsalias_registry_policies(config_get_path('installedpackages/dnsalias/policy_json','[]'))!==$policies)
        throw new RuntimeException('Explicit saved native registry update required');
    $reserved=get_reserved_table_names();$aliases=config_get_path('aliases/alias',[]);$definitions=dnsalias_registry_definitions($policies);
    foreach($old['definitions'] as $name=>$definition)if(($reserved[$name]??null)!==$definition)throw new RuntimeException('Owned registry changed before saved update');
    if(!is_array($reserved)||!is_array($aliases)||count($reserved)+count($aliases)>10000)throw new RuntimeException('Bounded native registry inventory required');
    $occupied=[];
    foreach($aliases as $alias){if(!is_array($alias)||!is_string($alias['name']??null))throw new RuntimeException('Native alias inventory changed');$occupied[strtolower($alias['name'])]=true;}
    foreach($reserved as $name=>$ignored)if(!isset($old['definitions'][$name]))$occupied[strtolower($name)]=true;
    foreach($definitions as $name=>$ignored)if(isset($occupied[$name]))throw new RuntimeException('Native registry namespace collision');
    foreach($old['definitions'] as $name=>$ignored)if(!isset($definitions[$name]))unset($GLOBALS['reserved_table_names'][$name]);
    foreach($definitions as $definition)add_reserved_table($definition,[' '=>$definition['detail']]);alias_make_table();
    $value=['state'=>'registered','mode'=>'registered-v1','definitions'=>$definitions,'policies'=>$policies];
    $GLOBALS['dnsalias_registry_registration']=$value;
    if(isset($GLOBALS['dnsalias_registry_status']))$GLOBALS['dnsalias_registry_status']=array_replace($GLOBALS['dnsalias_registry_status'],$value);
}
function dnsalias_registry_rules_script(array $names): string {
    $json=json_encode($names,JSON_THROW_ON_ERROR|JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT);
    $script=<<<'JS'
(() => {
  'use strict';
  const known = new Map(DNSALIAS_RULE_NAMES.map(name => ['da_' + name, name]));
  const cache = new Map(), pending = new Map();
  let requests = 0;
  const escape = value => String(value).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const url = (name, edit) => '/dnsalias_status.php?view=aliases&' + (edit ? 'edit_alias=' : 'inspect_members=') + encodeURIComponent(name) + (edit ? '#da-alias-editor' : '#da-alias-members');
  const message = (name, text) => '<p>' + escape(text) + '</p><a href="' + url(name, false) + '">View IPs and names</a>';
  const render = (name, value) => {
    if (!value || value.format !== 'dnsalias-popup-1' || value.name !== name || !Array.isArray(value.members) || value.members.length > 32 || !Array.isArray(value.names) || value.names.length > 16) throw new Error('Invalid popup');
    let text = '<strong>' + escape(value.state) + '</strong>';
    if (value.current === true && Number.isInteger(value.member_count) && value.member_count >= 0) {
      text += '<p>Live IP snapshot: ' + value.member_count + '</p>';
      if (value.members.length) text += '<ul>' + value.members.map(ip => '<li><code>' + escape(ip) + '</code></li>').join('') + '</ul>';
      else text += '<p>No IPs currently in this table.</p>';
      if (value.member_count > value.members.length) text += '<p>+' + (value.member_count - value.members.length) + ' more; open details.</p>';
      if (Number.isFinite(value.observed_utc)) text += '<small>Observed ' + escape(new Date(value.observed_utc * 1000).toLocaleTimeString()) + '</small>';
    } else text += '<p>Current membership unavailable.</p>';
    text += '<p>' + value.names.map(escape).join(', ') + (value.name_count > value.names.length ? ' …' : '') + '</p>';
    return text + '<p><a href="' + url(name, false) + '">View IPs and names</a> · <a href="' + url(name, true) + '">Edit alias</a></p>';
  };
  const load = name => {
    const saved = cache.get(name);
    if (saved && Date.now() - saved.time < 3000) return Promise.resolve(saved.html);
    if (pending.has(name)) return pending.get(name);
    if (requests >= 2) return Promise.resolve(message(name, 'Move back over this alias to refresh its IPs.'));
    requests++;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 2500);
    const request = fetch('/dnsalias_status.php?alias_popup=' + encodeURIComponent(name), {credentials:'same-origin', headers:{Accept:'application/json'}, signal:controller.signal})
      .then(response => {
        if (!response.ok || !(response.headers.get('content-type') || '').toLowerCase().startsWith('application/json')) throw new Error('Unavailable');
        return response.json();
      })
      .then(value => render(name, value))
      .catch(() => message(name, 'IP snapshot unavailable. Open DNS Aliases to inspect.'))
      .then(html => { cache.set(name, {html, time:Date.now()}); return html; })
      .finally(() => { clearTimeout(timer); requests--; pending.delete(name); });
    pending.set(name, request);
    return request;
  };
  const install = () => {
    if (!window.jQuery || !window.jQuery.fn.popover) return;
    const $ = window.jQuery;
    document.querySelectorAll('#ruletable a[data-toggle="popover"]').forEach(element => {
      const name = known.get((element.textContent || '').trim());
      if (!name || element.hasAttribute('href')) return;
      element.setAttribute('href', url(name, true));
      element.setAttribute('aria-label', 'Edit DNS alias da_' + name);
      element.setAttribute('data-original-title', 'DNS alias destinations');
      let active = false, drawing = false;
      const update = html => {
        element.setAttribute('data-content', html);
        $(element).data('content', html);
        const popup = $(element).data('bs.popover');
        if (popup && active && popup.tip().hasClass('in')) {
          drawing = true;
          try { popup.show(); } finally { drawing = false; }
        }
      };
      element.addEventListener('mouseenter', () => { active = true; });
      element.addEventListener('focusin', () => { active = true; });
      element.addEventListener('mouseleave', () => { active = false; });
      element.addEventListener('focusout', () => { active = false; });
      // Rule rows toggle checkboxes on click and edit on double-click.
      element.addEventListener('click', event => event.stopPropagation());
      element.addEventListener('dblclick', event => event.stopPropagation());
      $(element).on('show.bs.popover.dnsalias', () => {
        if (drawing) return;
        const saved = cache.get(name);
        update(saved ? saved.html : message(name, 'Loading live IP snapshot…'));
        load(name).then(update);
      });
    });
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', install, {once:true});
  else install();
})();
JS;
    return '<script id="dnsalias-native-rules-ui">'.str_replace('DNSALIAS_RULE_NAMES',$json,$script).'</script>';
}
function dnsalias_registry_rules_decorate(string $body,array $names,array $context): string {
    // The live callback derives context from server/auth state, not URL input.
    if(($context['method']??null)!=='GET'||($context['path']??null)!=='/firewall_rules.php'||
       ($context['file']??null)!=='/usr/local/www/firewall_rules.php'||($context['status']??null)!==200||
       ($context['allowed']??null)!==true||($context['native_sources']??null)!==true||
       !str_starts_with(strtolower($context['content_type']??''),'text/html')||
       !empty($context['encoded_or_sized'])||strlen($body)>2097152||!$names||
       !str_contains($body,'<html')||!str_contains($body,'id="ruletable"')||
       str_contains($body,'id="dnsalias-native-rules-ui"'))return $body;
    if(!array_is_list($names)||count($names)>127)throw new RuntimeException('Bounded native GUI alias list required');
    foreach($names as $name)if(!is_string($name)||!preg_match('/^[a-z][a-z0-9_]{0,22}$/D',$name))throw new RuntimeException('Saved alias identity required');
    $end=strripos($body,'</body>');if($end===false)return $body;
    return substr($body,0,$end).dnsalias_registry_rules_script($names).substr($body,$end);
}
function dnsalias_registry_rules_register(array $policies): void {
    if(PHP_SAPI==='cli'||($_SERVER['REQUEST_METHOD']??null)!=='GET'||
       ($_SERVER['SCRIPT_NAME']??null)!=='/firewall_rules.php'||
       ($_SERVER['SCRIPT_FILENAME']??null)!=='/usr/local/www/firewall_rules.php'||
       isset($GLOBALS['dnsalias_rules_ui_registered']))return;
    // Page-only decoration owned by the package fragment. No core-file edit.
    $pins=['/usr/local/www/firewall_rules.php'=>'54c7bbc6615670211f8a389cf2eb7d48e11a96dd0d1dfd76b3fa741098b5c838',
           '/usr/local/www/guiconfig.inc'=>'a722df32268ce3e3517a799c4481c4e3ea047335d0d840253cdc3c3adcb7ed99',
           '/usr/local/www/head.inc'=>'36c1ea4778a4b23a60c88a16d084d6371fd6f3089f28292ba7bfc27ae6bd607b',
           '/usr/local/www/foot.inc'=>'6dda0d9eacc9a62703fcea1387639c1422317f01f7454fba0f4eaeaaf710b740'];
    try{
        foreach($pins as $path=>$hash){$s=@lstat($path);if(!$s||($s['mode']&0170000)!==0100000||$s['uid']!==0||($s['mode']&0022)!==0||$s['size']>1048576||hash_file('sha256',$path)!==$hash)return;}
        $names=array_column($policies,'name');$GLOBALS['dnsalias_rules_ui_registered']=true;
        ob_start(static function(string $body,int $phase)use($names): string {
            if(!($phase&PHP_OUTPUT_HANDLER_FINAL))return $body;
            $type='';$sized=false;
            foreach(headers_list()as $header){
                if(stripos($header,'Content-Type:')===0)$type=trim(substr($header,13));
                if(stripos($header,'Content-Length:')===0||stripos($header,'Content-Encoding:')===0)$sized=true;
            }
            try{return dnsalias_registry_rules_decorate($body,$names,[
                'method'=>$_SERVER['REQUEST_METHOD']??null,'path'=>$_SERVER['SCRIPT_NAME']??null,'file'=>$_SERVER['SCRIPT_FILENAME']??null,
                'status'=>http_response_code(),'content_type'=>$type,'encoded_or_sized'=>$sized,'native_sources'=>true,
                'allowed'=>function_exists('isAllowedPage')&&isAllowedPage('/dnsalias_status.php')]);}
            catch(Throwable $ignored){return $body;}
        },2097153);
    }catch(Throwable $ignored){return;}
}
