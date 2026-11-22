<?php
/* DNS Alias statistics and separately prepared, scoped trial controls. */
require_once("guiconfig.inc");
// guiconfig authenticates and checks the requesting user's page privileges.
// No telemetry is opened before that check. No anonymous JSON endpoint exists.
require_once("/usr/local/libexec/dnsalias/web/lifecycle.php");
try {$da_source_lifetime=da_source_lifetime('/usr/local/libexec/dnsalias','/var/db/dnsalias');}
catch(Throwable $error){
    http_response_code(503);header('Content-Type: text/plain; charset=utf-8');header('Cache-Control: no-store');
    echo "DNS Alias is updating or unavailable. Refresh before retrying an action.\n";exit;
}
require_once("/usr/local/libexec/dnsalias/web/view.php");
if (($_GET['client_identity']??null)==='1' && ($_SERVER['REQUEST_METHOD']??'GET')==='GET') {
    header('Content-Type: application/json; charset=utf-8');header('Cache-Control: no-store');
    echo json_encode(da_identity_payload(da_identity_snapshot('/var/db/dnsalias'),time()),JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT|JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}
require_once("/usr/local/libexec/dnsalias/web/control.php");
require_once("/usr/local/libexec/dnsalias/web/policies.php");
if(isset($_GET['alias_popup'])&&($_SERVER['REQUEST_METHOD']??'GET')==='GET'){
    header('Content-Type: application/json; charset=utf-8');header('Cache-Control: no-store');header('X-Content-Type-Options: nosniff');
    try{
        if(!is_string($_GET['alias_popup'])||!preg_match('/^[a-z][a-z0-9_]{0,22}$/D',$_GET['alias_popup']))throw new InvalidArgumentException('Saved DNS alias required');
        $policies=dnsalias_policies_read();$name=$_GET['alias_popup'];
        $payload=da_alias_popup_payload($name,$policies,da_alias_display_status($policies,$name),time());
        echo json_encode($payload,JSON_THROW_ON_ERROR|JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT);
    }catch(OutOfBoundsException $error){http_response_code(404);echo '{"error":"Alias not found"}';}
    catch(InvalidArgumentException $error){http_response_code(400);echo '{"error":"Invalid alias"}';}
    catch(Throwable $error){http_response_code(503);echo '{"error":"Alias snapshot unavailable"}';}
    exit;
}
if(($_GET['preferences_export']??null)==='1'&&($_SERVER['REQUEST_METHOD']??'GET')==='GET'){
    header('Cache-Control: no-store');header('X-Content-Type-Options: nosniff');
    try{
        require_once('/usr/local/libexec/dnsalias/web/preferences.php');
        $backup=da_preferences_export('/var/db/dnsalias',dnsalias_policies_read());
        header('Content-Type: application/json; charset=utf-8');header('Content-Disposition: attachment; filename="dnsalias-preferences.json"');
        echo $backup;
    }catch(Throwable $error){http_response_code(503);header('Content-Type: text/plain; charset=utf-8');echo "DNS Alias preference backup is unavailable. Refresh and inspect its status before retrying.\n";}
    exit;
}
$da_trial=null;$da_trial_error='';$da_preparation=null;
$da_can_control=isAllowedPage('/firewall_rules.php');
$da_labels_error='';
if(($_SERVER['REQUEST_METHOD']??'GET')==='POST'&&isset($_POST['domain_label_op'])){
    try{
        da_labels_post($_POST,$da_can_control,'/var/db/dnsalias');
        header('Location: '.da_labels_return_url($_GET),true,303);exit;
    }catch(Throwable $error){
        http_response_code($da_can_control?400:403);
        $da_labels_error=$error instanceof InvalidArgumentException?$error->getMessage():($da_can_control?'Domain labels were not confirmed saved. Refresh and inspect before retrying.':'Firewall editing privilege required to edit domain labels.');
    }
}
$da_aliases=[];$da_service=[];$da_alias_error='';
try {
    if(($_SERVER['REQUEST_METHOD']??'GET')==='POST' && isset($_POST['alias_op'])&&!isset($_POST['domain_label_op'])){
        if(!$da_can_control){http_response_code(403);throw new RuntimeException('Firewall editing privilege required');}
        if($_POST['alias_op']==='save'){
            if(!is_string($_POST['alias_name']??null)||!is_string($_POST['alias_names']??null)||strlen($_POST['alias_names'])>65536)throw new RuntimeException('Invalid alias input');
            if(array_key_exists('alias_original_name',$_POST)&&!is_string($_POST['alias_original_name']))throw new RuntimeException('Invalid original alias identity');
            $mode=$_POST['alias_editor_mode']??null;$original=$_POST['alias_original_name']??null;
            if(!in_array($mode,['create','edit'],true)||($mode==='edit'&&$original===null)||($mode==='create'&&$original!==null))
                throw new RuntimeException('Alias form has changed. Refresh the page before saving.');
            $name=da_alias_save_identity($_POST['alias_name'],$_POST['alias_original_name']??null,dnsalias_policies_read());
            dnsalias_policies_save($name,preg_split('/[\s,]+/',$_POST['alias_names'],-1,PREG_SPLIT_NO_EMPTY),isset($_POST['alias_enabled']));
            if(dnsalias_service_enabled())da_alias_service('start');
        }elseif($_POST['alias_op']==='add_name'){
            if(!is_string($_POST['alias_name']??null)||!is_string($_POST['alias_domain']??null))throw new RuntimeException('Alias and domain required');
            $selected=null;foreach(dnsalias_policies_read() as $p)if($p['name']===$_POST['alias_name'])$selected=$p;
            if($selected===null)throw new RuntimeException('Saved DNS alias not found');
            dnsalias_policies_save($selected['name'],array_merge($selected['names'],[$_POST['alias_domain']]),$selected['enabled']);if(dnsalias_service_enabled())da_alias_service('start');
        }elseif($_POST['alias_op']==='settings'){
            $enabled=isset($_POST['service_enabled']);dnsalias_service_save($enabled);
            if($enabled){da_alias_service('boot_enable');da_alias_service('service_start');}
            else da_alias_service('service_stop');
        }elseif($_POST['alias_op']==='delete'){
            if(!is_string($_POST['alias_name']??null))throw new RuntimeException('Alias name required');
            da_alias_delete($_POST['alias_name']);
        }elseif(in_array($_POST['alias_op'],['start','stop','boot_enable','boot_disable'],true)){da_alias_service($_POST['alias_op']);}
        else throw new RuntimeException('Unknown alias action');
        header('Location: dnsalias_status.php?view=aliases'.($_POST['alias_op']==='settings'?'&settings=1':''),true,303);exit;
    }
}catch(Throwable $e){$da_alias_error=$e->getMessage();}
if(($_GET['view']??'')==='aliases'){
    try{
        $da_aliases=dnsalias_policies_read();
        // Only the list, editor, and members view display live PF membership.
        if(isset($_GET['inspect_members'])||(!isset($_GET['inspect_alias'])&&($_GET['settings']??'')!=='1')){
            $selected=isset($_GET['inspect_members'])&&is_string($_GET['inspect_members'])?$_GET['inspect_members']:null;
            $da_service=da_alias_display_status($da_aliases,$selected);
        }
    }catch(Throwable $e){if($da_alias_error==='')$da_alias_error=$e->getMessage();}
}
try {
    $da_request=da_trial_request('status');
    if (($_SERVER['REQUEST_METHOD']??'GET')==='POST' && !isset($_POST['alias_op'])&&!isset($_POST['domain_label_op'])) {
        if (!$da_can_control) {http_response_code(403);throw new RuntimeException('Firewall rule editing privilege required');}
        $da_request=($_POST['trial_op']??null)==='names'?da_policy_names_request($_POST):da_trial_request($_POST['trial_op']??null,$_POST['trial_token']??null);
    }
    if (in_array($da_request['op'],['prepare','prepare_observation','prepare_policy'],true)) {
        $da_policy=$da_request['op']==='prepare_policy'?da_policy_input($_POST):null;
        da_queue_trial_preparation('/var/db/dnsalias',da_identity_snapshot('/var/db/dnsalias'),time(),$da_request['op']==='prepare_observation'?'observe':'block',$da_policy);
        $da_request=da_trial_request('status');
    }
    $da_preparation=da_trial_preparation('/var/db/dnsalias');
    $da_trial=da_trial_exchange('/var/run/dnsalias-trial',$da_request);
    if ($da_request['op']!=='status' && $da_trial===null) {throw new RuntimeException('No prepared trial available');}
    if ($da_trial===null && $da_preparation['last']!==null) {$da_trial=$da_preparation['last'];}
    if (($_SERVER['REQUEST_METHOD']??'GET')==='POST' && !isset($_POST['alias_op'])&&!isset($_POST['domain_label_op'])) {
        header('Location: dnsalias_status.php?view=aliases',true,303);exit;
    }
} catch (Throwable $e) {
    $da_trial_error='Trial control unavailable or request refused. Refresh status before retrying; do not assume an unconfirmed request failed.';
}
$pgtitle = array(gettext("Status"), gettext("DNS Alias"));
$da_view = da_load('/var/db/dnsalias', $_GET, time());
if($da_view['view']==='domain' && $da_view['domain']!==''){
    // guiconfig has already loaded config.xml. Reuse that in-memory snapshot;
    // no service subprocess, PF read, DNS lookup or background polling.
    try{$da_view['domain_aliases']=dnsalias_policies_read();}
    catch(Throwable $ignored){$da_view['domain_aliases']=null;}
}
$da_view['trial']=$da_trial;$da_view['trial_error']=$da_trial_error;$da_view['can_control']=$da_can_control;
$da_view['preparation']=$da_preparation;
$da_view['labels_post_error']=$da_labels_error;
$da_view['policy_prefill']=da_policy_prefill($_GET);
$da_view['saved_aliases']=$da_aliases;$da_view['alias_service']=$da_service;$da_view['alias_error']=$da_alias_error;
if($da_view['view']==='aliases'&&is_string($_GET['inspect_members']??null)){
    $da_view['alias_members']=null;
    foreach($da_aliases as $policy)if($policy['name']===$_GET['inspect_members']){
        $da_view['alias_members']=da_alias_members_model('/var/db/dnsalias',$policy,$da_service,time(),$da_view['window']);break;
    }
}
$da_view['identity_pending']=($da_view['client']!=='' || in_array($da_view['view'],['overview','clients','client','domain','ip'],true)) && !$da_view['errors'] && da_queue_identity('/var/db/dnsalias',$da_view['status'],time());
$da_fragment=$_SERVER['HTTP_X_DNSALIAS_FRAGMENT']??'';
$da_client_fragment=($_SERVER['REQUEST_METHOD']??'GET')==='GET' && $da_view['view']==='client' && in_array($da_fragment,['client','client-v2'],true);
if($da_client_fragment){
    header('Content-Type: text/html; charset=utf-8');header('Cache-Control: no-store');
    da_render($da_view,$da_fragment);exit;
}
include("head.inc");
da_render($da_view);
include("foot.inc");
