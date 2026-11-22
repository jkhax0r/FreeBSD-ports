<?php
/* Inactive local CLI conversion only. Reads one bounded request from stdin.
 * Uses the qualified installed XML implementation, never config.inc. No user
 * paths, config reads/writes, cache, backups, commands, network or logging.
 * Output contains private configuration: keep it in local pipes, never logs.
 * Input is a trusted coordinator request, not a public HTTP endpoint.
 */
if (PHP_SAPI !== 'cli') { http_response_code(403); exit; }
ini_set('memory_limit', '128M');
ini_set('display_errors', '0');
const DNSALIAS_XML_LIMIT = 8388608;
const DNSALIAS_REQUEST_LIMIT = 16777216;
const DNSALIAS_XML_SOURCE_SHA256 = '9f0a71e0419e0587af645e94e6c15eef851bdd7185b6df419a67b7acb5a06966';
set_error_handler(static function() { throw new RuntimeException('native_xml_warning'); });
function logger(...$args) { throw new RuntimeException('native_xml_rejected'); }
function localize_text(...$args) { return 'native_xml_rejected'; }
define('LOG_PREFIX_CONFIG', 'dnsalias-native-xml');

function dnsalias_xml_tree(array $tree): void {
    $stack=[[$tree,0]]; $nodes=0; $bytes=0;
    while ($stack) {
        [$value,$depth]=array_pop($stack);
        if (++$nodes>200000 || $depth>32) { throw new RuntimeException('tree_structure_limit'); }
        if (is_array($value)) {
            if ($nodes+count($stack)+count($value)>200000) { throw new RuntimeException('tree_node_limit'); }
            $list=array_is_list($value);
            foreach ($value as $key=>$child) {
                if (!$list && (!is_string($key) || strlen($key)>160 || !preg_match('/^[a-z_][a-z0-9_.-]*$/D',$key))) {
                    throw new RuntimeException('tree_key_rejected');
                }
                $bytes+=strlen((string)$key);
                $stack[]=[$child,$depth+1];
            }
        } elseif (is_string($value)) {
            $bytes+=strlen($value);
            if (!preg_match('//u',$value) || preg_match('/[\x00-\x08\x0b\x0c\x0e-\x1f]/',$value)) {
                throw new RuntimeException('tree_text_rejected');
            }
        } else { throw new RuntimeException('tree_scalar_rejected'); }
        if ($bytes>DNSALIAS_XML_LIMIT) { throw new RuntimeException('tree_text_limit'); }
    }
}

function dnsalias_xml_parse(string $xml): array {
    if (strlen($xml)<1 || strlen($xml)>DNSALIAS_XML_LIMIT || !preg_match('//u',$xml) ||
        str_contains($xml,"\0") || preg_match('/<!\s*(?:DOCTYPE|ENTITY)\b/i',$xml)) {
        throw new RuntimeException('xml_input_rejected');
    }
    // The inspected native parser accepts a stream path, even though its
    // historical isstring parameter is unused. data:// keeps bytes in memory.
    $tree=parse_xml_config('data://text/plain;base64,'.base64_encode($xml),'pfsense');
    if (!is_array($tree) || array_is_list($tree)) { throw new RuntimeException('xml_root_rejected'); }
    dnsalias_xml_tree($tree);
    return $tree;
}

try {
    if (hash_file('sha256','/etc/inc/xmlparse.inc')!==DNSALIAS_XML_SOURCE_SHA256 || function_exists('parse_xml_config')) {
        throw new RuntimeException('native_source_unqualified');
    }
    require '/etc/inc/xmlparse.inc';
    $input=stream_get_contents(STDIN,DNSALIAS_REQUEST_LIMIT+1);
    if ($input===false || strlen($input)>DNSALIAS_REQUEST_LIMIT) { throw new RuntimeException('request_limit'); }
    $request=json_decode($input,true,40,JSON_THROW_ON_ERROR);
    if (!is_array($request) || count($request)!==3 || ($request['format']??null)!=='dnsalias-native-xml-1') {
        throw new RuntimeException('request_schema_rejected');
    }
    $operation=$request['operation']??null; $original=null;
    if ($operation==='parse' && isset($request['xml_base64']) && is_string($request['xml_base64'])) {
        $original=base64_decode($request['xml_base64'],true);
        if ($original===false || base64_encode($original)!==$request['xml_base64']) { throw new RuntimeException('xml_encoding_rejected'); }
        $tree=dnsalias_xml_parse($original);
    } elseif ($operation==='render' && isset($request['configuration']) && is_array($request['configuration']) && !array_is_list($request['configuration'])) {
        $tree=$request['configuration'];dnsalias_xml_tree($tree);
    } else { throw new RuntimeException('request_operation_rejected'); }
    $rendered=dump_xml_config($tree,'pfsense');
    if (!is_string($rendered) || strlen($rendered)>DNSALIAS_XML_LIMIT || dnsalias_xml_parse($rendered)!==$tree) {
        throw new RuntimeException('native_roundtrip_changed_tree');
    }
    echo json_encode(['format'=>'dnsalias-native-xml-1','operation'=>$operation,'configuration'=>$tree,
        'rendered_xml_base64'=>base64_encode($rendered),'rendered_xml_sha256'=>hash('sha256',$rendered),
        'source_xml_sha256'=>$original===null?null:hash('sha256',$original),'native_roundtrip_verified'=>true],JSON_THROW_ON_ERROR);
} catch (Throwable $e) {
    // Do not expose configuration values, parser fragments or paths on error.
    echo '{"format":"dnsalias-native-xml-1","error":"conversion_rejected"}';
    exit(1);
}
