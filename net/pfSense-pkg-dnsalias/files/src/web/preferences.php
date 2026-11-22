<?php
/* Data-only download. Never copies code, hooks, receipts, rules, IPs or logs. */
require_once __DIR__.'/domainlabels.php';
const DA_PREFERENCES_FORMAT='dnsalias-preferences-1';
const DA_PREFERENCES_MAX_BYTES=16777216;

function da_preferences_label(array $row): array {
    if(array_keys($row)!==['domain','review','tags']||!is_string($row['domain'])||
       da_labels_domain($row['domain'])!==$row['domain']||!is_string($row['review'])||
       !in_array($row['review'],['','good','bad','investigate'],true)||!is_array($row['tags'])||
       !array_is_list($row['tags'])||count($row['tags'])>8)
        throw new RuntimeException('Canonical domain annotation required for backup.');
    foreach($row['tags'] as $tag)if(!is_string($tag))throw new RuntimeException('Text tags required for backup.');
    if($row['tags']!==da_labels_tags(implode(',',$row['tags']))||($row['review']===''&&!$row['tags']))
        throw new RuntimeException('Canonical nonempty annotation required for backup.');
    return $row;
}
function da_preferences_export(string $data,array $policies): string {
    if(!function_exists('dnsalias_registry_policies'))throw new RuntimeException('Qualified preference validation unavailable.');
    $policies=dnsalias_registry_policies(json_encode($policies,JSON_THROW_ON_ERROR));
    $layout=da_labels_layout($data);$labels=[];$lock=null;$db=null;
    try{
        if($layout!==null){
            $lock=da_labels_lock($layout,LOCK_SH);$db=da_labels_open($layout);$db->exec('BEGIN');
            $check=$db->query('PRAGMA foreign_key_check');$bad=$check->fetchArray(SQLITE3_NUM);$check->finalize();
            if($bad!==false)throw new RuntimeException('Annotation relation changed.');
            $rows=$db->query('SELECT l.domain,l.review,t.tag FROM domain_labels l LEFT JOIN domain_tags t ON t.domain=l.domain ORDER BY l.domain,t.tag');
            $current=null;
            while($r=$rows->fetchArray(SQLITE3_ASSOC)){
                if($current===null||$current['domain']!==$r['domain']){
                    if($current!==null)$labels[]=da_preferences_label($current);
                    if(count($labels)>=DA_LABEL_MAX_DOMAINS)throw new RuntimeException('Annotation capacity exceeded.');
                    $current=['domain'=>$r['domain'],'review'=>$r['review'],'tags'=>[]];
                }
                if($r['tag']!==null){if(count($current['tags'])>=8)throw new RuntimeException('Annotation tag capacity exceeded.');$current['tags'][]=$r['tag'];}
            }
            $rows->finalize();if($current!==null)$labels[]=da_preferences_label($current);$db->exec('COMMIT');
        }
        $raw=json_encode(['format'=>DA_PREFERENCES_FORMAT,'policies'=>$policies,'labels'=>$labels],JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR)."\n";
        if(strlen($raw)>DA_PREFERENCES_MAX_BYTES)throw new RuntimeException('Preference backup size limit exceeded.');
        return $raw;
    }finally{
        if($db!==null)$db->close();
        if($lock!==null){flock($lock,LOCK_UN);fclose($lock);}
    }
}

function da_preferences_decode(string $raw): array {
    if(strlen($raw)===0||strlen($raw)>DA_PREFERENCES_MAX_BYTES)throw new InvalidArgumentException('Preference backup exceeds the size limit.');
    $value=json_decode($raw,true,16,JSON_THROW_ON_ERROR);
    if(!is_array($value)||count($value)!==3||array_diff(array_keys($value),['format','policies','labels'])||
       ($value['format']??null)!==DA_PREFERENCES_FORMAT||!is_array($value['policies']??null)||!array_is_list($value['policies'])||
       !is_array($value['labels']??null)||!array_is_list($value['labels'])||count($value['labels'])>DA_LABEL_MAX_DOMAINS)
        throw new InvalidArgumentException('Choose a data-only DNS Alias preferences backup.');
    if(!function_exists('dnsalias_registry_policies'))throw new RuntimeException('Qualified preference validation unavailable.');
    dnsalias_registry_policies(json_encode($value['policies'],JSON_THROW_ON_ERROR));$seen=[];
    foreach($value['labels'] as $row){
        if(!is_array($row))throw new InvalidArgumentException('Domain annotation records required.');
        da_preferences_label($row);
        if(isset($seen[$row['domain']]))throw new InvalidArgumentException('Duplicate domain annotation in backup.');
        $seen[$row['domain']]=true;
    }
    // Accept formatting whitespace, but reject duplicate keys and alternate
    // object/array spellings lost by PHP's associative JSON decoder. Both
    // package exporters use these ordinary ASCII JSON string spellings.
    $compact=preg_replace('~"(?:\\\\.|[^"\\\\])*"(*SKIP)(*F)|\s+~','',$raw);
    if($compact===null||$compact!==json_encode($value,JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR))
        throw new InvalidArgumentException('Use an unmodified DNS Alias preferences backup.');
    return $value;
}
function da_preferences_import_labels(string $data,array $labels): array {
    // This library operation is not exposed by an HTTP write endpoint yet.
    // Alias/native configuration and source ownership are never imported.
    if(!array_is_list($labels)||count($labels)>DA_LABEL_MAX_DOMAINS)throw new InvalidArgumentException('Bounded domain annotations required.');
    $seen=[];foreach($labels as $row){
        if(!is_array($row))throw new InvalidArgumentException('Domain annotation records required.');
        da_preferences_label($row);if(isset($seen[$row['domain']]))throw new InvalidArgumentException('Duplicate domain annotation.');$seen[$row['domain']]=true;
    }
    if(!$labels)return ['imported'=>0,'existing_overwritten'=>false,'automatic_retry'=>false];
    $layout=da_labels_layout($data,true);$lock=da_labels_lock($layout,LOCK_EX);$db=null;
    try{
        da_labels_initialize($layout);$db=da_labels_open($layout,true);
        $db->exec('PRAGMA max_page_count='.(int)floor(DA_LABEL_MAX_BYTES/(int)$db->querySingle('PRAGMA page_size')));
        $db->exec('BEGIN IMMEDIATE');
        if((int)$db->querySingle('SELECT count(*) FROM domain_labels')!==0||(int)$db->querySingle('SELECT count(*) FROM domain_tags')!==0)
            throw new RuntimeException('Import requires an empty owned label store; existing annotations are preserved.');
        $label=$db->prepare('INSERT INTO domain_labels(domain,review,updated_utc) VALUES(:domain,:review,:updated)');
        $tag=$db->prepare('INSERT INTO domain_tags(domain,tag) VALUES(:domain,:tag)');$now=time();
        foreach($labels as $row){
            $label->bindValue(':domain',$row['domain'],SQLITE3_TEXT);$label->bindValue(':review',$row['review'],SQLITE3_TEXT);$label->bindValue(':updated',$now,SQLITE3_INTEGER);$label->execute()->finalize();$label->reset();
            foreach($row['tags'] as $text){$tag->bindValue(':domain',$row['domain'],SQLITE3_TEXT);$tag->bindValue(':tag',$text,SQLITE3_TEXT);$tag->execute()->finalize();$tag->reset();}
        }
        $label->close();$tag->close();
        if((int)$db->querySingle('SELECT count(*) FROM domain_labels')!==count($labels))throw new RuntimeException('Imported label readback differs.');
        $db->exec('COMMIT');return ['imported'=>count($labels),'existing_overwritten'=>false,'automatic_retry'=>false];
    }catch(Throwable $e){if($db!==null){try{$db->exec('ROLLBACK');}catch(Throwable $ignored){}}throw $e;}
    finally{if($db!==null)$db->close();flock($lock,LOCK_UN);fclose($lock);}
}
