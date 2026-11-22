<?php
/* Inactive pure reserved-table definition builder for qualified pfSense builds.
 * No registration, configuration reads, file I/O, commands or PF changes.
 * Caller must qualify package integration, namespace and backing-file ownership,
 * fresh lease contents, reload coordination, boot recovery and helper failure.
 */
function dnsalias_native_validate_tables(array $tables, array $occupied_names): array {
    if (count($tables)>128 || count($occupied_names)>10000 || !array_is_list($tables)) {
        throw new InvalidArgumentException('Bounded table list and alias inventory required');
    }
    $occupied=[];
    foreach ($occupied_names as $name) {
        if (!is_string($name) || strlen($name)>128) { throw new InvalidArgumentException('Explicit existing alias names required'); }
        $occupied[strtolower($name)]=true;
    }
    $result=[];
    foreach ($tables as $table) {
        if (!is_array($table) || count($table)!==2 || !isset($table['name'],$table['description']) ||
            !is_string($table['name']) || !preg_match('/^da_[a-z][a-z0-9_]{0,22}$/D',$table['name']) ||
            !is_string($table['description']) || strlen($table['description'])>160 ||
            preg_match('/[\x00-\x1f\x7f]/',$table['description'])) {
            throw new InvalidArgumentException('Bounded owned table identity and description required');
        }
        $name=$table['name'];
        if (isset($result[$name]) || isset($occupied[$name])) {
            throw new InvalidArgumentException('Existing alias or duplicate policy table; no overwrite');
        }
        $result[$name]=$table['description'];
    }
    return $result;
}

function dnsalias_native_table_definitions(array $tables, string $directory, array $occupied_names): array {
    if (strlen($directory)>256 || !preg_match('~^/(?:[A-Za-z0-9_-][A-Za-z0-9_.-]*/)*[A-Za-z0-9_-][A-Za-z0-9_.-]*$~D',$directory)) {
        throw new InvalidArgumentException('Canonical absolute owned directory required');
    }
    $result=[];
    foreach(dnsalias_native_validate_tables($tables,$occupied_names) as $name=>$description) {
        $result[$name]=['name'=>$name,'type'=>'urltable','url'=>$directory.'/'.$name.'.txt',
            'descr'=>$description,'address'=>'','detail'=>''];
    }
    return $result;
}

/* Native persistent in-memory aliases for the inspected pfSense implementation.
 * Its nested expansion splits on ASCII spaces and skips empty tokens. Exactly
 * one ASCII space therefore expands to no destinations, while PHP empty(' ')
 * is false and filter_generate_alias_tables does not queue a late table flush.
 * This value is internal request-local metadata, never a configured domain or
 * an address sent to PF. Do not trim it or accept caller-supplied placeholders.
 * Native source/behavior must be qualified before registering this adapter.
 * No backing file resurrects leases; the helper/watchdog still owns expiry.
 */
function dnsalias_native_dynamic_table_definitions(array $tables, array $occupied_names): array {
    $result=[];
    foreach(dnsalias_native_validate_tables($tables,$occupied_names) as $name=>$description) {
        $result[$name]=['name'=>$name,'type'=>'host','descr'=>$description,'address'=>' ','detail'=>''];
    }
    return $result;
}

/* Inactive candidate for ordinary saved native aliases. No package parse hook
 * is required to recognize these definitions after a config/XML reload. Each
 * policy references one dedicated empty host alias: native expansion is empty,
 * but only the seed itself has an empty address and queues a native flush.
 * The seed is NEVER a destination policy or a helper-writable table. Caller
 * must own and preserve the complete definition set, qualify native sources,
 * and review rule/nested-alias references before editing or removing it.
 * No IP placeholder, backing membership file, rule, command or registration.
 */
function dnsalias_native_persistent_alias_definitions(array $tables,string $seed_name,array $occupied_names): array {
    if(!array_is_list($tables) || count($tables)<1 || count($tables)>127) {
        throw new InvalidArgumentException('One to 127 policies plus a separate empty seed required');
    }
    $seed=['name'=>$seed_name,'description'=>'DNS Alias internal empty definition; never populate'];
    $validated=dnsalias_native_validate_tables(array_merge([$seed],$tables),$occupied_names);
    $result=[];
    foreach($validated as $name=>$description) {
        $result[$name]=['name'=>$name,'type'=>'host','descr'=>$description,
            'address'=>$name===$seed_name?'':$seed_name,'detail'=>''];
    }
    return $result;
}

/* Pure queue transformation, never command execution or global modification.
 * Native source/version and actual package-hook ordering must be qualified by
 * the caller. Preserve every unrelated or noncanonical command byte-for-byte.
 */
function dnsalias_native_preserve_dynamic_tables(array $tables,array $commands): array {
    if(!array_is_list($commands) || count($commands)>10000) {
        throw new InvalidArgumentException('Bounded ordered native command queue required');
    }
    $owned=[];
    foreach(dnsalias_native_validate_tables($tables,[]) as $name=>$description) {
        $owned['/sbin/pfctl -T flush -t '.escapeshellarg($name)]=$name;
    }
    $kept=[];$removed=[];
    foreach($commands as $command) {
        if(!is_string($command) || strlen($command)>8192) {
            throw new InvalidArgumentException('Bounded explicit native command required');
        }
        if(isset($owned[$command]))$removed[]=$owned[$command];
        else $kept[]=$command;
    }
    return ['commands'=>$kept,'removed_owned_flushes'=>$removed,'enforcement_applied'=>false];
}
