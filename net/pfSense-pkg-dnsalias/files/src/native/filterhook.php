<?php
/* Inactive native package adapters. Including this file registers nothing.
 * A future owned parse_config plugin supplies inspected policy definitions;
 * the native package filter_rule_function calls dnsalias_native_filter_rules.
 * Neither adapter writes config, rules, files, states or PF memberships.
 */
require_once __DIR__.'/aliases.php';

function dnsalias_native_register_dynamic_tables(array $tables): array {
    global $dnsalias_native_registration;
    foreach(['get_reserved_table_names','config_get_path','add_reserved_table','alias_make_table'] as $name) {
        if(!function_exists($name))throw new RuntimeException('Qualified native alias API required');
    }
    $reserved=get_reserved_table_names();$aliases=config_get_path('aliases/alias',[]);
    if(!is_array($reserved) || !is_array($aliases) || count($reserved)+count($aliases)>10000) {
        throw new RuntimeException('Bounded native alias inventory required');
    }
    if(isset($dnsalias_native_registration)) {
        if($dnsalias_native_registration['tables']!==$tables)throw new RuntimeException('Policy changed within native request');
        foreach($dnsalias_native_registration['definitions'] as $name=>$definition) {
            if(($reserved[$name]??null)!==$definition)throw new RuntimeException('Owned native alias changed');
        }
        return $dnsalias_native_registration['definitions'];
    }
    $occupied=array_keys($reserved);
    foreach($aliases as $alias) {
        if(!is_array($alias) || !isset($alias['name']) || !is_string($alias['name'])) {
            throw new RuntimeException('Native alias inventory changed');
        }
        $occupied[]=$alias['name'];
    }
    $definitions=dnsalias_native_dynamic_table_definitions($tables,$occupied);
    // Validate the complete namespace before changing request-local globals.
    // The native API rebuilds address/detail from these entries. A single
    // fixed ASCII-space token has empty expansion but is not an empty address,
    // so native generation never schedules an asynchronous flush.
    foreach($definitions as $definition)add_reserved_table($definition,[' '=>'']);
    alias_make_table();
    $dnsalias_native_registration=['tables'=>$tables,'definitions'=>$definitions,'phases'=>[]];
    return $definitions;
}

function dnsalias_native_filter_rules(string $kind): string {
    global $dnsalias_native_registration,$after_filter_configure_run;
    if(!isset($dnsalias_native_registration))return '';
    if(!in_array($kind,['nat','pfearly','filter'],true))throw new RuntimeException('Unqualified native filter phase');
    $reserved=get_reserved_table_names();
    foreach($dnsalias_native_registration['definitions'] as $name=>$definition) {
        if(($reserved[$name]??null)!==$definition)throw new RuntimeException('Owned native alias changed before filter');
    }
    if(!is_array($after_filter_configure_run))throw new RuntimeException('Native filter queue unavailable');
    $result=dnsalias_native_preserve_dynamic_tables($dnsalias_native_registration['tables'],$after_filter_configure_run);
    $after_filter_configure_run=$result['commands'];
    $dnsalias_native_registration['phases'][$kind]=true;
    // Ordinary user source/VLAN/port rules continue to reference these aliases.
    // The adapter emits no pass/block rule or global allow.
    return '';
}
