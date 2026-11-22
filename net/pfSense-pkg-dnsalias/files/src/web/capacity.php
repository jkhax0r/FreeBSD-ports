<?php
/* On-demand size metadata only. No reads of policy contents or background work.
 * The native helper independently rechecks all admission conditions before Start.
 * The directory comes from the root-owned inspected profile, never HTTP input. */
function da_policy_capacity($mode,$limits,$directory) {
    if($mode!=='pfblockerng'){return null;}
    $out=['state'=>'unknown','current_bytes'=>null,'limit_bytes'=>null,'files'=>[]];
    $labels=['pfb_py_data.txt'=>'DNSBL','pfb_py_hsts.txt'=>'HSTS','pfb_py_ss.txt'=>'SafeSearch'];
    if(!is_array($limits)||count($limits)!==3||array_diff_key($limits,$labels)||array_diff_key($labels,$limits)){return $out;}
    foreach($limits as $limit){if(!is_int($limit)||$limit<0||$limit>1073741824){return $out;}}
    if(!is_string($directory)||strlen($directory)>1024||!str_starts_with($directory,'/')||str_contains($directory,"\0")||in_array('..',explode('/',$directory),true)){return $out;}
    clearstatcache(true,$directory);$parent=@lstat($directory);
    if(!$parent||($parent['mode']&0170000)!==0040000){return $out;}
    $rows=[];$total=0;$maximum=0;$exceeded=false;
    foreach($labels as $name=>$label){
        $path=$directory.'/'.$name;clearstatcache(true,$path);$item=@lstat($path);
        if(!$item||($item['mode']&0170000)!==0100000||$item['nlink']!==1||!is_int($item['size'])||$item['size']<0){return $out;}
        $over=$item['size']>$limits[$name];$exceeded=$exceeded||$over;
        $rows[]=['label'=>$label,'current_bytes'=>$item['size'],'limit_bytes'=>$limits[$name],'exceeded'=>$over];
        $total+=$item['size'];$maximum+=$limits[$name];
    }
    return ['state'=>$exceeded?'exceeded':'within','current_bytes'=>$total,'limit_bytes'=>$maximum,'files'=>$rows];
}
function da_policy_capacity_render($value) {
    if($value===null){return;}
    if($value['state']==='unknown'){
        echo '<p class="da-footnote">DNS policy size is unavailable. Full capacity and resolver checks still run during preparation.</p>';return;
    }
    echo '<p class="da-footnote">DNS policy data: '.da_h(da_bytes($value['current_bytes'])).' / '.da_h(da_bytes($value['limit_bytes'])).' reviewed size cap. Checked when this page loads.</p>';
    echo '<details><summary>Policy data sizes</summary>';
    $rows=[];foreach($value['files'] as $file){$rows[]=[$file['label'],da_bytes($file['current_bytes']),da_bytes($file['limit_bytes']),$file['exceeded']?'Capacity review required':'Within size cap'];}
    da_table(['Policy data','Current','Reviewed cap','Size check'],$rows);
    echo '<p class="da-footnote">Size metadata only; this does not verify a running reply feed or authorize a policy. No background polling or automatic capacity increase.</p></details>';
}
