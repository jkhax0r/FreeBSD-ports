<?php
/* Authenticated, explicitly prepared observation control; never policy input. */
function da_observation_snapshot($v) {
    if (!is_array($v) || ($v['format']??null)!=='dnsalias-observation-control-1' ||
        !in_array($v['state']??null,['prepared','queued','running','cancelling','cancelled','expired','complete','inspection_required'],true) ||
        !is_string($v['token']??null) || !preg_match('/^[a-f0-9]{32}$/D',$v['token']) ||
        !is_string($v['table']??null) || !preg_match('/^da_mvp_[a-f0-9]{12}$/D',$v['table']) ||
        !is_int($v['duration_seconds']??null) || $v['duration_seconds']<15 || $v['duration_seconds']>120 ||
        !is_numeric($v['preview_expires_utc']??null) || !is_finite((float)$v['preview_expires_utc']) ||
        !is_array($v['names']??null) || count($v['names'])<1 || count($v['names'])>8 ||
        ($v['enforcement_applied']??null)!==false || ($v['rule_created']??null)!==false ||
        ($v['shared_destination_table']??null)!==true || ($v['client_scope']??null)!=='any_trusted_reply') {
        throw new RuntimeException('Invalid observation status');
    }
    foreach ($v['names'] as $name) {
        if (!is_string($name) || strlen($name)>253 || !preg_match('/^[a-z0-9_.-]+$/D',$name)) {throw new RuntimeException('Invalid observation name');}
    }
    foreach (['started','cancel_requested','feed_ready','restoration_verified','resources_released'] as $key) {
        if (!is_bool($v[$key]??null)) {throw new RuntimeException('Invalid observation evidence');}
    }
    return $v;
}
function da_control_snapshot($v) {
    return ($v['format']??null)==='dnsalias-observation-control-1'?da_observation_snapshot($v):da_trial_snapshot($v);
}
function da_observation_render($v,$canControl,$error='') {
    $labels=['prepared'=>'Ready for review','queued'=>'Start requested','running'=>'Observation running',
        'cancelling'=>'Stop requested; restoration pending','cancelled'=>'Observation stopped',
        'expired'=>'Preview expired','complete'=>'Observation finished','inspection_required'=>'Inspection required'];
    $state=$v['state'];
    if ($state==='cancelled' && !$v['started']) {$labels['cancelled']='Preview cancelled';}
    echo '<div class="da-panel" id="da-trial-control" data-state="'.da_h($v['state']??'unavailable').'"><div class="da-panel-title"><h2>Trusted DNS reply session</h2></div>';
    if ($error!=='') {echo '<p class="da-notice da-danger">'.da_h($error).'</p>';}
    echo '<p><strong>'.da_h($labels[$state]).'</strong> · Up to '.da_h($v['duration_seconds']).' seconds · All observed DNS clients</p>';
    echo '<p>Collect trusted replies and populate a separate test table for <strong>'.da_h(implode(', ',$v['names'])).'</strong>. No firewall rule is attached.</p>';
    echo '<p>Feed ready: <strong>'.($v['feed_ready']?'observed':($v['started']?'waiting':'not started')).'</strong> · DNS restoration: <strong>'.($v['restoration_verified']?'verified':($v['started']?'pending':'not started')).'</strong></p>';
    if (isset($v['progress_age_seconds'])) {echo '<p class="da-footnote">Last progress update: '.da_h($v['progress_age_seconds']).' seconds ago.</p>';}
    echo '<p class="da-footnote">Stops automatically at its deadline. DNS evidence can suggest a destination name; it does not prove an HTTPS hostname. Existing traffic policy stays in place.</p>';
    if ($canControl && in_array($state,['prepared','queued','running','cancelling'],true)) {
        echo '<form method="post" action="dnsalias_status.php?view=aliases"><input type="hidden" name="trial_token" value="'.da_h($v['token']).'">';
        if ($state==='prepared') {echo '<button class="da-primary" name="trial_op" value="start" type="submit">Start DNS observation</button> ';}
        echo '<button name="trial_op" value="stop" type="submit">'.($v['started']?'Stop observation':'Cancel preview').'</button></form>';
    } elseif (!$canControl) {echo '<p class="da-footnote">Firewall rule editing privilege is required for session controls.</p>';}
    echo '<p><a href="dnsalias_status.php?view=aliases">Refresh observation status</a></p></div>';
}
