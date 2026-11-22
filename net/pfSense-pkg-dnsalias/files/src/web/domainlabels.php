<?php
/* Local review notes only. This store is never read on the DNS/PF reply path. */
const DA_LABEL_FORMAT='dnsalias-domain-labels-1';
const DA_LABEL_APPLICATION=0x44414c31;
const DA_LABEL_MAX_BYTES=16777216;
const DA_LABEL_MAX_DOMAINS=20000;

function da_labels_domain(string $value): string {
    $value=strtolower(rtrim(trim($value),'.'));
    if(strlen($value)>253||!preg_match('/^[a-z0-9_](?:[a-z0-9_.-]*[a-z0-9_])?$/D',$value))
        throw new InvalidArgumentException('Choose one exact DNS name for labels.');
    foreach(explode('.',$value) as $part)if($part===''||strlen($part)>63)
        throw new InvalidArgumentException('Invalid DNS name for labels.');
    return $value;
}
function da_labels_tags(string $value): array {
    if(strlen($value)>512)throw new InvalidArgumentException('Use up to eight tags, separated by commas.');
    $tags=[];
    foreach(explode(',',$value) as $part){
        $tag=strtolower(trim($part));if($tag==='')continue;
        if(!preg_match('~^[a-z0-9][a-z0-9 _./-]{0,39}$~D',$tag))
            throw new InvalidArgumentException('Tags must be 1–40 letters, digits, spaces, dots, slashes, underscores or hyphens.');
        $tags[$tag]=true;
    }
    if(count($tags)>8)throw new InvalidArgumentException('Use at most eight tags per domain.');
    $result=array_keys($tags);sort($result,SORT_STRING);return $result;
}
function da_labels_schema(): array {
    return [
        'domain_labels'=>"CREATE TABLE domain_labels(domain TEXT PRIMARY KEY,review TEXT NOT NULL CHECK(review IN ('','good','bad','investigate')),updated_utc INTEGER NOT NULL)",
        'domain_tags'=>'CREATE TABLE domain_tags(domain TEXT NOT NULL,tag TEXT NOT NULL,PRIMARY KEY(domain,tag),FOREIGN KEY(domain) REFERENCES domain_labels(domain) ON DELETE CASCADE)',
        'domain_labels_review'=>'CREATE INDEX domain_labels_review ON domain_labels(review,domain)',
        'domain_tags_tag'=>'CREATE INDEX domain_tags_tag ON domain_tags(tag,domain)',
    ];
}
function da_labels_file(string $path,int $limit): array {
    clearstatcache(true,$path);$s=@lstat($path);
    if(!$s||($s['mode']&0170000)!==0100000||($s['mode']&0777)!==0600||
       $s['uid']!==posix_geteuid()||$s['nlink']!==1||$s['size']>$limit)
        throw new RuntimeException('Domain label file ownership or size changed.');
    return $s;
}
function da_labels_create_file(string $path,string $bytes): void {
    $f=@fopen($path,'x+b');if($f===false)throw new RuntimeException('Domain label creation requires inspection.');
    try{
        if(!chmod($path,0600)||fwrite($f,$bytes)!==strlen($bytes)||!fflush($f)||!fsync($f))
            throw new RuntimeException('Domain label creation outcome requires inspection.');
    }finally{fclose($f);}
}
function da_labels_layout(string $data,bool $create=false): ?array {
    $directory=$data.'-labels';
    if(!file_exists($directory)&&!is_link($directory)){
        if(!$create)return null;
        $parent=@lstat($data);
        if(realpath($data)!==$data||!$parent||($parent['mode']&0170000)!==0040000||
           ($parent['mode']&0777)!==0700||$parent['uid']!==posix_geteuid())
            throw new RuntimeException('Owned DNS Alias data directory required.');
        if(!@mkdir($directory,0700))throw new RuntimeException('Domain label store creation requires inspection.');
        da_labels_create_file($directory.'/OWNER.json',json_encode(['format'=>DA_LABEL_FORMAT,'data'=>$data],JSON_THROW_ON_ERROR)."\n");
        da_labels_create_file($directory.'/labels.lock','');
    }
    clearstatcache(true,$directory);$s=@lstat($directory);
    if(realpath($directory)!==$directory||!$s||($s['mode']&0170000)!==0040000||
       ($s['mode']&0777)!==0700||$s['uid']!==posix_geteuid())
        throw new RuntimeException('Domain label store ownership changed.');
    $limits=['OWNER.json'=>2048,'labels.lock'=>0,'labels.sqlite'=>DA_LABEL_MAX_BYTES,
             'labels.sqlite-journal'=>DA_LABEL_MAX_BYTES,'labels.pending.sqlite'=>DA_LABEL_MAX_BYTES,
             'labels.pending.sqlite-journal'=>DA_LABEL_MAX_BYTES];
    foreach(new DirectoryIterator($directory) as $p){
        if($p->isDot())continue;$name=$p->getFilename();
        if(!isset($limits[$name]))throw new RuntimeException('Unexpected domain label store content.');
        da_labels_file($p->getPathname(),$limits[$name]);
    }
    da_labels_file($directory.'/OWNER.json',2048);da_labels_file($directory.'/labels.lock',0);
    $owner=json_decode(file_get_contents($directory.'/OWNER.json'),true,8,JSON_THROW_ON_ERROR);
    if($owner!==['format'=>DA_LABEL_FORMAT,'data'=>$data])throw new RuntimeException('Domain label store identity changed.');
    return ['directory'=>$directory,'database'=>$directory.'/labels.sqlite','lock'=>$directory.'/labels.lock'];
}
function da_labels_lock(array $layout,int $operation) {
    $before=da_labels_file($layout['lock'],0);$f=@fopen($layout['lock'],'r+b');
    if($f===false)throw new RuntimeException('Domain label lock unavailable.');
    $opened=fstat($f);
    if($before['dev']!==$opened['dev']||$before['ino']!==$opened['ino']){fclose($f);throw new RuntimeException('Domain label lock changed.');}
    $until=microtime(true)+0.25;
    while(!flock($f,$operation|LOCK_NB)){
        if(microtime(true)>=$until){fclose($f);throw new RuntimeException('Domain labels are busy. Refresh before saving again.');}
        usleep(5000);
    }
    return $f;
}
function da_labels_verify_db(SQLite3 $db): void {
    if($db->querySingle('PRAGMA application_id')!==DA_LABEL_APPLICATION||$db->querySingle('PRAGMA user_version')!==1||
       strtolower((string)$db->querySingle('PRAGMA journal_mode'))!=='delete')
        throw new RuntimeException('Domain label database identity changed.');
    $actual=[];$rows=$db->query('SELECT name,sql FROM sqlite_master WHERE sql IS NOT NULL');
    while($r=$rows->fetchArray(SQLITE3_ASSOC))$actual[$r['name']]=$r['sql'];$rows->finalize();
    $expected=da_labels_schema();ksort($actual);ksort($expected);
    if($actual!==$expected)throw new RuntimeException('Domain label database schema changed.');
}
function da_labels_open(array $layout,bool $write=false): SQLite3 {
    if(file_exists($layout['directory'].'/labels.pending.sqlite')||is_link($layout['directory'].'/labels.pending.sqlite'))
        throw new RuntimeException('Incomplete domain label creation requires inspection.');
    da_labels_file($layout['database'],DA_LABEL_MAX_BYTES);
    $db=new SQLite3($layout['database'],$write?SQLITE3_OPEN_READWRITE:SQLITE3_OPEN_READONLY);
    try{$db->enableExceptions(true);$db->busyTimeout(250);da_labels_verify_db($db);$db->exec('PRAGMA foreign_keys=ON');}
    catch(Throwable $e){$db->close();throw $e;}
    return $db;
}
function da_labels_initialize(array $layout): void {
    $pending=$layout['directory'].'/labels.pending.sqlite';
    if(file_exists($pending)||is_link($pending))throw new RuntimeException('Incomplete domain label creation requires inspection.');
    if(is_file($layout['database']))return;
    da_labels_create_file($pending,'');$db=new SQLite3($pending,SQLITE3_OPEN_READWRITE);$db->enableExceptions(true);
    try{
        $db->busyTimeout(250);$db->exec('PRAGMA journal_mode=DELETE');$db->exec('PRAGMA application_id='.DA_LABEL_APPLICATION);$db->exec('PRAGMA user_version=1');
        $db->exec('BEGIN IMMEDIATE');foreach(da_labels_schema() as $sql)$db->exec($sql);$db->exec('COMMIT');da_labels_verify_db($db);
    }finally{$db->close();}
    da_labels_file($pending,DA_LABEL_MAX_BYTES);
    if(file_exists($layout['database'])||!rename($pending,$layout['database']))throw new RuntimeException('Domain label publication outcome requires inspection.');
}
function da_labels_save(string $data,string $domain,string $review,string $tag_text): array {
    $domain=da_labels_domain($domain);$tags=da_labels_tags($tag_text);
    if(!in_array($review,['','good','bad','investigate'],true))throw new InvalidArgumentException('Choose a valid review status.');
    $layout=da_labels_layout($data,true);$lock=da_labels_lock($layout,LOCK_EX);$db=null;
    try{
        da_labels_initialize($layout);$db=da_labels_open($layout,true);
        $pages=(int)floor(DA_LABEL_MAX_BYTES/(int)$db->querySingle('PRAGMA page_size'));$db->exec('PRAGMA max_page_count='.$pages);
        $db->exec('BEGIN IMMEDIATE');
        $p=$db->prepare('SELECT count(*) FROM domain_labels WHERE domain=:domain');$p->bindValue(':domain',$domain,SQLITE3_TEXT);$result=$p->execute();$exists=$result->fetchArray(SQLITE3_NUM)[0]>0;$result->finalize();$p->close();
        if(!$exists&&($review!==''||$tags)&&(int)$db->querySingle('SELECT count(*) FROM domain_labels')>=DA_LABEL_MAX_DOMAINS)
            throw new RuntimeException('Domain label capacity reached. Remove unused labels before adding more.');
        $p=$db->prepare('DELETE FROM domain_tags WHERE domain=:domain');$p->bindValue(':domain',$domain,SQLITE3_TEXT);$p->execute()->finalize();$p->close();
        if($review===''&&!$tags){$p=$db->prepare('DELETE FROM domain_labels WHERE domain=:domain');}
        else{
            $p=$db->prepare('INSERT INTO domain_labels(domain,review,updated_utc) VALUES(:domain,:review,:updated) ON CONFLICT(domain) DO UPDATE SET review=excluded.review,updated_utc=excluded.updated_utc');
            $p->bindValue(':review',$review,SQLITE3_TEXT);$p->bindValue(':updated',time(),SQLITE3_INTEGER);
        }
        $p->bindValue(':domain',$domain,SQLITE3_TEXT);$p->execute()->finalize();$p->close();
        foreach($tags as $tag){$p=$db->prepare('INSERT INTO domain_tags(domain,tag) VALUES(:domain,:tag)');$p->bindValue(':domain',$domain,SQLITE3_TEXT);$p->bindValue(':tag',$tag,SQLITE3_TEXT);$p->execute()->finalize();$p->close();}
        $db->exec('COMMIT');return ['domain'=>$domain,'review'=>$review,'tags'=>$tags];
    }catch(Throwable $e){if($db!==null){try{$db->exec('ROLLBACK');}catch(Throwable $ignored){}}throw $e;}
    finally{if($db!==null)$db->close();flock($lock,LOCK_UN);fclose($lock);}
}
function da_labels_snapshot(string $data,array $domains=[]): array {
    $layout=da_labels_layout($data);$out=['available'=>true,'exists'=>$layout!==null,'labels'=>[],'tags'=>[]];
    if($layout===null)return $out;
    $lock=da_labels_lock($layout,LOCK_SH);$db=null;
    try{
        $db=da_labels_open($layout);$db->exec('BEGIN');
        $rows=$db->query('SELECT DISTINCT tag FROM domain_tags ORDER BY tag LIMIT 128');while($row=$rows->fetchArray(SQLITE3_NUM))$out['tags'][]=$row[0];$rows->finalize();
        if(count($domains)>500)throw new InvalidArgumentException('Bounded domain label lookup required.');
        $names=[];
        foreach($domains as $domain){
            try{$domain=da_labels_domain($domain);}catch(InvalidArgumentException $e){continue;}
            $names[$domain]=true;
        }
        if($names){
            $slots=implode(',',array_fill(0,count($names),'?'));
            $p=$db->prepare("SELECT l.domain,l.review,l.updated_utc,t.tag FROM domain_labels l LEFT JOIN domain_tags t ON t.domain=l.domain WHERE l.domain IN ($slots) ORDER BY l.domain,t.tag");
            foreach(array_keys($names) as $i=>$name)$p->bindValue($i+1,$name,SQLITE3_TEXT);
            $rows=$p->execute();$found=[];
            while($row=$rows->fetchArray(SQLITE3_ASSOC)){
                $name=$row['domain'];
                $found[$name]??=['review'=>$row['review'],'updated_utc'=>$row['updated_utc'],'tags'=>[]];
                if($row['tag']!==null)$found[$name]['tags'][]=$row['tag'];
            }
            $rows->finalize();$p->close();
            foreach($names as $name=>$_)if(isset($found[$name]))$out['labels'][$name]=$found[$name];
        }
        $db->exec('COMMIT');return $out;
    }finally{if($db!==null)$db->close();flock($lock,LOCK_UN);fclose($lock);}
}
function da_labels_attach(SQLite3 $events,string $data): bool {
    $layout=da_labels_layout($data);if($layout===null)return false;
    $lock=da_labels_lock($layout,LOCK_SH);$db=null;
    try{
        $db=da_labels_open($layout);$db->close();$db=null;
        $events->exec('PRAGMA query_only=ON');$p=$events->prepare('ATTACH DATABASE :path AS da_labels');
        $p->bindValue(':path',$layout['database'],SQLITE3_TEXT);$p->execute()->finalize();$p->close();return true;
    }finally{if($db!==null)$db->close();flock($lock,LOCK_UN);fclose($lock);}
}
function da_labels_query(array $query): array {
    $out=['review'=>'','tag'=>'','hide_tag'=>''];
    foreach($out as $key=>$ignored){
        $value=$query[$key]??'';if(!is_string($value))throw new InvalidArgumentException('Invalid domain label filter.');
        if($key==='review'){
            if(!in_array($value,['','hide_good','unreviewed','good','bad','investigate'],true))throw new InvalidArgumentException('Invalid domain review filter.');
            $out[$key]=$value;
        }elseif($value!==''){
            $tags=da_labels_tags($value);if(count($tags)!==1)throw new InvalidArgumentException('Choose one tag per filter.');$out[$key]=$tags[0];
        }
    }
    return $out;
}
function da_labels_filter_active(array $v): bool {
    return ($v['review']??'')!==''||($v['tag']??'')!==''||($v['hide_tag']??'')!=='';
}
function da_labels_clause(array $v,array &$params): string {
    if(($v['labels']['available']??true)!==true||!da_labels_filter_active($v))return '';
    $review=$v['review']??'';$tag=$v['tag']??'';$hide=$v['hide_tag']??'';
    if(empty($v['labels_joined']))return in_array($review,['good','bad','investigate'],true)||$tag!==''?' AND 0':'';
    $sql='';$status="COALESCE((SELECT l.review FROM da_labels.domain_labels l WHERE l.domain=events.domain),'')";
    if($review==='hide_good')$sql.=" AND $status<>'good'";
    elseif($review==='unreviewed')$sql.=" AND $status=''";
    elseif($review!==''){$sql.=" AND $status=:label_review";$params[':label_review']=$review;}
    if($tag!==''){$sql.=' AND EXISTS(SELECT 1 FROM da_labels.domain_tags t WHERE t.domain=events.domain AND t.tag=:label_tag)';$params[':label_tag']=$tag;}
    if($hide!==''){$sql.=' AND NOT EXISTS(SELECT 1 FROM da_labels.domain_tags t WHERE t.domain=events.domain AND t.tag=:label_hide_tag)';$params[':label_hide_tag']=$hide;}
    return $sql;
}
function da_labels_load_visible(array &$v): void {
    if(!in_array($v['view'],['overview','clients','client','domains','domain'],true)||($v['labels']['available']??true)!==true)return;
    $names=[];if(($v['domain']??'')!=='')$names[]=$v['domain'];
    foreach(['domains','dns','client_events'] as $key)foreach($v[$key]??[] as $row)if(is_string($row['domain']??null))$names[]=$row['domain'];
    try{$v['labels']=da_labels_snapshot($v['data_directory'],array_values(array_unique($names)));}
    catch(Throwable $error){$v['labels']=['available'=>false,'exists'=>true,'labels'=>[],'tags'=>[]];$v['labels_error']='Domain labels are unavailable. Review/tag filters are not applied.';}
}
function da_labels_return_url(array $query): string {
    $out=[];
    foreach(['window','client','domain','tracker','destination','action','view','feed','review','tag','hide_tag'] as $key)
        if(isset($query[$key])&&is_string($query[$key])&&strlen($query[$key])<=253&&$query[$key]!=='')$out[$key]=$query[$key];
    return 'dnsalias_status.php'.($out?'?'.http_build_query($out,'','&',PHP_QUERY_RFC3986):'');
}
function da_labels_post(array $post,bool $allowed,string $data): array {
    if(!$allowed)throw new RuntimeException('Firewall editing privilege required to edit domain labels.');
    if(($post['domain_label_op']??null)!=='save'||isset($post['alias_op'])||isset($post['trial_op']))throw new InvalidArgumentException('Invalid domain label action.');
    foreach(['label_domain'=>253,'label_review'=>16,'label_tags'=>512] as $key=>$limit)
        if(!is_string($post[$key]??null)||strlen($post[$key])>$limit)throw new InvalidArgumentException('Invalid domain label input.');
    return da_labels_save($data,$post['label_domain'],$post['label_review'],$post['label_tags']);
}
function da_labels_cell(array $v,string $domain): array {
    if(($v['labels']['available']??true)!==true)return ['text'=>'Labels unavailable'];
    try{$domain=da_labels_domain($domain);}catch(InvalidArgumentException $e){return ['text'=>''];}
    $label=$v['labels']['labels'][$domain]??['review'=>'','tags'=>[]];
    return ['domain_label'=>['domain'=>$domain,'review'=>$label['review'],'tags'=>$label['tags']],
            'editable'=>!empty($v['can_control'])&&($v['labels']['available']??true)];
}
function da_labels_cell_render(array $cell): void {
    $label=$cell['domain_label'];$text=$label['review']===''?'Unreviewed':ucfirst($label['review']);$tags=implode(', ',$label['tags']);
    if($tags!=='')$text.=' · '.(strlen($tags)>45?substr($tags,0,42).'…':$tags);
    if(!empty($cell['editable']))echo '<button type="button" class="da-detail da-domain-label" data-domain-label="'.da_h(json_encode($label,JSON_INVALID_UTF8_SUBSTITUTE)).'" title="'.da_h('Edit review / tags for '.$label['domain'].($tags!==''?' · '.$tags:'')).'">'.da_h($text).'</button>';
    else echo '<span title="'.da_h($tags).'">'.da_h($text).'</span>';
}
function da_labels_filters_render(array $v): void {
    // Preserve filters on other views without suggesting that they narrow traffic.
    if(!in_array($v['view'],['overview','clients','client','domains','domain'],true)){
        foreach(['review','tag','hide_tag'] as $key)echo '<input type="hidden" name="'.$key.'" value="'.da_h($v[$key]??'').'">';return;
    }
    ?>
    <details class="da-advanced da-label-filters" <?=da_labels_filter_active($v)?'open':''?>><summary>Domain review / tags<?=da_labels_filter_active($v)?' · active':''?></summary><div>
      <label>Review<select name="review"><?php foreach([''=>'All reviews','hide_good'=>'Hide Good','unreviewed'=>'Unreviewed','good'=>'Good','bad'=>'Bad','investigate'=>'Investigate'] as $value=>$label): ?><option value="<?=da_h($value)?>" <?=($v['review']??'')===$value?'selected':''?>><?=da_h($label)?></option><?php endforeach; ?></select></label>
      <label>Include tag<input name="tag" value="<?=da_h($v['tag']??'')?>" maxlength="40" list="da-known-tags" placeholder="Any tag"></label>
      <label>Hide tag<input name="hide_tag" value="<?=da_h($v['hide_tag']??'')?>" maxlength="40" list="da-known-tags" placeholder="No hidden tag"></label>
      <datalist id="da-known-tags"><?php foreach($v['labels']['tags']??[] as $tag): ?><option value="<?=da_h($tag)?>"></option><?php endforeach; ?></datalist>
      <p>Filters affect DNS lists and client timelines. Totals, charts and firewall traffic stay complete for the other selected filters.</p>
    </div></details>
    <?php
}
function da_labels_context_render(array $v): void {
    if(($v['labels_error']??'')!=='')echo '<div class="da-notice da-warn" role="status">'.da_h($v['labels_error']).'</div>';
    if(($v['labels_post_error']??'')!=='')echo '<div class="da-notice da-danger" role="alert">'.da_h($v['labels_post_error']).'</div>';
    if(da_labels_filter_active($v)){
        $applied=in_array($v['view'],['overview','domains','client'],true);
        echo '<p class="da-footnote">Review / tag filters '.($applied?'narrow DNS lists and timelines only.':'are retained for DNS lists; they do not narrow this view.').' <a href="'.da_h(da_url($v,['review'=>'','tag'=>'','hide_tag'=>'','before'=>'','asof'=>''])).'">Clear review / tag filters ×</a></p>';
    }
}
function da_labels_dialog_render(array $v): void {
    if(empty($v['can_control'])||!in_array($v['view'],['overview','clients','client','domains','domain'],true))return;
    ?>
    <dialog id="da-domain-label-dialog" aria-labelledby="da-domain-label-title"><form method="post" action="<?=da_h(da_labels_return_url($v))?>">
      <div class="da-dialog-header"><h2 id="da-domain-label-title">Domain review / tags</h2><button type="button" data-close-domain-label aria-label="Close domain review">✕</button></div>
      <p id="da-domain-label-name"></p><input type="hidden" name="domain_label_op" value="save"><input type="hidden" name="label_domain">
      <label>Review<select name="label_review"><?php foreach([''=>'Unreviewed','good'=>'Good','bad'=>'Bad','investigate'=>'Investigate'] as $value=>$text): ?><option value="<?=da_h($value)?>"><?=da_h($text)?></option><?php endforeach; ?></select></label>
      <label>Tags<input name="label_tags" maxlength="512" placeholder="social media, work"></label>
      <p class="da-footnote">Up to eight comma-separated tags. Labels apply to this exact DNS name across clients. They never change DNS replies, aliases or firewall rules. Unreviewed with no tags clears its labels.</p>
      <button type="submit" class="da-primary">Save labels</button> <button type="button" data-close-domain-label>Cancel</button>
    </form></dialog>
    <?php
}
