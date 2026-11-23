<script>
(() => {
  'use strict';
  const root = document.getElementById('da-console');
  if (!root) return;
  const labelDialog=root.querySelector('#da-domain-label-dialog');
  if(labelDialog){
    root.addEventListener('click',event=>{
      const button=event.target.closest('[data-domain-label]');if(!button)return;
      try{
        const label=JSON.parse(button.dataset.domainLabel);
        labelDialog.querySelector('[name=label_domain]').value=label.domain;
        labelDialog.querySelector('#da-domain-label-name').textContent=label.domain;
        labelDialog.querySelector('[name=label_review]').value=label.review;
        labelDialog.querySelector('[name=label_tags]').value=label.tags.join(', ');
        labelDialog.showModal();
      }catch(_){/* Invalid display data never becomes an action. */}
    });
    labelDialog.querySelectorAll('[data-close-domain-label]').forEach(button=>button.addEventListener('click',()=>labelDialog.close()));
  }
  const panels = [...root.querySelectorAll('[data-panel]')];
  const names = new Map([...root.querySelectorAll('.da-nav [data-nav]')].map(a=>[a.dataset.nav,a.childNodes[1].textContent.trim()]));
  const search = root.querySelector('#da-table-search');
  let searchText = new WeakMap();
  const applySearch = () => {
    if (!search) return;
    const value=search.value.toLowerCase();
    for (const panel of panels.filter(p=>p.dataset.panel===root.dataset.view)) for (const table of panel.querySelectorAll('table')) {
      const rows=[...table.querySelectorAll('tbody [data-row]')];
      if(!rows.length)continue; // Native alias forms/tables do not use this search.
      rows.forEach(row=>{
        if(value&&!searchText.has(row))searchText.set(row,row.textContent.toLowerCase());
        const hidden=!!value&&!searchText.get(row).includes(value);
        if(row.hidden!==hidden)row.hidden=hidden;
      });
      const notice=table.parentElement.nextElementSibling;
      if(notice?.classList.contains('da-search-empty'))notice.hidden=rows.some(r=>!r.hidden);
    }
  };
  const show = name => {
    if (!names.has(name)) name='overview';
    if (!panels.some(p=>p.dataset.panel===name)) {location.assign(root.querySelector('.da-nav [data-nav="'+name+'"]').href);return;}
    root.dataset.view=name;
    panels.forEach(p=>p.classList.toggle('da-visible',p.dataset.panel===name));
    root.querySelectorAll('.da-nav [data-nav]').forEach(a=>{if(a.dataset.nav===name)a.setAttribute('aria-current','page');else a.removeAttribute('aria-current');});
    root.querySelector('[name=view]').value=name;
    root.querySelector('#da-view-name').textContent=names.get(name);
    const searchTools=root.querySelector('.da-table-tools');
    if(searchTools)searchTools.hidden=['overview','aliases'].includes(name);
    if(search)search.value='';applySearch();
    root.querySelector('#da-refresh-now').href=location.href;
  };
  root.classList.add('da-js');
  // Only known navigation names are view hashes. Editor/reference fragments
  // identify elements within the selected view and must not hide that view.
  const hashView=location.hash.startsWith('#da-')?location.hash.slice(4):null;
  show(names.has(hashView)?hashView:root.dataset.view);
  root.querySelectorAll('[data-nav]').forEach(a=>a.addEventListener('click',e=>{
    if(e.defaultPrevented||e.button!==0||e.ctrlKey||e.metaKey||e.shiftKey||e.altKey)return;
    if(!panels.some(p=>p.dataset.panel===a.dataset.nav))return;
    if(a.dataset.nav===root.dataset.view)return;
    e.preventDefault();show(a.dataset.nav);history.pushState({dnsAliasPanel:true},'',a.href);
    root.querySelector('#da-refresh-now').href=location.href;
  }));
  if(search)search.addEventListener('input',applySearch);
  root.addEventListener('keydown',e=>{if(e.key==='Escape'&&document.activeElement===search){search.value='';applySearch();}});
  let sortCollator;
  // Keys contain only static column labels and the view name. Remember only
  // the column and direction for this browser tab.
  const pageOrders=new Map();
  const sortKey=table=>'sort.'+table.closest('[data-panel]').dataset.panel+'.'+
    Array.from(table.tHead.rows[0].cells,h=>h.textContent.trim()).join('|');
  const sortTable = (table, index, requestedDirection, remember=true) => {
    const header=table.tHead?.rows[0]?.cells[index], body=table.tBodies[0];
    if(!header||!body)return;
    if(!remember&&header.getAttribute('aria-sort')===requestedDirection)return;
    const rows=Array.from(body.rows).filter(row=>row.hasAttribute('data-row'));
    const keyed=rows.map(row=>{
      const cell=row.cells[index];
      if(cell.dataset.ipOrder!==undefined)return {row,type:'ip',value:cell.dataset.ipOrder};
      const raw=cell.dataset.order??cell.querySelector('time[data-utc]')?.dataset.utc??cell.textContent.trim();
      const number=Number(raw);
      return raw!==''&&Number.isFinite(number)?{row,type:'number',value:number}:{row,type:'text',value:raw};
    });
    let direction=requestedDirection;
    if(!direction){
      const previous=header.getAttribute('aria-sort');
      if(previous==='ascending')direction='descending';
      else if(previous==='descending')direction='ascending';
      else direction=keyed[0]?.type==='number'?'descending':'ascending';
    }
    if(!sortCollator)sortCollator=new Intl.Collator(undefined,{numeric:true});
    keyed.sort((a,b)=>{
      let order;
      if(a.type!==b.type)order=a.type<b.type?-1:1;
      else if(a.type==='number')order=a.value-b.value;
      else if(a.type==='ip')order=a.value<b.value?-1:a.value>b.value?1:0;
      else order=sortCollator.compare(a.value,b.value);
      return direction==='descending'?-order:order;
    });
    if(keyed.some((item,i)=>item.row!==rows[i])){
      let anchor=body.firstElementChild;
      for(const {row} of keyed){
        if(row===anchor)anchor=anchor.nextElementSibling;
        else if(body.moveBefore)body.moveBefore(row,anchor);
        else body.insertBefore(row,anchor);
      }
    }
    const previous=table.tHead.querySelector('[aria-sort="ascending"],[aria-sort="descending"]');
    previous?.removeAttribute('aria-sort');
    header.setAttribute('aria-sort',direction);
    if(remember){
      const key=sortKey(table),value=index+','+direction;
      pageOrders.set(key,value);
      preference(key,value);
    }
    if(table.classList.contains('da-client-timeline')){
      const controls=table.parentElement.previousElementSibling;
      if(controls?.classList.contains('da-card-sort')){
        controls.querySelector('select').value=String(index);
        controls.querySelector('button').textContent=direction==='descending'?'Descending ↓':'Ascending ↑';
      }
    }
  };
  root.addEventListener('click',e=>{
    const button=e.target.closest?.('.da-sort,.da-card-sort button');if(!button)return;
    const th=button.closest('th');
    if(th){sortTable(th.closest('table'),th.cellIndex);return;}
    const controls=button.closest('.da-card-sort');
    sortTable(controls.nextElementSibling.querySelector('table'),Number(controls.querySelector('select').value));
  });
  root.addEventListener('change',e=>{
    const controls=e.target.closest?.('.da-card-sort');
    if(controls&&e.target.tagName==='SELECT')sortTable(controls.nextElementSibling.querySelector('table'),Number(e.target.value));
  });
  const timeMode=root.querySelector('#da-time-mode');
  // Preferences only, scoped to this tab; never persist observations or filters.
  const preference=(key,value)=>{try {if(value===undefined)return sessionStorage.getItem('dnsalias.ui.'+key);sessionStorage.setItem('dnsalias.ui.'+key,value);}catch(_){}return null;};
  const restoreOrder=table=>{
    const key=sortKey(table),saved=pageOrders.get(key)??preference(key);
    const match=saved&&/^([0-9]+),(ascending|descending)$/.exec(saved);
    if(match)sortTable(table,Number(match[1]),match[2],false);
  };
  root.querySelectorAll('[data-panel] table.da-table').forEach(restoreOrder);
  const savedTime=preference('time');if(['local','utc'].includes(savedTime))timeMode.value=savedTime;
  let localTime;
  const setTimes=(scope=root)=>scope.querySelectorAll('time[data-utc]').forEach(t=>{
    const d=new Date(Number(t.dataset.utc)*1000);
    if(timeMode.value!=='utc'&&!localTime)localTime=new Intl.DateTimeFormat(undefined,{month:'short',day:'numeric',hour:'2-digit',minute:'2-digit',second:'2-digit'});
    t.textContent=timeMode.value==='utc'?d.toISOString().replace('T',' ').slice(0,19)+' UTC':localTime.format(d);
    t.title=d.toISOString();
  });
  timeMode.addEventListener('change',()=>{
    preference('time',timeMode.value);
    setTimes();
    searchText=new WeakMap();
    if(search?.value)applySearch();
  });
  setTimes();
  const dialog=root.querySelector('#da-event-dialog'), fields=root.querySelector('#da-event-fields');
  root.addEventListener('click',e=>{
    const b=e.target.closest?.('button[data-detail],button[data-detail-delta]');if(!b||!root.contains(b))return;
    let data;
    if (b.hasAttribute('data-detail-delta')) {
      const base=b.closest('table')?.querySelector('button[data-detail-base]');
      if(!base)return;
      data={...JSON.parse(base.dataset.detail),...JSON.parse(b.dataset.detailDelta)};
    } else data=JSON.parse(b.dataset.detail);
    fields.replaceChildren();
    for (const [key,value] of Object.entries(data)) {const dt=document.createElement('dt'),dd=document.createElement('dd');dt.textContent=key;dd.textContent=String(value);fields.append(dt,dd);}
    dialog.showModal();
  });
  root.querySelector('#da-close-dialog').addEventListener('click',()=>dialog.close());
  const policyDialog=root.querySelector('#da-policy-dialog'), policyFields=root.querySelector('#da-policy-fields');
  let draft=null;
  root.addEventListener('click',e=>{
    const button=e.target.closest?.('button[data-review-intent],button[data-review]');if(!button||!root.contains(button))return;
    const context=button.closest('[data-review-context]');
    const r=JSON.parse(context?context.dataset.reviewContext:button.dataset.review);
    if(context)r.intent=button.dataset.reviewIntent;
    if(!['allow','block'].includes(r.intent))return;
    const domain=r.target_type==='domain';
    const label=r.intent==='allow'?'Allow':'Block';
    draft={format:'dnsalias-policy-draft-1',state:'unapplied',created_utc:new Date().toISOString(),intent:r.intent,
      source:{kind:'exact_logged_address',address:r.client,identity_verified:false},
      target:{kind:domain?'exact_dns_name':'exact_destination_ip',value:r.target,include_subdomains:false},
      destination_ports:domain?[80,443]:[r.port],protocols:domain?['tcp','udp']:[r.protocol],
      observed_tracker:r.tracker||null,apply_authorized:false,
      required_checks:['verified_source_and_interface','qualified_reply_feed','owned_alias_and_rule','existing_policy_order','shared_ip_impact','router_local_rollback'],
      note:'Review artifact only. Not an executable configuration or an installed rule.'};
    root.querySelector('#da-policy-title').textContent=label+' for '+r.client;
    policyFields.replaceChildren();
    const values={'Client scope':r.client+' only (logged address)','Requested policy':label,'Target':r.target,
      'Match':domain?'Exact DNS name; no subdomains':'Exact destination IP',
      'Traffic':draft.protocols.map(p=>p.toUpperCase()).join(' / ')+' ports '+draft.destination_ports.join(', '),
      'Observed firewall rule':r.tracker||'DNS evidence; no firewall decision attached','Status':'Draft only; enforcement unavailable'};
    for(const [key,value] of Object.entries(values)){const dt=document.createElement('dt'),dd=document.createElement('dd');dt.textContent=key;dd.textContent=value;policyFields.append(dt,dd);}
    root.querySelector('#da-policy-impact').textContent=domain
      ?'DNS-fed IP enforcement can also affect other domains sharing those addresses. This DNS evidence alone does not establish a passed or blocked connection.'
      :'No trusted domain attribution is available for this event. This IP policy would affect every domain using this address in the selected traffic scope.';
    policyDialog.showModal();
  });
  root.querySelector('#da-close-policy').addEventListener('click',()=>policyDialog.close());
  root.querySelector('#da-download-draft').addEventListener('click',()=>{
    if(!draft)return;
    const url=URL.createObjectURL(new Blob([JSON.stringify(draft,null,2)+'\n'],{type:'application/json'}));
    const a=document.createElement('a');a.href=url;a.download='dnsalias-client-policy-draft.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
  });

  // Read-only client filters update only this panel. Native links remain the
  // fallback, including opening a new tab. Late responses cannot win a race.
  let timelineRequest=null,pendingTimeline=null,timelineSequence=0,displayedTimeline=location.pathname+location.search;
  const timelineUrl=(href)=>{
    const u=new URL(href,location.href),panel=root.querySelector('#da-client');
    if(!panel||u.origin!==location.origin||u.pathname!==location.pathname||u.searchParams.get('view')!=='client'||u.searchParams.get('client')!==panel.dataset.client)return null;
    return u;
  };
  const loadTimeline=async(href,push=true)=>{
    const url=timelineUrl(href);if(!url)return false;
    const target=url.pathname+url.search;
    if(timelineRequest&&pendingTimeline===target)return true;
    const sequence=++timelineSequence;timelineRequest?.abort();
    const abort=new AbortController();timelineRequest=abort;pendingTimeline=target;
    const old=root.querySelector('#da-client');
    const status=old.querySelector('.da-feed-status');old.setAttribute('aria-busy','true');
    if(status)status.textContent='Loading activity…';
    const timeout=setTimeout(()=>abort.abort(),8000);
    try{
      const response=await fetch(url,{credentials:'same-origin',cache:'no-store',headers:{'X-DNSAlias-Fragment':'client-v2'},signal:abort.signal});
      if(!response.ok||!(response.headers.get('Content-Type')||'').includes('text/html'))throw Error('Activity unavailable');
      const html=await response.text();if(html.length>8*1024*1024)throw Error('Activity response too large');
      const doc=new DOMParser().parseFromString(html,'text/html'),nextRoot=doc.querySelector('#da-console'),next=doc.querySelector('#da-client');
      if(!nextRoot||nextRoot.dataset.view!=='client'||!next||next.dataset.client!==old.dataset.client||next.querySelector('script,iframe,object,embed')||nextRoot.querySelector('.da-danger'))throw Error('Activity unavailable or session expired');
      if(sequence!==timelineSequence)return true;
      // The user can scroll or move focus while the request is in flight.
      const scrollX=window.scrollX,scrollY=window.scrollY,oldFocus=document.activeElement;
      if(push&&target!==location.pathname+location.search)history.pushState({dnsAliasClientFeed:true},'',url);
      setTimes(next);
      const nextTable=next.querySelector('.da-client-timeline');
      if(nextTable)restoreOrder(nextTable);
      next.classList.add('da-visible');
      const index=panels.indexOf(old);old.replaceWith(next);if(index>=0)panels[index]=next;
      for(const key of ['statusTime','statusAge','running'])root.dataset[key]=nextRoot.dataset[key];
      pageStarted=performance.now();statusAge=Number(root.dataset.statusAge);
      const freshBadge=nextRoot.querySelector('#da-health-badge');if(freshBadge)root.querySelector('#da-health-badge').replaceWith(freshBadge);
      // Coverage is outside the replaced panel. Keep its notice from the same
      // accepted response, including recovery, without accumulating notices.
      const oldReplyWarning=root.querySelector('.da-reply-warning'),freshReplyWarning=nextRoot.querySelector('.da-reply-warning');
      if(freshReplyWarning){
        const warning=document.importNode(freshReplyWarning,true);
        if(oldReplyWarning)oldReplyWarning.replaceWith(warning);else next.before(warning);
      }else oldReplyWarning?.remove();
      root.querySelector('#da-refresh-now').href=url.href;
      const freshLabelForm=doc.querySelector('#da-domain-label-dialog form');
      if(labelDialog&&freshLabelForm)labelDialog.querySelector('form').setAttribute('action',freshLabelForm.getAttribute('action'));
      const filters=root.querySelector('.da-filters');
      const rowsInput=filters.elements.namedItem('rows'),feedInput=filters.elements.namedItem('feed');
      if(rowsInput){rowsInput.value=next.dataset.rows||'';rowsInput.disabled=!rowsInput.value;}
      if(feedInput)feedInput.value=next.dataset.feed||url.searchParams.get('feed')||'all';
      displayedTimeline=target;
      if(search?.value)applySearch();
      // Empty/short results must still leave enough page height to retain the
      // clicked controls' position. The next panel replacement clears this.
      if(scrollY>0 || scrollX>0){
        const missingHeight=scrollY+window.innerHeight-document.documentElement.scrollHeight;
        if(missingHeight>0)next.style.minHeight=(next.getBoundingClientRect().height+missingHeight)+'px';
        window.scrollTo(scrollX,scrollY);
      }
      if(old.contains(oldFocus)&&document.activeElement===document.body){
        const area=oldFocus.closest('.da-page-sizes')?'.da-page-sizes':'.da-feed-filters';
        next.querySelector(area+' [aria-current]')?.focus({preventScroll:true});
      }
    }catch(error){
      if(sequence===timelineSequence){
        root.querySelector('#da-refresh-now').href=url.href;
        if(status)status.textContent='Could not update activity. The previous results are still shown. Use Refresh now to retry the requested view.';
      }
    }finally{
      clearTimeout(timeout);
      if(sequence===timelineSequence){root.querySelector('#da-client')?.removeAttribute('aria-busy');timelineRequest=null;pendingTimeline=null;}
    }
    return true;
  };
  root.addEventListener('click',event=>{
    if(event.defaultPrevented||event.button!==0||event.ctrlKey||event.metaKey||event.shiftKey||event.altKey)return;
    const link=event.target.closest?.('#da-client .da-feed-filters a, #da-client .da-client-cards a, #da-client .da-pagination a');
    if(!link||!timelineUrl(link.href))return;
    event.preventDefault();
    if(!timelineRequest&&link.matches('.da-page-sizes a[aria-current]')&&
       displayedTimeline===location.pathname+location.search&&!root.querySelector('.da-feed-status')?.textContent)return;
    // Re-selecting a freshly displayed filter should not enqueue another
    // query. Links from older cursors still select the latest activity.
    if(!timelineRequest&&link.matches('.da-feed-filters a[aria-current]')&&performance.now()-pageStarted<30000){
      const shown=new URL(displayedTimeline,location.href);
      if(!shown.searchParams.has('before')&&!shown.searchParams.has('asof')&&!root.querySelector('.da-feed-status')?.textContent)return;
    }
    loadTimeline(link.href);
  });
  window.addEventListener('popstate',()=>{
    const url=timelineUrl(location.href);
    if(url){
      if(timelineRequest||displayedTimeline!==url.pathname+url.search)loadTimeline(url.href,false);
    }else{
      const hash=location.hash.startsWith('#da-')?location.hash.slice(4):null;
      const view=names.has(hash)?hash:new URL(location.href).searchParams.get('view')||'overview';
      if(view!==root.dataset.view&&panels.some(p=>p.dataset.panel===view))show(view);
    }
  });
  // One demand-triggered prefetch per page load. No periodic name polling.
  // All returned names are data: create text nodes, never insert HTML.
  if(root.dataset.identityPending==='1') {
    const identityNote=document.createElement('span');identityNote.className='da-pill da-neutral';
    identityNote.textContent='Refreshing client names…';root.querySelector('.da-status').append(identityNote);
    const updateNames=data=>{
      if(data.format!=='dnsalias-client-names-1'||!data.clients||typeof data.clients!=='object')throw Error('Invalid metadata');
      for(const node of root.querySelectorAll('[data-client-ip]')){
        const ip=node.dataset.clientIp,claims=data.clients[ip];
        if(Array.isArray(claims)&&claims.length&&typeof claims[0].name==='string'){
          const claim=claims[0],iface=claim.source==='Router interface'&&typeof claim.interface==='string'&&claim.interface?' · '+claim.interface:'';
          node.textContent=claim.name+iface+' · '+ip;
          const row=node.closest('[data-row]');if(row)searchText.delete(row);
        }
      }
      const box=root.querySelector('#da-client-identity'),claims=box&&data.clients[box.dataset.client];
      if(box&&Array.isArray(claims)&&claims.length){
        const focusedHeader=box.contains(document.activeElement)?document.activeElement.closest('th')?.cellIndex:null;
        const wrap=document.createElement('div');wrap.className='da-table-wrap';
        const table=document.createElement('table');table.className='da-table da-identity-table';
        const head=table.createTHead().insertRow();
        for(const label of ['Name / label','Source','Interface','MAC','Lease expiry']){
          const th=document.createElement('th');th.scope='col';
          const button=document.createElement('button');button.type='button';button.className='da-sort';
          const arrow=document.createElement('span');arrow.setAttribute('aria-hidden','true');
          button.append(label,arrow);th.append(button);head.append(th);
        }
        const body=table.createTBody();
        for(const claim of claims.slice(0,6)){
          const row=body.insertRow();row.setAttribute('data-row','');
          for(const text of [claim.name,claim.source+(claim.alias_members?' · '+claim.alias_members+' configured entries':''),claim.interface||'',claim.mac||'']){row.insertCell().textContent=String(text);}
          const expiry=row.insertCell();
          if(Number.isFinite(claim.expires)){
            const time=document.createElement('time');time.dataset.utc=String(claim.expires);expiry.append(time);
          }else expiry.textContent='Configured';
        }
        wrap.append(table);
        const empty=document.createElement('p');empty.className='da-search-empty';empty.hidden=true;empty.textContent='No rows match this table search.';
        const note=document.createElement('p');note.className='da-footnote';note.textContent='Current local metadata; DHCP names are client supplied and firewall aliases can group devices. Historical address ownership may differ. No automatic DNS lookups.';
        box.replaceChildren(wrap,empty,note);
        setTimes(table);
        restoreOrder(table);
        if(focusedHeader!=null)table.tHead.rows[0].cells[focusedHeader]?.querySelector('button')?.focus({preventScroll:true});
        if(claims.some(claim=>claim.source==='Router interface')){const origin=document.createElement('p');origin.className='da-footnote';origin.textContent='Router interface address. Outbound logs can show translated traffic from other devices. This source alone does not identify the original LAN client or prove that pfSense generated the traffic.';box.append(origin);}
        if(data.at_capacity){const cap=document.createElement('p');cap.className='da-footnote';cap.textContent='Name metadata reached a collection limit; some labels may be absent.';box.append(cap);}
      }
      applySearch();identityNote.textContent='Client names updated';
    };
    const prefetch=async attempt=>{
      if(document.hidden){identityNote.textContent='Client names refresh requested';return;}
      const abort=new AbortController(),limit=setTimeout(()=>abort.abort(),2000);
      try {
        const url=new URL(location.href);url.search='?client_identity=1';url.hash='';
        const response=await fetch(url,{credentials:'same-origin',cache:'no-store',signal:abort.signal});
        if(!response.ok||!(response.headers.get('Content-Type')||'').includes('application/json'))throw Error('Metadata unavailable');
        const data=await response.json();
        if(Number(data.observed_utc)>Number(root.dataset.identityObserved)){updateNames(data);return;}
        if(attempt<3){setTimeout(()=>prefetch(attempt+1),700);return;}
        identityNote.textContent='Client names pending; refresh later';
      }catch(_){identityNote.textContent='Client names unavailable; cached labels retained';}
      finally{clearTimeout(limit);}
    };
    setTimeout(()=>prefetch(0),500);
  }
  let timer;
  // Visible, active controls only: GET status in place, never resend a POST.
  // Keep the native response's CSRF fields when replacing its action forms.
  let controlReads=0,controlFailures=0;
  const pollControls=async()=>{
    const active=['queued','running','cancelling'].includes(root.querySelector('#da-trial-control')?.dataset.state) || ['queued','preparing'].includes(root.querySelector('#da-preparation-control')?.dataset.state);
    if(!active || controlReads>=120)return;
    if(document.hidden){setTimeout(pollControls,2000);return;}
    const abort=new AbortController(),limit=setTimeout(()=>abort.abort(),2500);controlReads++;
    try{
      const url=new URL('dnsalias_status.php?view=aliases',location.href);
      const response=await fetch(url,{method:'GET',credentials:'same-origin',cache:'no-store',signal:abort.signal});
      if(!response.ok || new URL(response.url).origin!==location.origin)throw Error('Control status unavailable');
      const doc=new DOMParser().parseFromString(await response.text(),'text/html');
      if(!doc.querySelector('#da-console'))throw Error('Control status unavailable');
      for(const id of ['da-trial-control','da-preparation-control','da-aliases']){
        const old=root.querySelector('#'+id),fresh=doc.querySelector('#'+id);
        if(old&&fresh)old.replaceWith(document.importNode(fresh,true));
        else if(!old&&fresh&&id==='da-trial-control')root.querySelector('.da-shell').before(document.importNode(fresh,true));
      }
      controlFailures=0;
    }catch(_){controlFailures++;}
    finally{clearTimeout(limit);if(controlFailures<3)setTimeout(pollControls,controlFailures?2500:1000);}
  };
  setTimeout(pollControls,1000);
  const refresh=root.querySelector('#da-refresh');
  const savedRefresh=preference('refresh');if(['0','30','60'].includes(savedRefresh))refresh.value=savedRefresh;
  const arm=()=>{clearTimeout(timer);if(refresh.value!=='0'&&!root.querySelector('#da-trial-control'))timer=setTimeout(()=>{if(!document.hidden&&!dialog.open&&!policyDialog.open&&!labelDialog?.open)location.reload();else arm();},Number(refresh.value)*1000);};
  refresh.addEventListener('change',()=>{preference('refresh',refresh.value);arm();});arm();
  // Freshness must expire even if the user leaves a manually refreshed page open.
  let pageStarted=performance.now(),statusAge=Number(root.dataset.statusAge);
  const health=()=>{if(root.dataset.running==='1' && statusAge+(performance.now()-pageStarted)/1000>=30){const b=root.querySelector('#da-health-badge');b.textContent='● Status needs refresh';b.className='da-pill da-warn';}};
  setInterval(health,5000);health();
})();
</script>
