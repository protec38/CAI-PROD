(function () {
  'use strict';
  const el = (tag, text, className) => { const node = document.createElement(tag); if (text !== undefined) node.textContent = text; if (className) node.className = className; return node; };
  const store = () => window.CAIOfflineStore;
  const csrf = () => document.querySelector('meta[name="csrf-token"]')?.content || '';
  const post = (url, options={}) => fetch(url,{...options,method:'POST',headers:{'X-CSRFToken':csrf(),...options.headers}});
  let context, locked = false, lockDialog, lastActivity = Date.now(), activitySent = 0, draftTimer;
  let searchWatchTimer, searchWatchBusy = false, latestSearches;
  const searchWatchStates = new Map();
  const foundQueue = [];
  let showingFound = false;
  const norm = value => String(value || '').normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLocaleLowerCase('fr').trim().replace(/\s+/g, ' ');
  const labels = {nom:'Nom',prenom:'Prénom',date_naissance:'Date de naissance',telephone:'Téléphone',nationalite:'Nationalité',adresse:'Adresse',numero_pec:'N° PEC',code_sinus:'Code Sinus',difficultes:'Difficultés',competences:'Compétences',destination:'Destination',moyen_transport:'Transport',statut:'Statut',family_key:'Famille / groupe',autres_informations:'Autres informations',effets_perso:'Effets personnels',personne_a_prevenir:'Personne à prévenir',tel_personne_a_prevenir:'Téléphone à prévenir',recherche_personne:'Recherche personne',numero_recherche:'Numéro de recherche',animal_espece:'Espèce',animal_details:'Notes de l’animal',referent_humain_id:'Personne référente',bagages:'Bagages',restauration:'Restauration'};
  const readable = value => typeof value === 'object' ? JSON.stringify(value) : value === true ? 'Oui' : value === false ? 'Non' : String(value || 'Vide');
  const scoped = suffix => `${suffix}:${context.userId}:${context.eventId}`;
  function button(text, action, parent) { const b = el('button', text); b.type = 'button'; b.addEventListener('click', action); parent?.append(b); return b; }
  function link(text, href, parent) { const a = el('a', text); a.href = href; parent.append(a); return a; }
  function modal(title) { const d = el('dialog', undefined, 'feature-modal'); d.setAttribute('aria-label', title); d.append(el('h2', title)); document.body.append(d); return d; }
  async function data() { return window.CAIOffline.listFiches(await window.CAIOffline.cached()); }
  function announce(message, parent) { const p = el('p', message, 'feature-alert'); p.setAttribute('role', 'status'); (parent || document.querySelector('main') || document.body).prepend(p); return p; }
  function applyPreferences() {
    const prefs = context.preferences?.dashboard || {};
    window.CAIAppearance?.apply(prefs);
    for (const key of ['heure_arrivee','difficultes','competences','bagages']) document.body.classList.toggle('cai-hide-' + key, prefs[key] === false);
    document.body.classList.toggle('cai-compact', !!prefs.compact);
    document.body.classList.toggle('cai-hide-counters', prefs.show_counters === false);
  }
  async function preparation() {
    const dialog = modal('Disponibilité hors ligne');
    const content = el('div'); dialog.append(content);
    const render = async () => {
      content.replaceChildren();
      const all = await store().all();
      const contexts = all.filter(r => r.kind === 'context' && r.userId === context.userId);
      for (const item of contexts) {
        const snap = await store().get(`snapshot:${item.userId}:${item.eventId}`);
        const pending = await store().pending(item.userId, item.eventId);
        const card = el('section', undefined, 'feature-extra');
        card.append(el('h3', item.eventName || `Évènement ${item.eventId}`), el('p', snap ? `${snap.data.fiches.length} fiche(s) disponibles · Actualisé le ${new Date(snap.savedAt).toLocaleString('fr-FR')}` : 'Cet évènement n’a pas encore de copie sur cet appareil.'), el('p', `${pending.length} envoi(s) en attente du serveur.`));
        button('Préparer / actualiser cet évènement', async event => {
          event.target.disabled = true;
          try {
            const response = await fetch(`/evenement/${item.eventId}/fiches_json?details=1`, {cache:'no-store'});
            if (!response.ok || response.redirected) throw new Error('Connexion et accès à l’évènement nécessaires.');
            const payload = await response.json();
            await store().put({key:`snapshot:${item.userId}:${item.eventId}`,kind:'snapshot',data:payload,savedAt:new Date().toISOString()});
            await navigator.storage?.persist?.();
            await render();
          } catch (error) { announce(error.message, card); event.target.disabled = false; }
        }, card);
        content.append(card);
      }
      const deleted = all.filter(r=>r.kind==='fiche' && r.userId===context.userId && r.cancelled && r.archivedFields?.length && !r.server && !r.deliveryStarted);
      if(deleted.length) {
        const bin=el('section',undefined,'feature-extra');bin.append(el('h3','Corbeille de cet appareil'));
        for(const record of deleted) {
          const row=el('p',record.label + ' ');
          button('Restaurer cette fiche locale',async()=>{
            await store().change(record.key,current=>({...current,fields:current.archivedFields,archivedFields:[],cancelled:false,deleting:false}));
            window.dispatchEvent(new Event('cai:local')); await render(); window.CAIOffline.sync();
          },row);bin.append(row);
        }
        content.append(bin);
      }
      content.append(el('p', 'Gardez cet onglet ou l’application sur cet appareil. Le navigateur doit conserver ses données pour retrouver les fiches hors ligne.'));
    };
    button('Fermer', () => dialog.close(), dialog);
    dialog.addEventListener('close', () => dialog.remove()); await render(); dialog.showModal();
  }
  function toolbar() {
    const menu = document.querySelector('.dashboard-menu__items');
    if (!menu) return;
    const oldAlert=document.getElementById('feature-broadcast');
    if(context.permissions?.canBroadcast && !oldAlert){const a=link('Envoyer une alerte ou un message','/notifications/broadcast',menu);a.id='feature-broadcast';a.className='btn';menu.querySelector('.btn-main-menu')?.before(a);}
    else if(!context.permissions?.canBroadcast)oldAlert?.remove();
    if(document.getElementById('feature-event-tools'))return;
    const tools = link('Outils de l’évènement', `/evenement/${context.eventId}/outils`, menu);
    tools.id = 'feature-event-tools';
    const preferences = link('Personnaliser mon apparence', `/mes-preferences?next=${encodeURIComponent(`/evenement/${context.eventId}/dashboard`)}`, menu);
    const availability = button('Disponibilité hors ligne', () => {
      const details = menu.closest('details');
      details.open = false;
      details.querySelector('summary').focus();
      preparation().catch(error => announce(error.message));
    }, menu);
    for (const item of [tools, preferences, availability]) item.className = 'btn';
    const search=link('Recherche de personnes','/evenement/'+context.eventId+'/recherches',menu);search.className='btn';search.id='feature-person-search';
    menu.prepend(tools, preferences, availability, search);
  }
  async function lock() {
    if (locked) return;
    locked = true;
    document.querySelectorAll('.search-toast').forEach(node=>node.remove());foundQueue.length=0;
    await store().put({key:`lock:${context.userId}`,locked:true});
    // The dialog prevents keyboard, pointer and screen-reader access to the workspace.
    lockDialog = modal('Appareil verrouillé'); lockDialog.addEventListener('cancel', event => event.preventDefault());
    lockDialog.append(el('p','Vos modifications en attente sont conservées. Reconnectez cet appareil pour saisir votre mot de passe.'));
    const form = el('form', undefined, 'feature-form'), label = el('label','Mot de passe du compte');
    const input = el('input'); input.type='password'; input.autocomplete='current-password'; input.required=true; label.append(input);
    const submit = el('button','Déverrouiller','primary'); submit.type='submit'; const status = el('p'); status.setAttribute('role','alert'); form.append(label,submit,status); lockDialog.append(form); lockDialog.showModal(); input.focus();
    if (navigator.onLine) fetch('/api/session/verrouillage',{cache:'no-store'}).then(r=>r.json()).then(s=>post('/api/session/verrouillage',{headers:{'X-CSRFToken':s.csrf_token}})).catch(()=>{});
    form.addEventListener('submit', async event => {
      event.preventDefault(); submit.disabled=true;
      try {
        if (!navigator.onLine) throw new Error('Reconnectez cet appareil pour déverrouiller.');
        const sessionResponse = await fetch('/api/session/verrouillage',{cache:'no-store'}), sessionData = await sessionResponse.json();
        if (!sessionResponse.ok) throw new Error('Votre session a expiré. Connectez-vous à nouveau.');
        const response = await fetch('/session/deverrouiller',{method:'POST',headers:{'X-CSRFToken':sessionData.csrf_token},body:new URLSearchParams({password:input.value,json:'1'})});
        const result = await response.json(); input.value='';
        if (!response.ok || !result.unlocked || result.user_id!==context.userId) throw new Error(result.error || 'Déverrouillage impossible.');
        await store().put({key:`lock:${context.userId}`,locked:false});
        locked=false; lastActivity=Date.now(); await store().put({key:`activity:${context.userId}`,at:lastActivity}); lockDialog.close(); lockDialog.remove(); lockDialog=null;
        window.CAIOffline?.sync();
      } catch (error) { status.textContent=error.message; }
      finally { submit.disabled=false; }
    });
  }
  async function initLock() {
    const saved = await store().get(`activity:${context.userId}`);
    if (saved?.at) lastActivity=saved.at;
    else await store().put({key:`activity:${context.userId}`,at:lastActivity});
    const check = async () => {
      const latest=await store().get(`activity:${context.userId}`);if(latest?.at)lastActivity=Math.max(lastActivity,latest.at);
      const sharedLock=await store().get(`lock:${context.userId}`);if(sharedLock?.locked && !locked){await lock();return;}
      const minutes=context.preferences?.lock_minutes || 0;
      if (!locked && minutes && Date.now()-lastActivity>=minutes*60000) await lock();
    };
    if ((await store().get(`lock:${context.userId}`))?.locked) await lock();
    await check();
    for (const event of ['pointerdown','keydown','touchstart']) document.addEventListener(event, () => {
      if (locked || Date.now()-lastActivity<1000) return;
      const minutes=context.preferences?.lock_minutes || 0;
      if (minutes && Date.now()-lastActivity>=minutes*60000) { lock(); return; }
      lastActivity=Date.now(); store().put({key:`activity:${context.userId}`,at:lastActivity}).catch(()=>{});
      if (navigator.onLine && lastActivity-activitySent>15000) { activitySent=lastActivity; post('/api/session/activite').catch(()=>{}); }
    },{passive:true});
    setInterval(()=>check().catch(()=>{}),1000);
    document.addEventListener('visibilitychange',()=>{if(!document.hidden) check();});
  }
  function setupSeekerSuggestions() {
    const form=document.getElementById('person-search-create');
    if(!form || form.dataset.suggestionsReady)return;
    form.dataset.suggestionsReady='true';
    const choices=JSON.parse(document.getElementById('seeker-choices').textContent);
    const name=form.elements.seeker_nom, first=form.elements.seeker_prenom, id=form.elements.seeker_fiche_id;
    const host=document.getElementById('seeker-suggestions'), status=document.getElementById('seeker-selection'), unlink=document.getElementById('seeker-unlink');
    const clear=()=>{id.value='';status.textContent='Saisie libre, sans fiche rattachée.';unlink.hidden=true;};
    const suggest=()=>{
      clear();host.replaceChildren();
      const term=norm(name.value), given=norm(first.value);
      const matches=term ? choices.filter(f=>norm(f.nom).includes(term) && (!given || norm(f.prenom).includes(given))).slice(0,10) : [];
      host.hidden=!matches.length;
      for(const fiche of matches)button(`${fiche.nom} ${fiche.prenom} — ${fiche.numero}`,()=>{
        name.value=fiche.nom;first.value=fiche.prenom;id.value=fiche.id;
        status.textContent=`Fiche rattachée : ${fiche.numero} — ${fiche.nom} ${fiche.prenom}`;
        unlink.hidden=false;host.hidden=true;host.replaceChildren();
      },host);
    };
    name.addEventListener('input',suggest);first.addEventListener('input',suggest);
    unlink.addEventListener('click',()=>{clear();host.hidden=true;host.replaceChildren();name.focus();});
  }
  function searchAppearance(article, row) {
    const found=!!row.resolved_at;
    article.classList.toggle('search-found',found);article.classList.toggle('search-missing',!found);
    const status=article.querySelector('[data-search-status]');
    if(status)status.textContent=found?'Personne retrouvée · Recherche terminée':'Personne non retrouvée · Recherche en cours';
    const action=article.querySelector('input[name=action]'), submit=article.querySelector('button[type=submit]');
    if(action)action.value=found?'reopen':'resolve';
    if(submit)submit.textContent=found?'Relancer la recherche':'Marquer comme retrouvée';
  }
  function showNextFound() {
    if(showingFound || locked || !foundQueue.length)return;
    showingFound=true;
    const row=foundQueue.shift(), toast=el('div',`Personne retrouvée : ${row.target_nom} ${row.target_prenom} · Recherchée par ${row.seeker_nom} ${row.seeker_prenom}`,'search-toast');
    toast.setAttribute('role','status');toast.setAttribute('aria-live','polite');document.body.append(toast);
    setTimeout(()=>{toast.remove();showingFound=false;showNextFound();},5000);
  }
  async function pollSearchStatus() {
    if(!context?.eventId || locked || navigator.onLine===false || searchWatchBusy)return;
    searchWatchBusy=true;
    const key=scoped('search-watch');
    try {
      let saved=searchWatchStates.get(key);try{saved ||= JSON.parse(sessionStorage.getItem(key) || 'null');}catch{}
      saved ||= {since:context.searchWatchSince || new Date().toISOString(),seen:[]};
      const started=saved.started || saved.since;
      const response=await fetch(`/api/evenement/${context.eventId}/recherches/etat?since=${encodeURIComponent(saved.since)}`,{cache:'no-store',signal:AbortSignal.timeout(8000)});
      if(!response.ok || response.redirected)return;
      const payload=await response.json();
      // The event may have changed while the request was in flight.
      if(key!==scoped('search-watch') || locked)return;
      const seen=new Set(saved.seen);
      for(const row of payload.notifications){const token=row.id+':'+row.resolved_at;if(!seen.has(token)){seen.add(token);foundQueue.push(row);}}
      // A short overlap also covers resolutions committed while the prior poll ran.
      saved={since:new Date(Math.max(Date.parse(started),Date.parse(payload.server_time)-10000)).toISOString(),started,seen:[...seen].slice(-500)};
      searchWatchStates.set(key,saved);
      try{sessionStorage.setItem(key,JSON.stringify(saved));}catch{}
      latestSearches=payload.searches;
      const snapshot=await store().get(`snapshot:${context.userId}:${context.eventId}`);
      if(snapshot)await store().change(snapshot.key,current=>({...current,data:{...current.data,person_searches:payload.searches}}));
      showNextFound();if(window.CAIOffline)await refresh();
    } catch { /* Keep the current event available when disconnected. */ }
    finally {searchWatchBusy=false;}
  }
  async function ready(ctx) {
    const changed=context?.eventId!==ctx.eventId || context?.userId!==ctx.userId;
    context=ctx;applyPreferences();if(ctx.eventId)toolbar();await initLock();setupSeekerSuggestions();
    if(changed){latestSearches=undefined;clearInterval(searchWatchTimer);if(ctx.eventId){
      const key=scoped('search-watch');
      const initial={since:ctx.searchWatchSince || new Date().toISOString(),seen:[]};
      try{if(!sessionStorage.getItem(key))sessionStorage.setItem(key,JSON.stringify(initial));}catch{searchWatchStates.set(key,initial);}
      pollSearchStatus();searchWatchTimer=setInterval(pollSearchStatus,3000);
    }}
  }
  async function refresh() {
    if (!context || locked) return;
    applyPreferences();if(context.eventId)toolbar();
    const payload = await data(), settings=payload.evenement?.settings || context.eventSettings || {};
    for (const [id,key] of [['sortie-destination','destinations'],['sortie-moyen','transports']]) {
      const input=document.getElementById(id);if(!input)continue;
      const values=settings.choice_lists?.[key] || [], name='dashboard-choices-'+key;
      let dl=document.getElementById(name);if(!dl){dl=el('datalist');dl.id=name;input.after(dl);input.setAttribute('list',name);}
      if(dl.dataset.values!==JSON.stringify(values)){dl.replaceChildren();for(const value of values){const o=el('option');o.value=value;dl.append(o);}dl.dataset.values=JSON.stringify(values);}
    }
    const filters=document.querySelector('#filter-competences .filter-options__choices');
    if(filters) {
      if(!filters.caiDefaults)filters.caiDefaults=[...filters.querySelectorAll('input')].map(i=>i.value);
      const configured=settings.choice_lists?.competences;
      const values=[...new Set([...(configured?.length?configured:filters.caiDefaults),...payload.fiches.flatMap(f=>String(f.competences || '').split(',').filter(Boolean))])];
      if(filters.dataset.values!==JSON.stringify(values)) {
        const selected=[...filters.querySelectorAll('input:checked')].map(i=>i.value);filters.replaceChildren();
        for(const value of values){const label=el('label',undefined,'filter-chip'),input=el('input');input.type='checkbox';input.value=value;input.checked=selected.includes(value);input.addEventListener('change',()=>document.getElementById('search-bar').dispatchEvent(new Event('input')));label.append(input,document.createTextNode(' '+value));filters.append(label);}
        filters.dataset.values=JSON.stringify(values);
      }
    }
    const capacity=settings.capacity;
    let box=document.getElementById('capacity-alert');
    if (capacity) {
      if (!box) {box=el('p',undefined,'feature-alert');box.id='capacity-alert';box.setAttribute('role','status');document.querySelector('.event-info')?.append(box);}
      const present=payload.nb_present || 0, limit=present>=capacity, warning=present*100/capacity>=settings.warning_percent;
      box.textContent=`Capacité d’accueil : ${present} / ${capacity} personnes présentes${limit ? ' · Capacité atteinte' : warning ? ' · Seuil d’alerte atteint' : ''}${payload.fiches.some(f=>f.pending) ? ' · Inclut les envois en attente' : ''}`;
      box.dataset.level=limit?'danger':warning?'warning':'normal';
    } else box?.remove();
    const search=document.getElementById('search-bar');
    if (search) {
      search.placeholder='Nom, téléphone, Sinus, bagage, n° fiche ou groupe…';
      search.setAttribute('aria-label','Rechercher par nom, téléphone, code Sinus, bagage, numéro de fiche ou groupe');
      const group=new URLSearchParams(location.search).get('groupe');
      if(group && !search.dataset.groupLoaded) {search.value=group;search.dataset.groupLoaded='1';search.dispatchEvent(new Event('input'));}
    }
    if(document.body.classList.contains('cai-fiche-detail')) await detailExtras(payload);
    if(document.body.classList.contains('cai-dashboard')) await showWantedNotices();
    const offlineSearch=document.body.classList.contains('cai-offline-search');
    const searchList=document.getElementById(offlineSearch?'offline-search-list':'local-search-list');
    if(searchList) {
      document.querySelector('[data-cai-dashboard-link]').href='/evenement/'+context.eventId+'/dashboard';
      const current=[...(latestSearches || payload.person_searches || []),...(latestSearches ? (payload.person_searches || []).filter(row=>String(row.id).startsWith('local-')) : [])];
      const rendered=new Set([...document.querySelectorAll('[data-search-id]')].map(node=>node.dataset.searchId));
      for(const article of document.querySelectorAll('[data-search-id]')){const row=current.find(row=>String(row.id)===article.dataset.searchId);if(row)searchAppearance(article,row);}
      const searches=current.filter(row=>offlineSearch || !rendered.has(String(row.id)));
      searchList.hidden=!offlineSearch && !searches.length;
      searchList.replaceChildren(el('h2',offlineSearch?'Recherches disponibles sur cet appareil':'Nouvelles recherches disponibles'));
      if(offlineSearch) {
        searchList.append(el('p','Les recherches saisies dans une nouvelle fiche apparaissent ici, même hors ligne. Connectez cet appareil pour terminer une recherche.'));
        link('Créer une fiche et déclarer une recherche','/fiche/new?evenement_id='+context.eventId,searchList);
      }
      for(const row of searches) {
        const article=el('article',undefined,'search-entry');
        article.append(el('h3',row.target_nom+' '+row.target_prenom),el('p','Recherchée par : '+row.seeker_nom+' '+row.seeker_prenom));
        const status=el('p');status.dataset.searchStatus='';article.append(status);searchAppearance(article,row);
        if(row.pending)article.append(el('p','En attente du serveur'));
        for(const fiche of payload.fiches.filter(f=>!f.est_animal && f.statut!=='supprimé' && norm(f.nom)===norm(row.target_nom) && norm(f.prenom)===norm(row.target_prenom))) {
          const p=el('p');link('Fiche correspondante : '+fiche.numero+' — '+fiche.nom+' '+fiche.prenom,'/fiche/'+fiche.id+'?evenement_id='+context.eventId,p);article.append(p);
        }
        searchList.append(article);
      }
      if(!searches.length)searchList.append(el('p','Aucune recherche active dans la copie de cet appareil.'));
    }
  }
  function canonical(form, base) {
    const result={...base}; const entries=new FormData(form), animal=(entries.get('type_fiche') || base.type_fiche)==='animal';
    const aliases={difficulte:'difficultes',animal_nom:'nom',animal_particularites:'difficultes',animal_notes:'animal_details',animal_referent_id:'referent_humain_id'};
    for(const [name,value] of entries) {
      if(name.startsWith('animal_') && !animal) continue;
      if(animal && ['nom','prenom','difficulte'].includes(name)) continue;
      const key=aliases[name] || name;
      if(key in result && !['competences','custom_values'].includes(key)) result[key]=String(value);
    }
    if(form.elements.competences && !animal) result.competences=entries.getAll('competences').map(v=>v==='Autre'?entries.get('competence_autre'):v).filter(Boolean).join(',');
    if(form.elements.custom_values) result.custom_values=JSON.parse(form.elements.custom_values.value || '{}');
    return result;
  }
  function fill(form, values) {
    for(const input of form.elements) {
      if(!input.name || !(input.name in values)) continue;
      const value=values[input.name];
      if(input.multiple) {
        const list=Array.isArray(value)?value:String(value || '').split(',').filter(Boolean);
        for(const v of list) if(![...input.options].some(o=>o.value===v)) input.add(new Option(v,v));
        [...input.options].forEach(o=>o.selected=list.includes(o.value));
      } else if(input.type==='checkbox') input.checked=!!value;
      else input.value=value || '';
    }
    form.dispatchEvent(new Event('cai:restore'));
  }
  function customValues(form, original) {
    const values={...original};
    form.querySelectorAll('[data-custom-key]').forEach(input=>values[input.dataset.customKey]=input.type==='checkbox'?input.checked:input.value);
    form.elements.custom_values.value=JSON.stringify(values);
  }
  async function setupForm(form) {
    const payload=await data(), settings=payload.evenement?.settings || context.eventSettings || {};
    const path=location.pathname.match(/^\/fiche\/edit\/([^/]+)$/);
    const id=form.dataset.editId || path?.[1];
    let fiche=id && payload.fiches.find(f=>String(f.id)===id || 'local-'+f.client_uuid===id || f.qr_url?.endsWith('/q/'+id));
    const serverBase=document.getElementById('cai-edit-state');
    let base=fiche?.edit_state || (serverBase ? JSON.parse(serverBase.textContent) : null);
    if (id && !base && navigator.onLine && /^\d+$/.test(id)) {
      const response=await fetch(`/api/fiche/${id}/complement`,{cache:'no-store'});
      if(response.ok) {fiche={...fiche,...await response.json()};base=fiche.edit_state;}
    }
    if(id && !base) throw new Error('Cette fiche n’est pas disponible pour modification. Actualisez cet évènement avec une connexion.');
    if(id) {
      const operation=new URLSearchParams(location.search).get('operation');
      if(operation) {
        const candidate=await store().get('action:'+operation);
        if(candidate && candidate.action==='edit' && candidate.userId===context.userId && candidate.eventId===context.eventId && !candidate.server && !candidate.deliveryStarted && !candidate.cancelled) form.caiCorrection=candidate;
      }
      form.dataset.editId=id; form.caiBase=structuredClone(base); form.caiFiche=fiche || {id:Number(id)};
      document.getElementById('cai-edit-title')?.replaceChildren(document.createTextNode('Modifier la fiche'));
    }
    const extra=el('section',undefined,'feature-form');extra.append(el('h2','Groupe et informations complémentaires'));
    const label=el('label','Groupe manuel (facultatif)'), family=el('input');family.name='family_key';family.maxLength=80;family.setAttribute('list','family-choices');family.value=base?.family_key || '';
    const choices=el('datalist');choices.id='family-choices';
    for(const value of [...new Set(payload.fiches.map(f=>f.family_key).filter(Boolean))]) {const o=el('option');o.value=value;choices.append(o);}
    label.append(family,choices);extra.append(label,el('p','Les personnes portant le même nom de famille sont regroupées automatiquement. Un groupe manuel permet de relier aussi des noms différents.'));
    const autoFamily=el('p');autoFamily.id='automatic-family';extra.prepend(autoFamily);
    const updateFamily=()=>{const name=form.elements.nom?.value || '';const members=payload.fiches.filter(f=>!f.est_animal && norm(f.nom)===norm(name));autoFamily.textContent=form.elements.type_fiche?.value==='animal'?'':name.trim()?'Famille automatique : '+name.trim()+' · '+members.length+' fiche(s) déjà disponible(s).':'La famille sera déterminée à partir du nom.';};
    form.addEventListener('input',updateFamily);form.addEventListener('cai:restore',updateFamily);form.addEventListener('change',updateFamily);updateFamily();
    for(const [key,title] of Object.entries(labels).filter(([key])=>[...(id?['destination','moyen_transport','statut']:[])].includes(key))) {
      if(form.elements[key]) continue;
      const row=el('label',title), input=key==='statut'?el('select'):el('input');input.name=key;
      if(key==='statut') for(const value of ['présent','sorti']) {const o=el('option',value);o.value=value;input.append(o);}
      else {input.maxLength=key==='nationalite'?50:key==='numero_pec'?30:255;}
      if(key==='numero_pec' && context.permissions?.canEditPec===false) input.disabled=true;
      row.append(input);extra.append(row);
    }
    let hidden=form.elements.custom_values;
    if(!hidden) {hidden=el('input');hidden.type='hidden';hidden.name='custom_values';form.append(hidden);}
    const original=base?.custom_values || {};
    const definitions=[...(settings.custom_fields || [])];
    if(settings.choice_lists?.zones?.length) definitions.push({key:'zone_accueil',label:'Zone d’accueil',type:'choice',choices:settings.choice_lists.zones,scope:'all'});
    for(const field of definitions) {
      const row=el('label',field.label), input=field.type==='choice'?el('select'):el('input');
      input.setAttribute('aria-label',field.label);row.dataset.customScope=field.scope || 'all';input.dataset.customKey=field.key;input.name=`custom:${field.key}`; input.dataset.required=field.required?'true':'false';
      if(field.type==='choice') {
        input.append(el('option',''));
        for(const value of field.choices || []) {const o=el('option',value);o.value=value;input.append(o);}
      } else {input.type=field.type==='number'?'number':field.type==='date'?'date':field.type==='checkbox'?'checkbox':'text';if(input.type==='number') input.step='any';if(input.type==='text') input.maxLength=1000;}
      if(input.type==='checkbox') input.checked=!!original[field.key];else input.value=original[field.key] || '';
      row.append(input);extra.append(row);
    }
    const submit=form.querySelector('[type=submit]');submit?.before(extra);if(!submit) form.append(extra);
    const updateScope=()=>{const type=form.elements.type_fiche?.value || 'humain';extra.querySelectorAll('[data-custom-scope]').forEach(row=>{const visible=['all',type].includes(row.dataset.customScope);row.hidden=!visible;const input=row.querySelector('input,select');input.required=visible && input.dataset.required==='true';});customValues(form,original);};
    form.addEventListener('click',()=>setTimeout(updateScope,0));form.addEventListener('change',updateScope);form.addEventListener('input',()=>customValues(form,original));
    form.addEventListener('submit',()=>customValues(form,original),{capture:true});
    if(id) {
      const values={...base,difficulte:base.difficultes,animal_nom:base.nom,animal_notes:base.animal_details,animal_particularites:base.difficultes,animal_referent_id:base.referent_humain_id};fill(form,values);
      if(form.elements.numero) form.elements.numero.value=fiche?.numero || '';
      const numero=document.getElementById('numero');if(numero) numero.value=fiche?.numero || numero.value;
    }
    for(const [name,key] of [['destination','destinations'],['moyen_transport','transports']]) {
      const values=settings.choice_lists?.[key] || [];
      if(values.length && form.elements[name]) {const dl=el('datalist');dl.id=`choices-${name}`;values.forEach(v=>{const o=el('option');o.value=v;dl.append(o);});form.append(dl);form.elements[name].setAttribute('list',dl.id);}
    }
    const comp=form.elements.competences, compChoices=settings.choice_lists?.competences;
    if(comp && compChoices?.length) {
      const selected=[...comp.selectedOptions].map(o=>o.value);
      comp.replaceChildren();for(const value of [...new Set([...compChoices,...selected,'Autre'])]) {const o=new Option(value,value);o.selected=selected.includes(value);comp.add(o);}
    }
    updateScope();
    const warning=el('div');warning.id='duplicate-warning';warning.setAttribute('role','status');form.prepend(warning);
    let timer;
    const check=async()=>{const found=await findDuplicates(form);warning.replaceChildren();if(found.length){warning.className='feature-alert';warning.append(el('strong','Doublon possible : même identité et date de naissance.'));for(const f of found)link(` Ouvrir ${f.numero}`,`/fiche/${f.id}?evenement_id=${context.eventId}`,warning);}else warning.className='';};
    for(const key of ['nom','prenom','date_naissance','date_naissance_display']) form.elements[key]?.addEventListener('input',()=>{clearTimeout(timer);timer=setTimeout(()=>check().catch(()=>{}),350);});
    const wanted=el('div');wanted.id='wanted-warning';wanted.setAttribute('role','status');form.prepend(wanted);
    let wantedTimer,wantedSequence=0;
    const checkWanted=async()=>{
      const sequence=++wantedSequence,rows=await matchesForForm(form,true);if(sequence!==wantedSequence)return;
      wanted.replaceChildren();wanted.className=rows.length?'feature-alert':'';
      if(rows.length)wanted.append(el('strong','Cette personne est recherchée par : '+[...new Set(rows.map(r=>r.seeker_nom+' '+r.seeker_prenom))].join(', ')));
    };
    for(const name of ['nom','prenom'])form.elements[name]?.addEventListener('input',()=>{++wantedSequence;wanted.replaceChildren();clearTimeout(wantedTimer);wantedTimer=setTimeout(()=>checkWanted().catch(()=>{}),250);});
    form.addEventListener('cai:restore',()=>checkWanted().catch(()=>{}));
    form.addEventListener('change',()=>checkWanted().catch(()=>{}));
    form.addEventListener('click',event=>{if(event.target.closest('[data-fiche-type]')){++wantedSequence;wanted.replaceChildren();warning.replaceChildren();checkWanted().catch(()=>{});}});
    await checkWanted();
    await draft(form);form.dataset.featuresReady='true';
  }
  async function matchesForForm(form,online) {
    const fields=new FormData(form);if(fields.get('type_fiche')==='animal')return [];
    const nom=fields.get('nom') || '',prenom=fields.get('prenom') || '';if(!norm(nom)||!norm(prenom))return [];
    let rows=((await data()).person_searches || []).filter(r=>!r.resolved_at && norm(r.target_nom)===norm(nom) && norm(r.target_prenom)===norm(prenom));
    if(online && navigator.onLine)try{const response=await fetch('/api/evenement/'+context.eventId+'/recherches/correspondances?'+new URLSearchParams({nom,prenom}),{cache:'no-store',signal:AbortSignal.timeout(5000)});if(response.ok)rows=[...(await response.json()).matches,...rows.filter(row=>String(row.id).startsWith('local-'))];}catch{}
    return rows;
  }
  async function notifyWanted(matches,eventId,name,key) {
    if(!matches?.length || !context)return;
    const storageKey='wanted-notices:'+context.userId+':'+eventId;
    await store().change(storageKey,old=>({key:storageKey,entries:[...(old?.entries || []).filter(e=>e.key!==key),{key,name,matches}].slice(-30)}));
    if(eventId===context.eventId)await showWantedNotices();
  }
  async function showWantedNotices() {
    if(!document.body.classList.contains('cai-dashboard'))return;
    const key='wanted-notices:'+context.userId+':'+context.eventId,record=await store().get(key);
    let box=document.getElementById('wanted-person-notice');if(!record?.entries?.length){box?.remove();return;}
    if(!box){box=el('section',undefined,'feature-alert');box.id='wanted-person-notice';box.setAttribute('role','status');document.querySelector('main').prepend(box);}
    box.replaceChildren(el('h2','Personne recherchée'));
    for(const entry of record.entries)box.append(el('p',entry.name+' est recherchée par : '+[...new Set(entry.matches.map(m=>m.seeker_nom+' '+m.seeker_prenom))].join(', ')));
    button('Fermer ce message',async()=>{await store().put({key,entries:[]});box.remove();},box);
  }
  async function createdNotice(form,record) {try{await notifyWanted(await matchesForForm(form,false),context.eventId,record.label,record.uuid);}catch{}}
  async function findDuplicates(form) {
    const entries=new FormData(form);if(entries.get('type_fiche')==='animal')return [];
    const nom=entries.get('nom'),prenom=entries.get('prenom'),birth=entries.get('date_naissance');
    if(!nom || !birth) return [];
    const result=(await data()).fiches.filter(f=>String(f.id)!==form.dataset.editId && (!new URLSearchParams(location.search).get('draft') || f.client_uuid!==new URLSearchParams(location.search).get('draft')) && !f.est_animal && f.date_naissance===birth && norm(f.nom)===norm(nom) && norm(f.prenom)===norm(prenom));
    if(navigator.onLine) try {const r=await fetch(`/api/evenement/${context.eventId}/doublons?${new URLSearchParams({nom,prenom,date_naissance:birth,exclude:form.dataset.editId || ''})}`,{cache:'no-store'});if(r.ok) for(const f of (await r.json()).duplicates)if(!result.some(o=>String(o.id)===String(f.id)))result.push(f);}catch{}
    return result;
  }
  async function confirmDuplicate(form) {const found=await findDuplicates(form);if(found.length && !window.confirm(`Doublon possible : ${found.map(f=>f.numero).join(', ')}. Une fiche possède déjà ce nom et cette date de naissance. Créer / enregistrer quand même ?`)) throw new Error('Enregistrement annulé : vérifiez la fiche déjà présente.');}
  async function draft(form) {
    const key=scoped(`autosave:${form.dataset.editId || new URLSearchParams(location.search).get('draft') || 'new'}`);
    form.caiDraftKey=key;
    const banner=el('div',undefined,'feature-draft');banner.setAttribute('role','status');form.prepend(banner);
    const saved=await store().get(key);
    if(saved?.fields?.length) {
      banner.append(el('span',`Un brouillon du ${new Date(saved.savedAt).toLocaleString('fr-FR')} est disponible.`));
      button('Reprendre le brouillon',()=>{const values={};saved.fields.forEach(([k,v])=>{if(values[k]===undefined)values[k]=v;else values[k]=[].concat(values[k],v);});fill(form,values);if(values.date_naissance_display && form.elements.date_naissance_display)form.elements.date_naissance_display.value=values.date_naissance_display;if(saved.base)form.caiBase=saved.base;form.querySelectorAll('[data-custom-key]').forEach(input=>{const v=JSON.parse(values.custom_values || '{}')[input.dataset.customKey];if(input.type==='checkbox')input.checked=!!v;else input.value=v || '';});banner.replaceChildren(el('span','Brouillon récupéré.'));},banner);
      button('Supprimer ce brouillon',async()=>{await store().put({key,fields:[]});banner.replaceChildren();},banner);
    }
    const save=async()=>{
      if(form.dataset.draftComplete==='true')return;
      const fields=[...new FormData(form)].filter(([k])=>!['csrf_token','password','base_state'].includes(k));
      try {await store().put({key,kind:'autosave',userId:context.userId,eventId:context.eventId,fields,base:form.caiBase,savedAt:new Date().toISOString()});if(!banner.querySelector('button'))banner.replaceChildren(el('span','Brouillon enregistré sur cet appareil.'));}
      catch {banner.replaceChildren(el('span','Impossible d’enregistrer le brouillon. Gardez cette page ouverte.'));}
    };
    for(const event of ['input','change'])form.addEventListener(event,()=>{clearTimeout(draftTimer);draftTimer=setTimeout(save,250);});
    form.addEventListener('cai:restore',()=>{if(form.dataset.featuresReady)save();});
  }
  async function draftSaved(form) {form.dataset.draftComplete='true';clearTimeout(draftTimer);if(form.caiDraftKey)await store().put({key:form.caiDraftKey,fields:[]});}
  async function saveEdit(form) {
    if(locked)throw new Error('Déverrouillez l’appareil avant de modifier une fiche.');
    const after=canonical(form,form.caiBase), changes={}, base={};
    for(const [key,value] of Object.entries(after))if(JSON.stringify(value)!==JSON.stringify(form.caiBase[key])){changes[key]=value;base[key]=form.caiBase[key];}
    if(Object.keys(changes).length) {
      const payload=await data(), fiche=payload.fiches.find(f=>String(f.id)===form.dataset.editId) || form.caiFiche;
      if(form.caiCorrection) {
        const original=form.caiCorrection;
        const combined={...JSON.parse(original.payload.changes),...changes};
        const baseline={...base,...JSON.parse(original.payload.base)};
        await store().change(original.key,current=>{
          if(current.server || current.deliveryStarted || current.cancelled)throw new Error('Cet envoi a déjà commencé. Attendez sa confirmation.');
          return {...current,payload:{changes:JSON.stringify(combined),base:JSON.stringify(baseline)},error:'',deliveryStarted:false,revision:(current.revision || 0)+1};
        });
        window.dispatchEvent(new Event('cai:local')); window.CAIOffline.sync();
      } else await window.CAIOffline.queueAction('edit',fiche,{changes:JSON.stringify(changes),base:JSON.stringify(base)});
    }
    await draftSaved(form);
  }
  async function conflict(record, result) {
    await store().change(record.key,current=>({...current,conflicts:result.conflicts,conflictCurrent:result.current,error:result.error,deliveryStarted:false}));
    if(document.querySelector('dialog[data-conflict]'))return;
    await resolveConflict(record.key);
  }
  async function resolveConflict(key) {
    const record=await store().get(key);if(!record?.conflicts?.length || locked)return;
    const dialog=modal('Choisir les valeurs à conserver');dialog.dataset.conflict=key;
    dialog.append(el('p',`${record.provisional} — ${record.label}. Le même champ a été modifié sur un autre appareil.`));
    const form=el('form');
    record.conflicts.forEach((item,index)=>{
      const fs=el('fieldset');const fieldLabel=item.field.startsWith('custom_values.')?item.field.slice(14):labels[item.field] || item.field;
      fs.append(el('legend',fieldLabel),el('p',`Valeur initiale : ${readable(item.base)}`));
      for(const [value,title,text] of [['server','Valeur du serveur',item.server],['mine','Ma valeur',item.mine]]){const label=el('label'),input=el('input');input.type='radio';input.name=`choice-${index}`;input.value=value;input.required=true;label.append(input,document.createTextNode(`${title} : ${readable(text)}`));fs.append(label);}form.append(fs);
    });
    const submit=el('button','Appliquer mes choix et synchroniser','primary');submit.type='submit';form.append(submit);dialog.append(form);
    button('Décider plus tard',()=>dialog.close(),dialog);
    form.addEventListener('submit',async event=>{
      event.preventDefault();submit.disabled=true;
      try {
        const choices=new FormData(form),changes=JSON.parse(record.payload.changes),base=JSON.parse(record.payload.base);
        record.conflicts.forEach((item,index)=>{
          const chosen=choices.get(`choice-${index}`)==='mine'?item.mine:item.server;
          if(item.field.startsWith('custom_values.')){const k=item.field.slice(14);base.custom_values={...base.custom_values,[k]:item.server};changes.custom_values={...changes.custom_values,[k]:chosen};}
          else {base[item.field]=item.server;changes[item.field]=chosen;}
        });
        await store().change(key,current=>{if(current.server || current.cancelled)throw new Error('Cette action a déjà été traitée.');return {...current,payload:{changes:JSON.stringify(changes),base:JSON.stringify(base)},conflicts:[],error:'',deliveryStarted:false};});
        dialog.close();window.CAIOffline.sync();
      } catch(error){announce(error.message,form);submit.disabled=false;}
    });
    dialog.addEventListener('close',()=>dialog.remove());dialog.showModal();
  }
  async function detailExtras(payload) {
    const id=location.pathname.split('/').pop(), fiche=payload.fiches.find(f=>String(f.id)===id || 'local-'+f.client_uuid===id);
    if(!fiche)return;
    let root=document.getElementById('feature-detail');if(!root){root=el('section',undefined,'feature-extra');root.id='feature-detail';(document.querySelector('.wrapper') || document.querySelector('main')).append(root);}
    root.replaceChildren(el('h2','Famille, groupe, QR et historique détaillé'));
    if(!fiche.est_animal && norm(fiche.nom)){root.append(el('h3','Famille : '+fiche.nom));for(const member of payload.fiches.filter(f=>!f.est_animal && norm(f.nom)===norm(fiche.nom) && f.id!==fiche.id)){const p=el('p');link(member.numero+' — '+member.nom+' '+(member.prenom || ''),'/fiche/'+member.id+'?evenement_id='+context.eventId,p);root.append(p);}}
    const group=fiche.family_key;
    if(group) {const p=el('p','Groupe manuel : ');link(group,`/evenement/${context.eventId}/dashboard?groupe=${encodeURIComponent(group)}`,p);root.append(p);const members=payload.fiches.filter(f=>f.family_key && norm(f.family_key)===norm(group) && f.id!==fiche.id);for(const member of members){const p=el('p');link(`${member.numero} — ${member.nom} ${member.prenom || ''}`,`/fiche/${member.id}?evenement_id=${context.eventId}`,p);root.append(p);}}
    const dl=el('dl');for(const [key,value] of Object.entries(fiche.custom_values || {})){const def=payload.evenement?.settings?.custom_fields?.find(f=>f.key===key);dl.append(el('dt',def?.label || (key==='zone_accueil'?'Zone d’accueil':key)),el('dd',readable(value)));}root.append(dl);
    if(fiche.qr_data){const img=el('img');img.src=fiche.qr_data;img.alt=`QR d’accès à la fiche ${fiche.numero}`;root.append(img,el('p','Le QR ouvre cette fiche après connexion avec un compte autorisé.'));}
    else root.append(el('p','Le QR sera disponible après la première synchronisation.'));
    if(!fiche.deletionPending && !fiche.deliveryStarted)link(fiche.creationPending?'Corriger la fiche':'Modifier la fiche',fiche.creationPending?'/fiche/new?evenement_id='+context.eventId+'&draft='+fiche.client_uuid:'/fiche/edit/'+fiche.id+'?evenement_id='+context.eventId,root);
    const changes=el('details');changes.append(el('summary','Historique détaillé des modifications'));
    for(const entry of fiche.changes || []){const section=el('section');section.append(el('h3',`${new Date(entry.at).toLocaleString('fr-FR')} · ${entry.author}`));const list=el('dl');for(const [key,value]of Object.entries(entry.changes)){list.append(el('dt',labels[key] || key),el('dd',`${readable(value.old)} → ${readable(value.new)}`));}section.append(list);changes.append(section);}
    if(!fiche.changes?.length)changes.append(el('p','Aucune modification détaillée enregistrée. Les anciens commentaires restent dans le suivi.'));
    root.append(changes);
  }
  function settingsEditor() {
    const form=document.getElementById('event-settings');if(!form)return;
    const settings=JSON.parse(document.getElementById('settings-data').textContent),host=document.getElementById('custom-field-editor');
    const add=field=>{
      const row=el('section',undefined,'custom-editor-row');row.dataset.key=field.key || 'champ_'+crypto.randomUUID().slice(0,8);
      const grid=el('div',undefined,'feature-grid');
      function input(title,name,type,value){const label=el('label',title),node=el(type==='select'?'select':'input');node.setAttribute('aria-label',title);node.dataset.setting=name;if(type!=='select')node.type=type;if(type==='checkbox')node.checked=!!value;else node.value=value || '';label.append(node);grid.append(label);return node;}
      const label=input('Libellé du champ','label','text',field.label);label.maxLength=80;label.required=true;
      const type=input('Type','type','select');for(const [value,title]of [['text','Texte'],['number','Nombre'],['date','Date'],['choice','Liste de choix'],['checkbox','Case à cocher']]){const o=new Option(title,value);o.selected=value===(field.type || 'text');type.add(o);}
      const scope=input('Afficher pour','scope','select');for(const [value,title]of [['all','Toutes les fiches'],['humain','Personnes'],['animal','Animaux']]){const o=new Option(title,value);o.selected=value===(field.scope || 'all');scope.add(o);}
      input('Obligatoire','required','checkbox',field.required);
      const choicesLabel=el('label','Choix possibles (un par ligne)'),choices=el('textarea');choices.dataset.setting='choices';choices.rows=3;choices.value=(field.choices || []).join('\n');choicesLabel.append(choices);grid.append(choicesLabel);
      const show=()=>{choicesLabel.hidden=type.value!=='choice';choices.required=type.value==='choice';};type.addEventListener('change',show);show();
      row.append(grid);button('Retirer ce champ',()=>row.remove(),row);host.append(row);
    };
    settings.custom_fields.forEach(add);document.getElementById('add-custom-field').addEventListener('click',()=>{if(host.children.length>=20)return;add({});host.lastElementChild.querySelector('input').focus();});
    form.addEventListener('submit',event=>{
      try {
        const custom_fields=[...host.children].map(row=>{const val=k=>row.querySelector(`[data-setting=${k}]`);return {key:row.dataset.key,label:val('label').value.trim(),type:val('type').value,scope:val('scope').value,required:val('required').checked,choices:val('choices').value.split('\n').map(v=>v.trim()).filter(Boolean)};});
        const choice_lists={};form.querySelectorAll('[data-choice-list]').forEach(input=>choice_lists[input.dataset.choiceList]=input.value.split('\n').map(v=>v.trim()).filter(Boolean));
        document.getElementById('settings-value').value=JSON.stringify({capacity:document.getElementById('event-capacity').value,warning_percent:document.getElementById('event-warning').value,custom_fields,choice_lists});
      }catch(error){event.preventDefault();document.getElementById('settings-error').textContent=error.message;}
    });
  }
  window.CAIFeatures={createdNotice,notifyWanted,ready,refresh,setupForm,saveEdit,confirmDuplicate,draftSaved,conflict,resolveConflict,isLocked:()=>locked};
  document.addEventListener('DOMContentLoaded',()=>{const device=document.getElementById('cai-device-context');if(device)ready(JSON.parse(device.textContent)).catch(()=>{});settingsEditor();document.getElementById('select-labels')?.addEventListener('change',event=>document.querySelectorAll('input[name=fiche_ids]').forEach(input=>input.checked=event.target.checked));});
  window.addEventListener('cai:local',()=>refresh().catch(()=>{}));window.addEventListener('cai:sync',()=>refresh().catch(()=>{}));
})();
