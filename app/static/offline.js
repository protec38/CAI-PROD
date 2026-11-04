(function () {
  'use strict';
  const store = globalThis.CAIOfflineStore;
  const shell = document.body.classList.contains('cai-offline-dashboard');
  const offlineForm = document.body.classList.contains('cai-offline-form-page');
  const offlineSearch = document.body.classList.contains('cai-offline-search');
  const offlineDetail = document.body.classList.contains('cai-offline-detail');
  let context, busy = false, syncAgain = false, editing = null, panel, status, queue, indicator, connectionLabel;
  const field = (record, name) => (record.fields.find(pair => pair[0] === name) || [])[1] || '';
  const snapshotKey = () => `snapshot:${context.userId}:${context.eventId}`;
  const label = record => record.label || 'Fiche';
  function say(message, state = 'pending', text) {
    if (status) status.textContent = message;
    if (indicator) {
      indicator.dataset.state = state;
      indicator.title = message;
      connectionLabel.textContent = text || (state === 'synced' ? 'Synchronisé au serveur' :
        state === 'offline' ? 'Mode hors ligne' : 'En attente du serveur');
    }
  }
  function createPanel() {
    const bar = document.createElement('div'); bar.className = 'cai-connection-bar';
    const details = document.createElement('details'); details.className = 'cai-sync-details';
    indicator = document.createElement('summary');
    indicator.className = 'cai-connection-indicator'; indicator.dataset.state = 'pending';
    const dot = document.createElement('span'); dot.className = 'cai-sync-dot';
    dot.setAttribute('aria-hidden', 'true');
    connectionLabel = document.createElement('span');
    connectionLabel.id = 'cai-connection-label'; connectionLabel.setAttribute('role', 'status');
    connectionLabel.textContent = 'Vérification du serveur…';
    indicator.append(dot, connectionLabel);
    panel = document.createElement('section');
    panel.className = 'cai-offline-panel';
    panel.setAttribute('aria-label', 'Synchronisation des fiches');
    status = document.createElement('p');
    const button = document.createElement('button');
    button.type = 'button'; button.textContent = 'Synchroniser';
    button.addEventListener('click', () => sync().catch(report));
    queue = document.createElement('ul');
    panel.append(status, button, queue);
    details.append(indicator, panel); bar.append(details);
    const skip = document.querySelector('.cai-skip-link');
    if (skip) skip.after(bar); else document.body.prepend(bar);
  }
  function report(error) {
    if (!status) {
      status = document.createElement('p'); status.className = 'cai-offline-panel';
      status.setAttribute('role', 'alert'); document.body.prepend(status);
    }
    say(error.message || 'Le stockage local est indisponible. Gardez cette page ouverte.');
  }
  async function renderQueue() {
    queue.replaceChildren();
    const records = (await store.all()).filter(record => (!record.cancelled || record.obsolete) && ['fiche', 'mutation'].includes(record.kind) &&
      record.userId === context.userId && record.eventId === context.eventId);
    // Retain a short list of receipts, and every pending record.
    const recent = records.filter(record => record.server).slice(-5);
    for (const record of records.filter(record => !record.server).concat(recent)) {
      const li = document.createElement('li');
      li.append(document.createTextNode(
        ` ${record.server ? record.server.numero : record.provisional} — ${label(record)}${record.kind === 'mutation' ? ' · ' + ({bagages: 'Bagages', sortie: 'Sortie', delete: 'Suppression', edit: 'Modification'}[record.action]) : ''}${record.obsolete ? ' · Action annulée (identité de fiche modifiée)' : record.server ? ' · Synchronisé' : ' · En attente du serveur'}`));
      if (record.server && record.server.numero !== record.provisional) {
        li.append(document.createTextNode(` · ancien n° ${record.provisional}`));
      }
      if (record.kind === 'fiche' && !record.server && !record.deliveryStarted) {
        const a = document.createElement('a');
        a.href = `/fiche/new?evenement_id=${record.eventId}&draft=${record.uuid}`;
        a.textContent = ' Ouvrir / corriger'; li.append(a);
      }
      if (record.deliveryStarted && !record.server) {
        li.append(document.createTextNode(' · Envoi à vérifier au retour du serveur avant correction.'));
      }
      if (record.conflicts?.length) {
        const resolve = document.createElement('button'); resolve.type = 'button'; resolve.textContent = 'Résoudre le conflit';
        resolve.addEventListener('click', () => window.CAIFeatures.resolveConflict(record.key)); li.append(resolve);
      }
      if (record.error && record.action === 'edit' && !record.deliveryStarted && !record.conflicts?.length) {
        const correction = document.createElement('a');
        correction.href = '/fiche/edit/' + (record.target.id || record.target.uuid) + '?evenement_id=' + record.eventId + '&operation=' + record.uuid;
        correction.textContent = ' Corriger cette modification'; li.append(correction);
      }
      if (record.error) {
        const error = document.createElement('p'); error.className = 'cai-offline-error';
        error.textContent = record.error; li.append(error);
      }
      queue.append(li);
    }

  }
  const numbers = raw => [...new Set(String(raw || '').split(/[\s,;]+/).filter(Boolean))];
  const formatDate = value => new Date(value).toLocaleString('fr-FR', {timeZone: 'Europe/Paris'});
  const sameTarget = (fiche, target) => target.uuid ? fiche.client_uuid === target.uuid && (!target.identity || target.identity === fiche.identity_token) :
    String(fiche.id) === String(target.id) && (!target.identity || target.identity === fiche.identity_token);
  async function listFiches(data) {
    if (!context) return data;
    const records = (await store.all()).filter(record => !record.cancelled && record.userId === context.userId && record.eventId === context.eventId);
    const confirmed = new Set((data.fiches || []).map(fiche => fiche.client_uuid));
    const fiches = (data.fiches || []).map(fiche => ({...fiche, bagages: [...(fiche.bagages || [])], timeline: [...(fiche.timeline || [])]}));
    for (const record of records.filter(record => record.kind === 'fiche' && !record.observed && record.fields?.length && !confirmed.has(record.uuid))) {
      fiches.push({id: record.server?.id || 'local-' + record.uuid, client_uuid: record.uuid,
        creationPending: !record.server, pending: !record.server, event_id: record.eventId,
        deliveryStarted: !!record.deliveryStarted, numero: record.server?.numero || record.provisional + ' (provisoire)',
        nom: field(record, 'type_fiche') === 'animal' ? field(record, 'animal_nom') : field(record, 'nom'),
        prenom: field(record, 'prenom'), statut: 'présent', bagages: [],
        est_animal: field(record, 'type_fiche') === 'animal', type_fiche: field(record, 'type_fiche'),
        ...Object.fromEntries(['date_naissance', 'nationalite', 'adresse', 'telephone', 'numero_pec',
          'personne_a_prevenir', 'tel_personne_a_prevenir', 'recherche_personne', 'code_sinus',
          'autres_informations', 'effets_perso', 'numero_recherche'].map(name => [name, field(record, name)])),
        family_key: field(record, 'family_key'), custom_values: JSON.parse(field(record, 'custom_values') || '{}'),
        animal_details: field(record, 'animal_notes'), referent_id: field(record, 'animal_referent_id'),
        timeline: [{content: 'Création de la fiche', created_at: formatDate(record.createdAt), pending: !record.server}],
        animal_espece: field(record, 'animal_espece'), heure_arrivee: formatDate(record.createdAt),
        difficultes: field(record, 'difficulte') || field(record, 'animal_particularites'),
        competences: record.fields.filter(pair => pair[0] === 'competences').map(pair => pair[1]).join(',')});
    }
    const observed = new Set(data.applied_operations || []);
    const actions = records.filter(record => record.kind === 'mutation' && (!record.server || (!record.observed && !observed.has(record.uuid))))
      .sort((a,b) => a.sequence - b.sequence);
    for (const record of actions) {
      const fiche = fiches.find(fiche => sameTarget(fiche, record.target));
      if (!fiche) continue;
      fiche.pending = !!fiche.pending || !record.server;
      if (record.error) fiche.sync_error = record.error;
      fiche.timeline.push({content: {bagages: 'Modification des bagages', sortie: 'Sortie', delete: 'Suppression demandée', edit: 'Modification de la fiche'}[record.action],
        created_at: formatDate(record.createdAt), pending: !record.server});
      if (record.action === 'bagages') {
        const base = numbers(record.payload.base_numeros), desired = numbers(record.payload.numeros);
        fiche.bagages = [...new Set([...fiche.bagages.filter(number => !base.includes(number) || desired.includes(number)),
          ...desired.filter(number => !base.includes(number))])];
      } else if (record.action === 'edit') {
        const changes = JSON.parse(record.payload.changes);
        const previousCustom = {...fiche.custom_values};
        Object.assign(fiche, changes);
        if (changes.custom_values) {
          const initial = JSON.parse(record.payload.base).custom_values || {};
          const merged = previousCustom;
          for (const key of new Set([...Object.keys(initial), ...Object.keys(changes.custom_values)])) {
            if (JSON.stringify(initial[key]) !== JSON.stringify(changes.custom_values[key])) merged[key] = changes.custom_values[key] ?? '';
          }
          fiche.custom_values = merged;
        }
        fiche.edit_state = {...fiche.edit_state, ...changes, custom_values: fiche.custom_values};
        fiche.est_animal = fiche.type_fiche === 'animal';
      } else if (record.action === 'sortie') {
        fiche.statut = 'sorti'; fiche.heure_sortie = formatDate(record.createdAt);
        fiche.destination = record.payload.destination || fiche.destination;
        fiche.moyen_transport = record.payload.moyen_transport || fiche.moyen_transport;
        if (fiche.edit_state) fiche.edit_state = {...fiche.edit_state, statut: fiche.statut, destination: fiche.destination, moyen_transport: fiche.moyen_transport};
      } else if (record.action === 'delete') {
        fiche.deletionPending = !record.server; fiche.deletedConfirmed = !!record.server;
        fiche.statut = 'supprimé';
      }
    }
    const visible = fiches.filter(fiche => !fiche.deletedConfirmed);
    const normalizeName = value => String(value || '').normalize('NFD').replace(/[\u0300-\u036f]/g,'').toLocaleLowerCase('fr').trim().replace(/\s+/g,' ');
    const searches = [...(data.person_searches || [])];
    for (const record of records.filter(record => record.kind === 'fiche' && !record.observed && record.fields?.length && field(record, 'type_fiche') !== 'animal')) {
      const targetNom = field(record, 'recherche_nom').trim(), targetPrenom = field(record, 'recherche_prenom').trim();
      if (!targetNom || !targetPrenom) continue;
      const seekerNom = field(record, 'nom').trim(), seekerPrenom = field(record, 'prenom').trim();
      const values = {target_nom: targetNom, target_prenom: targetPrenom, seeker_nom: seekerNom, seeker_prenom: seekerPrenom};
      if (!searches.some(row => !row.resolved_at && Object.keys(values).every(key => normalizeName(row[key]) === normalizeName(values[key])))) {
        searches.push({id: 'local-' + record.uuid, ...values, created_at: record.createdAt, resolved_at: null, pending: !record.server});
      }
      const seeker = visible.find(fiche => fiche.client_uuid === record.uuid);
      if (seeker) seeker.recherche_personne = `${targetNom} ${targetPrenom}`;
    }
    const families=new Map();for(const f of visible)if(!f.est_animal && !f.deletionPending && normalizeName(f.nom))families.set(normalizeName(f.nom),(families.get(normalizeName(f.nom)) || 0)+1);
    for(const f of visible){f.family_name=f.est_animal?'':f.nom;f.family_count=f.est_animal?0:families.get(normalizeName(f.nom)) || 0;}
    const result = {...data, fiches: visible, person_searches: searches};
    result.nb_familles = new Set(visible.filter(f => !f.est_animal && !f.deletionPending &&
      normalizeName(f.statut) === 'present' && normalizeName(f.nom)).map(f => normalizeName(f.nom))).size;
    for (const animal of [false, true]) {
      const rows = visible.filter(fiche => !!fiche.est_animal === animal), suffix = animal ? '_animaux' : '';
      result['nb_total' + suffix] = rows.length;
      result['nb_present' + suffix] = rows.filter(fiche => fiche.statut === 'présent').length;
    }
    return result;
  }
  async function snapshot(data) {
    const previous = await store.get(snapshotKey());
    data = {...data, fiches: (data.fiches || []).map(fiche => ({...fiche,
      timeline: fiche.timeline ?? previous?.data.fiches.find(other => other.id === fiche.id)?.timeline,
      changes: fiche.changes ?? previous?.data.fiches.find(other => other.id === fiche.id)?.changes,
      qr_data: fiche.qr_data ?? previous?.data.fiches.find(other => other.id === fiche.id)?.qr_data}))};
    await store.put({key: snapshotKey(), kind: 'snapshot', data, savedAt: new Date().toISOString()});
    const creations = new Set((data.fiches || []).map(fiche => fiche.client_uuid));
    const operations = new Set(data.applied_operations || []);
    for (const record of (await store.all()).filter(record => record.userId === context.userId &&
      record.eventId === context.eventId && record.server && !record.observed &&
      (record.kind === 'fiche' ? creations.has(record.uuid) : operations.has(record.uuid)))) {
      await store.change(record.key, current => ({...current, observed: true, fields: []}));
    }
  }
  async function refreshSnapshot() {
    const response = await fetch(`/evenement/${context.eventId}/fiches_json?details=1`, {cache: 'no-store', signal: AbortSignal.timeout(10000)});
    if (!response.ok || response.redirected) throw new Error('Impossible d’actualiser les fiches du serveur.');
    const data = await response.json(); await snapshot(data);
  }
  async function sync() {
    if (!context || window.CAIFeatures?.isLocked()) return;
    if (busy) { syncAgain = true; return; }
    if (navigator.onLine === false) {
      say('Hors ligne : les fiches restent sur cet appareil, en attente du serveur.', 'offline');
      await renderQueue(); return;
    }
    busy = true;
    try {
      const pending = await store.pending(context.userId);
      say('Vérification de la connexion au serveur…', 'pending', 'Synchronisation en cours…');
      const response = await fetch('/api/offline/session', {cache: 'no-store', signal: AbortSignal.timeout(10000)});
      if (!response.ok) throw new Error('Reconnectez-vous pour synchroniser. Vos fiches restent sur cet appareil.');
      const session = await response.json();
      if (session.user_id !== context.userId) {
        throw new Error('Reconnectez-vous avec le compte ayant créé ces fiches. La synchronisation est suspendue.');
      }
      context.permissions = session.permissions;
      updateExportActions();
      context.preferences = session.preferences || context.preferences;
      await store.put({...context, kind: 'context', key: `context:${context.userId}:${context.eventId}`});
      const meta = document.querySelector('meta[name="csrf-token"]');
      if (meta) meta.content = session.csrf_token;
      document.querySelectorAll('input[name="csrf_token"]').forEach(input => { input.value = session.csrf_token; });
      window.CAIDashboard?.setToken(session.csrf_token);
      const creations = pending.filter(record => record.kind === 'fiche');
      const actions = pending.filter(record => record.kind === 'mutation').sort((a,b) => a.sequence - b.sequence);
      const blockedTargets = new Set();
      for (const pendingRecord of [...creations, ...actions]) {
        // A correction currently open must never be sent from its older version.
        if (pendingRecord.uuid === editing) continue;
        if (pendingRecord.conflicts?.length) { if (pendingRecord.target) blockedTargets.add(JSON.stringify(pendingRecord.target)); continue; }
        const targetKey = pendingRecord.kind === 'mutation' ? JSON.stringify(pendingRecord.target) : '';
        if (targetKey && blockedTargets.has(targetKey)) continue;
        if (pendingRecord.kind === 'mutation' && pendingRecord.target.uuid) {
          const creation = await store.get(`fiche:${pendingRecord.target.uuid}`);
          if (creation && !creation.server) continue;
        }
        // Atomically freeze the latest version, including corrections from
        // another tab, before building the request.
        const record = await store.beginDelivery(pendingRecord.key);
        if (!record) continue;
        const body = new URLSearchParams(record.kind === 'mutation' ? record.payload : record.fields);
        body.set('user_id', String(record.userId));
        if (record.kind === 'mutation') {
          body.set('operation_uuid', record.uuid); body.set('kind', record.action);
          body.set('occurred_at', record.createdAt);
          body.set(record.target.uuid ? 'fiche_uuid' : 'fiche_id', record.target.uuid || String(record.target.id));
          if (record.target.identity) body.set('identity_token', record.target.identity);
        } else {
          body.set('client_uuid', record.uuid); body.set('heure_arrivee_utc', record.createdAt);
        }
        body.delete('csrf_token');
        // If the response is lost, the record may already exist on the server.
        // Freeze corrections until its receipt is recovered; retries keep UUID.
        const result = await fetch(`/api/evenement/${record.eventId}/fiches/${record.kind === 'mutation' ? 'actions/' : ''}sync`, {
          method: 'POST', body, headers: {'X-CSRFToken': session.csrf_token},
          signal: AbortSignal.timeout(15000),
        });
        const json = await result.json().catch(() => ({}));
        if (!result.ok) {
          if (json.stale_identity) {
            await store.change(record.key, current => ({...current, cancelled: true, obsolete: true, deliveryStarted: false, error: json.error}));
            continue;
          }
          if (targetKey) blockedTargets.add(targetKey);
          record.error = json.error || 'Synchronisation refusée. Réessayez après reconnexion.';
          await store.change(record.key, current => current.server || current.revision !== record.revision ? current : {
            ...current, error: record.error,
            deliveryStarted: result.status !== 422,
          });
          if (json.conflicts) await window.CAIFeatures?.conflict(record, json);
          if (result.status === 401 || result.status === 400 || result.status >= 500) throw new Error(record.error);
          continue;
        }
        await store.acknowledge(record.key, json);
        if (json.wanted_matches?.length) await window.CAIFeatures?.notifyWanted(json.wanted_matches, record.eventId, record.label, record.uuid);
        if (record.kind === 'fiche' && json.deleted) {
          for (const action of (await store.pending(record.userId, record.eventId)).filter(action => action.target?.uuid === record.uuid)) {
            await store.change(action.key, current => ({...current, cancelled: true}));
          }
        }
        window.dispatchEvent(new Event('cai:local'));
      }
      await refreshSnapshot();
      const remaining = (await store.pending(context.userId)).length;
      say(remaining ? `${remaining} envoi(s) en attente sur cet appareil. Ouvrez l’évènement concerné pour consulter les messages.` :
        'Toutes les fiches sont sur le serveur. Le mode hors ligne est prêt sur cet appareil.', remaining ? 'pending' : 'synced');
      await renderQueue();
      window.dispatchEvent(new Event('cai:sync'));
    } catch (error) {
      const remaining = (await store.pending(context.userId)).length;
      const unreachable = error.name === 'TypeError' || error.name === 'TimeoutError';
      say(unreachable ? `Serveur inaccessible · ${remaining} fiche(s) en attente. Nouvel essai automatique au retour de la connexion.` :
        error.message, unreachable ? 'offline' : 'pending');
      await renderQueue();
    } finally {
      busy = false;
      if (syncAgain) { syncAgain = false; queueMicrotask(() => sync().catch(report)); }
    }
  }
  async function saveForm(form) {
    if (window.CAIFeatures?.isLocked()) throw new Error('Appareil verrouillé.');
    await window.CAIFeatures?.confirmDuplicate(form);
    if (form.dataset.editId) return window.CAIFeatures.saveEdit(form);
    const fields = Array.from(new FormData(form).entries()).filter(pair =>
      !['csrf_token', 'numero', 'client_uuid', 'user_id'].includes(pair[0]));
    const savedId = editing || form.dataset.savedUuid;
    const old = savedId ? await store.get(`fiche:${savedId}`) : null;
    if (old && old.server) throw new Error('Cette fiche a déjà été synchronisée. Ouvrez-la sur le serveur pour la modifier.');
    if (old?.deliveryStarted) throw new Error('La confirmation de cet envoi doit être vérifiée au retour du réseau avant toute correction.');
    const uuid = old ? old.uuid : store.uuid();
    const provisional = old ? old.provisional :
      `${context.eventId.toString().padStart(3, '0')}-LOCAL-${uuid.slice(0, 8)}`;
    // LOCAL makes it explicit that this number is provisional.
    const record = {key: `fiche:${uuid}`, kind: 'fiche', uuid, userId: context.userId,
      eventId: context.eventId, provisional, createdAt: old ? old.createdAt : new Date().toISOString(), fields};
    record.label = field(record, 'type_fiche') === 'animal' ? field(record, 'animal_nom') :
      `${field(record, 'nom')} ${field(record, 'prenom')}`.trim();
    // A previous transaction must finish successfully before showing success.
    await store.saveDraft(record);
    await window.CAIFeatures?.createdNotice(form, record);
    await window.CAIFeatures?.draftSaved(form);
    say('Fiche enregistrée sur cet appareil, en attente de confirmation du serveur.',
      navigator.onLine === false ? 'offline' : 'pending');
    form.dataset.savedUuid = uuid;
    editing = null;
    navigator.storage?.persist?.().catch(() => {});
    await renderQueue();
    return await store.get(record.key);
  }
  function interceptForm(form) {
    let saving = false;
    document.addEventListener('submit', async event => {
      if (event.target !== form || event.defaultPrevented) return;
      event.preventDefault();
      if (saving) return;
      saving = true;
      const submit = form.querySelector('[type="submit"]'); if (submit) submit.disabled = true;
      try {
        await saveForm(form);
        location.assign(`/evenement/${context.eventId}/dashboard`);
      } catch (error) { report(error); }
      finally { saving = false; if (submit) submit.disabled = false; }
    });
  }
  async function setupForm() {
    const form = document.querySelector('form[data-initial-type]');
    if (!form) return;
    if (form.elements.evenement_id) form.elements.evenement_id.value = context.eventId;
    const back = document.querySelector('[data-cai-dashboard-link]'); if (back) back.href = `/evenement/${context.eventId}/dashboard`;
    const draftId = new URLSearchParams(location.search).get('draft');
    if (draftId) {
      const draft = await store.get(`fiche:${draftId}`);
      if (draft && !draft.server && !draft.deliveryStarted && draft.userId === context.userId && draft.eventId === context.eventId) {
        editing = draft.uuid;
        for (const input of form.elements) {
          if (!input.name) continue;
          const values = draft.fields.filter(pair => pair[0] === input.name).map(pair => pair[1]);
          if (input.multiple) {
            for (const value of values) {
              if (!Array.from(input.options).some(option => option.value === value)) input.add(new Option(value, value));
            }
            Array.from(input.options).forEach(option => { option.selected = values.includes(option.value); });
          }
          else input.value = values[0] || '';
        }
        document.getElementById('cai-edit-title').textContent = `Corriger la fiche ${draft.provisional}`;
        document.getElementById('numero').value = draft.provisional;
        form.dispatchEvent(new Event('cai:restore'));
      }
    }
    await window.CAIFeatures?.setupForm(form);
    interceptForm(form);
    form.dataset.caiReady = 'true';
  }
  async function queueAction(action, fiche, values) {
    if (!fiche || !context) throw new Error('La fiche n’est pas disponible sur cet appareil.');
    if (action === 'bagages' && !context.permissions?.canBagages) {
      throw new Error('Vous n’êtes pas autorisé à modifier les bagages.');
    }
    if (action === 'delete' && !context.permissions?.canDelete) throw new Error('Vous n’êtes pas autorisé à supprimer cette fiche.');
    if (fiche.deletionPending) throw new Error('Cette fiche est déjà en attente de suppression.');
    if (action === 'bagages' && (values.numeros.length > 300 || numbers(values.numeros).some(number => number.length > 50))) {
      throw new Error('Liste trop longue : 300 caractères au total et 50 caractères par numéro de bagage.');
    }
    const target = fiche.client_uuid ? {uuid: fiche.client_uuid, id: fiche.id, identity: fiche.identity_token} : {id: fiche.id, identity: fiche.identity_token};
    const pending = (await store.pending(context.userId, context.eventId)).filter(record =>
      record.kind === 'mutation' && record.action === action && sameTarget(fiche, record.target));
    const latest = pending.sort((a,b) => b.sequence - a.sequence)[0];
    let saved;
    if (!['delete', 'edit'].includes(action) && latest && !latest.deliveryStarted) {
      await store.change(latest.key, current => {
        if (current.server || current.deliveryStarted) throw new Error('Un envoi vient de démarrer. Réessayez après sa confirmation.');
        return {...current, error: '', revision: (current.revision || 0) + 1,
          payload: {...values, ...(action === 'bagages' ? {base_numeros: current.payload.base_numeros} : {})}};
      });
    } else {
      const uuid = store.uuid();
      saved = await store.enqueueAction({key: `action:${uuid}`, uuid, kind: 'mutation', action, target,
        userId: context.userId, eventId: context.eventId, createdAt: new Date().toISOString(),
        localOnlyCandidate: !!fiche.creationPending,
        label: `${fiche.nom || ''} ${fiche.prenom || ''}`.trim(), provisional: fiche.numero, payload: values, revision: 1});
    }
    say(saved?.localCancelled ? 'Fiche locale supprimée. Elle ne sera pas envoyée au serveur.' :
      'Modification enregistrée sur cet appareil, en attente du serveur.', navigator.onLine === false ? 'offline' : 'pending');
    window.dispatchEvent(new Event('cai:local'));
    await renderQueue();
    sync().catch(report);
  }
  async function deleteFiche(fiche) {
    if (!fiche || !window.confirm(`Confirmer la suppression de la fiche ${fiche.numero} ?`)) return false;
    await queueAction('delete', fiche, {identity_token: fiche.identity_token || '', numero: fiche.numero});
    return true;
  }
  function element(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }
  function detailCard(title, pairs) {
    const card = element('article', 'card'), body = element('div', 'bd'), fields = element('div', 'fields');
    card.append(element('div', 'hd', title));
    for (const [name, title, value] of pairs) {
      const field = element('div', 'field'), content = element('div', 'value', value || '—');
      content.dataset.field = name; field.append(element('div', 'label', title), content); fields.append(field);
    }
    body.append(fields); card.append(body); return card;
  }
  function updateExportActions() {
    const menu = document.querySelector('.dashboard-menu__items');
    if (!menu) return;
    for (const [format, title, endpoint] of [['pdf', 'Export PDF', 'pdf'], ['xlsx', 'Export Excel', 'csv']]) {
      let action = menu.querySelector(`[data-cai-export="${format}"]`);
      if (!context.permissions?.canExport) { action?.remove(); continue; }
      if (!action) {
        action = element('a', 'btn', title); action.dataset.caiExport = format;
        (menu.querySelector('.btn-main-menu') || menu.lastElementChild).before(action);
      }
      action.href = `/evenement/${context.eventId}/export/${endpoint}`;
    }
  }
  function setupExports() {
    updateExportActions();
    let exporting = false;
    document.addEventListener('click', async event => {
      const action = event.target.closest('[data-cai-export]');
      if (!action) return;
      event.preventDefault();
      if (exporting) return;
      exporting = true; action.setAttribute('aria-disabled', 'true');
      try {
        if (window.CAIFeatures?.isLocked()) throw new Error('Déverrouillez l’appareil avant de générer un export.');
        if (!window.CAIExports) throw new Error('Actualisez cette page avec une connexion pour préparer les exports hors ligne.');
        const format = action.dataset.caiExport;
        if (format !== 'fiche-pdf' && !context.permissions?.canExport) throw new Error('Vous n’êtes pas autorisé à exporter cet évènement.');
        if (navigator.onLine) {
          try { await refreshSnapshot(); } catch { /* The prepared copy and local actions remain available. */ }
        }
        const saved = await store.get(snapshotKey());
        const data = await listFiches(saved?.data || {fiches: []});
        if (!saved && !data.fiches.length) throw new Error('Ouvrez cet évènement avec une connexion pour préparer les données à exporter.');
        let bytes, filename;
        if (format === 'fiche-pdf') {
          const id = action.dataset.ficheId;
          const fiche = data.fiches.find(row => String(row.id) === id || row.client_uuid === id || 'local-' + row.client_uuid === id);
          if (!fiche) throw new Error('Cette fiche n’est pas disponible sur cet appareil.');
          bytes = window.CAIExports.fichePdf(fiche, data, context);
          filename = 'fiche-' + String(fiche.numero || fiche.id).replace(/[^a-z0-9_-]/gi, '_') + '.pdf';
        } else {
          bytes = format === 'xlsx' ? window.CAIExports.eventXlsx(data, context) : window.CAIExports.eventPdf(data, context);
          filename = `fiches-evenement-${context.eventId}.${format === 'xlsx' ? 'xlsx' : 'pdf'}`;
        }
        window.CAIExports.download(bytes, filename, format === 'xlsx' ? window.CAIExports.MIME_EXCEL : window.CAIExports.MIME_PDF);
      } catch (error) { report(error); }
      finally { exporting = false; action.removeAttribute('aria-disabled'); }
    });
  }
  async function renderDetail() {
    const root = document.getElementById('cai-detail-content'); if (!root || !context) return;
    const id = new URLSearchParams(location.search).get('fiche') || decodeURIComponent(location.pathname.split('/').pop());
    const data = await listFiches(await window.CAIOffline.cached());
    const fiche = data.fiches.find(fiche => String(fiche.id) === id || 'local-' + fiche.client_uuid === id || fiche.client_uuid === id || fiche.qr_url?.endsWith('/q/'+id));
    document.querySelector('[data-cai-dashboard-link]').href = `/evenement/${context.eventId}/dashboard`;
    root.replaceChildren();
    if (!fiche) {
      root.append(element('p', 'card bd', 'Cette fiche a été supprimée ou n’est pas disponible dans la copie de cet appareil.'));
      return;
    }
    document.title = `Fiche ${fiche.numero} — ${fiche.nom} ${fiche.prenom || ''}`;
    const hero = element('section', 'hero'), state = element('span', 'cai-sync-badge' + (fiche.pending ? ' cai-sync-pending' : ''));
    const dot = element('span', 'cai-sync-dot'); dot.setAttribute('aria-hidden', 'true');
    state.append(dot, document.createTextNode(fiche.deletionPending ? 'Suppression en attente du serveur' : fiche.pending ? 'En attente du serveur' : 'Sur le serveur'));
    hero.append(state, element('h1', '', `Fiche ${fiche.numero} — ${fiche.nom} ${fiche.prenom || ''}`),
      element('p', 'meta', `Évènement : ${context.eventName} · ${fiche.est_animal ? 'Animal' : 'Humain'} · ${fiche.statut}`));
    const pdf = element('button', 'btn primary', 'Exporter PDF'); pdf.type = 'button';
    pdf.dataset.caiExport = 'fiche-pdf'; pdf.dataset.ficheId = String(fiche.id); hero.append(pdf);
    if (context.permissions?.canDelete && !fiche.deletionPending) {
      const button = element('button', 'btn secondary', 'Supprimer la fiche'); button.type = 'button';
      button.addEventListener('click', async () => {
        button.disabled = true;
        try { if (await deleteFiche(fiche)) location.assign(`/evenement/${context.eventId}/dashboard`); }
        catch (error) { report(error); }
        finally { button.disabled = false; }
      });
      hero.append(button);
    }
    root.append(hero);
    const grid = element('section', 'grid');
    grid.append(detailCard('Identité', fiche.est_animal ? [
      ['nom', 'Nom', fiche.nom], ['animal_espece', 'Espèce', fiche.animal_espece],
      ['animal_details', 'Notes', fiche.animal_details], ['difficultes', 'Particularités', fiche.difficultes],
    ] : [
      ['nom', 'Nom', fiche.nom], ['prenom', 'Prénom', fiche.prenom],
      ['date_naissance', 'Date de naissance', fiche.date_naissance?.split('-').reverse().join('/')],
      ['adresse', 'Adresse', fiche.adresse],
      ['telephone', 'Téléphone', fiche.telephone], ['code_sinus', 'Code Sinus', fiche.code_sinus],

    ]));
    grid.append(detailCard('Statut et informations', [
      ['statut', 'Statut', fiche.statut], ['heure_arrivee', 'Heure d’arrivée', fiche.heure_arrivee],
      ['heure_sortie', 'Heure de sortie', fiche.heure_sortie], ['destination', 'Destination', fiche.destination],
      ['moyen_transport', 'Moyen de transport', fiche.moyen_transport],
      ['personne_a_prevenir', 'Personne à prévenir', fiche.personne_a_prevenir],
      ['tel_personne_a_prevenir', 'Téléphone à prévenir', fiche.tel_personne_a_prevenir],
      ['recherche_personne', 'Recherche une personne', fiche.recherche_personne],
      ['difficultes', 'Difficultés', fiche.difficultes],
      ['competences', 'Compétences', fiche.competences], ['autres_informations', 'Autres informations', fiche.autres_informations],
      ['bagages', 'Bagages', fiche.bagages.join(', ') || 'Aucun'],
    ]));
    const related = data.fiches.filter(other => fiche.est_animal ?
      String(other.id) === String(fiche.referent?.id || fiche.referent_id) || other.client_uuid === fiche.referent_id :
      other.est_animal && (String(other.referent?.id || other.referent_id) === String(fiche.id) || other.referent_id === fiche.client_uuid));
    if (related.length) {
      const card = detailCard(fiche.est_animal ? 'Personne référente' : 'Animaux rattachés', []), body = card.querySelector('.bd');
      for (const other of related) {
        const link = element('a', 'btn secondary', `${other.numero} — ${other.nom} ${other.prenom || ''}`);
        link.href = `/fiche/${other.id}?evenement_id=${context.eventId}`; body.append(link);
      }
      grid.append(card);
    }
    root.append(grid);
    const timeline = detailCard('Suivi / Timeline', []), body = timeline.querySelector('.bd');
    for (const entry of fiche.timeline) {
      body.append(element('p', 'tmeta', `${entry.created_at || ''}${entry.user ? ' · ' + entry.user : ''}${entry.pending ? ' · En attente du serveur' : ''}`),
        element('p', 'tcontent', entry.content));
    }
    if (!fiche.timeline.length) body.append(element('p', 'tmeta', 'Aucun historique dans la copie de cet appareil.'));
    root.append(timeline);
  }
  function setupActions() {
    document.addEventListener('submit', async event => {
      const form = event.target;
      if (!form.matches('[data-cai-delete]')) return;
      event.preventDefault();
      if (form.dataset.saving) return;
      form.dataset.saving = 'true';
      try { await deleteFiche(window.CAIDashboard.getFiche(form.dataset.ficheId)); }
      catch (error) { report(error); }
      finally { delete form.dataset.saving; }
    });
    for (const [id, action] of [['form-bagage', 'bagages'], ['form-sortie', 'sortie']]) {
      const form = document.getElementById(id);
      if (!form) continue;
      let saving = false;
      form.addEventListener('submit', async event => {
        event.preventDefault(); if (saving) return; saving = true;
        const button = form.querySelector('[type="submit"]'); button.disabled = true;
        const error = form.querySelector('.cai-action-error'); if (error) error.remove();
        try {
          const fiche = window.CAIDashboard.getFiche(form.dataset.ficheId);
          const values = action === 'bagages' ? {numeros: form.elements.numeros.value, base_numeros: form.dataset.baseNumeros || ''} :
            {destination: form.elements.destination.value, moyen_transport: form.elements.moyen_transport.value};
          await queueAction(action, fiche, values);
          const dialogId = action === 'bagages' ? 'modal-bagage' : 'modal-sortie';
          if (window.CAIUI) window.CAIUI.closeDialog(dialogId);
          else document.getElementById(dialogId).style.display = 'none';
        } catch (problem) {
          const message = document.createElement('p'); message.className = 'cai-action-error';
          message.setAttribute('role', 'alert'); message.textContent = problem.message; form.append(message);
          report(problem);
        } finally { saving = false; button.disabled = false; }
      });
    }
  }
  async function init() {
    if (!store || !('indexedDB' in globalThis) || !globalThis.isSecureContext) {
      report(new Error('Le mode hors ligne nécessite HTTPS et le stockage local du navigateur.'));
      return;
    }
    const config = document.getElementById('cai-offline-context');
    if (config) {
      context = JSON.parse(config.textContent);
      await store.put({...context, kind: 'context', key: `context:${context.userId}:${context.eventId}`});
      await store.put({key: 'active', userId: context.userId, eventId: context.eventId});
    } else if (shell || offlineForm || offlineDetail || offlineSearch) {
      const active = await store.get('active');
      const match = location.pathname.match(/^\/evenement\/(\d+)\/(?:dashboard|recherches)$/);
      const parameters = new URLSearchParams(location.search);
      let eventId = Number(parameters.get('event') || parameters.get('evenement_id') || match?.[1] || active?.eventId);
      if (active?.userId && location.pathname.startsWith('/q/')) {
        for (const saved of (await store.all()).filter(r => r.kind === 'snapshot' && r.key.startsWith('snapshot:'+active.userId+':'))) {
          if (saved.data.fiches?.some(f => f.qr_url?.endsWith(location.pathname))) {eventId = Number(saved.key.split(':')[2]); break;}
        }
      }
      if (active?.userId) context = await store.get(`context:${active.userId}:${eventId}`);
      if (!context) {
        if (offlineForm) {
          document.querySelector('form[data-initial-type]').hidden = true;
        }
        report(new Error('Ouvrez d’abord cet évènement avec une connexion pour préparer cet appareil.'));
        return;
      }
    } else {
      // Login page: hide the old account's local workspace, preserve its queue.
      if (document.querySelector('input[type="password"]')) await store.put({key: 'active'});
      return;
    }
    createPanel();
    document.addEventListener('submit', async event => {
      const form = event.target;
      if (new URL(form.action, location.href).pathname !== '/logout' || form.dataset.localCleared) return;
      event.preventDefault();
      await store.put({key: 'active'});
      form.dataset.localCleared = 'true';
      form.requestSubmit();
    });
    await window.CAIFeatures?.ready(context);
    if (document.querySelector('form[data-initial-type]') && navigator.onLine && !window.CAIFeatures?.isLocked()) {
      try { await refreshSnapshot(); } catch { /* Existing copy remains usable. */ }
    }
    if (shell || document.getElementById("fiches-table-body")) {
      window.CAIDashboard?.configure(context); setupActions();
    }
    else if (document.querySelector('form[data-initial-type]')) await setupForm();
    else if (offlineDetail) await renderDetail();
    setupExports();
    if (offlineDetail) {
      window.addEventListener('cai:local', () => renderDetail().catch(report));
      window.addEventListener('cai:sync', () => renderDetail().catch(report));
    }
    await renderQueue();
    await window.CAIFeatures?.refresh();
    window.addEventListener('online', () => sync().catch(report));
    window.addEventListener('offline', () => say('Hors ligne : les nouvelles fiches seront conservées sur cet appareil.', 'offline'));
    if ('serviceWorker' in navigator) {
      try { await navigator.serviceWorker.register('/service-worker.js', {scope: '/'}); await navigator.serviceWorker.ready; }
      catch { say('La préparation du mode hors ligne a échoué. Réessayez avec une connexion.'); return; }
    }
    await sync();
    document.addEventListener('visibilitychange', () => { if (!document.hidden) sync().catch(report); });
    setInterval(() => sync().catch(report), 30000);
  }
  window.CAIOffline = {
    listFiches, snapshot, queueAction, sync,
    context: () => context,
    async findReferents(term) {
      const saved = context && await store.get(snapshotKey());
      const data = await listFiches(saved ? saved.data : {fiches: []});
      return data.fiches.filter(fiche => !fiche.est_animal &&
        `${fiche.numero} ${fiche.nom} ${fiche.prenom}`.toLocaleLowerCase('fr').includes(term.toLocaleLowerCase('fr')))
        .slice(0, 20).map(fiche => ({id: fiche.creationPending ? fiche.client_uuid : fiche.id,
          numero: fiche.numero, label: `${fiche.nom} ${fiche.prenom || ''}`.trim()}));
    },
    async cached() { const record = context && await store.get(snapshotKey()); return record?.data || {fiches: []}; },
  };
  document.addEventListener('DOMContentLoaded', () => init().catch(report));
})();
