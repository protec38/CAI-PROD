(function () {
  'use strict';
  const store = globalThis.CAIOfflineStore;
  const shell = document.body.classList.contains('cai-offline-shell');
  let context, busy = false, editing = null, panel, status, queue;
  const field = (record, name) => (record.fields.find(pair => pair[0] === name) || [])[1] || '';
  const snapshotKey = () => `snapshot:${context.userId}:${context.eventId}`;
  const label = record => record.label || 'Fiche';
  function say(message) { if (status) status.textContent = message; }
  function badge(pending) {
    const span = document.createElement('span');
    span.className = 'cai-sync-badge' + (pending ? ' cai-sync-pending' : '');
    const dot = document.createElement('span');
    dot.className = 'cai-sync-dot'; dot.setAttribute('aria-hidden', 'true');
    span.append(dot, document.createTextNode(pending ? 'En attente du serveur' : 'Sur le serveur'));
    return span;
  }
  function createPanel() {
    panel = document.createElement('section');
    panel.className = 'cai-offline-panel';
    panel.setAttribute('aria-label', 'Synchronisation des fiches');
    status = document.createElement('p'); status.setAttribute('role', 'status');
    const link = document.createElement('a');
    link.href = `/hors-ligne?event=${context.eventId}`;
    link.textContent = 'Saisie et fiches hors ligne';
    const button = document.createElement('button');
    button.type = 'button'; button.textContent = 'Synchroniser';
    button.addEventListener('click', () => sync().catch(report));
    queue = document.createElement('ul');
    panel.append(status, link, button, queue);
    (document.querySelector('main') || document.body).prepend(panel);
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
    const records = (await store.all()).filter(record => record.kind === 'fiche' &&
      record.userId === context.userId && record.eventId === context.eventId);
    // Retain a short list of receipts, and every pending record.
    const recent = records.filter(record => record.server).slice(-5);
    for (const record of records.filter(record => !record.server).concat(recent)) {
      const li = document.createElement('li');
      li.append(badge(!record.server), document.createTextNode(
        ` ${record.server ? record.server.numero : record.provisional + ' (provisoire)'} — ${label(record)}`));
      if (record.server && record.server.numero !== record.provisional) {
        li.append(document.createTextNode(` · ancien n° ${record.provisional}`));
      }
      if (!record.server && !record.deliveryStarted) {
        const a = document.createElement('a');
        a.href = `/hors-ligne?event=${record.eventId}&draft=${record.uuid}`;
        a.textContent = ' Ouvrir / corriger'; li.append(a);
      }
      if (record.deliveryStarted && !record.server) {
        li.append(document.createTextNode(' · Envoi à vérifier au retour du serveur avant correction.'));
      }
      if (record.error) {
        const error = document.createElement('p'); error.className = 'cai-offline-error';
        error.textContent = record.error; li.append(error);
      }
      queue.append(li);
    }
    if (shell) await renderSnapshot();
  }
  async function listFiches(data) {
    if (!context) return data;
    const pending = await store.pending(context.userId, context.eventId);
    const confirmed = new Set((data.fiches || []).map(fiche => fiche.client_uuid));
    const locals = pending.filter(record => !confirmed.has(record.uuid)).map(record => ({
      id: `local-${record.uuid}`, client_uuid: record.uuid, pending: true,
      event_id: record.eventId,
      deliveryStarted: !!record.deliveryStarted,
      numero: `${record.provisional} (provisoire)`,
      nom: field(record, 'type_fiche') === 'animal' ? field(record, 'animal_nom') : field(record, 'nom'),
      prenom: field(record, 'prenom'), statut: 'présent',
      est_animal: field(record, 'type_fiche') === 'animal',
      type_fiche: field(record, 'type_fiche'), animal_espece: field(record, 'animal_espece'),
      heure_arrivee: new Date(record.createdAt).toLocaleString('fr-FR', {timeZone: 'Europe/Paris'}),
      difficultes: field(record, 'difficulte') || field(record, 'animal_particularites'),
      competences: record.fields.filter(pair => pair[0] === 'competences').map(pair => pair[1]).join(','),
    }));
    const result = {...data, fiches: [...(data.fiches || []), ...locals]};
    for (const local of locals) {
      const suffix = local.est_animal ? '_animaux' : '';
      result[`nb_total${suffix}`] = (result[`nb_total${suffix}`] || 0) + 1;
      result[`nb_present${suffix}`] = (result[`nb_present${suffix}`] || 0) + 1;
    }
    return result;
  }
  async function snapshot(data) {
    await store.put({key: snapshotKey(), kind: 'snapshot', data, savedAt: new Date().toISOString()});
  }
  async function refreshSnapshot() {
    const response = await fetch(`/evenement/${context.eventId}/fiches_json`, {cache: 'no-store'});
    if (!response.ok || response.redirected) throw new Error('Impossible d’actualiser les fiches du serveur.');
    const data = await response.json(); await snapshot(data);
  }
  async function sync() {
    if (busy || !context) return;
    if (navigator.onLine === false) {
      say('Hors ligne : les fiches restent sur cet appareil, en attente du serveur.');
      await renderQueue(); return;
    }
    busy = true;
    try {
      const pending = await store.pending(context.userId);
      say('Vérification de la connexion au serveur…');
      const response = await fetch('/api/offline/session', {cache: 'no-store', signal: AbortSignal.timeout(10000)});
      if (!response.ok) throw new Error('Reconnectez-vous pour synchroniser. Vos fiches restent sur cet appareil.');
      const session = await response.json();
      if (session.user_id !== context.userId) {
        throw new Error('Reconnectez-vous avec le compte ayant créé ces fiches. La synchronisation est suspendue.');
      }
      const meta = document.querySelector('meta[name="csrf-token"]');
      if (meta) meta.content = session.csrf_token;
      for (const pendingRecord of pending) {
        // A correction currently open must never be sent from its older version.
        if (pendingRecord.uuid === editing) continue;
        // Atomically freeze the latest version, including corrections from
        // another tab, before building the request.
        const record = await store.beginDelivery(pendingRecord.key);
        if (!record) continue;
        const body = new URLSearchParams(record.fields);
        body.set('client_uuid', record.uuid); body.set('user_id', String(record.userId));
        body.set('heure_arrivee_utc', record.createdAt);
        body.delete('csrf_token');
        // If the response is lost, the record may already exist on the server.
        // Freeze corrections until its receipt is recovered; retries keep UUID.
        const result = await fetch(`/api/evenement/${record.eventId}/fiches/sync`, {
          method: 'POST', body, headers: {'X-CSRFToken': session.csrf_token},
          signal: AbortSignal.timeout(15000),
        });
        const json = await result.json().catch(() => ({}));
        if (!result.ok) {
          record.error = json.error || 'Synchronisation refusée. Réessayez après reconnexion.';
          await store.change(record.key, current => current.server || current.revision !== record.revision ? current : {
            ...current, error: record.error,
            deliveryStarted: result.status !== 422,
          });
          if (result.status === 401 || result.status === 400 || result.status >= 500) throw new Error(record.error);
          continue;
        }
        await store.acknowledge(record.key, json);
      }
      await refreshSnapshot();
      const remaining = (await store.pending(context.userId)).length;
      say(remaining ? `${remaining} fiche(s) en attente sur cet appareil. Ouvrez l’évènement concerné pour consulter les messages.` :
        'Toutes les fiches sont sur le serveur. Le mode hors ligne est prêt sur cet appareil.');
      await renderQueue();
      window.dispatchEvent(new Event('cai:sync'));
    } catch (error) {
      const remaining = (await store.pending(context.userId)).length;
      say(error.name === 'TypeError' || error.name === 'TimeoutError' ?
        `Serveur inaccessible · ${remaining} fiche(s) en attente. Nouvel essai automatique au retour de la connexion.` : error.message);
      await renderQueue();
    } finally { busy = false; }
  }
  async function saveForm(form) {
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
    form.dataset.savedUuid = uuid;
    editing = null;
    navigator.storage?.persist?.().catch(() => {});
    await renderQueue();
    await sync();
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
        const record = await saveForm(form);
        if (!shell) {
          location.assign(record.server ? `/evenement/${context.eventId}/dashboard` : `/hors-ligne?event=${context.eventId}`);
        } else {
          form.reset(); setType(form);
          delete form.dataset.savedUuid;
          document.getElementById('cai-edit-title').textContent = 'Nouvelle fiche';
          history.replaceState(null, '', `/hors-ligne?event=${context.eventId}`);
        }
      } catch (error) { report(error); }
      finally { saving = false; if (submit) submit.disabled = false; }
    });
  }
  function setType(form) {
    const type = form.elements.type_fiche.value;
    form.querySelectorAll('[data-for]').forEach(section => {
      const active = section.dataset.for === type;
      section.hidden = !active;
      section.querySelectorAll('input,select,textarea').forEach(input => { input.disabled = !active; });
    });
  }
  async function renderSnapshot() {
    const container = document.getElementById('cai-offline-fiches'); if (!container) return;
    const saved = await store.get(snapshotKey());
    const data = await listFiches(saved ? saved.data : {fiches: []});
    container.replaceChildren();
    const stamp = document.getElementById('cai-snapshot-date');
    stamp.textContent = saved ? `Dernière lecture du serveur : ${new Date(saved.savedAt).toLocaleString('fr-FR')}.` :
      'Aucune copie des fiches du serveur sur cet appareil.';
    for (const fiche of data.fiches) {
      const row = document.createElement('tr');
      for (const value of [fiche.numero, `${fiche.nom || ''} ${fiche.prenom || ''}`, fiche.statut]) {
        const td = document.createElement('td'); td.textContent = value; row.append(td);
      }
      const td = document.createElement('td'); td.append(badge(!!fiche.pending)); row.append(td);
      container.append(row);
    }
  }
  async function setupShell() {
    document.getElementById('cai-event-name').textContent = context.eventName;
    const picker = document.getElementById('cai-event');
    for (const record of (await store.all()).filter(record => record.kind === 'context' && record.userId === context.userId)) {
      const option = new Option(record.eventName, String(record.eventId));
      option.selected = record.eventId === context.eventId; picker.add(option);
    }
    picker.addEventListener('change', () => location.assign(`/hors-ligne?event=${picker.value}`));
    document.getElementById('cai-online-link').href = `/evenement/${context.eventId}/dashboard`;
    const form = document.getElementById('cai-offline-form');
    const saved = await store.get(snapshotKey());
    const referents = await listFiches(saved ? saved.data : {fiches: []});
    for (const fiche of referents.fiches.filter(fiche => !fiche.est_animal)) {
      form.elements.animal_referent_id.add(new Option(
        `${fiche.numero} — ${fiche.nom} ${fiche.prenom || ''}`, fiche.pending ? fiche.client_uuid : String(fiche.id)));
    }
    const draftId = new URLSearchParams(location.search).get('draft');
    if (draftId) {
      const draft = await store.get(`fiche:${draftId}`);
      if (draft && !draft.server && !draft.deliveryStarted && draft.userId === context.userId && draft.eventId === context.eventId) {
        editing = draft.uuid;
        for (const input of form.elements) {
          if (!input.name) continue;
          const values = draft.fields.filter(pair => pair[0] === input.name).map(pair => pair[1]);
          if (input.multiple) Array.from(input.options).forEach(option => { option.selected = values.includes(option.value); });
          else input.value = values[0] || '';
        }
        document.getElementById('cai-edit-title').textContent = `Corriger la fiche ${draft.provisional}`;
      }
    }
    setType(form);
    form.elements.type_fiche.addEventListener('change', () => setType(form));
    interceptForm(form);
    document.getElementById('cai-workspace').hidden = false;
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
    } else if (shell) {
      const active = await store.get('active');
      const match = location.pathname.match(/^\/evenement\/(\d+)\/dashboard$/);
      const parameters = new URLSearchParams(location.search);
      const eventId = Number(parameters.get('event') || parameters.get('evenement_id') || match?.[1] || active?.eventId);
      if (active?.userId) context = await store.get(`context:${active.userId}:${eventId}`);
      if (!context) return;
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
    if (shell) { document.getElementById('cai-start-message').hidden = true; await setupShell(); }
    else {
      const form = document.querySelector('form[data-initial-type]');
      if (form && location.pathname === '/fiche/new') interceptForm(form);
    }
    await renderQueue();
    if ('serviceWorker' in navigator) {
      try { await navigator.serviceWorker.register('/service-worker.js', {scope: '/'}); await navigator.serviceWorker.ready; }
      catch { say('La préparation du mode hors ligne a échoué. Réessayez avec une connexion.'); return; }
    }
    await sync();
    window.addEventListener('online', () => sync().catch(report));
    window.addEventListener('offline', () => say('Hors ligne : les nouvelles fiches seront conservées sur cet appareil.'));
    document.addEventListener('visibilitychange', () => { if (!document.hidden) sync().catch(report); });
    setInterval(() => sync().catch(report), 30000);
  }
  window.CAIOffline = {
    listFiches, snapshot,
    async cached() { const record = context && await store.get(snapshotKey()); return record?.data || {fiches: []}; },
  };
  document.addEventListener('DOMContentLoaded', () => init().catch(report));
})();
