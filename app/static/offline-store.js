/* Durable queue. Never remove an entry before a server acknowledgement. */
(function (global) {
  'use strict';
  let opening;
  function database() {
    if (!opening) opening = new Promise((resolve, reject) => {
      const request = indexedDB.open('cai-offline', 1);
      request.onupgradeneeded = () => {
        request.result.createObjectStore('records', {keyPath: 'key'});
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
      request.onblocked = () => reject(new Error('Fermez les autres onglets CAI puis réessayez.'));
    });
    return opening;
  }
  async function run(mode, operation) {
    const db = await database();
    return new Promise((resolve, reject) => {
      const transaction = db.transaction('records', mode);
      const request = operation(transaction.objectStore('records'));
      transaction.oncomplete = () => resolve(request.result);
      transaction.onerror = () => reject(transaction.error);
      transaction.onabort = () => reject(transaction.error || new Error('Stockage interrompu.'));
    });
  }
  async function change(key, update) {
    const db = await database();
    return new Promise((resolve, reject) => {
      const transaction = db.transaction('records', 'readwrite');
      const objects = transaction.objectStore('records');
      const request = objects.get(key);
      let result;
      request.onsuccess = () => {
        try { result = update(request.result); if (result) objects.put(result); }
        catch (error) { reject(error); transaction.abort(); }
      };
      transaction.oncomplete = () => resolve(result);
      transaction.onerror = () => reject(transaction.error);
      transaction.onabort = () => reject(transaction.error || new Error('Stockage interrompu.'));
    });
  }
  global.CAIOfflineStore = {
    get: key => run('readonly', store => store.get(key)),
    put: record => run('readwrite', store => store.put(record)),
    all: () => run('readonly', store => store.getAll()),
    uuid: () => crypto.randomUUID(),
    change,
    saveDraft(record) {
      return change(record.key, current => {
        if (current?.server || current?.deliveryStarted || current?.cancelled || current?.deleting) {
          throw new Error('Cette fiche a été envoyée. Attendez sa confirmation avant de la modifier sur le serveur.');
        }
        record.revision = (current?.revision || 0) + 1;
        return record;
      });
    },
    beginDelivery(key) {
      return change(key, current => current && !current.server && !current.cancelled ? {...current, deliveryStarted: true} : null);
    },
    async enqueueAction(record) {
      const db = await database();
      return new Promise((resolve, reject) => {
        const transaction = db.transaction('records', 'readwrite');
        const objects = transaction.objectStore('records');
        const request = objects.getAll();
        request.onsuccess = () => {
          try {
            const records = request.result;
            const same = other => other.kind === 'mutation' && other.userId === record.userId &&
              other.eventId === record.eventId && (record.target.uuid ? other.target.uuid === record.target.uuid :
                other.target.id === record.target.id && (!other.target.identity || !record.target.identity || other.target.identity === record.target.identity));
            const creation = record.target.uuid && records.find(other => other.key === `fiche:${record.target.uuid}`);
            if (record.action !== 'delete' && (creation?.cancelled || creation?.deleting || records.some(other =>
              same(other) && other.action === 'delete' && !other.cancelled))) {
              throw new Error('Cette fiche est déjà supprimée ou en attente de suppression.');
            }
            if (record.action === 'delete') {
              const previous = records.find(other => same(other) && other.action === 'delete' && !other.cancelled);
              if (previous) { record = previous; return; }
              for (const other of records.filter(other => same(other) && !other.server)) objects.put({...other, cancelled: true});
              if (creation && creation.userId === record.userId) {
                const local = record.localOnlyCandidate && !creation.server && !creation.deliveryStarted;
                objects.put({...creation, deleting: true, ...(local ? {cancelled: true, fields: []} : {})});
                if (local) {
                  record.cancelled = true; record.localCancelled = true;
                  for (const animal of records.filter(other => other.kind === 'fiche' && !other.server && !other.deliveryStarted &&
                    other.userId === record.userId && other.eventId === record.eventId && other.fields?.some(pair =>
                      pair[0] === 'animal_referent_id' && pair[1] === record.target.uuid))) {
                    objects.put({...animal, fields: animal.fields.filter(pair => pair[0] !== 'animal_referent_id'),
                      revision: (animal.revision || 0) + 1});
                  }
                }
              }
            }
            record.sequence = (records.find(other => other.key === 'action-sequence')?.value || 0) + 1;
            objects.put({key: 'action-sequence', value: record.sequence}); objects.put(record);
          } catch (error) { reject(error); transaction.abort(); }
        };
        transaction.oncomplete = () => resolve(record);
        transaction.onerror = () => reject(transaction.error);
        transaction.onabort = () => reject(transaction.error || new Error('Stockage interrompu.'));
      });
    },
    async pending(userId, eventId) {
      return (await this.all()).filter(record => ['fiche', 'mutation'].includes(record.kind) &&
        record.userId === userId && (!eventId || record.eventId === eventId) && !record.server && !record.cancelled)
        .sort((a, b) => a.createdAt.localeCompare(b.createdAt));
    },
    async acknowledge(key, result) {
      return change(key, record => {
        if (!record || (record.kind === 'mutation' ? result.operation_uuid : result.client_uuid) !== record.uuid || !result.synced || !result.id || !result.numero) {
          throw new Error('Confirmation du serveur invalide. La fiche reste en attente.');
        }
        record.server = {id: result.id, numero: result.numero, deleted: !!result.deleted};
        if (record.kind === 'fiche' && result.deleted) { record.cancelled = true; record.fields = []; }
        record.error = '';
        // Keep the local version until a fresh snapshot confirms this receipt.
        return record;
      });
    },
  };
})(globalThis);
