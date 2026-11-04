const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

// Exercise the dashboard's actual comparator and row reordering, without a server.
const template = fs.readFileSync('app/templates/dashboard.html', 'utf8');
const context = vm.createContext({ rowsCache: new Map() });
vm.runInContext(template.slice(template.indexOf('    function formatPrenomCell'),
  template.indexOf('    function normalizeStatutValue')), context);
vm.runInContext(template.slice(template.indexOf('    const ficheSortCollator'),
  template.indexOf('    function upsertRow')), context);
function compare(key, first, second, direction = 'asc') {
  vm.runInContext(`ficheSort={key:${JSON.stringify(key)},direction:${JSON.stringify(direction)}}`, context);
  return context.compareFichesForSort(first, second);
}
assert(compare('numero', { numero: 'F2' }, { numero: 'F10' }) < 0);
assert(compare('numero', { numero: 'F2' }, { numero: 'F10' }, 'desc') > 0);
assert.equal(compare('nom', { nom: 'ÉLODIE' }, { nom: 'elodie' }), 0);
assert(compare('nom', { nom: 'Émile' }, { nom: 'Zola' }) < 0);
assert(compare('prenom', { est_animal: true, animal_espece: 'Chat' }, { prenom: 'Zoé' }) < 0);
assert(compare('statut', { statut: 'présent' }, { statut: 'sorti' }) < 0);
assert(compare('heure_arrivee', { heure_arrivee: '31/01/2026 23:59' }, { heure_arrivee: '01/02/2026 00:00' }) < 0);
assert(compare('heure_arrivee', { heure_arrivee: '31/12/2025 23:59' }, { heure_arrivee: '01/01/2026 00:00' }) < 0);
assert(compare('heure_arrivee', { heure_arrivee: '-' }, { heure_arrivee: '01/01/2026 00:00' }, 'desc') > 0);
assert(compare('difficultes', { difficultes: '' }, { difficultes: 'Mobilité' }, 'desc') > 0);
assert(compare('competences', { competences: 'Accueil' }, { competences: 'Traduction' }) < 0);
assert(compare('bagages', { bagages: ['B2'] }, { bagages: ['B10'] }) < 0);
const original = ['B10', 'B2'];
context.ficheSortValue({ bagages: original }, 'bagages');
assert.deepEqual(original, ['B10', 'B2']);

const rows = [{ id: 'fiche-row-1', hidden: true }, { id: 'fiche-row-local-draft', hidden: false }, { id: 'fiche-row-3', hidden: false }];
const body = {
  children: [...rows],
  contains(node) { return this.children.includes(node); },
  insertBefore(node, reference) {
    this.children.splice(this.children.indexOf(node), 1);
    const index = reference ? this.children.indexOf(reference) : this.children.length;
    this.children.splice(index, 0, node);
    context.document.activeElement = null;
  },
};
rows[2].focus = () => { context.document.activeElement = rows[2]; };
context.document = { getElementById: () => body, activeElement: rows[2] };
context.rowsCache.set(1, { id: 1, nom: 'Zola' });
context.rowsCache.set('local-draft', { id: 'local-draft', nom: 'Émile' });
context.rowsCache.set(3, { id: 3, nom: 'Alice' });
compare('nom', {}, {});
context.sortFicheRows();
assert.deepEqual(body.children.map(row => row.id), ['fiche-row-3', 'fiche-row-local-draft', 'fiche-row-1']);
assert.equal(rows[0].hidden, true, 'Sorting preserves the active filters.');
assert.equal(context.document.activeElement, rows[2], 'Sorting preserves focus inside a row.');
context.rowsCache.set(1, { id: 1, nom: 'Aaron' });
context.sortFicheRows();
assert.deepEqual(body.children.map(row => row.id), ['fiche-row-1', 'fiche-row-3', 'fiche-row-local-draft']);
compare('', {}, {});
context.sortFicheRows();
assert.deepEqual(body.children.map(row => row.id), rows.map(row => row.id), 'Initial order can be restored.');
console.log('Dashboard: French text, natural numbers, dates, offline rows, refresh, filters and focus sorting passed.');
