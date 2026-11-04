const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

// No fetch, DOM, CDN, or network API is supplied to the exporter.
const context = vm.createContext({TextEncoder, Uint8Array, DataView});
vm.runInContext(fs.readFileSync(path.join(__dirname, '../app/static/offline-exports.js'), 'utf8'), context);
const exportsApi = context.CAIExports;
const event = {id: 5, numero: 'EV-005', nom: 'Évènement été — Cœur', adresse: '4 rue de la Paix',
  statut: 'ouvert', type_evt: 'Accueil', date_ouverture: '04/11/2026 10:30',
  settings: {custom_fields: [{key: 'zone', label: 'Zone d’accueil'}]}};
const first = {id: 'local-example', numero: 'LOCAL-001 (provisoire)', nom: 'Hélène Cœur', prenom: 'François',
  date_naissance: '1990-12-31', telephone: '+330600000000', adresse: '12 allée de l’Église\n75000 Paris',
  personne_a_prevenir: '=HYPERLINK("https://example.invalid","x")', tel_personne_a_prevenir: '-123',
  recherche_personne: '+SUM(1,1)', code_sinus: '@test', autres_informations: '<b>& "notes"\u0001',
  statut: 'sorti', destination: 'Hôpital', moyen_transport: 'Bus', bagages: ['B-01', 'B-02'],
  heure_arrivee: '04/11/2026 10:30', heure_sortie: '04/11/2026 11:30', pending: true,
  custom_values: {zone: 'Étage 2'}, timeline: [{created_at: '04/11/2026 11:30', content: 'Sortie locale', pending: true}]};
const data = {evenement: event, fiches: [first, ...Array.from({length: 149}, (_, index) => ({
  id: index + 1, numero: 'F-' + (index + 1), nom: 'Personne-' + (index + 1), prenom: 'Zoé',
  statut: 'présent', bagages: [],
})), {id: 999, numero: 'EXCLUDED', nom: 'SUPPRIMÉ_CONFIRME', deletedConfirmed: true}]};
const empty = {fiches: [], evenement: event};
const longFiche = {...first, autres_informations: 'Texte détaillé très long. '.repeat(1500) + 'FIN_NOTES',
  timeline: [...first.timeline, {created_at: '04/11/2026 11:31', content: 'FIN_HISTORIQUE'}]};
const files = {
  'event.xlsx': exportsApi.eventXlsx(data),
  'event.pdf': exportsApi.eventPdf(data),
  'fiche.pdf': exportsApi.fichePdf(longFiche, data),
  'empty.xlsx': exportsApi.eventXlsx(empty),
  'empty.pdf': exportsApi.eventPdf(empty),
};
assert.equal(Buffer.from(files['event.xlsx']).subarray(0, 4).toString('hex'), '504b0304');
assert.equal(Buffer.from(files['event.pdf']).subarray(0, 8).toString(), '%PDF-1.4');
assert.equal(Buffer.from(files['fiche.pdf']).subarray(-6).toString(), '%%EOF\n');
assert(files['event.pdf'].length > 30000);
assert(exportsApi.eventExcel === exportsApi.eventXlsx);
// Exporting does not mutate the merged snapshot.
assert.equal(data.fiches.length, 151);
assert.deepEqual(first.bagages, ['B-01', 'B-02']);
assert.equal(first.statut, 'sorti');
if (process.argv[2]) {
  fs.mkdirSync(process.argv[2], {recursive: true});
  for (const [name, bytes] of Object.entries(files)) fs.writeFileSync(path.join(process.argv[2], name), Buffer.from(bytes));
}
console.log('Offline exports: native PDF/XLSX generated without browser or network APIs.');
