const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

// Execute the actual template helpers with malicious stored values.
const tickets = fs.readFileSync('app/templates/tickets_board.html', 'utf8');
const helpers = tickets.slice(tickets.indexOf('    function escapeHTML'), tickets.indexOf('    /* ===== AJAX update'));
const context = vm.createContext({ CAN_MANAGE: true, CURRENT_USER_ID: 1, USERS: [{id: 1, nom: '<img src=x>', role: '<svg>'}] });
vm.runInContext(helpers, context);
const attack = '<img src=x onerror="alert(1)">';
const html = context.ticketCardHTML({id: 1, title: attack, description: attack, status: attack, priority: attack, category: attack, created_by: attack, assigned_to: attack});
assert(!html.includes('<img'), html);
assert(!html.includes('<svg'), html);
assert(html.includes('&lt;img'));

const dashboard = fs.readFileSync('app/templates/dashboard.html', 'utf8');
const dashboardHelpers = dashboard.slice(dashboard.indexOf('    function escapeHTML'), dashboard.indexOf('    const rowsCache')).replace(/\{\{ competence_colors \| tojson \| safe \}\}/g, '{}');
const dashboardContext = vm.createContext({ CAN_DELETE_FICHE: true, CAN_BAGAGES: true, CSRF_TOKEN: 'test-token' });
vm.runInContext(dashboardHelpers, dashboardContext);
const row = dashboardContext.ligneFicheHTML({id: 1, numero: 'F1', nom: attack, prenom: attack, difficultes: attack, competences: attack, statut: attack, heure_arrivee: attack});
assert(!row.includes('<img'), row);
assert(!dashboardContext.renderBagageBadges([attack]).includes('<img'));
assert(!dashboardContext.formatNomCell({nom: attack, est_animal: true}).includes('<img'));
assert(dashboardContext.syncBadgeHTML({pending: true}).includes('cai-sync-pending'));
assert(dashboardContext.syncBadgeHTML({}).includes('Sur le serveur'));
const pendingActions = dashboardContext.actionsHTML({id: 'local-test-uuid', pending: true, creationPending: true, event_id: 1, client_uuid: 'test-uuid'});
assert(pendingActions.includes('/fiche/new?evenement_id=1&draft=test-uuid'));
assert(!pendingActions.includes('/fiche/edit/'));
assert(pendingActions.includes('ouvrirModalBagage(&quot;local-test-uuid&quot;'));
assert(pendingActions.includes('ouvrirModalSortie(&quot;local-test-uuid&quot;'));
const existingPendingActions = dashboardContext.actionsHTML({id: 4, pending: true, numero: '001-0004'});
assert(existingPendingActions.includes('ouvrirModalBagage(4'));
assert(existingPendingActions.includes('ouvrirModalSortie(4'));

let calls = [];
let currentToken = 'csrf-token';
const browser = {
  location: {origin: 'https://example.test'},
  fetch(input, init) { calls.push({input, init}); return Promise.resolve(); },
};
const csrfContext = vm.createContext({
  Request, Headers, URL, window: browser,
  document: {
    addEventListener(_event, callback) { callback(); },
    querySelector() { return {getAttribute() { return currentToken; }}; },
    querySelectorAll() { return []; },
  },
});
vm.runInContext(fs.readFileSync('app/static/csrf.js', 'utf8'), csrfContext);
const request = new Request('https://example.test/test', {method: 'POST', headers: {'X-Existing': 'retained'}});
browser.fetch(request);
assert.equal(calls[0].init.headers.get('X-CSRFToken'), 'csrf-token');
assert.equal(calls[0].init.headers.get('X-Existing'), 'retained');
assert.equal(request.headers.get('X-CSRFToken'), null);
browser.fetch(new URL('https://evil.test'), {method: 'POST'});
assert.equal(calls[1].init.headers, undefined);
currentToken = 'refreshed-after-reconnection';
browser.fetch('/api/evenement/1/fiches/sync', {method: 'POST'});
assert.equal(calls[2].init.headers.get('X-CSRFToken'), currentToken);
console.log('Frontend: XSS escaping and CSRF Request handling passed.');
