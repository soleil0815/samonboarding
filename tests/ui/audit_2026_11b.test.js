// Code audit 2026-11b: list errors, error texts of invalid input, the shared result window and "1 Konto"
const assert = require('assert');
const src = require('./load_script.js');

const els = {};
function el(id) {
  if(!els[id]) {
    const classes = new Set(['hidden']);
    els[id] = {id, innerHTML: '', textContent: '', value: '', disabled: false,
      classList: {add: c => classes.add(c), remove: c => classes.delete(c), contains: c => classes.has(c),
        toggle: (c, on) => { if(on === undefined ? !classes.has(c) : on) classes.add(c); else classes.delete(c); }}};
  }
  return els[id];
}
const doc = {getElementById: el, querySelector: () => null, querySelectorAll: () => [], addEventListener() {},
  documentElement: {setAttribute() {}}};
const f = new Function('document', 'window', 'navigator', 'localStorage',
  src.replace(/document\.addEventListener\("DOMContentLoaded"[\s\S]*?\}\);\s*\n/, '') +
  '\nreturn {showListProblem, accountsText, detailText, closeResultModal, setResultFrom: v => { resultFrom = v; }, ' +
  'setRole: r => { currentUserRole = r; }};');
const app = f(doc, {matchMedia: () => ({matches: false, addEventListener() {}})}, {language: 'de'},
  {getItem: () => null, setItem() {}});

(async () => {
  // a list that cannot be loaded says why instead of "Lade Benutzer..." forever
  el('usermgmt-user-list').innerHTML = 'Lade Benutzer...';
  await app.showListProblem('usermgmt-user-list', 5, {ok: false, json: async () => ({detail: 'DC nicht erreichbar.'})});
  assert.ok(el('usermgmt-user-list').innerHTML.includes('DC nicht erreichbar.'));
  assert.ok(el('usermgmt-user-list').innerHTML.includes('colspan="5"'));
  // no JSON at all: a general text
  await app.showListProblem('pwdreset-user-list', 4, {ok: false, json: async () => { throw new Error('x'); }});
  assert.ok(el('pwdreset-user-list').innerHTML.includes('Die Liste konnte nicht geladen werden.'));
  // no source OUs: the server's hint, and for an operator who to ask
  app.setRole('Account Operator');
  await app.showListProblem('offboard-user-list', 7, null, {users: [], warning: 'Keine Quell-OUs für das Offboarding konfiguriert.'});
  assert.ok(el('offboard-user-list').innerHTML.includes('Keine Quell-OUs'));
  assert.ok(el('offboard-user-list').innerHTML.includes('Administrator bitten'));
  // the server's text is never inserted as HTML
  await app.showListProblem('usermgmt-user-list', 5, {ok: false, json: async () => ({detail: '<img src=x>'})});
  assert.ok(!el('usermgmt-user-list').innerHTML.includes('<img'));
  // a filled list stays as it is
  el('offboard-user-list').innerHTML = 'rows';
  await app.showListProblem('offboard-user-list', 7, null, {users: [{sam: 'a'}], warning: 'x'});
  assert.strictEqual(el('offboard-user-list').innerHTML, 'rows');

  // invalid input: FastAPI sends a list of objects (was shown as "[object Object]")
  assert.strictEqual(app.detailText([{msg: 'Field required'}, {msg: 'Input should be a valid integer'}]), 'Field required; Input should be a valid integer');
  assert.strictEqual(app.detailText('Template nicht gefunden.'), 'Template nicht gefunden.');
  assert.strictEqual(app.detailText(undefined), '');

  assert.strictEqual(app.accountsText(1), '1 Konto');
  assert.strictEqual(app.accountsText(3), '3 Konten');

  // closing the result of a password reset keeps a half-filled onboarding form
  el('hire-fn').value = 'Max';
  el('result-modal').classList.remove('hidden');
  app.setResultFrom('pwdreset');
  app.closeResultModal();
  assert.ok(el('result-modal').classList.contains('hidden'));
  assert.strictEqual(el('hire-fn').value, 'Max');

  console.log('audit_2026_11b: fertig');
})().catch(e => { console.error(e); process.exit(1); });
