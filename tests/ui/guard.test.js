// Double-click protection: a running action is not started a second time; late group responses are discarded
const src = require('./load_script.js');
const f = new Function('document', 'window', 'navigator', 'fetch',
  src.replace(/document\.addEventListener\("DOMContentLoaded"[\s\S]*?\}\);\s*\n/, '') + `
return {guarded, busyActions, openUserGroupsModal, src: { submitOnboard, submitPwdReset, executeOffboardBatch, executeOffboard, executeBatch, submitUpdateUserGroups }};`);
const els = {};
const el = id => els[id] || (els[id] = {id, value: '', innerHTML: '', classList: {add() {}, remove() {}, toggle() {}, contains: () => false}});
let release;
const slow = new Map();
const api = f({getElementById: el, querySelector: () => null, querySelectorAll: () => [], addEventListener() {}}, {}, {language: 'de'},
  async url => {
    const dn = decodeURIComponent(String(url).split('userDn=')[1] || '');
    if (dn === 'CN=A') await new Promise(r => slow.set('A', r));
    return {ok: true, json: async () => ({userMemberOf: dn === 'CN=A' ? ['CN=G1'] : [], availableGroups: [{dn: 'CN=G1', name: 'G1'}]})};
  });
(async () => {
  let runs = 0;
  const job = () => new Promise(r => { runs++; release = r; });
  const first = api.guarded('x', job);
  await api.guarded('x', job);  // second click while the first is running: nothing happens
  console.assert(runs === 1, 'Aktion laeuft nur einmal');
  release(); await first;
  await api.guarded('x', async () => { runs++; });
  console.assert(runs === 2 && !api.busyActions.has('x'), 'danach wieder moeglich');
  for (const [name, fn] of Object.entries(api.src)) console.assert(/guarded\('/.test(String(fn)), name + ' ist geschuetzt');
  // Groups: click A (slow), then B - in the end B with B's groups must be in the window
  const a = api.openUserGroupsModal('CN=A', 'a');
  await api.openUserGroupsModal('CN=B', 'b');
  slow.get('A')(); await a;
  console.assert(el('groups-user-dn').value === 'CN=B', 'Fenster gehoert zu B');
  console.assert(!el('user-groups-checkboxes').innerHTML.includes('checked'), 'Gruppen von B, nicht von A');
  console.log('Doppelklick-Tests fertig');
})();
