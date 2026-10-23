const src = require('./load_script.js');
const els = {};
const el = id => els[id] || (els[id] = {id, innerHTML:'', textContent:'', value:'', checked:false, disabled:false, focus(){}, classList:{add(){},remove(){},toggle(){}}, style:{}});
const doc = {getElementById: el, querySelectorAll: () => [], addEventListener(){}};
let calls = [], alerts = [], confirmAnswer = true, confirmText = '', batchResp;
const fetchStub = async (u, o) => {
  calls.push([u, o && o.body]);
  if(u === '/api/offboarding/execute-batch') return {ok: batchResp.ok !== false, status: batchResp.status || 200, json: async () => batchResp.body};
  return {ok:true, json: async () => ({users:[], ous:[], groups:[], templates:[]})};
};
const f = new Function('document','window','navigator','alert','fetch','confirm', src.replace(/document\.addEventListener\("DOMContentLoaded"[\s\S]*?\}\);\s*\n/, '') + `
return {renderOffboardTable, toggleOffboardSelect, toggleSelectAllOffboard, executeOffboardBatch, getSel:()=>offSelected, setUsers:u=>{cachedOffboardUsers=u}, setMe:n=>{currentLoggedInUsername=n}, stubRefresh:fn=>{refreshAllLdapData=fn}};`);
const mk = (i, extra) => Object.assign({dn:'CN=u'+i, name:'User '+i, sam:'u'+i, mail:'', disabled:false, protected:'', ou:'OU=x'}, extra || {});
(async () => {
  const api = f(doc, {}, {language:'de'}, m => alerts.push(m), fetchStub, m => { confirmText = m; return confirmAnswer; });
  let refreshed = 0; api.stubRefresh(async () => { refreshed++; });
  el('offboard-search').value = '';
  const users = [mk(1), mk(2, {disabled:true}), mk(3, {protected:'Mitglied von „Domänen-Admins“'}), mk(4, {name:'<b>X</b>'}), mk(5, {sam:'ich'})];
  api.setMe('ich'); api.setUsers(users); api.renderOffboardTable(users);
  const h = els['offboard-user-list'].innerHTML;
  console.assert((h.match(/class="off-sel/g) || []).length === 2, 'Nur auswaehlbare Konten haben ein Kontrollkaestchen');
  console.assert(h.includes('Geschützt') && !h.includes('<b>X</b>'), 'Schutz angezeigt, Name escaped');
  api.toggleOffboardSelect('CN=u1', true); api.toggleOffboardSelect('CN=u4', true);
  console.assert(api.getSel().size === 2 && els['off-sel-count'].textContent === 2 && els['off-batch-btn'].disabled === false, 'Auswahl + Zaehler');
  api.toggleOffboardSelect('CN=u1', false);
  console.assert(api.getSel().size === 1, 'Abwaehlen');
  api.toggleSelectAllOffboard(true);
  console.assert(api.getSel().size === 2 && !api.getSel().has('CN=u3') && !api.getSel().has('CN=u2'), 'Alle auswaehlen nur auswaehlbare');
  // Obergrenze 25
  const many = Array.from({length: 30}, (_, i) => mk(100 + i));
  api.setUsers(many); api.renderOffboardTable(many); api.getSel().clear();
  api.toggleSelectAllOffboard(true);
  console.assert(api.getSel().size === 25 && alerts.length === 1, 'Obergrenze 25 mit Hinweis');
  // Abbruch -> kein Request
  confirmAnswer = false; calls.length = 0; await api.executeOffboardBatch();
  console.assert(calls.length === 0 && confirmText.includes('25 Konten'), 'Abbruch ohne Request');
  // Erfolg mit Teilfehler
  confirmAnswer = true; api.setUsers(users); api.renderOffboardTable(users); api.getSel().clear(); api.toggleOffboardSelect('CN=u1', true);
  batchResp = {body:{status:'success', done:[{dn:'CN=u1', name:'User 1', sam:'u1', failedGroups:[]}], failed:[{dn:'CN=u9', name:'User 9', error:'Dieses Konto ist geschützt'}]}};
  alerts.length = 0; calls.length = 0; await api.executeOffboardBatch();
  const body = JSON.parse(calls.find(c => c[0] === '/api/offboarding/execute-batch')[1]);
  console.assert(body.userDns.length === 1 && body.userDns[0] === 'CN=u1', 'Payload');
  console.assert(alerts[0].includes('1 von 1') && alerts[0].includes('User 9') && api.getSel().size === 0 && refreshed === 1, 'Ergebnis mit Fehlerliste, Auswahl geleert, Liste neu geladen');
  // Serverfehler
  api.getSel().clear(); api.toggleOffboardSelect('CN=u1', true);
  batchResp = {ok:false, status:400, body:{detail:'Maximal 25 Konten gleichzeitig.'}}; alerts.length = 0;
  await api.executeOffboardBatch();
  console.assert(alerts[0] === 'Maximal 25 Konten gleichzeitig.' && api.getSel().size === 1, 'Serverfehler angezeigt, Auswahl bleibt');
  console.log('Offboarding-UI-Tests fertig');
})();
