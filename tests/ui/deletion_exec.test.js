const fs = require('fs');
const src = require('./load_script.js');
const els = {};
const el = id => els[id] || (els[id] = {id, innerHTML:'', textContent:'', value:'', checked:false, disabled:false, focus(){}, classList:{add(){},remove(){},toggle(){}}, style:{}});
const doc = {getElementById: el, querySelectorAll: () => [], addEventListener(){}};
let confirms = 0, confirmAnswer = true, calls = [], alerts = [];
let simResp, execResp, batchSim, batchExec, jobs = [];
const fetchStub = async (u, o) => {
  calls.push([u, o && o.body]);
  if(u === '/api/deletion/simulate') return {ok:true, json: async () => simResp};
  if(u === '/api/deletion/execute') return {ok: execResp.ok !== false, status: execResp.status || 200, json: async () => execResp.body};
  if(u === '/api/deletion/simulate-batch') return {ok:true, json: async () => batchSim};
  if(u === '/api/deletion/execute-batch') return {ok: batchExec.ok !== false, status: batchExec.status || 200, json: async () => batchExec.body};
  if(u.startsWith('/api/deletion/job/')) { const j = jobs.shift(); return {ok:true, json: async () => j}; }
  if(u === '/api/deletion/users') return {ok:true, json: async () => ({users:[]})};
  return {ok:true, json: async () => ({})};
};
const f = new Function('document','window','navigator','alert','fetch','confirm', src.replace(/document\.addEventListener\("DOMContentLoaded"[\s\S]*?\}\);\s*\n/, '') + `
return {simulateBatch, executeBatch, onDelBatchInput, toggleDeletionSelect, toggleSelectAllDeletion, pollDeletionJob, getSel:()=>delSelected, setUsers:u=>{cachedDeleteUsers=u}, simulateDeletion, executeDeletion, onDelConfirmInput, setRole:r=>{currentUserRole=r}, getPlan:()=>delPlan};`);
const base = {account:{name:'<b>A</b>', sam:'aalt', dn:'CN=a', groups:[]}, simulatedAt:'t', summary:{folders:1, files:2, size:10, allDeletable:true}, warnings:[], targets:[{label:'Profil', path:'\\\\fs\\p$\\aalt.V2', source:'Basispfad', status:'found', files:2, dirs:0, size:10, warnings:[], message:'Vorhanden.'}], blockers:[]};
(async () => {
  const api = f(doc, {}, {language:'de'}, m => alerts.push(m), fetchStub, m => { confirms++; return confirmAnswer; });
  api.setRole('Administrator');
  simResp = Object.assign({}, base, {planId:'P1', planExpiresAt:'2026-10-15T21:30:00+00:00'});
  await api.simulateDeletion('CN=a');
  let h = els['del-sim-result'].innerHTML;
  console.assert(h.includes('del-confirm-sam') && h.includes('disabled') && h.includes('Endgültig löschen') && !h.includes('<b>A</b>'), 'Loeschbox sichtbar, escaped');
  console.assert(api.getPlan().planId === 'P1', 'Plan gemerkt');
  // Button erst nach korrekter Eingabe aktiv
  els['del-confirm-sam'] = Object.assign(el('del-confirm-sam'), {value:'falsch'}); els['del-exec-btn'] = el('del-exec-btn');
  api.onDelConfirmInput(); console.assert(els['del-exec-btn'].disabled === true, 'gesperrt');
  els['del-confirm-pw'] = el('del-confirm-pw');
  els['del-confirm-sam'].value = ' AALT '; api.onDelConfirmInput(); console.assert(els['del-exec-btn'].disabled === true, 'ohne Passwort gesperrt');
  els['del-confirm-pw'].value = 'geheim'; api.onDelConfirmInput(); console.assert(els['del-exec-btn'].disabled === false, 'frei bei Treffer + Passwort');
  // falsche Eingabe -> kein Request
  els['del-confirm-sam'].value = 'x'; calls.length = 0; await api.executeDeletion();
  console.assert(calls.length === 0 && alerts.length === 1, 'kein Request bei falscher Bestaetigung');
  // Abbruch im Confirm-Dialog -> kein Request, Plan bleibt
  els['del-confirm-sam'].value = 'aalt'; confirmAnswer = false; await api.executeDeletion();
  console.assert(calls.length === 0 && confirms === 1 && api.getPlan(), 'Abbruch ohne Request');
  // Erfolg
  confirmAnswer = true;
  execResp = {body:{status:'success', accountDeleted:true, message:'Konto aalt und 1 Ordner wurden gelöscht.', results:[{kind:'profile', label:'Profil', path:'\\\\fs\\p$\\aalt.V2', status:'deleted', files:2, dirs:1, links:1, takeovers:2, errors:[], errorCount:0}]}};
  await api.executeDeletion();
  const body = JSON.parse(calls.find(c => c[0] === '/api/deletion/execute')[1]);
  console.assert(body.userDn === 'CN=a' && body.planId === 'P1' && body.confirmSam === 'aalt' && body.password === 'geheim', 'Payload ' + JSON.stringify(body));
  h = els['del-sim-result'].innerHTML;
  console.assert(h.includes('wurden gelöscht') && h.includes('Gelöscht') && api.getPlan() === null, 'Erfolgsanzeige, Plan verbraucht');
  console.assert(h.includes('1 Verknüpfung') && h.includes('Besitz übernommen: 2'), 'Links und Besitzuebernahme angezeigt');
  console.assert(calls.some(c => c[0] === '/api/deletion/users'), 'Liste neu geladen');
  // Teilweise
  simResp = Object.assign({}, base, {planId:'P2', planExpiresAt:null});
  await api.simulateDeletion('CN=a'); els['del-confirm-sam'].value = 'aalt';
  execResp = {body:{status:'partial', accountDeleted:false, message:'Nicht alle Ordner konnten gelöscht werden. Das AD-Konto wurde NICHT gelöscht.', results:[{kind:'profile', label:'Profil', path:'p', status:'failed', files:1, dirs:0, errors:['p\\\\x: <img src=x>', 'b'], errorCount:5}]}};
  await api.executeDeletion();
  h = els['del-sim-result'].innerHTML;
  console.assert(h.includes('NICHT gelöscht') && h.includes('Fehlgeschlagen') && h.includes('3 weitere') && !h.includes('<img') && h.includes('&lt;img'), 'Teilfehler-Anzeige');
  // Server-Fehler
  simResp = Object.assign({}, base, {planId:'P3'});
  await api.simulateDeletion('CN=a'); els['del-confirm-sam'].value = 'aalt';
  execResp = {ok:false, body:{detail:'Seit der Simulation hat sich etwas geändert <x>'}};
  await api.executeDeletion();
  h = els['del-sim-result'].innerHTML;
  console.assert(h.includes('nicht (vollständig) gelöscht') && h.includes('&lt;x&gt;'), 'Fehleranzeige');
  // Blocker
  simResp = Object.assign({}, base, {planId:null, blockers:['Profil \\\\fs\\p$\\aalt.V2: Verknüpfung <b>']});
  await api.simulateDeletion('CN=a');
  h = els['del-sim-result'].innerHTML;
  console.assert(h.includes('Löschen nicht möglich') && !h.includes('del-exec-btn') && h.includes('&lt;b&gt;') && api.getPlan() === null, 'Blocker statt Loeschbox');
  // Operator
  api.setRole('Account Operator'); simResp = Object.assign({}, base, {planId:'P9'});
  await api.simulateDeletion('CN=a');   // simuliert Server-Antwort; Ausfuehren muss clientseitig trotzdem blocken
  calls.length = 0; els['del-confirm-sam'].value = 'aalt'; await api.executeDeletion();
  console.assert(calls.length === 0, 'Operator: kein Execute-Request');
  api.setRole('Administrator');
  // ---- Passwort falsch im Einzelablauf: Formular bleibt, Plan bleibt
  simResp = Object.assign({}, base, {planId:'P9', planExpiresAt:null});
  await api.simulateDeletion('CN=a'); els['del-confirm-sam'].value = 'aalt'; els['del-confirm-pw'].value = 'falsch';
  confirmAnswer = true; alerts.length = 0;
  execResp = {ok:false, status:403, body:{detail:'Das Passwort ist falsch.'}};
  const fetchBak = fetchStub;
  await api.executeDeletion();
  console.assert(alerts.some(a => a.includes('Passwort')) && api.getPlan() && api.getPlan().planId === 'P9' && els['del-sim-result'].innerHTML.includes('del-confirm-pw'), 'Falsches Passwort: Plan und Formular bleiben');

  // ---- Auswahl
  const users = [1,2,3,4].map(i => ({dn:'CN=u'+i, name:'U'+i, sam:'u'+i, disabled:true, self:false})).concat([{dn:'CN=act', name:'A', sam:'act', disabled:false, self:false}]);
  api.setUsers(users);
  api.toggleDeletionSelect('CN=u1', true); api.toggleDeletionSelect('CN=u2', true);
  console.assert(api.getSel().size === 2 && els['del-sel-count'].textContent === 2 && els['del-batch-sim-btn'].disabled === false, 'Auswahl zaehlt');
  api.toggleDeletionSelect('CN=u2', false); console.assert(api.getSel().size === 1, 'abwaehlen');
  els['del-search'] = el('del-search'); els['del-search'].value = '';
  api.toggleSelectAllDeletion(true);
  console.assert(api.getSel().size === 4 && !api.getSel().has('CN=act'), 'Alle: nur deaktivierte');
  api.toggleSelectAllDeletion(false); console.assert(api.getSel().size === 0 && els['del-batch-sim-btn'].disabled === true, 'Alle abwaehlen');
  const many = Array.from({length: 30}, (_, i) => ({dn:'CN=m'+i, name:'M'+i, sam:'m'+i, disabled:true, self:false}));
  api.setUsers(many); alerts.length = 0; api.toggleSelectAllDeletion(true);
  console.assert(api.getSel().size === 25 && alerts.length === 1, 'Obergrenze 25');
  api.toggleSelectAllDeletion(false);

  // ---- Sammel-Simulation + Ausfuehrung
  api.setUsers(users); api.toggleDeletionSelect('CN=u1', true); api.toggleDeletionSelect('CN=u2', true); api.toggleDeletionSelect('CN=u3', true);
  const tgt = [{label:'Profil', path:'\\\\fs\\p$\\x', source:'Basispfad', status:'found', files:2, dirs:0, size:10, warnings:[], message:'Vorhanden.'}];
  batchSim = {items:[
    {dn:'CN=u1', state:'ready', name:'<i>U1</i>', sam:'u1', summary:{folders:1, files:2, size:10, takeovers:1, links:0}, warnings:[], targets:tgt, account:{}},
    {dn:'CN=u2', state:'ready', name:'U2', sam:'u2', summary:{folders:1, files:2, size:10, takeovers:0, links:0}, warnings:[], targets:tgt, account:{}},
    {dn:'CN=u3', state:'blocked', name:'U3', sam:'u3', error:'Nicht löschbar <b>', blockers:['x'], targets:tgt}],
    readyCount:2, planId:'B1', planExpiresAt:null};
  calls.length = 0; try { await api.simulateBatch(); } catch(e) { console.log('ERR', e.message); }
  h = els['del-sim-result'].innerHTML;
  console.assert(h.includes('2 von 3 Konten sind bereit') && h.includes('Blockiert') && h.includes('Bereit') && !h.includes('<i>U1</i>') && !h.includes('<b>') && h.includes('del-batch-pw') && h.includes('Anzahl eintippen: 2'), 'Sammel-Render, escaped');
  els['del-batch-count'] = el('del-batch-count'); els['del-batch-pw'] = el('del-batch-pw'); els['del-batch-btn'] = el('del-batch-btn');
  els['del-batch-count'].value = '3'; els['del-batch-pw'].value = 'pw'; api.onDelBatchInput();
  console.assert(els['del-batch-btn'].disabled === true, 'falsche Anzahl sperrt');
  els['del-batch-count'].value = '2'; els['del-batch-pw'].value = ''; api.onDelBatchInput();
  console.assert(els['del-batch-btn'].disabled === true, 'ohne Passwort gesperrt');
  els['del-batch-pw'].value = 'pw'; api.onDelBatchInput();
  console.assert(els['del-batch-btn'].disabled === false, 'frei bei Anzahl + Passwort');
  // falsches Passwort -> Formular bleibt, Plan weiter nutzbar
  batchExec = {ok:false, status:403, body:{detail:'Das Passwort ist falsch.'}}; alerts.length = 0; calls.length = 0;
  await api.executeBatch();
  const sent = JSON.parse(calls.find(c => c[0] === '/api/deletion/execute-batch')[1]);
  console.assert(sent.planId === 'B1' && sent.confirmCount === 2 && sent.password === 'pw', 'Batch-Payload');
  console.assert(alerts.some(a => a.includes('Passwort')) && els['del-sim-result'].innerHTML.includes('del-batch-pw'), 'Batch: falsches Passwort laesst Formular stehen');
  // Erfolg -> Polling bis fertig
  batchExec = {ok:true, body:{status:'started', jobId:'J1', total:2}};
  const item = (sam, status, extra) => Object.assign({dn:'CN='+sam, sam, name:'N '+sam, status, message:'', results:[]}, extra || {});
  jobs = [
    {total:2, done:0, current:'u1', finished:false, items:[item('u1','running'), item('u2','pending')]},
    {total:2, done:2, current:'', finished:true, items:[item('u1','success',{results:[{status:'deleted', files:2, takeovers:1, errors:[]}]}), item('u2','partial',{message:'Teilweise', results:[{status:'failed', files:1, takeovers:0, errors:['x <u>']}]})]}];
  const realSetTimeout = global.setTimeout; global.setTimeout = (fn) => { fn(); return 1; };
  await api.executeBatch(); await new Promise(r => realSetTimeout(r, 50));
  global.setTimeout = realSetTimeout;
  h = els['del-sim-result'].innerHTML;
  console.assert(h.includes('1 von 2 Konten gelöscht') && h.includes('Gelöscht') && h.includes('Unvollständig') && h.includes('Besitz übernommen: 1') && !h.includes('<u>') && jobs.length === 0, 'Job-Endanzeige ' + h.slice(0, 200));
  console.assert(api.getSel().size === 0, 'Auswahl nach dem Start geleert');
  console.log('Execute-UI-Tests fertig');
})();
