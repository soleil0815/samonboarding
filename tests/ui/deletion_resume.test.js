// Deletion as a server job: after reloading the page finds the running or finished deletion again; hide the result
const src = require('./load_script.js');
const els = {};
const el = id => els[id] || (els[id] = {id, innerHTML:'', textContent:'', value:'', checked:false, disabled:false, focus(){}, classList:{add(){},remove(){},toggle(){}}, style:{}});
const doc = {getElementById: el, querySelectorAll: () => [], addEventListener(){}};
let calls = [], jobsList = [], jobStates = [];
const fetchStub = async (u, o) => {
  calls.push([u, o && o.method]);
  if(u === '/api/deletion/jobs') return {ok:true, json: async () => ({jobs: jobsList})};
  if(u.startsWith('/api/deletion/job/') && u.endsWith('/dismiss')) return {ok:true, json: async () => ({status:'success'})};
  if(u.startsWith('/api/deletion/job/')) { const j = jobStates.shift(); return {ok:true, json: async () => j}; }
  if(u === '/api/deletion/users') return {ok:true, json: async () => ({users:[]})};
  return {ok:true, json: async () => ({})};
};
const f = new Function('document','window','navigator','alert','fetch','confirm', src.replace(/document\.addEventListener\("DOMContentLoaded"[\s\S]*?\}\);\s*\n/, '') + `
return {resumeDeletionJob, dismissDeletionJob, setRole:r=>{currentUserRole=r}, setPlan:p=>{delPlan=p}};`);
(async () => {
  const api = f(doc, {}, {language:'de'}, () => {}, fetchStub, () => true);
  const st0 = global.setTimeout; const ticks = [];
  global.setTimeout = fn => { ticks.push(fn); return 1; };
  api.setRole('Administrator');
  const job = (finished, extra) => Object.assign({id:'J9', kind:'single', total:1, done: finished ? 1 : 0, finished,
    items:[{dn:'CN=a', sam:'aalt', name:'<b>Anna</b>', status: finished ? 'success' : 'running', message: finished ? 'Konto aalt wurde gelöscht.' : '', results:[]}]}, extra || {});
  // nothing running: nothing shown
  jobsList = []; await api.resumeDeletionJob();
  console.assert(els['del-sim-result'].innerHTML === '', 'nichts anzuzeigen');
  // a running deletion is found again after reloading - and polled until it is finished
  jobsList = [job(false)]; jobStates = [job(false), job(true)];
  await api.resumeDeletionJob(); await new Promise(r => st0(r, 20));
  let h = els['del-sim-result'].innerHTML;
  console.assert(h.includes('Löschvorgang läuft auf dem Server') && h.includes('&lt;b&gt;Anna') && !h.includes('<b>Anna'), 'laufend wiedergefunden ' + h.slice(0, 120));
  while(ticks.length) { ticks.shift()(); await new Promise(r => st0(r, 20)); }
  h = els['del-sim-result'].innerHTML;
  console.assert(h.includes('wurde gelöscht') && h.includes('Ergebnis ausblenden'), 'Ergebnis + Ausblenden ' + h.slice(0, 160));
  // hide: the server is told, the box is empty
  calls.length = 0; await api.dismissDeletionJob('J9');
  console.assert(calls.some(c => c[0] === '/api/deletion/job/J9/dismiss' && c[1] === 'POST') && els['del-sim-result'].innerHTML === '', 'ausgeblendet');
  // a simulation on screen is never replaced
  els['del-sim-result'].innerHTML = '<div>Simulation</div>'; calls.length = 0; jobsList = [job(true)];
  await api.resumeDeletionJob();
  console.assert(calls.length === 0 && els['del-sim-result'].innerHTML === '<div>Simulation</div>', 'Simulation bleibt stehen');
  // operators never ask
  els['del-sim-result'].innerHTML = ''; api.setRole('Account Operator'); calls.length = 0;
  await api.resumeDeletionJob();
  console.assert(calls.length === 0, 'Operator fragt nicht');
  global.setTimeout = st0;
  console.log('Wiederfinden-Tests fertig');
})();
