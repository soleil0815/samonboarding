// Offboarding rueckgaengig machen: Liste, Vorschau, OU-Wechsel, Ausfuehren
const src = require('./load_script.js');
const els = {};
const el = id => els[id] || (els[id] = {id, innerHTML: '', textContent: '', value: '', checked: false, disabled: false, focus() {},
  classList: {_h: true, add(c) { if (c === 'hidden') this._h = true; }, remove(c) { if (c === 'hidden') this._h = false; }, toggle() {}}, style: {}});
const doc = {getElementById: el, querySelectorAll: () => [], querySelector: () => null, addEventListener() {}};
let calls = [], alerts = [], confirms = 0, records = [], preview = {}, restoreResp = {ok: true, body: {}};
const fetchStub = async (u, o) => {
  calls.push([u, o && o.body]);
  if (u === '/api/offboarding/records') return {ok: true, json: async () => ({records})};
  if (u.includes('/preview')) return {ok: true, json: async () => preview};
  if (u.endsWith('/restore')) return {ok: restoreResp.ok, json: async () => restoreResp.body};
  if (u.endsWith('/dismiss')) return {ok: true, json: async () => ({status: 'success'})};
  return {ok: true, json: async () => ({})};
};
const f = new Function('document', 'window', 'navigator', 'alert', 'fetch', 'confirm', src.replace(/document\.addEventListener\("DOMContentLoaded"[\s\S]*?\}\);\s*\n/, '') + `
return {loadOffboardRecords, openRestore, executeRestore, onRestoreOuChange, dismissRecord, closeRestore, setRole: r => { currentUserRole = r; }, stubRefresh: fn => { refreshAllLdapData = fn; }};`);
(async () => {
  const api = f(doc, {}, {language: 'de'}, m => alerts.push(m), fetchStub, () => { confirms++; return true; });
  let refreshed = 0; api.stubRefresh(async () => { refreshed++; });
  // Liste
  await api.loadOffboardRecords();
  console.assert(els['off-restore-list'].innerHTML.includes('Keine offgeboardeten Konten') && els['off-restore-count'].textContent === '0 Konten', 'Leere Liste mit Hinweis');
  records = [{id: 3, sam: 'aberg', name: '<b>Anna</b>', originalOu: 'OU=Sales,DC=x', groups: ['VPN'], offboardedAt: '2026-10-16T10:00:00+00:00', offboardedBy: 'op'}];
  api.setRole('Account Operator'); await api.loadOffboardRecords();
  let h = els['off-restore-list'].innerHTML;
  console.assert(h.includes('openRestore(3)') && !h.includes('<b>Anna</b>') && !h.includes('dismissRecord'), 'Zeile escaped, Operator ohne Verwerfen');
  console.assert(els['off-restore-count'].textContent === '1 Konto', 'Zaehler');
  api.setRole('Administrator'); await api.loadOffboardRecords();
  console.assert(els['off-restore-list'].innerHTML.includes('dismissRecord(3)'), 'Admin kann verwerfen');
  // Vorschau ohne Hindernis
  preview = {id: 3, sam: 'aberg', name: 'Anna', offboardedAt: '2026-10-16T10:00:00+00:00', offboardedBy: 'op', originalOu: 'OU=Sales,DC=x', targetOu: 'OU=Sales,DC=x', ouOptions: ['OU=Staff,DC=x'], enable: true,
    groups: [{name: 'VPN', status: 'add'}, {name: 'Alt', status: 'missing'}], blockers: [], notes: ['Nicht mehr vorhanden: Alt']};
  await api.openRestore(3);
  h = els['restore-body'].innerHTML;
  console.assert(els['restore-modal'].classList._h === false && els['restore-exec-btn'].disabled === false, 'Dialog offen, Knopf frei');
  console.assert(h.includes('wird wieder zugewiesen') && h.includes('gibt es nicht mehr') && h.includes('wieder aktiviert') && h.includes('(vorher)'), 'Plan sichtbar');
  // OU wechseln -> neue Vorschau mit targetOu
  els['restore-ou'] = Object.assign(el('restore-ou'), {value: 'OU=Staff,DC=x'});
  calls.length = 0; await api.onRestoreOuChange();
  console.assert(calls.some(c => c[0] === '/api/offboarding/records/3/preview?targetOu=' + encodeURIComponent('OU=Staff,DC=x')), 'Vorschau mit gewaehlter OU');
  // Hindernis sperrt den Knopf
  preview = Object.assign({}, preview, {blockers: ['Die OU gibt es nicht mehr.']});
  await api.openRestore(3);
  console.assert(els['restore-exec-btn'].disabled === true && els['restore-body'].innerHTML.includes('gibt es nicht mehr'), 'Hindernis sperrt');
  calls.length = 0; await api.executeRestore();
  console.assert(!calls.some(c => c[0].endsWith('/restore')), 'Kein Request bei Hindernis');
  // Fehler vom Server: Dialog bleibt, Knopf wieder frei
  preview = Object.assign({}, preview, {blockers: [], targetOu: 'OU=Staff,DC=x'});
  await api.openRestore(3);
  restoreResp = {ok: false, body: {detail: 'Fehler beim Verschieben.'}};
  alerts.length = 0; await api.executeRestore();
  console.assert(alerts[0] === 'Fehler beim Verschieben.' && els['restore-modal'].classList._h === false && els['restore-exec-btn'].disabled === false, 'Fehler: Dialog bleibt');
  // Erfolg mit Hinweis
  restoreResp = {ok: true, body: {message: 'Anna wurde wiederhergestellt und ist wieder aktiv.', warnings: ['Nicht wieder zugewiesen: X']}};
  alerts.length = 0; calls.length = 0; await api.executeRestore();
  const body = JSON.parse(calls.find(c => c[0] === '/api/offboarding/records/3/restore')[1]);
  console.assert(body.targetOu === 'OU=Staff,DC=x', 'gewaehlte OU gesendet');
  console.assert(alerts[0].includes('wiederhergestellt') && alerts[0].includes('Nicht wieder zugewiesen') && els['restore-modal'].classList._h === true && refreshed === 1, 'Erfolg: Meldung, Dialog zu, neu geladen');
  // Verwerfen mit Rueckfrage
  calls.length = 0; await api.dismissRecord(3);
  console.assert(confirms === 1 && calls.some(c => c[0] === '/api/offboarding/records/3/dismiss'), 'Verwerfen mit Rueckfrage');
  console.log('Restore-UI-Tests fertig');
})();
