const src = require('./load_script.js');
const els = {};
const el = id => els[id] || (els[id] = {id, innerHTML:'', textContent:'', value:'', checked:false, disabled:false, required:false, focus(){}, classList:{_h:false, add(c){ if(c==='hidden') this._h=true; }, remove(c){ if(c==='hidden') this._h=false; }, toggle(c, on){ if(c==='hidden') this._h=!!on; }}, style:{}});
const doc = {getElementById: el, querySelectorAll: () => [], addEventListener(){}};
let exResp = {ok:true, body:{enabled:true, server:'exch01', port:8443, ssl:false, verifyCert:false, auth:'ntlm', database:'DB1', domainController:'dc1'}}, testResp = {ok:true, body:{message:'Verbindung steht.'}};
let calls = [], alerts = [], cfgResp = {mailMode:'required'}, detectResp = {};
const fetchStub = async (u, o) => {
  calls.push([u, o && o.body]);
  if(u === '/api/onboarding-config/detect') return {ok:true, json: async () => detectResp};
  if(u === '/api/exchange-config' && !o) return {ok:true, json: async () => exResp.body};
  if(u === '/api/exchange-config' && o) return {ok:true, json: async () => ({status:'success'})};
  if(u === '/api/exchange-config/test') return {ok: testResp.ok, json: async () => testResp.body};
  if(u === '/api/onboard') return {ok:true, json: async () => ({samAccountName:'hm', upn:'hm@x', mail:'', generatedPassword:'pw', warnings:[]})};
  return {ok:true, json: async () => ({})};
};
const f = new Function('document','window','navigator','alert','fetch','confirm', src.replace(/document\.addEventListener\("DOMContentLoaded"[\s\S]*?\}\);\s*\n/, '') + `
return {applyMailMode, currentMailMode, submitOnboard, setRole:r=>{currentUserRole=r}, setTemplates:t=>{templates=t}, loadMailDetect, saveExchangeConfig, testExchangeConfig, loadExchangeConfig, stubRefresh:fn=>{refreshAllLdapData=fn}};`);
(async () => {
  const api = f(doc, {}, {language:'de'}, m => alerts.push(m), fetchStub, () => true);
  api.stubRefresh(async () => {});
  const tpls = [{id:1, name:'Mailserver', mailMode:'required'}, {id:2, name:'Optional', mailMode:'optional'}, {id:3, name:'Exchange', mailMode:'exchange'}, {id:4, name:'365', mailMode:'cloud'}, {id:5, name:'Alt'}];
  api.setTemplates(tpls);
  el('hire-fn').value = 'Hans'; el('hire-ln').value = 'Meier';
  const pick = id => { el('hire-template').value = String(id); api.applyMailMode(); };
  pick(1);
  console.assert(api.currentMailMode() === 'required' && el('hire-mail').required === true && el('hire-mail-box').classList._h === false && el('lbl-mail-onboard').textContent.includes('*'), 'Mailserver: Pflichtfeld');
  calls.length = 0; await api.submitOnboard();
  console.assert(!calls.some(c => c[0] === '/api/onboard') && alerts.length === 1, 'Pflicht: ohne E-Mail kein Request');
  pick(2);
  console.assert(el('hire-mail').required === false && el('lbl-mail-onboard').textContent.includes('optional') && el('hire-mail-box').classList._h === false, 'Optional');
  calls.length = 0; await api.submitOnboard();
  let body = JSON.parse(calls.find(c => c[0] === '/api/onboard')[1]);
  console.assert(body.customMail === '' && body.firstName === 'Hans' && body.templateId === 2, 'Optional: Request ohne E-Mail erlaubt');
  el('hire-mail').value = 'x@y.de'; pick(3);
  console.assert(el('hire-mail-box').classList._h === true && el('hire-mail').value === '', 'Exchange: Feld versteckt und geleert');
  el('hire-mail').value = 'versteckt@y.de'; calls.length = 0; await api.submitOnboard();
  body = JSON.parse(calls.find(c => c[0] === '/api/onboard')[1]);
  console.assert(body.customMail === '' && body.templateId === 3, 'Exchange: keine E-Mail gesendet');
  pick(4);
  console.assert(el('hire-mail-box').classList._h === true, '365: Feld versteckt');
  pick(5);
  console.assert(api.currentMailMode() === 'required' && el('hire-mail-box').classList._h === false, 'Template ohne Angabe -> Pflicht');
  // Wechsel zurueck blendet das Feld wieder ein
  pick(3); pick(1);
  console.assert(el('hire-mail-box').classList._h === false && el('hire-mail').required === true, 'Zurueckwechseln zeigt das Feld wieder');
  // Hinweis (Erkennung) im Template-Dialog
  detectResp = {exchange:true, entra:false}; await api.loadMailDetect();
  console.assert(els['tpl-mail-detect'].textContent.includes('Exchange'), 'Hinweis Exchange');
  detectResp = {exchange:false, entra:false}; await api.loadMailDetect();
  console.assert(els['tpl-mail-detect'].textContent.includes('Eigener Mailserver'), 'Hinweis nichts erkannt');
  detectResp = {exchange:null, entra:null}; await api.loadMailDetect();
  console.assert(els['tpl-mail-detect'].textContent.includes('nicht möglich'), 'Hinweis unbekannt');
  // Exchange-Einstellungen
  api.setRole('Administrator'); await api.loadExchangeConfig();
  console.assert(els['ex-enabled'].checked === true && els['ex-server'].value === 'exch01' && els['ex-port'].value === 8443 && els['ex-ssl'].checked === false && els['ex-auth'].value === 'ntlm', 'Exchange-Formular gefuellt');
  console.assert(els['ex-status'].textContent.includes('Zertifikatsprüfung ist ausgeschaltet'), 'Warnung bei ausgeschalteter Pruefung');
  els['ex-server'].value = ' exch02 '; els['ex-port'].value = '443'; calls.length = 0; await api.saveExchangeConfig();
  let sent = JSON.parse(calls.find(c => c[0] === '/api/exchange-config' && c[1])[1]);
  console.assert(sent.server === 'exch02' && sent.port === 443 && sent.enabled === true && sent.auth === 'ntlm' && sent.verifyCert === false, 'Speichern sendet bereinigte Werte ' + JSON.stringify(sent));
  calls.length = 0; await api.testExchangeConfig();
  console.assert(calls.some(c => c[0] === '/api/exchange-config/test') && els['ex-status'].textContent === 'Verbindung steht.', 'Test zeigt Meldung');
  testResp = {ok:false, body:{detail:'Server nicht erreichbar.'}}; await api.testExchangeConfig();
  console.assert(els['ex-status'].textContent === 'Server nicht erreichbar.', 'Test zeigt Fehler');
  api.setRole('Account Operator'); calls.length = 0; await api.saveExchangeConfig();
  console.assert(!calls.length, 'Operator kann nicht speichern');
  console.log('Onboarding-Mail-UI-Tests fertig');
})();
