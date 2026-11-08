// The user sees that something is happening: progress bar for every request, busy sign-in button,
// page lists start at once, the AD structure is requested only in the parts a page needs
const src = require('./load_script.js');
const els = {};
const mkClass = () => { const set = new Set(); return {add: c => set.add(c), remove: c => set.delete(c), toggle: (c, on) => { const w = on === undefined ? !set.has(c) : !!on; if (w) set.add(c); else set.delete(c); return w; }, contains: c => set.has(c)}; };
const el = id => els[id] || (els[id] = {id, innerHTML: '', textContent: '', value: '', disabled: false, style: {}, attrs: {},
  setAttribute(k, v) { this.attrs[k] = v; }, getAttribute(k) { return this.attrs[k]; }, focus() {}, classList: mkClass()});
const doc = {getElementById: el, querySelectorAll: () => [], querySelector: () => null, addEventListener() {}, visibilityState: 'visible'};

// a window with a real-looking fetch whose answers we release by hand
const pending = [];
const win = {fetch: (url, init) => new Promise(resolve => pending.push({url, init, resolve}))};
const alerts = [];
const f = new Function('document', 'window', 'navigator', 'alert', 'fetch',
  src.replace(/document\.addEventListener\("DOMContentLoaded"[\s\S]*?\}\);\s*\n/, '') + `
return {apiBusy, infraQuery, performLogin, setLoginBusy, refreshAllLdapData, setTab: t => { currentTab = t; },
  stub: rec => { loadInfrastructure = async () => { rec('infra-start'); await new Promise(r => setTimeout(r, 40)); rec('infra-end'); };
    loadOffboardingUsers = async () => rec('list'); loadOffboardRecords = async () => {};
    ['loadTemplates', 'loadExchangeConfig', 'loadOffboardingConfig', 'loadPwdResetConfig', 'loadUserMgmtConfig', 'loadSmtpConfig',
     'loadDeletionConfig', 'loadReferenceCheck', 'loadHostNotices'].forEach(n => { eval(n + ' = async () => rec(n)'); }); },
  pending: () => apiPending};`);
// bare fetch() in the page means window.fetch - the same here
const api = f(doc, win, {language: 'de'}, m => alerts.push(m), (u, i) => win.fetch(u, i));
const tick = ms => new Promise(r => setTimeout(r, ms));

(async () => {
  // 1. progress bar: every /api request counts, shown only after 250 ms, gone when all answers are in
  const bar = el('api-progress');
  const p1 = window_fetch('/api/offboarding/users');
  const p2 = window_fetch('/api/dashboard');
  console.assert(api.pending() === 2 && !bar.classList.contains('is-on'), 'not shown at once');
  await tick(300);
  console.assert(bar.classList.contains('is-on') && bar.attrs['aria-hidden'] === 'false', 'shown after a short delay');
  pending.shift().resolve({ok: true});
  await tick(0);
  console.assert(bar.classList.contains('is-on'), 'still shown while one request is open');
  pending.shift().resolve({ok: true});
  await Promise.all([p1, p2]);
  console.assert(api.pending() === 0 && !bar.classList.contains('is-on') && bar.attrs['aria-hidden'] === 'true', 'hidden when done');
  // quick answers do not flicker
  const p3 = window_fetch('/api/templates');
  pending.shift().resolve({ok: true});
  await p3; await tick(300);
  console.assert(!bar.classList.contains('is-on'), 'quick answer: no bar');
  // the keep-alive ping and pages are not counted; errors count down too
  window_fetch('/api/me');
  console.assert(api.pending() === 0, 'keep-alive not counted');
  pending.shift().resolve({ok: true});
  const p4 = window_fetch('/api/people').catch(() => 'failed');
  pending.shift().resolve(Promise.reject(new Error('offline')));
  console.assert(await p4 === 'failed' && api.pending() === 0, 'failed request counted down');

  // 2. sign-in button shows that it is working, cannot be clicked twice, recovers on error
  el('login-user').value = 'it.admin'; el('login-pass').value = 'x';
  const login = api.performLogin();
  console.assert(el('btn-login').disabled && el('btn-login').innerHTML.includes('Anmeldung läuft') && !el('login-status').classList.contains('hidden'), 'busy while signing in');
  api.performLogin();  // second click
  console.assert(pending.filter(p => p.url === '/api/login').length === 1, 'no second sign-in request');
  pending.shift().resolve({ok: false, json: async () => ({detail: 'LDAP-Anmeldung fehlgeschlagen. Bitte Zugangsdaten prüfen.'})});
  await login;
  console.assert(!el('btn-login').disabled && el('btn-login').innerHTML.includes('Anmelden') && el('login-status').classList.contains('hidden'), 'button back after an error');
  console.assert(alerts.some(a => a.includes('Zugangsdaten')), 'error shown');
  const login2 = api.performLogin();
  pending.shift().resolve(Promise.reject(new Error('down')));
  await login2;
  console.assert(!el('btn-login').disabled && alerts.some(a => a.includes('nicht erreichbar')), 'server unreachable');

  // 3. AD structure in parts: OUs always, groups/users only where shown
  console.assert(api.infraQuery('templates') === '?gruppen=1&benutzer=1', 'templates: everything');
  console.assert(api.infraQuery('hire') === '?gruppen=1&benutzer=0', 'onboarding: groups');
  console.assert(api.infraQuery('offboard') === '?gruppen=0&benutzer=0', 'offboarding: only OUs');
  console.assert(api.infraQuery('usermgmt', true) === '?gruppen=0&benutzer=0&frisch=1', 'refresh reads fresh');

  // 4. the page's own list starts at once, not after the AD structure and settings
  const order = [];
  api.stub(n => order.push(n));
  api.setTab('offboard');
  await api.refreshAllLdapData();
  console.assert(order.indexOf('list') < order.indexOf('infra-end'), 'list before the AD structure is done: ' + order.slice(0, 4));
  console.assert(order.includes('loadOffboardingConfig') && order.indexOf('infra-end') < order.indexOf('loadOffboardingConfig'), 'OU settings after the AD structure');
  console.log('Feedback UI tests fertig');
})();

function window_fetch(url, init) { return win.fetch(url, init); }
