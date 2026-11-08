// Start page live: counters load first after sign-in and refresh themselves (fresh from the DC, nothing kept in the browser)
const src = require('./load_script.js');
const els = {};
const el = id => els[id] || (els[id] = {id, innerHTML: '', textContent: '', value: '', style: {}, attrs: {},
  setAttribute(k, v) { this.attrs[k] = v; }, getAttribute(k) { return this.attrs[k]; },
  classList: {set: new Set(), add(c) { this.set.add(c); }, remove(c) { this.set.delete(c); }, toggle(c, on) { if (on) this.set.add(c); else this.set.delete(c); }, contains(c) { return this.set.has(c); }}});
const doc = {getElementById: el, querySelectorAll: () => [], querySelector: () => null, addEventListener() {}, visibilityState: 'visible'};
const calls = [];
const fetch = async url => { calls.push(url); return {ok: true, json: async () => ({users: []})}; };
const store = {};
const ls = {getItem: k => store[k] ?? null, setItem: (k, v) => { store[k] = String(v); }, removeItem: k => { delete store[k]; }};
const f = new Function('document', 'window', 'navigator', 'alert', 'fetch', 'localStorage', 'sessionStorage',
  src.replace(/document\.addEventListener\("DOMContentLoaded"[\s\S]*?\}\);\s*\n/, '') + `
return {refreshAllLdapData, loadDashboard, dashAutoRefreshDue, dashAutoRefresh,
  setTab: t => { currentTab = t; }, setRole: r => { currentUserRole = r; }, setActivity: t => { lastActivity = t; },
  setVisible: v => { appVisible = () => v; },
  stub: rec => { loadInfrastructure = async () => { rec('infra-start'); await new Promise(r => setTimeout(r, 30)); rec('infra-end'); };
    ['loadTemplates', 'loadExchangeConfig', 'loadOffboardingConfig', 'loadPwdResetConfig', 'loadUserMgmtConfig', 'loadSmtpConfig',
     'loadDeletionConfig', 'loadReferenceCheck', 'loadHostNotices', 'loadUserMgmtUsers', 'loadOffboardingUsers', 'loadOffboardRecords',
     'loadPwdResetUsers', 'loadDeletionUsers'].forEach(n => { eval(n + ' = async () => rec(n)'); }); }};`);
const api = f(doc, {}, {language: 'de'}, () => {}, fetch, ls, ls);
const order = [];
api.stub(n => order.push(n));
api.setVisible(true);
el('palette').classList.add('hidden');

(async () => {
  // 1. after sign-in the start page counters are requested before OUs/groups/templates are loaded
  api.setRole('Administrator');
  api.setTab('start');
  await api.refreshAllLdapData();
  console.assert(calls.filter(u => u === '/api/dashboard').length === 1, 'numbers read once: ' + calls);
  console.assert(order.indexOf('infra-end') > 0, 'settings still loaded');
  console.assert(!order.includes('loadOffboardingUsers'), 'no second list load for the start page');
  console.assert(els['dash-asof'].textContent.startsWith('Stand ') && els['dash-asof'].textContent.endsWith('aktualisiert sich jede Minute'), 'as-of time shown');
  console.assert(els['dash-inactive'].attrs['aria-busy'] === 'false', 'busy state cleared');

  // the dashboard request went out before the slow infrastructure load finished
  calls.length = 0; order.length = 0;
  const marks = [];
  const origPush = calls.push.bind(calls);
  calls.push = u => { marks.push('fetch:' + u.split('?')[0]); return origPush(u); };
  order.push = n => { marks.push(n); return Array.prototype.push.call(order, n); };
  await api.refreshAllLdapData();
  console.assert(marks.indexOf('fetch:/api/dashboard') < marks.indexOf('infra-end'), 'counters start before settings finish: ' + marks.slice(0, 4));
  calls.push = origPush;

  // 2. other pages are unchanged: no start page lists
  calls.length = 0;
  api.setTab('hire');
  await api.refreshAllLdapData();
  console.assert(!calls.includes('/api/dashboard'), 'onboarding does not read the start page numbers');

  // 3. automatic refresh: only on the start page, app visible, tab visible, recently active, search closed
  const now = Date.now();
  api.setTab('start');
  api.setActivity(now - 60000);
  console.assert(api.dashAutoRefreshDue(now) === true, 'due on the start page');
  api.setTab('offboard');
  console.assert(api.dashAutoRefreshDue(now) === false, 'not on other pages');
  api.setTab('start');
  doc.visibilityState = 'hidden';
  console.assert(api.dashAutoRefreshDue(now) === false, 'not while the browser tab is hidden');
  doc.visibilityState = 'visible';
  api.setActivity(now - 11 * 60000);
  console.assert(api.dashAutoRefreshDue(now) === false, 'stops after 10 minutes without activity (session may expire)');
  api.setActivity(now - 1000);
  api.setVisible(false);
  console.assert(api.dashAutoRefreshDue(now) === false, 'not on the login screen');
  api.setVisible(true);
  el('palette').classList.remove('hidden');
  console.assert(api.dashAutoRefreshDue(now) === false, 'not while the quick search is open');
  el('palette').classList.add('hidden');

  // the refresh asks the DC (the endpoint is never cached)
  calls.length = 0;
  api.dashAutoRefresh();
  await new Promise(r => setTimeout(r, 10));
  console.assert(calls.length === 1 && calls[0] === '/api/dashboard', 'refresh: ' + calls);

  // overlapping refreshes do not double the requests
  calls.length = 0;
  await Promise.all([api.loadDashboard(true), api.loadDashboard(true)]);
  console.assert(calls.length === 1, 'no overlapping loads: ' + calls.length);

  // nothing is written to browser storage
  console.assert(!Object.keys(store).some(k => /dash|count|user/i.test(k)), 'no counters in browser storage: ' + Object.keys(store));
  console.log('Start page live UI tests fertig');
})();
