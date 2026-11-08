// Start page ("Was steht an?"): counters from the existing lists, menu badges, quick search (Ctrl+K)
const src = require('./load_script.js');
const els = {};
const mkClass = () => {
  const set = new Set();
  return {add: c => set.add(c), remove: c => set.delete(c), toggle: (c, on) => { const want = on === undefined ? !set.has(c) : !!on; if (want) set.add(c); else set.delete(c); return want; }, contains: c => set.has(c)};
};
const el = id => els[id] || (els[id] = {id, innerHTML: '', textContent: '', value: '', className: '', style: {}, attrs: {},
  setAttribute(k, v) { this.attrs[k] = v; }, getAttribute(k) { return this.attrs[k]; }, removeAttribute(k) { delete this.attrs[k]; },
  focus() {}, classList: mkClass()});
const listeners = {};
const doc = {getElementById: el, querySelectorAll: () => [], querySelector: () => null, addEventListener(type, fn) { listeners[type] = fn; }};
const day = 86400000;
const now = Date.parse('2026-11-08T10:00:00Z');
const iso = ms => new Date(now - ms).toISOString();
const replies = {};
const calls = [];
const fetch = async url => { calls.push(url); const r = replies[url.split('?')[0]]; return r ? {ok: true, json: async () => r} : {ok: false, json: async () => ({})}; };
const f = new Function('document', 'window', 'navigator', 'alert', 'fetch', 'confirm',
  src.replace(/document\.addEventListener\("DOMContentLoaded"[\s\S]*?\}\);\s*\n/, '') + `
return {dashboardCounts, greeting, mergePeople, filterPeople, loadDashboard, renderPalette, paletteKey, paletteChoose, openPalette,
  setRole: r => { currentUserRole = r; }, setMe: n => { currentLoggedInUsername = n; }, tab: () => currentTab, sort: () => offSort,
  openInactiveAccounts, stubTabs: () => { refreshAllLdapData = async () => {}; }, setVisible: v => { appVisible = () => v; }};`);
const api = f(doc, {}, {language: 'de'}, () => {}, fetch, () => true);
api.stubTabs();

// counting: active, not protected, not oneself, last logon older than 90 days or never
const off = [
  {dn: 'a', sam: 'a', name: 'Anna', disabled: false, lastLogon: iso(120 * day)},
  {dn: 'b', sam: 'b', name: 'Ben', disabled: false, lastLogon: null},
  {dn: 'c', sam: 'c', name: 'Carl', disabled: false, lastLogon: iso(10 * day)},
  {dn: 'd', sam: 'd', name: 'Dora', disabled: true, lastLogon: iso(400 * day)},
  {dn: 'e', sam: 'e', name: 'Emil', disabled: false, protected: 'Domänen-Admins', lastLogon: iso(400 * day)},
  {dn: 'm', sam: 'IT.Admin', name: 'Ich', disabled: false, lastLogon: null},
];
const pwd = [{dn: 'a', sam: 'a', name: 'Anna', locked: true}, {dn: 'x', sam: 'x', name: 'Xaver Moll', locked: false, mail: 'x.moll@firma.local'}];
const del = [{dn: 'd', sam: 'd', disabled: true}, {dn: 'm', sam: 'it.admin', disabled: true, self: true}, {dn: 'p', disabled: true, protected: 'x'}, {dn: 'q', disabled: false}];
const c = api.dashboardCounts(off, pwd, del, now, 'it.admin');
console.assert(c.inactive === 2 && c.never === 1, 'inactive: Anna (120 days) and Ben (never) ' + JSON.stringify(c));
console.assert(c.locked === 1, 'one locked account');
console.assert(c.deletable === 1, 'only disabled, not self, not protected');
console.assert(api.dashboardCounts(null, null, null, now, '').inactive === 0, 'missing lists count as zero');
console.assert(api.dashboardCounts([{sam: 'z', disabled: false, lastLogon: iso(90 * day - 1000)}], [], [], now, '').inactive === 0, 'just under 90 days is not inactive');

// greeting by hour
console.assert(api.greeting(8) === 'Guten Morgen' && api.greeting(14) === 'Guten Tag' && api.greeting(20) === 'Guten Abend' && api.greeting(2) === 'Guten Abend', 'greeting');

// people: one entry per account, management list wins
const people = api.mergePeople([['usermgmt', [{dn: 'a', sam: 'a', name: 'Anna'}]], ['offboard', off], ['pwdreset', pwd]]);
console.assert(people.length === 7 && people.find(p => p.dn === 'a').tab === 'usermgmt' && people.find(p => p.dn === 'b').tab === 'offboard'
  && people.find(p => p.dn === 'x').tab === 'pwdreset', 'merged by DN');
console.assert(api.filterPeople(people, '', 8).length === 0, 'empty query shows no people');
console.assert(api.filterPeople(people, 'moll', 8)[0].dn === 'x', 'surname word');
console.assert(api.filterPeople(people, 'firma.local', 8)[0].dn === 'x', 'mail');
console.assert(api.filterPeople(people, 'a', 8)[0].dn === 'a', 'exact login name first');
console.assert(api.filterPeople(people, 'e', 2).length === 2, 'limit');

(async () => {
  // dashboard for an administrator: counters and menu badges
  replies['/api/offboarding/users'] = {users: off};
  replies['/api/pwdreset/users'] = {users: pwd};
  replies['/api/deletion/users'] = {users: del};
  api.setRole('Administrator');
  api.setMe('it.admin');
  await api.loadDashboard(true);
  console.assert(calls.includes('/api/deletion/users?frisch=1'), 'Aktualisieren reads fresh');
  console.assert(els['dash-locked-num'].textContent === '1' && els['dash-delete-num'].textContent === '1', 'counters');
  console.assert(els['dash-inactive-num'].textContent === String(api.dashboardCounts(off, pwd, del, Date.now(), 'it.admin').inactive), 'inactive counter');
  console.assert(els['nav-badge-pwdreset'].textContent === '1' && !els['nav-badge-pwdreset'].classList.contains('hidden'), 'badge shown');
  console.assert(els['start-name'].textContent === ', it.admin', 'name in the greeting');

  // operator: the deletion list is not requested
  calls.length = 0;
  api.setRole('Account Operator');
  await api.loadDashboard(false);
  console.assert(!calls.some(u => u.startsWith('/api/deletion')), 'operators do not read the deletion list');
  console.assert(els['nav-badge-delete'].classList.contains('hidden'), 'no deletion badge for operators');

  // not configured: no number, a hint instead, no badge
  replies['/api/pwdreset/users'] = {users: [], warning: 'Keine Quell-OUs für Passwort-Reset konfiguriert.'};
  await api.loadDashboard(false);
  console.assert(els['dash-locked-num'].textContent === '–' && els['dash-locked-sub'].textContent.includes('Noch nicht eingerichtet'), 'not configured');
  console.assert(els['nav-badge-pwdreset'].classList.contains('hidden'), 'no badge when not configured');
  replies['/api/pwdreset/users'] = {users: pwd};
  await api.loadDashboard(false);

  // card "inactive": offboarding opens sorted oldest first
  await api.openInactiveAccounts();
  console.assert(api.tab() === 'offboard' && api.sort() === 'asc', 'offboarding, oldest first');

  // quick search: Ctrl+K opens, choosing a person opens the right page with the search filled in
  replies['/api/usermgmt/users'] = {users: [{dn: 'a', sam: 'a', name: 'Anna'}]};
  api.setVisible(true);
  el('palette').classList.add('hidden');
  let prevented = false;
  await listeners.keydown({ctrlKey: true, key: 'k', preventDefault() { prevented = true; }});
  await new Promise(r => setTimeout(r, 0));
  console.assert(prevented && !els.palette.classList.contains('hidden'), 'Ctrl+K opens the quick search');
  els['palette-input'].value = 'moll';
  api.renderPalette();
  console.assert(els['palette-list'].innerHTML.includes('Xaver Moll') && els['palette-list'].innerHTML.includes('Passwort zurücksetzen'), 'hit with target page');
  api.paletteKey({key: 'Enter', preventDefault() {}});
  await new Promise(r => setTimeout(r, 0));
  console.assert(api.tab() === 'pwdreset' && els['pwdreset-search'].value === 'x' && els.palette.classList.contains('hidden'), 'opens password reset filtered');

  // pages are found by name; hidden pages (operators) are not offered
  await api.openPalette();
  els['nav-reports'].style.display = 'none';
  els['nav-templates'].style.display = '';
  els['palette-input'].value = 'bericht';
  api.renderPalette();
  console.assert(!els['palette-list'].innerHTML.includes('Berichte'), 'hidden page not offered');
  els['palette-input'].value = 'templ';
  api.renderPalette();
  console.assert(els['palette-list'].innerHTML.includes('Templates'), 'page found');
  api.paletteKey({key: 'Escape', preventDefault() {}});
  console.assert(els.palette.classList.contains('hidden'), 'Esc closes');

  // on the login screen Ctrl+K does nothing
  api.setVisible(false);
  prevented = false;
  await listeners.keydown({ctrlKey: true, key: 'k', preventDefault() { prevented = true; }});
  console.assert(!prevented && els.palette.classList.contains('hidden'), 'login screen: no quick search');
  console.log('Start page UI tests fertig');
})();
