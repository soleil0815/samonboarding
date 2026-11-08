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
return {greeting, mergePeople, filterPeople, loadDashboard, renderPalette, paletteKey, paletteChoose, openPalette,
  setRole: r => { currentUserRole = r; }, setMe: n => { currentLoggedInUsername = n; }, tab: () => currentTab, sort: () => offSort,
  openInactiveAccounts, stubTabs: () => { refreshAllLdapData = async () => {}; }, setVisible: v => { appVisible = () => v; }};`);
const api = f(doc, {}, {language: 'de'}, () => {}, fetch, () => true);
api.stubTabs();

// lists for the quick search
const off = [
  {dn: 'a', sam: 'a', name: 'Anna', disabled: false, lastLogon: iso(120 * day)},
  {dn: 'b', sam: 'b', name: 'Ben', disabled: false, lastLogon: null},
  {dn: 'c', sam: 'c', name: 'Carl', disabled: false, lastLogon: iso(10 * day)},
  {dn: 'd', sam: 'd', name: 'Dora', disabled: true, lastLogon: iso(400 * day)},
  {dn: 'e', sam: 'e', name: 'Emil', disabled: false, protected: 'Domänen-Admins', lastLogon: iso(400 * day)},
  {dn: 'm', sam: 'IT.Admin', name: 'Ich', disabled: false, lastLogon: null},
];
const pwd = [{dn: 'a', sam: 'a', name: 'Anna', locked: true}, {dn: 'x', sam: 'x', name: 'Xaver Moll', locked: false, mail: 'x.moll@firma.local'}];

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
  // dashboard for an administrator: only numbers from /api/dashboard, never lists
  replies['/api/dashboard'] = {status: 'success', inactive: {count: 2, never: 1}, locked: {count: 1}, deletion: {count: 3}};
  api.setRole('Administrator');
  api.setMe('it.admin');
  await api.loadDashboard(true);
  console.assert(calls.length === 1 && calls[0] === '/api/dashboard', 'one request for the numbers: ' + calls);
  console.assert(els['dash-inactive-num'].textContent === '2' && els['dash-inactive-sub'].textContent === 'davon 1 nie angemeldet', 'inactive counter');
  console.assert(els['dash-locked-num'].textContent === '1' && els['dash-delete-num'].textContent === '3', 'counters');
  console.assert(els['nav-badge-pwdreset'].textContent === '1' && !els['nav-badge-pwdreset'].classList.contains('hidden'), 'badge shown');
  console.assert(els['nav-badge-delete'].textContent === '3', 'deletion badge');
  console.assert(els['start-name'].textContent === ', it.admin', 'name in the greeting');

  // zero: calm card, no badge
  replies['/api/dashboard'] = {status: 'success', inactive: {count: 0, never: 0}, locked: {count: 0}, deletion: null};
  api.setRole('Account Operator');
  await api.loadDashboard(false);
  console.assert(els['dash-locked-sub'].textContent === 'Alles in Ordnung' && els['nav-badge-pwdreset'].classList.contains('hidden'), 'nothing locked');
  console.assert(els['nav-badge-delete'].classList.contains('hidden'), 'no deletion badge for operators');

  // not configured / not readable / DC unreachable: no number, no badge, never a false "0"
  replies['/api/dashboard'] = {status: 'success', inactive: {error: 'Liste nicht lesbar'}, locked: {warning: 'Keine Quell-OUs für Passwort-Reset konfiguriert.'}, deletion: null};
  await api.loadDashboard(false);
  console.assert(els['dash-locked-num'].textContent === '–' && els['dash-locked-sub'].textContent.includes('Noch nicht eingerichtet'), 'not configured');
  console.assert(els['dash-inactive-num'].textContent === '–' && els['dash-inactive-sub'].textContent === 'Liste nicht lesbar', 'not readable');
  console.assert(els['nav-badge-offboard'].classList.contains('hidden'), 'no badge without a number');
  delete replies['/api/dashboard'];
  await api.loadDashboard(false);
  console.assert(els['dash-locked-num'].textContent === '–' && els['dash-asof'].textContent.includes('nicht erreichbar'), 'DC unreachable');
  api.setRole('Administrator');

  // card "inactive": offboarding opens sorted oldest first
  await api.openInactiveAccounts();
  console.assert(api.tab() === 'offboard' && api.sort() === 'asc', 'offboarding, oldest first');

  // quick search: Ctrl+K opens, choosing a person opens the right page with the search filled in
  replies['/api/usermgmt/users'] = {users: [{dn: 'a', sam: 'a', name: 'Anna'}]};
  replies['/api/offboarding/users'] = {users: off};
  replies['/api/pwdreset/users'] = {users: pwd};
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
