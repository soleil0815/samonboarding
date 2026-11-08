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
const bodies = [];
const fetch = async (url, opts) => {
  calls.push(url);
  if (opts && opts.body) bodies.push([url, opts.method, JSON.parse(opts.body)]);
  const r = typeof replies[url.split('?')[0]] === 'function' ? replies[url.split('?')[0]](opts) : replies[url.split('?')[0]];
  return r ? {ok: true, json: async () => r} : {ok: false, json: async () => ({})};
};
const f = new Function('document', 'window', 'navigator', 'alert', 'fetch', 'confirm',
  src.replace(/document\.addEventListener\("DOMContentLoaded"[\s\S]*?\}\);\s*\n/, '') + `
return {greeting, loadDashboard, renderPalette, paletteInput, paletteKey, paletteChoose, openPalette,
  setRole: r => { currentUserRole = r; }, setMe: n => { currentLoggedInUsername = n; }, tab: () => currentTab, sort: () => offSort,
  openInactiveAccounts, stubTabs: () => { refreshAllLdapData = async () => {}; }, setVisible: v => { appVisible = () => v; }};`);
const api = f(doc, {}, {language: 'de'}, () => {}, fetch, () => true);
api.stubTabs();

// greeting by hour
console.assert(api.greeting(8) === 'Guten Morgen' && api.greeting(14) === 'Guten Tag' && api.greeting(20) === 'Guten Abend' && api.greeting(2) === 'Guten Abend', 'greeting');

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
  // the DC searches: the browser sends the text by POST and gets at most a few hits
  replies['/api/people'] = opts => {
    const q = JSON.parse(opts.body).q.toLowerCase();
    const all = [{dn: 'x', sam: 'x', name: 'Xaver Moll', mail: 'x.moll@firma.local', disabled: false, tab: 'pwdreset'},
                 {dn: 'a', sam: 'a', name: 'Anna', mail: '', disabled: false, tab: 'usermgmt'}];
    return {status: 'success', people: all.filter(p => (p.name + ' ' + p.mail).toLowerCase().includes(q))};
  };
  api.setVisible(true);
  el('palette').classList.add('hidden');
  let prevented = false;
  await listeners.keydown({ctrlKey: true, key: 'k', preventDefault() { prevented = true; }});
  await new Promise(r => setTimeout(r, 0));
  console.assert(prevented && !els.palette.classList.contains('hidden'), 'Ctrl+K opens the quick search');
  calls.length = 0; bodies.length = 0;
  els['palette-input'].value = 'm';
  api.paletteInput();
  await new Promise(r => setTimeout(r, 300));
  console.assert(!calls.includes('/api/people'), 'one character: no search');
  for (const typed of ['mo', 'mol', 'moll']) { els['palette-input'].value = typed; api.paletteInput(); }
  console.assert(els['palette-list'].innerHTML.includes('Suche im AD'), 'searching hint');
  await new Promise(r => setTimeout(r, 300));
  console.assert(calls.filter(u => u === '/api/people').length === 1, 'typing quickly: one search only');
  console.assert(bodies.length === 1 && bodies[0][1] === 'POST' && bodies[0][2].q === 'moll' && !calls.some(u => u.includes('moll')), 'search text in the body, never in the URL');
  console.assert(els['palette-list'].innerHTML.includes('Xaver Moll') && els['palette-list'].innerHTML.includes('Passwort zurücksetzen'), 'hit with target page');
  api.paletteKey({key: 'Enter', preventDefault() {}});
  await new Promise(r => setTimeout(r, 0));
  console.assert(api.tab() === 'pwdreset' && els['pwdreset-search'].value === 'x' && els.palette.classList.contains('hidden'), 'opens password reset filtered');

  // an answer that arrives after the text changed is ignored
  await api.openPalette();
  let releaseOld = null;
  replies['/api/people'] = opts => {
    const q = JSON.parse(opts.body).q;
    if (q === 've') return new Promise(r => { releaseOld = () => r({status: 'success', people: [{dn: 'old', sam: 'old', name: 'Veraltet', mail: '', tab: 'usermgmt'}]}); });
    return {status: 'success', people: [{dn: 'x', sam: 'x', name: 'Xaver Moll', mail: '', tab: 'pwdreset'}]};
  };
  els['palette-input'].value = 've';
  api.paletteInput();
  await new Promise(r => setTimeout(r, 300));  // first search sent, answer still outstanding
  els['palette-input'].value = 'xav';
  api.paletteInput();
  await new Promise(r => setTimeout(r, 300));
  releaseOld();
  await new Promise(r => setTimeout(r, 10));
  console.assert(!els['palette-list'].innerHTML.includes('Veraltet') && els['palette-list'].innerHTML.includes('Xaver'), 'stale answer not shown');

  // closing forgets the hits
  api.paletteKey({key: 'Escape', preventDefault() {}});
  await api.openPalette();
  els['palette-input'].value = 'moll';
  api.renderPalette();
  console.assert(!els['palette-list'].innerHTML.includes('Xaver'), 'hits are not kept after closing');

  // pages are found by name; hidden pages (operators) are not offered
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
