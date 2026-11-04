// News: subtle dot only for a new version since last read (orange for security), the window marks it as read
const src = require('./load_script.js');
const els = {};
function mkEl(id) {
  const cls = new Set(['hidden']);
  return {id, innerHTML: '', dataset: {}, classList: {add: c => cls.add(c), remove: c => cls.delete(c), contains: c => cls.has(c),
    toggle: (c, on) => { const v = on === undefined ? !cls.has(c) : !!on; if (v) cls.add(c); else cls.delete(c); return v; }}};
}
const el = id => els[id] || (els[id] = mkEl(id));
const store = {};
const localStorage = {getItem: k => (k in store ? store[k] : null), setItem: (k, v) => { store[k] = String(v); }};
let payload = {version: '1.45.0', entries: [
  {version: '1.45.0', title: '1.45.0', date: '2026-10-24', items: [{kind: 'new', text: 'Neu mit `code` <b>', sub: ['Unterpunkt']}]},
  {version: '1.44.0', title: '1.44.0', date: '2026-10-24', items: [{kind: 'security', text: 'Sicher', sub: []}]},
  {version: '1.43.0', title: '1.43.0', date: '', items: [{kind: 'fix', text: 'Behoben', sub: []}]},
]};
const fetchCalls = [];
const f = new Function('document', 'window', 'navigator', 'localStorage', 'fetch',
  src.replace(/document\.addEventListener\("DOMContentLoaded"[\s\S]*?\}\);\s*\n/, '') + `
return {checkNews, openNews, closeNews, versionNewer, reset: () => { newsData = null; newsLang = null; }};`);
const api = f({getElementById: el, querySelector: () => null, querySelectorAll: () => [], addEventListener() {}}, {}, {language: 'de'},
  localStorage, async url => { fetchCalls.push(url); return {ok: true, json: async () => payload}; });
(async () => {
  console.assert(api.versionNewer('1.10.0', '1.9.9') && !api.versionNewer('1.9.9', '1.10.0') && !api.versionNewer('1.45.0', '1.45.0'), 'Versionsvergleich numerisch');
  console.assert(api.versionNewer('1.45.0-s1', '1.45.0') && api.versionNewer('1.45.0-s10', '1.45.0-s9') && api.versionNewer('1.46.0', '1.45.0-s3')
    && !api.versionNewer('1.45.0-s1', '1.45.0-s1') && !api.versionNewer('1.45.0', '1.45.0-s1'), 'Sicherheitsupdates -s<Zaehler>');
  // First use: no dot, the state is remembered
  await api.checkNews();
  console.assert(el('news-dot').classList.contains('hidden') && store['samonboarding.newsSeen'] === '1.45.0', 'erste Nutzung: kein Hinweis');
  // Update from 1.43.0: dot, orange because of security update 1.44.0
  store['samonboarding.newsSeen'] = '1.43.0'; api.reset();
  await api.checkNews();
  console.assert(!el('news-dot').classList.contains('hidden'), 'Punkt nach Update sichtbar');
  console.assert(el('news-dot').classList.contains('is-security'), 'Sicherheitsupdate: orange');
  // Window: new versions marked, HTML escaped, read afterwards
  await api.openNews();
  const html = el('news-list').innerHTML;
  console.assert(html.includes('<code>code</code>') && html.includes('&lt;b&gt;') && !html.includes('<b>'), 'sicher dargestellt');
  console.assert((html.match(/news-chip-unread/g) || []).length === 2, 'zwei neue Versionen markiert');
  console.assert(html.includes('news-chip-security') && html.includes('news-chip-fix'), 'Arten markiert');
  console.assert(el('news-dot').classList.contains('hidden') && store['samonboarding.newsSeen'] === '1.45.0', 'nach dem Lesen kein Punkt');
  api.closeNews();
  // Update without a security topic: normal dot
  store['samonboarding.newsSeen'] = '1.44.0'; api.reset();
  await api.checkNews();
  console.assert(!el('news-dot').classList.contains('hidden') && !el('news-dot').classList.contains('is-security'), 'normaler Punkt');
  console.assert(fetchCalls.every(u => u.startsWith('/api/news?lang=')), 'nur eigener Server');
  console.log('Neuigkeiten-Tests fertig');
})();
