// Navigation (active entry), mobile menu and messages (toasts instead of alert)
const src = require('./load_script.js');
const els = {};
function mkEl(id) {
  const cls = new Set();
  const attrs = {};
  const e = {id, innerHTML: '', textContent: '', value: '', children: [], style: {}, scrollTop: 50,
    classList: {add: c => cls.add(c), remove: c => cls.delete(c), contains: c => cls.has(c),
      toggle: (c, on) => { const v = on === undefined ? !cls.has(c) : !!on; if (v) cls.add(c); else cls.delete(c); return v; }},
    setAttribute: (k, v) => { attrs[k] = String(v); }, removeAttribute: k => { delete attrs[k]; }, getAttribute: k => attrs[k],
    appendChild(ch) { this.children.push(ch); ch.parent = this; return ch; },
    removeChild(ch) { this.children = this.children.filter(x => x !== ch); },
    get firstChild() { return this.children[0]; },
    remove() { if (this.parent) this.parent.removeChild(this); },
    _cls: cls};
  Object.defineProperty(e, 'className', {get: () => [...cls].join(' '), set: v => { cls.clear(); String(v).split(/\s+/).filter(Boolean).forEach(x => cls.add(x)); }});
  return e;
}
const el = id => els[id] || (els[id] = mkEl(id));
const main = mkEl('main');
const doc = {getElementById: el, querySelector: q => q === '.app-main' ? main : null, querySelectorAll: () => [],
  createElement: () => mkEl(''), addEventListener() {}};
const timers = [];
const f = new Function('document', 'window', 'navigator', 'alert', 'fetch', 'confirm', 'setTimeout',
  src.replace(/document\.addEventListener\("DOMContentLoaded"[\s\S]*?\}\);\s*\n/, '') + `
return {switchTab, toggleSidebar, showToast, toastKind, setAvatar, stubRefresh: fn => { refreshAllLdapData = fn; }};`);
(async () => {
  const api = f(doc, {}, {language: 'de'}, () => {}, async () => ({ok: true, json: async () => ({})}), () => true, (fn, ms) => timers.push([fn, ms]));
  api.stubRefresh(async () => {});
  // Navigation: exactly one active entry, aria-current, content at the top
  await api.switchTab('offboard');
  console.assert(el('nav-offboard').classList.contains('is-active') && el('nav-offboard').getAttribute('aria-current') === 'page', 'Offboarding aktiv');
  console.assert(!el('nav-hire').classList.contains('is-active') && el('nav-hire').getAttribute('aria-current') === undefined, 'Onboarding nicht mehr aktiv');
  console.assert(el('tab-offboard').classList.contains('hidden') === false && el('tab-hire').classList.contains('hidden') === true, 'richtiger Tab sichtbar');
  console.assert(main.scrollTop === 0, 'Inhalt nach oben gescrollt');
  // Mobile menu
  api.toggleSidebar(true);
  console.assert(el('app-sidebar').classList.contains('is-open') && el('sidebar-scrim').classList.contains('is-open'), 'Menue offen');
  await api.switchTab('hire');
  console.assert(!el('app-sidebar').classList.contains('is-open') && !el('sidebar-scrim').classList.contains('is-open'), 'Tab-Wechsel schliesst das Menue');
  // Messages: detect the type
  console.assert(api.toastKind('Konfiguration gespeichert!') === 'success', 'Erfolg');
  console.assert(api.toastKind('Fehler beim Speichern.') === 'error', 'Fehler');
  console.assert(api.toastKind('Das Passwort ist falsch.') === 'error', 'falsch = Fehler');
  console.assert(api.toastKind('Hinweis:\nGruppe fehlt') === 'warn', 'Hinweis = Warnung');
  console.assert(api.toastKind('Verbindung wird geprüft') === 'info', 'neutral');
  // message appears, text stays text (no HTML), a short success message disappears on its own
  api.showToast('<b>x</b> gespeichert');
  const stack = el('toast-stack');
  const t = stack.children[0];
  console.assert(t && t.className.includes('toast-success'), 'Toast angelegt');
  const body = t.children[1];
  console.assert(body.textContent === '<b>x</b> gespeichert' && body.innerHTML === '', 'Text nicht als HTML');
  console.assert(timers.some(([, ms]) => ms > 4000), 'kurze Meldung mit Zeitlimit');
  const before = timers.length;
  api.showToast('Fehler: Server nicht erreichbar.');
  console.assert(timers.length === before, 'Fehler bleiben stehen');
  for (let i = 0; i < 6; i++) api.showToast('Info ' + i, 'info');
  console.assert(stack.children.length <= 4, 'hoechstens vier Meldungen gleichzeitig');
  // Initials
  api.setAvatar('anna.berger'); console.assert(el('user-avatar').textContent === 'AB', 'Kuerzel AB');
  api.setAvatar('FIRMA\\\\administrator'); console.assert(el('user-avatar').textContent === 'A', 'Kuerzel aus DOMAIN\\\\user');
  api.setAvatar('max@firma.local'); console.assert(el('user-avatar').textContent === 'M', 'Kuerzel aus UPN');
  console.log('Shell-UI-Tests fertig');
})();
