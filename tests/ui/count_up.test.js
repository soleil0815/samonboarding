// Start page: something visibly moves while waiting (seconds), and the numbers count up when they arrive
const src = require('./load_script.js');
const els = {};
const mkClass = () => { const set = new Set(); return {add: c => set.add(c), remove: c => set.delete(c), toggle: (c, on) => { const w = on === undefined ? !set.has(c) : !!on; if (w) set.add(c); else set.delete(c); return w; }, contains: c => set.has(c)}; };
const el = id => els[id] || (els[id] = {id, innerHTML: '', textContent: '', value: '', style: {}, attrs: {}, dataset: {},
  setAttribute(k, v) { this.attrs[k] = v; }, getAttribute(k) { return this.attrs[k]; }, classList: mkClass()});
const doc = {getElementById: el, querySelectorAll: () => [], querySelector: () => null, addEventListener() {}};
let reply = null;
let release = null;
const fetch = async () => new Promise(r => { release = () => r(reply ? {ok: true, json: async () => reply} : {ok: false}); });
let frames = [];
const raf = fn => { frames.push(fn); return frames.length; };
let reduce = false;
const win = {matchMedia: () => ({matches: reduce})};
const f = new Function('document', 'window', 'navigator', 'alert', 'fetch', 'requestAnimationFrame',
  src.replace(/document\.addEventListener\("DOMContentLoaded"[\s\S]*?\}\);\s*\n/, '') + `
return {loadDashboard, countTo, setRole: r => { currentUserRole = r; }};`);
const api = f(doc, win, {language: 'de'}, () => {}, fetch, raf);
const tick = ms => new Promise(r => setTimeout(r, ms));
const runFrames = async ms => { const end = Date.now() + ms; while (Date.now() < end) { const fs = frames; frames = []; fs.forEach(fn => fn()); await tick(16); } };

(async () => {
  api.setRole('Administrator');
  ['inactive', 'locked', 'delete'].forEach(k => { el('dash-' + k + '-num').textContent = '–'; });

  // 1. while waiting: the seconds count on the cards
  const loading = api.loadDashboard(false);
  await tick(10);
  console.assert(els['dash-inactive-sub'].textContent === 'Wird vom DC gelesen …', 'waiting hint at once');
  await tick(1100);
  console.assert(/^Wird vom DC gelesen … [12] s$/.test(els['dash-inactive-sub'].textContent), 'seconds count: ' + els['dash-inactive-sub'].textContent);
  console.assert(els['dash-inactive'].attrs['aria-busy'] === 'true', 'card marked busy');

  // 2. the answer arrives: numbers count up from 0, end exactly on the value
  reply = {status: 'success', inactive: {count: 144, never: 100}, locked: {count: 0}, deletion: {count: 3}};
  release();
  await loading;
  const num = els['dash-inactive-num'];
  console.assert(num.dataset.value === '144', 'target value known at once');
  await runFrames(300);
  const mid = Number(num.textContent);
  console.assert(mid > 0 && mid < 144, 'counting up: ' + num.textContent);
  await runFrames(800);
  console.assert(num.textContent === '144' && els['dash-delete-num'].textContent === '3', 'ends on the exact value: ' + num.textContent);
  console.assert(els['dash-locked-num'].textContent === '0', 'zero shown');
  console.assert(els['dash-inactive-sub'].textContent === 'davon 100 nie angemeldet', 'real hint after loading');

  // 3. refresh: "refreshing … s" next to the time, numbers count from the old to the new value
  const refresh = api.loadDashboard(false);
  await tick(1100);
  console.assert(/^aktualisiert … [12] s$/.test(els['dash-busy-text'].textContent), 'refresh seconds: ' + els['dash-busy-text'].textContent);
  console.assert(els['dash-inactive-sub'].textContent === 'davon 100 nie angemeldet', 'cards keep their text while refreshing');
  reply = {status: 'success', inactive: {count: 150, never: 100}, locked: {count: 0}, deletion: {count: 3}};
  release();
  await refresh;
  await runFrames(100);
  const mid2 = Number(num.textContent);
  console.assert(mid2 >= 144 && mid2 <= 150, 'counts from the old value: ' + num.textContent);
  await runFrames(900);
  console.assert(num.textContent === '150', 'new value');

  // 4. a newer value interrupts a running count; "–" stops it
  api.countTo(num, 10);
  await runFrames(50);
  api.countTo(num, 20);
  await runFrames(1000);
  console.assert(num.textContent === '20', 'last target wins');

  // 5. reduced motion: no animation, value at once
  reduce = true;
  api.countTo(num, 7);
  console.assert(num.textContent === '7' && frames.length === 0, 'reduced motion: no counting');
  console.log('Count-up UI tests fertig');
})();
