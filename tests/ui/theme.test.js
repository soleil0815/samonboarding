// Appearance: follows the computer by default (system); light and dark can be chosen and are remembered
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const src = require('./load_script.js');

function run(stored, systemDark) {
  const store = stored === undefined ? {} : {'samonboarding.theme': stored};
  const localStorage = {getItem: k => (k in store ? store[k] : null), setItem: (k, v) => { store[k] = String(v); }};
  const attrs = {};
  const btns = ['light', 'dark', 'system'].map(p => ({
    dataset: {themePref: p}, pressed: null, active: false,
    classList: {toggle(_c, on) { this.owner.active = on; }},
    setAttribute(_n, v) { this.pressed = v; },
  }));
  btns.forEach(b => { b.classList.owner = b; });
  const doc = {
    documentElement: {setAttribute: (n, v) => { attrs[n] = v; }},
    getElementById: () => null, querySelector: () => null, addEventListener() {},
    querySelectorAll: sel => (sel === '.theme-btn' ? btns : []),
  };
  const win = {matchMedia: () => ({matches: systemDark, addEventListener() {}})};
  const f = new Function('document', 'window', 'navigator', 'localStorage',
    src.replace(/document\.addEventListener\("DOMContentLoaded"[\s\S]*?\}\);\s*\n/, '') + '\nreturn {themePref, applyTheme, setTheme};');
  const api = f(doc, win, {language: 'de'}, localStorage);
  return {api, attrs, btns, store};
}

// default without a stored choice: system
let t = run(undefined, true);
assert.strictEqual(t.api.themePref(), 'system');
t.api.applyTheme(t.api.themePref());
assert.strictEqual(t.attrs['data-theme'], 'dark', 'system dark -> dark');
assert.deepStrictEqual(t.btns.map(b => b.active), [false, false, true], 'system button marked');
t = run(undefined, false);
t.api.applyTheme(t.api.themePref());
assert.strictEqual(t.attrs['data-theme'], 'light', 'system light -> light');

// a stored choice stays
assert.strictEqual(run('light', true).api.themePref(), 'light');
assert.strictEqual(run('dark', false).api.themePref(), 'dark');
assert.strictEqual(run('kaputt', false).api.themePref(), 'system');

// choosing stores and applies
t = run(undefined, false);
t.api.setTheme('dark');
assert.strictEqual(t.store['samonboarding.theme'], 'dark');
assert.strictEqual(t.attrs['data-theme'], 'dark');

// theme.js (before the page is drawn) has the same default
const early = fs.readFileSync(path.join(__dirname, '..', '..', 'samonboarding', 'web', 'theme.js'), 'utf8');
for (const [stored, systemDark, expected] of [[null, true, 'dark'], [null, false, 'light'], ['light', true, 'light'], ['dark', false, 'dark']]) {
  const attrs = {};
  new Function('document', 'window', 'localStorage', early)(
    {documentElement: {setAttribute: (n, v) => { attrs[n] = v; }}},
    {matchMedia: () => ({matches: systemDark})},
    {getItem: () => stored},
  );
  assert.strictEqual(attrs['data-theme'], expected, `theme.js ${stored}/${systemDark}`);
}
console.log('Darstellungs-Tests fertig');
