// Event handlers without inline JavaScript: data-on-* attributes are parsed (never evaluated) and dispatched
// from the document, like bubbling
const src = require('./load_script.js');
const listeners = {};
const doc = {getElementById: () => null, querySelectorAll: () => [], querySelector: () => null,
  addEventListener(type, fn) { (listeners[type] = listeners[type] || []).push(fn); }};
const win = {};
const f = new Function('document', 'window', 'navigator', 'alert',
  src.replace(/document\.addEventListener\("DOMContentLoaded"[\s\S]*?\}\);\s*\n/, '') + `
return {parseActions, dispatchAction, ACTION_EVENTS};`);
const api = f(doc, win, {language: 'de'}, () => {});

// 1. one delegated listener per event type
for (const t of ['click', 'change', 'input', 'keydown', 'mousemove']) {
  console.assert(listeners[t] && listeners[t].includes(api.dispatchAction), 'listener for ' + t);
}

// 2. parsing: literals, references, several calls
const p = api.parseActions("switchTab('hire'); toggle(this.checked, 3, -1.5, true, false, null, event, this, this.value, this.dataset.dn, 'it\\'s')");
console.assert(p.length === 2 && p[0].name === 'switchTab' && p[0].args[0].lit === 'hire', 'first call');
const a = p[1].args;
console.assert(a[0].prop === 'checked' && a[1].lit === 3 && a[2].lit === -1.5 && a[3].lit === true && a[4].lit === false && a[5].lit === null, 'literals');
console.assert(a[6].ref === 'event' && a[7].ref === 'this' && !a[7].prop && a[8].prop === 'value' && a[9].data === 'dn' && a[10].lit === "it's", 'references');
console.assert(api.parseActions('') .length === 0, 'empty');

// 3. anything else is refused - nothing is ever evaluated as code
for (const bad of ["alert(1)+1", "x = 1", "fn(window)", "fn(this.innerHTML)", "fn(a.b)", "fn(`x`)", "fn('x'", "constructor.constructor('x')()", "fn(1) fn(2)", "fn(this.dataset)"]) {
  let threw = false;
  try { api.parseActions(bad); } catch (e) { threw = true; }
  console.assert(threw, 'refused: ' + bad);
}

// 4. dispatch: target outwards, this = element with the attribute, arguments resolved
const calls = [];
win.rowClick = function (dn) { calls.push(['row', this.id, dn]); };
win.btnClick = function (ev, el, v) { calls.push(['btn', el.id, v, ev.type]); };
win.stopper = function (ev) { calls.push(['stop']); ev.stopPropagation(); };
const node = (id, attrs, parent) => ({id, nodeType: 1, parentElement: parent || null, dataset: attrs.dataset || {}, value: attrs.value,
  getAttribute: k => (attrs[k] === undefined ? null : attrs[k])});
const row = node('row', {'data-on-click': 'rowClick(this.dataset.dn)', dataset: {dn: 'CN=Anna,OU=MA,DC=firma,DC=local'}});
const cell = node('cell', {}, row);
const btn = node('btn', {'data-on-click': "btnClick(event, this, this.value)", value: 'v1'}, cell);
const text = {nodeType: 3, parentElement: btn};
const ev = (type, target) => ({type, target, cancelBubble: false, stopPropagation() { this.cancelBubble = true; }});
api.dispatchAction(ev('click', text));
console.assert(calls.length === 2 && calls[0][0] === 'btn' && calls[0][1] === 'btn' && calls[0][2] === 'v1' && calls[0][3] === 'click', 'inner handler first: ' + JSON.stringify(calls));
console.assert(calls[1][0] === 'row' && calls[1][1] === 'row' && calls[1][2] === 'CN=Anna,OU=MA,DC=firma,DC=local', 'then outer, like bubbling');

// stopPropagation in a handler ends the walk
calls.length = 0;
const inner = node('inner', {'data-on-click': 'stopper(event)'}, row);
api.dispatchAction(ev('click', inner));
console.assert(calls.length === 1 && calls[0][0] === 'stop', 'propagation stopped');

// other event types use their own attribute; unknown functions are reported, not thrown
calls.length = 0;
api.dispatchAction(ev('change', btn));
console.assert(calls.length === 0, 'no data-on-change: nothing runs');
const errors = [];
const origError = console.error;
console.error = m => errors.push(String(m));
api.dispatchAction(ev('click', node('x', {'data-on-click': 'doesNotExist()'})));
api.dispatchAction(ev('click', node('y', {'data-on-click': 'fn(1)+2'})));
console.error = origError;
console.assert(errors.length === 2 && errors[0].includes('doesNotExist') && errors[1].includes('Unsupported handler'), 'errors reported: ' + errors);
console.log('Action UI tests fertig');
