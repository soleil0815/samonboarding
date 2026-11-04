// Menu per role: items whose data the server gives only to administrators are hidden for operators
const src = require('./load_script.js');
const els = {};
const el = id => els[id] || (els[id] = {id, style: {}, disabled: false, classList: {add() {}, remove() {}, toggle() {}}});
const doc = {getElementById: el, querySelectorAll: () => [], querySelector: () => null, addEventListener() {}};
const f = new Function('document', 'window', 'navigator', src.replace(/document\.addEventListener\("DOMContentLoaded"[\s\S]*?\}\);\s*\n/, '') + `
return {setupRoleVisibility};`);
const api = f(doc, {}, {language: 'de'});
api.setupRoleVisibility('Account Operator');
for (const id of ['nav-delete', 'nav-reports', 'nav-cert', 'nav-smtp']) {
  console.assert(el(id).style.display === 'none', id + ' fuer Operatoren ausgeblendet');
}
api.setupRoleVisibility('Administrator');
for (const id of ['nav-delete', 'nav-reports', 'nav-cert', 'nav-smtp']) {
  console.assert(el(id).style.display === '', id + ' fuer Administratoren sichtbar');
}
console.log('Menue-Tests fertig');
