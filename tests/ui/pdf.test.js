// Print credentials: a pop-up blocker (window.open returns null) must not crash without a message
const src = require('./load_script.js');
const doc = {getElementById: () => null, querySelectorAll: () => [], querySelector: () => null, addEventListener() {}};
const alerts = [];
const f = new Function('document', 'window', 'navigator', 'alert', src.replace(/document\.addEventListener\("DOMContentLoaded"[\s\S]*?\}\);\s*\n/, '') + `
return {generatePDF, setUser: u => { lastCreatedUser = u; }};`);
const win = {open: () => null};
const api = f(doc, win, {language: 'de'}, m => alerts.push(m));
api.setUser({sam: 'mmuster', name: 'Max Muster', upn: 'mmuster@firma.local', password: 'x'});
let crashed = null;
try { api.generatePDF(); } catch (e) { crashed = e; }
console.assert(crashed === null, 'kein Absturz bei blockiertem Pop-up: ' + crashed);
console.assert(alerts.length === 1 && alerts[0].includes('blockiert'), 'Hinweis an den Benutzer');
// with a window: content is written
let written = '';
let printed = 0;
win.open = () => ({document: {write: h => { written += h; }, close() {}}, focus() {}, print() { printed++; }});
api.generatePDF();
console.assert(written.includes('mmuster'), 'Druckfenster bekommt die Zugangsdaten');
// the print window inherits the page's CSP: no inline script there, printing is started from the page
console.assert(!/<script/i.test(written) && printed === 1, 'kein Inline-Skript im Druckfenster, Druck vom Hauptfenster');
console.log('PDF-Tests fertig');
