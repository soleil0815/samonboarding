// Zugangsdaten drucken: ein Pop-up-Blocker (window.open liefert null) darf nicht ohne Hinweis abstuerzen
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
// mit Fenster: Inhalt wird geschrieben
let written = '';
win.open = () => ({document: {write: h => { written += h; }, close() {}}});
api.generatePDF();
console.assert(written.includes('mmuster'), 'Druckfenster bekommt die Zugangsdaten');
console.log('PDF-Tests fertig');
