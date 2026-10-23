// Sprachumschaltung: Uebersetzer (exakt, Muster, verschachtelt, Zeilen) mit dem echten Woerterbuch
const fs = require('fs');
const path = require('path');
const src = require('./load_script.js');
const dict = fs.readFileSync(path.join(__dirname, '..', '..', 'samonboarding', 'web', 'i18n.json'), 'utf8');
const els = {'i18n-data': {textContent: dict}};
const el = id => els[id] || (els[id] = {id, innerHTML: '', textContent: '', value: '', classList: {add() {}, remove() {}, toggle() {}}, style: {}, setAttribute() {}});
const store = {};
const doc = {getElementById: el, querySelectorAll: () => [], querySelector: () => null, addEventListener() {}, documentElement: {lang: 'de'}};
const f = new Function('document', 'window', 'navigator', 'alert', 'fetch', 'confirm', 'localStorage', src.replace(/document\.addEventListener\("DOMContentLoaded"[\s\S]*?\}\);\s*\n/, '') + `
return {tr, trText, setLanguage, initialLanguage, getLang: () => uiLang};`);
const ls = {getItem: k => store[k] || null, setItem: (k, v) => { store[k] = v; }};
const api = f(doc, {}, {language: 'de-DE'}, () => {}, async () => ({}), () => true, ls);
// Deutsch: nichts aendern
console.assert(api.tr('Konto suchen...') === 'Konto suchen...', 'DE unveraendert');
console.assert(api.initialLanguage() === 'de', 'Browser Deutsch -> de');
api.setLanguage('en');
console.assert(api.getLang() === 'en' && store['samonboarding.lang'] === 'en' && doc.documentElement.lang === 'en', 'gespeichert und lang-Attribut');
console.assert(api.initialLanguage() === 'en', 'gespeicherte Wahl hat Vorrang');
// exakt, Leerraum bleibt
console.assert(api.tr('  Konto suchen...  ') === '  Search account...  ', 'exakt mit Leerraum');
console.assert(api.trText('Benutzerkonten aufräumen, in andere OUs\n                verschieben und Gruppenmitgliedschaften anpassen') === 'Tidy up user accounts, move them to other OUs and adjust group memberships', 'Zeilenumbruch im Quelltext');
// Muster mit Zahlen
console.assert(api.tr('6 Konten') === '6 accounts', 'Zaehler');
// verschachtelt: Begruendung und Aktion werden mit uebersetzt
console.assert(api.tr('Dieses Konto ist geschützt (Mitglied von „Domänen-Admins“) und darf nicht offgeboardet werden. Soll es trotzdem bearbeitet werden, zuerst die Mitgliedschaft im AD entfernen.')
  === 'This account is protected (Member of “Domain Admins”) and must not be offboarded. If it really has to be processed, remove the membership in AD first.', 'verschachtelt');
// mehrzeilige Meldung mit Aufzaehlung
const multi = api.tr('2 von 3 Konten wurden offgeboardet.\n\nNICHT offgeboardet:\n- Anna: Das Konto liegt nicht in einer für diese Funktion freigegebenen Quell-OU.');
console.assert(multi === '2 of 3 accounts were offboarded.\n\nNOT offboarded:\n- Anna: The account is not in a source OU permitted for this function.', multi);
// Daten bleiben, unbekannte Texte bleiben
console.assert(api.tr('Hans von Berg') === 'Hans von Berg', 'Namen unveraendert');
console.assert(api.tr('OU=Mitarbeiter,DC=firma,DC=local') === 'OU=Mitarbeiter,DC=firma,DC=local', 'DN unveraendert');
console.assert(api.tr('12345') === '12345', 'Zahlen');
// Zurueck auf Deutsch
api.setLanguage('de');
console.assert(api.tr('Konto suchen...') === 'Konto suchen...' && store['samonboarding.lang'] === 'de', 'zurueck auf Deutsch');
console.log('I18n-UI-Tests fertig');
