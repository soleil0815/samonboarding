// Liefert das Haupt-Skript (letztes <script> ohne src) aus samonboarding/web/index.html
const fs = require('fs');
const path = require('path');

// console.assert gibt in Node nur eine Meldung aus und laesst den Exit-Code auf 0 - ein fehlgeschlagener Test waere in
// der CI gruen. Jeder Test laedt diese Datei: ein fehlgeschlagener Assert setzt hier den Exit-Code (Code-Audit 2026-11).
const originalAssert = console.assert.bind(console);
console.assert = (condition, ...message) => {
  if (!condition) process.exitCode = 1;
  originalAssert(condition, ...message);
};

const html = fs.readFileSync(path.join(__dirname, '..', '..', 'samonboarding', 'web', 'index.html'), 'utf8');
const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m => m[1]);
module.exports = scripts[scripts.length - 1];
