// Liefert das Haupt-Skript (letztes <script> ohne src) aus samonboarding/web/index.html
const fs = require('fs');
const path = require('path');
const html = fs.readFileSync(path.join(__dirname, '..', '..', 'samonboarding', 'web', 'index.html'), 'utf8');
const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m => m[1]);
module.exports = scripts[scripts.length - 1];
