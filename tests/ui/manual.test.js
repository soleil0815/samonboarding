// Handbuch: Markdown-Darstellung (sicher, Ueberschriften-Anker passen zum Inhaltsverzeichnis)
const fs = require('fs');
const path = require('path');
const src = require('./load_script.js');
const f = new Function('document', 'window', 'navigator',
  src.replace(/document\.addEventListener\("DOMContentLoaded"[\s\S]*?\}\);\s*\n/, '') + `
return {manualRender, manualSlug, manualInline};`);
const api = f({getElementById: () => null, querySelector: () => null, querySelectorAll: () => [], addEventListener() {}}, {}, {language: 'de'});

// Sicherheit: alles wird escaped, Links nur intern oder https
const evil = api.manualRender('# T<script>\n\nText <img src=x onerror=alert(1)> [x](javascript:alert(1)) [y](http://a.b) [z](https://ok.example/a?b=1&c=2)');
console.assert(!evil.includes('<script') && !evil.includes('<img'), 'HTML wird escaped');
console.assert(!evil.includes('javascript:') || !/href="javascript/.test(evil), 'kein javascript-Link');
console.assert(!evil.includes('href="http://'), 'kein http-Link');
console.assert(evil.includes('href="https://ok.example/a?b=1&amp;c=2" target="_blank" rel="noopener noreferrer"'), 'https-Link mit noopener');
const quoteAttack = api.manualInline('[a](#x"onmouseover="alert(1))');
console.assert(!/onmouseover="/.test(quoteAttack), 'kein Ausbruch aus dem Attribut');

// Bausteine
const html = api.manualRender([
  '## 1. Überblick', '', 'Absatz mit **fett**, *kursiv* und `code <b>`.', '',
  '| A | B |', '|---|---|', '| `x` | **y** |', '',
  '1. eins', '2. zwei', '   - unter', '', '- a', '- b', '', '```bash', 'sudo ./update.sh <x>', '```', '', '---', '> Hinweis'
].join('\n'));
for (const want of ['<h2 id="m-1-überblick">', '<strong>fett</strong>', '<em>kursiv</em>', '<code>code &lt;b&gt;</code>',
  '<table>', '<td><code>x</code></td>', '<ol><li>eins</li><li>zwei<ul><li>unter</li></ul></li></ol>', '<ul><li>a</li><li>b</li></ul>',
  '<pre><code>sudo ./update.sh &lt;x&gt;</code></pre>', '<hr>', '<blockquote>Hinweis</blockquote>']) {
  console.assert(html.includes(want), 'fehlt: ' + want + '\n' + html);
}
console.assert(!api.manualInline('ein * Stern und noch ein * Stern').includes('<em>'), 'einzelne Sterne bleiben');

// Alle Links im Inhaltsverzeichnis zeigen auf eine Ueberschrift
for (const file of ['HANDBUCH.md', 'MANUAL.en.md']) {
  const md = fs.readFileSync(path.join(__dirname, '..', '..', 'samonboarding', 'web', 'manual', file), 'utf8');
  const out = api.manualRender(md);
  const ids = new Set([...out.matchAll(/ id="([^"]+)"/g)].map(m => m[1]));
  const anchors = [...md.matchAll(/\]\(#([^)]+)\)/g)].map(m => m[1]);
  console.assert(anchors.length >= 17, file + ': Inhaltsverzeichnis');
  anchors.forEach(a => console.assert(ids.has('m-' + a), file + ': Anker fehlt ' + a));
  console.assert(!/href="http:/.test(out), file + ': kein http');
}
// Fett/Kursiv greifen nicht in Adressen ein, doppelte Ueberschriften bekommen eigene Anker, NUL wird entfernt
const tricky = api.manualInline('[a](https://e.x/-*x) y* und `\u00000\u0000` [**fett** `c`](#ziel)');
console.assert(tricky.includes('href="https://e.x/-*x"'), 'Adresse unveraendert: ' + tricky);
console.assert(tricky.includes('<a href="#ziel" data-anchor="ziel"><strong>fett</strong> <code>c</code></a>'), 'Link mit Fett und Code: ' + tricky);
const dup = api.manualRender('## Gleich\n\n## Gleich');
console.assert(dup.includes('id="m-gleich"') && dup.includes('id="m-gleich-2"'), 'eindeutige Anker');
console.log('fertig');
