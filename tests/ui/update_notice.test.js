// Newer version on GitHub: the note for administrators (only version numbers come from the server)
const assert = require('assert');
const src = require('./load_script.js');

const doc = {getElementById: () => null, querySelector: () => null, querySelectorAll: () => [], addEventListener() {},
  documentElement: {setAttribute() {}}};
const f = new Function('document', 'window', 'navigator', 'localStorage',
  src.replace(/document\.addEventListener\("DOMContentLoaded"[\s\S]*?\}\);\s*\n/, '') + '\nreturn {updateNoticeHtml};');
const {updateNoticeHtml} = f(doc, {matchMedia: () => ({matches: false, addEventListener() {}})}, {language: 'de'},
  {getItem: () => null, setItem() {}});

// a new version without a fixed version: the two usual update commands and the release link
let html = updateNoticeHtml({kind: 'update', level: 'version', installed: '2.6.2', latest: '2.7.0', switch: false});
assert.ok(html.includes('Neue Version verfügbar:'));
assert.ok(html.includes('>2.7.0<'));
assert.ok(html.includes('href="https://github.com/soleil0815/samonboarding/releases/tag/v2.7.0" target="_blank" rel="noopener noreferrer"'));
assert.ok(html.includes('sudo sh update.sh<'));
// the command wraps only between its parts, never inside "up -d"
assert.ok(html.includes('<span class="whitespace-nowrap">docker compose pull</span> &amp;&amp; <span class="whitespace-nowrap">docker compose up -d</span>'));
assert.ok(!html.includes('--version'));

// a security update is named as such
html = updateNoticeHtml({kind: 'update', level: 'security', installed: '2.6.2', latest: '2.6.2-s1', switch: false});
assert.ok(html.includes('Sicherheitsupdate verfügbar:'));
assert.ok(html.includes('Gleiches Programm'));

// an exact version in .env: pull never changes it, so the switch command is named
html = updateNoticeHtml({kind: 'update', level: 'security', installed: '2.6.2', latest: '2.6.2-s1', switch: true});
assert.ok(html.includes('sudo sh update.sh --version 2.6.2-s1'));
assert.ok(!html.includes('docker compose pull'));

// a newer line outside the fixed version, nothing newer inside it
html = updateNoticeHtml({installed: '2.6.2', latest: null, outside: '2.7.0', outsideTarget: '2.7'});
assert.ok(html.includes('Neuere Versionsreihe außerhalb der festen Version'));
assert.ok(html.includes('sudo sh update.sh --version 2.7'));
assert.ok(!html.includes('Neue Version verfügbar:'));

// anything that is not a version number is never put into a link or a command
html = updateNoticeHtml({kind: 'update', level: 'version', installed: '<b>x</b>', latest: '2.7.0"><script>', outside: 'javascript:alert(1)', outsideTarget: '2.7'});
assert.strictEqual(html, '');
html = updateNoticeHtml({kind: 'update', level: 'version', installed: '<b>x</b>', latest: '2.7.0'});
assert.ok(html.includes('&lt;b&gt;x&lt;/b&gt;'));
assert.ok(!html.includes('<b>x'));

// an exact pin switches to the exact newer version
html = updateNoticeHtml({installed: '2.6.2', latest: null, outside: '2.7.0', outsideTarget: '2.7.0'});
assert.ok(html.includes('sudo sh update.sh --version 2.7.0<'));

console.log('update_notice: fertig');
