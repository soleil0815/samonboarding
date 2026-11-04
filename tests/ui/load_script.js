// Returns the main script (last <script> without src) from samonboarding/web/index.html
const fs = require('fs');
const path = require('path');

// In Node, console.assert only prints a message and leaves the exit code at 0 - a failed test would be green in
// the CI. Every test loads this file: a failed assert sets the exit code here (code audit 2026-11).
const originalAssert = console.assert.bind(console);
console.assert = (condition, ...message) => {
  if (!condition) process.exitCode = 1;
  originalAssert(condition, ...message);
};

const html = fs.readFileSync(path.join(__dirname, '..', '..', 'samonboarding', 'web', 'index.html'), 'utf8');
const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m => m[1]);
module.exports = scripts[scripts.length - 1];
