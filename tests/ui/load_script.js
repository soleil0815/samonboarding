// Returns the interface script samonboarding/web/app.js
const fs = require('fs');
const path = require('path');

// In Node, console.assert only prints a message and leaves the exit code at 0 - a failed test would be green in
// the CI. Every test loads this file: a failed assert sets the exit code here (code audit 2026-11).
const originalAssert = console.assert.bind(console);
console.assert = (condition, ...message) => {
  if (!condition) process.exitCode = 1;
  originalAssert(condition, ...message);
};

// Since 2.3.0 the interface logic is its own file (served as /app.js), no longer inline in index.html
module.exports = fs.readFileSync(path.join(__dirname, '..', '..', 'samonboarding', 'web', 'app.js'), 'utf8');
