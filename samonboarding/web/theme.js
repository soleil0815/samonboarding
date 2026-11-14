// SPDX-License-Identifier: AGPL-3.0-or-later
// Applies the chosen appearance before the page is drawn, so nothing flashes white. The choice is kept per browser
// (localStorage 'samonboarding.theme': light - the default -, dark or system); the switch itself is in app.js.
(function () {
    var pref = 'light';
    try { pref = localStorage.getItem('samonboarding.theme') || 'light'; } catch (e) { /* storage blocked */ }
    var dark = pref === 'dark' || (pref === 'system' && !!window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches);
    document.documentElement.setAttribute('data-theme', dark ? 'dark' : 'light');
})();
