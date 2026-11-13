// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Die SAMONBOARDING-Autoren
// Interface logic of SAMONBOARDING. Served as /app.js (not inline), so the content security policy can forbid
// inline scripts (script-src 'self').

// ---------------------------------------------------------------
// Event handlers without inline JavaScript (content security policy: script-src 'self')
// HTML elements carry data-on-click="fn('x', this.value)" instead of inline on-click attributes. One listener per event type on the
// document finds them (from the clicked element outwards, like bubbling) and calls the named functions. The text
// is never evaluated as code: it is parsed into calls of global functions with a fixed set of arguments -
// literals ('text', numbers, true/false/null), event, this, this.value, this.checked and this.dataset.<name>.
// ---------------------------------------------------------------
const ACTION_EVENTS = ['click', 'change', 'input', 'keydown', 'mousemove'];
const actionCache = new Map();

function parseActions(text) {
    if(actionCache.has(text)) return actionCache.get(text);
    const src = String(text);
    let i = 0;
    const calls = [];
    const ws = () => { while(i < src.length && /\s/.test(src[i])) i++; };
    const fail = () => { throw new Error('Unsupported handler: ' + src); };
    const ident = () => {
        const m = /^[A-Za-z_$][\w$]*/.exec(src.slice(i));
        if(!m) fail();
        i += m[0].length;
        return m[0];
    };
    const arg = () => {
        ws();
        const ch = src[i];
        if(ch === "'" || ch === '"') {
            let out = '';
            i++;
            while(i < src.length && src[i] !== ch) {
                if(src[i] === '\\' && i + 1 < src.length) { out += src[i + 1]; i += 2; } else { out += src[i++]; }
            }
            if(src[i] !== ch) fail();
            i++;
            return {lit: out};
        }
        const num = /^-?\d+(\.\d+)?/.exec(src.slice(i));
        if(num) { i += num[0].length; return {lit: Number(num[0])}; }
        const word = ident();
        if(word === 'true') return {lit: true};
        if(word === 'false') return {lit: false};
        if(word === 'null') return {lit: null};
        if(word === 'event') return {ref: 'event'};
        if(word !== 'this') fail();
        if(src[i] !== '.') return {ref: 'this'};
        i++;
        const prop = ident();
        if(prop === 'value' || prop === 'checked') return {ref: 'this', prop};
        if(prop !== 'dataset' || src[i] !== '.') fail();
        i++;
        return {ref: 'this', data: ident()};
    };
    while(true) {
        ws();
        if(i >= src.length) break;
        const name = ident();
        ws();
        if(src[i] !== '(') fail();
        i++;
        const args = [];
        ws();
        if(src[i] !== ')') {
            while(true) {
                args.push(arg());
                ws();
                if(src[i] === ',') { i++; continue; }
                if(src[i] === ')') break;
                fail();
            }
        }
        i++;
        calls.push({name, args});
        ws();
        if(i < src.length) {
            if(src[i] !== ';') fail();  // calls are separated by ';'
            i++;
        }
    }
    actionCache.set(text, calls);
    return calls;
}

function actionFunction(name) {
    const fn = typeof window !== 'undefined' ? window[name] : undefined;
    return typeof fn === 'function' ? fn : null;
}

function runActions(text, el, event) {
    for(const call of parseActions(text)) {
        const fn = actionFunction(call.name);
        if(!fn) { console.error('Unknown handler function: ' + call.name); continue; }
        const args = call.args.map(a => {
            if('lit' in a) return a.lit;
            if(a.ref === 'event') return event;
            if(a.data) return el.dataset ? el.dataset[a.data] : undefined;
            if(a.prop) return el[a.prop];
            return el;
        });
        fn.apply(el, args);
    }
}

function dispatchAction(event) {
    const attr = 'data-on-' + event.type;
    let el = event.target && event.target.nodeType === 3 ? event.target.parentElement : event.target;
    // like bubbling: every element with a handler from the target outwards, until one stops the propagation
    while(el && el !== document && el.getAttribute) {
        const text = el.getAttribute(attr);
        if(text) {
            try { runActions(text, el, event); } catch(e) { console.error(e); }
            if(event.cancelBubble) break;
        }
        el = el.parentElement;
    }
}

if(typeof document !== 'undefined' && document.addEventListener) {
    ACTION_EVENTS.forEach(type => document.addEventListener(type, dispatchAction));
}

// Small helpers for what used to be written inline
function onEnter(event, name) {
    if(event && event.key === 'Enter') { const fn = actionFunction(name); if(fn) fn(); }
}
function onBackdrop(event, el, name) {
    if(event && event.target === el) { const fn = actionFunction(name); if(fn) fn(); }
}
function hideElement(id) {
    const el = document.getElementById(id);
    if(el) el.classList.add('hidden');
}
function copyValue(id, value) {
    const el = document.getElementById(id);
    if(el) el.value = value;
}

const userLang = (navigator.language || navigator.userLanguage || 'en').toLowerCase().startsWith('de') ? 'de' : 'en';
let currentUserRole = "";
let currentLoggedInUsername = "";
let cachedOffboardUsers = [];
let cachedPwdResetUsers = [];
let cachedUserMgmtUsers = [];
let globalAllowedTargetOus = [];

// ---------------------------------------------------------------
// Language (German/English). The UI is written in German; for English, tr() translates every
// displayed text via i18n.json (exact texts and patterns with placeholders {0}, {1} ...).
// AD data (names, OUs, groups) sits in elements with translate="no" and stays unchanged.
// ---------------------------------------------------------------
const I18N = (() => {
    try { return JSON.parse(document.getElementById('i18n-data').textContent); } catch(e) { return {exact: {}, patterns: []}; }
})();
const I18N_PATTERNS = (I18N.patterns || []).map(([de, en]) => {
    const parts = String(de).split(/\{(\d+)\}/);
    let src = '^', order = [];
    parts.forEach((part, i) => {
        if (i % 2) { src += '([\\s\\S]+?)'; order.push(Number(part)); }
        else src += part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    });
    return {re: new RegExp(src + '$'), en: String(en), order: order, weight: parts.filter((x, i) => !(i % 2)).join('').length};
}).sort((a, b) => b.weight - a.weight);
let uiLang = 'de';

function trCore(text, depth) {
    if (Object.prototype.hasOwnProperty.call(I18N.exact || {}, text)) return I18N.exact[text];
    if (depth > 3) return null;
    for (const p of I18N_PATTERNS) {
        const m = p.re.exec(text);
        if (!m) continue;
        const values = [];
        p.order.forEach((idx, i) => { const v = m[i + 1]; const t = trCore(v, depth + 1); values[idx] = t === null ? v : t; });
        return p.en.replace(/\{(\d+)\}/g, (_, i) => values[Number(i)] !== undefined ? values[Number(i)] : '');
    }
    return trFallback(text, depth);
}

// Composite lines: '- item', 'A · B', 'Name: message' (the left part stays if unknown)
function trFallback(text, depth) {
    if (text.startsWith('- ')) {
        const rest = trCore(text.slice(2), depth + 1);
        return rest === null ? null : '- ' + rest;
    }
    if (text.includes(' · ')) {
        const parts = text.split(' · ');
        const done = parts.map(p => trCore(p, depth + 1));
        if (done.some(d => d !== null)) return parts.map((p, i) => done[i] === null ? p : done[i]).join(' · ');
    }
    const cut = text.indexOf(': ');
    if (cut > 0) {
        const left = text.slice(0, cut), right = trCore(text.slice(cut + 2), depth + 1);
        if (right !== null) { const l = trCore(left, depth + 1); return (l === null ? left : l) + ': ' + right; }
    }
    return null;
}

function tr(text) {
    if (uiLang !== 'en' || text === null || text === undefined) return text;
    const str = String(text);
    if (!/[A-Za-zÄÖÜäöüß]/.test(str)) return str;
    if (str.includes('\n')) return str.split('\n').map(line => tr(line)).join('\n');
    const m = /^(\s*)([\s\S]*?)(\s*)$/.exec(str);
    const out = trCore(m[2], 0);
    return out === null ? str : m[1] + out + m[3];
}

// Text of a DOM node: line breaks in the source count as spaces
function trText(text) {
    if (uiLang !== 'en' || !text || !/[A-Za-zÄÖÜäöüß]/.test(text)) return text;
    const m = /^(\s*)([\s\S]*?)(\s*)$/.exec(text);
    const out = trCore(m[2].replace(/\s+/g, ' '), 0);
    return out === null ? text : m[1] + out + m[3];
}

const I18N_ATTRS = ['placeholder', 'title', 'aria-label'];
const i18nTextOrig = new WeakMap();
const i18nAttrOrig = new WeakMap();

function i18nSkip(node) {
    const el = node.nodeType === 1 ? node : node.parentElement;
    if (!el || !el.closest) return true;
    if (el.closest('script, style, textarea')) return true;
    const marked = el.closest('[translate]');
    return !!(marked && marked.getAttribute('translate') === 'no');
}

function i18nApply(root) {
    if (!root || !document.createTreeWalker) return;
    const start = root.nodeType === 3 ? root.parentNode : root;
    if (!start) return;
    const texts = root.nodeType === 3 ? [root] : [];
    if (root.nodeType !== 3) {
        const w = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
        for (let n = w.nextNode(); n; n = w.nextNode()) texts.push(n);
    }
    texts.forEach(n => {
        if (i18nSkip(n)) return;
        if (!i18nTextOrig.has(n)) i18nTextOrig.set(n, n.nodeValue);
        const want = uiLang === 'en' ? trText(i18nTextOrig.get(n)) : i18nTextOrig.get(n);
        if (n.nodeValue !== want) n.nodeValue = want;
    });
    const els = root.nodeType === 1 ? [root, ...root.querySelectorAll('[placeholder],[title],[aria-label]')] : [];
    els.forEach(el => {
        if (i18nSkip(el)) return;
        let orig = i18nAttrOrig.get(el);
        if (!orig) { orig = {}; i18nAttrOrig.set(el, orig); }
        I18N_ATTRS.forEach(a => {
            if (!el.hasAttribute || !el.hasAttribute(a)) return;
            if (!(a in orig)) orig[a] = el.getAttribute(a);
            const want = uiLang === 'en' ? trText(orig[a]) : orig[a];
            if (el.getAttribute(a) !== want) el.setAttribute(a, want);
        });
    });
}

let i18nObserver = null;
function i18nWatch() {
    if (i18nObserver || typeof MutationObserver === 'undefined') return;
    i18nObserver = new MutationObserver(records => {
        i18nObserver.disconnect();
        records.forEach(r => {
            if (r.type === 'childList') r.addedNodes.forEach(n => i18nApply(n));
            else if (r.type === 'characterData') { i18nTextOrig.set(r.target, r.target.nodeValue); i18nApply(r.target); }
            else if (r.type === 'attributes') {
                const orig = i18nAttrOrig.get(r.target);
                if (orig) orig[r.attributeName] = r.target.getAttribute(r.attributeName);
                i18nApply(r.target);
            }
        });
        i18nObserver.takeRecords();
        i18nObserve();
    });
    i18nObserve();
}
function i18nObserve() {
    i18nObserver.observe(document.body, {childList: true, subtree: true, characterData: true, attributes: true, attributeFilter: I18N_ATTRS});
}

function setLanguage(lang, save) {
    uiLang = lang === 'en' ? 'en' : 'de';
    if (save !== false) { try { localStorage.setItem('samonboarding.lang', uiLang); } catch(e) {} }
    if (document.documentElement) document.documentElement.lang = uiLang;
    (document.querySelectorAll('.lang-btn') || []).forEach(b => {
        const on = b.dataset.lang === uiLang;
        b.classList.toggle('is-active', on);
        b.setAttribute('aria-pressed', on ? 'true' : 'false');
    });
    if (i18nObserver) i18nObserver.disconnect();
    i18nApply(document.body);
    if (i18nObserver) { i18nObserver.takeRecords(); i18nObserve(); }
    const manualTab = document.getElementById('tab-faq');
    try { if (manualTab && !manualTab.classList.contains('hidden')) loadManual(); } catch(e) {}
    const newsModal = document.getElementById('news-modal');
    try { if (newsModal && !newsModal.classList.contains('hidden')) loadNews().then(renderNews); } catch(e) {}
}

function initialLanguage() {
    let saved = null;
    try { saved = localStorage.getItem('samonboarding.lang'); } catch(e) {}
    if (saved === 'de' || saved === 'en') return saved;
    return String((navigator.language || 'de')).toLowerCase().startsWith('de') ? 'de' : 'en';
}

if (typeof window !== 'undefined' && window.document) {
    const nativeFetch = window.fetch.bind(window);
    window.fetch = (url, opts) => {
        const o = Object.assign({}, opts || {});
        o.headers = Object.assign({}, o.headers || {}, {'X-UI-Lang': uiLang});
        const p = nativeFetch(url, o);
        // Session expired (30 minutes without activity, restart): back to the login
        if (p && p.then && typeof url === 'string' && url.startsWith('/api/') && url !== '/api/login') {
            p.then(res => { if (res && res.status === 401 && appVisible()) sessionEnded(); }, () => {});
        }
        return p;
    };
    const nativeConfirm = window.confirm.bind(window);
    window.confirm = (msg) => nativeConfirm(tr(msg));
}

// ---------------------------------------------------------------
// UI: mobile sidebar, messages, user initials
// ---------------------------------------------------------------
function toggleSidebar(open) {
    const bar = document.getElementById('app-sidebar');
    const scrim = document.getElementById('sidebar-scrim');
    if(bar && bar.classList) bar.classList.toggle('is-open', !!open);
    if(scrim && scrim.classList) scrim.classList.toggle('is-open', !!open);
}

function toastKind(text) {
    const t = String(text).toLowerCase();
    if(/fehler|fehlgeschlagen|nicht möglich|keine berechtigung|ungültig|falsch|abgelehnt|gesperrt|verweigert|nicht erreichbar|nicht gefunden/.test(t)) return 'error';
    if(/hinweis|achtung|warnung|nicht alle|nicht vollständig|nicht offgeboardet/.test(t)) return 'warn';
    if(/erfolgreich|gespeichert|gesendet|angelegt|gelöscht|offgeboardet|verschoben|zurückgesetzt|übernommen|wiederhergestellt|verworfen/.test(t)) return 'success';
    return 'info';
}

function showToast(message, kind) {
    const stack = document.getElementById('toast-stack');
    const text = String(message == null ? '' : message);
    if(!stack || !stack.appendChild) return;
    kind = kind || toastKind(text);
    const icons = {success: 'fa-circle-check', error: 'fa-circle-exclamation', warn: 'fa-triangle-exclamation', info: 'fa-circle-info'};
    const el = document.createElement('div');
    el.className = 'toast toast-' + kind;
    el.setAttribute('role', kind === 'error' ? 'alert' : 'status');
    const icon = document.createElement('i');
    icon.className = 'fa-solid ' + icons[kind] + ' toast-icon';
    const body = document.createElement('div');
    body.className = 'toast-body';
    body.textContent = tr(text);
    const close = document.createElement('button');
    close.type = 'button';
    close.className = 'icon-btn';
    close.setAttribute('aria-label', 'Meldung schließen');
    close.innerHTML = '<i class="fa-solid fa-xmark"></i>';
    el.appendChild(icon); el.appendChild(body); el.appendChild(close);
    const remove = () => { el.classList.add('is-leaving'); setTimeout(() => el.remove(), 220); };
    close.onclick = remove;
    stack.appendChild(el);
    // Long messages and errors stay until they are closed
    const sticky = kind === 'error' || kind === 'warn' || text.length > 180 || text.includes('\n\n');
    if(!sticky) setTimeout(remove, 4500 + Math.min(text.length * 30, 4000));
    while(stack.children.length > 4) stack.removeChild(stack.firstChild);
}
if(typeof window !== 'undefined' && window.document) window.alert = showToast;

function setAvatar(name) {
    const el = document.getElementById('user-avatar');
    if(!el) return;
    const clean = String(name || '').split('\\').pop().split('@')[0];
    const parts = clean.split(/[.\s_-]+/).filter(Boolean);
    el.textContent = ((parts[0] || '?')[0] + (parts[1] ? parts[1][0] : '')).toUpperCase();
}

document.addEventListener("DOMContentLoaded", async () => {
    setLanguage(initialLanguage(), false);
    i18nWatch();
    await loadPublicConfig();
    await checkExistingSession();
    if (!appVisible()) showSessionEndedNotice();
});

async function checkExistingSession() {
    try {
        const res = await fetch('/api/me');
        if(res.ok) {
            const data = await res.json();
            currentUserRole = data.role;
            currentLoggedInUsername = data.user.toLowerCase();
            document.getElementById('login-screen').classList.add('hidden');
            document.getElementById('app-screen').classList.remove('hidden');
            document.getElementById('user-display').textContent = data.user;
            setAvatar(data.user);
            document.getElementById('role-display').textContent = data.role;
            showDirectory(data.directory);
            startIdleWatch(data.idleMinutes);
        startDashAutoRefresh();
            
            setupRoleVisibility(data.role);
            checkNews();
            await refreshAllLdapData();
        }
    } catch(e) {}
}

function setupRoleVisibility(role) {
    const offboardConfigBox = document.getElementById('offboard-admin-config');
    const pwdresetConfigBox = document.getElementById('pwdreset-admin-config');
    const usermgmtConfigBox = document.getElementById('usermgmt-admin-config');
    const smtpReadonlyNotice = document.getElementById('smtp-readonly-notice');
    const smtpActionButtons = document.getElementById('smtp-action-buttons');
    const smtpInputs = document.querySelectorAll('#tab-smtp input, #tab-smtp select');
    const navDelete = document.getElementById('nav-delete');
    if(navDelete) navDelete.style.display = role === "Administrator" ? '' : 'none';
    const navReports = document.getElementById('nav-reports');
    if(navReports) navReports.style.display = role === "Administrator" ? '' : 'none';
    const navCert = document.getElementById('nav-cert');
    if(navCert) navCert.style.display = role === "Administrator" ? '' : 'none';
    // Support card on the start page: only administrators see it
    const startCoffee = document.getElementById('start-coffee');
    if(startCoffee) startCoffee.style.display = role === "Administrator" ? '' : 'none';
    // Only an administrator reads the SMTP settings (the server refuses them to operators)
    const navSmtp = document.getElementById('nav-smtp');
    if(navSmtp) navSmtp.style.display = role === "Administrator" ? '' : 'none';
    // Start page: the deletion card needs the deletion list, which only administrators get
    const dashDelete = document.getElementById('dash-delete');
    if(dashDelete) dashDelete.style.display = role === "Administrator" ? '' : 'none';

    if(role !== "Administrator") {
        document.getElementById('btn-new-tpl').classList.add('hidden');
        const exBox = document.getElementById('exchange-admin-config');
        if(exBox) exBox.classList.add('hidden');
        if(offboardConfigBox) offboardConfigBox.classList.add('hidden');
        if(pwdresetConfigBox) pwdresetConfigBox.classList.add('hidden');
        if(usermgmtConfigBox) usermgmtConfigBox.classList.add('hidden');
        
        if(smtpReadonlyNotice) smtpReadonlyNotice.classList.remove('hidden');
        if(smtpActionButtons) smtpActionButtons.classList.add('hidden');
        smtpInputs.forEach(el => el.disabled = true);
    } else {
        if(offboardConfigBox) offboardConfigBox.classList.remove('hidden');
        const exBoxAdmin = document.getElementById('exchange-admin-config');
        if(exBoxAdmin) exBoxAdmin.classList.remove('hidden');
        if(pwdresetConfigBox) pwdresetConfigBox.classList.remove('hidden');
        if(usermgmtConfigBox) usermgmtConfigBox.classList.remove('hidden');
        
        if(smtpReadonlyNotice) smtpReadonlyNotice.classList.add('hidden');
        if(smtpActionButtons) smtpActionButtons.classList.remove('hidden');
        smtpInputs.forEach(el => el.disabled = false);
    }
}

// Only what the opened section needs is loaded. Settings come from small local files (fast),
// the account lists from the DC - the server reads those from its cache for up to 60 seconds
// per session. force=true ("Aktualisieren", "Neu einlesen") always reads fresh from the DC.
let currentTab = 'start';

// Every request to the server shows the progress bar (after a short delay). Bare fetch() calls in this
// script use window.fetch, so wrapping it once covers all modules.
let apiPending = 0;
let apiBarTimer = null;
function apiBusy(delta) {
    apiPending = Math.max(0, apiPending + delta);
    const bar = document.getElementById('api-progress');
    if(!bar) return;
    if(apiPending > 0) {
        if(!apiBarTimer && !bar.classList.contains('is-on')) {
            apiBarTimer = setTimeout(() => {
                apiBarTimer = null;
                if(apiPending > 0) { bar.classList.add('is-on'); bar.setAttribute('aria-hidden', 'false'); }
            }, 250);
        }
    } else {
        if(apiBarTimer) clearTimeout(apiBarTimer);
        apiBarTimer = null;
        bar.classList.remove('is-on');
        bar.setAttribute('aria-hidden', 'true');
    }
}
function wrapFetchForProgress(win) {
    if(!win || typeof win.fetch !== 'function' || win.__samonboardingFetch) return;
    const original = win.fetch.bind(win);
    win.__samonboardingFetch = true;
    win.fetch = (input, init) => {
        const url = String((input && input.url) || input || '');
        const track = url.startsWith('/api/') && !url.startsWith('/api/me');  // not the keep-alive ping
        if(track) apiBusy(1);
        const done = () => { if(track) apiBusy(-1); };
        return original(input, init).then(r => { done(); return r; }, e => { done(); throw e; });
    };
}
if(typeof window !== 'undefined') wrapFetchForProgress(window);
// Protection against double submission (double click, Enter + click): the same action never runs twice at once
const busyActions = new Set();
async function guarded(key, fn) {
    if(busyActions.has(key)) return;
    busyActions.add(key);
    try { return await fn(); } finally { busyActions.delete(key); }
}
// An error while loading one section must not prevent the others
async function safeLoad(fn, ...args) {
    try { await fn(...args); } catch(e) { console.warn('Laden fehlgeschlagen:', e); }
}
const INFRA_TABS = new Set(['hire', 'templates', 'infra', 'usermgmt', 'offboard', 'pwdreset', 'delete']);
const TAB_LISTS = {
    start: force => loadDashboard(force),
    usermgmt: force => loadUserMgmtUsers(force),
    offboard: async force => { await loadOffboardingUsers(force); await loadOffboardRecords(); },
    pwdreset: force => loadPwdResetUsers(force),
    delete: force => loadDeletionUsers(force),
};
function freshQuery(force) { return force === true ? '?frisch=1' : ''; }
async function refreshAllLdapData(force) {
    force = force === true;
    // The start page needs none of the settings below: its counters start at once and in parallel,
    // so they are visible right after sign-in instead of after OUs, groups and templates
    const dashboard = currentTab === 'start' ? safeLoad(loadDashboard, force) : null;
    // The page's own account list is what the user waits for: it starts at once, in parallel with the
    // settings below (the tables do not depend on them)
    const loadList = currentTab === 'start' ? null : TAB_LISTS[currentTab];
    const list = loadList ? safeLoad(loadList, force) : null;
    const settings = (async () => {
        // The AD structure is the largest query: only the pages that show or edit OUs/groups load it
        // (templates, onboarding, AD structure and the OU settings of the lists). The OU trees of the
        // settings need it first; the small settings files then load side by side.
        if(INFRA_TABS.has(currentTab)) await safeLoad(loadInfrastructure, force);
        await Promise.all([
            safeLoad(loadTemplates),
            currentUserRole === "Administrator" ? safeLoad(loadExchangeConfig) : null,
            safeLoad(loadOffboardingConfig),
            safeLoad(loadPwdResetConfig),
            safeLoad(loadUserMgmtConfig),
            safeLoad(loadSmtpConfig),
            safeLoad(loadDeletionConfig),
        ]);
    })();
    await Promise.all([dashboard, list, settings]);
    await Promise.all([safeLoad(loadReferenceCheck, force), safeLoad(loadHostNotices)]);
}

// Operational notes (administrators only), e.g. an outdated docker-compose.yml on the server
async function loadHostNotices() {
    const box = document.getElementById('host-notice');
    if(!box) return;
    if(currentUserRole !== "Administrator") { box.classList.add('hidden'); return; }
    let notices = [];
    try {
        const res = await fetch('/api/host-notices');
        if(!res.ok) { box.classList.add('hidden'); return; }
        notices = ((await res.json()) || {}).notices || [];
    } catch(e) { box.classList.add('hidden'); return; }
    const compose = notices.find(n => n.kind === 'compose');
    if(!compose) { box.classList.add('hidden'); box.innerHTML = ''; return; }
    box.innerHTML = '<p class="font-semibold mb-1"><i class="fa-solid fa-circle-info mr-1"></i> <span>Die docker-compose.yml auf dem Server ist veraltet.</span></p>'
        + '<p class="text-xs"><span>Stand der Datei:</span> <span translate="no">' + esc(String(compose.have || '–')) + '</span>, <span>benötigt:</span> <span translate="no">' + esc(String(compose.need)) + '</span>. '
        + '<span>Abhilfe: im Ordner der docker-compose.yml „sh update.sh“ ausführen – oder die docker-compose.yml aus dem aktuellen Release herunterladen und „docker compose up -d“ ausführen. Die .env und die Daten bleiben unverändert.</span></p>';
    box.classList.remove('hidden');
}

// Settings refer to OUs/groups by DN. If one of them was renamed, moved or deleted in AD,
// the program shows a note here (administrators only, checked via the objectGUID).
const REF_KINDS = {moved: 'umbenannt oder verschoben', replaced: 'gelöscht und neu angelegt (anderes Objekt)', missing: 'nicht mehr vorhanden'};
async function loadReferenceCheck(force) {
    const box = document.getElementById('ref-warning');
    if(!box) return;
    if(currentUserRole !== "Administrator") { box.classList.add('hidden'); return; }
    let problems = [];
    try {
        const res = await fetch('/api/references' + freshQuery(force));
        if(!res.ok) { box.classList.add('hidden'); return; }
        problems = ((await res.json()) || {}).problems || [];
    } catch(e) { box.classList.add('hidden'); return; }
    if(!problems.length) { box.classList.add('hidden'); box.innerHTML = ''; box.dataset.html = ''; return; }
    const fixable = problems.some(p => p.kind !== 'missing');
    const html = '<p class="font-semibold mb-2"><i class="fa-solid fa-triangle-exclamation mr-1"></i> <span>Einstellungen verweisen auf geänderte OUs oder Gruppen</span></p>'
        + '<ul class="space-y-2 mb-3">' + problems.map(p => '<li' + (p.kind === 'replaced' ? ' data-replaced="' + esc(p.dn) + '"' : '') + '><span translate="no" class="font-mono text-xs break-all">' + esc(p.dn) + '</span> – <span>' + esc(REF_KINDS[p.kind] || p.kind) + '</span>'
            + (p.newDn ? '<br><span>Neu:</span> <span translate="no" class="font-mono text-xs break-all">' + esc(p.newDn) + '</span>' : '')
            + '<ul class="text-xs text-amber-300/80 ml-4 list-disc">' + (p.where || []).map(w => '<li><span>' + esc(w.label) + '</span>' + (w.template ? ' <span translate="no">„' + esc(w.template) + '“</span>' : '') + '</li>').join('') + '</ul></li>').join('') + '</ul>'
        + (fixable ? '<button data-on-click="repairReferences()" class="px-3 py-1.5 bg-amber-500/20 border border-amber-500/50 rounded-lg text-xs font-medium hover:bg-amber-500/30">Neue Namen übernehmen</button> ' : '')
        + (problems.some(p => p.kind === 'missing') ? '<span class="text-xs text-amber-300/80">Nicht mehr vorhandene Objekte bitte in den Einstellungen bzw. im Template von Hand ersetzen.</span>' : '');
    if(box.dataset.html !== html) { box.dataset.html = html; box.innerHTML = html; }  // otherwise the screen reader reads it out again on every change
    box.classList.remove('hidden');
}
let repairBusy = false;
async function repairReferences() {
    if(repairBusy) return;
    const box = document.getElementById('ref-warning');
    const replaced = [...(box ? box.querySelectorAll('[data-replaced]') : [])].map(el => el.dataset.replaced);
    if(replaced.length && !confirm('Diese Objekte wurden gelöscht und unter gleichem Namen neu angelegt. Das neue Objekt übernehmen?\n\n' + replaced.join('\n'))) return;
    repairBusy = true;
    try {
        const res = await fetch('/api/references/repair', {method: 'POST'});
        const data = await res.json().catch(() => ({}));
        if(!res.ok) { showToast(data.detail || 'Verweise konnten nicht angepasst werden.', 'error'); return; }
        showToast('Verweise angepasst: ' + (data.fixed || []).length, 'success');
        await refreshAllLdapData(true);
    } catch(e) {
        showToast('Verweise konnten nicht angepasst werden.', 'error');
    } finally { repairBusy = false; }
}

async function loadPublicConfig() {
    try {
        const res = await fetch('/api/public-config');
        if(res.ok) {
            const cfg = await res.json();
            if (cfg && cfg.domain) {
                document.getElementById('login-domain-text').textContent = cfg.domain;
                document.getElementById('header-domain-text').textContent = cfg.domain;
                document.title = cfg.domain + " - SAMONBOARDING v" + "__APP_VERSION__";
            }
            if (cfg && cfg.idleMinutes) {
                document.getElementById('login-session-hint').textContent = `Verschlüsselte Verbindung. Abmeldung nach ${Number(cfg.idleMinutes)} Minuten ohne Aktivität.`;
            }
        }
    } catch(e) {}
}

let adData = { ous: [], groups: [], users: [], countries: [] };
let templates = [];
let lastCreatedUser = {};

function handleLoginKey(event) {
    if(event.key === 'Enter') {
        performLogin();
    }
}

// ---------------------------------------------------------------
// Session: logout after inactivity (the server also checks on its own)
// ---------------------------------------------------------------
let idleLimitMs = 30 * 60000;
let lastActivity = Date.now();
let lastKeepAlive = Date.now();
let idleTimer = null;
let sessionEnding = false;

function appVisible() {
    const app = document.getElementById('app-screen');
    return !!app && !app.classList.contains('hidden');
}

// Several tabs share one session: activity in one tab counts for all (otherwise a forgotten tab
// would, after 30 minutes, also log out the tab that is currently in use)
const ACTIVITY_KEY = 'samonboarding.activity';
let lastShared = 0;
function sharedActivity() {
    try { return Number(localStorage.getItem(ACTIVITY_KEY)) || 0; } catch(e) { return 0; }
}

function noteActivity() {
    lastActivity = Date.now();
    if (lastActivity - lastShared > 10000) {
        lastShared = lastActivity;
        try { localStorage.setItem(ACTIVITY_KEY, String(lastActivity)); } catch(e) {}
    }
    // Whoever is active (e.g. filling in a long form) also stays logged in on the server
    if (appVisible() && lastActivity - lastKeepAlive > 5 * 60000) {
        lastKeepAlive = lastActivity;
        fetch('/api/me').catch(() => {});
    }
}

function startIdleWatch(minutes) {
    idleLimitMs = Math.max(1, Number(minutes) || 30) * 60000;
    lastActivity = lastKeepAlive = Date.now();
    if (idleTimer) return;
    ['pointerdown', 'keydown', 'wheel', 'touchstart', 'mousemove'].forEach(ev => document.addEventListener(ev, noteActivity, {passive: true}));
    idleTimer = setInterval(() => {
        if (appVisible() && Date.now() - Math.max(lastActivity, sharedActivity()) > idleLimitMs) sessionEnded(true);
    }, 15000);
}

async function sessionEnded(idle) {
    if (sessionEnding) return;
    sessionEnding = true;
    if (idle) { try { await fetch('/api/logout', {method: 'POST'}); } catch(e) {} }
    // Name the minutes only for inactivity; otherwise (maximum duration, logout in another tab) a general message
    try { sessionStorage.setItem('samonboarding.ended', idle ? String(Math.round(idleLimitMs / 60000)) : '0'); } catch(e) {}
    location.reload();
}

function showSessionEndedNotice() {
    let minutes = null;
    try { minutes = sessionStorage.getItem('samonboarding.ended'); sessionStorage.removeItem('samonboarding.ended'); } catch(e) {}
    if (minutes === '0') showToast('Ihre Sitzung ist beendet. Bitte erneut anmelden.', 'info');
    else if (minutes) showToast(`Sie wurden abgemeldet, weil ${minutes} Minuten lang nichts passiert ist.`, 'info');
}

// Sign-in takes a moment (bind and role check at the DC): show that something is happening
function setLoginBusy(on) {
    const btn = document.getElementById('btn-login');
    if(btn) {
        btn.disabled = on;
        btn.setAttribute('aria-busy', on ? 'true' : 'false');
        btn.innerHTML = on ? '<i class="fa-solid fa-circle-notch fa-spin mr-2" aria-hidden="true"></i><span>Anmeldung läuft …</span>' : '<span>Anmelden</span>';
    }
    const status = document.getElementById('login-status');
    if(status) status.classList.toggle('hidden', !on);
}

async function performLogin() {
    const btn = document.getElementById('btn-login');
    if(btn && btn.disabled) return;
    const username = document.getElementById('login-user').value;
    const password = document.getElementById('login-pass').value;
    setLoginBusy(true);
    let res;
    try {
        res = await fetch('/api/login', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({username, password}) });
    } catch(e) {
        setLoginBusy(false);
        alert('Der Server ist nicht erreichbar.');
        return;
    }
    setLoginBusy(false);
    if(res.ok) {
        const data = await res.json();
        currentUserRole = data.role;
        currentLoggedInUsername = data.user.toLowerCase();
        document.getElementById('login-screen').classList.add('hidden');
        document.getElementById('app-screen').classList.remove('hidden');
        document.getElementById('user-display').textContent = data.user;
        setAvatar(data.user);
        document.getElementById('role-display').textContent = data.role;
        showDirectory(data.directory);
        startIdleWatch(data.idleMinutes);
        startDashAutoRefresh();
        
        setupRoleVisibility(data.role);
        checkNews();
        await refreshAllLdapData();
    } else { 
        const err = await res.json();
        alert(err.detail || "Login fehlgeschlagen."); 
    }
}

async function loadSmtpConfig() {
    const res = await fetch('/api/smtp-config');
    if(res.ok) {
        const cfg = await res.json();
        document.getElementById('smtp-enabled').checked = cfg.enabled;
        document.getElementById('smtp-displayname').value = cfg.displayName || '';
        document.getElementById('smtp-host').value = cfg.host || '';
        document.getElementById('smtp-port').value = cfg.port || 587;
        document.getElementById('smtp-user').value = cfg.username || '';
        document.getElementById('smtp-pass').value = cfg.password || '';
        document.getElementById('smtp-from').value = cfg.fromEmail || '';
        document.getElementById('smtp-cc').value = cfg.ccRecipients || '';
        document.getElementById('smtp-tls').value = cfg.tlsMode || 'Auto';
        document.getElementById('smtp-notify-offboarding').checked = cfg.notifyOffboarding || false;
        document.getElementById('smtp-notify-pwdreset').checked = cfg.notifyPwdReset || false;
        document.getElementById('smtp-notify-usermgmt').checked = cfg.notifyUserMgmt || false;
        document.getElementById('smtp-notify-deletion').checked = cfg.notifyDeletion || false;
    }
}

async function saveSmtpConfig() {
    if(currentUserRole !== "Administrator") return alert("Keine Berechtigung.");
    const data = {
        enabled: document.getElementById('smtp-enabled').checked,
        displayName: document.getElementById('smtp-displayname').value,
        host: document.getElementById('smtp-host').value,
        port: parseInt(document.getElementById('smtp-port').value) || 587,
        username: document.getElementById('smtp-user').value,
        password: document.getElementById('smtp-pass').value,
        fromEmail: document.getElementById('smtp-from').value,
        ccRecipients: document.getElementById('smtp-cc').value,
        tlsMode: document.getElementById('smtp-tls').value,
        notifyOffboarding: document.getElementById('smtp-notify-offboarding').checked,
        notifyPwdReset: document.getElementById('smtp-notify-pwdreset').checked,
        notifyUserMgmt: document.getElementById('smtp-notify-usermgmt').checked,
        notifyDeletion: document.getElementById('smtp-notify-deletion').checked
    };
    const res = await fetch('/api/smtp-config', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(data) });
    if(res.ok) {
        alert("SMTP-Einstellungen erfolgreich gespeichert!");
    } else {
        const err = await res.json();
        alert(err.detail || "Fehler beim Speichern der SMTP-Einstellungen.");
    }
}

const MAIL_MODES = ['required', 'optional', 'exchange', 'cloud'];

function currentMailMode() {
    const sel = document.getElementById('hire-template');
    const tpl = templates.find(t => t.id == (sel ? sel.value : null));
    return tpl && MAIL_MODES.includes(tpl.mailMode) ? tpl.mailMode : 'required';
}

function applyMailMode() {
    const mode = currentMailMode();
    const box = document.getElementById('hire-mail-box');
    const input = document.getElementById('hire-mail');
    const label = document.getElementById('lbl-mail-onboard');
    if(!box || !input) return;
    const hidden = mode === 'exchange' || mode === 'cloud';
    box.classList.toggle('hidden', hidden);
    input.required = mode === 'required';
    if(label) label.textContent = mode === 'required' ? 'E-Mail-Adresse *' : 'E-Mail-Adresse (optional)';
    if(hidden) input.value = '';
}

function exchangeFormData() {
    return {
        enabled: document.getElementById('ex-enabled').checked,
        server: document.getElementById('ex-server').value.trim(),
        port: parseInt(document.getElementById('ex-port').value) || 443,
        ssl: document.getElementById('ex-ssl').checked,
        verifyCert: document.getElementById('ex-verify').checked,
        auth: document.getElementById('ex-auth').value,
        database: document.getElementById('ex-db').value.trim(),
        domainController: document.getElementById('ex-dc').value.trim()
    };
}

async function loadExchangeConfig() {
    try {
        const res = await fetch('/api/exchange-config');
        if(!res.ok) return;
        const c = await res.json();
        document.getElementById('ex-enabled').checked = !!c.enabled;
        document.getElementById('ex-server').value = c.server || '';
        document.getElementById('ex-port').value = c.port || 443;
        document.getElementById('ex-ssl').checked = c.ssl !== false;
        document.getElementById('ex-verify').checked = c.verifyCert !== false;
        document.getElementById('ex-auth').value = c.auth || 'negotiate';
        document.getElementById('ex-db').value = c.database || '';
        document.getElementById('ex-dc').value = c.domainController || '';
        document.getElementById('ex-status').textContent = c.verifyCert === false ? 'Achtung: Die Zertifikatsprüfung ist ausgeschaltet.' : '';
    } catch(e) {}
}

async function saveExchangeConfig() {
    if(currentUserRole !== "Administrator") return alert("Keine Berechtigung.");
    const res = await fetch('/api/exchange-config', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(exchangeFormData()) });
    const result = await res.json();
    if(res.ok) {
        alert("Exchange-Einstellungen gespeichert!");
        await loadExchangeConfig();
    } else {
        alert(result.detail || "Fehler beim Speichern.");
    }
}

async function testExchangeConfig() {
    if(currentUserRole !== "Administrator") return alert("Keine Berechtigung.");
    const status = document.getElementById('ex-status');
    status.textContent = 'Verbindung wird geprüft...';
    let res, result;
    try {
        res = await fetch('/api/exchange-config/test', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(exchangeFormData()) });
        result = await res.json();
    } catch(e) {
        status.textContent = 'Verbindungsfehler.';
        return;
    }
    status.textContent = res.ok ? (result.message || 'Verbindung steht.') : (result.detail || 'Verbindung fehlgeschlagen.');
}

async function loadMailDetect() {
    const box = document.getElementById('tpl-mail-detect');
    if(!box) return;
    let d = {};
    try {
        const res = await fetch('/api/onboarding-config/detect');
        if(res.ok) d = await res.json();
    } catch(e) {}
    const found = [];
    if(d.exchange) found.push('Exchange');
    if(d.entra) found.push('Azure/Entra-Synchronisation (MSOL_-Konto)');
    if(found.length) box.textContent = 'Erkannt: ' + found.join(' und ') + '. Empfehlung: „Exchange im eigenen Haus“ bzw. „Microsoft 365“.';
    else if(d.exchange === false && d.entra === false) box.textContent = 'Weder Exchange noch Azure/Entra-Synchronisation erkannt. Empfehlung: „Eigener Mailserver“.';
    else box.textContent = 'Automatische Erkennung nicht möglich (fehlende Rechte). Bitte selbst entscheiden.';
}

// Show the OU list: DNs are data (do not translate), the note shown without OUs is translated
function setOuSummary(el, dns) {
    if(!el) return;
    el.setAttribute('translate', dns.length ? 'no' : 'yes');
    el.textContent = dns.length ? dns.join(' | ') : 'Keine konfiguriert';
}

async function loadOffboardingConfig() {
    const res = await fetch('/api/offboarding-config');
    if(res.ok) {
        const cfg = await res.json();
        const srcSel = document.getElementById('off-cfg-source');
        const tgtSel = document.getElementById('off-cfg-target');
        const sourcesBadge = document.getElementById('off-summary-sources');
        const targetBadge = document.getElementById('off-summary-target');

        const sources = cfg.sourceOus || [];
        if(srcSel) adTreeSetSelected(srcSel.id, sources);
        if(tgtSel) tgtSel.value = cfg.targetOu || '';

        if(sourcesBadge) setOuSummary(sourcesBadge, sources);
        if(targetBadge) setOuSummary(targetBadge, cfg.targetOu ? [cfg.targetOu] : []);
    }
}

async function saveOffboardingConfig() {
    const srcSel = document.getElementById('off-cfg-source');
    const sourceOus = srcSel ? adTreeGetSelected(srcSel.id) : [];

    const data = {
        sourceOus: sourceOus,
        targetOu: document.getElementById('off-cfg-target').value
    };
    const res = await fetch('/api/offboarding-config', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(data) });
    if(res.ok) {
        alert("Offboarding-Konfiguration erfolgreich gespeichert!");
        await refreshAllLdapData();
    } else {
        const err = await res.json();
        alert(err.detail || "Fehler beim Speichern der Konfiguration.");
    }
}

async function loadPwdResetConfig() {
    const res = await fetch('/api/pwdreset-config');
    if(res.ok) {
        const cfg = await res.json();
        const srcSel = document.getElementById('pwdreset-cfg-source');
        const sourcesBadge = document.getElementById('pwdreset-summary-sources');

        const sources = cfg.sourceOus || [];
        if(srcSel) adTreeSetSelected(srcSel.id, sources);
        if(sourcesBadge) setOuSummary(sourcesBadge, sources);
    }
}

async function savePwdResetConfig() {
    const srcSel = document.getElementById('pwdreset-cfg-source');
    const sourceOus = srcSel ? adTreeGetSelected(srcSel.id) : [];

    const data = { sourceOus: sourceOus };
    const res = await fetch('/api/pwdreset-config', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(data) });
    if(res.ok) {
        alert("Passwort-Reset Konfiguration erfolgreich gespeichert!");
        await refreshAllLdapData();
    } else {
        const err = await res.json();
        alert(err.detail || "Fehler beim Speichern der Konfiguration.");
    }
}

async function loadUserMgmtConfig() {
    const res = await fetch('/api/usermgmt-config');
    if(res.ok) {
        const cfg = await res.json();
        const srcSel = document.getElementById('usermgmt-cfg-source');
        const tgtSel = document.getElementById('usermgmt-cfg-target');
        const grpSel = document.getElementById('usermgmt-cfg-groupou');

        const sources = cfg.sourceOus || [];
        const targets = cfg.targetOus || [];
        const groupOus = cfg.groupOus || [];
        globalAllowedTargetOus = targets;

        if(srcSel) adTreeSetSelected(srcSel.id, sources);
        if(tgtSel) adTreeSetSelected(tgtSel.id, targets);
        if(grpSel) adTreeSetSelected(grpSel.id, groupOus);

        setOuSummary(document.getElementById('usermgmt-summary-sources'), sources);
        setOuSummary(document.getElementById('usermgmt-summary-targets'), targets);
        setOuSummary(document.getElementById('usermgmt-summary-groups'), groupOus);
    }
}

async function saveUserMgmtConfig() {
    const srcSel = document.getElementById('usermgmt-cfg-source');
    const tgtSel = document.getElementById('usermgmt-cfg-target');
    const grpSel = document.getElementById('usermgmt-cfg-groupou');

    const data = {
        sourceOus: srcSel ? adTreeGetSelected(srcSel.id) : [],
        targetOus: tgtSel ? adTreeGetSelected(tgtSel.id) : [],
        groupOus: grpSel ? adTreeGetSelected(grpSel.id) : []
    };

    const res = await fetch('/api/usermgmt-config', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(data) });
    if(res.ok) {
        alert("Benutzerverwaltungs-Konfiguration erfolgreich gespeichert!");
        await refreshAllLdapData();
    } else {
        const err = await res.json();
        alert(err.detail || "Fehler beim Speichern.");
    }
}

async function loadUserMgmtUsers(force) {
    const res = await fetch('/api/usermgmt/users' + freshQuery(force));
    if(res.ok) {
        const data = await res.json();
        cachedUserMgmtUsers = data.users || [];
        renderUserMgmtTable(cachedUserMgmtUsers);
    }
}

function filterUserMgmtTable() {
    const query = document.getElementById('usermgmt-search').value.toLowerCase();
    const filtered = cachedUserMgmtUsers.filter(u => 
        u.name.toLowerCase().includes(query) || 
        u.sam.toLowerCase().includes(query) || 
        u.currentOu.toLowerCase().includes(query) ||
        u.groups.some(g => g.toLowerCase().includes(query))
    );
    renderUserMgmtTable(filtered);
}

function renderUserMgmtTable(users) {
    const tbody = document.getElementById('usermgmt-user-list');
    document.getElementById('usermgmt-count').textContent = `${users.length} Konten`;

    if(users.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" class="p-6 text-center text-slate-500 italic">Keine passenden Benutzer gefunden oder keine Quell-OUs konfiguriert.</td></tr>`;
        return;
    }

    let html = "";
    users.forEach(u => {
        let groupsHtml = '<span class="text-slate-500 italic">Keine</span>';
        if (u.groups && u.groups.length > 0) {
            const maxShow = 3;
            const displayed = u.groups.slice(0, maxShow).map(g => `<span class="px-1.5 py-0.5 rounded bg-slate-800 text-cyan-300 border border-slate-700 text-[10px] mr-1 inline-block my-0.5">${nt(g)}</span>`).join('');
            const overflow = u.groups.length > maxShow ? `<span class="text-[10px] text-slate-400" title="${esc(u.groups.join(', '))}">+${u.groups.length - maxShow} weitere</span>` : '';
            groupsHtml = displayed + overflow;
        }

        html += `
            <tr class="hover:bg-slate-900/40">
                <td class="p-3.5 text-white font-sans font-medium">${nt(u.name)}</td>
                <td class="p-3.5 text-cyan-400">${nt(u.sam)}</td>
                <td class="p-3.5 text-slate-300 truncate max-w-xs" title="${esc(u.currentOu)}">${nt(u.currentOu || '-')}</td>
                <td class="p-3.5 max-w-xs">${groupsHtml}</td>
                <td class="p-3.5 text-right space-x-2 whitespace-nowrap">
                    <button data-dn="${esc(u.dn)}" data-sam="${esc(u.sam)}" data-on-click="openMoveUserModal(this.dataset.dn, this.dataset.sam)" class="btn-primary px-3 py-1.5 text-white rounded-lg font-medium transition-all"><i class="fa-solid fa-folder-tree mr-1"></i> Verschieben</button>
                    <button data-dn="${esc(u.dn)}" data-sam="${esc(u.sam)}" data-on-click="openUserGroupsModal(this.dataset.dn, this.dataset.sam)" class="px-3 py-1.5 bg-amber-600 hover:bg-amber-500 text-white rounded-lg font-medium transition-all shadow"><i class="fa-solid fa-user-group mr-1"></i> Gruppen</button>
                </td>
            </tr>
        `;
    });
    tbody.innerHTML = html;
}

function esc(value) {
    return String(value === null || value === undefined ? '' : value).replace(/[&<>"']/g, ch => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[ch]));
}

function openMoveUserModal(dn, sam) {
    document.getElementById('move-user-dn').value = dn;
    const targetSelect = document.getElementById('move-target-ou');
    const ousToUse = adData.ous.filter(o => globalAllowedTargetOus.includes(o.dn));

    if (ousToUse.length === 0) {
        targetSelect.innerHTML = `<option value="">-- Keine Ziel-OUs vom Administrator freigegeben --</option>`;
    } else {
        targetSelect.innerHTML = ousToUse.map(ou => `<option value="${esc(ou.dn)}">${nt(ou.name)} (${nt(ou.dn)})</option>`).join('');
    }
    
    document.getElementById('move-user-modal').classList.remove('hidden');
}

async function submitMoveUser() {
    const userDn = document.getElementById('move-user-dn').value;
    const targetOu = document.getElementById('move-target-ou').value;

    if(!targetOu) {
        alert("Bitte wählen Sie eine gültige Ziel-OU aus.");
        return;
    }

    const res = await fetch('/api/usermgmt/move', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ userDn, targetOu }) });
    const result = await res.json();
    if(res.ok) {
        document.getElementById('move-user-modal').classList.add('hidden');
        alert(result.message || "Benutzer erfolgreich verschoben!");
        await refreshAllLdapData();
    } else {
        alert(result.detail || "Fehler beim Verschieben.");
    }
}

let groupsRequest = 0;
async function openUserGroupsModal(dn, sam) {
    const mine = ++groupsRequest;  // only the most recently clicked person counts (discard slow responses)
    const res = await fetch(`/api/usermgmt/user-groups?userDn=${encodeURIComponent(dn)}`);
    if(mine !== groupsRequest) return;
    document.getElementById('groups-user-dn').value = dn;
    if(res.ok) {
        const data = await res.json();
        const memberOf = data.userMemberOf.map(x => x.toLowerCase());
        const available = data.availableGroups || [];

        let html = "";
        if(available.length === 0) {
            html = `<div class="text-slate-500 italic p-2">Keine Gruppen in den konfigurierten Gruppen-OUs gefunden.</div>`;
        } else {
            available.forEach(g => {
                const isMember = memberOf.includes(g.dn.toLowerCase());
                html += `
                    <label class="flex items-center gap-2.5 p-2 bg-slate-900 rounded-lg hover:bg-slate-800 cursor-pointer">
                        <input type="checkbox" name="group-chk" value="${esc(g.dn)}" ${isMember ? 'checked' : ''} data-original="${isMember}" class="w-4 h-4 rounded bg-slate-950 border-slate-800 text-amber-600">
                        <span class="text-white font-medium">${nt(g.name)}</span>
                        <span class="text-[10px] text-slate-500 font-mono ml-auto truncate max-w-xs">${nt(g.dn)}</span>
                    </label>
                `;
            });
        }
        document.getElementById('user-groups-checkboxes').innerHTML = html;
        document.getElementById('user-groups-modal').classList.remove('hidden');
    } else {
        alert("Fehler beim Laden der Gruppen.");
    }
}

function submitUpdateUserGroups() { return guarded('groups', _submitUpdateUserGroups); }
async function _submitUpdateUserGroups() {
    const userDn = document.getElementById('groups-user-dn').value;
    const checkboxes = document.querySelectorAll('input[name="group-chk"]');
    
    const addGroupDns = [];
    const removeGroupDns = [];

    checkboxes.forEach(chk => {
        const isChecked = chk.checked;
        const wasOriginal = chk.getAttribute('data-original') === 'true';
        if(isChecked && !wasOriginal) addGroupDns.push(chk.value);
        if(!isChecked && wasOriginal) removeGroupDns.push(chk.value);
    });

    const res = await fetch('/api/usermgmt/update-groups', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ userDn, addGroupDns, removeGroupDns }) });
    const result = await res.json();
    if(res.ok) {
        document.getElementById('user-groups-modal').classList.add('hidden');
        alert(result.message || "Gruppen erfolgreich aktualisiert!");
        await refreshAllLdapData();
    } else {
        alert(result.detail || "Fehler beim Aktualisieren der Gruppen.");
    }
}

async function loadOffboardingUsers(force) {
    const res = await fetch('/api/offboarding/users' + freshQuery(force));
    if(res.ok) {
        const data = await res.json();
        cachedOffboardUsers = data.users || [];
        filterOffboardTable();
    }
}

const OFF_BATCH_MAX = 25;
const offSelected = new Set();

function offboardable(u) {
    return !u.disabled && !u.protected && u.sam.toLowerCase() !== currentLoggedInUsername;
}

function updateOffboardSelection() {
    const n = offSelected.size;
    const cnt = document.getElementById('off-sel-count');
    if(cnt) cnt.textContent = n;
    const btn = document.getElementById('off-batch-btn');
    if(btn) btn.disabled = n === 0 || busyActions.has('offboard-batch');
}

function toggleOffboardSelect(dn, on) {
    if(on) {
        if(offSelected.size >= OFF_BATCH_MAX) {
            alert(`Pro Durchlauf sind höchstens ${OFF_BATCH_MAX} Konten erlaubt.`);
            filterOffboardTable();
            return;
        }
        offSelected.add(dn);
    } else {
        offSelected.delete(dn);
    }
    updateOffboardSelection();
}

function visibleOffboardUsers() {
    const q = document.getElementById('offboard-search').value.toLowerCase();
    return cachedOffboardUsers.filter(u => offboardable(u) && (u.name.toLowerCase().includes(q) || u.sam.toLowerCase().includes(q) || (u.mail && u.mail.toLowerCase().includes(q))));
}

function toggleSelectAllOffboard(on) {
    const visible = visibleOffboardUsers();
    if(!on) visible.forEach(u => offSelected.delete(u.dn));
    else {
        let skipped = 0;
        visible.forEach(u => { if(offSelected.size < OFF_BATCH_MAX) offSelected.add(u.dn); else if(!offSelected.has(u.dn)) skipped++; });
        if(skipped) alert(`Es wurden ${OFF_BATCH_MAX} Konten ausgewählt, ${skipped} weitere nicht (Obergrenze pro Durchlauf).`);
    }
    filterOffboardTable();
}

function executeOffboardBatch() { return guarded('offboard-batch', _executeOffboardBatch); }
async function _executeOffboardBatch() {
    const dns = [...offSelected];
    if(dns.length === 0) return;
    const names = dns.map(dn => { const u = cachedOffboardUsers.find(x => x.dn === dn); return u ? `${u.name} (${u.sam})` : dn; });
    const shown = names.slice(0, 10).map(n => '- ' + n).join('\n') + (names.length > 10 ? `\n... und ${names.length - 10} weitere` : '');
    if(!confirm(`Möchten Sie ${dns.length} Konten wirklich offboarden?\n\n${shown}\n\n- Konten werden deaktiviert\n- Aus allen Gruppen entfernt\n- In die Ziel-OU verschoben\n- Keine Löschung!`)) return;
    const btn = document.getElementById('off-batch-btn');
    btn.disabled = true;
    let res, result;
    try {
        res = await fetch('/api/offboarding/execute-batch', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ userDns: dns }) });
        result = await res.json();
    } catch(e) {
        alert("Verbindungsfehler beim Offboarding.");
        updateOffboardSelection();
        return;
    }
    if(!res.ok) {
        alert(result.detail || "Fehler beim Offboarding.");
        updateOffboardSelection();
        return;
    }
    let msg = `${result.done.length} von ${dns.length} Konten wurden offgeboardet.`;
    const groupIssues = result.done.filter(d => d.failedGroups && d.failedGroups.length);
    if(groupIssues.length) msg += `\n\nHinweis: Bei ${groupIssues.length} Konto/Konten konnten nicht alle Gruppen entfernt werden: ` + groupIssues.map(d => d.name).join(', ');
    if(result.failed.length) msg += `\n\nNICHT offgeboardet:\n` + result.failed.map(f => `- ${f.name}: ${f.error}`).join('\n');
    offSelected.clear();
    alert(msg);
    await refreshAllLdapData();
}

// ---------------------------------------------------------------
// Undo offboarding
// ---------------------------------------------------------------
let offRecords = [];
let restorePlan = null;

function fmtDateTime(iso, seconds) {
    const d = new Date(iso);
    if(isNaN(d.getTime())) return String(iso || '');
    const loc = uiLang === 'en' ? 'en-GB' : 'de-DE';
    return d.toLocaleDateString(loc) + ' ' + d.toLocaleTimeString(loc, Object.assign({hour: '2-digit', minute: '2-digit'}, seconds ? {second: '2-digit'} : {}));
}

async function loadOffboardRecords() {
    try {
        const res = await fetch('/api/offboarding/records');
        if(!res.ok) return;
        const data = await res.json();
        offRecords = data.records || [];
        const ret = document.getElementById('off-restore-retention');
        const days = Number(data.retentionDays) || 0;
        if(ret) {
            ret.textContent = days > 0 ? `Datenschutz: Einträge werden ${days} Tage nach dem Offboarding automatisch entfernt.` : '';
            ret.classList.toggle('hidden', days <= 0);
        }
    } catch(e) { offRecords = []; }
    renderOffboardRecords();
}

function renderOffboardRecords() {
    const tbody = document.getElementById('off-restore-list');
    const cnt = document.getElementById('off-restore-count');
    if(cnt) cnt.textContent = offRecords.length === 1 ? '1 Konto' : `${offRecords.length} Konten`;
    if(!tbody) return;
    if(offRecords.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="p-6 text-center text-slate-500">Keine offgeboardeten Konten gespeichert. Konten, die vor Version 1.19 offgeboardet wurden, lassen sich nicht automatisch wiederherstellen.</td></tr>';
        return;
    }
    tbody.innerHTML = offRecords.map(r => {
        const groups = r.groups && r.groups.length ? `<span translate="no">${r.groups.map(esc).join(', ')}</span>` : '<span class="text-slate-500">keine</span>';
        const dismiss = currentUserRole === 'Administrator'
            ? `<button data-on-click="dismissRecord(${Number(r.id)})" class="icon-btn" title="Eintrag verwerfen" aria-label="Eintrag verwerfen"><i class="fa-solid fa-xmark"></i></button>` : '';
        return `<tr class="hover:bg-slate-900/40">
            <td class="p-3.5"><div class="text-white font-medium">${nt(r.name || r.sam)}</div><div class="text-cyan-300">${nt(r.sam)}</div></td>
            <td class="p-3.5 font-mono text-[11px] text-slate-300">${nt(r.originalOu)}</td>
            <td class="p-3.5 text-slate-300 max-w-[14rem]">${groups}</td>
            <td class="p-3.5 text-slate-400 whitespace-nowrap">${esc(fmtDateTime(r.offboardedAt))}<div class="text-[11px] text-slate-500">von ${nt(r.offboardedBy || '-')}</div></td>
            <td class="p-3.5 text-right whitespace-nowrap"><button data-on-click="openRestore(${Number(r.id)})" class="px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg font-medium"><i class="fa-solid fa-clock-rotate-left mr-1"></i> Wiederherstellen</button> ${dismiss}</td>
        </tr>`;
    }).join('');
}

async function openRestore(id, targetOu) {
    const body = document.getElementById('restore-body');
    const btn = document.getElementById('restore-exec-btn');
    document.getElementById('restore-modal').classList.remove('hidden');
    body.innerHTML = '<div class="text-slate-400"><i class="fa-solid fa-spinner fa-spin mr-1"></i> Prüfe, was wiederhergestellt würde ...</div>';
    btn.disabled = true;
    restorePlan = null;
    let res, data;
    try {
        const q = targetOu ? '?targetOu=' + encodeURIComponent(targetOu) : '';
        res = await fetch(`/api/offboarding/records/${Number(id)}/preview${q}`);
        data = await res.json();
    } catch(e) {
        body.innerHTML = '<div class="text-rose-400">Verbindungsfehler.</div>';
        return;
    }
    if(!res.ok) { body.innerHTML = `<div class="text-rose-400">${esc(data.detail || 'Vorschau fehlgeschlagen.')}</div>`; return; }
    restorePlan = data;
    renderRestorePlan();
}

function renderRestorePlan() {
    const p = restorePlan;
    const body = document.getElementById('restore-body');
    const options = [...new Set([p.originalOu, ...(p.ouOptions || []), p.targetOu])].filter(Boolean);
    const ouSelect = `<select id="restore-ou" data-on-change="onRestoreOuChange()" class="w-full bg-slate-950 border border-slate-800 rounded-xl p-2.5 text-white text-xs font-mono">${options.map(o => `<option value="${esc(o)}" ${o === p.targetOu ? 'selected' : ''}>${nt(o)}${o === p.originalOu ? '  (vorher)' : ''}</option>`).join('')}</select>`;
    const stat = {add: ['fa-plus', 'text-emerald-400', 'wird wieder zugewiesen'], member: ['fa-check', 'text-slate-400', 'bereits Mitglied'], missing: ['fa-triangle-exclamation', 'text-amber-400', 'gibt es nicht mehr']};
    const groups = (p.groups || []).length
        ? p.groups.map(g => { const s = stat[g.status] || stat.add; return `<li class="flex items-center gap-2"><i class="fa-solid ${s[0]} ${s[1]} w-4 text-center"></i><span class="text-white">${nt(g.name)}</span><span class="text-slate-500 text-xs">${s[2]}</span></li>`; }).join('')
        : '<li class="text-slate-500">Keine Gruppen gespeichert.</li>';
    const blockers = (p.blockers || []).map(b => `<div class="p-3 rounded-xl border border-rose-500/30 bg-rose-500/5 text-rose-300 text-xs">${esc(b)}</div>`).join('');
    const notes = (p.notes || []).map(n => `<div class="text-xs text-amber-300/90"><i class="fa-solid fa-circle-info mr-1"></i>${esc(n)}</div>`).join('');
    body.innerHTML = `
        <div><div class="text-white font-semibold text-base">${nt(p.name || p.sam)} <span class="text-cyan-300 font-normal text-sm">${nt(p.sam)}</span></div>
        <div class="text-xs text-slate-400">Offgeboardet am ${esc(fmtDateTime(p.offboardedAt))} von ${nt(p.offboardedBy || '-')}</div></div>
        <div><label class="field-label" for="restore-ou">Zurück in die OU</label>${ouSelect}</div>
        <div><div class="field-label">Gruppen</div><ul class="space-y-1.5">${groups}</ul></div>
        <div class="text-xs ${p.enable ? 'text-emerald-300' : 'text-slate-400'}"><i class="fa-solid ${p.enable ? 'fa-toggle-on' : 'fa-toggle-off'} mr-1"></i>${p.enable ? 'Das Konto wird wieder aktiviert. Das bisherige Passwort gilt weiter.' : 'Das Konto wird nicht aktiviert.'}</div>
        ${notes}${blockers}`;
    document.getElementById('restore-exec-btn').disabled = (p.blockers || []).length > 0;
}

function onRestoreOuChange() {
    if(!restorePlan) return;
    openRestore(restorePlan.id, document.getElementById('restore-ou').value);
}

// ---------------------------------------------------------------
// News: changelog of the installed version (comes from our own server, not from the internet).
// A small dot on the menu entry if a new version was installed since it was last read
// (orange for security updates). The read state is stored only in the browser.
// ---------------------------------------------------------------
const NEWS_KEY = 'samonboarding.newsSeen';
let newsData = null, newsLang = null, newsUnread = new Set();
function newsSeen() { try { return localStorage.getItem(NEWS_KEY) || ''; } catch(e) { return ''; } }
function setNewsSeen(v) { try { localStorage.setItem(NEWS_KEY, v); } catch(e) {} }
function versionParts(v) {  // '1.48.0-s2' -> [1, 48, 0, 2]: security update = same program, new packages
    const [base, s] = String(v || '').split('-s');
    const p = base.split('.').map(n => parseInt(n, 10) || 0);
    return [p[0] || 0, p[1] || 0, p[2] || 0, parseInt(s, 10) || 0];
}
function versionNewer(a, b) {
    const x = versionParts(a), y = versionParts(b);
    for(let i = 0; i < 4; i++) { if(x[i] !== y[i]) return x[i] > y[i]; }
    return false;
}
async function loadNews() {
    const lang = uiLang === 'en' ? 'en' : 'de';
    if(newsData && newsLang === lang) return newsData;
    try {
        const res = await fetch('/api/news?lang=' + lang);
        if(!res.ok) return null;
        newsData = await res.json(); newsLang = lang;
    } catch(e) { return null; }
    return newsData;
}
async function checkNews() {
    const dot = document.getElementById('news-dot');
    const data = await loadNews();
    if(!dot || !data) return;
    const seen = newsSeen();
    if(!seen) { setNewsSeen(data.version); return; }  // first use: no note about old versions
    const unread = (data.entries || []).filter(e => versionNewer(e.version, seen));
    newsUnread = new Set(unread.map(e => e.version));
    dot.classList.toggle('hidden', unread.length === 0);
    dot.classList.toggle('is-security', unread.some(e => (e.items || []).some(i => i.kind === 'security')));
}
function newsInline(text) {
    return esc(text).replace(/`([^`]+)`/g, '<code>$1</code>').replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>').replace(/\*([^*]+)\*/g, '<em>$1</em>');
}
function renderNews() {
    const list = document.getElementById('news-list');
    if(!list) return;
    const entries = (newsData && newsData.entries) || [];
    if(!entries.length) { list.innerHTML = '<p class="text-xs text-slate-500">' + esc(tr('Keine Neuigkeiten vorhanden.')) + '</p>'; return; }
    const chip = {fix: tr('Behoben'), security: tr('Sicherheit')};
    list.innerHTML = entries.map(e => '<div class="news-entry">'
        + '<p class="text-xs text-slate-400 mb-1.5"><span class="font-semibold text-slate-200" translate="no">' + esc(e.title) + '</span>'
        + (e.date ? ' · <span translate="no">' + esc(e.date) + '</span>' : '')
        + (newsUnread.has(e.version) ? ' <span class="news-chip news-chip-unread">' + esc(tr('Neu')) + '</span>' : '') + '</p>'
        + '<ul class="space-y-1" translate="no">' + (e.items || []).map(i => '<li>'
            + (chip[i.kind] ? '<span class="news-chip news-chip-' + esc(i.kind) + '">' + esc(chip[i.kind]) + '</span>' : '')
            + newsInline(i.text)
            + ((i.sub || []).length ? '<ul>' + i.sub.map(t => '<li>' + newsInline(t) + '</li>').join('') + '</ul>' : '')
            + '</li>').join('') + '</ul></div>').join('');
}
async function openNews() {
    toggleSidebar(false);
    document.getElementById('news-modal').classList.remove('hidden');
    await loadNews();
    renderNews();
    if(newsData) setNewsSeen(newsData.version);
    const dot = document.getElementById('news-dot');
    if(dot) dot.classList.add('hidden');
}
function closeNews() {
    document.getElementById('news-modal').classList.add('hidden');
    newsUnread = new Set();
}

async function openPrivacy() {
    toggleSidebar(false);
    document.getElementById('privacy-modal').classList.remove('hidden');
    const isAdmin = currentUserRole === 'Administrator' && !document.getElementById('app-screen').classList.contains('hidden');
    document.getElementById('privacy-admin').classList.toggle('hidden', !isAdmin);
    try {
        const res = await fetch('/api/privacy-info');
        if(!res.ok) return;
        const d = await res.json();
        const span = (days) => days > 0 ? `${days} Tage` : 'unbegrenzt';
        document.getElementById('privacy-retention').textContent =
            `Aufbewahrung: Berichte ${span(Number(d.auditDays) || 0)}, Protokoll ${span(Number(d.logDays) || 0)}, Wiederherstellungs-Einträge ${span(Number(d.offboardDays) || 0)}. Abmeldung nach ${Number(d.sessionIdleMinutes) || 30} Minuten ohne Aktivität.`;
    } catch(e) {}
}

function closePrivacy() {
    document.getElementById('privacy-modal').classList.add('hidden');
}

async function downloadPrivacyReport() {
    const input = document.getElementById('privacy-sam');
    const sam = input.value.trim();
    if(!sam) { showToast('Bitte einen Benutzernamen angeben.', 'error'); input.focus(); return; }
    const btn = document.getElementById('privacy-report-btn');
    btn.disabled = true;
    try {
        const res = await fetch('/api/privacy/report?sam=' + encodeURIComponent(sam));
        const data = await res.json().catch(() => ({}));
        if(!res.ok) { showToast(data.detail || 'Auskunft fehlgeschlagen.', 'error'); return; }
        const blob = new Blob([JSON.stringify(data, null, 2)], {type: 'application/json'});
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'auskunft-' + sam.replace(/[^A-Za-z0-9._-]/g, '_') + '.json';
        document.body.appendChild(a); a.click(); a.remove();
        setTimeout(() => URL.revokeObjectURL(a.href), 1000);
        const n = (data.auditEntries || []).length + (data.offboardingRecords || []).length;
        showToast(n === 1 ? '1 Eintrag gefunden.' : `${n} Einträge gefunden.`, n ? 'success' : 'info');
    } catch(e) {
        showToast('Auskunft fehlgeschlagen.', 'error');
    } finally {
        btn.disabled = false;
    }
}

function closeRestore() {
    document.getElementById('restore-modal').classList.add('hidden');
    restorePlan = null;
}

async function executeRestore() {
    const p = restorePlan;
    if(!p || (p.blockers || []).length) return;
    const btn = document.getElementById('restore-exec-btn');
    btn.disabled = true;
    let res, data;
    try {
        res = await fetch(`/api/offboarding/records/${Number(p.id)}/restore`, { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ targetOu: p.targetOu }) });
        data = await res.json();
    } catch(e) {
        btn.disabled = false;
        alert('Verbindungsfehler beim Wiederherstellen.');
        return;
    }
    if(!res.ok) {
        btn.disabled = false;
        alert(data.detail || 'Fehler beim Wiederherstellen.');
        return;
    }
    closeRestore();
    const warn = (data.warnings || []).length ? '\n\nHinweis:\n' + data.warnings.join('\n') : '';
    alert((data.message || 'Konto wiederhergestellt.') + warn);
    await refreshAllLdapData();
}

async function dismissRecord(id) {
    if(currentUserRole !== 'Administrator') return;
    const r = offRecords.find(x => x.id === id);
    if(!confirm(`Eintrag für ${r ? (r.name || r.sam) : 'dieses Konto'} verwerfen?\n\nDas Konto selbst wird nicht verändert. Es lässt sich danach nur noch von Hand wiederherstellen.`)) return;
    const res = await fetch(`/api/offboarding/records/${Number(id)}/dismiss`, { method: 'POST' });
    const data = await res.json();
    if(!res.ok) { alert(data.detail || 'Fehler beim Verwerfen.'); return; }
    alert('Eintrag verworfen.');
    await loadOffboardRecords();
}

// Sorting by last logon: '' = as delivered (by name), 'asc' = oldest first ("never" at the top), 'desc' = newest first
let offSort = '';

function sortOffboardUsers(users) {
    if(!offSort) return users;
    const time = u => u.lastLogon ? Date.parse(u.lastLogon) : -Infinity;
    const dir = offSort === 'asc' ? 1 : -1;
    return users.slice().sort((a, b) => (time(a) - time(b)) * dir || a.name.localeCompare(b.name));
}

function toggleOffboardSort() {
    setOffboardSort(offSort === '' ? 'asc' : offSort === 'asc' ? 'desc' : '');
}

function setOffboardSort(mode) {
    offSort = mode;
    const icon = document.getElementById('off-sort-icon');
    if(icon) icon.className = 'fa-solid ' + (offSort === 'asc' ? 'fa-sort-up text-cyan-400' : offSort === 'desc' ? 'fa-sort-down text-cyan-400' : 'fa-sort text-slate-500');
    const head = document.getElementById('off-sort-head');
    if(head) head.setAttribute('aria-sort', offSort === 'asc' ? 'ascending' : offSort === 'desc' ? 'descending' : 'none');
    filterOffboardTable();
}

// Last logon as date plus "x days ago"; the value is approximate (lastLogonTimestamp, synchronised every 9-14 days)
function lastLogonCell(iso) {
    if(!iso) return `<span class="text-slate-500 italic">nie</span>`;
    const d = new Date(iso);
    if(isNaN(d.getTime())) return '-';
    const loc = uiLang === 'en' ? 'en-GB' : 'de-DE';
    const days = Math.max(0, Math.floor((Date.now() - d.getTime()) / 86400000));
    const ago = days === 0 ? 'heute' : days === 1 ? 'vor 1 Tag' : `vor ${days} Tagen`;
    const tone = days >= 90 ? 'text-amber-400' : 'text-slate-400';
    return `<span class="text-slate-300">${d.toLocaleDateString(loc)}</span><br><span class="${tone} text-[10px]">${ago}</span>`;
}

function filterOffboardTable() {
    const query = document.getElementById('offboard-search').value.toLowerCase();
    const filtered = cachedOffboardUsers.filter(u => 
        u.name.toLowerCase().includes(query) || u.sam.toLowerCase().includes(query) || (u.mail && u.mail.toLowerCase().includes(query))
    );
    renderOffboardTable(sortOffboardUsers(filtered));
}

function renderOffboardTable(users) {
    const tbody = document.getElementById('offboard-user-list');
    const countBadge = document.getElementById('offboard-count');
    countBadge.textContent = `${users.length} Konten`;
    const known = new Set(cachedOffboardUsers.filter(offboardable).map(u => u.dn));
    [...offSelected].forEach(dn => { if(!known.has(dn)) offSelected.delete(dn); });
    updateOffboardSelection();

    if(users.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" class="p-6 text-center text-slate-500 italic">Keine passenden Benutzer gefunden.</td></tr>`;
        return;
    }

    let html = "";
    users.forEach(u => {
        const statusBadge = u.disabled ? 
            `<span class="px-2 py-0.5 rounded bg-rose-500/10 text-rose-400 border border-rose-500/20 text-[10px]">Deaktiviert</span>` : 
            `<span class="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 text-[10px]">Aktiv</span>`;
        
        let actionBtn = "";
        if(u.disabled) {
            actionBtn = `<span class="text-slate-500 italic">Bereits deaktiviert</span>`;
        } else if(u.sam.toLowerCase() === currentLoggedInUsername) {
            actionBtn = `<span class="text-amber-400 italic text-[11px]" title="Eigener Account">Eigener Account</span>`;
        } else if(u.protected) {
            actionBtn = `<span class="text-amber-400 italic text-[11px]" title="${esc(u.protected)}"><i class="fa-solid fa-lock mr-1"></i> Geschützt: ${esc(u.protected)}</span>`;
        } else {
            actionBtn = `<button data-dn="${esc(u.dn)}" data-sam="${esc(u.sam)}" data-on-click="executeOffboard(this.dataset.dn, this.dataset.sam)" class="px-3 py-1.5 bg-rose-600 hover:bg-rose-500 text-white rounded-lg font-medium transition-all shadow"><i class="fa-solid fa-user-slash mr-1"></i> Offboarding</button>`;
        }

        const selBox = offboardable(u)
            ? `<input type="checkbox" data-dn="${esc(u.dn)}" ${offSelected.has(u.dn) ? 'checked' : ''} data-on-change="toggleOffboardSelect(this.dataset.dn, this.checked)" class="off-sel accent-cyan-500">`
            : '';
        html += `
            <tr class="hover:bg-slate-900/40">
                <td class="p-3.5">${selBox}</td>
                <td class="p-3.5 text-white font-sans font-medium">${nt(u.name)}</td>
                <td class="p-3.5 text-cyan-400">${nt(u.sam)}</td>
                <td class="p-3.5 text-slate-300">${nt(u.mail || '-')}</td>
                <td class="p-3.5 whitespace-nowrap">${lastLogonCell(u.lastLogon)}</td>
                <td class="p-3.5">${statusBadge}</td>
                <td class="p-3.5 text-right">${actionBtn}</td>
            </tr>
        `;
    });
    tbody.innerHTML = html;
}

async function loadPwdResetUsers(force) {
    const res = await fetch('/api/pwdreset/users' + freshQuery(force));
    if(res.ok) {
        const data = await res.json();
        cachedPwdResetUsers = data.users || [];
        renderPwdResetTable(cachedPwdResetUsers);
    }
}

function filterPwdResetTable() {
    const query = document.getElementById('pwdreset-search').value.toLowerCase();
    const filtered = cachedPwdResetUsers.filter(u => 
        u.name.toLowerCase().includes(query) || u.sam.toLowerCase().includes(query) || (u.mail && u.mail.toLowerCase().includes(query))
    );
    renderPwdResetTable(filtered);
}

function renderPwdResetTable(users) {
    const tbody = document.getElementById('pwdreset-user-list');
    const countBadge = document.getElementById('pwdreset-count');
    countBadge.textContent = `${users.length} Konten`;

    if(users.length === 0) {
        tbody.innerHTML = `<tr><td colspan="4" class="p-6 text-center text-slate-500 italic">Keine passenden Benutzer gefunden.</td></tr>`;
        return;
    }

    let html = "";
    users.forEach(u => {
        let statusBadges = u.disabled ? 
            `<span class="px-2 py-0.5 rounded bg-rose-500/10 text-rose-400 border border-rose-500/20 text-[10px] mr-1">Deaktiviert</span>` : 
            `<span class="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 text-[10px] mr-1">Aktiv</span>`;
        
        if(u.locked) {
            statusBadges += `<span class="px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20 text-[10px]">Gesperrt</span>`;
        }

        html += `
            <tr class="hover:bg-slate-900/40">
                <td class="p-3.5 text-white font-sans font-medium">${nt(u.name)}</td>
                <td class="p-3.5 text-cyan-400">${nt(u.sam)}</td>
                <td class="p-3.5">${statusBadges}</td>
                <td class="p-3.5 text-right">
                    <button data-dn="${esc(u.dn)}" data-sam="${esc(u.sam)}" data-locked="${u.locked ? 'true' : 'false'}" data-on-click="openPwdResetModal(this.dataset.dn, this.dataset.sam, this.dataset.locked)" class="btn-primary px-3 py-1.5 text-white rounded-lg font-medium transition-all"><i class="fa-solid fa-key mr-1"></i> Kennwort zurücksetzen</button>
                </td>
            </tr>
        `;
    });
    tbody.innerHTML = html;
}

function openPwdResetModal(dn, sam, isLocked) {
    document.getElementById('pwdreset-target-dn').value = dn;
    document.getElementById('pwdreset-mode').value = 'auto';
    document.getElementById('pwdreset-new').value = '';
    document.getElementById('pwdreset-confirm').value = '';
    document.getElementById('pwdreset-force').checked = true;
    document.getElementById('pwdreset-unlock').checked = isLocked === true || isLocked === 'true';  // data attribute: text
    togglePwdResetMode();
    document.getElementById('pwdreset-modal').classList.remove('hidden');
}

function togglePwdResetMode() {
    const mode = document.getElementById('pwdreset-mode').value;
    document.getElementById('pwdreset-manual-box').classList.toggle('hidden', mode !== 'manual');
}

function submitPwdReset() { return guarded('pwdreset', _submitPwdReset); }
async function _submitPwdReset() {
    const userDn = document.getElementById('pwdreset-target-dn').value;
    const mode = document.getElementById('pwdreset-mode').value;
    const forceChange = document.getElementById('pwdreset-force').checked;
    const unlockAccount = document.getElementById('pwdreset-unlock').checked;
    let newPassword = "";

    if(mode === 'manual') {
        newPassword = document.getElementById('pwdreset-new').value;
        const confirmPwd = document.getElementById('pwdreset-confirm').value;
        if(!newPassword) {
            alert("Bitte geben Sie ein neues Passwort ein.");
            return;
        }
        if(newPassword !== confirmPwd) {
            alert("Die Passwörter stimmen nicht überein.");
            return;
        }
    }

    const data = { userDn, mode, newPassword, forceChange, unlockAccount };
    const res = await fetch('/api/pwdreset/execute', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(data) });
    const result = await res.json();
    
    if(res.ok) {
        document.getElementById('pwdreset-modal').classList.add('hidden');
        
        lastCreatedUser = {
            sam: result.sam || userDn.split(',')[0].replace('CN=', ''),
            upn: result.upn || '-',
            mail: result.mail || '-',
            pwd: result.newPassword
        };

        document.getElementById('res-title').textContent = "Passwort erfolgreich zurückgesetzt!";
        document.getElementById('res-sam').textContent = lastCreatedUser.sam;
        document.getElementById('res-upn').textContent = lastCreatedUser.upn;
        document.getElementById('res-mail').textContent = lastCreatedUser.mail || '-';
        document.getElementById('res-pwd').textContent = lastCreatedUser.pwd;
        if (result.warnings && result.warnings.length) setTimeout(() => alert("Hinweis:\n" + result.warnings.join("\n")), 300);
        document.getElementById('result-modal').classList.remove('hidden');

        await refreshAllLdapData();
    } else {
        alert(result.detail || "Fehler beim Zurücksetzen des Passworts.");
    }
}

function executeOffboard(userDn, samName) { return guarded('offboard', () => _executeOffboard(userDn, samName)); }
async function _executeOffboard(userDn, samName) {
    if(!confirm(`Möchten Sie den Benutzer '${samName}' wirklich offboarden?\n\n- Konto wird deaktiviert\n- Aus allen Gruppen entfernt\n- In die Ziel-OU verschoben\n- Keine Löschung!`)) return;
    
    const res = await fetch('/api/offboarding/execute', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ userDn }) });
    const result = await res.json();
    if(res.ok) {
        alert(result.message || "Offboarding erfolgreich durchgeführt!");
        await refreshAllLdapData();
    } else {
        alert(result.detail || "Fehler beim Offboarding.");
    }
}

async function testSmtpConfig() {
    if(currentUserRole !== "Administrator") return alert("Keine Berechtigung.");
    const res = await fetch('/api/smtp-test', { method: 'POST' });
    const result = await res.json();
    if(res.ok) {
        alert(result.message || "Test-Mail erfolgreich gesendet!");
    } else {
        alert(result.detail || "Fehler beim Senden der Test-Mail.");
    }
}

function showDirectory(dir) {
    const el = document.getElementById('dir-display');
    if(!el) return;
    const label = dir && dir.label ? dir.label : '';
    el.textContent = label ? label + (dir.host ? ' · ' + dir.host : '') : '';
}

async function performLogout() { try { await fetch('/api/logout', {method: 'POST'}); } catch(e) {} finally { location.reload(); } }

// ---------------------------------------------------------------
// Manual (help): Markdown from the server, rendered safely (everything is escaped,
// only a small subset of Markdown is supported, links only internal or https)
// ---------------------------------------------------------------
const manualCache = {};
let manualLang = null;

function manualSlug(text) {
    return String(text).toLowerCase().replace(/[^\p{L}\p{N}\s-]/gu, '').trim().replace(/\s/g, '-');
}

function manualEmphasis(html) {
    return html.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>').replace(/(^|[^*\w])\*([^*\s][^*]*)\*(?!\w)/g, '$1<em>$2</em>');
}

function manualInline(text) {
    // Placeholders for code and links so that bold/italic never touch addresses or code
    const parts = [];
    const hold = html => { parts.push(html); return '\u0000' + (parts.length - 1) + '\u0000'; };
    let out = esc(String(text).replace(/\u0000/g, ''));
    out = out.replace(/`([^`]+)`/g, (_, c) => hold(`<code>${c}</code>`));
    out = out.replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (m, label, href) => {
        const raw = href.replace(/&amp;/g, '&');
        const inner = manualEmphasis(label);
        if (raw.startsWith('#')) return hold(`<a href="${esc(raw)}" data-anchor="${esc(raw.slice(1))}">${inner}</a>`);
        if (/^https:\/\/[^\s"'<>]+$/.test(raw)) return hold(`<a href="${esc(raw)}" target="_blank" rel="noopener noreferrer">${inner}</a>`);
        return inner;
    });
    out = manualEmphasis(out);
    // Placeholders can be nested in link texts (code in a link) - repeat until nothing is left to replace
    for (let i = 0; i < 3 && out.includes('\u0000'); i++) out = out.replace(/\u0000(\d+)\u0000/g, (_, n) => parts[Number(n)]);
    return out;
}

function manualRender(md) {
    const lines = String(md || '').replace(/\r/g, '').split('\n');
    const out = [];
    const usedIds = new Set();
    const headingId = text => {
        const base = 'm-' + manualSlug(text);
        let id = base;
        for (let n = 2; usedIds.has(id); n++) id = base + '-' + n;
        usedIds.add(id);
        return id;
    };
    let i = 0;
    const isTableSep = l => /^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)*\|?\s*$/.test(l);
    const cells = l => l.trim().replace(/^\|/, '').replace(/\|$/, '').split('|').map(c => c.trim());
    const listRe = /^(\s*)([-*]|\d+\.)\s+(.*)$/;
    while (i < lines.length) {
        const line = lines[i];
        if (/^\s*$/.test(line)) { i++; continue; }
        if (/^```/.test(line)) {
            const buf = [];
            i++;
            while (i < lines.length && !/^```/.test(lines[i])) buf.push(lines[i++]);
            i++;
            out.push(`<pre><code>${esc(buf.join('\n'))}</code></pre>`);
            continue;
        }
        const h = /^(#{1,4})\s+(.*)$/.exec(line);
        if (h) {
            const level = h[1].length;
            out.push(`<h${level} id="${esc(headingId(h[2]))}">${manualInline(h[2])}</h${level}>`);
            i++;
            continue;
        }
        if (/^-{3,}\s*$/.test(line)) { out.push('<hr>'); i++; continue; }
        if (/^\s*\|/.test(line) && i + 1 < lines.length && isTableSep(lines[i + 1])) {
            const head = cells(line);
            i += 2;
            const rows = [];
            while (i < lines.length && /^\s*\|/.test(lines[i])) rows.push(cells(lines[i++]));
            out.push('<div class="table-wrap"><table><thead><tr>' + head.map(c => `<th>${manualInline(c)}</th>`).join('') +
                '</tr></thead><tbody>' + rows.map(r => '<tr>' + head.map((_, k) => `<td>${manualInline(r[k] || '')}</td>`).join('') + '</tr>').join('') +
                '</tbody></table></div>');
            continue;
        }
        if (/^>\s?/.test(line)) {
            const buf = [];
            while (i < lines.length && /^>\s?/.test(lines[i])) buf.push(lines[i++].replace(/^>\s?/, ''));
            out.push(`<blockquote>${manualInline(buf.join(' '))}</blockquote>`);
            continue;
        }
        if (listRe.test(line)) {
            // List with one level of nesting (indented items)
            const items = [];
            let ordered = /\d/.test(listRe.exec(line)[2]);
            while (i < lines.length && (listRe.test(lines[i]) || /^\s{2,}\S/.test(lines[i]))) {
                const m = listRe.exec(lines[i]);
                if (m && m[1].length < 2) items.push({text: m[3], sub: [], subOrdered: false});
                else if (m && items.length) { const it = items[items.length - 1]; if (!it.sub.length) it.subOrdered = /\d/.test(m[2]); it.sub.push(m[3]); }
                else if (items.length) { const it = items[items.length - 1]; if (it.sub.length) it.sub[it.sub.length - 1] += ' ' + lines[i].trim(); else it.text += ' ' + lines[i].trim(); }
                i++;
            }
            const tag = ordered ? 'ol' : 'ul';
            out.push(`<${tag}>` + items.map(it => `<li>${manualInline(it.text)}` +
                (it.sub.length ? `<${it.subOrdered ? 'ol' : 'ul'}>` + it.sub.map(x => `<li>${manualInline(x)}</li>`).join('') + `</${it.subOrdered ? 'ol' : 'ul'}>` : '') +
                '</li>').join('') + `</${tag}>`);
            continue;
        }
        const buf = [];
        while (i < lines.length && !/^\s*$/.test(lines[i]) && !/^(#{1,4}\s|```|>|\s*\|)/.test(lines[i]) && !listRe.test(lines[i]) && !/^-{3,}\s*$/.test(lines[i])) buf.push(lines[i++].trim());
        if (buf.length) out.push(`<p>${manualInline(buf.join(' '))}</p>`);
        else i++;
    }
    // Sections per H2 (for the search)
    const html = out.join('\n');
    const parts = html.split(/(?=<h2 )/);
    return parts.map((p, k) => k === 0 ? `<section data-intro="1">${p}</section>` : `<section>${p}</section>`).join('\n');
}

async function loadManual() {
    const body = document.getElementById('manual-body');
    if (!body) return;
    const lang = uiLang === 'en' ? 'en' : 'de';
    if (manualLang === lang && body.dataset.loaded === '1') return;
    try {
        if (!manualCache[lang]) {
            const res = await fetch('/api/manual?lang=' + lang);
            if (!res.ok) throw new Error(String(res.status));
            manualCache[lang] = await res.text();
        }
        body.innerHTML = manualRender(manualCache[lang]);
        body.dataset.loaded = '1';
        manualLang = lang;
        const search = document.getElementById('manual-search');
        if (search && search.value) filterManual(search.value);
    } catch(e) {
        body.innerHTML = `<p>${esc(lang === 'en' ? 'The manual could not be loaded.' : 'Das Handbuch konnte nicht geladen werden.')}</p>`;
    }
}

function manualClick(ev) {
    const a = ev.target && ev.target.closest ? ev.target.closest('a[data-anchor]') : null;
    if (!a) return;
    ev.preventDefault();
    const target = document.getElementById('m-' + a.dataset.anchor);
    if (target) {
        const search = document.getElementById('manual-search');
        if (search && search.value) { search.value = ''; filterManual(''); }
        target.scrollIntoView({behavior: 'smooth', block: 'start'});
    }
}

function filterManual(query) {
    const body = document.getElementById('manual-body');
    if (!body || !body.querySelectorAll) return;
    const q = String(query || '').trim().toLowerCase();
    let hits = 0;
    body.querySelectorAll('section').forEach(sec => {
        const show = !q || (!sec.dataset.intro && sec.textContent.toLowerCase().includes(q));
        sec.classList.toggle('is-hidden', !show && !(!q && sec.dataset.intro));
        if (show && q) hits++;
    });
    const none = document.getElementById('manual-nohit');
    if (none) none.classList.toggle('hidden', !q || hits > 0);
}

async function switchTab(targetTab) {
    ['start', 'hire', 'usermgmt', 'offboard', 'delete', 'pwdreset', 'templates', 'smtp', 'infra', 'reports', 'cert', 'faq'].forEach(tab => {
        const el = document.getElementById('tab-' + tab);
        if(el) el.classList.toggle('hidden', tab !== targetTab);
        const btn = document.getElementById('nav-' + tab);
        if(btn) {
            btn.classList.toggle('is-active', tab === targetTab);
            if(tab === targetTab) btn.setAttribute('aria-current', 'page'); else btn.removeAttribute('aria-current');
        }
    });
    toggleSidebar(false);
    const main = document.querySelector('.app-main');
    if(main) main.scrollTop = 0;
    currentTab = targetTab;
    if(targetTab === 'reports') { await loadReports(); return; }
    if(targetTab === 'cert') { await loadCertificate(); return; }
    if(targetTab === 'faq') { await loadManual(); return; }

    await refreshAllLdapData();
}

// ---------------------------------------------------------------
// Start page: what needs doing, counted from the existing lists
// (no extra AD query: the server answers from its 60-second cache)
// ---------------------------------------------------------------
function greeting(hour) {
    if(hour < 5) return 'Guten Abend';
    if(hour < 11) return 'Guten Morgen';
    if(hour < 18) return 'Guten Tag';
    return 'Guten Abend';
}

// Numbers count up to their value (from 0 on the first read, otherwise from the previous value), so it is
// visible that a new result has arrived. Only display: the value itself is set at once in data-value.
const COUNT_MS = 900;
const countTimers = new WeakMap();
function reducedMotion() {
    try { return !!(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches); } catch(e) { return false; }
}
function countTo(el, target) {
    const prev = countTimers.get(el);
    if(prev) prev.cancelled = true;
    const from = /^\d+$/.test(String(el.textContent)) ? Number(el.textContent) : 0;
    el.dataset && (el.dataset.value = String(target));
    const raf = typeof requestAnimationFrame === 'function' ? requestAnimationFrame : null;
    if(!raf || from === target || reducedMotion()) { el.textContent = String(target); return; }
    const job = {cancelled: false};
    countTimers.set(el, job);
    const start = Date.now();
    const step = () => {
        if(job.cancelled) return;
        const t = Math.min(1, (Date.now() - start) / COUNT_MS);
        const eased = 1 - Math.pow(1 - t, 3);  // fast at first, slowing down towards the end
        el.textContent = String(Math.round(from + (target - from) * eased));
        if(t < 1) raf(step); else countTimers.delete(el);
    };
    raf(step);
}

function setDashCard(key, num, sub, calm) {
    const n = document.getElementById('dash-' + key + '-num');
    if(n) {
        if(/^\d+$/.test(String(num))) countTo(n, Number(num));
        else { const prev = countTimers.get(n); if(prev) prev.cancelled = true; n.textContent = num; }
    }
    const s = document.getElementById('dash-' + key + '-sub');
    if(s && sub !== null) s.textContent = sub;
    const card = document.getElementById('dash-' + key);
    if(card) card.classList.toggle('is-calm', !!calm);
}

function setNavBadge(tab, count) {
    const b = document.getElementById('nav-badge-' + tab);
    if(!b) return;
    b.textContent = count > 99 ? '99+' : String(count || '');
    b.classList.toggle('hidden', !count);
}

let dashLoading = false;
let dashShown = false;
async function loadDashboard(force) {
    if(dashLoading) return;
    dashLoading = true;
    try { await loadDashboardNow(force); } finally { dashLoading = false; }
}

async function loadDashboardNow(force) {
    const g = document.getElementById('start-greeting');
    if(g) g.textContent = greeting(new Date().getHours());
    const nm = document.getElementById('start-name');
    if(nm) nm.textContent = currentLoggedInUsername ? ', ' + currentLoggedInUsername : '';
    const admin = currentUserRole === 'Administrator';
    const cards = ['inactive', 'locked', 'delete'];
    cards.forEach(k => {
        const card = document.getElementById('dash-' + k);
        if(card) card.setAttribute('aria-busy', 'true');
        const num = document.getElementById('dash-' + k + '-num');
        if(num && num.classList) num.classList.toggle('is-empty', num.textContent === '–');
    });
    const busy = document.getElementById('dash-busy');
    if(busy && busy.classList && dashShown) busy.classList.remove('hidden');  // refresh of numbers already shown
    // While waiting something visibly moves: the seconds count up - on the cards during the first read,
    // next to "refreshing" afterwards (honest: it is the waiting time, not a fake number)
    const began = Date.now();
    const tick = () => {
        const secs = Math.floor((Date.now() - began) / 1000);
        if(!dashShown) cards.forEach(k => {
            const sub = document.getElementById('dash-' + k + '-sub');
            if(sub) sub.textContent = secs > 0 ? `Wird vom DC gelesen … ${secs} s` : 'Wird vom DC gelesen …';
        });
        const label = document.getElementById('dash-busy-text');
        if(label) label.textContent = secs > 0 ? `aktualisiert … ${secs} s` : 'aktualisiert …';
    };
    tick();
    const ticker = typeof setInterval === 'function' ? setInterval(tick, 1000) : null;
    // Only numbers: the DC counts with search filters, the browser never receives account lists here
    let data = null;
    try {
        const res = await fetch('/api/dashboard');
        if(res.ok) data = await res.json();
    } catch(e) { data = null; }
    if(ticker) clearInterval(ticker);
    cards.forEach(k => { const card = document.getElementById('dash-' + k); if(card) card.setAttribute('aria-busy', 'false'); });
    if(busy && busy.classList) busy.classList.add('hidden');
    renderDashboard(data, admin);
    if(data) dashShown = true;
}

// One card from one answer section: {count, never?} | {warning} | {error} | null (no answer)
function dashSection(key, part, notSet, sub, calmSub) {
    if(!part || part.error) { setDashCard(key, '–', 'Liste nicht lesbar', true); return 0; }
    if(part.warning) { setDashCard(key, '–', notSet, true); return 0; }
    const n = Number(part.count) || 0;
    setDashCard(key, String(n), n ? sub(part) : calmSub, !n);
    return n;
}

function renderDashboard(data, admin) {
    const asof = document.getElementById('dash-asof');
    if(asof) {
        if(data) {
            const t = new Date().toLocaleTimeString(uiLang === 'en' ? 'en-GB' : 'de-DE', {hour: '2-digit', minute: '2-digit'});
            asof.textContent = `Stand ${t} · aktualisiert sich jede Minute`;
        } else {
            asof.textContent = 'Der DC ist gerade nicht erreichbar – neuer Versuch in einer Minute.';
        }
    }
    const d = data || {};
    const inactive = dashSection('inactive', d.inactive, 'Noch nicht eingerichtet: Quell-OUs unter „Austritt“ festlegen',
        p => p.never ? `davon ${p.never} nie angemeldet` : 'Aktive Konten in den Offboarding-OUs, ältestes zuerst',
        'Aktive Konten in den Offboarding-OUs, ältestes zuerst');
    const locked = dashSection('locked', d.locked, 'Noch nicht eingerichtet: Quell-OUs unter „Passwort zurücksetzen“ festlegen',
        () => 'Zu viele falsche Kennwörter', 'Alles in Ordnung');
    const deletable = admin ? dashSection('delete', d.deletion, 'Die Löschfunktion ist nicht aktiviert.', () => 'Deaktivierte Konten', 'Deaktivierte Konten') : 0;
    setNavBadge('offboard', inactive);
    setNavBadge('pwdreset', locked);
    setNavBadge('delete', deletable);
}

// Live without clicking: while the start page is open and the browser tab is visible, the counters
// are read fresh from the DC every minute and when returning to the tab - nothing is kept in the
// browser. Without user activity for 10 minutes it stops, so an unattended screen does not keep
// the session alive (every request extends it on the server).
const DASH_REFRESH_MS = 60000;
const DASH_ACTIVE_MS = 10 * 60000;
function dashAutoRefreshDue(now) {
    if(currentTab !== 'start' || !appVisible()) return false;
    if(typeof document.visibilityState === 'string' && document.visibilityState !== 'visible') return false;
    const box = document.getElementById('palette');
    if(box && box.classList && !box.classList.contains('hidden')) return false;
    return now - Math.max(lastActivity || 0, sharedActivity() || 0) < DASH_ACTIVE_MS;
}
function dashAutoRefresh() {
    if(dashAutoRefreshDue(Date.now())) safeLoad(loadDashboard, true);
}
let dashTimer = null;
function startDashAutoRefresh() {
    if(dashTimer) return;
    dashTimer = setInterval(dashAutoRefresh, DASH_REFRESH_MS);
    document.addEventListener('visibilitychange', dashAutoRefresh);
}

// Card "no logon for 90 days": open the offboarding list, oldest logon first
async function openInactiveAccounts() {
    setOffboardSort('asc');
    await switchTab('offboard');
}

// ---------------------------------------------------------------
// Quick search (Ctrl+K / Cmd+K): people and pages in one place
// ---------------------------------------------------------------
const PALETTE_PAGES = [
    {tab: 'start', label: 'Start', icon: 'fa-house'},
    {tab: 'hire', label: 'Neuer Mitarbeiter', sub: 'Onboarding', icon: 'fa-user-plus'},
    {tab: 'usermgmt', label: 'Benutzerverwaltung', sub: 'OU und Gruppen', icon: 'fa-users'},
    {tab: 'pwdreset', label: 'Passwort zurücksetzen', icon: 'fa-key'},
    {tab: 'offboard', label: 'Austritt', sub: 'Offboarding', icon: 'fa-user-minus'},
    {tab: 'delete', label: 'Konten löschen', icon: 'fa-trash-can'},
    {tab: 'templates', label: 'Templates', icon: 'fa-layer-group'},
    {tab: 'smtp', label: 'E-Mail-Benachrichtigung', icon: 'fa-envelope'},
    {tab: 'infra', label: 'AD-Struktur', icon: 'fa-sitemap'},
    {tab: 'reports', label: 'Berichte', icon: 'fa-clipboard-list'},
    {tab: 'cert', label: 'Zertifikat', icon: 'fa-certificate'},
    {tab: 'faq', label: 'Handbuch', icon: 'fa-book'},
];
let palettePeople = [];
let paletteItems = [];
let paletteIndex = 0;

function visiblePage(tab) {
    const btn = document.getElementById('nav-' + tab);
    return !!btn && btn.style.display !== 'none';
}

// People are searched by the DC (POST /api/people): from 2 characters, 250 ms after the last key,
// at most 10 hits. Only the newest answer counts; nothing is kept after the search is closed.
let paletteQuery = '';
let paletteSearching = false;
let paletteSeq = 0;
let paletteTimer = null;
const PALETTE_MIN = 2;
const PALETTE_DELAY = 250;

function paletteInput() {
    const q = document.getElementById('palette-input').value.trim();
    if(paletteTimer) clearTimeout(paletteTimer);
    paletteTimer = null;
    if(q.length < PALETTE_MIN) {
        paletteSeq++;
        palettePeople = []; paletteQuery = ''; paletteSearching = false;
    } else {
        paletteSearching = true;
        paletteTimer = setTimeout(() => searchPeople(q), PALETTE_DELAY);
    }
    renderPalette();
}

async function searchPeople(q) {
    const seq = ++paletteSeq;
    let people = [];
    try {
        const res = await fetch('/api/people', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({q})});
        if(res.ok) people = ((await res.json()) || {}).people || [];
    } catch(e) { people = []; }
    if(seq !== paletteSeq) return;  // a newer search is under way
    palettePeople = people;
    paletteQuery = q;
    paletteSearching = false;
    renderPalette();
}

async function openPalette() {
    const box = document.getElementById('palette');
    if(!box) return;
    toggleSidebar(false);
    box.classList.remove('hidden');
    const input = document.getElementById('palette-input');
    input.value = '';
    input.focus();
    paletteSeq++;
    palettePeople = []; paletteQuery = ''; paletteSearching = false;
    renderPalette();
}

function closePalette() {
    const box = document.getElementById('palette');
    if(box) box.classList.add('hidden');
    if(paletteTimer) clearTimeout(paletteTimer);
    paletteTimer = null;
    paletteSeq++;
    palettePeople = []; paletteQuery = '';
}

function renderPalette() {
    const input = document.getElementById('palette-input');
    const list = document.getElementById('palette-list');
    if(!input || !list) return;
    const q = input.value.trim().toLowerCase();
    const pages = PALETTE_PAGES.filter(p => visiblePage(p.tab) && (!q || tr(p.label).toLowerCase().includes(q) || p.label.toLowerCase().includes(q)
        || (p.sub && p.sub.toLowerCase().includes(q))));
    const people = paletteQuery && paletteQuery.toLowerCase() === q ? palettePeople : [];
    paletteItems = [...people.map(p => ({kind: 'person', p})), ...pages.map(p => ({kind: 'page', p}))];
    paletteIndex = Math.min(paletteIndex, Math.max(0, paletteItems.length - 1));
    if(!q) paletteIndex = 0;
    let html = '';
    let i = 0;
    if(people.length) {
        html += '<p class="palette-group">Personen</p>';
        people.forEach(p => {
            const initials = String(p.name).split(/\s+/).filter(Boolean).slice(0, 2).map(w => w[0]).join('').toUpperCase();
            const where = {usermgmt: 'Benutzerverwaltung', offboard: 'Austritt', pwdreset: 'Passwort zurücksetzen'}[p.tab];
            html += `<button type="button" role="option" id="pal-${i}" class="palette-item${i === paletteIndex ? ' is-active' : ''}" data-on-click="paletteChoose(${i})" data-on-mousemove="paletteHover(${i})">`
                + `<span class="p-icon" translate="no">${esc(initials || '?')}</span><span class="min-w-0"><span translate="no">${esc(p.name)}</span>`
                + `<span class="p-sub"><span translate="no">${esc(p.sam)}${p.mail ? ' · ' + esc(p.mail) : ''}</span>${p.disabled ? ' · <span>deaktiviert</span>' : ''} · <span>öffnet</span> <span>${esc(where)}</span></span></span></button>`;
            i++;
        });
    } else if(paletteSearching) {
        html += '<p class="palette-empty">Suche im AD …</p>';
    } else if(q.length >= PALETTE_MIN && !pages.length) {
        html += '<p class="palette-empty">Keine Person und keine Seite gefunden.</p>';
    }
    if(pages.length) {
        html += '<p class="palette-group">Seiten</p>';
        pages.forEach(p => {
            html += `<button type="button" role="option" id="pal-${i}" class="palette-item${i === paletteIndex ? ' is-active' : ''}" data-on-click="paletteChoose(${i})" data-on-mousemove="paletteHover(${i})">`
                + `<span class="p-icon"><i class="fa-solid ${p.icon}" aria-hidden="true"></i></span><span class="min-w-0"><span>${esc(p.label)}</span>${p.sub ? `<span class="p-sub">${esc(p.sub)}</span>` : ''}</span></button>`;
            i++;
        });
    }
    list.innerHTML = html;
    input.setAttribute('aria-activedescendant', paletteItems.length ? 'pal-' + paletteIndex : '');
}

function paletteHover(i) {
    if(i === paletteIndex) return;
    paletteIndex = i;
    document.querySelectorAll('.palette-item').forEach((el, k) => el.classList.toggle('is-active', k === i));
}

function paletteKey(e) {
    if(e.key === 'ArrowDown' || e.key === 'ArrowUp') {
        e.preventDefault();
        if(!paletteItems.length) return;
        paletteIndex = (paletteIndex + (e.key === 'ArrowDown' ? 1 : -1) + paletteItems.length) % paletteItems.length;
        renderPalette();
        const el = document.getElementById('pal-' + paletteIndex);
        if(el && el.scrollIntoView) el.scrollIntoView({block: 'nearest'});
    } else if(e.key === 'Enter') {
        e.preventDefault();
        paletteChoose(paletteIndex);
    } else if(e.key === 'Escape') {
        e.preventDefault();
        closePalette();
    }
}

const PALETTE_SEARCH = {
    usermgmt: ['usermgmt-search', () => filterUserMgmtTable()],
    offboard: ['offboard-search', () => filterOffboardTable()],
    pwdreset: ['pwdreset-search', () => filterPwdResetTable()],
};

async function paletteChoose(i) {
    const item = paletteItems[i];
    if(!item) return;
    closePalette();
    if(item.kind === 'page') { await switchTab(item.p.tab); return; }
    const [id, apply] = PALETTE_SEARCH[item.p.tab];
    const field = document.getElementById(id);
    if(field) field.value = item.p.sam || item.p.name;
    await switchTab(item.p.tab);
    if(field) { field.value = item.p.sam || item.p.name; apply(); }
}

if(document.addEventListener) document.addEventListener('keydown', e => {
    if((e.ctrlKey || e.metaKey) && !e.altKey && String(e.key).toLowerCase() === 'k') {
        if(typeof appVisible === 'function' && !appVisible()) return;
        e.preventDefault();
        const box = document.getElementById('palette');
        if(box && !box.classList.contains('hidden')) closePalette(); else openPalette();
    }
});

// ---------------------------------------------------------------
// Reports (administrators only): changes and log
// ---------------------------------------------------------------
let reportKind = 'audit';
let reportRows = [];
let reportNext = null;
let reportSummary = null;
const REPORT_ACTIONS = {
    'login': 'Anmeldung', 'logout': 'Abmeldung', 'onboard': 'Konto angelegt', 'offboarding': 'Offboarding',
    'offboarding-batch': 'Offboarding (mehrere)', 'offboarding-restore': 'Konto wiederhergestellt',
    'offboarding-record-dismiss': 'Wiederherstellungs-Eintrag verworfen', 'pwdreset': 'Passwort zurückgesetzt',
    'update-groups': 'Gruppen geändert', 'move-user': 'Konto verschoben',
    'deletion-simulate': 'Löschung simuliert', 'deletion-simulate-batch': 'Löschung simuliert (mehrere)',
    'deletion-execute': 'Konto gelöscht', 'deletion-batch': 'Konten gelöscht (mehrere)',
    'deletion-password-fail': 'Falsches Passwort bei Bestätigung', 'deletion-test': 'Speicherorte getestet',
    'template-save': 'Template gespeichert', 'template-delete': 'Template gelöscht', 'template-duplicate': 'Template kopiert',
    'exchange-test': 'Exchange-Verbindung getestet', 'privacy-report': 'Datenschutz-Auskunft erstellt',
    'reports-delete': 'Berichte gelöscht', 'tls-upload': 'Zertifikat hochgeladen', 'tls-self-signed': 'Selbstsigniertes Zertifikat erzeugt'
};
const REPORT_LEVELS = {INFO: ['Info', 'rep-info'], WARNING: ['Warnung', 'rep-warn'], ERROR: ['Fehler', 'rep-fail'], CRITICAL: ['Fehler', 'rep-fail']};

function reportActionLabel(action) {
    if(REPORT_ACTIONS[action]) return REPORT_ACTIONS[action];
    if(action.startsWith('config-')) return 'Einstellungen gespeichert';
    return action;
}

function setReportKind(kind) {
    reportKind = kind;
    document.getElementById('rep-kind-audit').classList.toggle('is-on', kind === 'audit');
    document.getElementById('rep-kind-log').classList.toggle('is-on', kind === 'log');
    document.getElementById('rep-filter-audit').classList.toggle('hidden', kind !== 'audit');
    document.getElementById('rep-filter-log').classList.toggle('hidden', kind !== 'log');
    document.getElementById('rep-del-label').textContent = kind === 'audit' ? 'Änderungen löschen …' : 'Protokoll löschen …';
    loadReports();
}

function reportDetails(details) {
    const keys = Object.keys(details || {});
    if(!keys.length) return '';
    return keys.map(k => {
        const v = details[k];
        const text = Array.isArray(v) ? v.join(', ') : (v !== null && typeof v === 'object' ? JSON.stringify(v) : String(v));
        return `<b translate="no">${esc(k)}</b> <span translate="no">${esc(text.length > 300 ? text.slice(0, 300) + ' …' : text)}</span>`;
    }).join(' · ');
}

function renderReports() {
    const head = document.getElementById('rep-head');
    const body = document.getElementById('rep-body');
    if(!head || !body) return;
    const cols = reportKind === 'audit' ? ['Zeit', 'Benutzer', 'Aktion', 'Ziel und Details', 'Ergebnis'] : ['Zeit', 'Stufe', 'Quelle', 'Meldung'];
    head.innerHTML = cols.map(c => `<th class="p-3.5">${esc(c)}</th>`).join('');
    if(!reportRows.length) {
        const hint = reportKind === 'log' ? '<div class="mt-1 text-[11px]">Hier stehen technische Meldungen des Programms: Start, erkannter Verzeichnisdienst, gesendete E-Mails, Warnungen und Fehler. Was Benutzer getan haben, steht unter „Änderungen“.</div>' : '';
        body.innerHTML = `<tr><td colspan="${cols.length}" class="p-6 text-center text-slate-500">Keine Einträge gefunden.${hint}</td></tr>`;
    } else if(reportKind === 'audit') {
        body.innerHTML = reportRows.map(r => `<tr class="align-top hover:bg-slate-900/40">
            <td class="p-3.5 text-slate-400 whitespace-nowrap">${esc(fmtDateTime(r.ts, true))}</td>
            <td class="p-3.5 text-white font-medium">${nt(r.actor || '-')}</td>
            <td class="p-3.5 text-slate-200">${esc(reportActionLabel(r.action))}<div class="text-[11px] text-slate-500 font-mono" translate="no">${esc(r.action)}</div></td>
            <td class="p-3.5 max-w-[28rem]"><div class="font-mono text-[11px] text-slate-300 break-all">${nt(r.target || '')}</div><div class="rep-details mt-0.5">${reportDetails(r.details)}</div></td>
            <td class="p-3.5"><span class="rep-badge ${r.ok ? 'rep-ok' : 'rep-fail'}">${esc(r.ok ? 'Erfolgreich' : 'Fehlgeschlagen')}</span></td>
        </tr>`).join('');
    } else {
        body.innerHTML = reportRows.map(r => {
            const lv = REPORT_LEVELS[r.level] || [r.level, 'rep-info'];
            return `<tr class="align-top hover:bg-slate-900/40">
                <td class="p-3.5 text-slate-400 whitespace-nowrap">${esc(fmtDateTime(r.ts, true))}</td>
                <td class="p-3.5"><span class="rep-badge ${lv[1]}">${esc(lv[0])}</span></td>
                <td class="p-3.5 font-mono text-[11px] text-slate-400" translate="no">${esc(r.source)}</td>
                <td class="p-3.5 text-slate-200 whitespace-pre-wrap break-words max-w-[36rem]" translate="no">${esc(r.message)}</td>
            </tr>`;
        }).join('');
    }
    const more = document.getElementById('rep-more');
    if(more) more.classList.toggle('hidden', !reportNext);
    const info = document.getElementById('rep-info');
    const s = reportSummary && reportSummary[reportKind];
    if(info) info.textContent = s ? `${reportRows.length} von ${s.count} angezeigt` : '';
    const ret = document.getElementById('rep-retention');
    if(ret && reportSummary) {
        const d = (n) => n > 0 ? `${n} Tagen` : 'nie (unbegrenzt)';
        ret.textContent = `Automatisch gelöscht werden Änderungen nach ${d(reportSummary.audit.retentionDays)} und das Protokoll nach ${d(reportSummary.log.retentionDays)}. Hier können Sie Einträge vorher löschen.`;
    }
}

async function loadReports(append) {
    const q = (document.getElementById('rep-search').value || '').trim();
    const filter = document.getElementById(reportKind === 'audit' ? 'rep-filter-audit' : 'rep-filter-log').value;
    const params = new URLSearchParams({q: q, limit: '100'});
    params.set(reportKind === 'audit' ? 'result' : 'level', filter);
    if(append && reportNext) params.set('before', String(reportNext));
    const kind = reportKind;
    try {
        const [res, sum] = await Promise.all([
            fetch(`/api/reports/${kind}?` + params.toString()),
            append ? Promise.resolve(null) : fetch('/api/reports/summary')
        ]);
        const data = await res.json().catch(() => ({}));
        if(!res.ok) { showToast(data.detail || 'Berichte konnten nicht geladen werden.', 'error'); return; }
        if(kind !== reportKind) return;
        if(sum && sum.ok) reportSummary = await sum.json();
        reportRows = append ? reportRows.concat(data.entries || []) : (data.entries || []);
        reportNext = data.nextBefore || null;
    } catch(e) {
        showToast('Berichte konnten nicht geladen werden.', 'error');
    }
    renderReports();
}

// ---------------------------------------------------------------
// HTTPS certificate (administrators only)
// ---------------------------------------------------------------
let certMode = 'pfx';

function setCertMode(mode) {
    certMode = mode;
    ['pfx', 'pem'].forEach(m => {
        document.getElementById('cert-mode-' + m).classList.toggle('is-on', m === mode);
        document.getElementById('cert-fields-' + m).classList.toggle('hidden', m !== mode);
        document.getElementById('cert-hint-' + m).classList.toggle('hidden', m !== mode);
    });
}

function renderCertificate(c) {
    const badge = document.getElementById('cert-badge');
    const dl = document.getElementById('cert-current');
    if(!c || !dl) return;
    const expired = c.daysLeft < 0, soon = !expired && c.daysLeft <= (c.warnDays || 30);
    badge.className = 'rep-badge ' + (expired ? 'rep-fail' : (c.selfSigned || soon ? 'rep-warn' : 'rep-ok'));
    badge.textContent = expired ? 'Abgelaufen' : (c.selfSigned ? 'Selbstsigniert' : 'Eigenes Zertifikat');
    const days = expired ? `abgelaufen seit ${-c.daysLeft} Tagen` : `noch ${c.daysLeft} Tage`;
    const rows = [
        ['Ausgestellt für', `<span class="font-mono text-slate-200" translate="no">${esc(c.subject)}</span>`],
        ['Aussteller', `<span class="font-mono text-slate-200" translate="no">${esc(c.issuer)}</span>`],
        ['Namen im Zertifikat', `<span class="font-mono text-slate-200 break-all" translate="no">${esc((c.names || []).join(', ') || '-')}</span>`],
        ['Gültig bis', `<span class="${expired ? 'text-rose-300' : (soon ? 'text-amber-300' : 'text-slate-200')}">${esc(fmtDateTime(c.notAfter))} (${esc(days)})</span>`],
        ['Schlüssel', `<span class="text-slate-200" translate="no">${esc(c.keyType)}</span>`],
        ['Zwischenzertifikate', `<span class="text-slate-200">${Number(c.chainLength) || 0}</span>`],
        ['Fingerabdruck (SHA-256)', `<span class="font-mono text-[10px] text-slate-400 break-all" translate="no">${esc(c.fingerprint)}</span>`]
    ];
    dl.innerHTML = rows.map(([k, v]) => `<div><dt class="text-slate-500 mb-0.5">${esc(k)}</dt><dd>${v}</dd></div>`).join('');
    const names = document.getElementById('cert-ss-names');
    if(names && !names.value) names.value = ((c.hostnames && c.hostnames.length) ? c.hostnames : (c.selfSigned ? c.names : [])).join(', ');
}

async function loadCertificate() {
    try {
        const res = await fetch('/api/tls/info');
        const data = await res.json().catch(() => ({}));
        if(!res.ok) { showToast(data.detail || 'Zertifikat konnte nicht gelesen werden.', 'error'); return; }
        renderCertificate(data.certificate);
    } catch(e) { showToast('Zertifikat konnte nicht gelesen werden.', 'error'); }
}

function readFileBase64(input) {
    const file = input && input.files && input.files[0];
    if(!file) return Promise.resolve('');
    if(file.size > 1024 * 1024) return Promise.reject(new Error('Die Datei ist zu groß (höchstens 1 MB).'));
    return new Promise((resolve, reject) => {
        const r = new FileReader();
        r.onload = () => {
            const bytes = new Uint8Array(r.result);
            let bin = '';
            for(let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
            resolve(btoa(bin));
        };
        r.onerror = () => reject(new Error('Die Datei konnte nicht gelesen werden.'));
        r.readAsArrayBuffer(file);
    });
}

function showCertResult(kind, html) {
    const box = document.getElementById('cert-result');
    const cls = kind === 'ok' ? 'border-emerald-500/30 bg-emerald-500/5 text-emerald-200' : (kind === 'warn' ? 'border-amber-500/30 bg-amber-500/5 text-amber-200' : 'border-rose-500/30 bg-rose-500/5 text-rose-300');
    box.className = `p-4 rounded-xl border text-xs space-y-1 ${cls}`;
    box.innerHTML = html;
}

async function uploadCertificate() {
    const btn = document.getElementById('cert-upload-btn');
    btn.disabled = true;
    try {
        const body = {password: document.getElementById('cert-password').value};
        if(certMode === 'pfx') {
            body.pfx = await readFileBase64(document.getElementById('cert-pfx'));
            if(!body.pfx) { showToast('Bitte eine PFX/P12-Datei auswählen.', 'error'); return; }
        } else {
            body.cert = await readFileBase64(document.getElementById('cert-file'));
            body.key = await readFileBase64(document.getElementById('cert-key'));
            body.chain = await readFileBase64(document.getElementById('cert-chain'));
            if(!body.cert) { showToast('Bitte das Zertifikat auswählen.', 'error'); return; }
        }
        const res = await fetch('/api/tls/upload', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)});
        const data = await res.json().catch(() => ({}));
        if(!res.ok) { showCertResult('error', `<p><i class="fa-solid fa-circle-exclamation mr-1"></i>${esc(tr(data.detail || 'Übernahme fehlgeschlagen.'))}</p>`); return; }
        renderCertificate(data.certificate);
        ['cert-pfx', 'cert-file', 'cert-key', 'cert-chain', 'cert-password'].forEach(id => { const el = document.getElementById(id); if(el) el.value = ''; });
        const warns = (data.warnings || []).map(w => `<p><i class="fa-solid fa-triangle-exclamation mr-1"></i>${esc(tr(w))}</p>`).join('');
        const live = data.live ? 'Das Zertifikat ist ab sofort aktiv. Seite neu laden, damit der Browser es verwendet.' : 'Gespeichert. Es wird nach einem Neustart des Containers aktiv.';
        showCertResult(warns ? 'warn' : 'ok', `<p><i class="fa-solid fa-circle-check mr-1"></i>${esc(tr(live))}</p>${warns}`);
        showToast('Zertifikat übernommen.', 'success');
    } catch(e) {
        showCertResult('error', `<p>${esc(tr(e.message || 'Übernahme fehlgeschlagen.'))}</p>`);
    } finally {
        btn.disabled = false;
    }
}

async function createSelfSigned() {
    const names = (document.getElementById('cert-ss-names').value || '').split(',').map(n => n.trim()).filter(Boolean);
    if(!confirm('Ein neues selbstsigniertes Zertifikat erzeugen und sofort verwenden? Das bisherige wird als .prev aufbewahrt.')) return;
    try {
        const res = await fetch('/api/tls/self-signed', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({names})});
        const data = await res.json().catch(() => ({}));
        if(!res.ok) { showToast(data.detail || 'Erzeugen fehlgeschlagen.', 'error'); return; }
        renderCertificate(data.certificate);
        showToast(data.live ? 'Selbstsigniertes Zertifikat erzeugt und aktiv.' : 'Selbstsigniertes Zertifikat erzeugt. Aktiv nach Neustart.', 'success');
    } catch(e) { showToast('Erzeugen fehlgeschlagen.', 'error'); }
}

function openReportsDelete() {
    const age = Number(document.getElementById('rep-del-age').value) || 0;
    const text = reportKind === 'audit'
        ? (age ? `Alle Änderungen löschen, die älter als ${age} Tage sind?` : 'Wirklich alle Änderungen löschen?')
        : (age ? `Alle Protokoll-Einträge löschen, die älter als ${age} Tage sind?` : 'Wirklich alle Protokoll-Einträge löschen?');
    document.getElementById('rep-del-text').textContent = text;
    document.getElementById('rep-del-pass').value = '';
    document.getElementById('reports-delete-modal').classList.remove('hidden');
    setTimeout(() => document.getElementById('rep-del-pass').focus(), 50);
}

function closeReportsDelete() {
    document.getElementById('reports-delete-modal').classList.add('hidden');
    document.getElementById('rep-del-pass').value = '';
}

async function executeReportsDelete() {
    const btn = document.getElementById('rep-del-exec');
    const password = document.getElementById('rep-del-pass').value;
    if(!password) { showToast('Bitte das Passwort zur Bestätigung eingeben.', 'error'); return; }
    btn.disabled = true;
    try {
        const res = await fetch('/api/reports/delete', {
            method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({kind: reportKind, olderThanDays: Number(document.getElementById('rep-del-age').value) || 0, password: password})
        });
        const data = await res.json().catch(() => ({}));
        if(!res.ok) { showToast(data.detail || 'Löschen fehlgeschlagen.', 'error'); return; }
        closeReportsDelete();
        showToast(data.removed === 1 ? '1 Eintrag gelöscht.' : `${data.removed} Einträge gelöscht.`, 'success');
        await loadReports();
    } catch(e) {
        showToast('Löschen fehlgeschlagen.', 'error');
    } finally {
        btn.disabled = false;
    }
}

// ---------------------------------------------------------------
// Delete accounts (administrators only) - configuration and simulation
// ---------------------------------------------------------------
let cachedDeleteUsers = [];
let delPlan = null;
const DEL_LOCATIONS = [
    {kind: 'profile', key: 'del-profile', attr: true, suffixes: true},
    {kind: 'folderRedirection', key: 'del-redir', attr: false, suffixes: false},
    {kind: 'home', key: 'del-home', attr: true, suffixes: false}
];

// Never translate AD data (names, DNs, paths)
function nt(value) {
    return `<span translate="no">${esc(value)}</span>`;
}

function fmtBytes(n) {
    n = Number(n) || 0;
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let i = 0;
    while(n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
    return (i === 0 ? n : n.toFixed(1)) + ' ' + units[i];
}

async function loadDeletionConfig() {
    if(currentUserRole !== "Administrator") return;
    const res = await fetch('/api/deletion-config');
    if(!res.ok) return;
    const cfg = await res.json();
    document.getElementById('del-enabled').checked = !!cfg.enabled;
    const offTarget = document.getElementById('off-cfg-target');
    document.getElementById('del-cfg-ou').value = cfg.disabledOu || (offTarget ? offTarget.value : '') || '';
    DEL_LOCATIONS.forEach(loc => {
        const c = cfg[loc.kind] || {};
        document.getElementById(loc.key + '-enabled').checked = !!c.enabled;
        document.getElementById(loc.key + '-roots').value = (c.roots || []).join('\n');
        if(loc.attr) document.getElementById(loc.key + '-attr').checked = c.useAdAttr !== false;
        if(loc.suffixes) document.getElementById(loc.key + '-suffixes').value = (c.suffixes || []).join(', ');
        document.getElementById(loc.key + '-take').checked = !!c.takeOwnership;
    });
}

async function saveDeletionConfig() {
    if(currentUserRole !== "Administrator") return alert("Keine Berechtigung.");
    const data = {
        enabled: document.getElementById('del-enabled').checked,
        disabledOu: document.getElementById('del-cfg-ou').value
    };
    DEL_LOCATIONS.forEach(loc => {
        data[loc.kind] = {
            enabled: document.getElementById(loc.key + '-enabled').checked,
            roots: document.getElementById(loc.key + '-roots').value.split('\n').map(x => x.trim()).filter(Boolean),
            useAdAttr: loc.attr ? document.getElementById(loc.key + '-attr').checked : false,
            suffixes: loc.suffixes ? document.getElementById(loc.key + '-suffixes').value.split(/[\s,;]+/).filter(Boolean) : [],
            takeOwnership: document.getElementById(loc.key + '-take').checked
        };
    });
    const res = await fetch('/api/deletion-config', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(data) });
    if(res.ok) {
        alert("Konfiguration gespeichert!");
        await refreshAllLdapData();
    } else {
        const err = await res.json();
        alert(err.detail || "Fehler beim Speichern der Konfiguration.");
    }
}

async function testDeletionPaths() {
    const box = document.getElementById('del-test-result');
    box.innerHTML = '<div class="text-slate-400">Teste Verbindung...</div>';
    const res = await fetch('/api/deletion/test', { method: 'POST' });
    const data = await res.json();
    if(!res.ok) { box.innerHTML = `<div class="text-rose-400">${esc(data.detail || 'Fehler beim Test.')}</div>`; return; }
    box.innerHTML = data.results.map(r => `<div class="p-2.5 rounded-xl border ${r.ok ? 'border-emerald-500/30 bg-emerald-500/5' : 'border-rose-500/30 bg-rose-500/5'}">
        <span class="${r.ok ? 'text-emerald-400' : 'text-rose-400'}">${r.ok ? '✔' : '✖'}</span> <strong class="text-slate-200">${esc(r.label)}</strong> <span class="text-slate-300">${nt(r.root)}</span>
        <div class="text-[11px] text-slate-400 mt-0.5">${esc(r.message)}${r.ok ? ' (' + r.entries + ' Einträge)' : ''}</div></div>`).join('');
}

async function loadDeletionUsers(force) {
    if(currentUserRole !== "Administrator") return;
    const res = await fetch('/api/deletion/users' + freshQuery(force));
    if(!res.ok) return;
    const data = await res.json();
    cachedDeleteUsers = data.users || [];
    renderDeletionTable(cachedDeleteUsers, data.warning);
}

function filterDeletionTable() {
    const q = document.getElementById('del-search').value.toLowerCase();
    renderDeletionTable(cachedDeleteUsers.filter(u => (u.name || '').toLowerCase().includes(q) || (u.sam || '').toLowerCase().includes(q)));
}

const DEL_BATCH_MAX = 25;
const delSelected = new Set();
let delBatchPlan = null;
let delJobTimer = null;

function updateDeletionSelection() {
    const n = delSelected.size;
    const cnt = document.getElementById('del-sel-count');
    if(cnt) cnt.textContent = n;
    const btn = document.getElementById('del-batch-sim-btn');
    if(btn) btn.disabled = n === 0;
}

function toggleDeletionSelect(dn, on) {
    if(on) {
        if(delSelected.size >= DEL_BATCH_MAX) {
            alert(`Pro Durchlauf sind höchstens ${DEL_BATCH_MAX} Konten erlaubt.`);
            filterDeletionTable();
            return;
        }
        delSelected.add(dn);
    } else {
        delSelected.delete(dn);
    }
    updateDeletionSelection();
}

function toggleSelectAllDeletion(on) {
    const q = document.getElementById('del-search').value.toLowerCase();
    const visible = cachedDeleteUsers.filter(u => u.disabled && !u.self && !u.protected && ((u.name || '').toLowerCase().includes(q) || (u.sam || '').toLowerCase().includes(q)));
    if(!on) visible.forEach(u => delSelected.delete(u.dn));
    else {
        let skipped = 0;
        visible.forEach(u => { if(delSelected.size < DEL_BATCH_MAX) delSelected.add(u.dn); else if(!delSelected.has(u.dn)) skipped++; });
        if(skipped) alert(`Es wurden ${DEL_BATCH_MAX} Konten ausgewählt, ${skipped} weitere nicht (Obergrenze pro Durchlauf).`);
    }
    filterDeletionTable();
}

function renderDeletionTable(users, warning) {
    const tbody = document.getElementById('del-user-list');
    document.getElementById('del-count').textContent = users.length + ' Konten';
    if(users.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" class="p-6 text-center text-slate-500 italic">${esc(warning || 'Keine Konten gefunden.')}</td></tr>`;
        return;
    }
    const known = new Set(cachedDeleteUsers.map(u => u.dn));
    [...delSelected].forEach(dn => { if(!known.has(dn)) delSelected.delete(dn); });
    updateDeletionSelection();
    tbody.innerHTML = users.map(u => {
        let status = '<span class="text-emerald-400">Deaktiviert</span>';
        let box = `<input type="checkbox" data-dn="${esc(u.dn)}" ${delSelected.has(u.dn) ? 'checked' : ''} data-on-change="toggleDeletionSelect(this.dataset.dn, this.checked)" class="del-sel accent-cyan-500">`;
        let action = `<button data-dn="${esc(u.dn)}" data-on-click="simulateDeletion(this.dataset.dn)" class="px-3 py-1.5 bg-amber-600 hover:bg-amber-500 text-white rounded-lg font-medium transition-all shadow"><i class="fa-solid fa-flask mr-1"></i> Simulation</button>`;
        if(u.self) { status = '<span class="text-slate-500">Eigenes Konto</span>'; action = ''; box = ''; }
        else if(u.protected) { status = `<span class="text-amber-400" title="${esc(u.protected)}"><i class="fa-solid fa-lock mr-1"></i>Geschützt: ${esc(u.protected)}</span>`; action = ''; box = ''; }
        else if(!u.disabled) { status = '<span class="text-amber-400">Noch aktiv</span>'; action = ''; box = ''; }
        return `<tr class="hover:bg-slate-900/40"><td class="p-3.5">${box}</td><td class="p-3.5 text-white font-sans">${nt(u.name)}</td><td class="p-3.5 text-slate-300">${nt(u.sam)}</td><td class="p-3.5">${status}</td><td class="p-3.5 text-right">${action}</td></tr>`;
    }).join('');
}

const DEL_STATUS = {
    found: ['Vorhanden', 'text-emerald-400'],
    takeover: ['Besitz nötig', 'text-amber-400'],
    missing: ['Nicht vorhanden', 'text-slate-500'],
    denied: ['Kein Zugriff', 'text-rose-400'],
    error: ['Fehler', 'text-rose-400'],
    skipped: ['Übersprungen', 'text-amber-400']
};

function delSimRows(targets) {
    return targets.map(t => {
        const st = DEL_STATUS[t.status] || [t.status, 'text-slate-400'];
        const notes = [t.message && !['found', 'missing'].includes(t.status) ? t.message : '', ...(t.warnings || [])].filter(Boolean).map(m => `<div class="text-[11px] text-amber-300/90 font-sans">${esc(m)}</div>`).join('');
        const numbers = t.status === 'found' ? `${t.files}${t.truncated ? '+' : ''} Dateien, ${t.dirs} Ordner, ${esc(fmtBytes(t.size))}${t.links ? ', ' + t.links + ' Verknüpfung(en)' : ''}` : (t.status === 'takeover' ? 'Inhalt vorab nicht zählbar' : '');
        return `<tr><td class="p-3 text-slate-200 font-sans">${esc(t.label)}</td>
            <td class="p-3"><div class="text-slate-300 break-all">${nt(t.path || '-')}</div><div class="text-[10px] text-slate-500 font-sans">Quelle: ${esc(t.source)}</div>${notes}</td>
            <td class="p-3 ${st[1]}">${esc(st[0])}</td><td class="p-3 text-slate-300">${numbers}</td></tr>`;
    }).join('');
}

async function simulateDeletion(userDn) {
    if(delJobTimer) { clearTimeout(delJobTimer); delJobTimer = null; }  // do not let it overwrite the display of a batch run
    const box = document.getElementById('del-sim-result');
    box.innerHTML = '<div class="text-xs text-slate-400">Simulation läuft (kann bei großen Profilen etwas dauern)...</div>';
    const res = await fetch('/api/deletion/simulate', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ userDn }) });
    const data = await res.json();
    if(!res.ok) { box.innerHTML = `<div class="p-4 rounded-xl border border-rose-500/30 bg-rose-500/5 text-xs text-rose-300">${esc(data.detail || 'Fehler bei der Simulation.')}</div>`; return; }
    const a = data.account, sum = data.summary;
    const rows = delSimRows(data.targets);
    const warn = (data.warnings || []).map(w => `<li>${esc(w)}</li>`).join('');
    delPlan = data.planId ? { dn: a.dn, planId: data.planId, sam: a.sam } : null;
    let deleteBox = '';
    if(data.planId) {
        const until = data.planExpiresAt ? new Date(data.planExpiresAt).toLocaleTimeString() : '';
        const skipped = data.targets.filter(t => t.status === 'skipped').length;
        deleteBox = `<div class="p-4 rounded-xl border border-rose-500/40 bg-rose-500/5 text-xs space-y-3">
            <div class="text-rose-300 font-semibold"><i class="fa-solid fa-triangle-exclamation mr-1"></i> Endgültig löschen</div>
            <p class="text-slate-300">Das AD-Konto <strong>${nt(a.sam)}</strong> und alle oben als „Vorhanden“ oder „Besitz nötig“ gezeigten Ordner werden <strong>unwiderruflich</strong> gelöscht. ${skipped ? 'Übersprungene Ordner bleiben bestehen. ' : ''}Vor dem Löschen wird der Zustand erneut geprüft; hat sich etwas geändert, passiert nichts.</p>
            <div class="flex gap-2 items-center">
                <input type="text" id="del-confirm-sam" data-on-input="onDelConfirmInput()" autocomplete="off" placeholder="Benutzernamen zur Bestätigung eintippen: ${esc(a.sam)}" class="flex-1 bg-slate-950 border border-slate-800 rounded-xl p-2.5 text-white text-xs font-mono focus:border-rose-500 focus:outline-none">
                <input type="password" id="del-confirm-pw" data-on-input="onDelConfirmInput()" autocomplete="current-password" placeholder="Ihr Passwort" class="w-44 bg-slate-950 border border-slate-800 rounded-xl p-2.5 text-white text-xs font-mono focus:border-rose-500 focus:outline-none">
                <button id="del-exec-btn" data-on-click="executeDeletion()" disabled class="px-4 py-2.5 bg-rose-600 hover:bg-rose-500 disabled:opacity-40 disabled:cursor-not-allowed text-white rounded-xl font-semibold shadow"><i class="fa-solid fa-trash-can mr-1"></i> Endgültig löschen</button>
            </div>
            <div class="text-[11px] text-slate-500">Der Plan ist nur kurz gültig${until ? ' (bis ' + esc(until) + ')' : ''}.</div>
        </div>`;
    } else if((data.blockers || []).length) {
        deleteBox = `<div class="p-4 rounded-xl border border-rose-500/30 bg-rose-500/5 text-xs space-y-1">
            <div class="text-rose-300 font-semibold"><i class="fa-solid fa-ban mr-1"></i> Löschen nicht möglich</div>
            <ul class="list-disc pl-5 text-rose-200/90 break-all">${data.blockers.map(b => `<li>${esc(b)}</li>`).join('')}</ul>
            <div class="text-slate-400">Ursache beheben (Rechte, Verknüpfungen, Erreichbarkeit) und die Simulation wiederholen.</div>
        </div>`;
    }
    box.innerHTML = `
        <div class="card p-5 space-y-2 text-xs">
            <h3 class="font-bold text-amber-400"><i class="fa-solid fa-flask mr-1"></i> Simulationsergebnis – es wurde nichts verändert</h3>
            <div class="font-mono space-y-1">
                <div><span class="text-slate-400">AD-Konto:</span> <strong class="text-white">${nt(a.name)}</strong> (${nt(a.sam)}) – würde gelöscht</div>
                <div class="text-slate-400 break-all">${nt(a.dn)}</div>
                <div class="text-slate-400">Gruppenmitgliedschaften: ${a.groups.length}${a.groups.length ? ' (' + esc(a.groups.join(', ')) + ')' : ''}</div>
            </div>
        </div>
        <div class="card overflow-hidden">
            <table class="w-full text-left text-xs font-mono">
                <thead class="table-head"><tr><th class="p-3">Ort</th><th class="p-3">Pfad</th><th class="p-3">Status</th><th class="p-3">Inhalt</th></tr></thead>
                <tbody class="divide-y divide-slate-800/60">${rows || '<tr><td colspan="4" class="p-4 text-slate-500 italic font-sans">Keine Speicherorte aktiviert.</td></tr>'}</tbody>
            </table>
        </div>
        <div class="p-4 rounded-xl bg-slate-900/80 border border-slate-800 text-xs space-y-1">
            <div class="text-slate-200"><strong>Zusammenfassung:</strong> ${sum.folders} Ordner gefunden, ${sum.files} Dateien, ${esc(fmtBytes(sum.size))}${sum.allDeletable ? '' : ' – <span class="text-rose-400">nicht alles wäre löschbar (fehlende Zugriffsrechte)</span>'}</div>
            ${sum.takeovers ? `<div class="text-amber-300/90">Bei ${sum.takeovers} Ordner(n) ohne Zugriff würde vor dem Löschen der Besitz übernommen (Administratoren erhalten Vollzugriff).</div>` : ''}
            ${sum.links ? `<div class="text-slate-400">${sum.links} Verknüpfung(en): Es wird nur die Verknüpfung entfernt, nie der Inhalt des Ziels.</div>` : ''}
            ${warn ? `<ul class="list-disc pl-5 text-amber-300/90">${warn}</ul>` : ''}
            <div class="text-slate-500">Stand: ${esc(data.simulatedAt)}</div>
        </div>${deleteBox}`;
    const confirmInput = document.getElementById('del-confirm-sam');
    if(confirmInput) confirmInput.focus();
}

function onDelConfirmInput() {
    const ok = delPlan && document.getElementById('del-confirm-sam').value.trim().toLowerCase() === delPlan.sam.toLowerCase() && document.getElementById('del-confirm-pw').value.length > 0;
    document.getElementById('del-exec-btn').disabled = !ok;
}

const DEL_RESULT = {
    deleted: ['Gelöscht', 'text-emerald-400'],
    missing: ['Nicht mehr vorhanden', 'text-slate-400'],
    failed: ['Fehlgeschlagen', 'text-rose-400']
};


// ---------------------------------------------------------------
// Batch deletion: simulate several accounts and delete them one after another
// ---------------------------------------------------------------
function delBox() { return document.getElementById('del-sim-result'); }
function delErr(msg) { return `<div class="p-4 rounded-xl border border-rose-500/30 bg-rose-500/5 text-xs text-rose-300">${esc(msg)}</div>`; }

async function simulateBatch() {
    if(currentUserRole !== "Administrator" || delSelected.size === 0) return;
    if(delJobTimer) { clearTimeout(delJobTimer); delJobTimer = null; }
    delPlan = null; delBatchPlan = null;
    const box = delBox();
    box.innerHTML = `<div class="text-xs text-slate-400"><i class="fa-solid fa-spinner fa-spin mr-1"></i> Simulation für ${delSelected.size} Konto/Konten läuft (kann bei großen Profilen etwas dauern)...</div>`;
    let res, data;
    try {
        res = await fetch('/api/deletion/simulate-batch', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ userDns: [...delSelected] }) });
        data = await res.json();
    } catch(e) { box.innerHTML = delErr('Verbindung unterbrochen: ' + e.message); return; }
    if(!res.ok) { box.innerHTML = delErr(data.detail || 'Fehler bei der Simulation.'); return; }
    const ready = data.items.filter(i => i.state === 'ready');
    delBatchPlan = data.planId ? { planId: data.planId, count: ready.length, sams: ready.map(i => i.sam) } : null;
    const cards = data.items.map(i => {
        if(i.state !== 'ready') {
            const why = [i.error, ...(i.blockers || [])].filter(Boolean).map(m => `<div class="text-[11px] text-rose-300/90 font-sans break-all">${esc(m)}</div>`).join('');
            return `<div class="p-3 rounded-xl border border-rose-500/30 bg-rose-500/5 text-xs"><span class="text-rose-400 font-semibold">Blockiert</span> <strong class="text-slate-200">${nt(i.name || i.dn)}</strong> ${i.sam ? `<span class="text-slate-400 font-mono">(${nt(i.sam)})</span>` : ''}${why}${i.targets ? `<details class="mt-2"><summary class="cursor-pointer text-slate-400">Pfade anzeigen</summary>${delSimTable(i.targets)}</details>` : ''}</div>`;
        }
        const sm = i.summary;
        const extra = [sm.takeovers ? `${sm.takeovers}× Besitzübernahme` : '', sm.links ? `${sm.links} Verknüpfung(en)` : '', ...(i.warnings || [])].filter(Boolean).map(x => tr(x)).join(' · ');
        return `<div class="p-3 rounded-xl border border-emerald-500/30 bg-emerald-500/5 text-xs"><span class="text-emerald-400 font-semibold">Bereit</span> <strong class="text-slate-200">${nt(i.name)}</strong> <span class="text-slate-400 font-mono">(${nt(i.sam)})</span>
            <div class="text-slate-300 font-mono mt-1">${sm.folders} Ordner, ${sm.files} Dateien, ${esc(fmtBytes(sm.size))}</div>${extra ? `<div class="text-[11px] text-amber-300/90 font-sans">${esc(extra)}</div>` : ''}
            <details class="mt-2"><summary class="cursor-pointer text-slate-400">Pfade anzeigen</summary>${delSimTable(i.targets)}</details></div>`;
    }).join('');
    let confirmBox = '';
    if(delBatchPlan) {
        const until = data.planExpiresAt ? new Date(data.planExpiresAt).toLocaleTimeString() : '';
        confirmBox = `<div class="p-4 rounded-xl border border-rose-500/40 bg-rose-500/5 text-xs space-y-3">
            <div class="text-rose-300 font-semibold"><i class="fa-solid fa-triangle-exclamation mr-1"></i> ${ready.length} Konto/Konten endgültig löschen</div>
            <p class="text-slate-300">Gelöscht werden die als „Bereit“ markierten Konten samt ihrer Ordner – <strong>unwiderruflich</strong>. Blockierte Konten bleiben unberührt. Jedes Konto wird vor dem Löschen erneut geprüft und einzeln abgearbeitet; bei einem Fehler bleibt dieses Konto bestehen, die übrigen laufen weiter.</p>
            <div class="flex flex-wrap gap-2 items-center">
                <input type="text" id="del-batch-count" data-on-input="onDelBatchInput()" autocomplete="off" inputmode="numeric" placeholder="Anzahl eintippen: ${ready.length}" class="w-52 bg-slate-950 border border-slate-800 rounded-xl p-2.5 text-white text-xs font-mono focus:border-rose-500 focus:outline-none">
                <input type="password" id="del-batch-pw" data-on-input="onDelBatchInput()" autocomplete="current-password" placeholder="Ihr Passwort" class="w-44 bg-slate-950 border border-slate-800 rounded-xl p-2.5 text-white text-xs font-mono focus:border-rose-500 focus:outline-none">
                <button id="del-batch-btn" data-on-click="executeBatch()" disabled class="px-4 py-2.5 bg-rose-600 hover:bg-rose-500 disabled:opacity-40 disabled:cursor-not-allowed text-white rounded-xl font-semibold shadow"><i class="fa-solid fa-trash-can mr-1"></i> Endgültig löschen</button>
            </div>
            <div class="text-[11px] text-slate-500">Der Plan ist nur kurz gültig${until ? ' (bis ' + esc(until) + ')' : ''}.</div>
        </div>`;
    } else {
        confirmBox = `<div class="p-4 rounded-xl border border-rose-500/30 bg-rose-500/5 text-xs text-rose-300"><i class="fa-solid fa-ban mr-1"></i> Keines der Konten kann gelöscht werden. Ursachen beheben und die Simulation wiederholen.</div>`;
    }
    box.innerHTML = `
        <div class="card p-5 space-y-3 text-xs">
            <h3 class="font-bold text-amber-400"><i class="fa-solid fa-flask mr-1"></i> Sammel-Simulation – es wurde nichts verändert</h3>
            <div class="text-slate-300">${ready.length} von ${data.items.length} Konten sind bereit.</div>
            <div class="space-y-2">${cards}</div>
        </div>${confirmBox}`;
    const c = document.getElementById('del-batch-count');
    if(c) c.focus();
}

function delSimTable(targets) {
    return `<table class="w-full text-left text-xs font-mono mt-2"><tbody class="divide-y divide-slate-800/60">${delSimRows(targets || [])}</tbody></table>`;
}

function onDelBatchInput() {
    const ok = delBatchPlan && document.getElementById('del-batch-count').value.trim() === String(delBatchPlan.count) && document.getElementById('del-batch-pw').value.length > 0;
    document.getElementById('del-batch-btn').disabled = !ok;
}

function executeBatch() { return guarded('delete-batch', _executeBatch); }
async function _executeBatch() {
    if(currentUserRole !== "Administrator" || !delBatchPlan) return;
    const countText = document.getElementById('del-batch-count').value.trim();
    const password = document.getElementById('del-batch-pw').value;
    if(countText !== String(delBatchPlan.count)) return alert('Die eingegebene Anzahl stimmt nicht.');
    if(!confirm(`${delBatchPlan.count} Konto/Konten und die gezeigten Ordner jetzt ENDGÜLTIG löschen?\n\nDas kann nicht rückgängig gemacht werden.`)) return;
    const box = delBox();
    const savedHtml = box.innerHTML;
    let res, data;
    try {
        res = await fetch('/api/deletion/execute-batch', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ planId: delBatchPlan.planId, confirmCount: Number(countText), password }) });
        data = await res.json();
    } catch(e) { delBatchPlan = null; box.innerHTML = delErr('Verbindung unterbrochen: ' + e.message + '. Bitte unter „Berichte“ prüfen, was erledigt wurde.'); return; }
    if(!res.ok && isPasswordError(res, data)) {
        box.innerHTML = savedHtml;
        document.getElementById('del-batch-count').value = countText;
        const pw = document.getElementById('del-batch-pw');
        pw.value = ''; pw.focus();
        onDelBatchInput();
        alert(data.detail || 'Das Passwort ist falsch.');
        return;
    }
    delBatchPlan = null;
    if(!res.ok) { box.innerHTML = delErr(data.detail || 'Löschen konnte nicht gestartet werden.'); return; }
    delSelected.clear();
    updateDeletionSelection();
    pollDeletionJob(data.jobId, 0);
}

const DEL_JOB_STATUS = {
    pending: ['Wartet', 'text-slate-500'],
    running: ['Läuft…', 'text-amber-300'],
    success: ['Gelöscht', 'text-emerald-400'],
    partial: ['Unvollständig – Konto besteht weiter', 'text-amber-400'],
    error: ['Nicht gelöscht', 'text-rose-400']
};

async function pollDeletionJob(jobId, failures) {
    const box = delBox();
    let job;
    try {
        const res = await fetch('/api/deletion/job/' + encodeURIComponent(jobId));
        if(!res.ok) throw new Error('HTTP ' + res.status);
        job = await res.json();
    } catch(e) {
        if(failures >= 5) { box.innerHTML = delErr('Der Fortschritt kann nicht mehr abgefragt werden (' + e.message + '). Der Löschauftrag läuft auf dem Server weiter – Ergebnis unter „Berichte“ prüfen.'); return; }
        delJobTimer = setTimeout(() => pollDeletionJob(jobId, failures + 1), 2000);
        return;
    }
    renderDeletionJob(job);
    if(job.finished) { delJobTimer = null; await loadDeletionUsers(); return; }
    delJobTimer = setTimeout(() => pollDeletionJob(jobId, 0), 1500);
}

function renderDeletionJob(job) {
    const pct = job.total ? Math.round(job.done * 100 / job.total) : 0;
    const rows = job.items.map(i => {
        const st = DEL_JOB_STATUS[i.status] || [i.status, 'text-slate-400'];
        const folders = (i.results || []).filter(r => ['deleted', 'failed'].includes(r.status));
        const errs = (i.results || []).flatMap(r => (r.errors || []).map(e => `<div class="text-[11px] text-rose-300/90 font-sans break-all">${esc(e)}</div>`)).join('');
        const detail = i.status === 'success' ? `${folders.length} Ordner, ${(i.results || []).reduce((n, r) => n + r.files, 0)} Dateien` + ((i.results || []).some(r => r.takeovers) ? `, Besitz übernommen: ${(i.results || []).reduce((n, r) => n + r.takeovers, 0)}×` : '') : (i.status === 'pending' || i.status === 'running' ? '' : String(i.message || ''));
        return `<tr><td class="p-3 text-slate-200 font-sans">${nt(i.name)}<div class="text-slate-500 font-mono text-[11px]">${nt(i.sam)}</div></td><td class="p-3 ${st[1]}">${esc(st[0])}</td><td class="p-3 text-slate-300 font-sans break-all">${esc(detail)}${errs}</td></tr>`;
    }).join('');
    const ok = job.items.filter(i => i.status === 'success').length;
    const head = job.finished
        ? `<div class="p-4 rounded-xl border ${ok === job.total ? 'border-emerald-500/30 bg-emerald-500/5 text-emerald-300' : 'border-amber-500/40 bg-amber-500/5 text-amber-200'} text-xs font-semibold">${ok === job.total ? '✔' : '⚠'} ${ok} von ${job.total} Konten gelöscht.${ok === job.total ? '' : ' Bei den übrigen bleibt das AD-Konto bestehen – Ursachen beheben und neu simulieren.'}</div>`
        : `<div class="p-4 rounded-xl border border-amber-500/30 bg-amber-500/5 text-xs text-amber-200 space-y-2"><div><i class="fa-solid fa-spinner fa-spin mr-1"></i> Löschauftrag läuft: ${job.done} von ${job.total}${job.current ? ' – aktuell ' + esc(job.current) : ''}. Die Seite kann offen bleiben; der Auftrag läuft auch auf dem Server weiter.</div><div class="h-2 bg-slate-800 rounded"><div class="h-2 bg-amber-500 rounded" style="width:${pct}%"></div></div></div>`;
    delBox().innerHTML = `${head}
        <div class="card overflow-hidden">
            <table class="w-full text-left text-xs font-mono">
                <thead class="table-head"><tr><th class="p-3">Konto</th><th class="p-3">Ergebnis</th><th class="p-3">Details</th></tr></thead>
                <tbody class="divide-y divide-slate-800/60">${rows}</tbody>
            </table>
        </div>`;
}

function isPasswordError(res, data) {
    return res.status === 429 || ((res.status === 403 || res.status === 400) && /Passwort/.test((data && data.detail) || ''));
}

async function executeDeletion() {
    if(currentUserRole !== "Administrator" || !delPlan) return;
    const typed = document.getElementById('del-confirm-sam').value.trim();
    const password = document.getElementById('del-confirm-pw').value;
    if(typed.toLowerCase() !== delPlan.sam.toLowerCase()) return alert("Die Bestätigung stimmt nicht mit dem Benutzernamen überein.");
    if(!confirm(`Konto '${delPlan.sam}' und die gezeigten Ordner jetzt ENDGÜLTIG löschen?\n\nDas kann nicht rückgängig gemacht werden.`)) return;
    const plan = delPlan;
    const box = document.getElementById('del-sim-result');
    const savedHtml = box.innerHTML;
    box.innerHTML = '<div class="text-xs text-amber-300"><i class="fa-solid fa-spinner fa-spin mr-1"></i> Löschvorgang läuft – bitte warten und die Seite nicht schließen...</div>';
    let res, data;
    try {
        res = await fetch('/api/deletion/execute', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ userDn: plan.dn, planId: plan.planId, confirmSam: typed, password }) });
        data = await res.json();
    } catch(e) {
        delPlan = null;
        box.innerHTML = `<div class="p-4 rounded-xl border border-rose-500/30 bg-rose-500/5 text-xs text-rose-300">Verbindung unterbrochen: ${esc(e.message)}. Bitte unter „Berichte“ prüfen, was erledigt wurde, und die Simulation wiederholen.</div>`;
        return;
    }
    if(!res.ok && isPasswordError(res, data)) {
        // The plan is still valid on the server: bring the form back and let the user enter it again
        box.innerHTML = savedHtml;
        const sam = document.getElementById('del-confirm-sam');
        if(sam) sam.value = typed;
        const pw = document.getElementById('del-confirm-pw');
        if(pw) { pw.value = ''; pw.focus(); }
        onDelConfirmInput();
        alert(data.detail || 'Das Passwort ist falsch.');
        return;
    }
    delPlan = null;
    if(!res.ok) {
        box.innerHTML = `<div class="p-4 rounded-xl border border-rose-500/30 bg-rose-500/5 text-xs text-rose-300 space-y-1"><div class="font-semibold">Es wurde nicht (vollständig) gelöscht.</div><div>${esc(data.detail || 'Fehler beim Löschen.')}</div></div>`;
        await loadDeletionUsers();
        return;
    }
    const rows = data.results.map(r => {
        const st = DEL_RESULT[r.status] || [r.status, 'text-slate-400'];
        const errs = (r.errors || []).map(e => `<div class="text-[11px] text-rose-300/90 font-sans break-all">${esc(e)}</div>`).join('');
        const more = r.errorCount > (r.errors || []).length ? `<div class="text-[11px] text-slate-500 font-sans">… und ${r.errorCount - r.errors.length} weitere Fehler</div>` : '';
        return `<tr><td class="p-3 text-slate-200 font-sans">${esc(r.label)}</td><td class="p-3"><div class="text-slate-300 break-all">${nt(r.path)}</div>${errs}${more}</td><td class="p-3 ${st[1]}">${esc(st[0])}</td><td class="p-3 text-slate-300">${r.files} Dateien, ${r.dirs} Ordner${r.links ? ', ' + r.links + ' Verknüpfung(en)' : ''}${r.takeovers ? `<div class="text-[11px] text-amber-300/90 font-sans">Besitz übernommen: ${r.takeovers}×</div>` : ''}</td></tr>`;
    }).join('');
    const ok = data.status === 'success';
    box.innerHTML = `
        <div class="p-4 rounded-xl border ${ok ? 'border-emerald-500/30 bg-emerald-500/5 text-emerald-300' : 'border-amber-500/40 bg-amber-500/5 text-amber-200'} text-xs font-semibold">${ok ? '✔' : '⚠'} ${esc(data.message)}</div>
        <div class="card overflow-hidden">
            <table class="w-full text-left text-xs font-mono">
                <thead class="table-head"><tr><th class="p-3">Ort</th><th class="p-3">Pfad</th><th class="p-3">Ergebnis</th><th class="p-3">Menge</th></tr></thead>
                <tbody class="divide-y divide-slate-800/60">${rows || '<tr><td colspan="4" class="p-4 text-slate-500 italic font-sans">Keine Ordner betroffen.</td></tr>'}</tbody>
            </table>
        </div>`;
    await loadDeletionUsers();
}

// What each page needs from the AD structure: OUs always (small); all groups and all users of the domain
// (the large part) only where they are shown - the rest keeps what was loaded before
const INFRA_GROUPS = new Set(['hire', 'templates', 'infra']);
const INFRA_USERS = new Set(['templates']);
function infraQuery(tab, force) {
    const q = [`gruppen=${INFRA_GROUPS.has(tab) ? 1 : 0}`, `benutzer=${INFRA_USERS.has(tab) ? 1 : 0}`];
    if(force === true) q.push('frisch=1');
    return '?' + q.join('&');
}

async function loadInfrastructure(force) {
    const res = await fetch('/api/ad/infrastructure' + infraQuery(currentTab, force));
    if(res.ok) {
        adData = Object.assign({}, adData, await res.json());
        if (adData.error && !window._infraErrShown) {
            window._infraErrShown = true;
            alert("AD-Abfrage fehlgeschlagen: " + adData.error);
        }
        populateDropdowns();
        renderInfraView();
    }
}

// ---------------------------------------------------------------
// AD tree with checkboxes (replaces the multi-select lists)
// ---------------------------------------------------------------
const AD_BS = String.fromCharCode(92);
const AD_TREE_DEFS = {
    'off-cfg-source':       {subtree: true},
    'pwdreset-cfg-source':  {subtree: true},
    'usermgmt-cfg-source':  {subtree: true},
    'usermgmt-cfg-target':  {subtree: false},
    'usermgmt-cfg-groupou': {subtree: true},
    'tpl-groups':           {subtree: false, group: true}
};
const AD_TREES = {};

function adSplitDn(dn) {
    const parts = [];
    let cur = '', escaped = false;
    for (const ch of String(dn || '')) {
        if (escaped) { cur += ch; escaped = false; }
        else if (ch === AD_BS) { cur += ch; escaped = true; }
        else if (ch === ',') { parts.push(cur); cur = ''; }
        else { cur += ch; }
    }
    parts.push(cur);
    return parts;
}

function adDnKey(dn) {
    return adSplitDn(dn).map(p => p.trim().toLowerCase()).join(',');
}

function adUnescape(value) {
    let out = '', escaped = false;
    for (const ch of String(value)) {
        if (escaped) { out += ch; escaped = false; }
        else if (ch === AD_BS) { escaped = true; }
        else { out += ch; }
    }
    return out;
}

function adRdnValue(part) {
    const i = part.indexOf('=');
    return adUnescape(i >= 0 ? part.slice(i + 1) : part).trim();
}

function adEl(tag, cls, text) {
    const el = document.createElement(tag);
    if (cls) el.className = cls;
    if (text !== undefined) el.textContent = text;
    return el;
}

function adBuildTree(t) {
    const itemByKey = new Map();
    t.items.forEach(it => { if (it && it.dn) itemByKey.set(adDnKey(it.dn), it); });
    const nodes = new Map();
    const roots = [];

    const getNode = (parts) => {
        const key = parts.map(p => p.trim().toLowerCase()).join(',');
        let n = nodes.get(key);
        if (n) return n;
        const isDomain = parts.every(p => p.trim().toUpperCase().startsWith('DC='));
        const item = itemByKey.get(key) || null;
        n = {
            key: key,
            dn: parts.join(','),
            item: item,
            domain: isDomain,
            children: [],
            parent: null,
            label: isDomain ? parts.map(adRdnValue).join('.') : ((item && item.name) || adRdnValue(parts[0]))
        };
        nodes.set(key, n);
        const parentParts = isDomain ? [] : parts.slice(1);
        if (parentParts.length) {
            n.parent = getNode(parentParts);
            n.parent.children.push(n);
        } else {
            roots.push(n);
        }
        return n;
    };

    itemByKey.forEach(it => getNode(adSplitDn(it.dn)));

    const sortList = (list) => {
        list.sort((a, b) => ((b.children.length > 0) - (a.children.length > 0)) || a.label.localeCompare(b.label, 'de', {sensitivity: 'base'}));
        list.forEach(n => sortList(n.children));
    };
    sortList(roots);
    return {nodes: nodes, roots: roots};
}

function adTreeExpandSelected(t) {
    if (!t.tree) return;
    t.selected.forEach((dn, key) => {
        const n = t.tree.nodes.get(key);
        for (let p = n ? n.parent : null; p; p = p.parent) t.expanded.add(p.key);
    });
}

function adTreeRender(t) {
    if (!t.tree) t.tree = adBuildTree(t);
    const q = t.query.trim().toLowerCase();
    const scrollTop = t.list.scrollTop;
    t.list.textContent = '';

    const visibleCache = new Map();
    const isVisible = (n) => {
        if (visibleCache.has(n.key)) return visibleCache.get(n.key);
        let v = !q || n.label.toLowerCase().includes(q) || n.dn.toLowerCase().includes(q);
        n.children.forEach(c => { if (isVisible(c)) v = true; });
        visibleCache.set(n.key, v);
        return v;
    };
    const hasSelectedAncestor = (n) => {
        for (let p = n.parent; p; p = p.parent) {
            if (p.item && t.selected.has(p.key)) return true;
        }
        return false;
    };

    const renderNode = (n, depth) => {
        if (!isVisible(n)) return;
        const open = q ? true : t.expanded.has(n.key);
        const row = adEl('div', 'flex items-center gap-1 rounded-md pr-1 py-0.5 hover:bg-slate-800/60');
        row.style.paddingLeft = (depth * 14 + 2) + 'px';

        if (n.children.length) {
            const btn = adEl('button', 'w-4 h-4 shrink-0 text-slate-500 hover:text-cyan-400 leading-none', open ? '\u25BE' : '\u25B8');
            btn.type = 'button';
            btn.title = open ? 'Zuklappen' : 'Aufklappen';
            btn.addEventListener('click', () => {
                if (t.expanded.has(n.key)) t.expanded.delete(n.key); else t.expanded.add(n.key);
                adTreeRender(t);
            });
            row.appendChild(btn);
        } else {
            row.appendChild(adEl('span', 'w-4 shrink-0'));
        }

        const lab = adEl('label', 'flex items-center gap-1.5 min-w-0 flex-1 cursor-pointer');
        if (n.item) {
            const cb = adEl('input', 'accent-cyan-500 shrink-0');
            cb.type = 'checkbox';
            cb.checked = t.selected.has(n.key);
            cb.addEventListener('change', () => {
                if (cb.checked) t.selected.set(n.key, n.item.dn); else t.selected.delete(n.key);
                adTreeRender(t);
            });
            lab.appendChild(cb);
        } else if (n.children.length) {
            lab.addEventListener('click', () => {
                if (t.expanded.has(n.key)) t.expanded.delete(n.key); else t.expanded.add(n.key);
                adTreeRender(t);
            });
        }
        const icon = n.domain ? '\uD83C\uDF10' : (n.item && t.group ? '\uD83D\uDC65' : '\uD83D\uDCC1');
        lab.appendChild(adEl('span', 'shrink-0', icon));
        const name = adEl('span', (n.item ? 'text-white' : 'text-slate-500') + ' truncate', n.label);
        name.title = n.dn;
        lab.appendChild(name);
        row.appendChild(lab);

        if (t.subtree && n.item && !t.selected.has(n.key) && hasSelectedAncestor(n)) {
            const badge = adEl('span', 'ml-auto text-[9px] text-cyan-500/70 shrink-0', 'enthalten');
            badge.title = 'Durch eine übergeordnete OU bereits abgedeckt';
            row.appendChild(badge);
        }
        t.list.appendChild(row);
        if (open) n.children.forEach(c => renderNode(c, depth + 1));
    };
    t.tree.roots.forEach(r => renderNode(r, 0));

    const orphans = [];
    t.selected.forEach((dn, key) => {
        const n = t.tree.nodes.get(key);
        if (!n || !n.item) orphans.push([key, dn]);
    });
    if (orphans.length) {
        { const gone = adEl('div', 'mt-2 px-1 text-[11px] text-amber-400', 'Nicht (mehr) im AD gefunden'); gone.setAttribute('translate', 'yes'); t.list.appendChild(gone); }
        orphans.forEach(([key, dn]) => {
            const lab = adEl('label', 'flex items-center gap-1.5 px-1 py-0.5 cursor-pointer text-amber-300');
            const cb = adEl('input', 'accent-amber-500 shrink-0');
            cb.type = 'checkbox';
            cb.checked = true;
            cb.addEventListener('change', () => { t.selected.delete(key); adTreeRender(t); });
            lab.appendChild(cb);
            const span = adEl('span', 'truncate', dn);
            span.title = dn;
            lab.appendChild(span);
            t.list.appendChild(lab);
        });
    }
    if (!t.tree.roots.length && !orphans.length) {
        t.list.appendChild(adEl('div', 'p-3 text-center text-slate-500', 'Keine Einträge geladen'));
    }
    t.count.textContent = t.selected.size + ' ausgewählt';
    t.list.scrollTop = scrollTop;
}

function adTreeEnsure(id) {
    if (AD_TREES[id]) return AD_TREES[id];
    const host = document.getElementById(id);
    if (!host) return null;
    const def = AD_TREE_DEFS[id] || {subtree: true};
    const t = {
        id: id, host: host, subtree: !!def.subtree, group: !!def.group,
        items: [], tree: null, selected: new Map(), expanded: new Set(), query: '', initExpanded: false
    };
    AD_TREES[id] = t;

    host.textContent = '';
    host.className = 'bg-slate-950 border border-slate-800 rounded-xl overflow-hidden';

    const bar = adEl('div', 'flex items-center gap-1 p-1.5 border-b border-slate-800 bg-slate-900/60');
    const search = adEl('input', 'flex-1 min-w-0 bg-slate-950 border border-slate-800 rounded-lg px-2 py-1 text-xs text-white');
    search.type = 'text';
    search.placeholder = 'Suchen …';
    search.addEventListener('input', () => { t.query = search.value; adTreeRender(t); });
    const btnOpen = adEl('button', 'px-1.5 py-1 text-slate-400 hover:text-cyan-400', '\u229E');
    btnOpen.type = 'button';
    btnOpen.title = 'Alle aufklappen';
    btnOpen.addEventListener('click', () => {
        if (!t.tree) return;
        t.tree.nodes.forEach(n => { if (n.children.length) t.expanded.add(n.key); });
        adTreeRender(t);
    });
    const btnClose = adEl('button', 'px-1.5 py-1 text-slate-400 hover:text-cyan-400', '\u229F');
    btnClose.type = 'button';
    btnClose.title = 'Alle zuklappen';
    btnClose.addEventListener('click', () => {
        t.expanded.clear();
        if (t.tree) t.tree.roots.forEach(r => t.expanded.add(r.key));
        adTreeRender(t);
    });
    bar.appendChild(search);
    bar.appendChild(btnOpen);
    bar.appendChild(btnClose);

    t.list = adEl('div', 'max-h-64 overflow-auto p-1 text-xs font-mono');
    t.list.setAttribute('translate', 'no');

    const foot = adEl('div', 'flex items-center justify-between gap-2 px-2 py-1 border-t border-slate-800 text-[10px] text-slate-500');
    t.count = adEl('span', '', '0 ausgewählt');
    if (t.subtree) {
        const hint = adEl('span', 'truncate', 'Unter-OUs sind enthalten');
        foot.appendChild(t.count);
        foot.appendChild(hint);
    } else {
        foot.appendChild(t.count);
    }
    const clear = adEl('button', 'text-slate-400 hover:text-rose-400 shrink-0', 'Leeren');
    clear.type = 'button';
    clear.addEventListener('click', () => { t.selected.clear(); adTreeRender(t); });
    foot.appendChild(clear);

    host.appendChild(bar);
    host.appendChild(t.list);
    host.appendChild(foot);
    adTreeRender(t);
    return t;
}

function adTreeSetItems(id, items) {
    const t = adTreeEnsure(id);
    if (!t) return;
    t.items = items || [];
    t.tree = adBuildTree(t);
    if (!t.initExpanded && t.items.length) {
        t.initExpanded = true;
        t.tree.roots.forEach(r => t.expanded.add(r.key));
        if (t.tree.nodes.size <= 40) t.tree.nodes.forEach(n => { if (n.children.length) t.expanded.add(n.key); });
    }
    adTreeExpandSelected(t);
    adTreeRender(t);
}

function adTreeSetSelected(id, dns) {
    const t = adTreeEnsure(id);
    if (!t) return;
    t.selected = new Map((dns || []).map(dn => [adDnKey(dn), dn]));
    adTreeExpandSelected(t);
    adTreeRender(t);
}

function adTreeGetSelected(id) {
    const t = adTreeEnsure(id);
    return t ? Array.from(t.selected.values()) : [];
}

function populateDropdowns() {
    const ouSelect = document.getElementById('tpl-ou-select');
    if(ouSelect) {
        ouSelect.innerHTML = `<option value="">-- Oder OU aus AD-Liste wählen --</option>` + adData.ous.map(ou => `<option value="${esc(ou.dn)}">${nt(ou.name)} (${nt(ou.dn)})</option>`).join('');
    }
    const offSrc = document.getElementById('off-cfg-source');
    if(offSrc) {
        adTreeSetItems('off-cfg-source', adData.ous);
    }
    const offTgt = document.getElementById('off-cfg-target');
    if(offTgt) {
        offTgt.innerHTML = `<option value="">-- Ziel-OU für Deaktivierte wählen --</option>` + adData.ous.map(ou => `<option value="${esc(ou.dn)}">${nt(ou.name)} (${nt(ou.dn)})</option>`).join('');
    }
    const delOu = document.getElementById('del-cfg-ou');
    if(delOu) {
        const keep = delOu.value;
        delOu.innerHTML = `<option value="">-- OU der deaktivierten Konten wählen --</option>` + adData.ous.map(ou => `<option value="${esc(ou.dn)}">${nt(ou.name)} (${nt(ou.dn)})</option>`).join('');
        delOu.value = keep;
    }
    const pwdSrc = document.getElementById('pwdreset-cfg-source');
    if(pwdSrc) {
        adTreeSetItems('pwdreset-cfg-source', adData.ous);
    }
    
    const umSrc = document.getElementById('usermgmt-cfg-source');
    const umTgt = document.getElementById('usermgmt-cfg-target');
    const umGrp = document.getElementById('usermgmt-cfg-groupou');
    if(umSrc) adTreeSetItems('usermgmt-cfg-source', adData.ous);
    if(umTgt) adTreeSetItems('usermgmt-cfg-target', adData.ous);
    if(umGrp) adTreeSetItems('usermgmt-cfg-groupou', adData.ous);

    const groupSelect = document.getElementById('tpl-groups');
    if(groupSelect) {
        adTreeSetItems('tpl-groups', adData.groups);
    }
    const managerSelect = document.getElementById('tpl-manager-select');
    if(managerSelect) {
        managerSelect.innerHTML = `<option value="">-- Oder Manager aus AD-Benutzern wählen --</option>` + (adData.users || []).map(u => `<option value="${esc(u.dn)}">${nt(u.name)} (${nt(u.dn)})</option>`).join('');
    }
    const countrySelect = document.getElementById('tpl-country-select');
    if(countrySelect) {
        const defaultCountries = ["Deutschland", "Österreich", "Schweiz"];
        const combinedCountries = Array.from(new Set([...defaultCountries, ...(adData.countries || [])]));
        countrySelect.innerHTML = `<option value="">-- Land aus AD / Liste wählen --</option>` + combinedCountries.map(c => `<option value="${esc(c)}">${esc(c)}</option>`).join('');
    }
}

function renderInfraView() {
    document.getElementById('infra-ous').innerHTML = adData.ous.map(ou => `<li class="px-3 py-2.5 bg-slate-950/60 rounded-xl border border-slate-800/80 truncate"><i class="fa-solid fa-folder text-amber-300/80 mr-2"></i><strong class="text-white font-semibold">${nt(ou.name)}</strong><span class="block text-[11px] text-slate-500 font-mono truncate mt-0.5">${nt(ou.dn)}</span></li>`).join('');
    document.getElementById('infra-groups').innerHTML = adData.groups.map(g => `<li class="px-3 py-2.5 bg-slate-950/60 rounded-xl border border-slate-800/80 truncate"><i class="fa-solid fa-user-group text-emerald-300/80 mr-2"></i><strong class="text-white font-semibold">${nt(g.name)}</strong><span class="block text-[11px] text-slate-500 font-mono truncate mt-0.5">${nt(g.dn)}</span></li>`).join('');
}

async function loadTemplates() {
    const res = await fetch('/api/templates');
    if(res.ok) {
        templates = await res.json();
        templates.sort((a, b) => (a.name || '').localeCompare(b.name || '', undefined, {sensitivity: 'base'}));
        
        document.getElementById('hire-template').innerHTML = templates.map(tpl => `<option value="${esc(tpl.id)}">${nt(tpl.name)}</option>`).join('');
        applyMailMode();
        
        let tplHtml = "";
        templates.forEach(tpl => {
            let adminButtons = '';
            if(currentUserRole === "Administrator") {
                adminButtons = `
                    <button data-on-click="openTemplateModal(${Number(tpl.id)})" class="px-3 py-1.5 bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 rounded-lg text-xs font-medium transition-all">Bearbeiten</button>
                    <button data-on-click="duplicateTemplate(${Number(tpl.id)})" class="px-3 py-1.5 bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 rounded-lg text-xs font-medium transition-all">Duplizieren</button>
                    <button data-on-click="deleteTemplate(${Number(tpl.id)})" class="px-3 py-1.5 bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 rounded-lg text-xs font-medium transition-all">Löschen</button>
                `;
            } else {
                adminButtons = `<span class="text-xs text-slate-500 italic">Read-only</span>`;
            }

            const mail = TPL_MAIL_LABELS[tpl.mailMode] || TPL_MAIL_LABELS.required;
            const groupCount = (tpl.groups || []).length;
            tplHtml += `
                <div class="card p-5 flex flex-wrap gap-4 justify-between items-center">
                    <div class="min-w-0 space-y-2">
                        <h4 class="font-bold text-white text-[15px]">${nt(tpl.name)}</h4>
                        <div class="flex flex-wrap gap-1.5 text-xs">
                            <span class="tpl-tag"><i class="fa-solid ${mail.icon}"></i> ${esc(mail.text)}</span>
                            <span class="tpl-tag"><i class="fa-solid fa-user-group"></i> ${groupCount === 1 ? '1 Gruppe' : groupCount + ' Gruppen'}</span>
                            ${tpl.createHomeFolder ? '<span class="tpl-tag"><i class="fa-solid fa-folder-plus"></i> Basisordner</span>' : ''}
                        </div>
                        <div class="text-xs text-slate-400 truncate">Benutzername <span class="font-mono text-slate-300">${nt(tpl.naming)}</span> in <span class="font-mono text-slate-300">${nt(tpl.ouDn)}</span></div>
                    </div>
                    <div class="flex gap-2 shrink-0">${adminButtons}</div>
                </div>
            `;
        });
        document.getElementById('template-list').innerHTML = tplHtml;
        previewTemplateInfo();
    }
}

const TPL_MAIL_LABELS = {
    required: {icon: 'fa-at', text: 'E-Mail Pflicht'},
    optional: {icon: 'fa-at', text: 'E-Mail optional'},
    exchange: {icon: 'fa-server', text: 'Exchange-Postfach'},
    cloud: {icon: 'fa-cloud', text: 'Microsoft 365'}
};

function previewTemplateInfo() {
    const tplId = document.getElementById('hire-template').value;
    const tpl = templates.find(item => item.id == tplId);
    applyMailMode();
    if(!tpl) return;
    document.getElementById('prev-ou').textContent = tpl.ouDn;
    document.getElementById('prev-naming').textContent = tpl.naming;
    document.getElementById('prev-pwd-mode').textContent = tpl.pwdMode === 'random' ? 'Zufallspasswort' : 'Festes Standardpasswort';
    document.getElementById('prev-never-expire').textContent = tpl.pwdNeverExpires ? 'Ja' : 'Nein';
    
    const groupDns = tpl.groups || [];
    if(groupDns.length === 0) {
        document.getElementById('prev-groups').textContent = 'Keine Gruppen zugewiesen';
    } else {
        const groupNames = groupDns.map(dn => {
            const found = adData.groups.find(g => g.dn.toLowerCase() === dn.toLowerCase());
            return found ? found.name : dn.split(',')[0].replace('CN=', '');
        });
        document.getElementById('prev-groups').textContent = groupNames.join(', ');
    }
}

function togglePwdMode() {
    const mode = document.getElementById('tpl-pwd-mode').value;
    document.getElementById('static-pwd-box').classList.toggle('hidden', mode !== 'static');
}

function resetOnboardingForm() {
    document.getElementById('hire-fn').value = '';
    document.getElementById('hire-ln').value = '';
    document.getElementById('hire-mail').value = '';
    if(document.getElementById('hire-template').options.length > 0) {
        document.getElementById('hire-template').selectedIndex = 0;
    }
    previewTemplateInfo();
}

// Home folder as in RSAT: "Local path" or "Connect <drive> to"
function fillHomeDriveOptions(extra) {
    const sel = document.getElementById('tpl-homedrive');
    const letters = [];
    for(let c = 68; c <= 90; c++) letters.push(String.fromCharCode(c) + ':');
    if(extra && !letters.includes(extra)) letters.unshift(extra);
    sel.innerHTML = letters.map(l => `<option value="${l}">${l}</option>`).join('');
}

function setHomeDriveForm(drive) {
    const m = /^([A-Za-z]):?$/.exec(String(drive || '').trim());
    const letter = m ? m[1].toUpperCase() + ':' : '';
    fillHomeDriveOptions(letter);
    document.getElementById('tpl-homedrive').value = letter || 'Z:';
    document.getElementById('tpl-home-mode-connect').checked = !!letter;
    document.getElementById('tpl-home-mode-local').checked = !letter;
    toggleHomeMode();
}

function toggleHomeMode() {
    document.getElementById('tpl-homedrive').disabled = !document.getElementById('tpl-home-mode-connect').checked;
}

function openTemplateModal(id) {
    if(currentUserRole !== "Administrator") return alert("Keine Berechtigung.");
    document.getElementById('template-modal').classList.remove('hidden');
    loadMailDetect();
    const fields = ['initials', 'displayname', 'office', 'telephone', 'mail', 'website', 'street', 'pobox', 'postalcode', 'city', 'state', 'country', 'homephone', 'mobile', 'fax', 'ipphone', 'notes', 'title', 'dept', 'company', 'manager', 'profile', 'script', 'homedir'];

    if(id) {
        const item = templates.find(x => x.id === id);
        document.getElementById('modal-title').textContent = "Template bearbeiten";
        document.getElementById('tpl-edit-id').value = item.id;
        document.getElementById('tpl-name').value = item.name || '';
        document.getElementById('tpl-naming').value = item.naming || '%LASTNAME%%FIRSTNAME%[3]';
        document.getElementById('tpl-ou').value = item.ouDn || '';
        document.getElementById('tpl-pwd-mode').value = item.pwdMode || 'random';
        document.getElementById('tpl-mail-mode').value = MAIL_MODES.includes(item.mailMode) ? item.mailMode : 'required';
        document.getElementById('tpl-static-pwd').value = item.staticPwd || 'Willkommen2026!';
        document.getElementById('tpl-force-change').checked = item.forceChange !== false;
        document.getElementById('tpl-never-expire').checked = item.pwdNeverExpires === true;
        
        const mapData = {
            initials: item.initials,
            displayname: item.displayName,
            office: item.office,
            telephone: item.telephone,
            mail: item.mail,
            website: item.website,
            street: item.street,
            pobox: item.pobox,
            postalcode: item.postalCode,
            city: item.city,
            state: item.state,
            country: item.country,
            homephone: item.homePhone,
            mobile: item.mobile,
            fax: item.fax,
            ipphone: item.ipPhone,
            notes: item.notes,
            title: item.title,
            dept: item.department,
            company: item.company,
            manager: item.manager,
            profile: item.profilePath,
            script: item.scriptPath,
            homedir: item.homeDirectory
        };

        fields.forEach(f => {
            const el = document.getElementById('tpl-' + f);
            if(el) el.value = mapData[f] || '';
        });

        setHomeDriveForm(item.homeDrive);
        document.getElementById('tpl-home-create').checked = !!item.createHomeFolder;
        togglePwdMode();
        
        adTreeSetSelected('tpl-groups', item.groups || []);
    } else {
        document.getElementById('modal-title').textContent = "Template erstellen";
        document.getElementById('tpl-edit-id').value = "";
        document.getElementById('tpl-name').value = "";
        document.getElementById('tpl-naming').value = "%LASTNAME%%FIRSTNAME%[3]";
        document.getElementById('tpl-ou').value = "";
        document.getElementById('tpl-pwd-mode').value = "random";
        document.getElementById('tpl-mail-mode').value = "required";
        document.getElementById('tpl-force-change').checked = true;
        document.getElementById('tpl-never-expire').checked = false;
        
        fields.forEach(f => {
            const el = document.getElementById('tpl-' + f);
            if(el) el.value = '';
        });
        setHomeDriveForm('');
        document.getElementById('tpl-home-create').checked = false;
        togglePwdMode();
        
        adTreeSetSelected('tpl-groups', []);
    }
}

function closeTemplateModal() { document.getElementById('template-modal').classList.add('hidden'); }

async function saveTemplateFromModal() {
    try {
        const idVal = document.getElementById('tpl-edit-id').value;
        const groups = adTreeGetSelected('tpl-groups');

        const getVal = (elId) => {
            const el = document.getElementById(elId);
            return el ? el.value : '';
        };

        const data = {
            id: idVal ? parseInt(idVal) : null,
            name: getVal('tpl-name'),
            naming: getVal('tpl-naming').toUpperCase(),
            ouDn: getVal('tpl-ou'),
            pwdMode: getVal('tpl-pwd-mode'),
            mailMode: getVal('tpl-mail-mode'),
            staticPwd: getVal('tpl-static-pwd'),
            forceChange: document.getElementById('tpl-force-change') ? document.getElementById('tpl-force-change').checked : true,
            pwdNeverExpires: document.getElementById('tpl-never-expire') ? document.getElementById('tpl-never-expire').checked : false,
            initials: getVal('tpl-initials'),
            displayName: getVal('tpl-displayname'),
            office: getVal('tpl-office'),
            telephone: getVal('tpl-telephone'),
            mail: getVal('tpl-mail'),
            website: getVal('tpl-website'),
            street: getVal('tpl-street'),
            pobox: getVal('tpl-pobox'),
            postalCode: getVal('tpl-postalcode'),
            city: getVal('tpl-city'),
            state: getVal('tpl-state'),
            country: getVal('tpl-country'),
            homePhone: getVal('tpl-homephone'),
            mobile: getVal('tpl-mobile'),
            fax: getVal('tpl-fax'),
            ipPhone: getVal('tpl-ipphone'),
            notes: getVal('tpl-notes'),
            title: getVal('tpl-title'),
            department: getVal('tpl-dept'),
            company: getVal('tpl-company'),
            manager: getVal('tpl-manager'),
            profilePath: getVal('tpl-profile'),
            scriptPath: getVal('tpl-script'),
            homeDirectory: getVal('tpl-homedir'),
            homeDrive: document.getElementById('tpl-home-mode-connect').checked ? getVal('tpl-homedrive') : '',
            createHomeFolder: document.getElementById('tpl-home-create').checked,
            groups: groups
        };

        if(!data.name) return alert("Bitte mindestens einen Namen für das Template angeben.");

        const res = await fetch('/api/templates', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(data) });
        if(res.ok) {
            closeTemplateModal();
            await refreshAllLdapData();
        } else {
            const err = await res.json();
            alert("Fehler beim Speichern: " + (err.detail || "Unknown error"));
        }
    } catch(e) {
        alert("Form processing error: " + e.message);
    }
}

async function duplicateTemplate(id) {
    const res = await fetch('/api/templates/' + id + '/duplicate', { method: 'POST' });
    if(res.ok) {
        await refreshAllLdapData();
    } else {
        const err = await res.json();
        alert(err.detail || "Fehler beim Duplizieren.");
    }
}

async function deleteTemplate(id) {
    if(!confirm("Template wirklich löschen?")) return;
    const res = await fetch('/api/templates/' + id, { method: 'DELETE' });
    if(res.ok) {
        await refreshAllLdapData();
    } else {
        const err = await res.json();
        alert(err.detail || "Fehler beim Löschen.");
    }
}

function submitOnboard() { return guarded('onboard', _submitOnboard); }
async function _submitOnboard() {
    const fn = document.getElementById('hire-fn').value.trim();
    const ln = document.getElementById('hire-ln').value.trim();
    const mail = document.getElementById('hire-mail').value.trim();
    
    const mailMode = currentMailMode();
    if(!fn || !ln || (mailMode === 'required' && !mail)) {
        alert(mailMode === 'required' ? "Bitte füllen Sie alle Pflichtfelder (Vorname, Nachname, E-Mail) aus." : "Bitte Vorname und Nachname ausfüllen.");
        return;
    }

    const data = {
        firstName: fn,
        lastName: ln,
        customMail: (mailMode === 'exchange' || mailMode === 'cloud') ? '' : mail,
        templateId: parseInt(document.getElementById('hire-template').value)
    };

    const res = await fetch('/api/onboard', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(data) });
    const result = await res.json();
    if(res.ok) {
        lastCreatedUser = {
            sam: result.samAccountName,
            upn: result.upn,
            mail: result.mail,
            pwd: result.generatedPassword
        };
        document.getElementById('res-title').textContent = "Mitarbeiter erfolgreich angelegt!";
        document.getElementById('res-sam').textContent = result.samAccountName;
        document.getElementById('res-upn').textContent = result.upn;
        document.getElementById('res-mail').textContent = result.mail || '-';
        document.getElementById('res-pwd').textContent = result.generatedPassword;
        if (result.warnings && result.warnings.length) setTimeout(() => alert("Hinweis:\n" + result.warnings.join("\n")), 300);
        document.getElementById('result-modal').classList.remove('hidden');

        await refreshAllLdapData();
    } else {
        alert("Onboarding error: " + (result.detail || "Unknown error"));
    }
}

function copyToClipboard() {
    const textToCopy = `${tr('Benutzername:')} ${lastCreatedUser.sam}\nUPN: ${lastCreatedUser.upn}\n${lastCreatedUser.mail ? tr('E-Mail:') + ' ' + lastCreatedUser.mail + '\n' : ''}${tr('Passwort:')} ${lastCreatedUser.pwd}`;
    navigator.clipboard.writeText(textToCopy).then(() => {
        alert("Zugangsdaten in die Zwischenablage kopiert!");
    }).catch(err => {
        alert("Fehler beim Kopieren: " + err);
    });
}

function generatePDF() {
    const printWindow = window.open('', '_blank');
    if (!printWindow) {  // Pop-up blocker: otherwise the function aborts without a message
        alert(tr('Das Fenster zum Drucken wurde blockiert. Bitte Pop-ups für diese Seite erlauben.'));
        return;
    }
    const T = (text) => esc(tr(text));
    const htmlContent = `<!DOCTYPE html>
        <html lang="${uiLang}">
        <head>
            <meta charset="UTF-8">
            <title>${T('Zugangsdaten')} - ${esc(lastCreatedUser.sam)}</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; color: #1e293b; line-height: 1.6; }
                .header { border-bottom: 2px solid #0284c7; padding-bottom: 15px; margin-bottom: 25px; display: flex; justify-content: space-between; align-items: center; }
                .header h1 { margin: 0; color: #0284c7; font-size: 22px; }
                .badge { background: #f1f5f9; padding: 6px 12px; font-size: 12px; border-radius: 6px; font-family: monospace; }
                .box { background: #f8fafc; border: 1px solid #cbd5e1; border-radius: 8px; padding: 20px; margin-bottom: 25px; }
                .row { margin-bottom: 12px; display: flex; }
                .label { width: 160px; font-weight: bold; color: #475569; }
                .value { font-family: monospace; font-size: 15px; color: #0f172a; }
                .pwd { font-size: 18px; color: #b45309; font-weight: bold; background: #fef3c7; padding: 2px 6px; border-radius: 4px; }
                .footer { margin-top: 40px; font-size: 11px; color: #64748b; border-top: 1px solid #e2e8f0; padding-top: 15px; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>${T('Mitarbeiter Zugangsdaten (Netzwerk / Passwort)')}</h1>
                <div class="badge">SAMONBOARDING v__APP_VERSION__</div>
            </div>
            <p>${T('Nachfolgend finden Sie Ihre Zugangsdaten für das Netzwerk und die IT-Dienste.')}</p>
            <div class="box">
                <div class="row"><div class="label">${T('Benutzername:')}</div><div class="value">${esc(lastCreatedUser.sam)}</div></div>
                <div class="row"><div class="label">${T('Benutzerprinzipal (UPN):')}</div><div class="value">${esc(lastCreatedUser.upn)}</div></div>
                <div class="row"><div class="label">${T('E-Mail-Adresse:')}</div><div class="value">${esc(lastCreatedUser.mail || '-')}</div></div>
                <div class="row"><div class="label">${T('Kennwort / Passwort:')}</div><div class="value pwd">${esc(lastCreatedUser.pwd)}</div></div>
            </div>
            <p><strong>${T('Wichtiger Hinweis:')}</strong> ${T('Bitte ändern Sie Ihr Passwort bei der nächsten Anmeldung an einem Unternehmenscomputer oder Dienst.')}</p>
            <div class="footer">
                ${T('Generiert am')} ${new Date().toLocaleDateString(uiLang === 'en' ? 'en-GB' : 'de-DE')} ${T('um')} ${new Date().toLocaleTimeString(uiLang === 'en' ? 'en-GB' : 'de-DE')} ${T('Uhr')} • ${T('Vertrauliche IT-Information')}
            </div>
        </body>
        </html>`;
    printWindow.document.write(htmlContent);
    printWindow.document.close();
    // Print from here: the new window inherits the page's CSP, an inline script there would be blocked
    printWindow.focus();
    printWindow.print();
}

function submitOnboarding() { submitOnboard(); }
