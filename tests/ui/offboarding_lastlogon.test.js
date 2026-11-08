// Offboarding list: column "last logon" (approximate lastLogonTimestamp) and sorting by it
const src = require('./load_script.js');
const els = {};
const el = id => els[id] || (els[id] = {id, innerHTML:'', textContent:'', value:'', checked:false, disabled:false, className:'', attrs:{}, setAttribute(k, v){ this.attrs[k] = v; }, focus(){}, classList:{add(){},remove(){},toggle(){}}, style:{}});
const doc = {getElementById: el, querySelectorAll: () => [], addEventListener(){}};
const f = new Function('document','window','navigator','alert','fetch','confirm', src.replace(/document\.addEventListener\("DOMContentLoaded"[\s\S]*?\}\);\s*\n/, '') + `
return {lastLogonCell, sortOffboardUsers, toggleOffboardSort, setUsers:u=>{cachedOffboardUsers=u}, setMe:n=>{currentLoggedInUsername=n}};`);
const api = f(doc, {}, {language:'de'}, () => {}, async () => ({ok:true, json: async () => ({})}), () => true);
const day = 86400000;
const iso = ms => new Date(Date.now() - ms).toISOString();
const mk = (i, lastLogon) => ({dn:'CN=u'+i, name:'User '+i, sam:'u'+i, mail:'', disabled:false, protected:'', ou:'OU=x', lastLogon});

// cell: never / today / days ago, old accounts highlighted
console.assert(api.lastLogonCell(null).includes('>nie<'), 'never logged on');
console.assert(api.lastLogonCell(iso(1000)).includes('>heute<'), 'today');
console.assert(api.lastLogonCell(iso(1 * day + 1000)).includes('>vor 1 Tag<'), 'one day');
const old = api.lastLogonCell(iso(120 * day + 1000));
console.assert(old.includes('>vor 120 Tagen<') && old.includes('text-amber-400'), 'old account highlighted');
console.assert(!api.lastLogonCell(iso(10 * day)).includes('text-amber-400'), 'recent account not highlighted');
console.assert(api.lastLogonCell('kaputt') === '-', 'invalid value');

// sorting: off -> oldest first (never at the top) -> newest first -> off
const users = [mk(1, iso(5 * day)), mk(2, null), mk(3, iso(300 * day)), mk(4, iso(1 * day))];
console.assert(api.sortOffboardUsers(users).map(u => u.sam).join() === 'u1,u2,u3,u4', 'unsorted by default');
el('offboard-search').value = '';
api.setMe('ich'); api.setUsers(users);
api.toggleOffboardSort();
let h = els['offboard-user-list'].innerHTML;
console.assert(h.indexOf('>u2<') < h.indexOf('>u3<') && h.indexOf('>u3<') < h.indexOf('>u1<') && h.indexOf('>u1<') < h.indexOf('>u4<'), 'oldest first, never at the top');
console.assert(els['off-sort-icon'].className.includes('fa-sort-up') && els['off-sort-head'].attrs['aria-sort'] === 'ascending', 'icon and aria ascending');
api.toggleOffboardSort();
h = els['offboard-user-list'].innerHTML;
console.assert(h.indexOf('>u4<') < h.indexOf('>u1<') && h.indexOf('>u3<') < h.indexOf('>u2<'), 'newest first, never at the end');
api.toggleOffboardSort();
console.assert(els['off-sort-head'].attrs['aria-sort'] === 'none', 'back to unsorted');
console.assert(users.map(u => u.sam).join() === 'u1,u2,u3,u4', 'original list not changed');
console.log('Offboarding last-logon UI tests fertig');
