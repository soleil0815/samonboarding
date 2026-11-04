// Only the opened section loads its account list; "Aktualisieren" (force) reads fresh (?frisch=1)
const src = require('./load_script.js');
const calls = [];
const names = ['loadInfrastructure', 'loadTemplates', 'loadExchangeConfig', 'loadOffboardingConfig', 'loadPwdResetConfig',
  'loadUserMgmtConfig', 'loadSmtpConfig', 'loadDeletionConfig', 'loadUserMgmtUsers', 'loadOffboardingUsers',
  'loadOffboardRecords', 'loadPwdResetUsers', 'loadDeletionUsers'];
const f = new Function('document', 'window', 'navigator', 'alert', 'fetch',
  src.replace(/document\.addEventListener\("DOMContentLoaded"[\s\S]*?\}\);\s*\n/, '') + `
return {refreshAllLdapData, freshQuery, setTab: t => { currentTab = t; }, setRole: r => { currentUserRole = r; },
  stub: rec => { ${names.map(n => `${n} = async force => rec('${n}', force);`).join(' ')} }};`);
const api = f({getElementById: () => null, querySelector: () => null, querySelectorAll: () => [], addEventListener() {}},
  {}, {language: 'de'}, () => {}, async () => ({ok: false}));
api.stub((n, force) => calls.push([n, force]));
const lists = ['loadUserMgmtUsers', 'loadOffboardingUsers', 'loadPwdResetUsers', 'loadDeletionUsers'];
(async () => {
  api.setRole('Administrator');
  api.setTab('hire');
  await api.refreshAllLdapData();
  console.assert(!calls.some(([n]) => lists.includes(n)), 'Onboarding laedt keine Kontolisten');
  console.assert(calls.some(([n]) => n === 'loadInfrastructure') && calls.some(([n]) => n === 'loadTemplates'), 'Onboarding: OUs/Gruppen und Vorlagen');
  calls.length = 0;
  api.setTab('offboard');
  await api.refreshAllLdapData();
  const got = calls.filter(([n]) => lists.includes(n)).map(([n]) => n);
  console.assert(got.length === 1 && got[0] === 'loadOffboardingUsers', 'Offboarding laedt nur seine Liste: ' + got);
  console.assert(calls.some(([n]) => n === 'loadOffboardRecords'), 'Offboarding laedt die Wiederherstellungs-Eintraege');
  console.assert(calls.every(([, force]) => force !== true), 'Tab-Wechsel nutzt den Zwischenspeicher');
  calls.length = 0;
  api.setTab('delete');
  await api.refreshAllLdapData(true);
  console.assert(calls.find(([n]) => n === 'loadDeletionUsers')[1] === true, 'Aktualisieren liest die Liste frisch');
  console.assert(calls.find(([n]) => n === 'loadInfrastructure')[1] === true, 'Aktualisieren liest OUs/Gruppen frisch');
  // a click event as the argument must not count as "fresh"
  calls.length = 0;
  await api.refreshAllLdapData({type: 'click'});
  console.assert(calls.every(([, force]) => force !== true), 'nur true erzwingt frisches Lesen');
  console.assert(api.freshQuery(true) === '?frisch=1' && api.freshQuery(undefined) === '' && api.freshQuery({}) === '', 'freshQuery');
  console.log('Tab-Lade-Tests fertig');
})();
