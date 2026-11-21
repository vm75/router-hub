#!/usr/bin/env node
// Offline composition/syntax checks; no browser, npm, or network required.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
import {Script} from 'node:vm';

execFileSync('python3', ['scripts/build-web-ui.py', '--check'], {stdio:'inherit'});
const html=readFileSync('web/index.html','utf8');
assert.equal((html.match(/<script>/g)||[]).length,1);
assert.equal((html.match(/<style>/g)||[]).length,1);
const js=html.split('<script>')[1].split('</script>')[0];
new Script(js,{filename:'composed-maestro.js'});
for(const view of ['dashboard','services','nginx','certificates','wol','firewall','adguard','wireguard']) {
  assert.ok(html.includes('id="view-'+view+'"'),'missing '+view+' view');
  assert.ok(js.includes("load"+({nginx:'Nginx',wol:'Wol',adguard:'Adguard',wireguard:'Wireguard',firewall:'Firewall',dashboard:'Dashboard',services:'Services',certificates:'Certificates'}[view])),'missing '+view+' logic');
}
assert.match(js,/rhNavigationGroups/);
assert.match(js,/rhLoadModules/);
assert.match(js,/data-dashboard-widget/);
assert.match(js,/data-widget-state/);
assert.match(js,/rhSelectView/);
assert.ok(!html.includes('<script src='),'UI must contain no remote JS');
assert.ok(!html.includes('<link rel="stylesheet"'),'UI must contain no external CSS');
// Exercise the manifest functions without a browser. All tabs are composed
// from modules, with deterministic groups and legacy section IDs.
const navigation = readFileSync('web/src/js/navigation.js', 'utf8');
const manifestStart = navigation.indexOf('    const RH_FALLBACK_MODULES =');
const composeStart = navigation.indexOf('    function rhComposeNavigation()', manifestStart);
assert.ok(manifestStart >= 0 && composeStart > manifestStart);
const groups = new Script(navigation.slice(manifestStart, composeStart) + `
const original = rhNavigationGroups();
const markup = rhNavigationMarkup(original, false);
rhModuleCatalog = RH_FALLBACK_MODULES
  .filter(module => module.id !== 'nginx')
  .map(module => module.id === 'adguard' ? {...module, availability: 'unsupported'} : module);
({
  normal: original.map(group => [group.id, ...group.sections.map(section => section.id)]),
  reduced: rhNavigationGroups().map(group => [group.id, ...group.sections.map(section => section.id)]),
  markup
});
`).runInNewContext({esc: value => String(value)});
assert.equal(JSON.stringify(groups.normal), JSON.stringify([
  ['dashboard', 'dashboard'], ['services', 'services'],
  ['web', 'nginx', 'certificates'], ['security', 'firewall'],
  ['network', 'wol', 'adguard', 'wireguard']
]));
assert.equal(JSON.stringify(groups.reduced), JSON.stringify([
  ['dashboard', 'dashboard'], ['services', 'services'],
  ['web', 'certificates'], ['security', 'firewall'],
  ['network', 'wol', 'wireguard']
]));
assert.match(groups.markup, /data-group="web" data-view="nginx"/);
assert.match(groups.markup, /data-view="certificates"/);

const keyboardStart = navigation.indexOf('    function rhBindKeyboardNavigation(');
const keyboardEnd = navigation.indexOf('    function rhSetupTabs()', keyboardStart);
assert.ok(keyboardStart >= 0 && keyboardEnd > keyboardStart);
const keyboard = new Script(navigation.slice(keyboardStart, keyboardEnd) + `
const listeners = {};
const root = {
  dataset: {},
  contains: () => true,
  addEventListener: (name, listener) => { listeners[name] = listener; }
};
rhBindKeyboardNavigation(root);
let clicks = 0, prevented = 0;
const tab = {tagName: 'DIV', click: () => { clicks++; }};
for (const key of ['Enter', ' ', 'Escape']) {
  listeners.keydown({target: {closest: () => tab}, key,
    preventDefault: () => { prevented++; }});
}
const button = {tagName: 'BUTTON', click: () => { clicks++; }};
listeners.keydown({target: {closest: () => button}, key: ' ',
  preventDefault: () => { prevented++; }});
rhBindKeyboardNavigation(root);
({clicks, prevented, handlers: Object.keys(listeners).length});
`).runInNewContext({});
assert.equal(keyboard.clicks, 2);
assert.equal(keyboard.prevented, 2);
assert.equal(keyboard.handlers, 1);
console.log('Composed UI syntax, capability navigation, keyboard access, and offline embedding verified');
