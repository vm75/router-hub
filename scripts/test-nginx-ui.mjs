#!/usr/bin/env node
// Optional browser regression test. Node 22+ and Chromium; no npm dependencies.
// All writes target a temporary, explicitly verified test-mode Maestro.
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {mkdtemp, mkdir, writeFile, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {createServer} from 'node:net';
import {once} from 'node:events';
import {Script} from 'node:vm';

const lab=await mkdtemp(join(tmpdir(),'maestro-ui-'));
const token='maestro-ui-test-token';
const binary=resolve(process.argv[2] || 'target/debug/maestro');
const chromium=process.argv[3] || '/usr/sbin/chromium';
let hub, browser, socket, failed=true;
const sleep=ms => new Promise(resolve => setTimeout(resolve,ms));
async function waitFor(check, label) {
  for(let i=0;i<200;i++) {try {if(await check()) return;} catch {} await sleep(25);}
  throw new Error(`Timed out: ${label}`);
}
const portServer=createServer(); portServer.listen(0,'127.0.0.1'); await once(portServer,'listening');
const port=portServer.address().port; await new Promise(resolve => portServer.close(resolve));
const base=`http://127.0.0.1:${port}`;
async function api(path, method='GET', body) {
  const response=await fetch(base+'/api'+path,{method,headers:{Authorization:`Bearer ${token}`,'Content-Type':'application/json'},body:body === undefined ? undefined : JSON.stringify(body)});
  const result=await response.json(); assert.ok(response.ok,JSON.stringify(result)); return result;
}
const quote=JSON.stringify;
const nginx=join(lab,'nginx');
const paths={data_dir:join(lab,'state'),runtime_dir:join(lab,'run'),log_file:join(lab,'hub.log'),hosts_add:join(lab,'hosts.add'),dnsmasq_conf_add:join(lab,'dnsmasq.add'),wireguard_conf:join(lab,'wg.conf')};
const nginxPaths={root_dir:nginx,inputs_dir:join(lab,'inputs'),config_path:join(nginx,'nginx.conf'),pid_path:join(lab,'run/nginx.pid'),domains_available_dir:join(nginx,'domains-available'),domains_enabled_dir:join(nginx,'domains-enabled'),domain_upstream_map_path:join(nginx,'conf.d/02_domain_upstream_map.conf'),subdomain_upstream_map_path:join(nginx,'conf.d/03_subdomain_upstream_map.conf'),subfolder_upstream_map_path:join(nginx,'conf.d/04_subfolder_upstream_map.conf'),http_forwarder_path:join(nginx,'conf.d/05-http-to-https.conf'),log_dir:join(lab,'logs/nginx')};
const table=(name,values) => `[${name}]\n`+Object.entries(values).map(([key,value])=>`${key} = ${quote(value)}\n`).join('');
const config='test_mode = true\n'+table('server',{bind:'127.0.0.1',port,auth_token:token})+table('paths',paths)+table('nginx',nginxPaths)+table('certificates',{certs_dir:join(lab,'certs')})+table('services',{init_dir:join(lab,'init.d'),log_dirs:[join(lab,'logs')]})+table('asus_ui',{enabled:false})+table('firewall',{log_dirs:[join(lab,'logs/nginx')]});

try {
  await mkdir(nginx,{recursive:true}); await writeFile(join(nginx,'nginx.conf'),'events {} http {}\n');
  await writeFile(join(lab,'maestro.toml'),config);
  hub=spawn(binary,['--config',join(lab,'maestro.toml'),'serve'],{stdio:['ignore','ignore','pipe']});
  let hubErrors=''; hub.stderr.on('data',data => hubErrors+=data.toString());
  await waitFor(async()=>{if(hub.exitCode !== null) throw new Error(hubErrors); return (await fetch(base+'/healthz')).ok;},'test API startup');
  assert.equal((await api('/runtime')).test_mode,true);
  assert.equal((await api('/nginx/status')).root_dir,nginx,'refuse to mutate a non-lab server');
  browser=spawn(chromium,['--headless','--no-sandbox','--disable-gpu','--disable-dev-shm-usage','--disable-background-networking','--disable-component-update','--no-first-run','--remote-debugging-port=0',`--user-data-dir=${join(lab,'browser')}`,'about:blank'],{stdio:['ignore','ignore','pipe']});
  let debugging=''; browser.stderr.on('data',data => debugging+=data.toString());
  await waitFor(()=>debugging.includes('DevTools listening on'),'browser startup');
  const browserUrl=debugging.match(/DevTools listening on (ws:\/\/[^\s]+)/)[1];
  const targets=await (await fetch(browserUrl.replace('ws://','http://').split('/devtools/')[0]+'/json/list')).json();
  socket=new WebSocket(targets.find(target=>target.type==='page').webSocketDebuggerUrl);
  await once(socket,'open');
  let sequence=0; const pending=new Map(), errors=[], requests=[];
  socket.addEventListener('message',event=>{
    const message=JSON.parse(event.data);
    if(message.id) {const request=pending.get(message.id); pending.delete(message.id); if(message.error) request.reject(new Error(message.error.message)); else request.resolve(message.result);}
    if(message.method==='Runtime.exceptionThrown') errors.push(message.params.exceptionDetails.text+': '+(message.params.exceptionDetails.exception?.description || ''));
    if(message.method==='Network.requestWillBeSent') requests.push(message.params.request.url);
  });
  const call=(method,params={})=>new Promise((resolve,reject)=>{const id=++sequence; pending.set(id,{resolve,reject}); socket.send(JSON.stringify({id,method,params}));});
  const evaluate=async expression=>{
    let wrapped=`(async()=>(${expression}))()`;
    try {new Script(wrapped);} catch {wrapped=`(async()=>{${expression}})()`;}
    const result=await call('Runtime.evaluate',{expression:wrapped,awaitPromise:true,returnByValue:true});
    if(result.exceptionDetails) throw new Error(result.exceptionDetails.exception?.description || result.exceptionDetails.text);
    return result.result.value;
  };
  const wait=expression=>waitFor(()=>evaluate(expression),expression);
  await call('Page.enable'); await call('Runtime.enable'); await call('Network.enable');
  await call('Network.setCookie',{name:'maestro-token',value:token,url:base});
  await call('Page.navigate',{url:base});
  await wait('typeof editNginxSettings === "function" && document.readyState === "complete"');
  assert.deepEqual(await evaluate("Array.from(document.querySelectorAll('#rh-nav > .rh-group > .rh-tab')).map(el => el.dataset.group)"),
    ['dashboard','services','web','security','network'],'expected grouped navigation');
  assert.ok(await evaluate("!!document.querySelector('#rh-nav [data-view=nginx]') && !!document.querySelector('#rh-nav [data-view=certificates]')"),
    'Web must retain both existing feature views');

  await evaluate('document.querySelector(\'[data-view="nginx"]\').click(); editNginxSettings()');
  await wait('!!document.querySelector("#nginx-settings-form")');
  assert.equal(await evaluate(`(() => {
    const form=document.getElementById('nginx-settings-form'), control=form.elements.nginx_daemon, warning=form.querySelector('[data-nginx-daemon-warning]');
    if(control.value !== 'true' || !warning.hidden) return false;
    control.value='false'; control.dispatchEvent(new Event('change',{bubbles:true}));
    if(warning.hidden || !warning.textContent.includes('init.d')) return false;
    control.value=''; control.dispatchEvent(new Event('change',{bubbles:true}));
    return warning.hidden;
  })()`),true,'daemon mode defaults on and disabling it shows a warning');
  await evaluate(`document.getElementById('nginx-profile-rows').insertAdjacentHTML('beforeend',nginxProfileCard()); document.getElementById('nginx-access-rows').insertAdjacentHTML('beforeend',nginxAccessCard());
    const f=document.getElementById('nginx-settings-form'); f.querySelector('[data-profile-name]').value='internal'; f.querySelector('[data-endpoint-port]').value='19443'; f.querySelector('[data-access-name]').value='trusted'; f.querySelector('[data-access-allow]').value='127.0.0.1/32'; f.elements.http_mode.value='off'; document.getElementById('editor-save').click()`);
  await wait('!document.getElementById("editor").open');
  assert.equal((await api('/nginx/settings')).listener_profiles.internal.https[0].port,19443);
  assert.equal((await api('/nginx/settings')).http_access.mode,'off');
  await evaluate(`document.querySelector('[data-view="certificates"]').click()`);
  await wait('document.getElementById("certificate-http-status").textContent.includes("HTTP closed")');
  await evaluate(`document.querySelector('[data-view="nginx"]').click()`);
  await evaluate('nginxObjectEditor("domain")'); await wait('!!document.querySelector("#nginx-object-form")');
  await evaluate(`const f=document.getElementById('nginx-object-form'); f.elements.domain.value='example.test'; f.elements.disable_root.value='false'; f.elements.upstream.value='http://127.0.0.1:9'; f.elements.listener_profile.value='internal'; f.elements.access_policy.value='trusted'; f.querySelector('[data-block-path]').value='/admin'; nginxAddBlockedPath(f); document.getElementById('editor-save').click()`);
  await wait('!document.getElementById("editor").open');
  let site=await api('/nginx/objects/domain/example.test/example.test');
  assert.equal(site.settings.listener_profile,'internal'); assert.equal(site.settings.access_policy,'trusted');
  assert.deepEqual(site.settings.routes.map(route=>[route.path,route.match,route.access_policy]),[['/admin','exact','deny'],['/admin/','prefix','deny']]);
  await evaluate('editNginxObject("domain","example.test","example.test")'); await wait('!!document.querySelector("#nginx-object-form")');
  await evaluate(`document.querySelector('#nginx-object-form [name=upstream]').value='http://127.0.0.1:8123'; nginxManageFromSite()`);
  await wait('!!document.querySelector("#nginx-settings-form")');
  await evaluate(`document.getElementById('nginx-access-rows').insertAdjacentHTML('beforeend',nginxAccessCard()); const rows=document.querySelectorAll('[data-nginx-access]'), row=rows[rows.length-1]; row.querySelector('[data-access-name]').value='other'; row.querySelector('[data-access-allow]').value='127.0.0.2/32'; const f=document.getElementById('nginx-settings-form'); f.elements.http_mode.value='renewal_only'; f.elements.http_wan.value='external'; document.getElementById('editor-save').click()`);
  await wait('!!document.querySelector("#nginx-object-form") && document.getElementById("editor").open');
  assert.equal(await evaluate('document.querySelector("#nginx-object-form [name=upstream]").value'),'http://127.0.0.1:8123');
  assert.equal((await api('/nginx/settings')).http_access.mode,'renewal_only');
  assert.equal((await api('/nginx/settings')).http_access.externally_managed_wan,true);
  assert.equal(await evaluate('document.querySelector("#nginx-object-form [name=listener_profile]").value'),'internal');
  assert.equal(await evaluate('!!document.querySelector(\'#nginx-object-form [name=access_policy] option[value="other"]\')'),true);
  // Delay an older preview so it completes after the latest selection.
  await evaluate(`window.previewOriginalApi=api; window.slowPreviewStarted=false; api=async (path,options={})=>{const result=await previewOriginalApi(path,options); if(path==='/nginx/access-preview' && JSON.parse(options.body).settings.access_policy==='trusted') {window.slowPreviewStarted=true; await new Promise(resolve=>setTimeout(resolve,900));} return result;}; nginxScheduleAccessPreview(document.getElementById('nginx-object-form'))`);
  await wait('window.slowPreviewStarted');
  await evaluate(`const f=document.getElementById('nginx-object-form'); f.elements.access_policy.value='other'; f.elements.access_policy.dispatchEvent(new Event('change',{bubbles:true}))`);
  await wait('document.querySelector("[data-effective-access]").textContent.includes("127.0.0.2/32")');
  await sleep(1000);
  assert.ok(await evaluate('document.querySelector("[data-effective-access]").textContent.includes("127.0.0.2/32")'));
  await evaluate('api=previewOriginalApi; closeEditor()');
  // Advanced route data must survive ordinary access edits without JSON editing.
  site.settings.routes.push({path:'/events',proxy_transport:'sse',children:[{path:'/events/private',access_policy:'trusted'}]});
  await api('/nginx/objects/domain/example.test/example.test','PUT',{settings:site.settings});
  await evaluate('editNginxObject("domain","example.test","example.test")'); await wait('!!document.querySelector("#nginx-object-form")');
  await evaluate(`const f=document.getElementById('nginx-object-form'), rows=f.querySelectorAll('[data-path-rule]'); rows[2].querySelector('[data-route-access]').value='public'; nginxPathRulesChanged(f); document.getElementById('editor-save').click()`);
  await wait('!document.getElementById("editor").open');
  const routes=(await api('/nginx/objects/domain/example.test/example.test')).settings.routes;
  assert.equal(routes[2].proxy_transport,'sse'); assert.deepEqual(routes[2].children,[{path:'/events/private',access_policy:'trusted'}]);
  await evaluate('editNginxObject("domain","example.test","example.test")'); await wait('!!document.querySelector("#nginx-object-form")');
  await evaluate(`const f=document.getElementById('nginx-object-form'); f.elements.disable_root.value='true'; f.elements.disable_root.dispatchEvent(new Event('change',{bubbles:true}))`);
  await wait('document.querySelector("[data-nginx-path-controls]").hidden && !document.querySelector("[data-nginx-container-help]").hidden && !document.querySelector("[data-effective-access]").textContent.includes("Blocked:")');
  await evaluate(`const f=document.getElementById('nginx-object-form'); f.elements.disable_root.value='false'; f.elements.disable_root.dispatchEvent(new Event('change',{bubbles:true}))`);
  await wait('!document.querySelector("[data-nginx-path-controls]").hidden && document.querySelector("[data-effective-access]").textContent.includes("Blocked:")');
  await call('Emulation.setDeviceMetricsOverride',{width:390,height:844,deviceScaleFactor:1,mobile:false});
  assert.ok(await evaluate('document.getElementById("editor").getBoundingClientRect().width <= innerWidth'));
  await call('Input.dispatchKeyEvent',{type:'keyDown',key:'Tab',code:'Tab',windowsVirtualKeyCode:9});
  await call('Input.dispatchKeyEvent',{type:'keyUp',key:'Tab',code:'Tab',windowsVirtualKeyCode:9});
  assert.ok(await evaluate('!!document.activeElement.closest("#editor")'));
  await wait('document.querySelector("[data-effective-access]").textContent.includes("Effective access")');
  await writeFile(join(lab,'mobile.png'),Buffer.from((await call('Page.captureScreenshot',{format:'png'})).data,'base64'));
  await call('Network.emulateNetworkConditions',{offline:true,latency:0,downloadThroughput:0,uploadThroughput:0});
  await evaluate(`const f=document.getElementById('nginx-object-form'); f.querySelector('[data-block-path]').value='/control'; nginxAddBlockedPath(f); document.getElementById('editor-save').click()`);
  await wait('!!document.querySelector("#nginx-object-form [data-form-error]") && !document.querySelector("#nginx-object-form [data-form-error]").hidden');
  assert.ok(await evaluate('document.getElementById("editor").open && document.querySelector("#nginx-object-form [name=routes]").value.includes("/control")'));
  assert.deepEqual(errors,[],'browser exceptions');
  assert.ok(requests.every(url=>url.startsWith(base) || url==='about:blank' || url.startsWith('data:')),'UI must not fetch external assets');
  console.log('PASS: normal form setup, blocked paths, draft preservation, advanced route round-trip, stale preview rejection, mobile/keyboard and offline failure handling');
  failed=false;
} finally {
  socket?.close();
  for(const process of [browser,hub]) if(process && process.exitCode === null) {process.kill('SIGTERM'); await Promise.race([once(process,'exit'),sleep(3000)]); if(process.exitCode === null) process.kill('SIGKILL');}
  if(failed || process.argv.includes('--keep')) console.log(`UI lab retained: ${lab}`);
  else await rm(lab,{recursive:true,force:true});
}
