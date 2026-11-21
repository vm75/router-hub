    function nginxPath(value) { return value.split('/').map(encodeURIComponent).join('/') }
    function nginxObjectUrl(o) { return `/nginx/objects/${o.kind}/${encodeURIComponent(o.domain)}/${encodeURIComponent(o.name)}` }
    async function loadNginx() { await Promise.all([loadNginxObjects(), loadNginxStatus(), loadNginxLogs()]) }
    function nginxObjectStatus(o) { const state = o.state || (o.enabled ? (o.running ? 'live' : 'down') : 'disabled'); const kind = state === 'live' ? 'ok' : state === 'down' ? 'warn' : 'off'; return `<span class="status ${kind}">${esc(state)}</span>` }
    function nginxRowAccess(o) { const a=o.effective_access; return a ? `<div class="hint">${esc(a.listener_profile)} · ${esc(a.access_policy)}</div><div class="hint">${esc(a.https.map(e => `${e.address}:${e.port}`).join(', '))}</div>${a.allowed_sources?.length === 0 ? '<div class="status off">Blocked</div>' : ''}` : ''; }
    function launchNginxSite(kind,domain,name) {
      const o=state.nginxObjects.find(x => x.kind === kind && x.domain === domain && x.name === name), target=o?.display_name || (kind === 'subdomain' ? `${name}.${domain}` : kind === 'subfolder' ? `${domain}/${name}` : domain);
      if(!target) return toast('Site launch URL unavailable',true);
      const port=o?.effective_access?.https?.[0]?.port, split=target.indexOf('/'), host=split < 0 ? target : target.slice(0,split), path=split < 0 ? '' : target.slice(split);
      window.open(`https://${host}${port && port !== 443 ? ':'+port : ''}${path}`,'_blank','noopener,noreferrer');
    }
    function nginxObjectRow(o) { const child = o.kind !== 'domain', kind = esc(o.kind), domain = esc(o.domain), name = esc(o.name); return `<tr class="${child ? 'nginx-child-row' : 'nginx-domain-row'}"><td><strong>${esc(o.display_name || o.name)}</strong> <span class="tag">${kind}</span></td><td>${o.port ?? '<span class="muted">—</span>'}</td><td>${o.managed ? '<span class="tag">Managed</span>'+nginxRowAccess(o) : '<span class="muted">Custom configuration</span>'}</td><td>${nginxObjectStatus(o)}</td><td><div class="row-actions"><button class="btn small" onclick="editNginxObject('${kind}','${domain}','${name}')">Edit</button><button class="btn small" onclick="nginxObjectAction('${kind}','${domain}','${name}','${o.enabled ? 'disable' : 'enable'}')">${o.enabled ? 'Disable' : 'Enable'}</button><button class="btn small danger" onclick="deleteNginxObject('${kind}','${domain}','${name}')">Delete</button><button class="btn small action" title="Launch site" aria-label="Launch site" onclick="launchNginxSite('${kind}','${domain}','${name}')"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-label="Open URL"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" /><polyline points="15 3 21 3 21 9" /><line x1="10" y1="14" x2="21" y2="3" /></svg></button></div></td></tr>` }
    function nginxObjectRows(objects) { const sort = tableSorts.nginx, compare = (a, b) => sort.dir * compareTableValues(a, b, sort.key) || (a.kind || '').localeCompare(b.kind || '') || (a.display_name || a.name).localeCompare(b.display_name || b.name), domains = objects.filter(o => o.kind === 'domain').sort(compare), children = objects.filter(o => o.kind !== 'domain'), rows = []; domains.forEach(domain => { rows.push(domain); if (domain.enabled) rows.push(...children.filter(child => child.domain === domain.domain).sort(compare)) }); const knownDomains = new Set(domains.map(domain => domain.domain)); rows.push(...children.filter(child => !knownDomains.has(child.domain)).sort(compare)); return rows.map(nginxObjectRow).join('') }
    async function loadNginxObjects() { try { state.nginxObjects = await api('/nginx/objects'); document.getElementById('nginx-objects-body').innerHTML = state.nginxObjects.length ? nginxObjectRows(state.nginxObjects) : emptyRow(5, 'No nginx sites'); updateSortHeaders('nginx') } catch (e) { toast(e.message, true) } }
    async function loadNginxStatus() { try { const s = await api('/nginx/status'); document.getElementById('nginx-status').innerHTML = `${status(s.running)} <span title="Config: ${esc(s.config_path)} · Root: ${esc(s.root_dir)}">Config <code>${esc(s.config_path)}</code></span>` } catch (e) { document.getElementById('nginx-status').textContent = e.message } }
    function openNginxReference() { document.getElementById('nginx-reference-modal').showModal() }
    const nginxPolicyFields = [
      ['limit_policy', 'Limit policy name', 'text', 'default'],
      ['enable_lanonly', 'LAN only', 'bool', true], ['enable_subfolders', 'Enable subfolders (domain)', 'bool', true],
      ['disable_root', 'Return 404 at domain root', 'bool', true], ['enable_large_upload', 'Large uploads', 'bool', false],
      ['enable_longlived', 'Long-lived connections', 'bool', false], ['enable_streaming', 'Stream responses', 'bool', false],
      ['enable_byte_ranges', 'Byte ranges', 'bool', false],
      ['enable_restricted_sessions', 'LAN-only Sessions route', 'bool', false],
      ['clear_origin', 'Clear Origin header', 'bool', false], ['access_log', 'Ordinary access logging', 'bool', true],
      ['backend_auth', 'Backend authentication', 'bool', false], ['hide_etag', 'Hide ETag', 'bool', false],
      ['disable_proxy_redirect', 'Disable proxy redirects', 'bool', false],
      ['client_max_body_size', 'Body size limit', 'text', '100M'], ['large_upload_max_body_size', 'Large upload limit', 'text', '5G'],
      ['proxy_connect_timeout', 'Connect timeout', 'text', '10s'], ['proxy_session_timeout', 'Session timeout', 'text', '3600s'],
      ['client_upload_timeout', 'Upload idle timeout', 'text', '3600s'],
      ['proxy_transport', 'Transport', ['websocket', 'http', 'sse'], 'websocket'],
      ['cache_policy', 'Cache policy', ['inherit', 'no_cache', 'immutable', 'pwa'], 'inherit'],
      ['forwarded_for', 'Forwarded client chain', ['replace', 'append'], 'replace'],
      ['spa_fallback', 'SPA fallback URI', 'text', ''], ['rewrite_to', 'Rewrite URI', 'text', ''], ['cors_origin', 'CORS origin', 'text', '']
    ];
    const nginxSettingHelp = {
      limit_policy: 'Named request and concurrent-request budget from Global settings. Blank inherits; default restores Ban Shield 30r/s, burst 60, immediate, 30 concurrent. Different names have independent per-IP budgets; reusing a name shares its budget.',
      enable_lanonly: 'Allow only clients listed in Global settings → Allowed client IPs / CIDRs. A parent domain’s LAN restriction also applies to its subfolders.',
      enable_subfolders: 'Domain only: load enabled child apps at paths such as /music/. Subdomains are configured separately.',
      disable_root: 'Domain only: return 404 for requests outside enabled subfolders and ACME routes. Set No to expose the root app’s upstream and proxy settings.',
      enable_large_upload: 'Send uploaded request bodies to the backend without buffering them in nginx temporary files. Uses Large upload limit and the extended session/upload idle timeouts.',
      enable_longlived: 'Extend idle read, write, and client-send timeouts for long jobs, streams, or idle WebSockets. Session timeout controls the idle gap, not total connection lifetime.',
      enable_streaming: 'Deliver backend responses as they arrive instead of buffering them. Useful for streaming media and live updates; SSE always streams.',
      enable_byte_ranges: 'Enable partial responses and forward Range / If-Range headers for media seeking and resumable downloads.',
      enable_restricted_sessions: 'Add a LAN-only /Sessions route under this app and suppress its ordinary access logs. Useful for media-server session APIs.',
      clear_origin: 'Remove the Origin header sent to the backend. Leave No unless the application specifically requires this.',
      access_log: 'Write normal request logs. Setting No keeps ordinary requests quiet while security traps remain logged.',
      backend_auth: 'Pass Authorization and WWW-Authenticate through to the backend and disable nginx basic authentication for this app. The backend authenticates users.',
      hide_etag: 'Remove the backend’s ETag response header. Useful for app-shell routes that should not reuse cached versions.',
      disable_proxy_redirect: 'Pass backend redirects through without nginx rewriting them. Useful when the application already knows its public URL.',
      client_max_body_size: 'Maximum request/upload body in normal proxy mode, such as 128M. Does not limit downloads. Large uploads uses its separate limit; 0 means unlimited.',
      large_upload_max_body_size: 'Maximum request/upload body while Large uploads is enabled, such as 1G. Replaces Body size limit in that mode; 0 means unlimited.',
      proxy_connect_timeout: 'Maximum time to establish a connection to the backend, such as 10s. This is separate from the idle timeout of an established connection.',
      proxy_session_timeout: 'Idle time allowed between upstream reads/writes and client sends for long-lived connections or large uploads. Not a total session deadline.',
      client_upload_timeout: 'Allowed idle gap between reads of an uploaded request body when Large uploads is enabled. Not a total upload deadline.',
      proxy_transport: 'websocket supports both normal HTTP and upgrades; http omits upgrade headers. sse clears Connection, always streams, and uses 300s connection/session timeouts unless a route overrides them.',
      cache_policy: 'inherit keeps the app’s cache headers; no_cache prevents storage; pwa keeps the shell fresh and caches static assets; immutable long-caches versioned files.',
      forwarded_for: 'replace uses nginx’s observed client IP. append adds it to the incoming X-Forwarded-For chain and is intended for trusted proxy setups.',
      spa_fallback: 'On an upstream 404, serve this URI, commonly /index.html, for client-side routing. Exclude API/auth routes. Leave blank for apps that should return their own 404s.',
      rewrite_to: 'Rewrite matching requests to this one backend URI before proxying. Leave blank for normal path handling, including automatic subfolder-prefix removal.',
      cors_origin: 'Add CORS response headers allowing GET / OPTIONS from this origin, or *. The backend still needs to handle any required preflight requests.',
      router_ip: 'Local address nginx listens on for the generated HTTP and HTTPS servers. This address must exist on the nginx host; it is not the backend address.',
      http_port: 'Listening port for HTTP redirects and HTTP-01 certificate challenges, normally 80.',
      https_port: 'Listening port for TLS sites, normally 443.',
      worker_processes: 'Number of nginx worker processes, or auto. Choose a value appropriate for the host’s CPU and memory.',
      worker_connections: 'Maximum simultaneous connections per worker. Proxied traffic uses connections to both clients and backends.',
      resolver_addr: 'DNS server nginx uses to resolve backend hostnames. It must be reachable from the nginx host.',
      resolver_validity: 'How long nginx caches DNS answers before refreshing them, such as 30s.',
      var_dir: 'Base directory for generated access and security logs. Maestro’s main configuration separately controls nginx’s PID and error-log paths.',
      acme_challenge_dir: 'Directory containing HTTP-01 challenge files. It must match the certificate issuer’s challenge directory and be readable by nginx.',
      default_certificate_dir: 'Certificate directory for the unknown-host TLS server. Requires fullchain.pem and privkey.pem. Relative paths resolve beneath the nginx root.',
      nginx_daemon: 'Defaults to Yes on Asuswrt-Merlin, Linux, and in test mode. No keeps nginx in the foreground and prevents init.d startup scripts from continuing. Disable only for a foreground supervisor.',
      nginx_user: 'When Maestro runs as root, workers use this account or nobody if blank. When Maestro runs as non-root, the generated configuration omits the user directive.',
      temp_dir: 'Writable parent for nginx’s client-body, proxy, fastcgi, uwsgi, and scgi temporary folders. Only the parent folder is configurable.',
      pwa_shell_cache_control: 'Cache-Control header for PWA app-shell files. The default prevents stale shell files from being stored.',
      pwa_asset_cache_control: 'Cache-Control header for static PWA assets. Long-lived caching requires versioned asset URLs so application updates are picked up.',
      allowed_ips: 'One client IP or CIDR per line. LAN-only sites deny clients outside this list; an empty list denies all clients to those locations.',
      free_subdomains: 'One shared domain suffix per line, such as duckdns.org. Used to select certificate folders for individual accounts; put more specific suffixes first.',
      domain: 'Domain group and hostname for this root site, such as example.com. Add aliases separately if the site answers to multiple hostnames.',
      parent_domain: 'Existing domain group that owns this child site. The parent must be enabled before its child sites can be served.',
      site_name: 'Name of the subdomain or subfolder within its parent. A subfolder name becomes the public path prefix, such as /music/.',
      server_names: 'Hostnames and aliases accepted by this server, separated by spaces or new lines. Leave blank to use the name derived from the site identity.',
      upstream: 'Internal HTTP or HTTPS URL of the application, including its port if needed. Subfolder routes remove their public prefix before forwarding.',
      enabled: 'Enable this site after creating it. Nginx configuration is tested before applying the change; a parent domain must be enabled to serve its children.',
      content: 'Authored nginx text for an existing custom site. It is not processed as Jinja or regenerated when managed defaults change.',
      routes: 'JSON array of route overrides. Paths are relative to the app mount. Blank inherits global routes; [] disables them. Feature settings can also supply defaults to child routes.',
      default_routes: 'Default JSON route policies inherited by managed sites. Each site can replace this list. Route paths are relative to that app’s mount.'
    };
    function nginxFieldHeading(key, label, id) {
      const help = nginxSettingHelp[key];
      return `<div class="nginx-field-heading"><label for="${esc(id)}">${esc(label)}</label>${help ? `<button type="button" class="nginx-help-toggle" aria-label="Help: ${esc(label)}" aria-expanded="false" aria-controls="${esc(id)}-help" onclick="nginxToggleHelp(this)">?</button><span class="hint nginx-field-help" id="${esc(id)}-help" hidden>${esc(help)}</span>` : ''}</div>`;
    }
    function nginxToggleHelp(button) {
      const help = document.getElementById(button.dataset.helpId || button.getAttribute('aria-controls'));
      if (button.closest('#nginx-object-form')) {
        document.getElementById('nginx-help-title').textContent = button.closest('.nginx-field-heading').querySelector('label').textContent;
        document.getElementById('nginx-help-content').textContent = help.textContent;
        document.getElementById('nginx-help-modal').showModal();
        return;
      }
      help.hidden = !help.hidden;
      button.setAttribute('aria-expanded', String(!help.hidden));
    }
    const nginxDomainPolicyKeys = new Set(['enable_subfolders', 'disable_root']);
    function nginxPolicyFieldsFor(kind) { return nginxPolicyFields.filter(([key]) => key !== 'enable_lanonly' && (kind === 'domain' || !nginxDomainPolicyKeys.has(key))) }
    function nginxUpdateSiteFields(form, kind, inherited) {
      if (form.elements.mode.value === 'custom') return;
      const definitions = new Map(nginxPolicyFields.map(field => [field[0], field]));
      const effective = key => {
        const field = definitions.get(key), value = form.elements[key]?.value;
        if (value !== undefined && value !== '') return field[2] === 'bool' ? value === 'true' : value;
        return inherited[key] ?? field[3];
      };
      const proxy = kind !== 'domain' || !effective('disable_root');
      form.nginxProxyActive = proxy;
      form.querySelector('[data-nginx-path-controls]').hidden = !proxy;
      form.querySelector('[data-nginx-container-help]').hidden = proxy;
      const largeUpload = effective('enable_large_upload'), sse = effective('proxy_transport') === 'sse';
      const routeText = form.elements.routes.value.trim();
      let routeDefaults = !!routeText;
      try { routeDefaults = (routeText ? JSON.parse(routeText) : inherited.routes || []).length > 0 } catch { }
      for (const field of form.querySelectorAll('[data-nginx-setting]')) {
        const key = field.dataset.nginxSetting;
        let visible = proxy || key === 'enable_lanonly' || nginxDomainPolicyKeys.has(key);
        if (visible && !nginxDomainPolicyKeys.has(key) && key !== 'enable_lanonly') {
          if (['large_upload_max_body_size', 'client_upload_timeout'].includes(key)) visible = largeUpload || routeDefaults;
          if (key === 'client_max_body_size') visible = !largeUpload || routeDefaults;
          if (key === 'proxy_session_timeout') visible = !sse && (effective('enable_longlived') || largeUpload || routeDefaults);
          if (key === 'proxy_connect_timeout') visible = !sse;
          if (key === 'enable_longlived') visible = (!sse && !largeUpload) || routeDefaults;
          if (key === 'enable_streaming') visible = !sse || routeDefaults;
        }
        field.hidden = !visible;
      }
      form.querySelector('[data-nginx-upstream]').hidden = !proxy;
      form.querySelector('[data-nginx-routes]').hidden = !proxy;
    }
    const nginxSharedFields = [
      ['router_ip', 'Listen address', 'text', '127.0.0.1'], ['http_port', 'HTTP port', 'number', 80], ['https_port', 'HTTPS port', 'number', 443],
      ['worker_processes', 'Worker processes (or auto)', 'text', 2], ['worker_connections', 'Worker connections', 'number', 64],
      ['resolver_addr', 'DNS resolver', 'text', '127.0.0.1'], ['resolver_validity', 'DNS validity', 'text', '30s'],
      ['var_dir', 'Runtime directory', 'text', '/opt/var'], ['acme_challenge_dir', 'ACME challenge directory', 'text', ''],
      ['default_certificate_dir', 'Fallback certificate directory', 'text', ''],
      ['nginx_daemon', 'Run nginx in background', 'bool', true],
      ['nginx_user', 'Worker user (root only; default nobody)', 'text', 'nobody'],
      ['temp_dir', 'Temporary files parent directory', 'text', ''],
      ['pwa_shell_cache_control', 'PWA shell Cache-Control', 'text', 'no-cache, no-store, must-revalidate'],
      ['pwa_asset_cache_control', 'PWA asset Cache-Control', 'text', 'public, max-age=31536000, immutable']
    ];
    function nginxSettingsFields(fields, values = {}, inherited = {}, prefix = '') {
      return fields.map(([key, label, type, fallback]) => {
        const value = values[key], base = inherited[key] ?? fallback, name = prefix + key, id = 'nginx-setting-' + name;
        let control;
        if (type === 'bool' || Array.isArray(type)) {
          const options = type === 'bool' ? [true, false] : type;
          control = `<select class="input" name="${name}" id="${id}"><option value="">Use default (${esc(String(base))})</option>${options.map(option => `<option value="${esc(String(option))}" ${value === option ? 'selected' : ''}>${type === 'bool' ? (option ? 'Yes' : 'No') : esc(option)}</option>`).join('')}</select>`;
        } else control = `<input class="input" name="${name}" id="${id}" type="${type === 'number' ? 'number' : 'text'}" value="${esc(value ?? (key === 'nginx_user' ? fallback : ''))}" placeholder="${esc(String(base))}">`;
        const warning = key === 'nginx_daemon' ? '<p class="notice" role="alert" data-nginx-daemon-warning hidden>Warning: foreground nginx prevents init.d startup scripts from continuing. Disable background mode only for a foreground supervisor.</p>' : '';
        return `<div class="field" data-nginx-setting="${esc(key)}">${nginxFieldHeading(key, label, id)}${control}${warning}</div>`;
      }).join('');
    }
    function nginxReadSettings(form, fields, prefix = '') {
      const result = {};
      fields.forEach(([key, , type]) => { const control = form.elements[prefix + key]; if (!control) return; const value = control.value.trim(); if (value !== '') result[key] = type === 'bool' ? value === 'true' : (type === 'number' || key === 'worker_processes' && value !== 'auto') ? Number(value) : value });
      return result;
    }
    function nginxRoutesSummary(value, defaults = false) {
      if (!value.trim()) return defaults ? 'No default routes' : 'Use global defaults';
      try { const routes = JSON.parse(value); return Array.isArray(routes) ? (routes.length ? `${routes.length} route ${routes.length === 1 ? 'policy' : 'policies'}` : 'No routes') : 'Invalid policies' } catch { return 'Invalid JSON' }
    }
    function nginxRoutesField(settings = {}, name = 'routes') {
      const value = settings.routes ? JSON.stringify(settings.routes, null, 2) : '';
      return `<div class="field full site-routes" data-nginx-routes><button type="button" class="btn small" aria-haspopup="dialog" aria-controls="nginx-routes-modal" onclick="openNginxRoutes(this)">Advanced route policies</button><span class="hint" data-route-summary>${esc(nginxRoutesSummary(value, name === 'default_routes'))}</span><textarea hidden name="${name}">${esc(value)}</textarea></div>`;
    }
    function openNginxRoutes(button) {
      const source = button.closest('[data-nginx-routes]').querySelector('textarea');
      const modal = document.getElementById('nginx-routes-modal');
      modal.routeTarget = source;
      document.getElementById('nginx-routes-title').textContent = source.name === 'default_routes' ? 'Default route policies' : 'Site route policies';
      document.getElementById('nginx-route-draft').value = source.value;
      document.getElementById('nginx-route-inheritance').textContent = source.name === 'default_routes' ? 'Leave blank or use [] for no default routes. Sites inherit this list unless they replace it.' : 'Leave blank to inherit global routes. Use [] to disable routes for this site. Use policies returns these edits to the site form; Save applies them.';
      document.getElementById('nginx-route-error').hidden = true;
      modal.showModal();
      document.getElementById('nginx-route-draft').focus();
    }
    function applyNginxRoutes(event) {
      event.preventDefault();
      const modal = document.getElementById('nginx-routes-modal'), source = modal.routeTarget;
      const value = document.getElementById('nginx-route-draft').value.trim();
      try {
        if (value && !Array.isArray(JSON.parse(value))) throw new Error('Policies must be a JSON array, such as [{"path":"/admin/","enable_lanonly":true}].');
        source.value = value;
        source.closest('[data-nginx-routes]').querySelector('[data-route-summary]').textContent = nginxRoutesSummary(value, source.name === 'default_routes');
        source.dispatchEvent(new Event('input', { bubbles: true }));
        modal.close();
      } catch (error) {
        const message = document.getElementById('nginx-route-error');
        message.textContent = error.message;
        message.hidden = false;
      }
    }
    function nginxEndpointRow(protocol, endpoint = {}) {
      const isHttps = protocol === 'https';
      return `<div class="nginx-endpoint-row" data-nginx-endpoint="${protocol}">
        <span class="endpoint-proto-badge ${protocol}">${protocol.toUpperCase()}</span>
        <div class="field endpoint-field-address">
          <label>Listen address</label>
          <input class="input" data-endpoint-address value="${esc(endpoint.address || '127.0.0.1')}" placeholder="127.0.0.1" required>
        </div>
        <div class="field endpoint-field-port">
          <label>Port</label>
          <input class="input" data-endpoint-port type="number" min="1" max="65535" value="${endpoint.port || (isHttps ? 8444 : 8080)}" required>
        </div>
        <div class="endpoint-field-action">
          <button type="button" class="btn small danger endpoint-remove-btn" title="Remove address" onclick="this.closest('[data-nginx-endpoint]').remove()">✕ Remove</button>
        </div>
      </div>`;
    }
    function nginxUsageHint(type, name) {
      const rows = (state.nginxUsage || {})[`${type}:${name}`] || [];
      const count = rows.length;
      return `<details class="nginx-usage-details"><summary class="nginx-usage-summary"><span class="nginx-usage-pill ${count > 0 ? 'active' : ''}">${count} reference${count === 1 ? '' : 's'}</span><span class="nginx-usage-label">affected by edits</span></summary><div class="nginx-usage-content"><p class="hint">${count ? rows.map(esc).join('<br>') : 'Not referenced by saved managed settings.'}</p></div></details>`;
    }
    function nginxProfileCard(name = '', profile = {https:[{address:'127.0.0.1',port:8444}],http:[],http_redirect:false}) {
      return `<div class="card nginx-item-card" data-nginx-profile>
        <div class="card-head">
          <div class="card-title-group">
            <span class="card-title-badge">Listener</span>
            <h4 class="card-title-name" data-profile-title>${esc(name || 'New listener')}</h4>
          </div>
          <button type="button" class="btn small danger" onclick="this.closest('[data-nginx-profile]').remove()">Delete listener</button>
        </div>
        <div class="card-body">
          <div class="form-grid nginx-profile-header-grid">
            <div class="field">
              <label>Listener name</label>
              <input class="input" data-profile-name value="${esc(name)}" placeholder="internal" required pattern="[A-Za-z0-9_]{1,32}" oninput="const t=this.closest('[data-nginx-profile]').querySelector('[data-profile-title]'); if(t) t.textContent=this.value.trim() || 'New listener'">
            </div>
            <div class="field nginx-usage-field">
              ${nginxUsageHint('listener', name)}
            </div>
          </div>
          <div class="nginx-endpoints-wrapper">
            <div class="nginx-endpoints-header">
              <span class="endpoints-heading">Bound addresses &amp; ports</span>
              <div class="actions">
                <button type="button" class="btn small action" onclick="this.closest('[data-nginx-profile]').querySelector('[data-endpoints]').insertAdjacentHTML('beforeend', nginxEndpointRow('https'))">+ Add HTTPS</button>
                <button type="button" class="btn small" onclick="this.closest('[data-nginx-profile]').querySelector('[data-endpoints]').insertAdjacentHTML('beforeend', nginxEndpointRow('http'))">+ Add HTTP</button>
              </div>
            </div>
            <div data-endpoints>
              ${profile.https.map(e => nginxEndpointRow('https',e)).join('')}
              ${profile.http.map(e => nginxEndpointRow('http',e)).join('')}
            </div>
          </div>
          <div class="nginx-card-options">
            <label class="checkbox-label">
              <input type="checkbox" data-http-redirect ${profile.http_redirect ? 'checked' : ''}>
              <span>HTTP redirects when shared HTTP mode is Always on</span>
            </label>
            <p class="hint">Use literal addresses; 0.0.0.0 means all IPv4 interfaces, :: means all IPv6 interfaces. Choose additional interfaces explicitly.</p>
          </div>
        </div>
      </div>`;
    }
    function nginxAccessCard(name = '', policy = {allow:[]}) {
      return `<div class="card nginx-item-card" data-nginx-access>
        <div class="card-head">
          <div class="card-title-group">
            <span class="card-title-badge access">Access rule</span>
            <h4 class="card-title-name" data-access-title>${esc(name || 'New rule')}</h4>
          </div>
          <button type="button" class="btn small danger" onclick="this.closest('[data-nginx-access]').remove()">Delete access rule</button>
        </div>
        <div class="card-body">
          <div class="form-grid nginx-profile-header-grid">
            <div class="field">
              <label>Access rule name</label>
              <input class="input" data-access-name value="${esc(name)}" placeholder="trusted_clients" required pattern="[A-Za-z0-9_]{1,32}" oninput="const t=this.closest('[data-nginx-access]').querySelector('[data-access-title]'); if(t) t.textContent=this.value.trim() || 'New rule'">
            </div>
            <div class="field nginx-usage-field">
              ${nginxUsageHint('access', name)}
            </div>
          </div>
          <div class="field full">
            <label for="access-allow-${esc(name || 'new')}">Allowed IPs / networks (one per line)</label>
            <textarea class="input nginx-mono-textarea" id="access-allow-${esc(name || 'new')}" data-access-allow placeholder="192.168.1.0/24&#10;10.0.0.1&#10;127.0.0.1">${esc(policy.allow.join('\n'))}</textarea>
            <p class="hint">Empty blocks all sources. Loopback identifies a forwarding process, not the individual users behind it.</p>
          </div>
        </div>
      </div>`;
    }
    function nginxReadCollections(form) {
      const listener_profiles = Object.create(null), access_policies = Object.create(null);
      for (const row of form.querySelectorAll('[data-nginx-profile]')) {
        const name = row.querySelector('[data-profile-name]').value.trim();
        if (!name || listener_profiles[name] || name === 'legacy') throw new Error('Listener names must be unique; legacy is reserved for Existing configuration.');
        const profile = {https:[],http:[],http_redirect:row.querySelector('[data-http-redirect]').checked};
        for (const endpoint of row.querySelectorAll('[data-nginx-endpoint]')) profile[endpoint.dataset.nginxEndpoint].push({address:endpoint.querySelector('[data-endpoint-address]').value.trim(),port:Number(endpoint.querySelector('[data-endpoint-port]').value)});
        listener_profiles[name] = profile;
      }
      for (const row of form.querySelectorAll('[data-nginx-access]')) {
        const name = row.querySelector('[data-access-name]').value.trim();
        if (!name || access_policies[name] || ['legacy','public','deny'].includes(name)) throw new Error('Access rule names must be unique; legacy, public and deny are reserved.');
        access_policies[name] = {allow:jsonLines(row.querySelector('[data-access-allow]').value)};
      }
      return {listener_profiles,access_policies};
    }
    function nginxAccessOptions(global, selected = '', inherited = 'existing rule') {
      const options = [['',`Use inherited rule (${inherited})`],['public','Any source'],['deny','Block all'],['legacy','Existing configuration allowlist'],...Object.keys(global.access_policies || {}).map(name => [name,name])];
      return options.map(([value,label]) => `<option value="${esc(value)}" ${selected === value ? 'selected' : ''}>${esc(label)}</option>`).join('');
    }
    function nginxSelectedAccess(settings) { return settings.access_policy ?? (settings.enable_lanonly === undefined ? '' : settings.enable_lanonly ? 'legacy' : 'public') }
    function nginxAccessControl(global, settings, prefix = '') {
      return `<div class="field"><label for="${prefix}access-policy">Access rule</label><select class="input" name="${prefix}access_policy" id="${prefix}access-policy">${nginxAccessOptions(global,nginxSelectedAccess(settings),nginxSelectedAccess(global.site_defaults) || 'Existing configuration allowlist')}</select></div>`;
    }
    function nginxSessionPolicyControl(global,settings,prefix='') {
      return `<div class="field"><label for="${prefix}restricted-sessions-policy">Restricted Sessions access rule</label><select class="input" name="${prefix}restricted_sessions_policy" id="${prefix}restricted-sessions-policy">${nginxAccessOptions(global,settings.restricted_sessions_policy || '',global.site_defaults.restricted_sessions_policy || 'Existing configuration allowlist')}</select></div>`;
    }
    function nginxListenerOptions(global, selected = '') {
      return [['','Use configured default'],['legacy','Existing configuration'],...Object.entries(global.listener_profiles || {}).map(([name,p]) => [name,`${name} · ${p.https.map(e => `${e.address}:${e.port}`).join(', ')}`])].map(([value,label]) => `<option value="${esc(value)}" ${value === selected ? 'selected' : ''}>${esc(label)}</option>`).join('');
    }
    async function editNginxSettings() {
      try {
        const [settings, usage] = await Promise.all([api('/nginx/settings'),api('/nginx/ingress-usage')]);
        state.nginxUsage = usage;
        const http = settings.http_access || {mode:'always',window_seconds:3600,listener_profile:'legacy'}, profiles = settings.listener_profiles || {}, policies = settings.access_policies || {};
        const legacyFields = nginxSharedFields.filter(([key]) => ['router_ip','http_port','https_port'].includes(key)), advancedFields = nginxSharedFields.filter(([key]) => !legacyFields.some(([legacy]) => legacy === key));
        openEditor('Nginx listeners and access', `<form id="nginx-settings-form" class="form">
          <div class="nginx-settings-intro">
            <div class="nginx-intro-icon">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>
            </div>
            <div class="nginx-intro-text">
              Configure reusable listeners and source rules once, then select them for each site. Names do not configure VPN user permissions or general firewall policy.
            </div>
          </div>

          <div class="nginx-section-header">
            <div class="nginx-section-title">
              <span class="nginx-section-badge">HTTP</span>
              <h3>Public HTTP access</h3>
            </div>
          </div>
          <div class="card pad nginx-section-card">
            <div class="form-grid">
              <div class="field">
                <label for="nginx-http-mode">HTTP mode</label>
                <select class="input" name="http_mode" id="nginx-http-mode">
                  <option value="off" ${http.mode === 'off' ? 'selected' : ''}>Off</option>
                  <option value="renewal_only" ${http.mode === 'renewal_only' ? 'selected' : ''}>Certificate validation only</option>
                  <option value="always" ${http.mode === 'always' ? 'selected' : ''}>Always on with redirects</option>
                </select>
              </div>
              <div class="field">
                <label for="nginx-http-listener">Challenge listener</label>
                <select class="input" name="http_listener" id="nginx-http-listener">${nginxListenerOptions(settings,http.listener_profile)}</select>
              </div>
              <div class="nginx-mode-hint">
                <p class="hint">Validation only closes managed public HTTP outside actual HTTP-01 batches. Normal HTTP redirects are unavailable. DNS-01 never opens a window.</p>
              </div>
              <div class="field">
                <label for="nginx-http-window">Maximum validation window (seconds)</label>
                <input class="input" name="http_window" id="nginx-http-window" type="number" min="60" max="86400" value="${http.window_seconds}">
              </div>
              <div class="field">
                <label for="nginx-http-wan">Validation WAN access</label>
                <select class="input" id="nginx-http-wan" name="http_wan">
                  <option value="unconfigured">Not configured</option>
                  <option value="external" ${http.externally_managed_wan ? 'selected' : ''}>Externally managed</option>
                  <option value="managed" ${http.wan ? 'selected' : ''}>Managed IPv4 (firmware verification required)</option>
                </select>
              </div>
              <div class="field">
                <label for="nginx-wan-interface">WAN interface</label>
                <input class="input" id="nginx-wan-interface" name="wan_interface" value="${esc(http.wan?.interface || '')}" placeholder="Verified interface name">
              </div>
              <div class="field">
                <label for="nginx-wan-target">Router IPv4 challenge address</label>
                <input class="input" id="nginx-wan-target" name="wan_target" value="${esc(http.wan?.target || '')}" placeholder="Address bound by the challenge listener">
              </div>
            </div>
            <div class="notice nginx-wan-notice">
              The experimental managed adapter controls only owned TCP-80 rules, requires iptables, ip6tables and ipset, and blocks WAN IPv6 TCP 80. Verify firmware rule ordering before deployment. Its timed kernel gate limits WAN access after a crash; local nginx cleanup requires Maestro startup recovery. External mode does not toggle your WAN rules.
            </div>
          </div>

          <div class="nginx-section-header">
            <div class="nginx-section-title">
              <span class="nginx-section-badge">Listeners</span>
              <h3>Listeners</h3>
            </div>
            <button class="btn small action" type="button" onclick="document.getElementById('nginx-profile-rows').insertAdjacentHTML('beforeend',nginxProfileCard())">+ Add listener</button>
          </div>
          <details class="nginx-settings-accordion">
            <summary><span>Existing configuration · legacy listener</span></summary>
            <div class="nginx-accordion-content">
              <div class="form-grid">${nginxSettingsFields(legacyFields,settings.shared)}</div>
              <div style="margin-top: 10px;">${nginxUsageHint('listener','legacy')}</div>
            </div>
          </details>
          <div id="nginx-profile-rows">${Object.entries(profiles).map(([name,p]) => nginxProfileCard(name,p)).join('')}</div>

          <div class="nginx-section-header">
            <div class="nginx-section-title">
              <span class="nginx-section-badge">Access</span>
              <h3>Access rules</h3>
            </div>
            <button class="btn small action" type="button" onclick="document.getElementById('nginx-access-rows').insertAdjacentHTML('beforeend',nginxAccessCard())">+ Add access rule</button>
          </div>
          <details class="nginx-settings-accordion">
            <summary><span>Existing configuration allowlist</span></summary>
            <div class="nginx-accordion-content">
              <div class="field full">
                <label for="nginx-allowed-ips">Allowed IPs / networks (one per line)</label>
                <textarea class="input nginx-mono-textarea" id="nginx-allowed-ips" name="allowed_ips">${esc(settings.allowed_ips.join('\n'))}</textarea>
              </div>
              <div style="margin-top: 10px;">${nginxUsageHint('access','legacy')}</div>
            </div>
          </details>
          <div id="nginx-access-rows">${Object.entries(policies).map(([name,p]) => nginxAccessCard(name,p)).join('')}</div>

          <div class="nginx-section-header">
            <div class="nginx-section-title">
              <span class="nginx-section-badge">Defaults</span>
              <h3>Default site settings</h3>
            </div>
          </div>
          <details class="nginx-settings-accordion">
            <summary><span>Default site settings (inherited by sites)</span></summary>
            <div class="nginx-accordion-content">
              <div class="notice" style="margin-bottom: 12px;">Changes affect inheriting sites. Explicit site selections are retained.</div>
              <div class="form-grid">
                <div class="field">
                  <label for="default-listener-profile">Default listener</label>
                  <select class="input" name="default_listener_profile" id="default-listener-profile">${nginxListenerOptions(settings,settings.site_defaults.listener_profile || '')}</select>
                </div>
                ${nginxAccessControl(settings,settings.site_defaults,'default_')}
                ${nginxSettingsFields(nginxPolicyFields.filter(([key]) => key !== 'enable_lanonly'),settings.site_defaults,{},'default_')}
                ${nginxSessionPolicyControl(settings,settings.site_defaults,'default_')}
                ${nginxRoutesField(settings.site_defaults,'default_routes')}
              </div>
            </div>
          </details>

          <div class="nginx-section-header">
            <div class="nginx-section-title">
              <span class="nginx-section-badge">Advanced</span>
              <h3>Advanced global settings</h3>
            </div>
          </div>
          <details class="nginx-settings-accordion">
            <summary><span>Advanced global settings</span></summary>
            <div class="nginx-accordion-content">
              <div class="form-grid">${nginxSettingsFields(advancedFields,settings.shared)}</div>
              <div class="field full" style="margin-top: 12px;">
                <label for="nginx-limit-policies">Request limit policies (JSON object)</label>
                <textarea class="input nginx-mono-textarea" id="nginx-limit-policies" name="limit_policies">${esc(JSON.stringify(settings.limit_policies || {},null,2))}</textarea>
              </div>
              <div class="field full" style="margin-top: 12px;">
                <label for="nginx-free-subdomains">Shared domain suffixes (one per line)</label>
                <textarea class="input nginx-mono-textarea" id="nginx-free-subdomains" name="free_subdomains">${esc(settings.free_subdomains.join('\n'))}</textarea>
              </div>
            </div>
          </details>
          <p class="route-policy-error" role="alert" data-form-error hidden></p>
        </form>`, async () => {
          const f = document.getElementById('nginx-settings-form');
          try {
            if (!f.reportValidity()) return;
            const defaults = nginxReadSettings(f,nginxPolicyFields,'default_');
            if (f.elements.default_routes.value.trim()) defaults.routes = JSON.parse(f.elements.default_routes.value);
            if (f.elements.default_listener_profile.value) defaults.listener_profile = f.elements.default_listener_profile.value;
            if (f.elements.default_access_policy.value) defaults.access_policy = f.elements.default_access_policy.value;
            if (f.elements.default_restricted_sessions_policy.value) defaults.restricted_sessions_policy=f.elements.default_restricted_sessions_policy.value;
            const payload = {...settings,...nginxReadCollections(f),shared:nginxReadSettings(f,nginxSharedFields),site_defaults:defaults,limit_policies:JSON.parse(f.elements.limit_policies.value || '{}'),allowed_ips:jsonLines(f.elements.allowed_ips.value),free_subdomains:jsonLines(f.elements.free_subdomains.value)};
            payload.http_access = {mode:f.elements.http_mode.value,window_seconds:Number(f.elements.http_window.value),listener_profile:f.elements.http_listener.value || 'legacy',wan:null,externally_managed_wan:f.elements.http_wan.value === 'external'};
            if (f.elements.http_wan.value === 'managed') payload.http_access.wan = {interface:f.elements.wan_interface.value.trim(),target:f.elements.wan_target.value.trim()};
            await api('/nginx/settings',{method:'PUT',body:JSON.stringify(payload)});
            closeEditor(); toast('Nginx settings saved'); loadNginx();
          } catch (e) { const error = f.querySelector('[data-form-error]'); error.textContent=e.message; error.hidden=false; }
        });
        const form=document.getElementById('nginx-settings-form');
        const update = event => {
          form.querySelector('[data-nginx-daemon-warning]').hidden = form.elements.nginx_daemon.value !== 'false';
          const mode=form.elements.http_mode.value, managed=mode !== 'always' && form.elements.http_wan.value === 'managed';
          if (mode === 'always') form.elements.http_wan.value='unconfigured';
          form.elements.http_wan.disabled=mode === 'always';
          for (const name of ['wan_interface','wan_target']) { form.elements[name].closest('.field').hidden=!managed; form.elements[name].required=managed; }
          if (event?.target.matches('[data-profile-name], [data-access-name], [data-endpoint-address], [data-endpoint-port]')) {
            const draft={...settings,listener_profiles:Object.create(null),access_policies:Object.create(null)};
            for(const row of form.querySelectorAll('[data-nginx-profile]')) { const name=row.querySelector('[data-profile-name]').value.trim(); if(name) draft.listener_profiles[name]={https:[...row.querySelectorAll('[data-nginx-endpoint="https"]')].map(endpoint => ({address:endpoint.querySelector('[data-endpoint-address]').value,port:Number(endpoint.querySelector('[data-endpoint-port]').value)}))}; }
            for(const row of form.querySelectorAll('[data-nginx-access]')) { const name=row.querySelector('[data-access-name]').value.trim(); if(name) draft.access_policies[name]={}; }
            for(const [name,render] of [['http_listener',nginxListenerOptions],['default_listener_profile',nginxListenerOptions],['default_access_policy',nginxAccessOptions]]) {
              const control=form.elements[name], value=control.value; control.innerHTML=render(draft,value);
              if(![...control.options].some(option => option.value === value)) control.insertAdjacentHTML('beforeend',`<option value="${esc(value)}" selected>Missing choice: ${esc(value)}</option>`);
            }
          }
        };
        form.addEventListener('input',update); form.addEventListener('change',update); update();
      } catch (e) { toast(e.message,true) }
    }
    function nginxIngressFields(kind, global, settings) {
      return `<div data-nginx-ingress><div class="form-grid">${kind === 'subfolder' ? '<div class="field"><label>Listener (inherited from domain)</label><span data-listener-inherited>Resolving…</span></div>' : `<div class="field"><label for="site-listener">Listener</label><select class="input" id="site-listener" name="listener_profile">${nginxListenerOptions(global,settings.listener_profile || '')}</select></div>`}${nginxAccessControl(global,settings)}${kind === 'domain' ? `<div class="field"><label>Root application<select class="input" name="disable_root"><option value="" ${settings.disable_root === undefined ? 'selected' : ''}>Use configured default</option><option value="false" ${settings.disable_root === false ? 'selected' : ''}>Serve upstream at root</option><option value="true" ${settings.disable_root === true ? 'selected' : ''}>Subfolder container only</option></select></label></div>` : ''}</div><button type="button" class="btn small" onclick="nginxManageFromSite()">Manage listeners and access rules</button><div class="notice" data-effective-access aria-live="polite">Resolving effective access…</div><p class="hint" data-nginx-container-help hidden>This domain is a subfolder container. Configure path rules on each subfolder application; root application rules are inactive.</p><div data-nginx-path-controls><div class="field"><label for="nginx-block-path">Blocked paths</label><input class="input" id="nginx-block-path" data-block-path placeholder="/admin"><label><input type="checkbox" data-block-subpaths checked> Include subpaths</label><button type="button" class="btn small" onclick="nginxAddBlockedPath(this.form)">Block path</button></div><details><summary>Path access rules</summary><div data-simple-routes></div><button type="button" class="btn small" onclick="nginxAddPathRule(this.form)">Add path rule</button><p class="hint">A child rule cannot remove a parent restriction. Regex, nested and proxy-specific settings remain in Advanced route policies.</p></details></div></div>`;
    }
    function nginxRouteData(form) {
      const value = form.elements.routes.value.trim();
      return structuredClone(value ? JSON.parse(value) : form.nginxGlobal.site_defaults.routes || []);
    }
    function nginxRenderPathRules(form) {
      const rows = form.querySelector('[data-simple-routes]');
      if (!rows) return;
      try {
        const routes = nginxRouteData(form);
        rows.innerHTML = routes.length ? '' : '<p class="muted">No path rules.</p>';
        routes.forEach(route => {
          const row = document.createElement('div'); row.className='card'; row.dataset.pathRule=''; row.nginxRoute=route;
          const advanced = Object.keys(route).some(key => !['path','match','access_policy','enable_lanonly'].includes(key)) || ['regex','regex_i'].includes(route.match);
          row.innerHTML = `<div class="form-grid"><div class="field"><label>Path<input class="input" data-route-path value="${esc(route.path)}" ${['regex','regex_i'].includes(route.match) ? 'readonly' : ''}></label></div><div class="field"><label>Match<select class="input" data-route-match><option value="prefix" ${!route.match || route.match === 'prefix' ? 'selected' : ''}>Prefix (starts with)</option><option value="exact" ${route.match === 'exact' ? 'selected' : ''}>Exact path</option>${['regex','regex_i'].includes(route.match) ? `<option value="${route.match}" selected>Advanced regex</option>` : ''}</select></label></div><div class="field"><label>Access rule<select class="input" data-route-access>${nginxAccessOptions(form.nginxGlobal,nginxSelectedAccess(route),'parent rule')}</select></label></div></div>${advanced ? '<span class="hint">Advanced properties are preserved. Use Advanced route policies to edit them.</span>' : ''}<button type="button" class="btn small danger" onclick="const f=this.form; this.closest('[data-path-rule]').remove(); nginxPathRulesChanged(f)">Remove rule</button>`;
          row.addEventListener('input',() => nginxPathRulesChanged(form)); row.addEventListener('change',() => nginxPathRulesChanged(form)); rows.appendChild(row);
        });
      } catch (error) { rows.textContent=`Advanced route draft: ${error.message}`; }
    }
    function nginxCollectPathRules(form) {
      return [...form.querySelectorAll('[data-path-rule]')].map(row => {
        const route = {...row.nginxRoute,path:row.querySelector('[data-route-path]').value.trim(),match:row.querySelector('[data-route-match]').value};
        delete route.access_policy; delete route.enable_lanonly;
        const policy = row.querySelector('[data-route-access]').value;
        if (policy) route.access_policy=policy;
        return route;
      });
    }
    function nginxSetRoutes(form, routes) {
      form.elements.routes.value=JSON.stringify(routes);
      form.querySelector('[data-route-summary]').textContent=nginxRoutesSummary(form.elements.routes.value);
    }
    function nginxPathRulesChanged(form) { nginxSetRoutes(form,nginxCollectPathRules(form)); nginxScheduleAccessPreview(form); }
    function nginxAddPathRule(form) {
      const routes=nginxRouteData(form); routes.push({path:'/path',match:'exact'});
      nginxSetRoutes(form,routes); nginxRenderPathRules(form); nginxScheduleAccessPreview(form);
    }
    function nginxAddBlockedPath(form) {
      try {
        const input=form.querySelector('[data-block-path]'), path=input.value.trim().replace(/\/+$/,'');
        if (!path.startsWith('/') || path === '' || /[\s?#;{}"']/.test(path)) throw new Error('Enter an application path such as /admin; use Block all to deny the whole site.');
        const routes=nginxRouteData(form), additions=[{path,match:'exact',access_policy:'deny'}];
        if (form.querySelector('[data-block-subpaths]').checked) additions.push({path:path+'/',match:'prefix',access_policy:'deny'});
        for (const addition of additions) {
          const existing=routes.find(route => route.path === addition.path && (route.match || 'prefix') === addition.match);
          if (existing && existing.access_policy !== 'deny') throw new Error(`An access rule already exists for ${addition.path}; edit it instead of adding a conflicting block.`);
          if (!existing) routes.push(addition);
        }
        nginxSetRoutes(form,routes); nginxRenderPathRules(form); input.value=''; nginxScheduleAccessPreview(form);
      } catch (error) { nginxSiteError(form,error.message); }
    }
    function nginxSiteSettings(form, original, fields) {
      const result={...original};
      for (const [key] of fields) if (form.elements[key]) delete result[key];
      Object.assign(result,nginxReadSettings(form,fields));
      delete result.enable_lanonly; delete result.access_policy;
      if (form.elements.access_policy.value) result.access_policy=form.elements.access_policy.value;
      delete result.restricted_sessions_policy;
      if (form.elements.restricted_sessions_policy?.value) result.restricted_sessions_policy=form.elements.restricted_sessions_policy.value;
      delete result.listener_profile;
      if (form.elements.listener_profile?.value) result.listener_profile=form.elements.listener_profile.value;
      if (form.elements.routes.value.trim()) result.routes=JSON.parse(form.elements.routes.value); else delete result.routes;
      return result;
    }
    function nginxSiteError(form, message) {
      let error=form.querySelector('[data-form-error]');
      if (!error) { error=document.createElement('p'); error.dataset.formError=''; error.className='route-policy-error'; error.setAttribute('role','alert'); form.appendChild(error); }
      error.textContent=message; error.hidden=!message;
    }
    function nginxScheduleAccessPreview(form) {
      clearTimeout(form.nginxPreviewTimer);
      const sequence=(form.nginxPreviewSequence || 0)+1; form.nginxPreviewSequence=sequence;
      form.nginxPreviewTimer=setTimeout(async () => {
        if (!form.isConnected) return;
        const output=form.querySelector('[data-effective-access]');
        try {
          const settings=nginxSiteSettings(form,form.nginxOriginalSettings,form.nginxFields), domain=form.elements.domain.value;
          const effective=await api('/nginx/access-preview',{method:'POST',body:JSON.stringify({kind:form.nginxKind,domain,settings})});
          if (!form.isConnected || sequence !== form.nginxPreviewSequence) return;
          const sources=effective.allowed_sources === null ? 'Any source' : effective.allowed_sources.length ? effective.allowed_sources.join(', ') : 'No matching sources; requests will be blocked';
          const bindings=effective.https.map(e => `${e.address}:${e.port}`).join(', '), inherited=effective.inherited_from ? ` · limited by domain ${effective.inherited_from}` : '';
          output.innerHTML=`<strong>Effective access</strong><div>${esc(effective.listener_profile)} · HTTPS ${esc(bindings)}</div><div>${esc(sources + inherited)}</div><div>${effective.http.length ? 'Normal HTTP redirects configured' : 'No normal HTTP redirects'}</div>${(form.nginxProxyActive === false ? [] : effective.routes).filter(route => route.allowed_sources?.length === 0).map(route => `<div>Blocked: ${esc(route.path)}</div>`).join('')}`;
          const parent=state.nginxObjects.find(o => o.kind === 'domain' && o.domain === domain);
          if (form.nginxKind !== 'domain' && parent && !parent.enabled) output.insertAdjacentHTML('beforeend','<div>Containing domain is disabled.</div>');
          const label=form.querySelector('[data-listener-inherited]'); if(label) label.textContent=`${effective.listener_profile} · ${bindings}`;
        } catch(error) { if (sequence === form.nginxPreviewSequence && form.isConnected) { output.textContent=`Effective access unavailable: ${error.message}`; } }
      },180);
    }
    async function nginxManageFromSite() {
      const form=document.getElementById('nginx-object-form'), body=document.getElementById('editor-body'), dialog=document.getElementById('editor');
      clearTimeout(form.nginxPreviewTimer); form.nginxPreviewSequence=(form.nginxPreviewSequence || 0)+1;
      const fragment=document.createDocumentFragment(), title=document.getElementById('editor-title').textContent, save=document.getElementById('editor-save').onclick;
      while(body.firstChild) fragment.appendChild(body.firstChild);
      await editNginxSettings();
      const restore=async () => {
        try { Object.assign(form.nginxGlobal,await api('/nginx/settings')); } catch(error) { toast(error.message,true); }
        body.replaceChildren(fragment); document.getElementById('editor-title').textContent=title; document.getElementById('editor-save').onclick=save; dialog.classList.add('nginx-site-editor');
        for (const [name, render] of [['listener_profile',nginxListenerOptions],['access_policy',nginxAccessOptions]]) {
          const control=form.elements[name]; if(!control) continue;
          const value=control.value; control.innerHTML=render(form.nginxGlobal,value);
          if (!control.querySelector(`option[value="${CSS.escape(value)}"]`)) control.insertAdjacentHTML('beforeend',`<option value="${esc(value)}" selected>Missing saved choice: ${esc(value)}</option>`);
        }
        nginxRenderPathRules(form); dialog.showModal(); nginxScheduleAccessPreview(form);
      };
      if (!document.getElementById('nginx-settings-form')) { await restore(); return; }
      dialog.addEventListener('close',restore,{once:true});
    }
    function nginxDomainOptions(selected = '') { return state.nginxObjects.filter(o => o.kind === 'domain').map(o => `<option value="${esc(o.domain)}" ${selected === o.domain ? 'selected' : ''}>${esc(o.domain)}</option>`).join('') }
    async function newNginxObject(kind) { return nginxObjectEditor(kind) }
    async function editNginxObject(kind, domain, name) { return nginxObjectEditor(kind, domain, name) }
    async function nginxObjectEditor(kind, domain = '', name = '') {
      try {
        const existing = !!domain, row = existing ? await api(nginxObjectUrl({ kind, domain, name })) : null, global = await api('/nginx/settings');
        const settings = row?.settings || {}, custom = existing && row.settings === null, policyFields = nginxPolicyFieldsFor(kind);
        const identity = `<div class="field">${nginxFieldHeading(kind === 'domain' ? 'domain' : 'parent_domain', kind === 'domain' ? 'Domain' : 'Parent domain', 'nginx-object-domain')}${existing ? `<input class="input" name="domain" id="nginx-object-domain" value="${esc(domain)}" readonly>` : kind === 'domain' ? '<input class="input" name="domain" id="nginx-object-domain" placeholder="example.com" required>' : `<select class="input" name="domain" id="nginx-object-domain" required>${nginxDomainOptions()}</select>`}</div>${kind === 'domain' ? '' : `<div class="field">${nginxFieldHeading('site_name', kind + ' name', 'nginx-object-name')}<input class="input" id="nginx-object-name" name="name" value="${esc(name)}" ${existing ? 'readonly' : 'required'}></div>`}`;
        openEditor(existing ? `Edit ${kind}: ${name}` : `Add ${kind}`, `<form id="nginx-object-form" class="form"><div class="site-toolbar"><span class="hint">${custom ? 'Custom configuration' : 'Blank settings inherit global defaults · ? for help'}</span><button type="button" class="btn small" onclick="openNginxReference()">Setup guide</button></div><div class="form-grid">${identity}${kind === 'subfolder' ? '' : `<div class="field">${nginxFieldHeading('server_names', 'Hostnames / aliases', 'nginx-object-server-names')}<textarea class="input" id="nginx-object-server-names" name="server_names">${esc((row?.server_names || []).join('\n'))}</textarea></div>`}<div class="field" data-nginx-upstream>${nginxFieldHeading('upstream', 'Upstream URL', 'nginx-object-upstream')}<input class="input" id="nginx-object-upstream" name="upstream" value="${esc(row?.upstream || '')}" placeholder="http://192.168.1.10:8080"></div>${custom ? '<input type="hidden" name="mode" value="custom">' : '<input type="hidden" name="mode" value="managed">'}</div><div class="site-options" data-managed-settings ${custom ? 'hidden' : ''}>${nginxIngressFields(kind,global,settings)}<details><summary>Advanced proxy settings</summary><div class="form-grid site-policy-grid">${nginxSettingsFields(policyFields.filter(([key]) => key !== 'disable_root'), settings, global.site_defaults)}${nginxSessionPolicyControl(global,settings)}</div>${nginxRoutesField(settings)}</details></div><div class="field" data-custom-settings ${custom ? '' : 'hidden'}>${nginxFieldHeading('content', 'Custom server configuration', 'nginx-object-content')}<textarea class="input" id="nginx-object-content" name="content" style="min-height:320px">${esc(custom ? row.content : '')}</textarea></div>${existing ? '' : `<div class="field">${nginxFieldHeading('enabled', 'Enable after creation', 'nginx-object-enabled')}<input type="checkbox" id="nginx-object-enabled" name="enabled"></div>`}</form>`, async () => {
          try {
            const f = document.getElementById('nginx-object-form'), domain = f.elements.domain.value.trim(), name = kind === 'domain' ? domain : f.elements.name.value.trim();
            const payload = { upstream: f.elements.upstream.value.trim(), server_names: kind === 'subfolder' ? [] : f.elements.server_names.value.split(/\s+/).filter(Boolean) };
            if (f.elements.mode.value === 'custom') payload.content = f.elements.content.value;
            else { if (!f.reportValidity()) return; payload.settings = nginxSiteSettings(f,settings,policyFields) }
            if (!existing) Object.assign(payload, { domain, name, enabled: f.elements.enabled.checked });
            await api(existing ? nginxObjectUrl({ kind, domain, name }) : `/nginx/objects/${kind}`, { method: existing ? 'PUT' : 'POST', body: JSON.stringify(payload) });
            closeEditor(); toast('Site saved'); loadNginx();
          } catch (e) { nginxSiteError(document.getElementById('nginx-object-form'),e.message) }
        });
        const form = document.getElementById('nginx-object-form');
        form.querySelectorAll('.nginx-help-toggle').forEach(button => {
          button.dataset.helpId = button.getAttribute('aria-controls');
          button.setAttribute('aria-controls', 'nginx-help-modal');
          button.setAttribute('aria-haspopup', 'dialog');
          button.removeAttribute('aria-expanded');
        });
        form.nginxKind=kind; form.nginxGlobal=global; form.nginxOriginalSettings=settings; form.nginxFields=policyFields;
        if (!custom) nginxRenderPathRules(form);
        const updateFields = event => {
          nginxUpdateSiteFields(form,kind,global.site_defaults);
          if (!custom) { if (event?.target === form.elements.routes) nginxRenderPathRules(form); nginxScheduleAccessPreview(form); }
        };
        form.addEventListener('input', updateFields);
        form.addEventListener('change', updateFields);
        updateFields();
      } catch (e) { toast(e.message, true) }
    }
    async function nginxObjectAction(kind, domain, name, action) { try { await api(`${nginxObjectUrl({ kind, domain, name })}/${action}`, { method: 'POST' }); toast(`${name}: ${action} complete`); await Promise.all([loadNginxObjects(), loadNginxStatus()]) } catch (e) { toast(e.message, true) } }
    async function deleteNginxObject(kind, domain, name) { const detail = kind === 'domain' ? 'This also deletes all nested subdomain and subfolder definitions. ' : ''; if (!confirm(`${detail}Delete ${kind} ${name}?`)) return; try { await api(nginxObjectUrl({ kind, domain, name }), { method: 'DELETE' }); toast(`${kind} deleted`); loadNginxObjects() } catch (e) { toast(e.message, true) } }
    function nginxCommandResult(command, result) { const action = command === 'test' ? 'Nginx configuration test' : 'Nginx reload'; const detail = (result.stderr || result.stdout || '').trim(); const message = result.success ? `${action} successful` : `${action} failed${detail ? `: ${detail}` : result.code !== null && result.code !== undefined ? ` (exit code ${result.code})` : ': no failure reason returned'}`; showOutput(action, message) }
    async function nginxCommand(command) { try { const r = await api(`/nginx/${command}`, { method: 'POST' }); nginxCommandResult(command, r); await Promise.all([loadNginxStatus(), loadNginxObjects()]) } catch (e) { const action = command === 'test' ? 'Nginx configuration test' : 'Nginx reload'; showOutput(action, `${action} failed: ${e.message}`) } }
    async function loadNginxLogs() { try { const logs = await api('/nginx/logs'), select = document.getElementById('nginx-log-select'), selected = select.value; select.innerHTML = logs.length ? logs.map(log => `<option value="${esc(log.path)}">${esc(log.path)} (${log.size} bytes)</option>`).join('') : '<option value="">No logs found</option>'; if (logs.some(log => log.path === selected)) select.value = selected } catch (e) { toast(e.message, true) } }
    async function viewNginxLog() { const path = document.getElementById('nginx-log-select').value; if (!path) return toast('No nginx log selected', true); try { const result = await api(`/nginx/logs/${nginxPath(path)}`), output = document.getElementById('nginx-log-content'); output.textContent = result.content; requestAnimationFrame(() => { output.scrollTop = output.scrollHeight }) } catch (e) { toast(e.message, true) } }

