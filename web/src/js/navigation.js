    // This manifest mirrors GET /api/modules, so offline navigation still works
    // when the API is initially unreachable or an older backend is being upgraded.
    const RH_FALLBACK_MODULES = [{"id":"services","availability":"ready","ui":[{"tab":"services","tab_label":"Services","tab_order":10,"section":"services","section_label":"Services","section_order":10,"dashboard_widgets":["services"]}]},{"id":"nginx","availability":"ready","ui":[{"tab":"web","tab_label":"Web","tab_order":20,"section":"nginx","section_label":"Nginx","section_order":10,"dashboard_widgets":["nginx"]}]},{"id":"certificates","availability":"ready","ui":[{"tab":"web","tab_label":"Web","tab_order":20,"section":"certificates","section_label":"Certificates","section_order":20,"dashboard_widgets":["certificates"]}]},{"id":"ban_shield","availability":"ready","ui":[{"tab":"security","tab_label":"Security","tab_order":30,"section":"firewall","section_label":"Ban Shield","section_order":10,"dashboard_widgets":["active_bans"]}]},{"id":"wol","availability":"ready","ui":[{"tab":"network","tab_label":"Network","tab_order":40,"section":"wol","section_label":"Wake-on-LAN","section_order":10,"dashboard_widgets":[]}]},{"id":"adguard","availability":"ready","ui":[{"tab":"network","tab_label":"Network","tab_order":40,"section":"adguard","section_label":"AdGuard Home","section_order":20,"dashboard_widgets":[]}]},{"id":"wireguard","availability":"ready","ui":[{"tab":"network","tab_label":"Network","tab_order":40,"section":"wireguard","section_label":"WireGuard","section_order":30,"dashboard_widgets":[]}]}];
    let rhModuleCatalog = RH_FALLBACK_MODULES;
    function rhGroupFor(view) {
      if (view === 'dashboard') return 'dashboard';
      for (const module of rhModuleCatalog) {
        for (const section of module.ui || []) if (section.section === view) return section.tab;
      }
      return view;
    }
    function rhNavigationGroups() {
      const groups = new Map([['dashboard', { id: 'dashboard', label: 'Dashboard', order: 0,
        sections: [{ id: 'dashboard', label: 'Dashboard', order: 0 }] }]]);
      for (const module of rhModuleCatalog) {
        if (module.availability === 'unsupported') continue;
        for (const section of module.ui || []) {
          if (!groups.has(section.tab)) groups.set(section.tab, {
            id: section.tab, label: section.tab_label, order: section.tab_order, sections: []
          });
          const group = groups.get(section.tab);
          if (!group.sections.some(item => item.id === section.section)) group.sections.push({
            id: section.section, label: section.section_label, order: section.section_order
          });
        }
      }
      for (const group of groups.values()) group.sections.sort((a, b) => a.order - b.order || a.id.localeCompare(b.id));
      return [...groups.values()].sort((a, b) => a.order - b.order || a.id.localeCompare(b.id));
    }
    function rhNavigationMarkup(groups, sidebar) {
      return groups.map(group => {
        const first = group.sections[0], subnav = group.sections.length > 1;
        const title = esc(group.label) + (subnav && !sidebar ? ' ▾' : '');
        const primary = '<div class="rh-tab tab" role="tab" tabindex="0" data-group="' +
          esc(group.id) + '" data-view="' + esc(first.id) + '"' +
          (sidebar ? ' data-sidebar' : '') + '>' + title + '</div>';
        const sections = subnav ? '<div class="rh-group-menu" role="group" aria-label="' +
          esc(group.label) + ' sections">' + group.sections.map(section =>
            '<button type="button" data-view="' + esc(section.id) + '"' +
            (sidebar ? ' data-sidebar' : '') + '>' + esc(section.label) + '</button>').join('') + '</div>' : '';
        return '<div class="rh-group">' + primary + sections + '</div>';
      }).join('');
    }
    function rhComposeNavigation() {
      const groups = rhNavigationGroups();
      const nav = document.getElementById('rh-nav'), sidebar = document.getElementById('rh-sidebar');
      if (nav) nav.innerHTML = rhNavigationMarkup(groups, false);
      if (sidebar) sidebar.innerHTML = rhNavigationMarkup(groups, true);
      RH_TAB_MARKUP = nav ? nav.innerHTML : '';
      RH_TAB_COUNT = groups.length;
      const asusTabs = document.getElementById('tabMenu');
      if (asusTabs) rhInstallAsusTabs(asusTabs);
      rhApplyView();
      rhSyncSidebarActive(state.view);
    }
    async function rhLoadModules() {
      try {
        const response = await api('/modules');
        if (!Array.isArray(response.modules)) return;
        rhModuleCatalog = response.modules;
        if (!rhNavigationGroups().some(g => g.sections.some(s => s.id === state.view))) {
          state.view = 'dashboard';
        }
        rhComposeNavigation();
        if (state.view === 'dashboard') loadDashboard();
      } catch (_) {
        // Keep existing offline navigation when discovery is unavailable.
      }
    }
    function rhSelectView(view) {
      const tab = (document.getElementById('tabMenu') || document.getElementById('rh-nav'))
        ?.querySelector('[data-view="' + view + '"]');
      if (tab) tab.click();
    }
    const requestedTab = new URLSearchParams(location.search).get('tab');
    if (requestedTab && Object.prototype.hasOwnProperty.call(titles, requestedTab)) state.view = requestedTab;
    function esc(v = '') { return String(v).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])) }
    function toast(message, error = false) { const el = document.getElementById('toast'); el.textContent = message; el.className = 'toast show' + (error ? ' error' : ''); clearTimeout(el.timer); el.timer = setTimeout(() => el.className = 'toast', 3600) }
    function setConnection(ok, label) { const status = document.getElementById('connection-status'); document.getElementById('connection').textContent = label || (ok ? 'Connected' : 'Offline'); status.classList.toggle('ok', ok); status.classList.toggle('bad', !ok) }
    async function api(path, options = {}) { const headers = { ...(options.headers || {}), Authorization: `Bearer ${CONFIG.token}` }; if (options.body && !headers['Content-Type']) headers['Content-Type'] = 'application/json'; if (options.body && (path === '/nginx/objects/domain' || path.startsWith('/nginx/objects/domain/'))) { try { const body = JSON.parse(options.body); const upstream = document.querySelector('#nginx-object-form [name=upstream], #nginx-object-edit [name=upstream]')?.value?.trim() || ''; body.upstream = upstream; options = { ...options, body: JSON.stringify(body) } } catch { } } let response; try { response = await fetch(apiBase + '/api' + path, { ...options, headers }) } catch (error) { setConnection(false); throw error } setConnection(response.ok, response.ok ? 'Connected' : 'API error'); if (response.status === 401 && __MAESTRO_TOKEN_JSON__ === null) { const t = prompt('Please enter your Maestro token:'); if (t) { document.cookie = `maestro-token=${t}; path=/; max-age=31536000`; CONFIG.token = t; return api(path, options); } } if (!response.ok) { let body = {}; try { body = await response.json() } catch { } throw new Error(body.error || body.message || `${response.status} ${response.statusText}`) } const type = response.headers.get('content-type') || ''; return type.includes('json') ? response.json() : response.text() }
    function showOutput(title, value) { const output = document.getElementById('log-content'); document.getElementById('log-title').textContent = title; output.textContent = typeof value === 'string' ? value : JSON.stringify(value, null, 2); document.getElementById('log-modal').showModal(); requestAnimationFrame(() => { output.scrollTop = output.scrollHeight }) }
    function updateSortHeaders(table) { const sort = tableSorts[table]; document.querySelectorAll(`[data-sort-table="${table}"]`).forEach(button => { const active = button.dataset.sortKey === sort.key; button.setAttribute('aria-sort', active ? (sort.dir === 1 ? 'ascending' : 'descending') : 'none'); button.querySelector('.table-sort-indicator').textContent = active ? (sort.dir === 1 ? '↑' : '↓') : '↕' }) }
    function sortValue(value) { return value == null ? '' : String(value) }
    function compareTableValues(a, b, key) { if (key === 'expires') return (new Date(a.expires_at || 0) - new Date(b.expires_at || 0)); if (key === 'port') return (Number(a.port || 0) - Number(b.port || 0)); if (key === 'state') return sortValue(a.state).localeCompare(sortValue(b.state)); const av = key === 'site' ? (a.display_name || a.name) : key === 'hostnames' ? (a.hostnames || []).join(' ') : a[key]; return sortValue(av).localeCompare(sortValue(key === 'site' ? (b.display_name || b.name) : key === 'hostnames' ? (b.hostnames || []).join(' ') : b[key]), undefined, { numeric: true, sensitivity: 'base' }) }
    function sortTable(table, key) { const sort = tableSorts[table]; if (sort.key === key) sort.dir *= -1; else { sort.key = key; sort.dir = 1 } if (table === 'nginx') loadNginxObjects(); else if (table === 'bans') showActiveBans(); else if (table === 'rewrites') { state.adguardRewrites.sort((a, b) => sort.dir * compareTableValues(a, b, key)); renderAdguardRewrites() } else if (table === 'hosts') { state.adguardHosts.sort((a, b) => sort.dir * compareTableValues(a, b, key)); renderAdguardHosts() } else if (table === 'dnsmasq') { state.dnsmasqHosts.sort((a, b) => sort.dir * compareTableValues(a, b, key)); renderDnsmasqHosts() } updateSortHeaders(table) }
    function emptyRow(cols, text = 'No items configured') { return `<tr><td colspan="${cols}" class="empty">${esc(text)}</td></tr>` }
    function status(ok, on = 'Running', off = 'Stopped') { return `<span class="status ${ok ? 'ok' : 'off'}">${ok ? on : off}</span>` }
    function openEditor(title, html, save) { const ed = document.getElementById('editor'); ed.classList.toggle('nginx-site-editor', html.includes('id="nginx-object-form"')); ed.classList.toggle('nginx-settings-editor', html.includes('id="nginx-settings-form"')); document.getElementById('editor-title').textContent = title; document.getElementById('editor-body').innerHTML = html; document.getElementById('editor-save').onclick = save; ed.showModal() }
    function closeEditor() { const ed = document.getElementById('editor'); ed.close(); ed.classList.remove('nginx-site-editor', 'nginx-settings-editor') }
    function formObject(form) { return Object.fromEntries(new FormData(form).entries()) }
    function jsonLines(value) { return (value || '').split(/\r?\n/).map(v => v.trim()).filter(Boolean) }
    function envObject(value) { const result = {}; for (const line of jsonLines(value)) { const split = line.indexOf('='); if (split <= 0) throw new Error('Hook environment entries must use KEY=value'); result[line.slice(0, split).trim()] = line.slice(split + 1) } return result }
    function prettyDate(value) { if (!value) return 'Unknown'; return new Date(value).toLocaleString() }
    function refreshCurrent() { ({ dashboard: loadDashboard, services: loadServices, nginx: loadNginx, certificates: loadCertificatesWithLock, wol: loadWol, firewall: loadFirewall, adguard: loadAdguard, wireguard: loadWireguard }[state.view] || (() => { }))() }

    // Tab navigation: hook into ASUS initial() when embedded, else run immediately.
    // ASUS renders the menu twice while its asynchronous menuTree module loads, so
    // keep canonical markup and restore our tabs if the firmware replaces them.
    let RH_TAB_MARKUP = document.getElementById('rh-nav')?.innerHTML || '';
    let RH_TAB_COUNT = Object.keys(titles).length;
    let rhTabObserver;
    function rhInstallAsusTabs(asusTabs) {
      asusTabs.innerHTML = RH_TAB_MARKUP;
      asusTabs.classList.add('rh-tabs');
      asusTabs.querySelectorAll('[data-view]').forEach(tab => {
        tab.classList.toggle('tabClicked', (tab.dataset.view === state.view || (tab.classList.contains('rh-tab') && tab.dataset.group === rhGroupFor(state.view))));
        tab.classList.toggle('tab', !(tab.dataset.view === state.view || (tab.classList.contains('rh-tab') && tab.dataset.group === rhGroupFor(state.view))));
      });
    }
    function rhApplyView() {
      document.querySelectorAll('.view').forEach(view => view.classList.toggle('active', view.id === 'view-' + state.view));
      document.getElementById('page-title').textContent = titles[state.view][0];
      document.getElementById('page-subtitle').textContent = titles[state.view][1];
      document.querySelectorAll('[data-view]').forEach(tab => {
        const selected = tab.dataset.view === state.view || (tab.classList.contains('rh-tab') && tab.dataset.group === rhGroupFor(state.view));
        tab.classList.toggle('tabClicked', selected);
        tab.classList.toggle('tab', !selected);
      });
    }
    function rhToggleSidebar() {
      const sidebar = document.getElementById('rh-sidebar');
      const btn = document.getElementById('rh-sidebar-toggle');
      if (!sidebar || !btn) return;
      const open = sidebar.classList.toggle('open');
      btn.classList.toggle('open', open);
      btn.setAttribute('aria-expanded', open);
    }

    function rhSyncSidebarActive(view) {
      const sidebar = document.getElementById('rh-sidebar');
      if (!sidebar) return;
      sidebar.querySelectorAll('[data-view]').forEach(x => {
        x.classList.toggle('tabClicked', (x.dataset.view === view || (x.classList.contains('rh-tab') && x.dataset.group === rhGroupFor(view))));
        x.classList.toggle('tab', !(x.dataset.view === view || (x.classList.contains('rh-tab') && x.dataset.group === rhGroupFor(view))));
      });
      const label = document.getElementById('rh-sidebar-label');
      const activeTab = sidebar.querySelector(`[data-view="${view}"]`);
      if (label && activeTab) label.textContent = activeTab.textContent.trim();
    }

    // Group headers use div[role=tab] for ASUS compatibility; make their
    // advertised keyboard focusability functional. Subsection buttons already
    // receive native keyboard activation and must not be clicked twice.
    function rhBindKeyboardNavigation(root) {
      if (!root || root.dataset.rhKeyboardBound) return;
      root.dataset.rhKeyboardBound = 'true';
      root.addEventListener('keydown', event => {
        const tab = event.target.closest('.rh-tab[data-view]');
        if (!tab || tab.tagName !== 'DIV' || !root.contains(tab)) return;
        if (event.key !== 'Enter' && event.key !== ' ') return;
        event.preventDefault();
        tab.click();
      });
    }

    function rhSetupTabs() {
      const asusTabs = document.getElementById('tabMenu');
      const ownNav = document.getElementById('rh-nav');
      if (asusTabs && ownNav) {
        rhInstallAsusTabs(asusTabs);
        ownNav.style.display = 'none';
        if (!rhTabObserver) {
          rhTabObserver = new MutationObserver(() => {
            if (asusTabs.querySelectorAll('.rh-tab').length !== RH_TAB_COUNT) rhInstallAsusTabs(asusTabs);
          });
          rhTabObserver.observe(asusTabs, { childList: true });
        }
      }
      const model = document.getElementById('router-model');
      if (model && typeof based_modelid === 'string' && based_modelid.trim()) model.textContent = based_modelid;
      const navRoot = asusTabs || ownNav;
      if (!navRoot) return;

      // Wire sidebar nav (mobile only, standalone)
      const sidebar = document.getElementById('rh-sidebar');
      rhBindKeyboardNavigation(navRoot);
      rhBindKeyboardNavigation(sidebar);
      if (sidebar && !sidebar.dataset.rhTabsBound) {
        sidebar.dataset.rhTabsBound = 'true';
        sidebar.addEventListener('click', event => {
          const tab = event.target.closest('[data-view]'); if (!tab) return;
          // Sync sidebar active state
          rhSyncSidebarActive(tab.dataset.view);
          // Close sidebar after selection
          const btn = document.getElementById('rh-sidebar-toggle');
          sidebar.classList.remove('open');
          if (btn) { btn.classList.remove('open'); btn.setAttribute('aria-expanded', 'false'); }
          // Sync horizontal nav active state too
          navRoot.querySelectorAll('[data-view]').forEach(x => {
            x.classList.toggle('tabClicked', (x.dataset.view === tab.dataset.view || (x.classList.contains('rh-tab') && x.dataset.group === rhGroupFor(tab.dataset.view))));
            x.classList.toggle('tab', !(x.dataset.view === tab.dataset.view || (x.classList.contains('rh-tab') && x.dataset.group === rhGroupFor(tab.dataset.view))));
          });
          document.querySelectorAll('.view').forEach(x => x.classList.remove('active'));
          const previousView = state.view;
          state.view = tab.dataset.view;
          const url = new URL(location.href);
          url.searchParams.set('tab', state.view);
          history.replaceState(null, '', url);
          if (previousView === 'wol' && state.view !== 'wol') stopWolStatusPolling();
          if (previousView === 'certificates' && state.view !== 'certificates') stopCertificatePolling();
          if (previousView === 'adguard' && state.view !== 'adguard') stopAdguardPolling();
          document.getElementById('view-' + state.view).classList.add('active');
          document.getElementById('page-title').textContent = titles[state.view][0];
          document.getElementById('page-subtitle').textContent = titles[state.view][1];
          refreshCurrent();
        });
      }

      if (!navRoot.dataset.rhTabsBound) {
        navRoot.dataset.rhTabsBound = 'true';
        navRoot.addEventListener('click', event => {
          const tab = event.target.closest('[data-view]'); if (!tab) return;
          navRoot.querySelectorAll('[data-view]').forEach(x => {
            const selected = x.dataset.view === tab.dataset.view ||
              (x.classList.contains('rh-tab') && x.dataset.group === rhGroupFor(tab.dataset.view));
            x.classList.toggle('tabClicked', selected);
            x.classList.toggle('tab', !selected);
          });
          // Keep sidebar in sync when horizontal tabs are used
          rhSyncSidebarActive(tab.dataset.view);
          document.querySelectorAll('.view').forEach(x => x.classList.remove('active'));
          const previousView = state.view;
          state.view = tab.dataset.view;
          const url = new URL(location.href);
          url.searchParams.set('tab', state.view);
          history.replaceState(null, '', url);
          if (previousView === 'wol' && state.view !== 'wol') stopWolStatusPolling();
          if (previousView === 'certificates' && state.view !== 'certificates') stopCertificatePolling();
          if (previousView === 'adguard' && state.view !== 'adguard') stopAdguardPolling();
          document.getElementById('view-' + state.view).classList.add('active');
          document.getElementById('page-title').textContent = titles[state.view][0];
          document.getElementById('page-subtitle').textContent = titles[state.view][1];
          refreshCurrent();
        });
      }
      rhApplyView();
      rhSyncSidebarActive(state.view);
    }
    rhComposeNavigation();
    // Install before the ASUS window load handler so the observer sees both menu
    // renders. Keep the initial() hook as a fallback even if ASUS setup throws.
    if (typeof initial === 'function') {
      const _origInitial = initial;
      window.initial = function () { try { return _origInitial() } finally { rhSetupTabs() } };
    }
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', rhSetupTabs);
    } else {
      rhSetupTabs();
    }


