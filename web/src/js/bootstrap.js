    const fragmentToken = new URLSearchParams(location.hash.replace(/^#/, '')).get('token');
    if (fragmentToken) { sessionStorage.setItem('maestro-token', fragmentToken); history.replaceState(null, '', location.pathname + location.search); }
    const cookieToken = document.cookie.match(/(?:^|; )(?:maestro-token|router-hub-token)=([^;]*)/)?.[1];
    const CONFIG = { version: __MAESTRO_VERSION_JSON__, apiBase: __MAESTRO_API_BASE_JSON__, token: __MAESTRO_TOKEN_JSON__ || sessionStorage.getItem('maestro-token') || sessionStorage.getItem('router-hub-token') || cookieToken };
    const apiBase = CONFIG.apiBase.replace('{PROTOCOL}', location.protocol).replace('{HOST}', location.hostname).replace(/\/$/, '');
    const state = { view: 'dashboard', nginxObjects: [], certs: [], dehydratedLock: { locked: false, path: '' }, machines: [], machineStatuses: {}, firewall: null, adguard: null, adguardRewrites: [], adguardHosts: [], dnsmasqHosts: [], wireguard: null };
    const tableSorts = { nginx: { key: 'site', dir: 1 }, bans: { key: 'reason', dir: 1 }, rewrites: { key: 'domain', dir: 1 }, hosts: { key: 'ip', dir: 1 }, dnsmasq: { key: 'mac', dir: 1 } };
    let wolStatusTimer;
    let wolStatusRequest;
    let wolStatusGeneration = 0;
    let certPollingTimer;
    let adguardPollingTimer;

    function stopCertificatePolling() { clearInterval(certPollingTimer); certPollingTimer = undefined; }
    function startCertificatePolling() { stopCertificatePolling(); certPollingTimer = setInterval(() => { if (state.view === 'certificates') loadCertificateLock(); }, 15000); }

    function stopAdguardPolling() { clearInterval(adguardPollingTimer); adguardPollingTimer = undefined; }
    function startAdguardPolling() { stopAdguardPolling(); adguardPollingTimer = setInterval(() => { if (state.view === 'adguard') loadAdguardStatusOnly(); }, 15000); }
    const titles = { dashboard: ['Dashboard', 'Router status at a glance'], services: ['Services', 'Manage services'], nginx: ['Nginx', 'Virtual hosts, subdomains and subfolders'], certificates: ['Certificates', "Let's Encrypt issuance and renewal"], wol: ['Wake-on-LAN', 'Maintain and wake LAN machines'], firewall: ['Ban Shield', 'Lightweight hybrid-DFA intrusion blocking'], adguard: ['AdGuard Home', 'Manage AdGuard Home integration'], wireguard: ['WireGuard', 'Manage WireGuard VPN Interface and Peers'] };

