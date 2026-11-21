    async function loadCertificates() {
      try {
        state.certs = await api('/certificates');
        document.getElementById('certs-body').innerHTML = state.certs.length ? state.certs.map(x => {
          const s = x.spec;
          const expiry = x.exists
            ? `${x.renewal_due ? `<span class="status warn">${x.days_remaining} days</span>` : `<span class="status ok">${x.days_remaining} days</span>`}<div class="muted">${prettyDate(x.expires_at)}</div>`
            : '<span class="status off">Not issued</span>';
          return `<tr><td><strong>${esc(s.name)}</strong><div class="muted">${s.auto_renew ? 'Auto-renew' : 'Manual'}</div></td><td>${s.domains.map(d => `<span class="tag">${esc(d)}</span>`).join('')}</td><td>${esc(s.method)}</td><td>${expiry}</td><td><div class="row-actions"><button class="btn small" onclick="editCertificate('${s.id}')">Edit</button><button class="btn small" onclick="certificateAction('${s.id}','${x.exists ? 'renew' : 'issue'}')">${x.exists ? 'Renew' : 'Issue'}</button><button class="btn small danger" onclick="deleteCertificate('${s.id}')">Delete</button></div></td></tr>`
        }).join('') : emptyRow(5)
      } catch (e) { toast(e.message, true) }
    }
    function editCertificate(id) { const row = state.certs.find(x => x.spec.id === id), s = row ? row.spec : { name: '', domains: [], method: 'http', hook: '', hook_env: {}, staging: false, auto_renew: true }; openEditor(id ? 'Edit certificate' : 'Add certificate', `<form id="cert-form" class="form"><div class="form-grid"><div class="field"><label>Name</label><input class="input" name="name" value="${esc(s.name)}" required></div><div class="field full"><label>Domains, one per line</label><textarea class="input" name="domains">${esc(s.domains.join('\n'))}</textarea></div><div class="field"><label>Challenge</label><select class="input" name="method"><option value="http" ${s.method === 'http' ? 'selected' : ''}>HTTP-01</option><option value="dns" ${s.method === 'dns' ? 'selected' : ''}>DNS-01</option></select></div><div class="field"><label>Hook path</label><input class="input" name="hook" value="${esc(s.hook || '')}" placeholder="/opt/var/lib/maestro/dehydrated/dehydrated-dns01-hook.sh"><span class="hint">Optional for HTTP-01. Leave blank for the default DNS hook in the dehydrated data directory.</span></div><div class="field full"><label>Hook environment, one KEY=value per line</label><textarea class="input" name="hook_env">${esc(Object.entries(s.hook_env || {}).map(([k, v]) => `${k}=${v}`).join('\n'))}</textarea><span class="hint">For example, DUCKDNS_TOKEN=... . Values are stored in the dehydrated config.</span></div><div class="field"><label><input type="checkbox" name="staging" ${s.staging ? 'checked' : ''}> Use Let's Encrypt staging</label></div><div class="field"><label><input type="checkbox" name="auto_renew" ${s.auto_renew ? 'checked' : ''}> Auto renew</label></div></div></form>`, async () => { try { const f = document.getElementById('cert-form'), v = formObject(f), payload = { ...s, name: v.name, domains: jsonLines(v.domains), method: v.method, hook: v.hook || null, hook_env: envObject(v.hook_env), staging: f.elements.staging.checked, auto_renew: f.elements.auto_renew.checked }; await api(id ? `/certificates/${id}` : '/certificates', { method: id ? 'PUT' : 'POST', body: JSON.stringify(payload) }); closeEditor(); loadCertificates() } catch (e) { toast(e.message, true) } }) }
    function certificateErrorMessage(result) {
      const output = (result.stderr || result.stdout || '').trim();
      const detail = output.match(/\["error","detail"\]\s*("(?:[^"\\]|\\.)*")/);
      if (detail) { try { return JSON.parse(detail[1]) } catch { } }
      return output.split(' (result:')[0].trim() || `Command failed${result.code == null ? '' : ` (exit code ${result.code})`}`;
    }
    async function certificateAction(id, action) {
      const certificate = state.certs.find(x => x.spec.id === id)?.spec.name || '';
      state.dehydratedLock = {
        ...state.dehydratedLock,
        status: 'running',
        operation: { certificate, action, status: 'running' }
      };
      applyCertificateLockUi();
      try {
        const p = api(`/certificates/${id}/${action}`, { method: 'POST' });
        setTimeout(() => { if (state.view === 'certificates') loadCertificateLock().catch(e => toast(e.message, true)); }, 500);
        const result = await p;
        if (!result.success) alert(`Certificate ${action} failed: ${certificateErrorMessage(result)}`);
      } catch (e) {
        alert(`Certificate ${action} failed: ${e.message}`);
      } finally {
        await loadCertificatesWithLock();
      }
    }
    async function updateDehydrated() { try { await api('/certificates/dehydrated/update', { method: 'POST' }); await loadCertificatesWithLock() } catch (e) { alert(`Dehydrated update failed: ${e.message}`) } }
    async function deleteCertificate(id) { if (!confirm('Delete only the Maestro definition? Dehydrated config and certificate files remain.')) return; try { await api(`/certificates/${id}`, { method: 'DELETE' }); loadCertificates() } catch (e) { toast(e.message, true) } }

