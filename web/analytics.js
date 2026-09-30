    function analyticsNumber(value) { return Number(value || 0).toLocaleString(); }
    function analyticsBytes(value) {
      let bytes = Number(value || 0);
      const units = ['B', 'KB', 'MB', 'GB'];
      let unit = 0;
      while (bytes >= 1024 && unit < units.length - 1) { bytes /= 1024; unit++; }
      return `${bytes.toFixed(unit ? 1 : 0)} ${units[unit]}`;
    }
    function analyticsFindingHtml(finding) {
      const severity = finding.severity === 'critical' ? 'danger' : finding.severity === 'warning' ? 'warn' : '';
      const evidence = (finding.evidence || []).map(item => `<li>${esc(item)}</li>`).join('');
      return `<div class="notice ${severity}" style="margin-bottom:8px"><strong>${esc(finding.title)}</strong> <span class="tag">${esc(finding.category)}</span>${evidence ? `<ul style="margin:6px 0 0 18px">${evidence}</ul>` : ''}${finding.recommendation ? `<div class="hint" style="margin-top:6px">${esc(finding.recommendation)}</div>` : ''}</div>`;
    }
    function renderAnalyticsStatus(statusValue) {
      const summary = statusValue.last_24h || {};
      const metricRows = [
        ['Blocked packets', analyticsNumber((summary.input_packets_blocked || 0) + (summary.forward_packets_blocked || 0)), `${analyticsNumber(summary.input_packets_blocked)} INPUT · ${analyticsNumber(summary.forward_packets_blocked)} FORWARD`],
        ['Blocked bytes', analyticsBytes((summary.input_bytes_blocked || 0) + (summary.forward_bytes_blocked || 0)), `${analyticsBytes(summary.input_bytes_blocked)} INPUT · ${analyticsBytes(summary.forward_bytes_blocked)} FORWARD`],
        ['New bans', analyticsNumber((summary.new_ip_bans || 0) + (summary.new_subnet_bans || 0)), `${analyticsNumber(summary.new_subnet_bans)} subnet · ${analyticsNumber(summary.new_ip_bans)} IP`],
        ['Repeat offenders', analyticsNumber(summary.repeat_offender_bans), `${analyticsNumber(summary.subnet_promotions)} subnet promotions`]
      ];
      document.getElementById('analytics-metrics').innerHTML = metricRows.map(row => `<div class="card metric"><div class="label">${row[0]}</div><div class="value">${row[1]}</div><div class="sub">${row[2]}</div></div>`).join('');
      const findings = summary.findings || statusValue.findings || [];
      document.getElementById('analytics-findings').innerHTML = findings.length ? findings.map(analyticsFindingHtml).join('') : `<div class="notice">${statusValue.enabled ? 'No local warnings in the current window.' : 'Analytics is disabled.'}</div>`;
      const overhead = statusValue.overhead || {};
      document.getElementById('analytics-overhead').innerHTML = [
        ['Processing time', `${((overhead.processing_micros || 0) / 1000).toFixed(1)} ms`],
        ['Estimated memory', analyticsBytes(overhead.estimated_memory_bytes)],
        ['Disk written', analyticsBytes(overhead.disk_bytes_written)],
        ['External commands', analyticsNumber(overhead.external_commands)],
        ['AI requests', `${analyticsNumber(overhead.ai_requests_succeeded)} ok · ${analyticsNumber(overhead.ai_requests_failed)} failed`],
        ['AI bytes sent', analyticsBytes(overhead.ai_bytes_sent)],
        ['Events dropped', analyticsNumber(summary.analytics_event_drops)],
        ['Samples dropped', analyticsNumber(overhead.samples_dropped)],
        ['Last rollup', statusValue.last_rollup_at ? prettyDate(statusValue.last_rollup_at) : 'Not yet'],
        ['Last kernel verify', statusValue.last_kernel_verify_at ? prettyDate(statusValue.last_kernel_verify_at) : 'Not yet']
      ].map(row => `<div style="display:flex;justify-content:space-between;gap:12px;padding:4px 0;border-bottom:1px solid #263742"><span>${row[0]}</span><strong>${row[1]}</strong></div>`).join('');
      const rules = summary.rule_activity || [];
      document.getElementById('analytics-rules-body').innerHTML = rules.length ? rules.slice().sort((a, b) => (b.matches || 0) - (a.matches || 0)).map(rule => `<tr><td><code>${esc(rule.name)}</code></td><td>${analyticsNumber(rule.matches)}</td><td>${analyticsNumber(rule.ban_transitions)}</td></tr>`).join('') : emptyRow(3, 'No rule activity recorded');
    }
    function populateAnalyticsForm(config) {
      const form = document.getElementById('analytics-form');
      if (!form || !config) return;
      for (const name of ['enabled', 'detect_issues', 'collect_kernel_counters', 'collect_event_samples']) form.elements[name].value = String(!!config[name]);
      for (const name of ['sample_interval_seconds', 'kernel_verify_interval_seconds', 'rollup_interval_minutes', 'hourly_retention_days', 'daily_retention_days', 'max_samples_per_hour', 'max_sample_path_bytes', 'max_summary_bytes']) form.elements[name].value = config[name];
      const ai = config.ai || {};
      form.elements.ai_enabled.value = String(!!ai.enabled);
      form.elements.ai_automatic.value = String(!!ai.automatic);
      form.elements.ai_endpoint.value = ai.endpoint || '';
      form.elements.ai_model.value = ai.model || '';
      form.elements.ai_api_key.value = '';
      form.elements.ai_interval_hours.value = ai.interval_hours || 24;
      form.elements.ai_privacy_mode.value = ai.privacy_mode || 'strict';
      form.elements.ai_max_payload_bytes.value = ai.max_payload_bytes || 32768;
      form.elements.ai_max_samples.value = ai.max_samples ?? 50;
      form.elements.ai_max_output_tokens.value = ai.max_output_tokens || 1200;
      form.elements.ai_timeout_seconds.value = ai.timeout_seconds || 30;
      form.elements.ai_additional_headers.value = JSON.stringify(ai.additional_headers || {}, null, 2);
      form.elements.ai_clear_api_key.checked = false;
      document.getElementById('analytics-api-key-state').textContent = ai.api_key_configured ? 'A key is saved; leave blank to keep it.' : 'No key saved.';
      document.getElementById('analytics-ai-run').disabled = !config.enabled || !ai.enabled;
    }
    function renderAnalyticsAi(historyValue) {
      const records = historyValue?.ai || [];
      const el = document.getElementById('analytics-ai-findings');
      if (!records.length) { el.className = 'empty'; el.textContent = 'No AI analysis has been saved.'; return; }
      const record = records[records.length - 1];
      const findings = record.analysis?.findings || [];
      el.className = '';
      el.innerHTML = `<div class="notice"><strong>${esc(record.model)}</strong> · ${prettyDate(record.created_at)}<div style="margin-top:6px">${esc(record.analysis?.summary || '')}</div></div>${findings.map(finding => analyticsFindingHtml({ ...finding, source: 'ai' })).join('')}${(record.analysis?.policy_suggestions || []).length ? `<div class="notice warn"><strong>Policy suggestions for human review</strong><ul>${record.analysis.policy_suggestions.map(item => `<li>${esc(item)}</li>`).join('')}</ul></div>` : ''}`;
    }
    async function loadAnalytics() {
      try {
        const [statusValue, configValue, historyValue] = await Promise.all([api('/analytics/status'), api('/analytics/config'), api('/analytics/history')]);
        renderAnalyticsStatus(statusValue);
        populateAnalyticsForm(configValue);
        renderAnalyticsAi(historyValue);
      } catch (e) { toast(e.message, true); }
    }
    async function saveAnalyticsSettings(event) {
      event.preventDefault();
      const form = event.target;
      let additionalHeaders = {};
      try { additionalHeaders = JSON.parse(form.elements.ai_additional_headers.value || '{}'); }
      catch { return toast('Additional AI headers must be a JSON object', true); }
      if (!additionalHeaders || Array.isArray(additionalHeaders) || typeof additionalHeaders !== 'object') return toast('Additional AI headers must be a JSON object', true);
      const payload = {
        enabled: form.elements.enabled.value === 'true',
        sample_interval_seconds: Number(form.elements.sample_interval_seconds.value),
        kernel_verify_interval_seconds: Number(form.elements.kernel_verify_interval_seconds.value),
        rollup_interval_minutes: Number(form.elements.rollup_interval_minutes.value),
        hourly_retention_days: Number(form.elements.hourly_retention_days.value),
        daily_retention_days: Number(form.elements.daily_retention_days.value),
        detect_issues: form.elements.detect_issues.value === 'true',
        collect_kernel_counters: form.elements.collect_kernel_counters.value === 'true',
        collect_event_samples: form.elements.collect_event_samples.value === 'true',
        max_samples_per_hour: Number(form.elements.max_samples_per_hour.value),
        max_sample_path_bytes: Number(form.elements.max_sample_path_bytes.value),
        max_summary_bytes: Number(form.elements.max_summary_bytes.value),
        ai: {
          enabled: form.elements.ai_enabled.value === 'true',
          automatic: form.elements.ai_automatic.value === 'true',
          endpoint: form.elements.ai_endpoint.value.trim(),
          api_key: form.elements.ai_api_key.value ? form.elements.ai_api_key.value : null,
          clear_api_key: form.elements.ai_clear_api_key.checked,
          model: form.elements.ai_model.value.trim(),
          interval_hours: Number(form.elements.ai_interval_hours.value),
          privacy_mode: 'strict',
          max_payload_bytes: Number(form.elements.ai_max_payload_bytes.value),
          max_samples: Number(form.elements.ai_max_samples.value),
          max_output_tokens: Number(form.elements.ai_max_output_tokens.value),
          timeout_seconds: Number(form.elements.ai_timeout_seconds.value),
          additional_headers: additionalHeaders
        }
      };
      try {
        const saved = await api('/analytics/config', { method: 'PUT', body: JSON.stringify(payload) });
        populateAnalyticsForm(saved);
        toast('Security Analytics settings saved');
        await loadAnalytics();
      } catch (e) { toast(e.message, true); }
    }
    async function previewAnalyticsAi() {
      try { showOutput('Exact privacy-sanitized AI payload', await api('/analytics/ai/preview')); }
      catch (e) { toast(e.message, true); }
    }
    async function runAnalyticsAi() {
      if (!confirm('Send the previewed privacy-sanitized summary to the configured AI endpoint now?')) return;
      try {
        const result = await api('/analytics/ai/analyze', { method: 'POST' });
        showOutput('AI security analysis', result);
        toast('AI analysis completed');
        await loadAnalytics();
      } catch (e) { toast(e.message, true); }
    }
