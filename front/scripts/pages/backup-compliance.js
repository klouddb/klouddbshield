import {
  getBackupComplianceSummary,
  getBackupComplianceHistory,
  getBackupCompliancePolicy,
  putBackupCompliancePolicy,
} from '../api/services/backup-compliance.js';

let latestSummary = null;
let selectedServer = 'all';
let selectedPolicyDays = new Set();

function browserTimezone() {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || '';
  } catch {
    return '';
  }
}

function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

function formatTime(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString();
}

function formatDuration(sec) {
  if (sec == null || sec === '' || Number.isNaN(Number(sec))) return '—';
  const n = Number(sec);
  if (n < 60) return `${n} sec`;
  if (n < 3600) return `${Math.round(n / 60)} min`;
  return `${(n / 3600).toFixed(1)} hr`;
}

function statusBadge(status) {
  const s = (status || '').toLowerCase();
  if (s === 'failed' || s === 'fail' || s === 'error' || s === 'interrupted' || s === 'auth_failed') {
    const label = s === 'auth_failed' ? 'Auth Failed' : s === 'interrupted' ? 'Interrupted' : 'Failed';
    return `<span class="badge badge-danger">${label}</span>`;
  }
  if (s === 'running') {
    return `<span class="badge badge-info">Running</span>`;
  }
  return `<span class="badge badge-success">Success</span>`;
}

function complianceBadge(c) {
  const s = (c || '').toLowerCase();
  if (s === 'unauthorized') {
    return `<span class="badge badge-warning">Unauthorized</span>`;
  }
  return `<span class="badge badge-success">Authorized</span>`;
}

function renderBarChart(el, items, colorClass) {
  if (!el) return;
  if (!items.length) {
    el.innerHTML = '<p class="bc-bar-empty">No data</p>';
    return;
  }
  const max = Math.max(...items.map((i) => i.value), 1);
  el.innerHTML = items
    .map((item) => {
      const pct = Math.max(8, Math.round((item.value / max) * 100));
      const cls = item.colorClass || colorClass || 'secure';
      return `<div class="bc-bar-group">
        <div class="bc-bar-track">
          <div class="bc-bar-fill ${cls}" style="height:${pct}%;" title="${item.label}: ${item.value}"></div>
        </div>
        <div class="bc-bar-label">${item.label}</div>
        <div class="bc-bar-value">${item.value}</div>
      </div>`;
    })
    .join('');
}

function formatScanTime(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, {
    day: 'numeric',
    month: 'short',
    year: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
    hour12: true,
  });
}

function formatAllowedDays(days) {
  if (!Array.isArray(days) || !days.length) return '';
  const short = {
    sunday: 'Sun',
    sun: 'Sun',
    monday: 'Mon',
    mon: 'Mon',
    tuesday: 'Tue',
    tue: 'Tue',
    tues: 'Tue',
    wednesday: 'Wed',
    wed: 'Wed',
    thursday: 'Thu',
    thu: 'Thu',
    thur: 'Thu',
    thurs: 'Thu',
    friday: 'Fri',
    fri: 'Fri',
    saturday: 'Sat',
    sat: 'Sat',
  };
  return days
    .map((d) => {
      const key = String(d || '').trim().toLowerCase();
      return short[key] || d;
    })
    .filter(Boolean)
    .join(', ');
}

function formatPolicyWindow(start, end, days, source) {
  const s = (start || '').trim();
  const e = (end || '').trim();
  const dayPart = formatAllowedDays(days);
  const timePart = !s && !e ? '' : `${s || '?'} – ${e || '?'}`;
  let base = 'Not configured';
  if (timePart && dayPart) base = `${dayPart} ${timePart}`;
  else if (timePart || dayPart) base = timePart || dayPart;
  if (source === 'collector_config') return `${base} (config)`;
  if (source === 'dashboard') return `${base} (dashboard)`;
  return base;
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function activeScope() {
  if (!selectedServer || selectedServer === 'all') return null;
  return latestSummary?.hosts?.find((h) => h.host === selectedServer) || null;
}

function updateScopeBar() {
  const bar = document.getElementById('bc-scope-bar');
  const label = document.getElementById('bc-scope-label-text');
  const clearBtn = document.getElementById('bc-scope-clear');
  if (!bar || !label) return;

  const hosts = latestSummary?.hosts || [];
  if (!latestSummary?.available || hosts.length === 0) {
    bar.hidden = true;
    return;
  }
  bar.hidden = false;
  if (selectedServer && selectedServer !== 'all') {
    label.textContent = selectedServer;
    if (clearBtn) clearBtn.hidden = false;
  } else {
    label.textContent = `All servers (${hosts.length})`;
    if (clearBtn) clearBtn.hidden = true;
  }
}

function updateServerFilterOptions(hosts) {
  const sel = document.getElementById('bc-filter-server');
  if (!sel) return;
  const current = selectedServer || 'all';
  sel.innerHTML = `<option value="all">All servers</option>${(hosts || [])
    .map((h) => `<option value="${escapeHtml(h.host)}">${escapeHtml(h.host)}</option>`)
    .join('')}`;
  sel.value = [...sel.options].some((o) => o.value === current) ? current : 'all';
  selectedServer = sel.value;
}

function renderServersTable(hosts) {
  const body = document.getElementById('bc-servers-body');
  const empty = document.getElementById('bc-meta-empty');
  const hint = document.getElementById('bc-servers-hint');
  if (!body) return;

  if (!hosts?.length) {
    body.innerHTML = '';
    if (empty) {
      empty.hidden = false;
      empty.textContent = latestSummary?.message || 'No backup compliance data yet.';
    }
    if (hint) hint.hidden = true;
    return;
  }

  if (empty) empty.hidden = true;
  if (hint) hint.hidden = false;

  body.innerHTML = hosts
    .map((h) => {
      const active = selectedServer === h.host ? ' class="bc-server-row is-active"' : ' class="bc-server-row"';
      return `<tr${active} data-server="${escapeHtml(h.host)}" tabindex="0" role="button" title="Focus this server">
      <td><strong>${escapeHtml(h.host)}</strong></td>
      <td>${escapeHtml(formatPolicyWindow(h.allowed_start, h.allowed_end, h.allowed_days, h.policy_source))}</td>
      <td>${escapeHtml(formatScanTime(h.scanned_at))}</td>
      <td>${h.total ?? 0}</td>
      <td class="success">${h.success ?? 0}</td>
      <td class="danger">${h.failed ?? 0}</td>
      <td class="warning">${h.unauthorized ?? 0}</td>
    </tr>`;
    })
    .join('');
}

function updateStatsAndCharts() {
  const hosts = latestSummary?.hosts || [];
  const scope = activeScope();
  const scopeLabel = scope ? scope.host : 'Fleet';

  setText('bc-stat-servers', hosts.length);
  if (scope) {
    setText('bc-stat-total', scope.total ?? 0);
    setText('bc-stat-success', scope.success ?? 0);
    setText('bc-stat-failed', scope.failed ?? 0);
    setText('bc-stat-unauthorized', scope.unauthorized ?? 0);
  } else {
    setText('bc-stat-total', latestSummary?.total_backups ?? 0);
    setText('bc-stat-success', latestSummary?.success ?? 0);
    setText('bc-stat-failed', latestSummary?.failed ?? 0);
    setText('bc-stat-unauthorized', latestSummary?.unauthorized ?? 0);
  }

  setText('bc-chart-scope-status', `· ${scopeLabel}`);
  setText('bc-chart-scope-type', `· ${scopeLabel}`);

  const success = scope ? scope.success ?? 0 : latestSummary?.success ?? 0;
  const failed = scope ? scope.failed ?? 0 : latestSummary?.failed ?? 0;
  renderBarChart(document.getElementById('bc-chart-status'), [
    { label: 'Success', value: success, colorClass: 'secure' },
    { label: 'Failed', value: failed, colorClass: 'trust' },
  ]);

  const byType = scope ? scope.by_type || {} : latestSummary?.by_type || {};
  const typeItems = ['pg_dump', 'pg_dumpall', 'pg_basebackup', 'pgbackrest'].map((t) => ({
    label: t,
    value: byType[t] || 0,
    colorClass: 'user',
  }));
  renderBarChart(document.getElementById('bc-chart-type'), typeItems);
}

function updateSummary(summary) {
  latestSummary = summary;
  if (!summary?.available) {
    selectedServer = 'all';
  }
  updateServerFilterOptions(summary?.hosts || []);
  updateScopeBar();
  renderServersTable(summary?.hosts || []);
  updateStatsAndCharts();
}

function renderHistory(rows) {
  const body = document.getElementById('bc-history-body');
  if (!body) return;
  if (!rows?.length) {
    body.innerHTML = '<tr><td colspan="9" style="color:var(--muted);">No backups match the current filters.</td></tr>';
    return;
  }
  body.innerHTML = rows
    .map(
      (r) => `<tr>
      <td>${formatTime(r.start_time)}</td>
      <td>${escapeHtml(r.server || '—')}</td>
      <td>${escapeHtml(r.database || '—')}</td>
      <td>${escapeHtml(r.backup_type || '—')}</td>
      <td>${escapeHtml(r.user || '—')}</td>
      <td>${escapeHtml(r.client_addr || '—')}</td>
      <td>${formatDuration(r.duration_seconds)}</td>
      <td class="bc-col-status" title="${escapeHtml(r.error_message || '')}">${statusBadge(r.status)}</td>
      <td class="bc-col-compliance">${complianceBadge(r.compliance_status)}</td>
    </tr>`
    )
    .join('');
}

function renderUnauthorized(rows) {
  const body = document.getElementById('bc-unauthorized-body');
  if (!body) return;
  if (!rows?.length) {
    body.innerHTML = '<tr><td colspan="6" style="color:var(--muted);">No unauthorized backup attempts.</td></tr>';
    return;
  }
  body.innerHTML = rows
    .map((r) => {
      const window = formatPolicyWindow(r.allowed_start, r.allowed_end, r.allowed_days, r.policy_source);
      return `<tr>
      <td>${formatTime(r.start_time)}</td>
      <td>${escapeHtml(r.user || '—')}</td>
      <td>${escapeHtml(r.database || '—')}</td>
      <td>${escapeHtml(r.backup_type || r.application_name || '—')}</td>
      <td>${escapeHtml(r.server || '—')}</td>
      <td>${escapeHtml(window === 'Not configured' ? '—' : window)}</td>
    </tr>`;
    })
    .join('');
}

function currentFilters() {
  const date = document.getElementById('bc-filter-date')?.value || 'last_7_days';
  const serverSel = document.getElementById('bc-filter-server')?.value || 'all';
  selectedServer = serverSel;
  const filters = {
    date,
    server: serverSel,
    backup_type: document.getElementById('bc-filter-type')?.value || 'all',
    status: document.getElementById('bc-filter-status')?.value || 'all',
  };
  if (date === 'custom') {
    filters.from = document.getElementById('bc-filter-from')?.value || '';
    filters.to = document.getElementById('bc-filter-to')?.value || '';
  }
  return filters;
}

async function selectServer(server) {
  selectedServer = server || 'all';
  const sel = document.getElementById('bc-filter-server');
  if (sel) sel.value = selectedServer;
  updateScopeBar();
  renderServersTable(latestSummary?.hosts || []);
  updateStatsAndCharts();
  await loadHistoryOnly();
}

async function loadHistoryOnly() {
  const body = document.getElementById('bc-history-body');
  if (body) {
    body.innerHTML = '<tr><td colspan="9" style="color:var(--muted);">Loading…</td></tr>';
  }
  try {
    const history = await getBackupComplianceHistory(currentFilters());
    renderHistory(history?.backups || []);
    renderUnauthorized(history?.unauthorized || []);
  } catch (err) {
    if (body) {
      body.innerHTML = `<tr><td colspan="9" style="color:var(--danger);">${escapeHtml(err.message)}</td></tr>`;
    }
  }
}

async function loadPage() {
  const body = document.getElementById('bc-history-body');
  const serversBody = document.getElementById('bc-servers-body');
  if (body) {
    body.innerHTML = '<tr><td colspan="9" style="color:var(--muted);">Loading…</td></tr>';
  }
  if (serversBody) {
    serversBody.innerHTML = '<tr><td colspan="7" style="color:var(--muted);">Loading…</td></tr>';
  }
  try {
    const [summary, history] = await Promise.all([
      getBackupComplianceSummary(),
      getBackupComplianceHistory(currentFilters()),
    ]);
    updateSummary(summary);
    renderHistory(history?.backups || []);
    renderUnauthorized(history?.unauthorized || []);
  } catch (err) {
    if (body) {
      body.innerHTML = `<tr><td colspan="9" style="color:var(--danger);">${escapeHtml(err.message)}</td></tr>`;
    }
    if (serversBody) {
      serversBody.innerHTML = `<tr><td colspan="7" style="color:var(--danger);">${escapeHtml(err.message)}</td></tr>`;
    }
  }
}

function syncDayChips() {
  document.querySelectorAll('#bc-policy-days .bc-day-chip').forEach((btn) => {
    const day = btn.getAttribute('data-day');
    btn.classList.toggle('is-active', selectedPolicyDays.has(day));
    btn.setAttribute('aria-pressed', selectedPolicyDays.has(day) ? 'true' : 'false');
  });
}

function applyPolicyToForm(policy) {
  const start = document.getElementById('bc-policy-start');
  const end = document.getElementById('bc-policy-end');
  const meta = document.getElementById('bc-policy-meta');
  if (start) start.value = (policy?.allowed_start || '').slice(0, 5);
  if (end) end.value = (policy?.allowed_end || '').slice(0, 5);
  selectedPolicyDays = new Set(
    (policy?.allowed_days || []).map((d) => String(d).trim().toLowerCase()).filter(Boolean)
  );
  syncDayChips();
  if (meta) {
    if (policy?.configured && policy?.updated_at) {
      meta.hidden = false;
      meta.textContent = `Saved on main-server · updated ${formatTime(policy.updated_at)}`;
    } else if (policy?.configured) {
      meta.hidden = false;
      meta.textContent = 'Saved on main-server';
    } else {
      meta.hidden = false;
      meta.textContent = 'No dashboard window saved yet — collector config will be used when set.';
    }
  }
}

async function loadPolicyForm() {
  try {
    const policy = await getBackupCompliancePolicy();
    applyPolicyToForm(policy);
  } catch (err) {
    const meta = document.getElementById('bc-policy-meta');
    if (meta) {
      meta.hidden = false;
      meta.textContent = `Could not load policy: ${err.message}`;
    }
  }
}

async function savePolicyForm() {
  const start = document.getElementById('bc-policy-start')?.value || '';
  const end = document.getElementById('bc-policy-end')?.value || '';
  const btn = document.getElementById('bc-policy-save');
  const meta = document.getElementById('bc-policy-meta');
  if (btn) {
    btn.disabled = true;
    btn.textContent = 'Saving…';
  }
  try {
    const policy = await putBackupCompliancePolicy({
      allowed_start: start,
      allowed_end: end,
      allowed_days: [...selectedPolicyDays],
      timezone: browserTimezone(),
    });
    applyPolicyToForm(policy);
    if (meta) {
      meta.hidden = false;
      meta.textContent = `Saved on main-server · updated ${formatTime(policy.updated_at)}`;
    }
    await loadPage();
  } catch (err) {
    if (meta) {
      meta.hidden = false;
      meta.textContent = `Save failed: ${err.message}`;
    }
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = 'Save Window';
    }
  }
}

function bindPolicyForm() {
  const days = document.getElementById('bc-policy-days');
  if (days && !days.dataset.bound) {
    days.dataset.bound = '1';
    days.addEventListener('click', (e) => {
      const btn = e.target.closest('.bc-day-chip');
      if (!btn) return;
      const day = btn.getAttribute('data-day');
      if (!day) return;
      if (selectedPolicyDays.has(day)) selectedPolicyDays.delete(day);
      else selectedPolicyDays.add(day);
      syncDayChips();
    });
  }
  const save = document.getElementById('bc-policy-save');
  if (save && !save.dataset.bound) {
    save.dataset.bound = '1';
    save.addEventListener('click', (e) => {
      e.preventDefault();
      void savePolicyForm();
    });
  }
  const form = document.getElementById('bc-policy-form');
  if (form && !form.dataset.bound) {
    form.dataset.bound = '1';
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      void savePolicyForm();
    });
  }
}

function bindFilters() {
  const dateSel = document.getElementById('bc-filter-date');
  const customFrom = document.getElementById('bc-custom-range');
  const customTo = document.getElementById('bc-custom-range-to');
  if (dateSel && !dateSel.dataset.bound) {
    dateSel.dataset.bound = '1';
    dateSel.addEventListener('change', () => {
      const show = dateSel.value === 'custom';
      if (customFrom) customFrom.hidden = !show;
      if (customTo) customTo.hidden = !show;
    });
  }

  const serverSel = document.getElementById('bc-filter-server');
  if (serverSel && !serverSel.dataset.bound) {
    serverSel.dataset.bound = '1';
    serverSel.addEventListener('change', () => {
      void selectServer(serverSel.value);
    });
  }

  const btn = document.getElementById('bc-apply-filters');
  if (btn && !btn.dataset.bound) {
    btn.dataset.bound = '1';
    btn.addEventListener('click', () => {
      void loadPage();
    });
  }

  const clearBtn = document.getElementById('bc-scope-clear');
  if (clearBtn && !clearBtn.dataset.bound) {
    clearBtn.dataset.bound = '1';
    clearBtn.addEventListener('click', () => {
      void selectServer('all');
    });
  }

  const serversBody = document.getElementById('bc-servers-body');
  if (serversBody && !serversBody.dataset.bound) {
    serversBody.dataset.bound = '1';
    serversBody.addEventListener('click', (e) => {
      const row = e.target.closest('tr[data-server]');
      if (!row) return;
      const host = row.getAttribute('data-server');
      void selectServer(selectedServer === host ? 'all' : host);
    });
    serversBody.addEventListener('keydown', (e) => {
      if (e.key !== 'Enter' && e.key !== ' ') return;
      const row = e.target.closest('tr[data-server]');
      if (!row) return;
      e.preventDefault();
      const host = row.getAttribute('data-server');
      void selectServer(selectedServer === host ? 'all' : host);
    });
  }
}

let bcInitPromise = null;

async function initBackupCompliancePageInner() {
  bindFilters();
  bindPolicyForm();
  await Promise.all([loadPolicyForm(), loadPage()]);
}

export function initBackupCompliancePage() {
  if (bcInitPromise) return bcInitPromise;
  bcInitPromise = initBackupCompliancePageInner().finally(() => {
    bcInitPromise = null;
  });
  return bcInitPromise;
}
