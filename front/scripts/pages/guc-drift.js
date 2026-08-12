import {
  getGucDrift,
  getGucBaseline,
  getGucSnapshots,
  putGucBaseline,
  putGucIgnore,
  getGucGroups,
  upsertGucGroup,
  deleteGucGroup,
  putGucGroupMembers,
} from '../api/services/guc.js';
import { paginateSlice, mountTablePagination } from '../utils/pagination.js';

const gucDriftPager = { page: 1, pageSize: 15 };
const gucHostPager = { page: 1, pageSize: 12 };
const gucHostFilter = { search: '', status: 'all', showIgnored: false };
const gucDetailFilter = { search: '', showIgnored: false };
const gucBaselineHostSearch = { q: '' };

let gucDriftCache = null;
let gucSnapshotsCache = null;
let gucGroupsCache = [];
let gucSelectedGroupId = '';
let gucDetailTargetId = '';
let gucHostToolbarBound = false;
let gucBaselineFormBound = false;
let gucDetailBound = false;
let gucGroupUiBound = false;

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function statusBadge(status) {
  if (status === 'matched' || status === 'baseline') return 'badge-success';
  if (status === 'drifted' || status === 'drift') return 'badge-danger';
  if (status === 'missing') return 'badge-warning';
  if (status === 'version_updated') return 'badge-info';
  if (status === 'version_new') return 'badge-success';
  if (status === 'version_removed') return 'badge-muted';
  if (status === 'ignored') return 'badge-muted';
  if (status === 'no_snapshot') return 'badge-muted';
  return 'badge-warning';
}

function statusLabel(status) {
  const map = {
    matched: 'Matched',
    drifted: 'Drifting',
    missing: 'Missing keys',
    no_snapshot: 'No snapshot',
    no_baseline: 'No baseline',
    baseline: 'Reference',
    drift: 'Drift',
    ignored: 'Ignored',
    version_updated: 'Updated (version)',
    version_new: 'New (version)',
    version_removed: 'Removed (version)',
  };
  return map[status] || status;
}

/**
 * Map GUC snapshot target_id (postgres:host:port:db) to host-detail route key (host:port/db).
 * @param {string} targetId
 * @returns {string}
 */
export function hostKeyFromGucTarget(targetId) {
  const raw = String(targetId || '').trim();
  if (!raw) return '';
  if (raw.startsWith('postgres:')) {
    const parts = raw.split(':');
    if (parts.length >= 4) {
      return parts[1] + ':' + parts[2] + '/' + parts[3];
    }
    if (parts.length >= 3) {
      return parts[1] + ':' + parts[2];
    }
  }
  return raw;
}

function formatTimestamp(iso) {
  if (!iso) return '—';
  try {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return iso;
    return d.toLocaleString(undefined, {
      year: 'numeric', month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit',
    });
  } catch {
    return iso;
  }
}

/**
 * Parse postgresql.conf-style lines into a GUC map (key -> value).
 * @param {string} text
 * @returns {Record<string, string>}
 */
export function parsePostgresqlConf(text) {
  const confOnly = new Set(['include', 'include_dir', 'include_if_exists']);
  const settings = {};
  for (const rawLine of text.split(/\r?\n/)) {
    let line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const hash = line.indexOf('#');
    if (hash > 0) {
      line = line.slice(0, hash).trim();
    }
    const eq = line.indexOf('=');
    if (eq < 1) continue;
    const key = line.slice(0, eq).trim().toLowerCase();
    let value = line.slice(eq + 1).trim();
    if (
      (value.startsWith("'") && value.endsWith("'")) ||
      (value.startsWith('"') && value.endsWith('"'))
    ) {
      value = value.slice(1, -1);
    }
    if (key && !confOnly.has(key)) settings[key] = value;
  }
  return settings;
}

/**
 * @param {string} text
 * @param {string} [filename]
 * @returns {{ settings: Record<string, string> }}
 */
export function parseBaselineFileContent(text, filename = '') {
  const trimmed = text.trim();
  const isJson = filename.toLowerCase().endsWith('.json') || trimmed.startsWith('{');
  if (isJson) {
    const parsed = JSON.parse(trimmed);
    const settings = parsed.settings || parsed;
    if (!settings || typeof settings !== 'object' || Array.isArray(settings)) {
      throw new Error('JSON must be an object or { "settings": { ... } }');
    }
    const out = {};
    const confOnly = new Set(['include', 'include_dir', 'include_if_exists']);
    for (const [k, v] of Object.entries(settings)) {
      const key = String(k).trim().toLowerCase();
      if (v != null && key && !confOnly.has(key)) out[key] = String(v);
    }
    if (!Object.keys(out).length) {
      throw new Error('No GUC settings found in JSON file');
    }
    return { settings: out };
  }
  const settings = parsePostgresqlConf(text);
  if (!Object.keys(settings).length) {
    throw new Error('No GUC settings found — use postgresql.conf (key = value) lines');
  }
  return { settings };
}

function setBaselineUploadStatus(message, isError = false) {
  const el = document.getElementById('guc-baseline-upload-status');
  if (!el) return;
  el.textContent = message || '';
  el.classList.toggle('guc-baseline-upload-status--error', Boolean(isError && message));
  el.classList.toggle('guc-baseline-upload-status--ok', Boolean(!isError && message));
}

function instanceLabelFromTarget(targetId) {
  const raw = String(targetId || '').trim();
  if (!raw) return '';
  if (raw.startsWith('postgres:')) {
    const parts = raw.split(':');
    if (parts.length >= 3) return parts[1] + ':' + parts[2];
  }
  return raw;
}

function parseGucDriftHash() {
  const raw = (location.hash || '').replace(/^#/, '');
  const m = raw.match(/^guc-drift(?:\/host\/(.+))?$/);
  if (!m) return { detailTarget: '' };
  return { detailTarget: m[1] ? decodeURIComponent(m[1]) : '' };
}

function setGucDriftHash(detailTarget) {
  const next = detailTarget
    ? '#guc-drift/host/' + encodeURIComponent(detailTarget)
    : '#guc-drift';
  if (location.hash !== next) {
    location.hash = next.slice(1);
  }
}

function showLandingView() {
  const landing = document.getElementById('guc-view-landing');
  const detail = document.getElementById('guc-view-detail');
  if (landing) landing.hidden = false;
  if (detail) detail.hidden = true;
  gucDetailTargetId = '';
}

function showDetailView(targetId) {
  const landing = document.getElementById('guc-view-landing');
  const detail = document.getElementById('guc-view-detail');
  if (landing) landing.hidden = true;
  if (detail) detail.hidden = false;
  gucDetailTargetId = targetId;
}

function fillBaselineHostSelect(snapshots, selectedTargetId) {
  const sel = document.getElementById('guc-baseline-host-select');
  if (!sel) return;
  const rows = snapshots?.snapshots || [];
  const q = gucBaselineHostSearch.q.trim().toLowerCase();
  const opts = ['<option value="">Select a host with a SHOW ALL snapshot…</option>'];
  for (const s of rows) {
    const id = String(s.target_id || '');
    if (!id) continue;
    const instance = instanceLabelFromTarget(id);
    const host = s.host || instance || id;
    const hay = (host + ' ' + instance + ' ' + id).toLowerCase();
    if (q && !hay.includes(q)) continue;
    const label = instance && instance !== host
      ? host + ' (' + instance + ') · ' + (s.key_count ?? 0) + ' keys'
      : host + ' · ' + (s.key_count ?? 0) + ' keys';
    const selected = id === selectedTargetId ? ' selected' : '';
    opts.push('<option value="' + escapeHtml(id) + '"' + selected + '>' + escapeHtml(label) + '</option>');
  }
  sel.innerHTML = opts.join('');
}

function renderBaselinePanel(baseline, snapshots) {
  const title = document.getElementById('guc-baseline-title');
  const metaRow = document.getElementById('guc-baseline-meta-row');
  const keysEl = document.getElementById('guc-baseline-keys');
  if (!title || !metaRow || !keysEl) return;

  fillBaselineHostSelect(snapshots, baseline?.target_id || '');

  const source = String(baseline?.source || '').toLowerCase();
  const keyCount = baseline?.key_count || 0;

  if (!keyCount && source !== 'host') {
    title.textContent = 'Not configured';
    metaRow.innerHTML = '<span class="guc-meta-chip guc-meta-chip--warn">No reference host</span>';
    keysEl.innerHTML =
      '<p class="guc-empty-inline">Select a host below to set the baseline for this group/fleet.</p>';
    return;
  }

  if (source === 'host') {
    const hostName = baseline.host || baseline.label || baseline.target_id || 'host';
    const instance = instanceLabelFromTarget(baseline.target_id);
    title.textContent = instance ? hostName + ' · ' + instance : hostName;
    metaRow.innerHTML =
      '<span class="guc-meta-chip">pg_settings</span>' +
      '<span class="guc-meta-chip">' + keyCount + ' keys</span>' +
      '<span class="guc-meta-chip">Updated ' + escapeHtml(formatTimestamp(baseline.updated_at)) + '</span>';
    keysEl.innerHTML =
      '<p class="guc-empty-inline">Full live config from this host · compared with unit-aware pg_settings values.</p>';
    return;
  }

  const baselineLabel = String(baseline.label || 'global').trim() || 'global';
  title.textContent = baselineLabel.charAt(0).toUpperCase() + baselineLabel.slice(1);
  metaRow.innerHTML =
    '<span class="guc-meta-chip">Legacy file</span>' +
    '<span class="guc-meta-chip">' + keyCount + ' keys</span>' +
    '<span class="guc-meta-chip">Updated ' + escapeHtml(formatTimestamp(baseline.updated_at)) + '</span>';
  keysEl.innerHTML =
    '<p class="guc-empty-inline">Legacy conf/JSON baseline still active. Prefer a reference host for full SHOW ALL coverage.</p>';
}

function updateStats(data) {
  const sub = document.getElementById('guc-drift-subtitle');
  const banner = document.getElementById('guc-fleet-banner');
  const stats = data?.stats || {};

  if (sub) {
    const groupBit = data?.group_name ? (data.group_name + ' · ') : '';
    const hosts = stats.hosts_compared ?? 0;
    if (!stats.baseline_keys && data?.group_id) {
      sub.textContent = groupBit + hosts + ' server(s) · set a Baseline for this group to compare';
    } else {
      const src = stats.baseline_source === 'host'
        ? ('Reference host ' + (stats.baseline_host || stats.baseline_label || '') + ' pg_settings')
        : 'Golden baseline';
      sub.textContent = groupBit + src + ' vs collectors · ' + hosts + ' server(s)';
    }
  }

  const set = (id, val) => {
    const el = document.getElementById(id);
    if (el) el.textContent = String(val ?? '—');
  };
  set('guc-stat-hosts', stats.hosts_compared);
  set('guc-stat-matched', stats.matched_servers);
  set('guc-stat-drifting', stats.drifting_servers);
  set('guc-stat-missing', stats.missing_servers);

  if (banner) {
    const compared = stats.hosts_compared ?? 0;
    const drifting = stats.drifting_servers ?? 0;
    const missing = stats.missing_servers ?? 0;
    if (compared === 0) {
      banner.hidden = true;
    } else if (drifting === 0 && missing === 0) {
      banner.hidden = false;
      banner.className = 'callout guc-fleet-callout guc-fleet-callout--ok';
      banner.innerHTML = '<strong>All clear</strong> — ' + compared + ' host(s) match the baseline';
    } else {
      banner.hidden = false;
      banner.className = 'callout guc-fleet-callout guc-fleet-callout--warn';
      banner.innerHTML = '<strong>Attention</strong> — ' + drifting + ' drifting · ' + missing + ' with missing keys';
    }
  }
}

export function filterHostSummaries(summaries, filter) {
  let out = summaries || [];
  const q = (filter?.search || '').trim().toLowerCase();
  if (q) {
    out = out.filter((h) =>
      String(h.host || '').toLowerCase().includes(q) ||
      String(h.target_id || '').toLowerCase().includes(q),
    );
  }
  if (!filter?.showIgnored) {
    out = out.filter((h) => h.status !== 'ignored' && !h.host_ignored);
  }
  const status = filter?.status || 'all';
  if (status !== 'all') {
    out = out.filter((h) => h.status === status);
  }
  return out;
}

function renderGroupTabs() {
  const tabs = document.getElementById('guc-group-tabs');
  const settingsBtn = document.getElementById('guc-group-settings-btn');
  if (!tabs) return;
  const items = [{ id: '', name: 'Fleet (global)' }].concat(
    (gucGroupsCache || []).map((g) => ({ id: g.id, name: g.name })),
  );
  tabs.innerHTML = items.map((g) => {
    const active = (g.id || '') === (gucSelectedGroupId || '');
    return '<button type="button" class="guc-group-tab' + (active ? ' active' : '') +
      '" data-guc-group="' + escapeHtml(g.id || '') + '" role="tab" aria-selected="' +
      (active ? 'true' : 'false') + '">' + escapeHtml(g.name) + '</button>';
  }).join('');
  if (settingsBtn) settingsBtn.hidden = !gucSelectedGroupId;
}

function renderHostSummaries(data) {
  const tbody = document.getElementById('guc-host-summaries');
  const hint = document.getElementById('guc-host-status-hint');
  const pagerEl = document.getElementById('guc-host-pagination');
  if (!tbody) return;

  const all = data?.host_summaries || [];
  const filtered = filterHostSummaries(all, gucHostFilter);
  const pg = paginateSlice(filtered, gucHostPager.page, gucHostPager.pageSize);
  gucHostPager.page = pg.page;

  if (hint) {
    if (!all.length) {
      hint.textContent = 'No data';
    } else if (filtered.length !== all.length) {
      hint.textContent = filtered.length + ' of ' + all.length + ' hosts';
    } else {
      hint.textContent = all.length + ' host' + (all.length === 1 ? '' : 's') + ' in view';
    }
  }

  if (!all.length) {
    tbody.innerHTML =
      '<tr><td colspan="6" class="guc-table-empty">' +
      'No live config yet. Collectors include SHOW ALL with each scan push when mainserver is enabled.</td></tr>';
    mountTablePagination(pagerEl, {
      page: 1, totalPages: 1, total: 0, start: 0, end: 0, pageSize: gucHostPager.pageSize,
      onPage: () => {}, onPageSize: () => {},
    });
    return;
  }

  if (!filtered.length) {
    tbody.innerHTML =
      '<tr><td colspan="6" class="guc-table-empty">No hosts match your search or filter.</td></tr>';
    mountTablePagination(pagerEl, {
      page: 1, totalPages: 1, total: 0, start: 0, end: 0, pageSize: gucHostPager.pageSize,
      onPage: () => {}, onPageSize: () => {},
    });
    return;
  }

  tbody.innerHTML = pg.items.map((h) => {
    const tid = escapeHtml(h.target_id || '');
    const ignored = h.status === 'ignored' || h.host_ignored;
    const ignoreLabel = ignored ? 'Un-ignore host' : 'Ignore host';
    return '<tr class="guc-host-row guc-host-row--' + escapeHtml(h.status) + '">' +
      '<td><strong>' + escapeHtml(h.host) + '</strong></td>' +
      '<td><span class="badge ' + statusBadge(h.status) + '">' + escapeHtml(statusLabel(h.status)) + '</span></td>' +
      '<td>' + escapeHtml(h.drift_count ?? 0) + '</td>' +
      '<td>' + escapeHtml(h.missing_count ?? 0) + '</td>' +
      '<td class="guc-host-target-cell">' + escapeHtml(h.target_id || '—') + '</td>' +
      '<td class="guc-host-actions">' +
      '<button type="button" class="btn btn-row" data-guc-open="' + tid + '">Open</button> ' +
      '<button type="button" class="btn btn-row" data-guc-ignore-host="' + tid + '" data-ignore="' +
      (ignored ? '0' : '1') + '">' + ignoreLabel + '</button>' +
      '</td></tr>';
  }).join('');

  mountTablePagination(pagerEl, {
    page: pg.page,
    totalPages: pg.totalPages,
    total: pg.total,
    start: pg.start,
    end: pg.end,
    pageSize: pg.pageSize,
    pageSizes: [12, 24, 50],
    onPage: (p) => {
      gucHostPager.page = p;
      renderHostSummaries(gucDriftCache);
    },
    onPageSize: (size) => {
      gucHostPager.pageSize = size;
      gucHostPager.page = 1;
      renderHostSummaries(gucDriftCache);
    },
  });
}

function bindGucHostToolbar() {
  if (gucHostToolbarBound) return;
  const searchEl = document.getElementById('guc-host-search');
  const statusEl = document.getElementById('guc-host-status-filter');
  const showIgnoredEl = document.getElementById('guc-show-ignored-hosts');
  if (!searchEl && !statusEl && !showIgnoredEl) return;
  gucHostToolbarBound = true;

  const applyFilter = () => {
    gucHostFilter.search = searchEl?.value || '';
    gucHostFilter.status = statusEl?.value || 'all';
    gucHostFilter.showIgnored = Boolean(showIgnoredEl?.checked);
    gucHostPager.page = 1;
    renderHostSummaries(gucDriftCache);
  };

  if (searchEl) searchEl.addEventListener('input', applyFilter);
  if (statusEl) statusEl.addEventListener('change', applyFilter);
  if (showIgnoredEl) showIgnoredEl.addEventListener('change', applyFilter);
}

function filterDetailRows(rows, filter) {
  let out = rows || [];
  const q = (filter?.search || '').trim().toLowerCase();
  if (q) {
    out = out.filter((r) => String(r.guc || '').toLowerCase().includes(q));
  }
  if (!filter?.showIgnored) {
    out = out.filter((r) => !r.ignored);
  }
  return out;
}

function renderDetailTable(data) {
  const tbody = document.getElementById('guc-drift-tbody');
  const pagerEl = document.getElementById('guc-drift-pagination');
  const tableHint = document.getElementById('guc-drift-table-hint');
  const title = document.getElementById('guc-detail-title');
  const sub = document.getElementById('guc-detail-subtitle');
  if (!tbody) return;

  const hostSummary = (data?.host_summaries || []).find((h) => h.target_id === gucDetailTargetId)
    || (data?.host_summaries || [])[0];
  const hostName = hostSummary?.host || instanceLabelFromTarget(gucDetailTargetId) || gucDetailTargetId;
  if (title) title.textContent = hostName;
  if (sub) {
    const bl = data?.stats?.baseline_host || data?.stats?.baseline_label || 'baseline';
    const fromMaj = data?.stats?.baseline_major;
    const toMaj = hostSummary?.postgres_major;
    let line = 'Configuration differences vs ' + bl;
    if (fromMaj && toMaj && fromMaj !== toMaj) {
      line += ' · PG ' + fromMaj + ' → ' + toMaj + ' (version-aware)';
    } else if (toMaj) {
      line += ' · PG ' + toMaj;
    }
    const vu = hostSummary?.version_updated_count || 0;
    const vn = hostSummary?.version_new_count || 0;
    const vr = hostSummary?.version_removed_count || 0;
    if (vu || vn || vr) {
      line += ' · version: ' + vu + ' updated, ' + vn + ' new, ' + vr + ' removed';
    }
    sub.textContent = line;
  }

  if (hostSummary?.status === 'ignored' || hostSummary?.host_ignored) {
    tbody.innerHTML =
      '<tr><td colspan="5" class="guc-table-empty">' +
      'This host is ignored from GUC drift findings. Use Un-ignore on the landing page to restore it.</td></tr>';
    if (tableHint) tableHint.textContent = 'Host ignored';
    mountTablePagination(pagerEl, {
      page: 1, totalPages: 1, total: 0, start: 0, end: 0, pageSize: gucDriftPager.pageSize,
      onPage: () => {}, onPageSize: () => {},
    });
    return;
  }

  const allRows = (data?.rows || []).filter((r) => !gucDetailTargetId || r.target_id === gucDetailTargetId);
  const rows = filterDetailRows(allRows, gucDetailFilter);

  if (tableHint) {
    const active = allRows.filter((r) => !r.ignored).length;
    const ignored = allRows.filter((r) => r.ignored).length;
    const versionOnly = allRows.filter((r) => !r.ignored && String(r.status || '').startsWith('version_')).length;
    const real = active - versionOnly;
    tableHint.textContent = active
      ? (real ? real + ' drift/missing' : '0 drift') +
        (versionOnly ? ' · ' + versionOnly + ' version' : '') +
        (ignored ? ' · ' + ignored + ' ignored' : '')
      : (ignored ? ignored + ' ignored · all clear otherwise' : 'All clear');
  }

  const pg = paginateSlice(rows, gucDriftPager.page, gucDriftPager.pageSize);
  gucDriftPager.page = pg.page;

  if (!pg.total) {
    tbody.innerHTML =
      '<tr><td colspan="5" class="guc-table-empty guc-table-empty--ok">' +
      (allRows.length && !gucDetailFilter.showIgnored
        ? 'No active differences — enable Show ignored to review suppressed findings.'
        : 'No drift or missing keys — this host matches the baseline (version-only changes still appear when present).') +
      '</td></tr>';
    mountTablePagination(pagerEl, {
      page: 1, totalPages: 1, total: 0, start: 0, end: 0, pageSize: gucDriftPager.pageSize,
      onPage: () => {}, onPageSize: () => {},
    });
    return;
  }

  tbody.innerHTML = pg.items.map((row) => {
    const badge = statusBadge(row.status);
    const ignoreLabel = row.ignored ? 'Un-ignore' : 'Ignore';
    return '<tr' + (row.ignored ? ' class="guc-row-ignored"' : '') + '>' +
      '<td><code>' + escapeHtml(row.guc) + '</code></td>' +
      '<td><span class="guc-val-live">' + escapeHtml(row.live) + '</span></td>' +
      '<td><span class="guc-val-baseline">' + escapeHtml(row.baseline) + '</span></td>' +
      '<td><span class="badge ' + badge + '">' + escapeHtml(statusLabel(row.status)) +
      (row.ignored ? ' · ignored' : '') + '</span></td>' +
      '<td><button type="button" class="btn btn-row" data-guc-ignore-guc="' +
      escapeHtml(row.guc) + '" data-target="' + escapeHtml(row.target_id) +
      '" data-ignore="' + (row.ignored ? '0' : '1') + '">' + ignoreLabel + '</button></td></tr>';
  }).join('');

  mountTablePagination(pagerEl, {
    page: pg.page,
    totalPages: pg.totalPages,
    total: pg.total,
    start: pg.start,
    end: pg.end,
    pageSize: pg.pageSize,
    onPage: (p) => {
      gucDriftPager.page = p;
      renderDetailTable(gucDriftCache);
    },
    onPageSize: (size) => {
      gucDriftPager.pageSize = size;
      gucDriftPager.page = 1;
      renderDetailTable(gucDriftCache);
    },
  });
}

function renderLanding(data) {
  updateStats(data);
  renderHostSummaries(data);
}

async function refreshGucDriftPage() {
  const groupId = gucSelectedGroupId || '';
  const [baseline, snapshots, data, groups] = await Promise.all([
    getGucBaseline(groupId).catch(() => ({ key_count: 0, settings: {}, source: 'none' })),
    getGucSnapshots().catch(() => ({ snapshots: [] })),
    getGucDrift({ groupId, targetId: gucDetailTargetId || undefined }),
    getGucGroups().catch(() => ({ groups: [] })),
  ]);
  gucGroupsCache = groups?.groups || [];
  gucSnapshotsCache = snapshots;
  renderGroupTabs();
  renderBaselinePanel(baseline, snapshots);
  gucDriftCache = data;
  gucDriftPager.page = 1;
  gucHostPager.page = 1;

  if (gucDetailTargetId) {
    showDetailView(gucDetailTargetId);
    renderDetailTable(data);
  } else {
    showLandingView();
    renderLanding(data);
  }
  return baseline;
}

function bindGucBaselineUploadForm() {
  if (gucBaselineFormBound) return;
  const btn = document.getElementById('guc-baseline-host-submit');
  const sel = document.getElementById('guc-baseline-host-select');
  const search = document.getElementById('guc-baseline-host-search');
  if (!btn || !sel) return;
  gucBaselineFormBound = true;

  if (search) {
    search.addEventListener('input', () => {
      gucBaselineHostSearch.q = search.value || '';
      fillBaselineHostSelect(gucSnapshotsCache, sel.value);
    });
  }

  btn.addEventListener('click', async () => {
    const targetId = (sel.value || '').trim();
    if (!targetId) {
      setBaselineUploadStatus('Select a reference host first', true);
      return;
    }
    setBaselineUploadStatus('Saving…');
    btn.disabled = true;
    try {
      const result = await putGucBaseline({
        target_id: targetId,
        group_id: gucSelectedGroupId || undefined,
      });
      setBaselineUploadStatus(
        'Reference host saved — ' + (result.key_count ?? 0) + ' pg_settings keys',
        false,
      );
      await refreshGucDriftPage();
    } catch (err) {
      setBaselineUploadStatus(err.message || 'Save failed', true);
    } finally {
      btn.disabled = false;
    }
  });
}

function renderGroupMembersEditor() {
  const el = document.getElementById('guc-group-members');
  if (!el) return;
  const snaps = gucSnapshotsCache?.snapshots || [];
  const group = (gucGroupsCache || []).find((g) => g.id === gucSelectedGroupId);
  const selected = new Set(group?.member_ids || []);
  if (!snaps.length) {
    el.innerHTML = '<p class="guc-empty-inline">No snapshots available to assign.</p>';
    return;
  }
  el.innerHTML = '<div class="guc-group-member-list">' + snaps.map((s) => {
    const id = s.target_id;
    const host = s.host || instanceLabelFromTarget(id);
    return '<label class="guc-group-member-row">' +
      '<input type="checkbox" data-guc-member="' + escapeHtml(id) + '"' +
      (selected.has(id) ? ' checked' : '') + ' />' +
      '<span class="guc-group-member-text">' +
      '<span class="guc-group-member-host">' + escapeHtml(host) + '</span>' +
      '<span class="guc-group-member-target">' + escapeHtml(id) + '</span>' +
      '</span></label>';
  }).join('') + '</div>';
}

function setGroupModalStatus(message, isError = false) {
  const el = document.getElementById('guc-group-modal-status');
  if (!el) return;
  el.textContent = message || '';
  el.classList.toggle('guc-modal-status--error', Boolean(isError && message));
}

function openCreateGroupModal() {
  const modal = document.getElementById('guc-group-modal');
  const nameEl = document.getElementById('guc-group-modal-name');
  const descEl = document.getElementById('guc-group-modal-desc');
  if (!modal) return;
  if (nameEl) nameEl.value = '';
  if (descEl) descEl.value = '';
  setGroupModalStatus('');
  modal.hidden = false;
  requestAnimationFrame(() => nameEl?.focus());
}

function closeCreateGroupModal() {
  const modal = document.getElementById('guc-group-modal');
  if (modal) modal.hidden = true;
  setGroupModalStatus('');
}

function openDeleteGroupModal() {
  const modal = document.getElementById('guc-confirm-modal');
  const status = document.getElementById('guc-confirm-modal-status');
  if (!modal || !gucSelectedGroupId) return;
  if (status) status.textContent = '';
  modal.hidden = false;
}

function closeDeleteGroupModal() {
  const modal = document.getElementById('guc-confirm-modal');
  if (modal) modal.hidden = true;
}

function bindGroupUi() {
  if (gucGroupUiBound) return;
  const bar = document.getElementById('guc-group-bar');
  if (!bar) return;
  gucGroupUiBound = true;

  bar.addEventListener('click', async (e) => {
    const tab = e.target.closest('[data-guc-group]');
    if (tab) {
      gucSelectedGroupId = tab.getAttribute('data-guc-group') || '';
      document.getElementById('guc-group-settings-panel')?.setAttribute('hidden', '');
      await refreshGucDriftPage();
      return;
    }
  });

  document.getElementById('guc-group-create-btn')?.addEventListener('click', () => {
    openCreateGroupModal();
  });

  document.getElementById('guc-group-modal')?.addEventListener('click', (e) => {
    if (e.target.closest('[data-guc-modal-close]')) {
      closeCreateGroupModal();
    }
  });

  document.getElementById('guc-group-modal-submit')?.addEventListener('click', async () => {
    const nameEl = document.getElementById('guc-group-modal-name');
    const descEl = document.getElementById('guc-group-modal-desc');
    const submit = document.getElementById('guc-group-modal-submit');
    const name = nameEl?.value?.trim() || '';
    const description = descEl?.value?.trim() || '';
    if (!name) {
      setGroupModalStatus('Enter a group name', true);
      nameEl?.focus();
      return;
    }
    setGroupModalStatus('Creating…');
    if (submit) submit.disabled = true;
    try {
      const g = await upsertGucGroup({ name, description });
      gucSelectedGroupId = g.id;
      closeCreateGroupModal();
      await refreshGucDriftPage();
      openGroupSettings();
    } catch (err) {
      setGroupModalStatus(err.message || 'Failed to create group', true);
    } finally {
      if (submit) submit.disabled = false;
    }
  });

  document.getElementById('guc-group-modal-name')?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      document.getElementById('guc-group-modal-submit')?.click();
    }
    if (e.key === 'Escape') closeCreateGroupModal();
  });

  document.getElementById('guc-baseline-open-btn')?.addEventListener('click', () => {
    const panel = document.getElementById('guc-baseline-panel');
    if (!panel) return;
    panel.hidden = false;
    document.getElementById('guc-group-settings-panel')?.setAttribute('hidden', '');
  });
  document.getElementById('guc-baseline-close-btn')?.addEventListener('click', () => {
    document.getElementById('guc-baseline-panel')?.setAttribute('hidden', '');
  });

  document.getElementById('guc-group-settings-btn')?.addEventListener('click', () => openGroupSettings());
  document.getElementById('guc-group-settings-close')?.addEventListener('click', () => {
    document.getElementById('guc-group-settings-panel')?.setAttribute('hidden', '');
  });

  document.getElementById('guc-group-save-btn')?.addEventListener('click', async () => {
    if (!gucSelectedGroupId) return;
    const name = document.getElementById('guc-group-name-input')?.value?.trim() || '';
    const description = document.getElementById('guc-group-desc-input')?.value?.trim() || '';
    const memberEls = document.querySelectorAll('#guc-group-members [data-guc-member]');
    const targetIds = [];
    memberEls.forEach((el) => {
      if (el.checked) targetIds.push(el.getAttribute('data-guc-member'));
    });
    const saveBtn = document.getElementById('guc-group-save-btn');
    if (saveBtn) saveBtn.disabled = true;
    try {
      await upsertGucGroup({ id: gucSelectedGroupId, name, description });
      await putGucGroupMembers(gucSelectedGroupId, targetIds);
      await refreshGucDriftPage();
      openGroupSettings();
      const hint = document.getElementById('guc-host-status-hint');
      if (hint) {
        hint.textContent = targetIds.length
          ? targetIds.length + ' member(s) saved · set Baseline if not set'
          : 'No members selected';
      }
    } catch (err) {
      window.alert(err.message || 'Failed to save group');
    } finally {
      if (saveBtn) saveBtn.disabled = false;
    }
  });

  document.getElementById('guc-group-delete-btn')?.addEventListener('click', () => {
    openDeleteGroupModal();
  });

  document.getElementById('guc-confirm-modal')?.addEventListener('click', (e) => {
    if (e.target.closest('[data-guc-confirm-close]')) {
      closeDeleteGroupModal();
    }
  });

  document.getElementById('guc-confirm-modal-submit')?.addEventListener('click', async () => {
    if (!gucSelectedGroupId) return;
    const submit = document.getElementById('guc-confirm-modal-submit');
    const status = document.getElementById('guc-confirm-modal-status');
    if (submit) submit.disabled = true;
    if (status) status.textContent = 'Deleting…';
    try {
      await deleteGucGroup(gucSelectedGroupId);
      gucSelectedGroupId = '';
      document.getElementById('guc-group-settings-panel')?.setAttribute('hidden', '');
      closeDeleteGroupModal();
      await refreshGucDriftPage();
    } catch (err) {
      if (status) {
        status.textContent = err.message || 'Failed to delete group';
        status.classList.add('guc-modal-status--error');
      }
    } finally {
      if (submit) submit.disabled = false;
    }
  });
}

function openGroupSettings() {
  const panel = document.getElementById('guc-group-settings-panel');
  if (!panel || !gucSelectedGroupId) return;
  document.getElementById('guc-baseline-panel')?.setAttribute('hidden', '');
  const group = (gucGroupsCache || []).find((g) => g.id === gucSelectedGroupId);
  const nameEl = document.getElementById('guc-group-name-input');
  const descEl = document.getElementById('guc-group-desc-input');
  if (nameEl) nameEl.value = group?.name || '';
  if (descEl) descEl.value = group?.description || '';
  renderGroupMembersEditor();
  panel.hidden = false;
}

function bindDetailAndActions() {
  if (gucDetailBound) return;
  const page = document.getElementById('page-guc-drift');
  if (!page) return;
  gucDetailBound = true;

  page.addEventListener('click', async (e) => {
    const openBtn = e.target.closest('[data-guc-open]');
    if (openBtn) {
      e.preventDefault();
      e.stopPropagation();
      const tid = openBtn.getAttribute('data-guc-open');
      if (!tid) return;
      setGucDriftHash(tid);
      gucDetailTargetId = tid;
      showDetailView(tid);
      gucDetailFilter.search = '';
      gucDetailFilter.showIgnored = false;
      const searchEl = document.getElementById('guc-detail-guc-search');
      const showEl = document.getElementById('guc-show-ignored-gucs');
      if (searchEl) searchEl.value = '';
      if (showEl) showEl.checked = false;
      try {
        gucDriftCache = await getGucDrift({
          groupId: gucSelectedGroupId || undefined,
          targetId: tid,
        });
        renderDetailTable(gucDriftCache);
      } catch (err) {
        const tbody = document.getElementById('guc-drift-tbody');
        if (tbody) {
          tbody.innerHTML = '<tr><td colspan="5" class="guc-table-empty" style="color:var(--danger);">' +
            escapeHtml(err.message) + '</td></tr>';
        }
      }
      return;
    }

    const ignoreHost = e.target.closest('[data-guc-ignore-host]');
    if (ignoreHost) {
      e.preventDefault();
      e.stopPropagation();
      const tid = ignoreHost.getAttribute('data-guc-ignore-host');
      const ignore = ignoreHost.getAttribute('data-ignore') !== '0';
      try {
        await putGucIgnore({ scope: 'host', target_id: tid, ignore });
        await refreshGucDriftPage();
      } catch (err) {
        window.alert(err.message || 'Ignore failed');
      }
      return;
    }

    const ignoreGuc = e.target.closest('[data-guc-ignore-guc]');
    if (ignoreGuc) {
      e.preventDefault();
      e.stopPropagation();
      const guc = ignoreGuc.getAttribute('data-guc-ignore-guc');
      const tid = ignoreGuc.getAttribute('data-target');
      const ignore = ignoreGuc.getAttribute('data-ignore') !== '0';
      try {
        await putGucIgnore({ scope: 'guc', target_id: tid, guc, ignore });
        gucDriftCache = await getGucDrift({
          groupId: gucSelectedGroupId || undefined,
          targetId: tid,
        });
        renderDetailTable(gucDriftCache);
      } catch (err) {
        window.alert(err.message || 'Ignore failed');
      }
    }
  });

  document.getElementById('guc-detail-back')?.addEventListener('click', async () => {
    setGucDriftHash('');
    gucDetailTargetId = '';
    showLandingView();
    await refreshGucDriftPage();
  });

  document.getElementById('guc-detail-guc-search')?.addEventListener('input', (e) => {
    gucDetailFilter.search = e.target.value || '';
    gucDriftPager.page = 1;
    renderDetailTable(gucDriftCache);
  });
  document.getElementById('guc-show-ignored-gucs')?.addEventListener('change', (e) => {
    gucDetailFilter.showIgnored = Boolean(e.target.checked);
    gucDriftPager.page = 1;
    renderDetailTable(gucDriftCache);
  });
}

export async function initGucDriftPage() {
  const page = document.getElementById('page-guc-drift');
  if (!page) return;
  bindGucBaselineUploadForm();
  bindGucHostToolbar();
  bindGroupUi();
  bindDetailAndActions();
  setBaselineUploadStatus('');

  const route = parseGucDriftHash();
  gucDetailTargetId = route.detailTarget || '';

  const tbody = document.getElementById('guc-host-summaries');
  if (tbody) tbody.innerHTML = '<tr><td colspan="6" class="guc-table-empty">Loading…</td></tr>';
  try {
    await refreshGucDriftPage();
  } catch (err) {
    if (tbody) {
      tbody.innerHTML = '<tr><td colspan="6" class="guc-table-empty" style="color:var(--danger);">Failed to load: ' +
        escapeHtml(err.message) + '</td></tr>';
    }
  }
}
