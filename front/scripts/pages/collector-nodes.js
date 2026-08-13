import {
  fetchCollectorNodes,
  fetchCollectorNodeRuns,
  fetchCollectorNodeActivity,
  fetchCollectorNodeLogs,
} from '../api/services/collectors.js';
import { errorMessageFromCaught } from '../api/errors.js';
import { paginateSlice, mountTablePagination } from '../utils/pagination.js';

const REFRESH_MS = 30000;
const nodesPager = { page: 1, pageSize: 15 };
let refreshTimer = null;
let selectedNodeId = null;
let nodesCache = [];
let fleetOfflineThresholdSec = 90;
let logsCache = [];
let logsFilter = 'all';

function escapeHtml(s) {
  return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function fmtTime(iso) {
  if (!iso) return '—';
  try {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return escapeHtml(String(iso));
    return d.toLocaleString();
  } catch {
    return '—';
  }
}

function formatDurationMs(ms) {
  const n = Number(ms);
  if (ms == null || ms === '' || Number.isNaN(n) || n < 0) return '—';
  if (n < 1000) return `${Math.round(n)} ms`;
  const sec = n / 1000;
  if (sec < 60) return `${sec.toFixed(1)} sec`;
  if (sec < 3600) return `${Math.round(sec / 60)} min`;
  return `${(sec / 3600).toFixed(1)} hr`;
}

function normalizeLogLevel(level) {
  const s = String(level || '').toLowerCase();
  if (s === 'warning') return 'warn';
  if (s === 'error' || s === 'warn' || s === 'info') return s;
  return 'log';
}

function logLevelBadge(level) {
  const s = normalizeLogLevel(level);
  if (s === 'error') return '<span class="badge badge-danger">Error</span>';
  if (s === 'warn') return '<span class="badge badge-warning">Warn</span>';
  if (s === 'info') return '<span class="badge badge-info">Info</span>';
  return '<span class="badge badge-muted">Log</span>';
}

function logEntryTitle(message) {
  const m = String(message || '').trim();
  if (!m) return 'Log entry';
  const head = m.split(':')[0].trim();
  if (head.length > 0 && head.length <= 56) return head;
  return m.length > 56 ? `${m.slice(0, 56)}…` : m;
}

function logLevelClass(level) {
  const s = normalizeLogLevel(level);
  if (s === 'error' || s === 'warn' || s === 'info') return `cn-log-entry--${s}`;
  return '';
}

function countLogsByLevel(items) {
  const counts = { all: items.length, error: 0, warn: 0, info: 0, log: 0 };
  for (const line of items) {
    const lvl = normalizeLogLevel(line.level);
    if (lvl in counts) counts[lvl] += 1;
  }
  return counts;
}

function feedEmptyState(title, detail) {
  return `<div class="cn-feed-empty">
    <div class="cn-feed-empty-icon" aria-hidden="true">◇</div>
    <div class="cn-feed-empty-title">${escapeHtml(title)}</div>
    <p>${escapeHtml(detail)}</p>
  </div>`;
}

function loadingState(label) {
  return feedEmptyState('Loading…', `Fetching ${label} from main-server.`);
}

function statusBadge(status) {
  const s = String(status || '').toLowerCase();
  if (s === 'online') return '<span class="badge badge-success">Online</span>';
  if (s === 'offline') return '<span class="badge badge-danger">Offline</span>';
  return `<span class="badge badge-muted">${escapeHtml(status || 'unknown')}</span>`;
}

function boolBadge(yes, yesLabel, noLabel) {
  return yes
    ? `<span class="badge badge-info">${escapeHtml(yesLabel)}</span>`
    : `<span class="badge badge-muted">${escapeHtml(noLabel)}</span>`;
}

function scrollToNodeDetail() {
  const detail = document.getElementById('cn-detail');
  if (!detail || detail.style.display === 'none') return;
  requestAnimationFrame(() => {
    detail.scrollIntoView({ behavior: 'smooth', block: 'start' });
  });
}

function setMessage(text, isError) {
  const el = document.getElementById('cn-message');
  if (!el) return;
  if (!text) {
    el.style.display = 'none';
    el.textContent = '';
    return;
  }
  el.style.display = 'block';
  el.textContent = text;
  el.style.color = isError ? 'var(--critical)' : 'var(--kloud-green)';
}

function updateStats(nodes) {
  const total = nodes.length;
  const online = nodes.filter((n) => String(n.status).toLowerCase() === 'online').length;
  const offline = nodes.filter((n) => String(n.status).toLowerCase() === 'offline').length;
  const jobs = nodes.reduce((sum, n) => sum + (Number(n.scheduled_jobs) || 0), 0);

  const set = (id, val) => {
    const el = document.getElementById(id);
    if (el) el.textContent = String(val);
  };
  set('cn-stat-total', total);
  set('cn-stat-online', online);
  set('cn-stat-offline', offline);
  set('cn-stat-jobs', jobs);
}

function renderNodesTable() {
  const tbody = document.getElementById('cn-nodes-tbody');
  const pagerEl = document.getElementById('cn-nodes-pagination');
  if (!tbody) return;

  const pg = paginateSlice(nodesCache, nodesPager.page, nodesPager.pageSize);
  nodesPager.page = pg.page;

  if (!pg.total) {
    tbody.innerHTML =
      '<tr><td colspan="7" style="color:var(--muted);padding:20px;">' +
      'No collector heartbeats yet. Start <code>ciscollector --setup-cron</code> with <code>[mainserver] enabled</code>.</td></tr>';
    mountTablePagination(pagerEl, {
      page: 1,
      totalPages: 1,
      total: 0,
      start: 0,
      end: 0,
      pageSize: nodesPager.pageSize,
      onPage: () => {},
      onPageSize: () => {},
    });
    return;
  }

  tbody.innerHTML = pg.items.map((n) => {
    const id = escapeHtml(n.node_id);
    const selected = n.node_id === selectedNodeId ? ' selected' : '';
    const err = n.last_error
      ? `<span style="color:var(--critical);font-size:12px;">${escapeHtml(n.last_error)}</span>`
      : '<span style="color:var(--muted);">—</span>';
    return `<tr class="clickable${selected}" data-node-id="${id}">
      <td><strong>${escapeHtml(n.hostname)}</strong><br><span style="font-size:11px;color:var(--muted);">${id.slice(0, 12)}…</span></td>
      <td>${statusBadge(n.status)}</td>
      <td>${boolBadge(n.cron_running, 'Running', 'Idle')}</td>
      <td>${escapeHtml(String(n.scheduled_jobs ?? 0))}</td>
      <td>${fmtTime(n.last_seen_at)}</td>
      <td>${fmtTime(n.last_run_at)}</td>
      <td>${err}</td>
    </tr>`;
  }).join('');

  tbody.querySelectorAll('tr[data-node-id]').forEach((row) => {
    row.addEventListener('click', () => {
      const id = row.getAttribute('data-node-id');
      const node = nodesCache.find((x) => x.node_id === id);
      if (node) void selectNode(node);
    });
  });

  mountTablePagination(pagerEl, {
    page: pg.page,
    totalPages: pg.totalPages,
    total: pg.total,
    start: pg.start,
    end: pg.end,
    pageSize: pg.pageSize,
    pageSizes: [10, 15, 25, 50],
    onPage: (p) => {
      nodesPager.page = p;
      renderNodesTable();
    },
    onPageSize: (size) => {
      nodesPager.pageSize = size;
      nodesPager.page = 1;
      renderNodesTable();
    },
  });
}

async function renderRuns(nodeId) {
  const tbody = document.getElementById('cn-runs-tbody');
  if (!tbody) return;
  tbody.innerHTML = '<tr><td colspan="6" style="color:var(--muted);padding:16px;">Loading…</td></tr>';
  try {
    const data = await fetchCollectorNodeRuns(nodeId);
    const runs = data?.runs || [];
    if (!runs.length) {
      tbody.innerHTML = '<tr><td colspan="6" style="color:var(--muted);padding:16px;">No runs recorded yet.</td></tr>';
      return;
    }
    tbody.innerHTML = runs.map((r) => {
      const ok = r.success
        ? '<span class="badge badge-success">OK</span>'
        : '<span class="badge badge-danger">Fail</span>';
      const err = r.error
        ? `<span style="color:var(--critical);font-size:12px;">${escapeHtml(r.error)}</span>`
        : '—';
      let durationMs = r.duration_ms;
      if ((durationMs == null || durationMs === 0) && r.started_at && r.finished_at) {
        const start = new Date(r.started_at).getTime();
        const end = new Date(r.finished_at).getTime();
        if (!Number.isNaN(start) && !Number.isNaN(end) && end >= start) {
          durationMs = end - start;
        }
      }
      return `<tr>
        <td>${fmtTime(r.started_at)}</td>
        <td>${fmtTime(r.finished_at)}</td>
        <td>${formatDurationMs(durationMs)}</td>
        <td>${escapeHtml(r.trigger || '')}</td>
        <td>${ok}</td>
        <td>${err}</td>
      </tr>`;
    }).join('');
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="6" style="color:var(--critical);padding:16px;">${escapeHtml(errorMessageFromCaught(e))}</td></tr>`;
  }
}

async function renderActivity(nodeId) {
  const root = document.getElementById('cn-activity-list');
  const meta = document.getElementById('cn-activity-meta');
  const hint = document.getElementById('cn-activity-hint');
  if (!root) return;

  root.innerHTML = loadingState('activity');
  if (meta) meta.textContent = '';
  if (hint) hint.style.display = 'none';

  try {
    const data = await fetchCollectorNodeActivity(nodeId);
    const items = data?.activity || [];

    if (meta) {
      meta.textContent = items.length ? `${items.length} event${items.length === 1 ? '' : 's'}` : '';
    }
    if (hint) {
      hint.style.display = items.length ? 'block' : 'none';
      hint.textContent = items.length
        ? 'Operational events pushed by this collector (register, cron ticks, scan push).'
        : '';
    }

    if (!items.length) {
      root.innerHTML = feedEmptyState(
        'No activity yet',
        'Events appear when the collector registers, runs cron ticks, or pushes scan data.'
      );
      return;
    }

    root.innerHTML = items.map((a) => `
      <article class="cn-timeline-item">
        <div class="cn-timeline-msg">${escapeHtml(a.message)}</div>
        <div class="cn-timeline-meta">
          <span class="cn-kind-pill">${escapeHtml(a.kind || 'event')}</span>
          <span>${fmtTime(a.created_at)}</span>
        </div>
      </article>
    `).join('');
  } catch (e) {
    root.innerHTML = feedEmptyState('Could not load activity', errorMessageFromCaught(e));
  }
}

function renderLogFilters(counts) {
  const bar = document.getElementById('cn-logs-filters');
  if (!bar) return;

  if (!counts.all) {
    bar.style.display = 'none';
    bar.innerHTML = '';
    return;
  }

  const filters = [
    { id: 'all', label: 'All' },
    { id: 'error', label: 'Errors' },
    { id: 'warn', label: 'Warnings' },
    { id: 'info', label: 'Info' },
  ].filter((f) => f.id === 'all' || counts[f.id] > 0);

  bar.style.display = 'flex';
  bar.innerHTML = filters.map((f) => {
    const active = logsFilter === f.id ? ' active' : '';
    const n = counts[f.id];
    return `<button type="button" class="cn-log-filter-btn${active}" data-log-filter="${f.id}">
      ${escapeHtml(f.label)}<span class="cn-filter-count">(${n})</span>
    </button>`;
  }).join('');

  bar.querySelectorAll('[data-log-filter]').forEach((btn) => {
    btn.addEventListener('click', () => {
      logsFilter = btn.getAttribute('data-log-filter') || 'all';
      renderLogEntries();
      renderLogFilters(countLogsByLevel(logsCache));
    });
  });
}

function renderLogEntries() {
  const root = document.getElementById('cn-logs-list');
  const meta = document.getElementById('cn-logs-meta');
  if (!root) return;

  const counts = countLogsByLevel(logsCache);
  const filtered = logsFilter === 'all'
    ? logsCache
    : logsCache.filter((line) => normalizeLogLevel(line.level) === logsFilter);

  if (meta) {
    const errPart = counts.error ? ` · ${counts.error} error${counts.error === 1 ? '' : 's'}` : '';
    meta.textContent = counts.all ? `${counts.all} entr${counts.all === 1 ? 'y' : 'ies'}${errPart}` : '';
  }

  renderLogFilters(counts);

  if (!filtered.length) {
    root.innerHTML = feedEmptyState(
      logsFilter === 'all' ? 'No logs yet' : `No ${logsFilter} logs`,
      logsFilter === 'all'
        ? 'Log lines are pushed when scans, register, or heartbeat calls fail.'
        : 'Try another filter or wait for new collector events.'
    );
    return;
  }

  root.innerHTML = filtered.map((line) => `
    <article class="cn-log-entry ${logLevelClass(line.level)}">
      <div class="cn-log-entry-head">
        <div class="cn-log-entry-head-left">
          ${logLevelBadge(line.level)}
          <span class="cn-log-title">${escapeHtml(logEntryTitle(line.message))}</span>
        </div>
        <time class="cn-log-time">${fmtTime(line.created_at)}</time>
      </div>
      <pre class="cn-log-message">${escapeHtml(line.message)}</pre>
    </article>
  `).join('');
}

async function renderLogs(nodeId) {
  const root = document.getElementById('cn-logs-list');
  const hint = document.getElementById('cn-logs-hint');
  if (!root) return;

  root.innerHTML = loadingState('logs');
  if (hint) hint.style.display = 'none';

  try {
    const data = await fetchCollectorNodeLogs(nodeId);
    logsCache = data?.logs || [];
    logsFilter = 'all';

    if (hint) {
      hint.style.display = logsCache.length ? 'block' : 'none';
      hint.textContent = logsCache.length
        ? 'Live log stream from POST /api/collector/logs — refreshed with the page.'
        : '';
    }

    renderLogEntries();
  } catch (e) {
    logsCache = [];
    const meta = document.getElementById('cn-logs-meta');
    if (meta) meta.textContent = '';
    const bar = document.getElementById('cn-logs-filters');
    if (bar) {
      bar.style.display = 'none';
      bar.innerHTML = '';
    }
    root.innerHTML = feedEmptyState('Could not load logs', errorMessageFromCaught(e));
  }
}

async function selectNode(node) {
  selectedNodeId = node.node_id;
  renderNodesTable();

  const detail = document.getElementById('cn-detail');
  const title = document.getElementById('cn-detail-title');
  const sub = document.getElementById('cn-detail-subtitle');
  if (detail) detail.style.display = 'block';
  if (title) title.textContent = node.hostname || 'Collector node';
  if (sub) {
    const errNote = node.last_error ? ' · last error recorded' : '';
    sub.textContent =
      `${node.status === 'online' ? 'Connected' : 'Not connected'} · ` +
      `${node.scheduled_jobs || 0} scheduled job(s) · ` +
      `node ${node.node_id}${errNote}`;
  }

  scrollToNodeDetail();

  await Promise.all([
    renderRuns(node.node_id),
    renderActivity(node.node_id),
    renderLogs(node.node_id),
  ]);
}

async function loadNodes() {
  const tbody = document.getElementById('cn-nodes-tbody');
  if (tbody && !nodesCache.length) {
    tbody.innerHTML = '<tr><td colspan="7" style="color:var(--muted);padding:20px;">Loading…</td></tr>';
  }
  try {
    const data = await fetchCollectorNodes();
    nodesCache = data?.nodes || [];
    if (Number(data?.offline_threshold_sec) > 0) {
      fleetOfflineThresholdSec = Number(data.offline_threshold_sec);
    }
    updateStats(nodesCache);
    renderNodesTable();

    const subtitle = document.querySelector('#page-collector-nodes .subtitle');
    if (subtitle && fleetOfflineThresholdSec > 0) {
      const pushSec = Number(data?.push_interval_sec) > 0 ? Number(data.push_interval_sec) : 30;
      subtitle.innerHTML =
        `Live fleet from <code>ciscollector --setup-cron</code> — ` +
        `register on startup, health ping every ${pushSec}s, ` +
        `offline after ${fleetOfflineThresholdSec}s without ping. ` +
        `Scan results: <a href="#hosts" class="link-kloud">Hosts</a>.`;
    }

    const updated = document.getElementById('cn-updated-at');
    if (updated) {
      updated.textContent = data?.updated_at
        ? `Updated ${fmtTime(data.updated_at)}`
        : `Updated ${new Date().toLocaleTimeString()}`;
    }

    if (selectedNodeId) {
      const still = nodesCache.find((n) => n.node_id === selectedNodeId);
      if (still) {
        await selectNode(still);
      } else {
        selectedNodeId = null;
        logsCache = [];
        const detail = document.getElementById('cn-detail');
        if (detail) detail.style.display = 'none';
      }
    } else if (nodesCache.length === 1) {
      await selectNode(nodesCache[0]);
    }

    setMessage('');
  } catch (e) {
    setMessage(errorMessageFromCaught(e), true);
    if (tbody) {
      tbody.innerHTML = `<tr><td colspan="7" style="color:var(--critical);padding:20px;">${escapeHtml(errorMessageFromCaught(e))}</td></tr>`;
    }
  }
}

function stopRefresh() {
  if (refreshTimer) {
    clearInterval(refreshTimer);
    refreshTimer = null;
  }
}

export function stopCollectorNodesPage() {
  stopRefresh();
}

export async function initCollectorNodesPage() {
  stopRefresh();
  selectedNodeId = null;
  nodesCache = [];
  logsCache = [];
  logsFilter = 'all';
  nodesPager.page = 1;
  nodesPager.pageSize = 15;

  const refreshBtn = document.getElementById('cn-refresh-btn');
  if (refreshBtn && !refreshBtn.dataset.bound) {
    refreshBtn.dataset.bound = '1';
    refreshBtn.addEventListener('click', () => void loadNodes());
  }

  await loadNodes();
  refreshTimer = setInterval(() => {
    if (document.getElementById('page-collector-nodes')?.classList.contains('active')) {
      void loadNodes();
    }
  }, REFRESH_MS);
}
