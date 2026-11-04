import { getLogParserScanner } from '../api/services/scanner.js';
import {
  enrichScannerDatabases,
  fetchScannerTargets,
  populateScannerInstanceSelect,
  scannerHostKey,
} from '../utils/scanner-host-select.js';
import { paginateSlice, mountTablePagination } from '../utils/pagination.js';

const LOG_PARSER_HIDDEN_COMMANDS = new Set(['inactive_users']);
const logParserCmdPager = { page: 1, pageSize: 4 };
const logParserDetailPagers = {};
const logParserFilesPager = { page: 1, pageSize: 15 };
let logParserCache = null;

function escapeHtml(s) {
  return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function pagerKeyForCommand(cmd, index) {
  return String(cmd?.command || index).replace(/[^a-zA-Z0-9_-]/g, '_');
}

function visibleLogParserCommands(commands) {
  return (commands || []).filter((cmd) => !LOG_PARSER_HIDDEN_COMMANDS.has(cmd.command));
}

function summarizeLogParserCommands(commands) {
  let pass = 0;
  let warn = 0;
  let fail = 0;
  (commands || []).forEach((cmd) => {
    switch (cmd.status) {
      case 'pass':
        pass += 1;
        break;
      case 'warn':
        warn += 1;
        break;
      case 'fail':
        fail += 1;
        break;
      default:
        break;
    }
  });
  return { pass, warn, fail };
}

function statusBadgeClass(status) {
  switch (status) {
    case 'pass':
      return 'pass';
    case 'fail':
      return 'fail';
    case 'warn':
      return 'warn';
    default:
      return 'info';
  }
}

function formatTimeRange(meta) {
  const begin = (meta?.begin || '').trim();
  const end = (meta?.end || '').trim();
  if (begin && end) return begin + ' → ' + end;
  if (begin) return 'from ' + begin;
  if (end) return 'until ' + end;
  return '';
}

function formatDurationMs(ms) {
  const n = Number(ms);
  if (!Number.isFinite(n) || n < 0) return '—';
  if (n < 1000) return n + ' ms';
  return (n / 1000).toFixed(2) + ' s';
}

function renderDetailRowsTable(cmd, pagerKey) {
  const detailRows = cmd.detailRows || [];
  if (!detailRows.length) return '';

  if (!logParserDetailPagers[pagerKey]) {
    logParserDetailPagers[pagerKey] = { page: 1, pageSize: 15 };
  }
  const dp = logParserDetailPagers[pagerKey];
  const rowPg = paginateSlice(detailRows, dp.page, dp.pageSize);
  dp.page = rowPg.page;

  let html = '<div class="host-module-table data-log-table" style="margin-top:12px;"><table><thead><tr>' +
    '<th>Finding</th><th>Detail</th></tr></thead><tbody>';
  rowPg.items.forEach((row) => {
    html += '<tr><td class="host-col-title">' + escapeHtml(row.label) +
      '</td><td><code class="data-log-code">' + escapeHtml(row.value) + '</code></td></tr>';
  });
  html += '</tbody></table></div>';
  html += '<div class="table-pagination" id="log-parser-detail-' + pagerKey + '-pagination" hidden></div>';
  return { html, rowPg, pagerKey, dp };
}

function renderCommandCard(cmd, index) {
  const statusCls = statusBadgeClass(cmd.status);
  const pagerKey = pagerKeyForCommand(cmd, index);
  let detailHtml = '';
  let detailMeta = null;

  if (cmd.detailRows?.length) {
    detailMeta = renderDetailRowsTable(cmd, pagerKey);
    detailHtml = detailMeta.html;
  } else if (cmd.detailText) {
    detailHtml = '<pre class="data-log-code" style="margin-top:12px;white-space:pre-wrap;">' +
      escapeHtml(cmd.detailText) + '</pre>';
  }

  const cardHtml = '<article class="report-block log-parser-command-card" style="margin-bottom:16px;" data-cmd-key="' +
    escapeHtml(pagerKey) + '">' +
    '<div class="report-block-header" style="display:flex;justify-content:space-between;align-items:flex-start;gap:12px;">' +
    '<div><h2 style="margin:0;font-size:18px;">' + escapeHtml(cmd.title || cmd.command) + '</h2>' +
    '<p style="margin:4px 0 0;"><code>' + escapeHtml(cmd.command) + '</code></p></div>' +
    '<span class="hba-badge ' + statusCls + '">' + escapeHtml(cmd.status || 'info') + '</span></div>' +
    '<div class="report-block-body">' +
    '<p><strong>Parse status:</strong> ' + escapeHtml(cmd.parseStatus || '—') + '</p>' +
    '<p><strong>Result:</strong> ' + escapeHtml(cmd.result || '—') + '</p>' +
    detailHtml +
    '</div></article>';

  return { cardHtml, detailMeta };
}

function mountDetailPaginations(detailMetas) {
  (detailMetas || []).forEach(({ rowPg, pagerKey, dp }) => {
    if (!rowPg || rowPg.total <= rowPg.pageSize) return;
    const el = document.getElementById('log-parser-detail-' + pagerKey + '-pagination');
    mountTablePagination(el, {
      page: rowPg.page,
      totalPages: rowPg.totalPages,
      total: rowPg.total,
      start: rowPg.start,
      end: rowPg.end,
      pageSize: dp.pageSize,
      pageSizes: [15, 25, 50],
      onPage: (p) => {
        dp.page = p;
        renderLogParserResults(logParserCache);
      },
      onPageSize: (size) => {
        dp.pageSize = size;
        dp.page = 1;
        renderLogParserResults(logParserCache);
      },
    });
  });
}

function renderFileScanPanel(data) {
  const panel = document.getElementById('log-parser-files-panel');
  const tbody = document.getElementById('log-parser-files-tbody');
  const pagerEl = document.getElementById('log-parser-files-pagination');
  const files = data?.scanMeta?.files || [];
  if (!panel || !tbody) return;

  if (!files.length) {
    panel.hidden = true;
    tbody.innerHTML = '<tr><td colspan="4" style="color:var(--muted);">No file scan data.</td></tr>';
    mountTablePagination(pagerEl, {
      page: 1, totalPages: 1, total: 0, start: 0, end: 0, pageSize: logParserFilesPager.pageSize,
      onPage: () => {},
    });
    return;
  }

  panel.hidden = false;
  const pg = paginateSlice(files, logParserFilesPager.page, logParserFilesPager.pageSize);
  logParserFilesPager.page = pg.page;
  tbody.innerHTML = pg.items.map((f) => {
    const status = f.status || (f.scanned ? 'scanned' : 'skipped');
    const err = f.error ? ' — ' + f.error : '';
    return '<tr>' +
      '<td><code class="data-log-code">' + escapeHtml(f.fileName || '—') + '</code></td>' +
      '<td>' + escapeHtml(formatDurationMs(f.durationMs)) + '</td>' +
      '<td>' + (f.scanned ? 'Yes' : 'No') + '</td>' +
      '<td>' + escapeHtml(status + err) + '</td>' +
      '</tr>';
  }).join('');

  mountTablePagination(pagerEl, {
    page: pg.page,
    totalPages: pg.totalPages,
    total: pg.total,
    start: pg.start,
    end: pg.end,
    pageSize: logParserFilesPager.pageSize,
    pageSizes: [15, 25, 50],
    onPage: (p) => {
      logParserFilesPager.page = p;
      renderLogParserResults(logParserCache);
    },
    onPageSize: (size) => {
      logParserFilesPager.pageSize = size;
      logParserFilesPager.page = 1;
      renderLogParserResults(logParserCache);
    },
  });
}

function renderTerminalReportPanel(data) {
  const panel = document.getElementById('log-parser-terminal-panel');
  const pre = document.getElementById('log-parser-terminal-report');
  if (!panel || !pre) return;
  const text = (data?.terminalReport || '').trim();
  if (!text) {
    panel.hidden = true;
    pre.textContent = '';
    return;
  }
  panel.hidden = false;
  pre.textContent = text;
}

function renderLogParserResults(data) {
  logParserCache = data;
  const list = document.getElementById('log-parser-command-list');
  const pagerEl = document.getElementById('log-parser-command-pagination');
  if (!list) return;

  const allCommands = data?.commands || [];
  const commands = visibleLogParserCommands(allCommands);
  if (!commands.length) {
    let emptyMsg = data?.message || 'No log parser data. Add unique_ip, unused_lines, password_leak_scanner, or sql_injection_scan to scan_commands.';
    if (allCommands.length && allCommands.every((c) => c.command === 'inactive_users')) {
      emptyMsg = 'Inactive users are on the Inactive Users Report page. This page shows unique_ip, unused_lines, password_leak_scanner, and sql_injection_scan.';
    }
    list.innerHTML = '<p style="color:var(--muted);padding:16px;">' + escapeHtml(emptyMsg) + '</p>';
    mountTablePagination(pagerEl, {
      page: 1, totalPages: 1, total: 0, start: 0, end: 0, pageSize: logParserCmdPager.pageSize,
      onPage: () => {},
    });
  } else {
    const cmdPg = paginateSlice(commands, logParserCmdPager.page, logParserCmdPager.pageSize);
    logParserCmdPager.page = cmdPg.page;

    const detailMetas = [];
    list.innerHTML = cmdPg.items.map((cmd, i) => {
      const globalIndex = (cmdPg.page - 1) * cmdPg.pageSize + i;
      const { cardHtml, detailMeta } = renderCommandCard(cmd, globalIndex);
      if (detailMeta) detailMetas.push(detailMeta);
      return cardHtml;
    }).join('');

    mountDetailPaginations(detailMetas);

    mountTablePagination(pagerEl, {
      page: cmdPg.page,
      totalPages: cmdPg.totalPages,
      total: cmdPg.total,
      start: cmdPg.start,
      end: cmdPg.end,
      pageSize: logParserCmdPager.pageSize,
      pageSizes: [4, 8, 12],
      onPage: (p) => {
        logParserCmdPager.page = p;
        renderLogParserResults(logParserCache);
      },
      onPageSize: (size) => {
        logParserCmdPager.pageSize = size;
        logParserCmdPager.page = 1;
        renderLogParserResults(logParserCache);
      },
    });
  }

  const totalEl = document.getElementById('log-parser-stat-total');
  const passEl = document.getElementById('log-parser-stat-pass');
  const warnEl = document.getElementById('log-parser-stat-warn');
  const failEl = document.getElementById('log-parser-stat-fail');
  const foundEl = document.getElementById('log-parser-stat-files-found');
  const scannedEl = document.getElementById('log-parser-stat-files-scanned');
  const stats = summarizeLogParserCommands(commands);
  if (totalEl) totalEl.textContent = commands.length;
  if (passEl) passEl.textContent = stats.pass;
  if (warnEl) warnEl.textContent = stats.warn;
  if (failEl) failEl.textContent = stats.fail;
  if (foundEl) {
    foundEl.textContent = data?.scanMeta ? String(data.scanMeta.filesFound ?? 0) : '—';
  }
  if (scannedEl) {
    scannedEl.textContent = data?.scanMeta ? String(data.scanMeta.filesScanned ?? 0) : '—';
  }

  renderFileScanPanel(data);
  renderTerminalReportPanel(data);

  const metaEl = document.getElementById('log-parser-scan-meta');
  if (metaEl) {
    const parts = [];
    if (data.host) {
      parts.push('Live log parser findings for ' + data.host + ' from latest scan report');
    }
    const range = formatTimeRange(data?.scanMeta);
    if (range) parts.push('log filter ' + range);
    if (data?.scanMeta?.duration) parts.push('duration ' + data.scanMeta.duration);
    metaEl.textContent = parts.join(' · ');
  }
  const auditLink = document.getElementById('log-parser-host-audit-link');
  if (auditLink && data.host) auditLink.dataset.host = data.host;
}

let logParserBound = false;

async function loadLogParserForHost(host) {
  const list = document.getElementById('log-parser-command-list');
  if (list) {
    list.innerHTML = '<p style="color:var(--muted);padding:16px;">Loading log parser scan…</p>';
  }
  logParserCmdPager.page = 1;
  logParserFilesPager.page = 1;
  Object.keys(logParserDetailPagers).forEach((k) => delete logParserDetailPagers[k]);
  try {
    const data = await getLogParserScanner(host);
    renderLogParserResults(data);
  } catch (err) {
    logParserCache = null;
    if (list) list.innerHTML = '<p style="color:var(--danger);">' + escapeHtml(err.message) + '</p>';
  }
}

async function logParserHostKeyForInstance(instance) {
  const inst = await enrichScannerDatabases(instance);
  const db = inst?.databases?.[0]?.name || '';
  return scannerHostKey(instance, db);
}

export async function initLogParserPage() {
  const select = document.getElementById('log-parser-host-select');
  const keepHost = select?.value || '';

  try {
    const targets = await fetchScannerTargets();
    populateScannerInstanceSelect(select, targets, keepHost);
  } catch {
    /* keep existing options */
  }

  const instance = select?.value || '';
  const host = instance ? await logParserHostKeyForInstance(instance) : '';
  await loadLogParserForHost(host);

  if (!logParserBound && select) {
    logParserBound = true;
    select.addEventListener('change', async () => {
      const key = select.value ? await logParserHostKeyForInstance(select.value) : '';
      loadLogParserForHost(key);
    });
  }
}
