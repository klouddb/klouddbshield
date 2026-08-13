/** Shared HTML helpers for host detail modules. */

import {
  normalizeSslAuditStatus,
  renderSslAuditSummary,
  renderSslAuditCheckList,
  renderSslParamsPanel,
} from '../../utils/ssl-ui.js';
import { paginateSlice, mountTablePagination } from '../../utils/pagination.js';

const hostTablePagerState = new Map();

export function resetHostDetailTablePagers() {
  hostTablePagerState.clear();
}

function hostTablePager(key) {
  if (!hostTablePagerState.has(key)) {
    hostTablePagerState.set(key, { page: 1, pageSize: 15 });
  }
  return hostTablePagerState.get(key);
}

function scrollHostTableSection(root, anchorSelector) {
  if (!root) return;
  const el = root.querySelector(anchorSelector) || root.querySelector('.host-cis-table-wrap');
  if (!el) return;
  requestAnimationFrame(() => {
    el.scrollIntoView({ behavior: 'smooth', block: 'start' });
  });
}

function renderAuditRowHtml(r, rowIndex, idPrefix) {
  const rowId = idPrefix + '-detail-' + rowIndex;
  const crit = r.Critical ? ' host-cis-row--critical' : '';
  const label = [r.Control, r.Title].filter(Boolean).join(' ');
  const hasDetail = r.Description || r.FailReason || r.Rationale || r.Procedure || r.References;
  let html = '<tr class="host-cis-row' + crit + '">' +
    '<td class="host-cis-control-cell">' + escapeHtml(label) + '</td>' +
    cisStatusCell(r.Status) +
    '<td class="host-cis-icon-col">' +
    (hasDetail
      ? '<button type="button" class="host-cis-info-btn" aria-label="Show details" data-detail="' + rowId + '">ℹ</button>'
      : '<span style="color:var(--muted);">—</span>') +
    '</td></tr>';
  if (hasDetail) {
    html += '<tr class="host-cis-detail-row" id="' + rowId + '"><td colspan="3">' +
      '<div class="host-cis-detail-panel"><table class="host-cis-inner-table">' +
      '<tr><th>Description</th><td>' + nl2br(r.Description) + '</td></tr>';
    if (r.FailReason) {
      html += '<tr><th>Fail Reason</th><td>' + nl2br(r.FailReason) + '</td></tr>';
    }
    html += '<tr><th>Rationale</th><td>' + nl2br(r.Rationale) + '</td></tr>' +
      '<tr><th>Process to Validate</th><td>' + nl2br(r.Procedure) + '</td></tr>' +
      '<tr><th>References</th><td>' + nl2br(r.References) + '</td></tr></table></div></td></tr>';
  }
  return html;
}

function refreshHostAuditTable(root, pagerKey, rows, options) {
  const { idPrefix = 'host-audit', scrollToTop = false } = options;
  const pager = hostTablePager(pagerKey);
  const pg = paginateSlice(rows, pager.page, pager.pageSize);
  pager.page = pg.page;

  const tbody = root.querySelector('#' + CSS.escape(idPrefix + '-tbody'));
  if (tbody) {
    tbody.innerHTML = pg.items.map((r, i) => renderAuditRowHtml(r, pg.start - 1 + i, idPrefix)).join('');
  }

  const pagerEl = root.querySelector('#' + CSS.escape(idPrefix + '-pagination'));
  mountTablePagination(pagerEl, {
    page: pg.page,
    totalPages: pg.totalPages,
    total: pg.total,
    start: pg.start,
    end: pg.end,
    pageSize: pg.pageSize,
    onPage: (p) => {
      pager.page = p;
      refreshHostAuditTable(root, pagerKey, rows, { ...options, scrollToTop: true });
      bindHostCisInteractions(root);
    },
    onPageSize: (size) => {
      pager.pageSize = size;
      pager.page = 1;
      refreshHostAuditTable(root, pagerKey, rows, { ...options, scrollToTop: true });
      bindHostCisInteractions(root);
    },
  });

  if (scrollToTop) {
    scrollHostTableSection(root, '.host-cis-details-title');
  }
}

export function initHostAuditTable(root, rows, options = {}) {
  if (!root || !rows?.length) return;
  const idPrefix = options.idPrefix || 'host-audit';
  refreshHostAuditTable(root, idPrefix, rows, options);
}

function renderViolationRowHtml(c) {
  const status = String(c.status || 'Manual');
  const num = String(c.id ?? '').padStart(2, '0');
  return '<tr class="host-cis-row">' +
    '<td class="host-cis-num-col">' + escapeHtml(num) + '</td>' +
    '<td class="host-cis-control-cell">' + escapeHtml(c.title) + '</td>' +
    cisStatusCell(status) +
    '<td class="host-cis-meta-col">' + escapeHtml(c.source || '—') + '</td>' +
    '<td class="host-cis-detail-col">' + escapeHtml(c.details || '—') + '</td></tr>';
}

function refreshCriticalViolationsTable(root, rows, opts = {}) {
  const { scrollToTop = false } = opts;
  const pagerKey = 'host-critical';
  const pager = hostTablePager(pagerKey);
  const pg = paginateSlice(rows, pager.page, pager.pageSize);
  pager.page = pg.page;

  const tbody = root.querySelector('#host-critical-tbody');
  if (tbody) {
    tbody.innerHTML = pg.items.map(renderViolationRowHtml).join('');
  }

  const pagerEl = root.querySelector('#host-critical-pagination');
  mountTablePagination(pagerEl, {
    page: pg.page,
    totalPages: pg.totalPages,
    total: pg.total,
    start: pg.start,
    end: pg.end,
    pageSize: pg.pageSize,
    onPage: (p) => {
      pager.page = p;
      refreshCriticalViolationsTable(root, rows, { scrollToTop: true });
    },
    onPageSize: (size) => {
      pager.pageSize = size;
      pager.page = 1;
      refreshCriticalViolationsTable(root, rows, { scrollToTop: true });
    },
  });

  if (scrollToTop) {
    scrollHostTableSection(root, '.host-cis-details-header');
  }
}

export function initCriticalViolationsTable(root, checks) {
  const rows = automatedViolations(checks);
  if (!root || !rows.length) return;
  refreshCriticalViolationsTable(root, rows);
}

export function resolveCisAuditRows(cisResponses, mod) {
  return cisRowsFromData(cisResponses, mod);
}

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

export function statusIcon(status) {
  const s = (status || '').toLowerCase();
  if (s === 'pass' || s === 'passing') return 'icon-pass';
  if (s === 'fail' || s === 'failing') return 'icon-fail';
  return 'icon-fail';
}

function cellClass(i, total, statusCls) {
  if (i === 0) return 'host-col-check';
  if (i === total - 1) return 'host-col-result' + (statusCls ? ' ' + statusCls : '');
  return 'host-col-title';
}

function hbaDetailFromItem(item) {
  const failRows = item.FailRows || item.fail_rows || item.failrows;
  if (Array.isArray(failRows) && failRows.length) {
    return failRows.join('; ');
  }
  return item.Description || item.description || item.Procedure || item.procedure || '';
}

export function hbaChecksFromScanResult(hbaScanResult) {
  if (!Array.isArray(hbaScanResult) || !hbaScanResult.length) return [];
  return hbaScanResult.map((item, index) => {
    const rawStatus = item.Status || item.status || '';
    const status = String(rawStatus).toLowerCase() === 'pass' ? 'pass' : 'fail';
    const control = item.Control ?? item.control ?? index + 1;
    return {
      n: control,
      title: item.Title || item.title || '',
      desc: hbaDetailFromItem(item),
      status,
    };
  });
}

export function renderHbaCheckList(checks) {
  if (!checks?.length) {
    return '<p class="module-empty" style="color:var(--muted);font-size:13px;">No HBA checks in latest scan.</p>';
  }
  return '<div class="hba-check-list">' + checks.map(c => {
    const isPass = c.status === 'pass';
    const rowClass = isPass ? 'hba-check-row--pass' : 'hba-check-row--fail';
    return '<div class="hba-check-row ' + rowClass + '">' +
      '<div class="hba-check-bar ' + (isPass ? 'pass' : 'fail') + '"></div>' +
      '<div class="hba-check-main">' +
      '<div class="hba-check-num">HBA Check ' + escapeHtml(c.n) + '</div>' +
      '<div class="hba-check-title">' + escapeHtml(c.title) + '</div>' +
      (c.desc ? '<div class="hba-check-desc">' + escapeHtml(c.desc) + '</div>' : '') +
      '</div>' +
      '<div class="hba-check-status"><span class="hba-badge ' + (isPass ? 'pass' : 'fail') + '">' +
      (isPass ? 'Pass' : 'Fail') + '</span></div></div>';
  }).join('') + '</div>';
}

function hbaChecksFromModuleRows(mod) {
  if (!mod?.rows?.length) return [];
  return mod.rows.map((row, index) => {
    const check = row.cells?.[0] || '';
    const titleCell = row.cells?.[1] || '';
    const status = String(row.status || row.cells?.[2] || '').toLowerCase() === 'pass' ? 'pass' : 'fail';
    const nMatch = check.match(/(\d+)\s*$/);
    const n = nMatch ? parseInt(nMatch[1], 10) : index + 1;
    const sepIdx = titleCell.indexOf(' — ');
    return {
      n,
      title: sepIdx >= 0 ? titleCell.slice(0, sepIdx) : titleCell,
      desc: sepIdx >= 0 ? titleCell.slice(sepIdx + 3) : '',
      status,
    };
  });
}

export function renderPgHbaModule(mod, hbaScanResult, hbaChecks) {
  if (!mod?.available) {
    return '<p class="module-empty" style="color:var(--muted);font-size:13px;">' +
      (mod?.empty_reason || 'No HBA data for this module.') + '</p>';
  }
  const checks = (hbaChecks?.length ? hbaChecks : null)
    || hbaChecksFromScanResult(hbaScanResult)
    || hbaChecksFromModuleRows(mod);
  if (checks.length) {
    return renderHbaCheckList(checks);
  }
  return renderTable(mod, 'No HBA data for this module.');
}

function gucDriftStatusBadge(status) {
  if (status === 'drift') return 'badge-danger';
  if (status === 'missing') return 'badge-warning';
  if (status === 'version_updated') return 'badge-info';
  if (status === 'version_new') return 'badge-success';
  if (status === 'version_removed') return 'badge-muted';
  if (status === 'ignored') return 'badge-muted';
  return 'badge-muted';
}

function gucDriftStatusLabel(status) {
  if (status === 'drift') return 'Drift';
  if (status === 'missing') return 'Missing';
  if (status === 'version_updated') return 'Updated (version)';
  if (status === 'version_new') return 'New (version)';
  if (status === 'version_removed') return 'Removed (version)';
  if (status === 'ignored') return 'Ignored';
  return status || '—';
}

export function renderGucDriftModule(detail) {
  if (!detail) {
    return '<p class="module-empty" style="color:var(--muted);font-size:13px;">No GUC drift data.</p>';
  }
  const meta = [];
  if (detail.baseline_label) {
    meta.push('Baseline: <strong>' + escapeHtml(detail.baseline_label) + '</strong>');
  }
  meta.push('Drifted: <strong>' + (detail.drift_count ?? 0) + '</strong>');
  meta.push('Missing: <strong>' + (detail.missing_count ?? 0) + '</strong>');
  let html = '<p class="guc-host-drift-meta" style="font-size:12px;color:var(--muted);margin:0 0 12px;">' +
    meta.join(' · ') + ' · <span class="link" data-goto="guc-drift">Fleet GUC drift →</span></p>';

  if (!detail.available || detail.status === 'no_baseline' || detail.status === 'no_snapshot' || detail.status === 'ignored') {
    return html + '<p class="module-empty" style="color:var(--muted);font-size:13px;">' +
      escapeHtml(detail.empty_reason || 'No GUC drift data for this host.') + '</p>';
  }
  const activeRows = (detail.rows || []).filter((row) => !row.ignored);
  if (!activeRows.length) {
    return html + '<p class="module-empty" style="font-size:13px;color:var(--success);">' +
      escapeHtml(detail.empty_reason || 'All baseline keys match live SHOW ALL.') + '</p>';
  }
  const body = activeRows.map((row) =>
    '<tr><td><code>' + escapeHtml(row.guc) + '</code></td>' +
    '<td><span class="guc-val-live">' + escapeHtml(row.live || '—') + '</span></td>' +
    '<td><span class="guc-val-baseline">' + escapeHtml(row.baseline) + '</span></td>' +
    '<td><span class="badge ' + gucDriftStatusBadge(row.status) + '">' +
    escapeHtml(gucDriftStatusLabel(row.status)) + '</span></td></tr>'
  ).join('');
  return html + '<div class="host-module-table"><table><thead><tr>' +
    '<th>GUC</th><th>Live value</th><th>Baseline</th><th>Status</th></tr></thead><tbody>' +
    body + '</tbody></table></div>';
}

export function renderTable(mod, emptyMsg) {
  if (!mod?.available) {
    return '<p class="module-empty" style="color:var(--muted);font-size:13px;">' +
      (mod?.empty_reason || emptyMsg) + '</p>';
  }
  if (mod.summary?.length) {
    return mod.summary.map(kv =>
      '<p style="margin-bottom:8px;"><strong>' + escapeHtml(kv.key) + ':</strong> ' + escapeHtml(kv.value) + '</p>'
    ).join('');
  }
  if (!mod.rows?.length) {
    return '<p class="module-empty" style="color:var(--muted);font-size:13px;">No rows in latest scan.</p>';
  }
  const head = (mod.columns || []).map(c => '<th>' + escapeHtml(c) + '</th>').join('');
  const body = mod.rows.map(row => {
    const cls = row.status ? statusIcon(row.status) : '';
    const total = row.cells.length;
    return '<tr>' + row.cells.map((cell, i) => {
      const colCls = cellClass(i, total, i === total - 1 ? cls : '');
      return '<td class="' + colCls + '">' + escapeHtml(cell) + '</td>';
    }).join('') + '</tr>';
  }).join('');
  let html = '<div class="host-module-table"><table><thead><tr>' + head + '</tr></thead><tbody>' +
    body + '</tbody></table></div>';
  if (mod.callout) {
    html += '<div class="callout" style="margin-top:12px;">' + mod.callout + '</div>';
  }
  return html;
}

export function renderSectionScores(sections) {
  if (!sections?.length) return '';
  return '<div class="section-scores">' + sections.map(s =>
    '<div class="section-row"><span>' + escapeHtml(s.label) + '</span>' +
    '<div class="progress-bar"><div class="progress-fill" style="width:' + s.pct + '%"></div></div>' +
    '<span>' + s.pct + '%</span></div>'
  ).join('') + '</div>';
}

const CIS_SECTIONS = [
  { id: 0, name: 'Overall Score', color: '#373854' },
  { id: 1, name: 'Section 1 - Installation and Patches', color: '#EA4335' },
  { id: 2, name: 'Section 2 - Directory and File Permissions', color: '#FBBC05' },
  { id: 3, name: 'Section 3 - Logging Monitoring and Auditing', color: '#34A853' },
  { id: 4, name: 'Section 4 - User Access and Authorization', color: '#673AB7' },
  { id: 5, name: 'Section 5 - Connection and Login', color: '#4285F4' },
  { id: 6, name: 'Section 6 - Postgres Settings', color: '#9E379F' },
  { id: 7, name: 'Section 7 - Replication', color: '#7BB3FF' },
  { id: 8, name: 'Section 8 - Special Configuration Considerations', color: '#FF6F69' },
];

function nl2br(text) {
  return escapeHtml(text).replace(/\n/g, '<br>');
}

function normalizeCis(raw) {
  if (!raw || typeof raw !== 'object') return null;
  return {
    Control: raw.Control ?? raw.control ?? '',
    Title: raw.Title ?? raw.title ?? '',
    Status: raw.Status ?? raw.status ?? '',
    Description: raw.Description ?? raw.description ?? '',
    FailReason: raw.FailReason ?? raw.fail_reason ?? '',
    Rationale: raw.Rationale ?? raw.rationale ?? '',
    Procedure: raw.Procedure ?? raw.procedure ?? '',
    References: raw.References ?? raw.references ?? '',
    Critical: !!(raw.Critical ?? raw.critical),
  };
}

function cisRowsFromData(cisResponses, mod) {
  const fromTop = (cisResponses || []).map(normalizeCis).filter(Boolean);
  if (fromTop.length) return fromTop;
  const rows = mod?.rows || [];
  return rows.map(row => normalizeCis({
    Control: row.cells?.[0],
    Title: row.cells?.[1],
    Status: row.status || row.cells?.[2],
  })).filter(r => r.Control || r.Title);
}

function cisSectionScores(cis) {
  const scores = CIS_SECTIONS.map(() => ({ pass: 0, fail: 0 }));
  cis.forEach(r => {
    const prefix = parseInt(String(r.Control).split('.')[0], 10);
    if (Number.isNaN(prefix) || prefix < 0 || prefix > 8) return;
    const bucket = scores[prefix] || scores[0];
    if (String(r.Status).toLowerCase() === 'pass') {
      bucket.pass++;
      scores[0].pass++;
    } else if (String(r.Status).toLowerCase() === 'fail') {
      bucket.fail++;
      scores[0].fail++;
    }
  });
  return scores;
}

function cisStatusCell(status) {
  const s = String(status).toLowerCase();
  if (s === 'pass') {
    return '<td class="host-cis-icon-col host-cis-pass" aria-label="Pass"><span class="host-cis-status-icon">✓</span> Pass</td>';
  }
  if (s === 'fail') {
    return '<td class="host-cis-icon-col host-cis-fail" aria-label="Fail"><span class="host-cis-status-icon">✗</span> Fail</td>';
  }
  if (s === 'manual' || s === 'unknown' || !s) {
    return '<td class="host-cis-icon-col host-cis-manual" aria-label="Manual"><span class="host-cis-status-icon">◎</span> Manual</td>';
  }
  return '<td class="host-cis-icon-col host-cis-manual" aria-label="' + escapeHtml(status) + '"><span class="host-cis-status-icon">◎</span> ' + escapeHtml(status) + '</td>';
}

function sectionLabel(sectionId) {
  const sec = CIS_SECTIONS.find(s => s.id === sectionId);
  return sec ? sec.name : 'Section ' + sectionId;
}

function sectionColor(sectionId) {
  const sec = CIS_SECTIONS.find(s => s.id === sectionId);
  return sec ? sec.color : '#556080';
}

/** Build summary scores from scan rows only — sections with zero checks are omitted. */
function summaryFromRows(rows) {
  const sectionMap = new Map();
  let overallPass = 0;
  let overallFail = 0;

  rows.forEach(r => {
    const prefix = parseInt(String(r.Control).split('.')[0], 10);
    if (Number.isNaN(prefix) || prefix < 1) return;
    const status = String(r.Status).toLowerCase();
    if (status !== 'pass' && status !== 'fail') return;

    if (!sectionMap.has(prefix)) sectionMap.set(prefix, { pass: 0, fail: 0 });
    const bucket = sectionMap.get(prefix);
    if (status === 'pass') {
      bucket.pass++;
      overallPass++;
    } else {
      bucket.fail++;
      overallFail++;
    }
  });

  const sections = [...sectionMap.entries()]
    .sort((a, b) => a[0] - b[0])
    .map(([id, s]) => ({ id, pass: s.pass, fail: s.fail }));

  return { sections, overallPass, overallFail };
}

function renderAuditSummary(rows) {
  const { sections, overallPass, overallFail } = summaryFromRows(rows);
  const oTotal = overallPass + overallFail;
  if (!oTotal) return '';

  let html = '<div class="host-cis-summary"><h4 class="host-cis-summary-title">Summary</h4>';
  sections.forEach(s => {
    const total = s.pass + s.fail;
    const pct = (s.pass / total) * 100;
    html += '<div class="host-cis-progress">' +
      '<div class="host-cis-progress-label"><span>' + escapeHtml(sectionLabel(s.id)) + '</span>' +
      '<span>' + s.pass + '/' + total + ' (' + pct.toFixed(1) + '%)</span></div>' +
      '<div class="host-cis-progress-track"><div class="host-cis-progress-fill" style="width:' + pct + '%;background:' + sectionColor(s.id) + '"></div></div></div>';
  });
  const oPct = (overallPass / oTotal) * 100;
  html += '<div class="host-cis-progress host-cis-progress--overall">' +
    '<div class="host-cis-progress-label"><span>' + escapeHtml(sectionLabel(0)) + '</span>' +
    '<span>' + overallPass + '/' + oTotal + ' (' + oPct.toFixed(1) + '%)</span></div>' +
    '<div class="host-cis-progress-track"><div class="host-cis-progress-fill" style="width:' + oPct + '%;background:' + sectionColor(0) + '"></div></div></div>';
  html += '</div>';
  return html;
}

function renderCisSummary(scores) {
  let html = '<div class="host-cis-summary"><h4 class="host-cis-summary-title">Summary</h4>';
  CIS_SECTIONS.slice(1).forEach(sec => {
    const s = scores[sec.id];
    const total = s.pass + s.fail;
    if (!total) return;
    const pct = (s.pass / total) * 100;
    html += '<div class="host-cis-progress">' +
      '<div class="host-cis-progress-label"><span>' + escapeHtml(sec.name) + '</span>' +
      '<span>' + s.pass + '/' + total + ' (' + pct.toFixed(1) + '%)</span></div>' +
      '<div class="host-cis-progress-track"><div class="host-cis-progress-fill" style="width:' + pct + '%;background:' + sec.color + '"></div></div></div>';
  });
  const overall = scores[0];
  const oTotal = overall.pass + overall.fail;
  if (oTotal) {
    const oPct = (overall.pass / oTotal) * 100;
    html += '<div class="host-cis-progress host-cis-progress--overall">' +
      '<div class="host-cis-progress-label"><span>' + escapeHtml(CIS_SECTIONS[0].name) + '</span>' +
      '<span>' + overall.pass + '/' + oTotal + ' (' + oPct.toFixed(1) + '%)</span></div>' +
      '<div class="host-cis-progress-track"><div class="host-cis-progress-fill" style="width:' + oPct + '%;background:' + CIS_SECTIONS[0].color + '"></div></div></div>';
  }
  html += '</div>';
  return html;
}

function enrichModuleRows(mod, cisResponses) {
  if (!mod?.rows?.length) return [];
  const lookup = new Map();
  (cisResponses || []).forEach(raw => {
    const c = normalizeCis(raw);
    if (c?.Control) lookup.set(String(c.Control).trim(), c);
  });
  return mod.rows.map(row => {
    const control = String(row.cells?.[0] ?? '').trim();
    const hit = lookup.get(control);
    if (hit) return { ...hit };
    return normalizeCis({
      Control: row.cells?.[0],
      Title: row.cells?.[1],
      Status: row.status || row.cells?.[2],
    });
  }).filter(r => r && (r.Control || r.Title));
}

function renderHostAuditTable(rows, options = {}) {
  const {
    showSummary = false,
    idPrefix = 'host-audit',
    emptyMsg = 'No data in latest scan.',
    controlLabel = 'Control',
  } = options;

  if (!rows.length) {
    return '<p class="module-empty" style="color:var(--muted);font-size:13px;">' + escapeHtml(emptyMsg) + '</p>';
  }

  let html = '<div class="host-cis-report">';
  if (showSummary) {
    html += renderAuditSummary(rows);
  }
  html += '<h4 class="host-cis-details-title">Control Details</h4>' +
    '<div class="host-cis-toolbar">' +
    '<button type="button" class="host-cis-expand-all">Expand All</button>' +
    '<div class="host-cis-legend"><span class="host-cis-pass">✓ Pass</span>' +
    '<span class="host-cis-fail">✗ Fail</span>' +
    '<span class="host-cis-manual">◎ Manual</span></div></div>' +
    '<div class="host-cis-table-wrap"><table class="host-cis-table"><thead><tr>' +
    '<th>' + escapeHtml(controlLabel) + '</th><th class="host-cis-icon-col">Result</th><th class="host-cis-icon-col">Details</th></tr></thead>' +
    '<tbody id="' + escapeHtml(idPrefix) + '-tbody"></tbody></table>' +
    '<div class="table-pagination host-cis-pagination" id="' + escapeHtml(idPrefix) + '-pagination" hidden></div></div></div>';
  return html;
}

function isAutomatedViolationStatus(status) {
  const s = String(status || '').toLowerCase();
  return s === 'pass' || s === 'fail';
}

function automatedViolations(checks) {
  return (checks || []).filter((c) => isAutomatedViolationStatus(c.status));
}

function renderCriticalViolationsSummary(checks) {
  let pass = 0;
  let fail = 0;
  checks.forEach((c) => {
    const s = String(c.status).toLowerCase();
    if (s === 'pass') pass++;
    else if (s === 'fail') fail++;
  });
  const total = checks.length;
  if (!total) return '';

  const passPct = (pass / total) * 100;
  const failPct = (fail / total) * 100;
  let html = '<div class="host-cis-summary"><h4 class="host-cis-summary-title">Summary</h4>' +
    '<div class="host-cis-progress">' +
    '<div class="host-cis-progress-label"><span>Passing Checks</span><span>' + pass + '/' + total + ' (' + passPct.toFixed(1) + '%)</span></div>' +
    '<div class="host-cis-progress-track"><div class="host-cis-progress-fill" style="width:' + passPct + '%;background:var(--success)"></div></div></div>' +
    '<div class="host-cis-progress">' +
    '<div class="host-cis-progress-label"><span>Failing Checks</span><span>' + fail + '/' + total + ' (' + failPct.toFixed(1) + '%)</span></div>' +
    '<div class="host-cis-progress-track"><div class="host-cis-progress-fill" style="width:' + failPct + '%;background:var(--danger)"></div></div></div>';
  html += '</div>';
  return html;
}

export function renderCriticalViolationsModule(checks, failedCount) {
  if (!checks?.length) {
    return '<p class="module-empty" style="color:var(--muted);font-size:13px;">No critical violation data in latest scan.</p>';
  }

  const automated = automatedViolations(checks);
  if (!automated.length) {
    return '<p class="module-empty" style="color:var(--muted);font-size:13px;">No automated critical violations in latest scan.</p>';
  }

  let html = '<div class="host-cis-report">';
  html += renderCriticalViolationsSummary(automated);
  html += '<div class="host-cis-details-header">' +
    '<h4 class="host-cis-details-title">Violation Details</h4>' +
    '<div class="host-cis-legend"><span class="host-cis-pass">✓ Pass</span>' +
    '<span class="host-cis-fail">✗ Fail</span></div></div>' +
    '<div class="host-cis-table-wrap"><table class="host-cis-table"><thead><tr>' +
    '<th class="host-cis-num-col">Check</th><th>Violation</th><th class="host-cis-icon-col">Result</th>' +
    '<th class="host-cis-meta-col">Source</th><th class="host-cis-detail-col">Details</th></tr></thead>' +
    '<tbody id="host-critical-tbody"></tbody></table>' +
    '<div class="table-pagination host-cis-pagination" id="host-critical-pagination" hidden></div></div></div>';
  return html;
}

/** @deprecated use renderCriticalViolationsModule */
export const renderCriticalChecksModule = renderCriticalViolationsModule;

export function renderCisAuditModule(cisResponses, mod) {
  const cis = cisRowsFromData(cisResponses, mod);
  return renderHostAuditTable(cis, {
    showSummary: true,
    idPrefix: 'host-cis',
    emptyMsg: 'No CIS data in latest scan.',
    controlLabel: 'Control',
  });
}

export function renderConfigAuditModule(cisResponses, mod, options = {}) {
  if (!mod?.available) {
    return '<p class="module-empty" style="color:var(--muted);font-size:13px;">' +
      escapeHtml(mod?.empty_reason || options.emptyMsg || 'No configuration data in latest scan.') + '</p>';
  }
  const rows = enrichModuleRows(mod, cisResponses);
  return renderHostAuditTable(rows, {
    showSummary: true,
    idPrefix: options.idPrefix || 'host-config',
    emptyMsg: options.emptyMsg || 'No configuration checks in latest scan.',
    controlLabel: options.controlLabel || 'GUC / Check',
  });
}

function userReportSections(userData) {
  if (userData == null || userData === '') return [];
  if (typeof userData === 'string') {
    const trimmed = userData.trim();
    if (!trimmed) return [];
    try {
      return userReportSections(JSON.parse(trimmed));
    } catch {
      return [];
    }
  }
  if (Array.isArray(userData)) return userData;
  if (typeof userData === 'object') {
    const tables = userData.Tables || userData.tables;
    if (Array.isArray(tables)) return tables;
    if (userData.Data || userData.data || userData.Title || userData.title) return [userData];
  }
  return [];
}

function formatUserCell(cell) {
  if (cell === true || cell === false) {
    const cls = cell ? 'host-users-bool--true' : 'host-users-bool--false';
    return '<span class="host-users-bool ' + cls + '">' + (cell ? 'true' : 'false') + '</span>';
  }
  if (cell == null) return '';
  return escapeHtml(String(cell));
}

function renderUserSectionBody(data) {
  if (!data || typeof data !== 'object') {
    return '<p class="module-empty" style="color:var(--muted);font-size:13px;">No data for this section.</p>';
  }
  const desc = data.Description || data.description || '';
  const list = data.List || data.list || [];
  const table = data.Table || data.table;
  let html = '';
  if (desc) html += '<p class="host-users-note">' + escapeHtml(desc) + '</p>';
  if (list.length) {
    html += '<ul class="host-users-list">' + list.map(item => '<li>' + escapeHtml(item) + '</li>').join('') + '</ul>';
  }
  if (table) {
    const cols = table.Columns || table.columns || [];
    const rows = table.Rows || table.rows || [];
    html += '<div class="host-users-data-table"><table><thead><tr>';
    cols.forEach(c => { html += '<th>' + escapeHtml(c) + '</th>'; });
    html += '</tr></thead><tbody>';
    rows.forEach(row => {
      html += '<tr>';
      (Array.isArray(row) ? row : []).forEach(cell => {
        html += '<td>' + formatUserCell(cell) + '</td>';
      });
      html += '</tr>';
    });
    html += '</tbody></table></div>';
  }
  return html || '<p class="module-empty" style="color:var(--muted);font-size:13px;">No data for this section.</p>';
}

export function renderUsersReportModule(userData, mod) {
  let sections = userReportSections(userData);
  if (!sections.length && mod?.summary?.length) {
    const kv = mod.summary.find(s => /^users report$/i.test(s.key || s.Key || ''));
    if (kv) sections = userReportSections(kv.value ?? kv.Value);
  }
  if (!sections.length) {
    return '<p class="module-empty" style="color:var(--muted);font-size:13px;">No users report in latest scan.</p>';
  }
  let html = '<div class="host-cis-report">' +
    '<div class="host-cis-toolbar">' +
    '<button type="button" class="host-cis-expand-all">Expand All</button></div>' +
    '<div class="host-cis-table-wrap"><table class="host-cis-table"><thead><tr>' +
    '<th>Title</th><th class="host-cis-icon-col">Details</th></tr></thead><tbody>';
  sections.forEach((sec, i) => {
    const title = sec.Title || sec.title || 'Report';
    const rowId = 'host-users-' + i;
    const body = sec.Data || sec.data;
    const hasContent = body && (body.Description || body.List?.length || body.Table || body.table);
    html += '<tr class="host-cis-row">' +
      '<td class="host-cis-control-cell">' + escapeHtml(title) + '</td>' +
      '<td class="host-cis-icon-col">' +
      (hasContent
        ? '<button type="button" class="host-cis-info-btn" aria-label="Show details" data-detail="' + rowId + '">ℹ</button>'
        : '<span style="color:var(--muted);">—</span>') +
      '</td></tr>';
    if (hasContent) {
      html += '<tr class="host-cis-detail-row" id="' + rowId + '"><td colspan="2">' +
        '<div class="host-cis-detail-panel">' + renderUserSectionBody(body) + '</div></td></tr>';
    }
  });
  html += '</tbody></table></div></div>';
  return html;
}

const SSL_CIS_CONTROLS = new Set(['6.7', '6.8', '6.9', '6.10']);

function isSslRelatedText(text) {
  const t = String(text || '').toLowerCase();
  return t.includes('ssl') || t.includes('tls') || t.includes('hostssl') || t.includes('certificate');
}

function normalizeCheckStatus(raw) {
  return normalizeSslAuditStatus(raw) === 'pass' ? 'pass' : 'fail';
}

function filterSslCisResponses(cisResponses) {
  if (!Array.isArray(cisResponses)) return [];
  return cisResponses
    .map(r => normalizeCis(r))
    .filter(r => r && SSL_CIS_CONTROLS.has(String(r.Control || '').trim()));
}

function sslScanFromData(sslScanResult, mod) {
  if (sslScanResult && typeof sslScanResult === 'object') {
    return sslScanResult;
  }
  return null;
}

function sslAuditCells(sslData) {
  if (!sslData) return [];
  if (Array.isArray(sslData.cells)) return sslData.cells;
  if (Array.isArray(sslData.Cells)) {
    return sslData.Cells.map(c => ({
      title: c.Title || c.title || '',
      status: c.Status || c.status || '',
      message: c.Message || c.message || '',
    }));
  }
  return [];
}

function sslParamsFromData(sslData) {
  if (!sslData) return {};
  return sslData.ssl_params || sslData.sslParams || sslData.SSLParams || {};
}

function sslHbaLinesFromData(sslData) {
  if (!sslData) return [];
  return sslData.hba_lines || sslData.hbaLines || sslData.HBALines || [];
}

function sslCheckKey(source, id) {
  return source + ':' + id;
}

function collectSslChecks(mod, hbaScanResult, cisResponses) {
  const map = new Map();
  const put = (check) => {
    const key = sslCheckKey(check.source, check.id);
    const existing = map.get(key);
    if (!existing
      || (check.failLines?.length && !existing.failLines?.length)
      || (check.desc?.length > (existing.desc?.length || 0))) {
      map.set(key, check);
    }
  };

  if (Array.isArray(hbaScanResult)) {
    hbaScanResult.forEach((item, index) => {
      const title = item.Title || item.title || '';
      const desc = item.Description || item.description || '';
      if (!isSslRelatedText(title + ' ' + desc)) return;
      const control = item.Control ?? item.control ?? index + 1;
      const failRows = item.FailRows || item.fail_rows || item.failrows;
      put({
        source: 'hba',
        id: String(control),
        label: 'HBA Check ' + control,
        title,
        desc,
        procedure: item.Procedure || item.procedure || '',
        status: normalizeCheckStatus(item.Status || item.status),
        failLines: Array.isArray(failRows) ? failRows.map(String) : [],
      });
    });
  }

  if (Array.isArray(cisResponses)) {
    cisResponses.forEach((item) => {
      const title = item.title || item.Title || '';
      const control = item.control || item.Control || '';
      const blob = (control + ' ' + title + ' ' + (item.description || item.Description || '')).toLowerCase();
      if (!isSslRelatedText(blob)) return;
      const failReason = item.fail_reason || item.FailReason || item.case_fail_reason || item.CaseFailReason || '';
      put({
        source: 'cis',
        id: String(control || title),
        label: control ? 'CIS ' + control : 'CIS',
        title,
        desc: failReason || item.description || item.Description || '',
        procedure: item.procedure || item.Procedure || '',
        status: normalizeCheckStatus(item.status || item.Status),
        failLines: [],
      });
    });
  }

  if (mod?.rows?.length) {
    mod.rows.forEach((row, index) => {
      const checkCell = row.cells?.[0] || '';
      const titleCell = row.cells?.[1] || '';
      if (!isSslRelatedText(checkCell + ' ' + titleCell)) return;
      const hbaMatch = checkCell.match(/hba\s*(\d+)/i);
      const cisMatch = checkCell.match(/^([\d.]+)$/);
      const source = hbaMatch ? 'hba' : (cisMatch ? 'cis' : 'ssl');
      const id = hbaMatch ? hbaMatch[1] : (cisMatch ? cisMatch[1] : String(index + 1));
      if (map.has(sslCheckKey(source, id))) return;
      const sepIdx = titleCell.indexOf(' — ');
      put({
        source,
        id,
        label: checkCell,
        title: sepIdx >= 0 ? titleCell.slice(0, sepIdx) : titleCell,
        desc: sepIdx >= 0 ? titleCell.slice(sepIdx + 3) : '',
        procedure: '',
        status: normalizeCheckStatus(row.status || row.cells?.[2]),
        failLines: [],
      });
    });
  }

  const order = { hba: 0, cis: 1, ssl: 2 };
  return [...map.values()].sort((a, b) => {
    const d = (order[a.source] ?? 9) - (order[b.source] ?? 9);
    if (d !== 0) return d;
    return String(a.id).localeCompare(String(b.id), undefined, { numeric: true });
  });
}

export function renderSslTlsModule(mod, hbaScanResult, cisResponses, sslScanResult) {
  const sslCis = filterSslCisResponses(cisResponses);
  const sslData = sslScanFromData(sslScanResult, mod);
  const auditCells = sslAuditCells(sslData).map(c => ({
    title: c.title || c.Title || '',
    status: normalizeSslAuditStatus(c.status || c.Status),
    message: c.message || c.Message || c.desc || c.Desc || '',
  }));
  const params = sslParamsFromData(sslData);
  const hbaLines = sslHbaLinesFromData(sslData);

  if (!sslCis.length && !auditCells.length && !Object.keys(params).length) {
    if (!mod?.available) {
      return '<p class="module-empty" style="color:var(--muted);font-size:13px;">' +
        escapeHtml(mod?.empty_reason || 'No SSL/TLS data for this module.') + '</p>';
    }
    const legacy = collectSslChecks(mod, hbaScanResult, cisResponses);
    if (!legacy.length) {
      return '<p class="module-empty" style="color:var(--muted);font-size:13px;">No SSL/TLS checks in latest scan.</p>';
    }
  }

  let html = '<div class="ssl-module">' +
    '<p class="ssl-module-meta">htmlreport: <strong>SSL audit Report</strong> · CIS §6.7–6.10 · <span class="link" data-goto="ssl-scanner">Open SSL scanner →</span></p>';

  if (sslCis.length) {
    html += '<h4 class="ssl-section-title">CIS SSL controls (6.7–6.10)</h4>' +
      renderHostAuditTable(sslCis, { idPrefix: 'host-ssl-cis', emptyMsg: 'No CIS SSL controls in latest scan.' });
  }

  if (auditCells.length || hbaLines.length) {
    html += '<h4 class="ssl-section-title">SSL audit checks</h4>';
    if (auditCells.length) html += renderSslAuditSummary(auditCells);
    html += renderSslAuditCheckList(auditCells, hbaLines);
  }

  html += renderSslParamsPanel(params, { title: 'SSL Parameters', layout: 'compact' });
  return html + '</div>';
}

function accessResultClass(status, text) {
  const s = String(status || text).toLowerCase();
  if (s === 'pass' || s === 'ok') return 'host-cis-pass';
  if (s === 'fail' || s.includes('fail')) return 'host-cis-fail';
  if (s === 'partial' || s === 'warn' || s === 'warning') return 'host-cis-manual';
  return '';
}

function accessResultBadgeClass(status, text) {
  const cls = accessResultClass(status, text);
  if (cls === 'host-cis-pass') return 'pass';
  if (cls === 'host-cis-manual') return 'warn';
  if (cls === 'host-cis-fail') return 'fail';
  return 'neutral';
}

function renderAccessSummary(rows) {
  const pass = rows.filter(r => accessResultClass(r.status, r.cells?.[2]) === 'host-cis-pass').length;
  const fail = rows.length - pass;
  const total = rows.length;
  const passPct = total ? Math.round((pass / total) * 100) : 0;
  const overall = fail > 0 ? 'fail' : 'pass';
  return '<div class="access-summary">' +
    '<div class="access-summary-stats">' +
    '<span class="access-summary-pill access-summary-pill--pass">' + pass + ' pass</span>' +
    '<span class="access-summary-pill access-summary-pill--fail">' + fail + ' fail</span>' +
    '<span class="access-summary-total">' + total + ' connection checks</span>' +
    '</div>' +
    '<div class="access-summary-track">' +
    '<div class="access-summary-fill access-summary-fill--' + overall + '" style="width:' + passPct + '%"></div>' +
    '</div></div>';
}

function renderAccessCheckList(rows) {
  return '<div class="hba-check-list access-check-list">' + rows.map(row => {
    const area = row.cells?.[0] || '—';
    const check = row.cells?.[1] || '';
    const result = row.cells?.[2] || '—';
    const badgeCls = accessResultBadgeClass(row.status, result);
    const rowCls = badgeCls === 'pass' ? 'hba-check-row--pass' : 'hba-check-row--fail';
    return '<div class="hba-check-row ' + rowCls + '">' +
      '<div class="hba-check-bar ' + (badgeCls === 'pass' ? 'pass' : badgeCls === 'warn' ? 'warn' : 'fail') + '"></div>' +
      '<div class="hba-check-main">' +
      '<div class="access-check-area">' + escapeHtml(area) + '</div>' +
      '<div class="hba-check-title">' + escapeHtml(check) + '</div>' +
      '</div>' +
      '<div class="hba-check-status">' +
      '<span class="access-result-badge ' + badgeCls + '">' + escapeHtml(result) + '</span>' +
      '</div></div>';
  }).join('') + '</div>';
}

export function renderAccessCheckTable(mod, emptyMsg, options = {}) {
  if (!mod?.available) {
    return '<p class="module-empty" style="color:var(--muted);font-size:13px;">' +
      escapeHtml(mod?.empty_reason || emptyMsg) + '</p>';
  }
  if (!mod.rows?.length) {
    return '<p class="module-empty" style="color:var(--muted);font-size:13px;">No rows in latest scan.</p>';
  }
  let html = '<div class="access-check-module">';
  if (options.meta) {
    html += '<p class="access-check-meta">' + options.meta + '</p>';
  }
  html += renderAccessSummary(mod.rows) + renderAccessCheckList(mod.rows);
  if (mod.callout) {
    html += '<div class="callout access-check-callout">' + escapeHtml(mod.callout) + '</div>';
  }
  html += '</div>';
  return html;
}

function renderDataModuleShell(options) {
  const statusCls = options.status === 'ok' ? 'ok' : options.status === 'warn' ? 'warn' : 'empty';
  return '<div class="data-log-card-inner">' +
    '<div class="data-log-card-head">' +
    '<div class="data-log-card-icon data-log-card-icon--' + escapeHtml(options.iconKey) + '" aria-hidden="true"></div>' +
    '<div class="data-log-card-titles">' +
    '<h3 class="data-log-card-title">' + escapeHtml(options.title) + '</h3>' +
    '<p class="data-log-card-meta">' + options.meta + '</p>' +
    '</div>' +
    '<span class="data-log-status data-log-status--' + statusCls + '">' + escapeHtml(options.statusLabel) + '</span>' +
    '</div>' +
    '<div class="data-log-card-body">' + options.body + '</div>' +
    (options.footer ? '<div class="data-log-card-foot">' + options.footer + '</div>' : '') +
    '</div>';
}

function renderDataEmptyState(message, actionHtml) {
  return '<div class="data-empty-state">' +
    '<p class="data-empty-state-text">' + escapeHtml(message) + '</p>' +
    (actionHtml ? '<div class="data-empty-state-actions">' + actionHtml + '</div>' : '') +
    '</div>';
}

function logParserResultBadge(status, text) {
  const cls = accessResultBadgeClass(status, text);
  return '<span class="access-result-badge ' + cls + '">' + escapeHtml(text) + '</span>';
}

export function renderPiiModule(mod) {
  const hasRows = mod?.available && mod.rows?.length;
  const ranWithoutFindings = mod?.available && !hasRows && mod?.empty_reason;
  const body = hasRows
    ? renderTable(mod, 'No PII data in latest scan.')
    : renderDataEmptyState(
      mod?.empty_reason || 'PII scan results load from pii_report_json — run PII scanner (menu 4).',
      ranWithoutFindings
        ? '<a class="link data-log-action" href="#" data-goto="pii-scanner">Open PII scanner →</a>'
        : '<a class="link data-log-action" href="#" data-goto="pii-scanner">Open PII scanner →</a>',
    );
  return renderDataModuleShell({
    iconKey: 'pii',
    title: 'PII scan',
    meta: 'htmlreport: <strong>PII Scanner Report</strong> · menu 4',
    status: hasRows ? 'ok' : (ranWithoutFindings ? 'warn' : 'empty'),
    statusLabel: hasRows
      ? mod.rows.length + ' findings'
      : (ranWithoutFindings ? 'Scan completed' : 'Not run'),
    body,
    footer: (hasRows || ranWithoutFindings)
      ? '<a class="link data-log-action" href="#" data-goto="pii-scanner">View full PII report →</a>'
      : '',
  });
}

export function renderLogParserModule(mod) {
  const hasRows = mod?.available && mod.rows?.length;
  let body;
  if (hasRows) {
    const cols = mod.columns || ['Command', 'Report block', 'Result'];
    const lastIdx = cols.length - 1;
    let table = '<div class="host-module-table data-log-table"><table><thead><tr>';
    cols.forEach(c => { table += '<th>' + escapeHtml(c) + '</th>'; });
    table += '</tr></thead><tbody>';
    mod.rows.forEach(row => {
      table += '<tr>';
      row.cells.forEach((cell, i) => {
        if (i === lastIdx) {
          table += '<td class="host-col-result">' + logParserResultBadge(row.status, cell) + '</td>';
        } else if (i === 0) {
          table += '<td class="host-col-check"><code class="data-log-code">' + escapeHtml(cell) + '</code></td>';
        } else {
          table += '<td class="host-col-title">' + escapeHtml(cell) + '</td>';
        }
      });
      table += '</tr>';
    });
    table += '</tbody></table></div>';
    if (mod.callout) {
      table += '<div class="callout data-log-callout">' + escapeHtml(mod.callout) + '</div>';
    }
    body = table;
  } else {
    body = renderDataEmptyState(
      mod?.empty_reason || 'No matching checks in the latest scan report.',
      '<a class="link data-log-action" href="#" data-goto="log-parser">Open log parser scan →</a>',
    );
  }
  const failCount = hasRows
    ? mod.rows.filter(r => accessResultClass(r.status, r.cells?.[2]) === 'host-cis-fail').length
    : 0;
  return renderDataModuleShell({
    iconKey: 'log',
    title: 'pg_log parser',
    meta: 'htmlreport: <strong>Log Parser</strong> · <code>logparser.tmpl</code>',
    status: hasRows ? (failCount > 0 ? 'warn' : 'ok') : 'empty',
    statusLabel: hasRows ? mod.rows.length + ' commands' : 'No data',
    body,
    footer: hasRows
      ? '<a class="link data-log-action" href="#" data-goto="log-parser">Open log parser scan →</a>'
      : '',
  });
}

export function renderFullReportPanel(options) {
  const { hostLabel, openUrl, downloadUrl } = options;
  const download = downloadUrl
    ? '<a class="btn btn-report-download" href="' + escapeHtml(downloadUrl) + '" download>Download Raw Export</a>'
    : '';
  return '<div class="full-report-panel">' +
    '<div class="full-report-hero">' +
    '<div class="full-report-icon" aria-hidden="true"></div>' +
    '<div class="full-report-copy">' +
    '<h3 class="full-report-title">Fullscreen Audit Report</h3>' +
    '<p class="full-report-desc">Open the styled KloudDB Shield report in a new tab. Includes the top 25 critical violations, CIS, HBA, Users, SSL, PII, and log parser sections from the latest scan.</p>' +
    '</div></div>' +
    '<div class="full-report-actions">' +
    '<a class="btn btn-report-open" href="' + escapeHtml(openUrl) + '" target="_blank" rel="noopener noreferrer">Open Fullscreen Report</a>' +
    download +
    '</div>' +
    '<div class="full-report-scope">' +
    '<span class="full-report-scope-label">Report scope</span>' +
    '<code class="full-report-scope-host">' + escapeHtml(hostLabel) + '</code>' +
    '<span class="full-report-scope-note">Latest scan for this host only</span>' +
    '</div></div>';
}

export function bindHostCisInteractions(root) {
  if (!root) return;
  const toggle = (id) => {
    const row = root.querySelector('#' + CSS.escape(id));
    if (row) row.classList.toggle('open');
  };
  root.querySelectorAll('.host-cis-info-btn').forEach(btn => {
    btn.addEventListener('click', e => {
      e.stopPropagation();
      toggle(btn.dataset.detail);
    });
  });
  root.querySelectorAll('.host-cis-expand-all').forEach(btn => {
    btn.addEventListener('click', () => {
      const rows = root.querySelectorAll('.host-cis-detail-row');
      const expand = ![...rows].every(r => r.classList.contains('open'));
      rows.forEach(r => r.classList.toggle('open', expand));
      btn.textContent = expand ? 'Collapse All' : 'Expand All';
    });
  });
}
