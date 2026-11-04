import { getPasswordLeakReport } from '../api/services/user-reports.js';
import { paginateSlice, mountTablePagination } from '../utils/pagination.js';
import {
  escapeHtml,
  renderUserCell,
  renderInstanceCell,
  renderDatabasesCell,
  renderEmptyRow,
  rowInstance,
  rowTimeRangeLabel,
  renderTimeRangeCell,
} from '../utils/user-report-ui.js';

const pager = { page: 1, pageSize: 15 };
const filter = { search: '' };
let cache = { rows: [], message: '', leakCount: 0, hostCount: 0 };
let toolbarBound = false;
const COLSPAN = 6;

function updateStats(all, filtered) {
  const leaksEl = document.getElementById('password-leak-stat-leaks');
  const hostsEl = document.getElementById('password-leak-stat-hosts');
  const rangeEl = document.getElementById('password-leak-stat-range');
  if (leaksEl) {
    leaksEl.textContent = String(all.length ? (filtered.length !== all.length ? filtered.length : (cache.leakCount || all.length)) : 0);
  }
  if (hostsEl) {
    const hostSet = new Set((filter.search ? filtered : all).map((r) => rowInstance(r)));
    hostsEl.textContent = String(hostSet.size || cache.hostCount || 0);
  }
  if (rangeEl) {
    const ranges = new Set();
    (filter.search ? filtered : all).forEach((row) => {
      const label = rowTimeRangeLabel(row);
      if (label && label !== '—') ranges.add(label);
    });
    if (ranges.size === 1) {
      rangeEl.textContent = [...ranges][0];
    } else if (ranges.size > 1) {
      rangeEl.textContent = ranges.size + ' ranges';
    } else {
      rangeEl.textContent = '—';
    }
  }
}

function rowDatabasesLabel(row) {
  return row?.databases_label || row?.databasesLabel || '-';
}

function rowPassword(row) {
  return row?.password || '';
}

function rowQuery(row) {
  return row?.query || '';
}

function filterRows(rows) {
  const q = (filter.search || '').trim().toLowerCase();
  if (!q) return rows || [];
  return (rows || []).filter((row) => {
    const blob = [rowPassword(row), rowQuery(row), rowInstance(row), rowDatabasesLabel(row), rowTimeRangeLabel(row)].join(' ').toLowerCase();
    return blob.includes(q);
  });
}

function renderTable() {
  const tbody = document.getElementById('password-leak-tbody');
  const hint = document.getElementById('password-leak-hint');
  const pagerEl = document.getElementById('password-leak-pagination');
  if (!tbody) return;

  const all = cache.rows || [];
  const filtered = filterRows(all);
  const pg = paginateSlice(filtered, pager.page, pager.pageSize);
  pager.page = pg.page;

  updateStats(all, filtered);

  if (hint) {
    if (!all.length) {
      hint.textContent = 'No leaked passwords found';
    } else {
      hint.textContent = filtered.length + ' leak' + (filtered.length === 1 ? '' : 's') +
        (filtered.length !== all.length ? ' (filtered)' : '') + ' across fleet';
    }
  }

  if (!all.length) {
    tbody.innerHTML = renderEmptyRow(COLSPAN, cache.message || 'No leaked passwords in latest scans.');
    mountTablePagination(pagerEl, {
      page: 1, totalPages: 1, total: 0, start: 0, end: 0, pageSize: pager.pageSize,
      onPage: () => {},
    });
    return;
  }

  if (!filtered.length) {
    tbody.innerHTML = renderEmptyRow(COLSPAN, 'No rows match this search.');
    mountTablePagination(pagerEl, {
      page: 1, totalPages: 1, total: 0, start: 0, end: 0, pageSize: pager.pageSize,
      onPage: () => {},
    });
    return;
  }

  tbody.innerHTML = pg.items.map((row) => {
    const inst = rowInstance(row);
    const query = rowQuery(row) || '—';
    return '<tr class="user-report-row">' +
    '<td class="user-report-col-user">' + renderUserCell(rowPassword(row) || '—') + '</td>' +
    '<td class="user-report-col-line"><code class="user-report-hba-line" title="' + escapeHtml(query) + '">' + escapeHtml(query) + '</code></td>' +
    '<td class="user-report-col-host">' + renderInstanceCell(inst) + '</td>' +
    '<td class="user-report-col-databases">' + renderDatabasesCell(rowDatabasesLabel(row)) + '</td>' +
    '<td class="user-report-col-range">' + renderTimeRangeCell(row) + '</td>' +
    '<td class="user-report-col-action">' +
    '<button type="button" class="btn btn-row user-report-action" data-goto="host-detail" data-host-instance="' +
    escapeHtml(inst) + '">View Host <span aria-hidden="true">→</span></button>' +
    '</td>' +
    '</tr>';
  }).join('');

  mountTablePagination(pagerEl, {
    page: pg.page,
    totalPages: pg.totalPages,
    total: pg.total,
    start: pg.start,
    end: pg.end,
    pageSize: pager.pageSize,
    pageSizes: [15, 25, 50],
    onPage: (p) => {
      pager.page = p;
      renderTable();
    },
    onPageSize: (size) => {
      pager.pageSize = size;
      pager.page = 1;
      renderTable();
    },
  });
}

function bindToolbar() {
  if (toolbarBound) return;
  toolbarBound = true;
  const searchEl = document.getElementById('password-leak-search');
  if (searchEl) {
    searchEl.addEventListener('input', () => {
      filter.search = searchEl.value;
      pager.page = 1;
      renderTable();
    });
  }
}

let loaded = false;

export async function initPasswordLeakReportPage({ force = false } = {}) {
  bindToolbar();
  const tbody = document.getElementById('password-leak-tbody');
  if (tbody && (!loaded || force)) {
    tbody.innerHTML = renderEmptyRow(COLSPAN, 'Loading password leak findings…');
  }
  try {
    const data = await getPasswordLeakReport();
    cache = {
      rows: data?.rows || [],
      message: data?.message || '',
      leakCount: data?.leakCount ?? 0,
      hostCount: data?.hostCount ?? 0,
    };
    pager.page = 1;
    renderTable();
    loaded = true;
  } catch (err) {
    cache = { rows: [], message: '', leakCount: 0, hostCount: 0 };
    if (tbody) {
      tbody.innerHTML = renderEmptyRow(COLSPAN, err.message, 'user-report-empty user-report-empty--error');
    }
  }
}
