import { getUniqueIPReport } from '../api/services/user-reports.js';
import { paginateSlice, mountTablePagination } from '../utils/pagination.js';
import {
  escapeHtml,
  renderUserCell,
  renderInstanceCell,
  renderDatabasesCell,
  renderEmptyRow,
  rowInstance,
  rowTimeRangeLabel,
} from '../utils/user-report-ui.js';

const pager = { page: 1, pageSize: 15 };
const filter = { search: '' };
let cache = { rows: [], message: '', ipCount: 0, hostCount: 0 };
let toolbarBound = false;
const COLSPAN = 5;

function updateStats(all, filtered) {
  const ipsEl = document.getElementById('unique-ip-stat-ips');
  const hostsEl = document.getElementById('unique-ip-stat-hosts');
  const aggEl = document.getElementById('unique-ip-stat-aggregated');
  if (ipsEl) {
    ipsEl.textContent = String(all.length ? (filtered.length !== all.length ? filtered.length : (cache.ipCount || all.length)) : 0);
  }
  if (hostsEl) {
    const hostSet = new Set((filter.search ? filtered : all).map((r) => rowInstance(r)));
    hostsEl.textContent = String(hostSet.size || cache.hostCount || 0);
  }
  if (aggEl) {
    const n = (filter.search ? filtered : all).filter((r) => r.data_source === 'aggregation' || r.first_seen).length;
    aggEl.textContent = n ? String(n) + ' with first_seen' : '—';
  }
}

function rowIPTimeLabel(row) {
  if (row?.first_seen) {
    return 'first seen ' + row.first_seen;
  }
  return rowTimeRangeLabel(row);
}

function rowDatabasesLabel(row) {
  return row?.databases_label || row?.databasesLabel || '-';
}

function rowIP(row) {
  return row?.ip || '';
}

function filterRows(rows) {
  const q = (filter.search || '').trim().toLowerCase();
  if (!q) return rows || [];
  return (rows || []).filter((row) => {
    const blob = [rowIP(row), rowInstance(row), rowDatabasesLabel(row), rowIPTimeLabel(row)].join(' ').toLowerCase();
    return blob.includes(q);
  });
}

function renderTable() {
  const tbody = document.getElementById('unique-ip-tbody');
  const hint = document.getElementById('unique-ip-hint');
  const pagerEl = document.getElementById('unique-ip-pagination');
  if (!tbody) return;

  const all = cache.rows || [];
  const filtered = filterRows(all);
  const pg = paginateSlice(filtered, pager.page, pager.pageSize);
  pager.page = pg.page;

  updateStats(all, filtered);

  if (hint) {
    if (!all.length) {
      hint.textContent = 'No unique IPs found';
    } else {
      hint.textContent = filtered.length + ' IP' + (filtered.length === 1 ? '' : 's') +
        (filtered.length !== all.length ? ' (filtered)' : '') + ' across fleet';
    }
  }

  if (!all.length) {
    tbody.innerHTML = renderEmptyRow(COLSPAN, cache.message || 'No unique IPs in latest scans.');
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
    return '<tr class="user-report-row">' +
    '<td class="user-report-col-user">' + renderUserCell(rowIP(row)) + '</td>' +
    '<td class="user-report-col-host">' + renderInstanceCell(inst) + '</td>' +
    '<td class="user-report-col-databases">' + renderDatabasesCell(rowDatabasesLabel(row)) + '</td>' +
    '<td class="user-report-col-range">' + escapeHtml(rowIPTimeLabel(row) || '—') +
    (row.data_source === 'aggregation' ? ' <span class="user-report-meta">(aggregated)</span>' : '') + '</td>' +
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
  const searchEl = document.getElementById('unique-ip-search');
  if (searchEl) {
    searchEl.addEventListener('input', () => {
      filter.search = searchEl.value;
      pager.page = 1;
      renderTable();
    });
  }
}

let loaded = false;

export async function initUniqueIPReportPage({ force = false } = {}) {
  bindToolbar();
  const tbody = document.getElementById('unique-ip-tbody');
  if (tbody && (!loaded || force)) {
    tbody.innerHTML = renderEmptyRow(COLSPAN, 'Loading unique IPs…');
  }
  try {
    const data = await getUniqueIPReport();
    cache = {
      rows: data?.rows || [],
      message: data?.message || '',
      ipCount: data?.ipCount ?? 0,
      hostCount: data?.hostCount ?? 0,
    };
    pager.page = 1;
    renderTable();
    loaded = true;
  } catch (err) {
    cache = { rows: [], message: '', ipCount: 0, hostCount: 0 };
    if (tbody) {
      tbody.innerHTML = renderEmptyRow(COLSPAN, err.message, 'user-report-empty user-report-empty--error');
    }
  }
}
