import { getInactiveUsersReport } from '../api/services/user-reports.js';
import { paginateSlice, mountTablePagination } from '../utils/pagination.js';
import {
  escapeHtml,
  renderUserCell,
  renderInstanceCell,
  renderDatabasesCell,
  renderStatusBadge,
  renderEmptyRow,
  rowInstance,
  rowTimeRangeLabel,
} from '../utils/user-report-ui.js';

const pager = { page: 1, pageSize: 15 };
const filter = { search: '', bucket: 'all' };
let cache = { rows: [], message: '', userCount: 0, hostCount: 0, countOver30: 0, countOver90: 0, countOver180: 0 };
let toolbarBound = false;
const COLSPAN = 6;

function countEligible(rows) {
  return (rows || []).filter((r) => r.eligible_for_review).length;
}

function updateBucketPills(rows) {
  const list = rows || [];
  const map = {
    all: list.length,
    gt30: cache.countOver30 ?? 0,
    gt90: cache.countOver90 ?? 0,
    gt180: cache.countOver180 ?? 0,
    eligible: countEligible(list),
  };
  document.querySelectorAll('#inactive-users-bucket-filters [data-bucket-count]').forEach((el) => {
    const key = el.getAttribute('data-bucket-count');
    const n = map[key];
    el.textContent = n != null ? String(n) : '—';
  });
  document.querySelectorAll('#inactive-users-bucket-filters [data-bucket]').forEach((btn) => {
    const on = btn.getAttribute('data-bucket') === filter.bucket;
    btn.classList.toggle('is-active', on);
    btn.setAttribute('aria-pressed', on ? 'true' : 'false');
  });
}

function updateStats(all, filtered) {
  const usersEl = document.getElementById('inactive-users-stat-users');
  const hostsEl = document.getElementById('inactive-users-stat-hosts');
  const bucketEl = document.getElementById('inactive-users-stat-buckets');
  if (usersEl) {
    usersEl.textContent = String(all.length ? (filtered.length !== all.length ? filtered.length : (cache.userCount || all.length)) : 0);
  }
  if (hostsEl) {
    const hostSet = new Set((filter.search ? filtered : all).map((r) => rowInstance(r)));
    hostsEl.textContent = String(hostSet.size || cache.hostCount || 0);
  }
  if (bucketEl) {
    const o30 = cache.countOver30 ?? 0;
    const o90 = cache.countOver90 ?? 0;
    const o180 = cache.countOver180 ?? 0;
    bucketEl.textContent = o30 + ' / ' + o90 + ' / ' + o180;
  }
}

function rowInactiveSinceLabel(row) {
  if (row?.inactive_since) return row.inactive_since;
  return rowTimeRangeLabel(row);
}

function rowMatchesBucket(row) {
  const b = filter.bucket || 'all';
  if (b === 'all') return true;
  if (b === 'eligible') return !!row.eligible_for_review;
  const buckets = row.inactivity_buckets || [];
  return buckets.includes(b);
}

function rowDatabasesLabel(row) {
  return row?.databases_label || row?.databasesLabel || '-';
}

function filterRows(rows) {
  let list = rows || [];
  list = list.filter((row) => rowMatchesBucket(row));
  const q = (filter.search || '').trim().toLowerCase();
  if (!q) return list;
  return list.filter((row) => {
    const blob = [row.user, rowInstance(row), rowDatabasesLabel(row), row.status, rowInactiveSinceLabel(row)].join(' ').toLowerCase();
    return blob.includes(q);
  });
}

function renderTable() {
  const tbody = document.getElementById('inactive-users-tbody');
  const hint = document.getElementById('inactive-users-hint');
  const pagerEl = document.getElementById('inactive-users-pagination');
  if (!tbody) return;

  const all = cache.rows || [];
  const filtered = filterRows(all);
  const pg = paginateSlice(filtered, pager.page, pager.pageSize);
  pager.page = pg.page;

  updateStats(all, filtered);
  updateBucketPills(all);

  if (hint) {
    if (!all.length) {
      hint.textContent = 'No inactive users found';
    } else {
      hint.textContent = filtered.length + ' user' + (filtered.length === 1 ? '' : 's') +
        (filtered.length !== all.length ? ' (filtered)' : '') + ' across fleet';
    }
  }

  if (!all.length) {
    tbody.innerHTML = renderEmptyRow(COLSPAN, cache.message || 'No inactive users in latest scans.');
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
    '<td class="user-report-col-user">' + renderUserCell(row.user) + '</td>' +
    '<td class="user-report-col-host">' + renderInstanceCell(inst) + '</td>' +
    '<td class="user-report-col-databases">' + renderDatabasesCell(rowDatabasesLabel(row)) + '</td>' +
    '<td class="user-report-col-range">' + escapeHtml(rowInactiveSinceLabel(row) || '—') +
    (row.days_inactive ? ' <span class="user-report-meta">(' + row.days_inactive + 'd)</span>' : '') + '</td>' +
    '<td class="user-report-col-status">' + renderStatusBadge(row.status) + '</td>' +
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
  const searchEl = document.getElementById('inactive-users-search');
  if (searchEl) {
    searchEl.addEventListener('input', () => {
      filter.search = searchEl.value;
      pager.page = 1;
      renderTable();
    });
  }
  const bucketRoot = document.getElementById('inactive-users-bucket-filters');
  if (bucketRoot) {
    bucketRoot.addEventListener('click', (ev) => {
      const btn = ev.target.closest('[data-bucket]');
      if (!btn || !bucketRoot.contains(btn)) return;
      filter.bucket = btn.getAttribute('data-bucket') || 'all';
      pager.page = 1;
      renderTable();
    });
  }
}

let loaded = false;

export async function initInactiveUsersReportPage({ force = false } = {}) {
  bindToolbar();
  const tbody = document.getElementById('inactive-users-tbody');
  if (tbody && (!loaded || force)) {
    tbody.innerHTML = renderEmptyRow(COLSPAN, 'Loading inactive users…');
  }
  try {
    const data = await getInactiveUsersReport();
    cache = {
      rows: data?.rows || [],
      message: data?.message || '',
      userCount: data?.userCount ?? 0,
      hostCount: data?.hostCount ?? 0,
      countOver30: data?.countOver30 ?? 0,
      countOver90: data?.countOver90 ?? 0,
      countOver180: data?.countOver180 ?? 0,
    };
    pager.page = 1;
    renderTable();
    loaded = true;
  } catch (err) {
    cache = { rows: [], message: '', userCount: 0, hostCount: 0 };
    if (tbody) {
      tbody.innerHTML = renderEmptyRow(COLSPAN, err.message, 'user-report-empty user-report-empty--error');
    }
  }
}
