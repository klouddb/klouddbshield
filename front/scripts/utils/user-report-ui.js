const AVATAR_HUES = [210, 168, 280, 32, 145, 12];

export function escapeHtml(s) {
  return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function userAvatarHue(name) {
  let h = 0;
  for (let i = 0; i < name.length; i++) h = (h + name.charCodeAt(i) * (i + 1)) % AVATAR_HUES.length;
  return AVATAR_HUES[h];
}

export function renderUserCell(user) {
  const safe = escapeHtml(user);
  const initial = escapeHtml((user || '?').charAt(0).toUpperCase());
  const hue = userAvatarHue(user || '');
  return (
    '<div class="user-report-user-cell">' +
    '<span class="user-report-avatar" style="--avatar-hue:' + hue + '" aria-hidden="true">' + initial + '</span>' +
    '<span class="user-report-username" title="' + safe + '">' + safe + '</span>' +
    '</div>'
  );
}

export function renderInstanceCell(instance) {
  const safe = escapeHtml(instance);
  return '<strong class="user-report-instance">' + safe + '</strong>';
}

export function renderDatabasesCell(label) {
  const safe = escapeHtml(label || '-');
  return '<span class="user-report-databases" title="' + safe + '">' + safe + '</span>';
}

export function renderHostCell(host) {
  const inst = String(host || '').includes('/') ? String(host).replace(/\/[^/]+$/, '') : host;
  return renderInstanceCell(inst);
}

export function renderStatusBadge(status) {
  const safe = escapeHtml(status || '—');
  const lower = safe.toLowerCase();
  let tone = 'neutral';
  if (lower.includes('inactive') || lower.includes('never')) tone = 'warn';
  if (lower.includes('active') || lower.includes('pass')) tone = 'ok';
  const cls = tone === 'warn' ? 'badge-posture-fail' : tone === 'ok' ? 'badge-success' : 'badge-muted';
  return '<span class="badge user-report-status ' + cls + '">' + safe + '</span>';
}

export function rowInstance(row) {
  return row?.instance || row?.host || '';
}

export function renderEmptyRow(colspan, message, className = 'user-report-empty') {
  return '<tr><td colspan="' + colspan + '" class="' + className + '">' + escapeHtml(message) + '</td></tr>';
}

export function rowTimeRangeRaw(row) {
  return row?.time_range_label || row?.timeRangeLabel ||
    ((row?.begin || row?.end)
      ? [(row.begin ? row.begin : ''), (row.end ? row.end : '')].filter(Boolean).join(' → ')
      : '—');
}

/** Keep log-filter timestamps as ISO UTC (e.g. 2026-09-23T06:44:00Z). */
export function formatRangeStamp(raw) {
  const s = String(raw || '').trim();
  if (!s || s === '—') return '';
  const iso = s.match(/^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2})(?::(\d{2}))?(?:\.\d+)?(Z|[+-]\d{2}:?\d{2})?$/i);
  if (iso) {
    const sec = iso[3] || '00';
    let tz = iso[4] || 'Z';
    if (tz.toUpperCase() === 'Z') tz = 'Z';
    return iso[1] + 'T' + iso[2] + ':' + sec + tz.toUpperCase();
  }
  // Pretty form from earlier UI: "23 Sep 2026, 06:42 UTC"
  const pretty = s.match(/^(\d{1,2})\s+([A-Za-z]{3})\s+(\d{4}),\s+(\d{2}:\d{2})(?:\s+UTC)?$/i);
  if (pretty) {
    const months = { jan: '01', feb: '02', mar: '03', apr: '04', may: '05', jun: '06', jul: '07', aug: '08', sep: '09', oct: '10', nov: '11', dec: '12' };
    const mon = months[pretty[2].toLowerCase()];
    if (mon) {
      const day = String(pretty[1]).padStart(2, '0');
      return pretty[3] + '-' + mon + '-' + day + 'T' + pretty[4] + ':00Z';
    }
  }
  return s;
}

export function rowTimeRangeParts(row) {
  const begin = formatRangeStamp(row?.begin);
  const end = formatRangeStamp(row?.end);
  if (begin || end) return { begin: begin || '—', end: end || '—' };
  const raw = rowTimeRangeRaw(row);
  if (!raw || raw === '—') return null;
  const parts = raw.split(/\s*→\s*|\s*->\s*/);
  if (parts.length === 2) {
    return {
      begin: formatRangeStamp(parts[0]) || parts[0],
      end: formatRangeStamp(parts[1]) || parts[1],
    };
  }
  return { begin: formatRangeStamp(raw) || raw, end: '' };
}

export function rowTimeRangeLabel(row) {
  const parts = rowTimeRangeParts(row);
  if (!parts) return '—';
  if (parts.end) return parts.begin + ' → ' + parts.end;
  return parts.begin;
}

export function renderTimeRangeCell(row) {
  const parts = rowTimeRangeParts(row);
  if (!parts) {
    return '<span class="user-report-range user-report-range--empty">—</span>';
  }
  const title = escapeHtml(rowTimeRangeRaw(row));
  const label = parts.end ? (parts.begin + ' → ' + parts.end) : parts.begin;
  return '<span class="user-report-range" title="' + title + '">' +
    '<span class="user-report-range-line">' + escapeHtml(label) + '</span></span>';
}

/** Stat-card Log Filter Range: ISO begin/end stacked so text stays inside the box. */
export function setTimeRangeStat(el, label) {
  if (!el) return;
  const raw = String(label || '').trim();
  if (!raw || raw === '—') {
    el.textContent = '—';
    el.removeAttribute('title');
    return;
  }
  const parts = raw.split(/\s*→\s*|\s*->\s*/).map((p) => p.trim()).filter(Boolean);
  el.title = raw;
  if (parts.length >= 2) {
    el.innerHTML =
      '<span class="user-report-stat-range-line">' + escapeHtml(formatRangeStamp(parts[0]) || parts[0]) + '</span>' +
      '<span class="user-report-stat-range-line">' +
      '<span class="user-report-stat-range-arrow" aria-hidden="true">→</span> ' +
      escapeHtml(formatRangeStamp(parts[1]) || parts[1]) +
      '</span>';
    return;
  }
  el.textContent = formatRangeStamp(raw) || raw;
}
