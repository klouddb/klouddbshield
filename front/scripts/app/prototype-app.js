import { gid, gval, gon, gq, gcls } from '../utils/dom.js';
import { paginateSlice, mountTablePagination } from '../utils/pagination.js';
import { PAGE_META as pages } from '../router/routes.js';
import { ensurePageHtml } from '../utils/page-loader.js';
import { ensureHtmlReportCss } from '../utils/styles.js';
import { getHostsSearchFilter } from '../pages/search.js';
import { hostsApi } from '../api/index.js';
import { mapHostsResponse } from '../api/mappers.js';

const PAGE_ASSET = (path) => new URL(`../../${path}`, import.meta.url).pathname;

let hostsPageInited = false;
let criticalViolationsPageInited = false;
let strategicDashboardInited = false;
let hostDetailChromeInited = false;
let policiesChromeInited = false;

    function setRouteHash(nextHash) {
      if (!nextHash || location.hash === nextHash) return;
      try {
        history.replaceState(null, '', nextHash);
      } catch (err) {
        location.hash = nextHash.charAt(0) === '#' ? nextHash.slice(1) : nextHash;
      }
    }

    let hosts = [];
    let FLEET_CATEGORIES = [];
    const fleetCategoryPager = { catId: '', page: 1, pageSize: 15 };
    let activePageId = '';

    function defaultHostName() {
      const h = hosts[0];
      if (!h) return '';
      return h.instance || h[0] || '';
    }

    function hostRowInstance(h) {
      return h?.instance || h?.[0] || '';
    }

    function hostRowIP(h) {
      return h?.ip || h?.[1] || '';
    }

    function hostRowPosture(h) {
      return h?.posture || h?.[3] || '';
    }

    function hostRowAgent(h) {
      return h?.agent || h?.[5] || 'Online';
    }

    function parseHostTargetKey(key) {
      const raw = decodeURIComponent(String(key || '').trim());
      if (!raw) return { instance: '', database: '' };
      const dbRoute = raw.match(/^([^/]+)\/db\/([^/]+)/);
      if (dbRoute) {
        return { instance: dbRoute[1], database: dbRoute[2] };
      }
      const slash = raw.indexOf('/');
      if (slash > 0 && raw.includes(':')) {
        const inst = raw.slice(0, slash);
        const rest = raw.slice(slash + 1);
        if (rest && !rest.startsWith('block-') && !rest.startsWith('sub-')) {
          return { instance: inst, database: rest.split('/')[0] };
        }
        return { instance: inst, database: '' };
      }
      return { instance: raw, database: '' };
    }

    function buildRouteHash(page, hostName, sectionId, fleetCatId, hostsMode, checkPreset, database) {
      if (page === 'host-detail') {
        const target = parseHostTargetKey(hostName);
        const inst = target.instance || hostName || defaultHostName();
        let hash = '#host/' + encodeURIComponent(inst);
        const db = database || target.database;
        if (db) hash += '/db/' + encodeURIComponent(db);
        if (sectionId) hash += '/' + sectionId;
        return hash;
      }
      if (page === 'html-report') {
        const host = hostName || defaultHostName();
        return '#report/' + encodeURIComponent(host);
      }
      if (page === 'fleet-category' && fleetCatId) {
        return '#fleet/' + fleetCatId;
      }
      if (page === 'guc-drift') {
        return '#guc-drift';
      }
      if (page === 'critical-violations') {
        return checkPreset ? '#critical-violations/' + encodeURIComponent(checkPreset) : '#critical-violations';
      }
      if (page === 'hosts') return '#hosts';
      return '#' + page;
    }

    function parseRouteHash() {
      const raw = (location.hash || '').replace(/^#/, '');
      if (!raw) return { page: 'strategic-dashboard' };
      const critViolRoute = raw.match(/^critical-violations(?:\/(.+))?$/);
      if (critViolRoute) {
        return { page: 'critical-violations', checkPreset: critViolRoute[1] ? decodeURIComponent(critViolRoute[1]) : '' };
      }
      const legacyChecksRoute = raw.match(/^critical-checks(?:\/(.+))?$/);
      if (legacyChecksRoute) {
        return { page: 'critical-violations', checkPreset: legacyChecksRoute[1] ? decodeURIComponent(legacyChecksRoute[1]) : '' };
      }
      const legacyTop25Route = raw.match(/^top-25-checks(?:\/(.+))?$/);
      if (legacyTop25Route) {
        return { page: 'critical-violations', checkPreset: legacyTop25Route[1] ? decodeURIComponent(legacyTop25Route[1]) : '' };
      }
      const hostsCrit = raw.match(/^hosts\/critical(?:\/(.+))?$/);
      if (hostsCrit) {
        return { page: 'critical-violations', checkPreset: hostsCrit[1] ? decodeURIComponent(hostsCrit[1]) : '' };
      }
      if (raw === 'hosts') return { page: 'hosts', hostsMode: 'list' };
      if (raw === 'host-detail' || raw === 'host') {
        return { page: 'host-detail', host: defaultHostName() };
      }
      const reportParts = raw.match(/^report\/([^/]+)$/);
      if (reportParts) {
        return { page: 'html-report', host: decodeURIComponent(reportParts[1]) };
      }
      const hostParts = raw.match(/^host\/(.+)$/);
      if (hostParts) {
        const path = decodeURIComponent(hostParts[1]);
        const dbRoute = path.match(/^([^/]+)\/db\/([^/]+)(?:\/(.+))?$/);
        if (dbRoute) {
          return {
            page: 'host-detail',
            host: dbRoute[1],
            database: dbRoute[2],
            section: dbRoute[3] || null,
          };
        }
        const target = parseHostTargetKey(path);
        if (target.database) {
          return { page: 'host-detail', host: target.instance, database: target.database };
        }
        const sectionMatch = path.match(/^([^/]+)\/(block-.+|sub-.+)$/);
        if (sectionMatch) {
          return { page: 'host-detail', host: sectionMatch[1], section: sectionMatch[2] };
        }
        return { page: 'host-detail', host: path };
      }
      const fleetParts = raw.match(/^fleet\/([^/]+)$/);
      if (fleetParts) {
        return { page: 'fleet-category', fleetCat: fleetParts[1] };
      }
      const gucDriftParts = raw.match(/^guc-drift(?:\/host\/(.+))?$/);
      if (gucDriftParts) {
        return {
          page: 'guc-drift',
          gucTarget: gucDriftParts[1] ? decodeURIComponent(gucDriftParts[1]) : '',
        };
      }
      return { page: raw };
    }

    function buildFleetTilesMarkup() {
      const tiles = FLEET_CATEGORIES.map(cat => {
        const cls = cat.level === 'critical' ? 'critical' : cat.level === 'healthy' ? 'healthy' : 'medium';
        return '<button type="button" class="fleet-tile fleet-tile--' + cls + '" data-goto="fleet-category" data-fleet-cat="' + cat.id + '" aria-label="' + escapeHtml(cat.title + ', ' + cat.count + ' items, ' + cat.menu) + '">' +
          '<span class="fleet-tile-title">' + cat.title + '</span>' +
          '<span class="fleet-tile-count" aria-hidden="true">' + cat.count + '</span>' +
          '<span class="fleet-tile-meta">' + cat.menu + '</span></button>';
      }).join('');
      return '<div class="strategic-fleet-block">' +
        '<h2 class="strategic-section-title">Fleet Status</h2>' +
        '<div class="fleet-tile-legend">' +
        '<span class="legend-critical"><i aria-hidden="true"></i> Critical Risk</span>' +
        '<span class="legend-medium"><i aria-hidden="true"></i> Medium</span>' +
        '<span class="legend-healthy"><i aria-hidden="true"></i> Healthy</span></div>' +
        '<div class="fleet-grid-panel"><div class="fleet-tile-grid" role="group" aria-label="Fleet status categories">' + tiles + '</div></div></div>';
    }

    function resolveFleetCategoryId(rawId) {
      if (!rawId) return FLEET_CATEGORIES[0]?.id || '';
      const norm = String(rawId).trim().toLowerCase();
      const wanted = norm.replace(/_/g, '-');
      const direct = FLEET_CATEGORIES.find(c => (c.id || '').toLowerCase() === wanted);
      if (direct) return direct.id;
      return FLEET_CATEGORIES[0]?.id || '';
    }

    function fleetRowHostKey(cat, row) {
      const hostCol = cat.cols.findIndex(c => /^host$/i.test(c));
      const dbCol = cat.cols.findIndex(c => /^database$/i.test(c));
      const inst = hostCol >= 0 ? row[hostCol] : '';
      const db = dbCol >= 0 ? row[dbCol] : '';
      if (inst && db && db !== '-') return inst + '/' + db;
      return inst;
    }

    // Keep table columns aligned when some rows include an extra Databases
    // summary cell (multi-db instances) while others do not.
    function alignFleetCategoryTable(cat) {
      const baseCols = Array.isArray(cat.cols) ? cat.cols.slice() : [];
      const rawRows = Array.isArray(cat.rows) ? cat.rows : [];
      const maxLen = rawRows.reduce((m, r) => Math.max(m, Array.isArray(r) ? r.length : 0), 0);
      const cols = baseCols.slice();
      if (maxLen > cols.length) {
        const hostIdx = cols.findIndex((c) => /^host$/i.test(c));
        const insertAt = hostIdx >= 0 ? hostIdx + 1 : 1;
        if (!cols.some((c) => /^databases?$/i.test(c))) {
          cols.splice(insertAt, 0, 'Databases');
        }
        while (cols.length < maxLen) {
          cols.splice(Math.max(cols.length - 1, 0), 0, '');
        }
      }
      const insertAt = (() => {
        const hostIdx = cols.findIndex((c) => /^host$/i.test(c));
        return hostIdx >= 0 ? hostIdx + 1 : 1;
      })();
      const rows = rawRows.map((row) => {
        if (!Array.isArray(row)) return row;
        if (row.length === cols.length) return row;
        if (row.length > cols.length) return row.slice(0, cols.length);
        const copy = row.slice();
        while (copy.length < cols.length) {
          const at = Math.min(insertAt, copy.length);
          // Keep Action as the last cell.
          if (at >= copy.length) copy.push('—');
          else copy.splice(at, 0, '—');
        }
        return copy;
      });
      return { cols, rows };
    }

    function renderFleetCategoryRow(cat, row, actionLabels) {
      const hostCol = cat.cols.findIndex(c => /^host$/i.test(c));
      const rowHost = fleetRowHostKey(cat, row) || (hostCol >= 0 ? row[hostCol] : '');
      const navigable = !!rowHost;
      const cells = row.map((cell, i) => {
        const colName = (cat.cols[i] || '').toLowerCase();
        if (colName === 'host' && hostCol === i) {
          return '<td class="fleet-col-host"><strong>' + escapeHtml(cell) + '</strong></td>';
        }
        if (colName === 'database' || colName === 'databases') {
          return '<td class="fleet-col-databases"><code class="fleet-db-name">' + escapeHtml(cell) + '</code></td>';
        }
        if (colName === 'last seen' || colName === 'detail' || colName === 'issue') {
          return '<td class="fleet-col-detail">' + escapeHtml(cell).replace(/\n/g, '<br>') + '</td>';
        }
        if (colName === 'posture') {
          const failing = /failing/i.test(cell);
          const cls = failing ? 'badge-posture-fail' : (/passing/i.test(cell) ? 'badge-success' : 'badge-warning');
          return '<td><span class="badge ' + cls + '">' + escapeHtml(cell) + '</span></td>';
        }
        if (colName === 'mfa') {
          const cls = cell === 'Yes' ? 'mfa-yes' : 'mfa-no';
          return '<td class="' + cls + '">' + escapeHtml(cell) + '</td>';
        }
        if (colName === 'result') {
          let cls = '';
          if (/^pass$/i.test(cell)) cls = 'icon-pass';
          else if (/^fail$/i.test(cell)) cls = 'icon-fail';
          else if (/^manual$/i.test(cell)) cls = 'badge-warning';
          return '<td' + (cls ? ' class="' + cls + '"' : '') + '>' + escapeHtml(cell) + '</td>';
        }
        const isAction = i === row.length - 1 && actionLabels.includes(cell);
        if (isAction) {
          let goto = 'host-detail';
          const target = parseHostTargetKey(rowHost);
          let extra = target.database
            ? ' data-host="' + escapeHtml(rowHost) + '"'
            : ' data-host-instance="' + escapeHtml(target.instance || rowHost) + '"';
          if (cell === 'Scan') { goto = 'pii-scanner'; extra = ''; }
          if (cell === 'Drift page') { goto = 'guc-drift'; extra = ''; }
          if (cell === 'Policies') { goto = 'policies'; extra = ''; }
          if (cell === 'View detail' && cat.id === 'inactive-users') {
            extra = target.database
              ? ' data-host="' + escapeHtml(rowHost) + '"'
              : ' data-host-instance="' + escapeHtml(target.instance || rowHost) + '"';
          } else if (cell === 'View detail' && cat.userTable) {
            extra = target.database
              ? ' data-host="' + escapeHtml(rowHost) + '"'
              : ' data-host-instance="' + escapeHtml(target.instance || rowHost) + '"';
          }
          return '<td class="fleet-col-action"><span class="action-link" data-goto="' + goto + '"' + extra + '>' + escapeHtml(cell) + '</span></td>';
        }
        return '<td>' + escapeHtml(cell) + '</td>';
      }).join('');
      if (!navigable) {
        return '<tr>' + cells + '</tr>';
      }
      const target = parseHostTargetKey(rowHost);
      const rowAttr = target.database
        ? ' data-host="' + escapeHtml(rowHost) + '"'
        : ' data-host-instance="' + escapeHtml(target.instance || rowHost) + '"';
      return '<tr class="clickable" data-goto="host-detail"' + rowAttr + '>' + cells + '</tr>';
    }

    function renderFleetCategory(catId) {
      const resolvedId = resolveFleetCategoryId(catId);
      const cat = FLEET_CATEGORIES.find(c => c.id === resolvedId) || FLEET_CATEGORIES[0];
      if (!cat) return;
      if (fleetCategoryPager.catId !== resolvedId) {
        fleetCategoryPager.catId = resolvedId;
        fleetCategoryPager.page = 1;
      }
      const levelLabel = cat.level === 'critical' ? 'Critical risk' : cat.level === 'healthy' ? 'Healthy' : 'Medium';
      const levelBadge = cat.level === 'critical' ? 'badge-danger' : cat.level === 'healthy' ? 'badge-success' : 'badge-warning';
      const actionLabels = ['Open', 'Scan', 'Investigate', 'Review', 'Remediate', 'Disable', 'Enforce MFA', 'Drift page', 'View detail', 'View', 'OK', 'Policies'];
      const titleEl = document.getElementById('fleet-category-title');
      const subEl = document.getElementById('fleet-category-subtitle');
      const calloutEl = document.getElementById('fleet-category-callout');
      const theadEl = document.getElementById('fleet-category-thead');
      const tbodyEl = document.getElementById('fleet-category-tbody');
      const pagerEl = document.getElementById('fleet-category-pagination');
      if (!titleEl || !tbodyEl) return;
      titleEl.textContent = cat.title;
      const aligned = alignFleetCategoryTable(cat);
      const displayCat = Object.assign({}, cat, { cols: aligned.cols, rows: aligned.rows });
      const allRows = displayCat.rows || [];
      const pg = paginateSlice(allRows, fleetCategoryPager.page, fleetCategoryPager.pageSize);
      fleetCategoryPager.page = pg.page;
      if (subEl) {
        subEl.textContent = cat.count + ' · ' + cat.menu + (pg.total ? ' · ' + pg.total + ' rows' : '');
      }
      if (calloutEl) {
        let reportLink = '';
        if (cat.id === 'inactive-users') {
          reportLink = ' · <span class="link" data-goto="inactive-users-report">Open fleet inactive users report →</span>';
        } else if (cat.id === 'common-users') {
          reportLink = ' · <span class="link" data-goto="common-users-report">Open fleet common users report →</span>';
        }
        calloutEl.innerHTML =
          '<strong>' + cat.title + ':</strong> <span class="badge ' + levelBadge + '">' + levelLabel + '</span> · ' + cat.menu + reportLink;
      }
      if (theadEl) {
        theadEl.innerHTML = '<tr>' + displayCat.cols.map((c, i) => {
          const cls = i === displayCat.cols.length - 1 ? ' class="fleet-col-action"' : '';
          return '<th' + cls + '>' + escapeHtml(c) + '</th>';
        }).join('') + '</tr>';
      }
      if (!pg.total) {
        tbodyEl.innerHTML =
          '<tr><td colspan="' + Math.max(displayCat.cols.length, 1) + '" style="color:var(--muted);padding:20px;">No rows for this category yet. Run a collector scan.</td></tr>';
      } else {
        tbodyEl.innerHTML = pg.items.map(row => renderFleetCategoryRow(displayCat, row, actionLabels)).join('');
      }
      mountTablePagination(pagerEl, {
        page: pg.page,
        totalPages: pg.totalPages,
        total: pg.total,
        start: pg.start,
        end: pg.end,
        pageSize: pg.pageSize,
        onPage: (p) => {
          fleetCategoryPager.page = p;
          renderFleetCategory(resolvedId);
        },
        onPageSize: (size) => {
          fleetCategoryPager.pageSize = size;
          fleetCategoryPager.page = 1;
          renderFleetCategory(resolvedId);
        },
      });
    }

    async function showFleetCategory(catId) {
      const resolvedId = resolveFleetCategoryId(catId);
      fleetCategoryPager.catId = resolvedId;
      fleetCategoryPager.page = 1;
      await showPage('fleet-category', undefined, { fleetCat: resolvedId });
    }

    async function showPage(id, hostName, options) {
      const opts = options || {};
      const prevPageId = activePageId;
      let pageId = id;

      await ensurePageHtml(pageId, PAGE_ASSET);

      if (pageId === 'html-report' || pageId === 'host-detail') {
        ensureHtmlReportCss();
      }

      document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
      document.querySelectorAll('.nav-item').forEach((n) => {
        n.classList.remove('active');
        n.removeAttribute('aria-current');
      });

      let pageEl = document.getElementById('page-' + pageId);
      if (!pageEl) {
        pageId = 'strategic-dashboard';
        await ensurePageHtml(pageId, PAGE_ASSET);
        pageEl = document.getElementById('page-strategic-dashboard');
      }
      if (pageEl) pageEl.classList.add('active');

      const nav = document.querySelector('.nav-item[data-page="' + pageId + '"]');
      if (nav) {
        nav.classList.add('active');
        nav.setAttribute('aria-current', 'page');
      } else if (pageId === 'host-detail') {
        const hostsNav = document.querySelector('.nav-item[data-page="hosts"]');
        if (hostsNav) {
          hostsNav.classList.add('active');
          hostsNav.setAttribute('aria-current', 'page');
        }
      } else if (pageId === 'fleet-category') {
        const strategicNav = document.querySelector('.nav-item[data-page="strategic-dashboard"]');
        if (strategicNav) {
          strategicNav.classList.add('active');
          strategicNav.setAttribute('aria-current', 'page');
        }
      }

      const meta = pages[pageId] || pages['strategic-dashboard'];
      let title = meta.title;
      const resolvedHost = pageId === 'host-detail' ? (hostName || defaultHostName()) : hostName;
      if (pageId === 'host-detail') {
        title = resolvedHost;
        ensureHostDetailChromeInit();
        const { loadHostDetail } = await import('../pages/host-detail/index.js');
        void loadHostDetail(resolvedHost, { section: opts.section, database: opts.database });
        if (opts.section && !String(opts.section).startsWith('sub-')) {
          requestAnimationFrame(() => scrollToHostSection(opts.section));
        }
      }
      if (pageId === 'fleet-category' && opts.fleetCat) {
        const cat = FLEET_CATEGORIES.find(c => c.id === opts.fleetCat);
        if (cat) title = cat.title;
        renderFleetCategory(opts.fleetCat);
      }
      const crumbEl = document.getElementById('breadcrumb');
      if (crumbEl) crumbEl.innerHTML = '<strong>' + title + '</strong> / ' + meta.crumb;

      if (pageId === 'strategic-dashboard') {
        ensureStrategicDashboardInit();
        renderStrategicDashboard(strategicRange);
      }
      if (pageId === 'hosts') {
        ensureHostsPageInit();
        showHostsView();
        renderHostsTable();
      }
      if (pageId === 'critical-violations') {
        ensureCriticalViolationsPageInit();
        refreshCriticalViolationsFromApi(opts.checkPreset || '', { resetFilters: !!opts.resetFilters });
      }
      if (pageId === 'guc-drift') {
        const { initGucDriftPage } = await import('../pages/guc-drift.js');
        initGucDriftPage();
      }
      if (pageId === 'collector-nodes') {
        const { initCollectorNodesPage } = await import('../pages/collector-nodes.js');
        void initCollectorNodesPage();
      }
      if (pageId === 'hba-scanner') {
        const { initHbaScannerPage } = await import('../pages/hba-scanner.js');
        initHbaScannerPage();
      }
      if (pageId === 'ssl-scanner') {
        const { initSslScannerPage } = await import('../pages/ssl-scanner.js');
        initSslScannerPage();
      }
      if (pageId === 'pii-scanner' && pageId !== prevPageId) {
        const { initPiiScannerPage } = await import('../pages/pii-scanner.js');
        void initPiiScannerPage();
      }
      if (pageId === 'backup-compliance') {
        import('../pages/backup-compliance.js').then(({ initBackupCompliancePage }) => {
          void initBackupCompliancePage();
        });
      }
      if (pageId === 'log-parser' && pageId !== prevPageId) {
        const { initLogParserPage } = await import('../pages/log-parser.js');
        void initLogParserPage();
      }
      if (pageId === 'log-readiness' && pageId !== prevPageId) {
        const { initLogReadinessPage } = await import('../pages/log-readiness.js');
        void initLogReadinessPage();
      }
      if (pageId === 'inactive-users-report' && pageId !== prevPageId) {
        const { initInactiveUsersReportPage } = await import('../pages/inactive-users-report.js');
        void initInactiveUsersReportPage();
      }
      if (pageId === 'common-users-report' && pageId !== prevPageId) {
        const { initCommonUsersReportPage } = await import('../pages/common-users-report.js');
        void initCommonUsersReportPage();
      }
      if (pageId === 'policies') {
        ensurePoliciesChromeInit();
        const { initPoliciesPage } = await import('../pages/policies-page.js');
        initPoliciesPage();
      }
      if (pageId === 'html-report') {
        const reportHost = resolvedHost || defaultHostName();
        import('../pages/html-report-viewer.js').then(({ initHtmlReportPage }) => {
          void initHtmlReportPage(reportHost);
        });
        if (reportHost) title = reportHost + ' — HTML report';
      }

      activePageId = pageId;

      const announcer = document.getElementById('route-announcer');
      if (announcer) announcer.textContent = title + ' — ' + meta.crumb;

      if (!opts.skipHash) {
        const nextHash = buildRouteHash(pageId, resolvedHost, opts.section, opts.fleetCat, opts.hostsMode, opts.checkPreset, opts.database);
        setRouteHash(nextHash);
      }

      if (!opts.skipScrollTop) {
        window.scrollTo(0, 0);
      }
    }

    async function applyRouteFromHash() {
      const route = parseRouteHash();
      if (route.page === 'strategic-dashboard') {
        ensureStrategicDashboardInit();
        const rangeFromHash = route.range || strategicRange;
        renderStrategicDashboard(rangeFromHash);
      }
      if (route.page === 'hosts') {
        await showPage('hosts', undefined, { skipHash: true });
        return;
      }
      if (route.page === 'critical-violations') {
        await showPage('critical-violations', undefined, { skipHash: true, checkPreset: route.checkPreset || '' });
        return;
      }
      if (route.page === 'fleet-category' && route.fleetCat) {
        const resolvedFleetCat = resolveFleetCategoryId(route.fleetCat);
        await showPage('fleet-category', undefined, { skipHash: true, fleetCat: resolvedFleetCat });
        return;
      }
      await showPage(route.page, route.host, {
        skipHash: true,
        skipScrollTop: !!route.section,
        fleetCat: route.fleetCat,
        hostsMode: route.hostsMode,
        checkPreset: route.checkPreset,
        database: route.database,
        section: route.section,
      });
      if (route.section) {
        requestAnimationFrame(() => scrollToHostSection(route.section));
      }
    }

    const boot = window.__SHIELD_BOOT__;
    if (boot?.hosts?.length) hosts = boot.hosts;
    if (boot?.fleetCategories?.length) FLEET_CATEGORIES = boot.fleetCategories;


    document.querySelectorAll('.nav-item').forEach(el => {
      el.addEventListener('click', e => {
        e.preventDefault();
        const page = el.dataset.page;
        if (page === 'critical-violations') {
          void showPage(page, undefined, { checkPreset: '', resetFilters: true });
          return;
        }
        void showPage(page);
      });
    });

    document.addEventListener('click', e => {
      const goto = e.target.closest('[data-goto]');
      if (!goto) return;
      const page = goto.dataset.goto;
      if (!page) return;
      e.preventDefault();
      if (page === 'fleet-category' && goto.dataset.fleetCat) {
        void showFleetCategory(goto.dataset.fleetCat);
        return;
      }
      if (page === 'critical-violations') {
        const reset = goto.dataset.resetCritFilters === '1';
        void showPage('critical-violations', undefined, {
          checkPreset: reset ? '' : (goto.dataset.checkPreset || ''),
          resetFilters: reset,
        });
        return;
      }
      if (page === 'hosts') {
        void showPage('hosts', undefined);
        return;
      }
      void showPage(page, goto.dataset.hostInstance || goto.dataset.host || undefined, {
        section: goto.dataset.section || undefined,
        database: goto.dataset.database || undefined,
        skipScrollTop: !!goto.dataset.section,
      });
    });

    let CRITICAL_VIOLATION_ROWS = boot?.criticalViolationRows || [];
    const criticalViolationsPager = { page: 1, pageSize: 15 };
    let criticalViolationsDetailCheckId = null;
    let CRITICAL_VIOLATION_FILTERS = boot?.criticalViolationFilters || {
      checkOptions: [], checkDefinitions: [], serverOptions: [], sourceOptions: [], typeOptions: [], severityOptions: [],
    };

    let hostsListFilter = 'all';
    const hostsPager = { page: 1, pageSize: 15 };

    function updateHostsFilterLabels() {
      const total = hosts.length;
      const passing = hosts.filter(h => hostRowPosture(h) === 'Passing').length;
      const failing = hosts.filter(h => hostRowPosture(h) === 'Failing').length;
      const drift = hosts.filter(h => (h?.failing_count || 0) > 0 || (Array.isArray(h) && h[4] !== '-')).length;
      const offline = hosts.filter(h => h[5] !== 'Online').length;
      const labels = {
        all: 'All (' + total + ')',
        passing: 'Passing (' + passing + ')',
        failing: 'Failing threshold (' + failing + ')',
        drift: 'GUC drift (' + drift + ')',
        offline: 'Offline (' + offline + ')',
      };
      document.querySelectorAll('#hosts-filter-pills [data-hosts-filter]').forEach(p => {
        const f = p.dataset.hostsFilter;
        if (labels[f]) p.textContent = labels[f];
      });
    }

    function parseCriticalViolationDateRange() {
      const from = gval('crit-viol-filter-date-from', '').trim();
      const to = gval('crit-viol-filter-date-to', '').trim();
      if (!from && !to) return null;
      let start = from ? new Date(from + 'T00:00:00') : new Date('1970-01-01T00:00:00');
      let end = to ? new Date(to + 'T23:59:59') : new Date('2099-12-31T23:59:59');
      if (start > end) {
        const swapStart = start;
        start = new Date(end.toISOString().slice(0, 10) + 'T00:00:00');
        end = new Date(swapStart.toISOString().slice(0, 10) + 'T23:59:59');
      }
      return { start, end };
    }

    function hasCriticalViolationDateFilterActive() {
      return !!(
        gval('crit-viol-filter-date-from', '').trim() ||
        gval('crit-viol-filter-date-to', '').trim()
      );
    }

    function violationInDateRange(detected, range) {
      if (!range) return true;
      const d = new Date(String(detected).replace(' ', 'T'));
      if (isNaN(d.getTime())) return true;
      return d >= range.start && d <= range.end;
    }

    function hostDatabaseTotal(h) {
      if (Number.isFinite(h?.database_count) && h.database_count > 0) return h.database_count;
      if (Array.isArray(h?.databases) && h.databases.length) return h.databases.length;
      const m = String(h?.databases_label || (Array.isArray(h) ? h[2] : '') || '').match(/^(\d+)\b/);
      return m ? parseInt(m[1], 10) : 0;
    }

    function hostInstanceFailingCount(h) {
      if (Number.isFinite(h?.failing_count)) return h.failing_count;
      if (Array.isArray(h?.databases) && h.databases.length) {
        return h.databases.filter((db) => db?.posture === 'Failing').length;
      }
      const failLabel = h?.fail_label || (Array.isArray(h) ? h[4] : '');
      const m = String(failLabel || '').match(/^(\d+)\s*\/\s*(\d+)/i);
      if (m) return parseInt(m[1], 10);
      return 0;
    }

    function hostPostureDisplay(h) {
      if (h?.posture_label) return h.posture_label;
      const total = hostDatabaseTotal(h);
      let failing = hostInstanceFailingCount(h);
      if (failing <= 0 && hostRowPosture(h) === 'Failing' && total > 0) failing = 1;
      if (total > 0) {
        if (failing > 0) return failing + '/' + total + ' Failing';
        return 'Passing';
      }
      return hostRowPosture(h) || 'Passing';
    }

    function hostPostureBadgeClass(h) {
      const failing = hostInstanceFailingCount(h);
      const posture = hostRowPosture(h);
      if (failing > 0 || posture === 'Failing') return 'badge-posture-fail';
      if (posture === 'Passing') return 'badge-success';
      return 'badge-warning';
    }

    function severityBadgeClass(sev) {
      return String(sev).toUpperCase() === 'HIGH' ? 'badge-severity-high' : 'badge-critical-pill';
    }

    function filterHostsRows() {
      const q = getHostsSearchFilter();
      return hosts.filter((h) => {
        const name = hostRowInstance(h);
        const ip = hostRowIP(h);
        const status = hostRowPosture(h);
        const agent = hostRowAgent(h);
        const hasDrift = (h?.failing_count || 0) > 0 || (Array.isArray(h) && h[4] !== '-');
        if (q && !name.toLowerCase().includes(q) && !ip.toLowerCase().includes(q)) return false;
        if (hostsListFilter === 'passing' && status !== 'Passing') return false;
        if (hostsListFilter === 'failing' && status !== 'Failing') return false;
        if (hostsListFilter === 'drift' && !hasDrift) return false;
        if (hostsListFilter === 'offline' && agent === 'Online') return false;
        return true;
      });
    }

    function renderHostsTable() {
      const tbody = document.getElementById('hosts-tbody');
      const pagerEl = document.getElementById('hosts-pagination');
      if (!tbody) return;
      updateHostsFilterLabels();
      const filtered = filterHostsRows();
      const pg = paginateSlice(filtered, hostsPager.page, hostsPager.pageSize);
      hostsPager.page = pg.page;

      if (!pg.total) {
        tbody.innerHTML =
          '<tr><td colspan="7" style="color:var(--muted);padding:20px;">No hosts match this filter.</td></tr>';
      } else {
        tbody.innerHTML = pg.items.map((inst) => {
          const instance = hostRowInstance(inst);
          const ip = hostRowIP(inst);
          const dbLabel = inst.databases_label || inst[2] || '-';
          const postureText = hostPostureDisplay(inst);
          const statusClass = hostPostureBadgeClass(inst);
          const agent = hostRowAgent(inst);
          const scan = inst.last_audit || inst[6] || '-';
          return '<tr class="clickable" data-goto="host-detail" data-host-instance="' + escapeHtml(instance) + '">' +
            '<td><strong>' + escapeHtml(instance) + '</strong></td><td>' + escapeHtml(ip) + '</td>' +
            '<td>' + escapeHtml(dbLabel) + '</td>' +
            '<td><span class="badge ' + statusClass + '">' + escapeHtml(postureText) + '</span></td>' +
            '<td>' + escapeHtml(agent) + '</td><td>' + escapeHtml(scan) + '</td>' +
            '<td><span class="link">Open</span></td></tr>';
        }).join('');
      }

      mountTablePagination(pagerEl, {
        page: pg.page,
        totalPages: pg.totalPages,
        total: pg.total,
        start: pg.start,
        end: pg.end,
        pageSize: pg.pageSize,
        pageSizes: [15, 25, 50],
        onPage: (p) => {
          hostsPager.page = p;
          renderHostsTable();
        },
        onPageSize: (size) => {
          hostsPager.pageSize = size;
          hostsPager.page = 1;
          renderHostsTable();
        },
      });
    }

    function escapeHtml(s) {
      return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
    }

    function resolveCriticalCheckPreset(preset) {
      if (!preset) return { detailCheckId: null, typeFilter: '' };
      const trimmed = String(preset).trim();
      // Drill-down URLs use a bare check id only (e.g. #critical-violations/5).
      if (/^\d{1,2}$/.test(trimmed)) return { detailCheckId: parseInt(trimmed, 10), typeFilter: '' };
      return { detailCheckId: null, typeFilter: trimmed };
    }

    function criticalCheckTitle(checkId) {
      const def = (CRITICAL_VIOLATION_FILTERS.checkDefinitions || []).find(c => c.id === checkId);
      if (def?.title) return def.title;
      const row = CRITICAL_VIOLATION_ROWS.find(v => v.checkId === checkId);
      return row?.check || ('Check ' + checkId);
    }

    function filterCriticalViolationRows(detailCheckId) {
      const violF = gval('crit-viol-filter-violation', '');
      const serverF = gval('crit-viol-filter-server', '');
      const sourceF = gval('crit-viol-filter-source', '');
      const typeF = gval('crit-viol-filter-type', '');
      const sevF = gval('crit-viol-filter-severity', '');
      const dateRange = parseCriticalViolationDateRange();
      return CRITICAL_VIOLATION_ROWS.filter(v => {
        if (detailCheckId != null && Number(v.checkId) !== Number(detailCheckId)) return false;
        if (violF) {
          const rowLabel = v.checkId + ' — ' + v.check;
          if (violF !== rowLabel && violF !== String(v.checkId)) return false;
        }
        if (serverF && v.server !== serverF) return false;
        if (sourceF && v.source !== sourceF) return false;
        if (typeF && v.violationType !== typeF) return false;
        if (sevF && v.severity !== sevF) return false;
        if (!violationInDateRange(v.detected, dateRange)) return false;
        return true;
      });
    }

    function criticalViolationGroupKey(row) {
      const id = row?.checkId;
      if (id != null && id !== '' && !Number.isNaN(Number(id))) {
        return 'id:' + Number(id);
      }
      const title = String(row?.check || '').trim().toLowerCase();
      return title ? 'title:' + title : '';
    }

    function groupCriticalViolationsByCheck(rows) {
      const map = new Map();
      for (const r of rows) {
        const key = criticalViolationGroupKey(r);
        if (!key) continue;
        if (!map.has(key)) {
          const checkId = r.checkId != null && r.checkId !== '' ? Number(r.checkId) : r.checkId;
          map.set(key, {
            checkId,
            check: r.check,
            violationType: r.violationType,
            severity: r.severity,
            sources: new Set(),
            serverCount: 0,
            latestDetected: r.detected || '',
            instances: [],
          });
        }
        const g = map.get(key);
        if (r.source) g.sources.add(r.source);
        g.instances.push(r);
        g.serverCount = new Set(g.instances.map(i => i.server)).size;
        if ((r.detected || '') > g.latestDetected) g.latestDetected = r.detected || '';
        if (r.severity === 'CRITICAL') g.severity = 'CRITICAL';
      }
      return [...map.values()].sort((a, b) => a.checkId - b.checkId);
    }

    function formatCriticalSources(sources) {
      const list = [...sources].filter(Boolean).sort();
      if (!list.length) return '—';
      if (list.length === 1) return list[0];
      if (list.length === 2) return list.join(', ');
      return list.slice(0, 2).join(', ') + ' +' + (list.length - 2);
    }

    function resetCriticalViolationFilters() {
      [
        'crit-viol-filter-violation',
        'crit-viol-filter-server',
        'crit-viol-filter-source',
        'crit-viol-filter-type',
        'crit-viol-filter-severity',
      ].forEach((id) => {
        const el = document.getElementById(id);
        if (el) el.value = '';
      });
      const dateFrom = document.getElementById('crit-viol-filter-date-from');
      const dateTo = document.getElementById('crit-viol-filter-date-to');
      if (dateFrom) dateFrom.value = '';
      if (dateTo) dateTo.value = '';
    }

    function hasCriticalViolationFiltersActive() {
      return !!(
        gval('crit-viol-filter-violation', '') ||
        gval('crit-viol-filter-server', '') ||
        gval('crit-viol-filter-source', '') ||
        gval('crit-viol-filter-type', '') ||
        gval('crit-viol-filter-severity', '') ||
        hasCriticalViolationDateFilterActive()
      );
    }

    function updateCriticalViolationsBackLinks() {
      const backHosts = document.getElementById('critical-violations-back-hosts-link');
      if (!backHosts || criticalViolationsDetailCheckId != null) return;
      if (hasCriticalViolationFiltersActive()) {
        backHosts.textContent = '← Back To All Violations';
        backHosts.dataset.goto = 'critical-violations';
        backHosts.dataset.resetCritFilters = '1';
      } else {
        backHosts.textContent = '← Back To Host List';
        backHosts.dataset.goto = 'hosts';
        delete backHosts.dataset.resetCritFilters;
      }
    }

    function setCriticalViolationsLayout(detailCheckId) {
      criticalViolationsDetailCheckId = detailCheckId;
      const isDetail = detailCheckId != null;
      const summaryPanel = document.getElementById('critical-violations-summary-panel');
      const detailPanel = document.getElementById('critical-violations-detail-panel');
      const backHosts = document.getElementById('critical-violations-back-hosts');
      const backSummary = document.getElementById('critical-violations-back-summary');
      const titleEl = document.getElementById('critical-violations-page-title');
      const subtitleEl = document.getElementById('critical-violations-page-subtitle');
      const violFilter = document.getElementById('crit-viol-filter-violation');
      const violGroup = document.getElementById('crit-viol-filter-violation-group');
      const typeGroup = document.getElementById('crit-viol-filter-type-group');
      const filtersBar = document.getElementById('critical-violations-filters-bar');
      if (summaryPanel) summaryPanel.hidden = isDetail;
      if (detailPanel) detailPanel.hidden = !isDetail;
      if (backHosts) backHosts.hidden = isDetail;
      if (backSummary) backSummary.hidden = !isDetail;
      if (violGroup) violGroup.hidden = isDetail;
      if (typeGroup) typeGroup.hidden = isDetail;
      if (filtersBar) filtersBar.classList.toggle('critical-violations-filters--detail', isDetail);
      if (violFilter) violFilter.disabled = isDetail;
      if (titleEl) {
        titleEl.textContent = isDetail
          ? 'Check ' + String(detailCheckId).padStart(2, '0') + ' — ' + criticalCheckTitle(detailCheckId)
          : 'Critical Violations';
      }
      if (subtitleEl) {
        subtitleEl.textContent = isDetail
          ? 'Servers failing this check from latest fleet scans · click a row to open host audit'
          : 'One row per violation · click a row to see affected servers · filter lists all 25 canonical checks';
      }
      const crumbEl = document.getElementById('breadcrumb');
      if (crumbEl && activePageId === 'critical-violations') {
        const meta = pages['critical-violations'];
        const crumb = isDetail ? 'Affected Servers' : meta.crumb;
        crumbEl.innerHTML = '<strong>' + (titleEl?.textContent || meta.title) + '</strong> / ' + crumb;
      }
      updateCriticalViolationsBackLinks();
    }

    function renderCriticalViolations() {
      if (criticalViolationsDetailCheckId != null) {
        renderCriticalViolationsDetail(criticalViolationsDetailCheckId);
      } else {
        renderCriticalViolationsSummary();
      }
      updateCriticalViolationsBackLinks();
    }

    function renderCriticalViolationsSummary() {
      const tbody = document.getElementById('critical-violations-tbody');
      const countEl = document.getElementById('critical-violations-result-count');
      const pagerEl = document.getElementById('critical-violations-pagination');
      if (!tbody) return;
      const filteredRows = filterCriticalViolationRows(null);
      const grouped = groupCriticalViolationsByCheck(filteredRows);
      const pg = paginateSlice(grouped, criticalViolationsPager.page, criticalViolationsPager.pageSize);
      criticalViolationsPager.page = pg.page;
      if (!pg.total) {
        tbody.innerHTML =
          '<tr><td colspan="7" class="critical-violations-empty">No critical violations match these filters.</td></tr>';
      } else {
        tbody.innerHTML = pg.items.map(g =>
          '<tr class="clickable critical-violations-row" data-goto="critical-violations" data-check-preset="' + escapeHtml(String(g.checkId)) + '">' +
            '<td class="critical-viol-num">' + escapeHtml(String(g.checkId).padStart(2, '0')) + '</td>' +
            '<td class="critical-viol-name">' + escapeHtml(g.check) + '</td>' +
            '<td class="critical-viol-affected"><span class="critical-affected-count">' + escapeHtml(String(g.serverCount)) + '</span></td>' +
            '<td class="critical-viol-type">' + escapeHtml(g.violationType || '—') + '</td>' +
            '<td class="critical-viol-severity"><span class="' + severityBadgeClass(g.severity) + '">' + escapeHtml(g.severity || 'CRITICAL') + '</span></td>' +
            '<td class="critical-viol-source">' + escapeHtml(formatCriticalSources(g.sources)) + '</td>' +
            '<td class="critical-detected-at">' + escapeHtml(g.latestDetected || '—') + '</td></tr>'
        ).join('');
      }
      mountTablePagination(pagerEl, {
        page: pg.page,
        totalPages: pg.totalPages,
        total: pg.total,
        start: pg.start,
        end: pg.end,
        pageSize: pg.pageSize,
        onPage: (p) => {
          criticalViolationsPager.page = p;
          renderCriticalViolations();
        },
        onPageSize: (size) => {
          criticalViolationsPager.pageSize = size;
          criticalViolationsPager.page = 1;
          renderCriticalViolations();
        },
      });
      if (countEl) {
        countEl.textContent =
          'Showing ' + (pg.total ? pg.start + '–' + pg.end : '0') + ' of ' + grouped.length +
          ' violations · ' + filteredRows.length + ' open instance(s) in fleet · filter lists all 25 checks';
      }
    }

    function renderCriticalViolationsDetail(checkId) {
      const tbody = document.getElementById('critical-violations-detail-tbody');
      const countEl = document.getElementById('critical-violations-result-count');
      const pagerEl = document.getElementById('critical-violations-pagination');
      if (!tbody) return;
      const filtered = filterCriticalViolationRows(checkId);
      const pg = paginateSlice(filtered, criticalViolationsPager.page, criticalViolationsPager.pageSize);
      criticalViolationsPager.page = pg.page;
      if (!pg.total) {
        tbody.innerHTML =
          '<tr><td colspan="6" class="critical-violations-empty">No servers match these filters for this violation.</td></tr>';
      } else {
        tbody.innerHTML = pg.items.map(v =>
          '<tr class="clickable critical-violations-row" data-goto="host-detail" data-host="' + escapeHtml(v.server) + '" data-section="block-critical-violations">' +
            '<td class="critical-viol-num">' + escapeHtml(String(v.checkId).padStart(2, '0')) + '</td>' +
            '<td class="critical-viol-server">' + escapeHtml(v.server) + '</td>' +
            '<td class="critical-details-cell" title="' + escapeHtml(v.details) + '">' + escapeHtml(v.details) + '</td>' +
            '<td class="critical-viol-severity"><span class="' + severityBadgeClass(v.severity) + '">' + escapeHtml(v.severity || 'CRITICAL') + '</span></td>' +
            '<td class="critical-viol-source">' + escapeHtml(v.source || '—') + '</td>' +
            '<td class="critical-detected-at">' + escapeHtml(v.detected) + '</td></tr>'
        ).join('');
      }
      mountTablePagination(pagerEl, {
        page: pg.page,
        totalPages: pg.totalPages,
        total: pg.total,
        start: pg.start,
        end: pg.end,
        pageSize: pg.pageSize,
        onPage: (p) => {
          criticalViolationsPager.page = p;
          renderCriticalViolations();
        },
        onPageSize: (size) => {
          criticalViolationsPager.pageSize = size;
          criticalViolationsPager.page = 1;
          renderCriticalViolations();
        },
      });
      if (countEl) {
        const uniqueServers = new Set(filtered.map(v => v.server)).size;
        countEl.textContent =
          'Showing ' + (pg.total ? pg.start + '–' + pg.end : '0') + ' of ' + filtered.length +
          ' instance(s) · ' + uniqueServers + ' server(s) failing check ' + String(checkId).padStart(2, '0');
      }
    }

    function showHostsView() {
      const listView = document.getElementById('hosts-view-list');
      if (!listView) return;
      listView.classList.add('active');
      document.querySelectorAll('#hosts-filter-pills .filter-pill[data-hosts-filter]').forEach(p => {
        p.classList.toggle('active', p.dataset.hostsFilter === hostsListFilter);
      });
    }

    function populateSelectOptions(selectId, allLabel, fromApi, fromRows) {
      const sel = document.getElementById(selectId);
      if (!sel) return;
      const prev = sel.value;
      let opts = [...new Set([...(fromApi || []), ...(fromRows || [])])].filter(Boolean);
      if (selectId === 'crit-viol-filter-violation') {
        const defs = (CRITICAL_VIOLATION_FILTERS.checkDefinitions || []).map(
          c => c.id + ' — ' + c.title,
        );
        if (defs.length) opts = [...new Set([...defs, ...opts])];
        opts.sort((a, b) => (parseInt(a, 10) || 0) - (parseInt(b, 10) || 0));
      } else if (selectId === 'crit-viol-filter-severity') {
        const order = ['CRITICAL', 'HIGH'];
        opts = [...new Set([...order, ...opts])];
        opts.sort((a, b) => order.indexOf(a) - order.indexOf(b));
      } else if (selectId === 'crit-viol-filter-type') {
        const order = ['SSL Violation', 'HBA Violation', 'Password Leak', 'PII Exposure', 'Unauthorized Superuser', 'Critical Config'];
        opts = [...new Set([...order, ...opts])];
        opts.sort((a, b) => {
          const ai = order.indexOf(a);
          const bi = order.indexOf(b);
          if (ai === -1 && bi === -1) return a.localeCompare(b);
          if (ai === -1) return 1;
          if (bi === -1) return -1;
          return ai - bi;
        });
      } else if (selectId === 'crit-viol-filter-source') {
        opts.sort();
      } else {
        opts.sort();
      }
      sel.innerHTML = '<option value="">' + allLabel + '</option>' +
        opts.map(o => '<option value="' + escapeHtml(o) + '">' + escapeHtml(o) + '</option>').join('');
      if (prev && opts.includes(prev)) sel.value = prev;
    }

    function populateCriticalViolationFilters() {
      populateSelectOptions(
        'crit-viol-filter-violation',
        'All Violations',
        CRITICAL_VIOLATION_FILTERS.checkOptions,
        CRITICAL_VIOLATION_ROWS.map(v => v.checkId + ' — ' + v.check),
      );
      populateSelectOptions(
        'crit-viol-filter-server',
        'All Servers',
        CRITICAL_VIOLATION_FILTERS.serverOptions,
        CRITICAL_VIOLATION_ROWS.map(v => v.server),
      );
      populateSelectOptions(
        'crit-viol-filter-source',
        'All Sources',
        CRITICAL_VIOLATION_FILTERS.sourceOptions,
        CRITICAL_VIOLATION_ROWS.map(v => v.source),
      );
      populateSelectOptions(
        'crit-viol-filter-type',
        'All Types',
        CRITICAL_VIOLATION_FILTERS.typeOptions,
        CRITICAL_VIOLATION_ROWS.map(v => v.violationType),
      );
      populateSelectOptions(
        'crit-viol-filter-severity',
        'All Severities',
        CRITICAL_VIOLATION_FILTERS.severityOptions,
        CRITICAL_VIOLATION_ROWS.map(v => v.severity),
      );
    }

    function showCriticalViolationsView(checkPreset, viewOpts) {
      const opts = viewOpts || {};
      if (opts.resetFilters) resetCriticalViolationFilters();
      populateCriticalViolationFilters();
      criticalViolationsPager.page = 1;
      const resolved = resolveCriticalCheckPreset(checkPreset);
      setCriticalViolationsLayout(resolved.detailCheckId);
      if (resolved.detailCheckId == null && checkPreset && !opts.resetFilters) {
        const violSel = document.getElementById('crit-viol-filter-violation');
        if (violSel) {
          const match = [...violSel.options].find(o => o.value === checkPreset || o.value.startsWith(checkPreset + ' —'));
          if (match) violSel.value = match.value;
        }
        const typeSel = document.getElementById('crit-viol-filter-type');
        if (typeSel && !violSel?.value) typeSel.value = resolved.typeFilter || checkPreset;
      }
      renderCriticalViolations();
    }

    async function refreshCriticalViolationsFromApi(checkPreset, viewOpts) {
      try {
        const { criticalChecksApi, mapCriticalChecksResponse } = await import('../api/index.js');
        const data = await criticalChecksApi.getCriticalChecks();
        const mapped = mapCriticalChecksResponse(data);
        CRITICAL_VIOLATION_ROWS = mapped.rows;
        CRITICAL_VIOLATION_FILTERS = {
          checkOptions: mapped.checkOptions,
          checkDefinitions: mapped.checks || [],
          serverOptions: mapped.serverOptions,
          sourceOptions: mapped.sourceOptions,
          typeOptions: mapped.typeOptions,
          severityOptions: mapped.severityOptions,
        };
        showCriticalViolationsView(checkPreset || '', viewOpts);
      } catch (err) {
        console.warn('Critical violations reload failed:', err);
        showCriticalViolationsView(checkPreset || '', viewOpts);
      }
    }

    async function refreshHostsFromApi() {
      try {
        const data = await hostsApi.getHosts();
        const rows = mapHostsResponse(data);
        if (rows?.length) {
          hosts = rows;
          window.__SHIELD_BOOT__ = { ...(window.__SHIELD_BOOT__ || {}), hosts };
        }
      } catch (err) {
        console.warn('Hosts refresh failed:', err);
      }
    }

    function applyHostsSearch() {
      const q = getHostsSearchFilter();
      hostsPager.page = 1;
      if (q && activePageId !== 'hosts') {
        void showPage('hosts');
        return;
      }
      if (activePageId === 'hosts') {
        renderHostsTable();
      }
    }

    function initHostsPage() {
      void refreshHostsFromApi().then(() => renderHostsTable());
      renderHostsTable();
      window.addEventListener('shield:hosts-search', applyHostsSearch);
      gon('hosts-filter-pills', 'click', e => {
        const pill = e.target.closest('[data-hosts-filter]');
        if (!pill) return;
        document.querySelectorAll('#hosts-filter-pills .filter-pill[data-hosts-filter]').forEach(p => p.classList.remove('active'));
        pill.classList.add('active');
        hostsListFilter = pill.dataset.hostsFilter;
        hostsPager.page = 1;
        renderHostsTable();
      });
    }

    function initCriticalViolationsPage() {
      populateCriticalViolationFilters();
      gon('crit-viol-filter-apply', 'click', () => {
        criticalViolationsPager.page = 1;
        renderCriticalViolations();
      });
      ['crit-viol-filter-violation', 'crit-viol-filter-server', 'crit-viol-filter-source',
        'crit-viol-filter-type', 'crit-viol-filter-severity',
        'crit-viol-filter-date-from', 'crit-viol-filter-date-to'].forEach(id => {
        const el = document.getElementById(id);
        if (!el) return;
        el.addEventListener('change', renderCriticalViolations);
      });
    }

    function ensureHostsPageInit() {
      if (hostsPageInited) return;
      hostsPageInited = true;
      initHostsPage();
    }

    function ensureCriticalViolationsPageInit() {
      if (criticalViolationsPageInited) return;
      criticalViolationsPageInited = true;
      initCriticalViolationsPage();
    }

    function ensureHostDetailChromeInit() {
      if (hostDetailChromeInited) return;
      hostDetailChromeInited = true;
      document.querySelectorAll('#host-report .sub-tabs').forEach(bar => {
        bar.addEventListener('click', e => {
          const sub = e.target.closest('.sub-tab');
          if (!sub) return;
          const block = bar.closest('.report-block');
          block.querySelectorAll('.sub-tab').forEach(t => t.classList.remove('active'));
          block.querySelectorAll('.host-subpanel').forEach(p => p.classList.remove('active'));
          sub.classList.add('active');
          const panel = block.querySelector('#sub-' + sub.dataset.sub);
          if (panel) panel.classList.add('active');
        });
      });

      document.querySelectorAll('.host-toc a[href^="#"]').forEach(a => {
        a.addEventListener('click', e => {
          e.preventDefault();
          scrollToHostSection(a.getAttribute('href').slice(1));
        });
      });

      document.querySelectorAll('[data-goto-section]').forEach(el => {
        el.addEventListener('click', e => {
          e.preventDefault();
          e.stopPropagation();
          const id = el.dataset.gotoSection || (el.getAttribute('href') ? el.getAttribute('href').slice(1) : '');
          if (!id) return;
          if (!document.getElementById('page-host-detail').classList.contains('active')) {
            void showPage('host-detail');
          }
          requestAnimationFrame(() => scrollToHostSection(id));
        });
      });
    }

    function ensurePoliciesChromeInit() {
      if (policiesChromeInited) return;
      policiesChromeInited = true;
      bindPoliciesPrototypeChrome();
    }

    function scrollToHostSection(id) {
      if (id === 'block-critical-checks') id = 'block-critical-violations';
      if (String(id).startsWith('sub-')) {
        import('../pages/host-detail/index.js').then(({ activateHostSubTab }) => {
          activateHostSubTab(id);
          const el = document.getElementById(id);
          if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
        });
        return;
      }
      const el = document.getElementById(id);
      if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    /* HBA scanner: see pages/hba-scanner.js (loads /api/scanner/hba from SQLite) */
    /* PII scanner: see pages/pii-scanner.js (GET /api/scanner/pii; run via ciscollector on agent) */

    /* Fleet Overview — UI from prototype; KPIs/widgets filled from API (SQLite via /api/strategic). */
    let strategicRange = '30d';

    const STRATEGIC_BY_RANGE = {
      '24h': { label: 'Last 24 hours', health: 0, grade: '-', gradeColor: 'var(--muted)', critical: 0, cis: 0, servers: 0, privs: [], hygiene: { active: 0, inactive: 0, common: 0 }, cred: { hosts: 0, exposed: 0, weak: 0, ok: 0 }, hba: [], sslEnforced: 0, sslScanned: false, drift: [], driftLabels: [], audit: [], heatmap: [], heatmapColumns: [], piiScanned: false },
      '7d': { label: 'Last 7 days', health: 0, grade: '-', gradeColor: 'var(--muted)', critical: 0, cis: 0, servers: 0, privs: [], hygiene: { active: 0, inactive: 0, common: 0 }, cred: { hosts: 0, exposed: 0, weak: 0, ok: 0 }, hba: [], sslEnforced: 0, sslScanned: false, drift: [], driftLabels: [], audit: [], heatmap: [], heatmapColumns: [], piiScanned: false },
      '30d': { label: 'Last 30 days', health: 0, grade: '-', gradeColor: 'var(--muted)', critical: 0, cis: 0, servers: 0, privs: [], hygiene: { active: 0, inactive: 0, common: 0 }, cred: { hosts: 0, exposed: 0, weak: 0, ok: 0 }, hba: [], sslEnforced: 0, sslScanned: false, drift: [], driftLabels: [], audit: [], heatmap: [], heatmapColumns: [], piiScanned: false },
    };
    if (boot?.strategic30d) STRATEGIC_BY_RANGE['30d'] = boot.strategic30d;

    function strategicNeedleDeg(score) {
      return -90 + (Math.min(100, Math.max(0, score)) / 100) * 180;
    }

    function strategicDonutCss(active, inactive, common) {
      const a = active * 3.6;
      const i = inactive * 3.6;
      return 'conic-gradient(var(--success) 0deg ' + a + 'deg, var(--warning) ' + a + 'deg ' + (a + i) + 'deg, var(--danger) ' + (a + i) + 'deg 360deg)';
    }

    function strategicHmClass(v) {
      if (v >= 3) return 'strategic-hm-high';
      if (v === 2) return 'strategic-hm-mod';
      if (v === 1) return 'strategic-hm-des';
      return 'strategic-hm-low';
    }

    /** One bar per API bucket (max ~8); do not expand to 30 daily columns. */
    function buildStrategicDriftItems(drift, driftLabels) {
      const d = drift || [];
      const labels = driftLabels || [];
      const n = Math.max(d.length, labels.length);
      const items = [];
      for (let i = 0; i < n; i++) {
        const row = d[i];
        if (!row && !labels[i]) continue;
        items.push({
          label: labels[i] != null ? String(labels[i]) : '',
          b: row?.b ?? row?.B ?? 0,
          dev: row?.d ?? row?.D ?? 0,
        });
      }
      return items;
    }

    function shortStrategicHostLabel(label) {
      const raw = String(label || '').trim();
      if (!raw) return 'host';
      const parts = raw.split(':');
      const host = parts.length >= 2 && parts[0] === 'postgres' ? parts[1] : raw;
      if (host.length <= 12) return host;
      return host.slice(0, 11) + '…';
    }

    const STRATEGIC_AUDIT_VISIBLE = 6;

    function renderStrategicComplianceCard(title, bodyHtml, footHtml, extraClass) {
      const cls = 'strategic-widget panel strategic-compliance-card' + (extraClass ? ' ' + extraClass : '');
      return '<div class="' + cls + '">' +
        '<div class="panel-header strategic-compliance-head">' + escapeHtml(title) + '</div>' +
        '<div class="strategic-compliance-body">' + bodyHtml + '</div>' +
        '<div class="strategic-compliance-foot">' + footHtml + '</div></div>';
    }

    function renderStrategicWidgetPanel(title, subtitle, bodyHtml, footHtml) {
      const foot = footHtml
        ? '<p class="strategic-widget-foot">' + footHtml + '</p>'
        : '';
      return '<div class="strategic-widget panel">' +
        '<div class="panel-header strategic-widget-head">' + escapeHtml(title) + '</div>' +
        '<div class="strategic-widget-body">' +
        (subtitle ? '<p class="strategic-widget-sub">' + escapeHtml(subtitle) + '</p>' : '') +
        bodyHtml + foot + '</div></div>';
    }

    function renderStrategicAuditPanel(audit) {
      const items = audit || [];
      if (!items.length) {
        return '<div class="strategic-chart-empty strategic-compliance-empty"></div>';
      }
      const rows = items.map(a =>
        '<li><span class="strategic-audit-text" title="' + escapeHtml(a[0] + ' - ' + a[1]) + '">' +
        '<span class="strategic-audit-check">' + escapeHtml(a[0]) + '</span>' +
        '<span class="strategic-audit-host"> · ' + escapeHtml(a[1]) + '</span></span>' +
        '<span class="badge badge-danger strategic-audit-badge">FAIL</span></li>',
      ).join('');
      const overflow = items.length > STRATEGIC_AUDIT_VISIBLE;
      return '<div class="strategic-audit-scroll' + (overflow ? ' is-scrollable' : '') + '"' +
        (overflow ? ' tabindex="0" aria-label="Scroll critical settings audit list"' : '') + '>' +
        '<ul class="strategic-audit-list">' + rows + '</ul></div>';
    }

    function renderStrategicDashboard(range, opts) {
      const r = STRATEGIC_BY_RANGE[range] || STRATEGIC_BY_RANGE['30d'];
      strategicRange = range;
      const root = document.getElementById('strategic-root');
      if (!root) return;

      const privsBarWidth = 68;
      const privsCount = r.privs?.length || 0;
      const privsChartMinPx = Math.max(privsCount * privsBarWidth, 1);
      const privsHtml = (r.privs || []).map((p) => {
        const hostLabel = shortStrategicHostLabel(p.l);
        return '<div class="strategic-bar-group" title="' + escapeHtml(p.l || hostLabel) + '">' +
          '<div class="strategic-bar-stack">' +
          '<div class="strategic-bar-seg admin" style="height:' + p.a + '%"></div>' +
          '<div class="strategic-bar-seg user" style="height:' + p.u + '%"></div></div>' +
          '<span class="strategic-bar-label">' + escapeHtml(hostLabel) + '</span></div>';
      }).join('');
      const privsChartHtml = privsCount
        ? '<div class="strategic-bar-chart-scroll" tabindex="0" aria-label="Scroll elevated role exposure chart">' +
          '<div class="strategic-bar-chart strategic-bar-chart--scroll" style="min-width:' + privsChartMinPx + 'px">' +
          privsHtml + '</div></div>' +
          '<p class="strategic-bar-legend">' +
          '<span class="strategic-bar-legend-item"><span class="strategic-bar-leg strategic-bar-leg--fail">■</span> Elevated Roles</span>' +
          '<span class="strategic-bar-legend-item"><span class="strategic-bar-leg strategic-bar-leg--pass">■</span> Standard Roles</span></p>'
        : '<div class="strategic-chart-empty"></div>';
      const privsSubtitle = privsCount
        ? privsCount + ' host' + (privsCount === 1 ? '' : 's') +
          ' · share of login roles with SUPERUSER, CREATEDB, CREATEROLE, or BYPASSRLS'
        : 'Run CIS users report scans to compare elevated role share per host';

      const hbaBarWidth = 68;
      const hbaCount = r.hba?.length || 0;
      const hbaBarsHtml = r.hbaScanned && hbaCount
        ? r.hba.map(h => {
          const failPct = Math.max(0, Number(h.o) || 0);
          const passPct = Math.max(0, Number(h.s) || 0);
          const inactivePct = Math.max(0, Number(h.i) || 0);
          const hostLabel = shortStrategicHostLabel(h.l);
          const inactiveSeg = inactivePct > 0
            ? '<div class="strategic-bar-seg inactive" style="height:' + inactivePct + '%"></div>'
            : '';
          return '<div class="strategic-bar-group" title="' + escapeHtml(h.l || hostLabel) + '">' +
            '<div class="strategic-bar-stack">' +
            '<div class="strategic-bar-seg secure" style="height:' + passPct + '%"></div>' +
            inactiveSeg +
            '<div class="strategic-bar-seg open" style="height:' + failPct + '%"></div></div>' +
            '<span class="strategic-bar-label">' + escapeHtml(hostLabel) + '</span></div>';
        }).join('')
        : '';
      const hbaChartMinPx = Math.max(hbaCount * hbaBarWidth, 1);
      const hbaHtml = hbaBarsHtml
        ? '<div class="strategic-bar-chart-scroll" tabindex="0" aria-label="Scroll HBA config risks chart">' +
          '<div class="strategic-bar-chart strategic-bar-chart--scroll" style="min-width:' + hbaChartMinPx + 'px">' +
          hbaBarsHtml + '</div></div>'
        : '<div class="strategic-chart-empty"></div>';
      const hbaHasInactive = (r.hba || []).some(h => (Number(h.i) || 0) > 0);
      const hbaLegendHtml = '<p class="strategic-bar-legend">' +
        '<span class="strategic-bar-legend-item"><span class="strategic-bar-leg strategic-bar-leg--pass">■</span> Pass</span>' +
        '<span class="strategic-bar-legend-item"><span class="strategic-bar-leg strategic-bar-leg--fail">■</span> Fail</span>' +
        (hbaHasInactive
          ? '<span class="strategic-bar-legend-item"><span class="strategic-bar-leg strategic-bar-leg--inactive">■</span> Inactive</span>'
          : '') +
        '</p>';
      const hbaSubtitle = r.hbaScanned && hbaCount
        ? hbaCount + ' host' + (hbaCount === 1 ? '' : 's') + ' · pg_hba rule outcomes from hba_scanner'
        : 'Add hba_scanner to scan_commands to assess pg_hba.conf rules';

      const driftItems = buildStrategicDriftItems(r.drift, r.driftLabels);
      const driftHostsWithData = driftItems.filter((p) => (Number(p.b) || 0) + (Number(p.dev) || 0) > 0);
      const driftHasData = driftHostsWithData.length > 0;
      const driftHostCount = driftHostsWithData.length;
      const driftMatchedKeys = driftHostsWithData.reduce((sum, p) => sum + (Number(p.b) || 0), 0);
      const driftDeviatedKeys = driftHostsWithData.reduce((sum, p) => sum + (Number(p.dev) || 0), 0);
      const driftBarWidth = 68;
      const driftChartMinPx = Math.max(driftHostCount * driftBarWidth, 1);
      const driftBarsHtml = driftHostsWithData.map((p) => {
        const stableN = Number(p.b) || 0;
        const devN = Number(p.dev) || 0;
        const hostLabel = shortStrategicHostLabel(p.label);
        return '<div class="strategic-bar-group" title="' + escapeHtml(p.label || hostLabel) + '">' +
          '<div class="strategic-drift-col">' +
          '<div class="strategic-drift-base" style="flex:' + stableN + '"></div>' +
          '<div class="strategic-drift-dev" style="flex:' + devN + '"></div></div>' +
          '<span class="strategic-bar-label">' + escapeHtml(hostLabel) + '</span></div>';
      }).join('');
      const driftChartHtml = driftHasData
        ? '<div class="strategic-bar-chart-scroll" tabindex="0" aria-label="Scroll GUC config drift chart">' +
          '<div class="strategic-line-chart strategic-line-chart--compliance strategic-bar-chart--scroll" style="min-width:' + driftChartMinPx + 'px">' +
          driftBarsHtml + '</div></div>'
        : '';
      const driftSubtitle = driftHasData
        ? driftHostCount + ' host' + (driftHostCount === 1 ? '' : 's') +
          ' · ' + driftMatchedKeys + ' matched · ' + driftDeviatedKeys + ' drifted GUC keys'
        : 'Compare live SHOW ALL settings from collectors against your golden baseline';

      const hmRows = ['High', 'Moderate', 'Desirable', 'Low'];
      const hmCols = r.heatmapColumns || [];
      const hmGrid = r.heatmap || [];
      const heatmapHtml = r.piiScanned && hmCols.length && hmGrid.length
        ? hmGrid.map((row, i) =>
          '<tr><td>' + hmRows[i] + '</td>' + row.map(v => '<td class="' + strategicHmClass(v) + '">' + v + '</td>').join('') + '</tr>',
        ).join('')
        : '';
      const heatmapBody = heatmapHtml
        ? '<table class="strategic-heatmap-table"><thead><tr><th>Severity</th>' +
          hmCols.map(c => '<th>' + escapeHtml(c) + '</th>').join('') +
          '</tr></thead><tbody>' + heatmapHtml + '</tbody></table>'
        : '<div class="strategic-chart-empty strategic-compliance-empty"></div>' +
          '<p class="strategic-compliance-hint">No PII scan data yet. Add <code>pii_scanner</code> to <code>scan_commands</code> and configure <code>[piiscanner]</code>.</p>';
      const sslDeg = r.sslScanned ? r.sslEnforced * 3.6 : 0;
      const violPct = r.sslScanned ? 100 - r.sslEnforced : 0;
      const sslDonutHtml = r.sslScanned
        ? '<div class="strategic-donut" style="background:conic-gradient(var(--success) 0deg ' + sslDeg + 'deg, var(--danger) ' + sslDeg + 'deg 360deg);"></div>' +
          '<div class="strategic-donut-legend">' +
          '<span class="strategic-legend-enforced">TLS Enforced (' + r.sslEnforced + '%)</span>' +
          '<span class="strategic-legend-violation">Gaps (' + violPct + '%)</span></div>'
        : '<div class="strategic-donut strategic-donut--empty"></div>';
      const sslSubtitle = r.sslScanned
        ? r.sslEnforced + '% of fleet connections enforce TLS · ' + violPct + '% gaps'
        : 'Add ssl_audit to scan_commands to measure TLS enforcement';
      const hygieneSubtitle = (r.hygiene?.active || r.hygiene?.inactive || r.hygiene?.common)
        ? 'Active ' + (r.hygiene.active || 0) + '% · inactive expiry ' + (r.hygiene.inactive || 0) +
          '% · elevated roles ' + (r.hygiene.common || 0) + '%'
        : 'Password expiry and elevated-role counts from Users Report';
      const credSubtitle = ((r.cred?.exposed || 0) + (r.cred?.weak || 0) + (r.cred?.ok || 0)) > 0
        ? (r.cred.hosts || 0) + ' leak host' + ((r.cred.hosts || 0) === 1 ? '' : 's') +
          ' · ' + (r.cred.weak || 0) + ' weak hygiene · ' + (r.cred.ok || 0) + ' OK'
        : 'Dark-web password leaks and weak credential hygiene per host';
      const auditCount = r.audit?.length || 0;
      const auditSubtitle = auditCount
        ? auditCount + ' failed logging/GUC controls · latest scan per host'
        : 'Failed CIS config-audit checks (sections 3–6)';
      const piiHostCount = hmCols.length;
      const piiFindings = (r.heatmap || []).flat().reduce((sum, v) => sum + (Number(v) || 0), 0);
      const piiSubtitle = r.piiScanned && piiHostCount
        ? piiHostCount + ' host' + (piiHostCount === 1 ? '' : 's') + ' · ' + piiFindings +
          ' PII finding' + (piiFindings === 1 ? '' : 's') + ' by severity'
        : 'Add pii_scanner to scan_commands and configure [piiscanner]';
      const updatedNote = opts && opts.refreshed ? '<span class="strategic-updated">Updated just now</span>' : '';

      root.innerHTML =
        '<div class="strategic-page-head">' +
        '<h1>Fleet Overview</h1>' +
        '<p class="subtitle">Main report view · fleet aggregates for <strong>' + r.label + '</strong> · ' + r.servers + ' monitored servers</p></div>' +
        '<div class="strategic-toolbar">' +
        '<select id="strategic-range-select" class="btn" style="padding:8px 14px;cursor:pointer;" aria-label="Fleet overview time range">' +
        '<option value="24h"' + (range === '24h' ? ' selected' : '') + '>Last 24 hours</option>' +
        '<option value="7d"' + (range === '7d' ? ' selected' : '') + '>Last 7 days</option>' +
        '<option value="30d"' + (range === '30d' ? ' selected' : '') + '>Last 30 days</option></select>' +
        '<button type="button" class="btn btn-primary" id="strategic-refresh-btn">Refresh</button>' + updatedNote +
        '</div>' +
        (r.servers === 0
          ? '<div class="strategic-notice" style="border-color:var(--warning);"><strong>No scan data</strong> — run <code>ciscollector</code> to persist reports in SQLite, then refresh.</div>'
          : '') +
        '<div class="strategic-kpi-row stats" style="margin-bottom:28px;">' +
        '<div class="stat-card strategic-kpi"><div class="stat-label">Estate Health Score</div>' +
        '<div class="strategic-gauge-wrap" style="margin-top:8px;">' +
        '<div class="strategic-gauge"><span class="strategic-gauge-needle" style="transform:translateX(-50%) rotate(' + strategicNeedleDeg(r.health) + 'deg)"></span></div>' +
        '<div><div class="strategic-grade" style="color:' + r.gradeColor + '">' + r.grade + '</div>' +
        '<div style="font-size:26px;font-weight:700;color:var(--text-bright);">' + r.health + '<span style="font-size:14px;color:var(--muted);font-weight:400;">/100</span></div></div></div></div>' +
        '<div class="stat-card strategic-kpi"><div class="stat-label">Critical Violations</div>' +
        '<div class="stat-value danger" style="font-size:40px;margin-top:6px;">' + r.critical + '</div>' +
        '<div class="strategic-kpi-sub">Drill Down: <span class="link" data-goto="critical-violations">Critical Violations Table</span></div></div>' +
        '<div class="stat-card strategic-kpi"><div class="stat-label">CIS Compliance</div>' +
        '<div style="font-size:28px;font-weight:700;color:var(--text-bright);margin-top:6px;">' + r.cis + '%</div>' +
        '<div class="strategic-progress"><div class="strategic-progress-fill" style="width:' + r.cis + '%"></div></div>' +
        '<div class="strategic-kpi-sub">CIS Benchmarks · Menu 2</div></div>' +
        '<div class="stat-card strategic-kpi"><div class="stat-label">Monitored Servers</div>' +
        '<div class="stat-value" style="font-size:40px;margin-top:6px;">' + r.servers + '</div>' +
        '<div class="strategic-kpi-sub">PostgreSQL Collectors</div></div></div>' +
        buildFleetTilesMarkup() +
        '<h2 class="strategic-section-title">Identity &amp; Access</h2><div class="strategic-row">' +
        renderStrategicWidgetPanel(
          'Elevated Role Exposure',
          privsSubtitle,
          privsChartHtml,
          '',
        ) +
        renderStrategicWidgetPanel(
          'Login Role Hygiene',
          hygieneSubtitle,
          '<div class="strategic-widget-chart strategic-widget-chart--center">' +
          '<div class="strategic-donut" style="background:' + strategicDonutCss(r.hygiene.active, r.hygiene.inactive, r.hygiene.common) + '"></div>' +
          '<div class="strategic-donut-legend">' +
          '<span class="strategic-legend-active">Active ' + (r.hygiene.active || 0) + '%</span>' +
          '<span class="strategic-legend-inactive">Inactive Expiry ' + (r.hygiene.inactive || 0) + '%</span>' +
          '<span class="strategic-legend-common">Elevated ' + (r.hygiene.common || 0) + '%</span></div></div>',
          '',
        ) +
        renderStrategicWidgetPanel(
          'Credential & Password Risks',
          credSubtitle,
          '<p class="strategic-cred-lead">Password Leak Hosts: <strong style="color:var(--danger);">' + (r.cred.hosts || 0) + '</strong></p>' +
          '<div class="strategic-risk-bar">' +
          '<span style="flex:' + (r.cred.exposed || 0) + ';background:var(--danger);font-size:10px;">EXPOSED</span>' +
          '<span style="flex:' + (r.cred.weak || 0) + ';background:var(--warning);font-size:10px;">WEAK</span>' +
          '<span style="flex:' + (r.cred.ok || 0) + ';background:var(--kloud-purple-mid);color:var(--muted);font-size:10px;">OK</span></div>',
          '<span class="link" data-goto="fleet-category" data-fleet-cat="password-leakage">Open Password Leakage →</span>',
        ) +
        '</div>' +
        '<h2 class="strategic-section-title">Network &amp; Connectivity</h2><div class="strategic-row">' +
        renderStrategicWidgetPanel(
          'pg_hba.conf Rule Outcomes',
          hbaSubtitle,
          hbaHtml + hbaLegendHtml,
          '<span class="link" data-goto="hba-scanner">Open HBA Scanner →</span>',
        ) +
        renderStrategicWidgetPanel(
          'SSL/TLS Enforcement',
          sslSubtitle,
          '<div class="strategic-widget-chart strategic-widget-chart--center">' + sslDonutHtml + '</div>',
          '<span class="link" data-goto="ssl-scanner">Open SSL Scanner →</span>',
        ) +
        '</div>' +
        '<h2 class="strategic-section-title">Configuration &amp; Compliance</h2><div class="strategic-row strategic-row-2">' +
        renderStrategicComplianceCard(
          'GUC Config Drift vs Baseline',
          '<p class="strategic-compliance-sub">' + escapeHtml(driftSubtitle) + '</p>' +
          '<div class="strategic-compliance-slot">' +
          (driftHasData
            ? driftChartHtml
            : '<div class="strategic-chart-empty strategic-compliance-empty"></div>' +
              '<p class="strategic-compliance-hint">Upload a GUC baseline on the <span class="link" data-goto="guc-drift">GUC drift</span> page, or run CIS config-audit scans.</p>') +
          '</div>' +
          '<p class="strategic-compliance-legend">' +
          '<span class="strategic-leg strategic-leg--stable">Matched Baseline</span>' +
          '<span class="strategic-leg strategic-leg--deviation">Drifted</span></p>',
          '<span class="link" data-goto="guc-drift">Open GUC Drift →</span>',
        ) +
        renderStrategicComplianceCard(
          'Critical CIS Config Failures',
          '<p class="strategic-compliance-sub">' + escapeHtml(auditSubtitle) + '</p>' +
          '<div class="strategic-compliance-slot strategic-compliance-slot--audit">' +
          renderStrategicAuditPanel(r.audit) + '</div>',
          '<span class="link" data-goto="fleet-category" data-fleet-cat="config-audit">Open Config Audit →</span>',
          'strategic-compliance-card--audit',
        ) +
        renderStrategicComplianceCard(
          'PII Sensitivity Heatmap',
          '<p class="strategic-compliance-sub">' + escapeHtml(piiSubtitle) + '</p>' +
          '<div class="strategic-compliance-slot strategic-compliance-slot--heatmap">' + heatmapBody + '</div>',
          '<span class="link" data-goto="fleet-category" data-fleet-cat="pii-violations">Open PII Violations →</span>',
          'strategic-compliance-card--heatmap',
        ) +
        '</div>';

      const globalRange = document.getElementById('global-range-select');
      if (globalRange) globalRange.value = range;
    }

    async function applyStrategicRange(range, refresh) {
      const root = document.getElementById('strategic-root');
      if (root) root.classList.add('is-refreshing');
      const api = window.__SHIELD_API__;
      if (api?.fetchStrategic) {
        try {
          const live = await api.fetchStrategic(range);
          if (live) STRATEGIC_BY_RANGE[range] = live;
        } catch (err) {
          console.warn('Strategic range load failed:', err);
        }
      }
      if (refresh && api?.reloadFleetCategories) {
        try {
          const cats = await api.reloadFleetCategories();
          if (cats?.length) FLEET_CATEGORIES = cats;
        } catch (err) {
          console.warn('Fleet categories reload failed:', err);
        }
      }
      const delay = refresh ? 380 : 0;
      setTimeout(() => {
        renderStrategicDashboard(range, { refreshed: refresh });
        if (root) root.classList.remove('is-refreshing');
      }, delay);
    }

    function ensureStrategicDashboardInit() {
      if (strategicDashboardInited) return;
      strategicDashboardInited = true;
      initStrategicDashboard();
    }

    function initStrategicDashboard() {
      renderStrategicDashboard(strategicRange);
      const root = document.getElementById('strategic-root');
      if (root) {
        root.addEventListener('change', e => {
          if (e.target.id === 'strategic-range-select') applyStrategicRange(e.target.value);
        });
        root.addEventListener('click', e => {
          if (e.target.id === 'strategic-refresh-btn') applyStrategicRange(strategicRange, true);
        });
      }
      const globalRange = document.getElementById('global-range-select');
      const globalRefresh = document.getElementById('global-refresh-btn');
      if (globalRange) {
        globalRange.addEventListener('change', () => {
          const range = globalRange.value;
          if (gcls('page-strategic-dashboard', 'active')) {
            applyStrategicRange(range);
          } else {
            strategicRange = range;
          }
        });
      }
      if (globalRefresh) {
        globalRefresh.addEventListener('click', () => {
          if (gcls('page-strategic-dashboard', 'active')) {
            const range = globalRange?.value || strategicRange;
            applyStrategicRange(range, true);
          }
        });
      }
    }

    /* Image 3 - Security policy engine (prototype) */
    const POLICY_CHECKS = [
      { id: 'postgres_cis', label: 'CIS benchmarks', cmd: 'postgres_cis', menu: '2' },
      { id: 'hba_scanner', label: 'HBA scanner', cmd: 'hba_scanner', menu: '3' },
      { id: 'pii_scan', label: 'PII scan', cmd: 'datascan', menu: '4' },
      { id: 'log_parser', label: 'Log parser (pg_log)', cmd: 'logparser', menu: '-' },
      { id: 'ssl_audit', label: 'SSL audit', cmd: 'ssl_audit', menu: '15' },
      { id: 'config_audit', label: 'Config audit', cmd: 'config_audit', menu: '16' },
      { id: 'password_leak', label: 'Password leakage', cmd: 'password_leak', menu: '10' },
      { id: 'common_users', label: 'Common users', cmd: 'common_users', menu: '9→4' },
      { id: 'inactive_users', label: 'Inactive users', cmd: 'inactive', menu: '6' },
    ];

    const POLICY_TEMPLATES = [
      { id: 'prod_strict', name: 'Prod strict', desc: 'All checks - critical production', checks: POLICY_CHECKS.map(c => c.id) },
      { id: 'dev_light', name: 'Dev light', desc: 'CIS + config audit only - dev/staging', checks: ['postgres_cis', 'config_audit', 'hba_scanner'] },
      { id: 'cis_only', name: 'CIS-only', desc: 'Compliance baseline - CIS report only', checks: ['postgres_cis'] },
      { id: 'log_heavy', name: 'Log-heavy', desc: 'CIS + log parser + inactive + password leak', checks: ['postgres_cis', 'log_parser', 'inactive_users', 'password_leak', 'config_audit'] },
      { id: 'minimal', name: 'Minimal', desc: 'HBA + SSL - connectivity smoke test', checks: ['hba_scanner', 'ssl_audit'] },
    ];

    let policySelectedChecks = new Set(POLICY_TEMPLATES[0].checks);
    let policyActiveTemplate = 'prod_strict';

    const POLICY_DEFINITIONS = [
      { id: 'prod_critical_policy', name: 'prod_critical_policy', checks: POLICY_TEMPLATES[0].checks },
      { id: 'prod_standard_policy', name: 'prod_standard_policy', checks: POLICY_TEMPLATES[1].checks },
      { id: 'dev_light_policy', name: 'dev_light_policy', checks: POLICY_TEMPLATES[1].checks },
    ];

    let POLICY_GROUPS = [
      { name: 'prod-critical', hosts: 30, policy: 'prod_critical_policy', schedule: '0 2 1 * *' },
      { name: 'prod-standard', hosts: 70, policy: 'prod_standard_policy', schedule: '0 3 * * 0' },
      { name: 'staging-all', hosts: 12, policy: 'dev_light_policy', schedule: '0 4 * * 1' },
    ];

    let POLICY_HOST_MAP = [
      { host: 'prod-db-01', group: 'prod-critical', policy: 'prod_critical_policy', override: false },
      { host: 'prod-db-02', group: 'prod-critical', policy: 'prod_critical_policy', override: false },
      { host: 'staging-db', group: 'staging-all', policy: 'dev_light_policy', override: false },
      { host: 'analytics-01', group: 'prod-standard', policy: 'prod_standard_policy', override: true },
      { host: 'legacy-pg', group: 'prod-standard', policy: 'dev_light_policy', override: true },
    ];

    function renderPolicyChecks() {
      const grid = document.getElementById('policy-check-grid');
      if (!grid) return;
      grid.innerHTML = POLICY_CHECKS.map(c => {
        const on = policySelectedChecks.has(c.id);
        return '<label class="policy-check-item"><input type="checkbox" data-check="' + c.id + '" ' + (on ? 'checked' : '') + ' />' +
          '<span><strong>' + c.label + '</strong><br><code>' + c.cmd + '</code> · menu ' + c.menu + '</span></label>';
      }).join('');
      grid.querySelectorAll('input[data-check]').forEach(cb => {
        cb.addEventListener('change', () => {
          if (cb.checked) policySelectedChecks.add(cb.dataset.check);
          else policySelectedChecks.delete(cb.dataset.check);
        });
      });
    }

    function renderPolicyTemplates() {
      const grid = document.getElementById('policy-template-grid');
      if (!grid) return;
      grid.innerHTML = POLICY_TEMPLATES.map(t => {
        const sel = t.id === policyActiveTemplate ? ' selected' : '';
        return '<div class="policy-template-card' + sel + '" data-template="' + t.id + '">' +
          '<h4>' + t.name + '</h4><p>' + t.desc + '</p><p style="margin-top:8px;font-size:11px;color:var(--muted);">' + t.checks.length + ' checks</p></div>';
      }).join('');
      grid.querySelectorAll('[data-template]').forEach(card => {
        card.addEventListener('click', () => {
          policyActiveTemplate = card.dataset.template;
          const t = POLICY_TEMPLATES.find(x => x.id === policyActiveTemplate);
          if (t) {
            policySelectedChecks = new Set(t.checks);
            document.getElementById('policy-selected-name').textContent = t.name;
            renderPolicyChecks();
            renderPolicyTemplates();
          }
        });
      });
    }

    function fillPolicySelects() {
      const opts = POLICY_DEFINITIONS.map(p => '<option value="' + p.id + '">' + p.name + '</option>').join('');
      ['policy-new-group-policy', 'policy-host-policy', 'policy-sched-target', 'email-policy-bundle'].forEach(id => {
        const el = document.getElementById(id);
        if (!el) return;
        if (id === 'policy-sched-target') {
          el.innerHTML = POLICY_GROUPS.map(g => '<option value="group:' + g.name + '">Group: ' + g.name + '</option>').join('') +
            POLICY_DEFINITIONS.map(p => '<option value="policy:' + p.id + '">Policy: ' + p.name + '</option>').join('');
        } else {
          el.innerHTML = opts;
        }
      });
      const hostPick = document.getElementById('policy-host-pick');
      if (hostPick) hostPick.innerHTML = hosts.map(([n]) => '<option value="' + n + '">' + n + '</option>').join('');
    }

    function renderPolicyGroups() {
      const tbody = document.getElementById('policy-groups-tbody');
      if (!tbody) return;
      tbody.innerHTML = POLICY_GROUPS.map(g =>
        '<tr><td><strong>' + g.name + '</strong></td><td>' + g.hosts + '</td><td><code>' + g.policy + '</code></td><td><code>' + g.schedule + '</code></td>' +
        '<td><span class="action-link" data-policy-tab-jump="schedule">Edit schedule</span></td></tr>'
      ).join('');
    }

    function renderPolicyHosts() {
      const tbody = document.getElementById('policy-hosts-tbody');
      if (!tbody) return;
      tbody.innerHTML = POLICY_HOST_MAP.map(h =>
        '<tr><td><strong>' + h.host + '</strong></td><td>' + h.group + '</td><td><code>' + h.policy + '</code></td>' +
        '<td>' + (h.override ? '<span class="badge badge-warning">Host override</span>' : '<span class="badge badge-muted">From group</span>') + '</td>' +
        '<td><span class="action-link" data-policy-host-edit="' + h.host + '">Change</span></td></tr>'
      ).join('');
    }

    function buildCronToml() {
      const target = gval('policy-sched-target', 'policy:prod_critical_policy');
      const cron = gval('policy-sched-cron', '0 2 1 * *');
      const cmds = [...policySelectedChecks].map(id => {
        const c = POLICY_CHECKS.find(x => x.id === id);
        return c ? '  name = "' + c.cmd + '"' : '';
      }).filter(Boolean).join('\n\n');
      return '# Policy schedule → kshieldconfig.toml\n[[crons]]\nschedule = "' + cron + '"\n# target: ' + target + '\n\n' +
        (cmds || '  name = "postgres_cis"') + '\n\n  [[crons.commands.postgres]]\n  host = "..."\n  # one block per host in group';
    }

    function buildEmailToml() {
      const host = gval('email-host', 'smtp.gmail.com');
      const port = gval('email-port', '587');
      const user = gval('email-user', 'you@gmail.com');
      const to = gval('email-to', '');
      const bundle = gval('email-policy-bundle', 'prod_critical_policy');
      return '# Email reports (Image 3 req 7)\n[email]\nhost = "' + host + '"\nport = ' + port +
        '\nusername = "' + user + '"\npassword = "app-password"\n\n# Report job (extends cron output)\nto = "' + to + '"\npolicy_bundle = "' + bundle + '"\nattach_html = true';
    }

    function bindPoliciesPrototypeChrome() {
      document.querySelectorAll('.policy-tab').forEach(tab => {
        tab.addEventListener('click', () => {
          document.querySelectorAll('.policy-tab').forEach(t => t.classList.remove('active'));
          document.querySelectorAll('.policy-section').forEach(s => s.classList.remove('active'));
          tab.classList.add('active');
          const id = tab.dataset.policyTab;
          (function(){var _e=document.getElementById('policy-sec-' + id);if(_e)_e.classList.add('active');})();
        });
      });

      gon('policy-use-template', 'click', () => {
        (function(){var _q=document.querySelector('.policy-tab[data-policy-tab="custom"]');if(_q)_q.click();})();
      });

      gon('policy-check-all', 'click', () => {
        policySelectedChecks = new Set(POLICY_CHECKS.map(c => c.id));
        renderPolicyChecks();
      });
      gon('policy-check-none', 'click', () => {
        policySelectedChecks.clear();
        renderPolicyChecks();
      });
      gon('policy-save', 'click', () => {
        const st = document.getElementById('policy-save-status');
        const name = gval('policy-name', 'custom_policy');
        if (st) { st.textContent = 'Saved "' + name + '" with ' + policySelectedChecks.size + ' checks'; st.style.color = 'var(--success)'; }
      });

      gon('policy-add-group', 'click', () => {
        const name = (gval('policy-new-group', '')).trim();
        const policy = gval('policy-new-group-policy');
        if (!name) return;
        POLICY_GROUPS.push({ name, hosts: 0, policy: policy || 'prod_standard_policy', schedule: '0 2 1 * *' });
        renderPolicyGroups();
        fillPolicySelects();
      });

      gon('policy-host-assign', 'click', () => {
        const host = gval('policy-host-pick');
        const policy = gval('policy-host-policy');
        const row = POLICY_HOST_MAP.find(h => h.host === host);
        if (row && policy) { row.policy = policy; row.override = true; renderPolicyHosts(); }
      });

      gon('policy-sched-save', 'click', () => {
        const pre = document.getElementById('policy-cron-toml');
        if (pre) pre.textContent = buildCronToml();
      });

      gon('policy-email-save', 'click', () => {
        const pre = document.getElementById('policy-email-toml');
        const st = document.getElementById('policy-email-status');
        if (pre) pre.textContent = buildEmailToml();
        if (st) { st.textContent = 'Email config preview updated'; st.style.color = 'var(--success)'; }
      });

      gon('policy-sched-freq', 'change', e => {
        const cronIn = document.getElementById('policy-sched-cron');
        if (cronIn && e.target.value !== 'custom') cronIn.value = e.target.value;
      });

      document.addEventListener('click', e => {
        const jump = e.target.closest('[data-policy-tab-jump]');
        if (jump) {
          e.preventDefault();
          (function(){var _q=document.querySelector('.policy-tab[data-policy-tab="' + jump.dataset.policyTabJump + '"]');if(_q)_q.click();})();
        }
        const fleetPol = e.target.closest('[data-goto="policies"]');
        if (fleetPol && location.hash.indexOf('fleet/custom-security') >= 0) {
          (function(){var _q=document.querySelector('.policy-tab[data-policy-tab="custom"]');if(_q)_q.click();})();
        }
      });
    }

    /* Policies page: initPoliciesPage() on navigate — see pages/policies-page.js */

    window.addEventListener('hashchange', () => { void applyRouteFromHash(); });
    void applyRouteFromHash();
