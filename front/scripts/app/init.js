import { loadHtml } from '../utils/dom.js';
import { parseInitialPageId } from '../router/routes.js';
import { ensurePageHtml, prefetchPagesIdle } from '../utils/page-loader.js';
import {
  hostsApi,
  fleetApi,
  strategicApi,
  mapHostsResponse,
  mapFleetCategories,
  mapStrategicRange,
  normalizeStrategicRange,
  emptyStrategicRange,
} from '../api/index.js';

const BASE = new URL('.', import.meta.url);

function asset(path) {
  return new URL(`../../${path}`, BASE).pathname;
}

async function loadShell(initialPageId) {
  const [sidebar, topbar] = await Promise.all([
    loadHtml(asset('components/sidebar.html')),
    loadHtml(asset('components/topbar.html')),
  ]);

  const root = document.getElementById('app-root');
  if (!root) throw new Error('#app-root not found');

  root.innerHTML =
    sidebar +
    `<div class="main">${topbar}<main class="content" id="page-root" tabindex="-1"></main></div>`;

  await ensurePageHtml(initialPageId, asset);
  prefetchPagesIdle(
    ['strategic-dashboard', 'hosts', 'critical-violations', 'fleet-category', 'host-detail'],
    asset,
  );
}

async function loadBootData() {
  let hosts = [];
  let fleetCategories = [];
  let strategic30d = null;
  let criticalViolationRows = [];
  let criticalViolationFilters = {
    checkOptions: [],
    checkDefinitions: [],
    serverOptions: [],
    sourceOptions: [],
    typeOptions: [],
    severityOptions: [],
  };

  try {
    const [hostsData, fleetData, strategicData] = await Promise.all([
      hostsApi.getHosts(),
      fleetApi.getFleetCategories(),
      strategicApi.getStrategicMatrix('30d'),
    ]);
    hosts = mapHostsResponse(hostsData);
    fleetCategories = mapFleetCategories(fleetData);
    strategic30d = normalizeStrategicRange(
      mapStrategicRange(strategicData, '30d'),
      emptyStrategicRange('Last 30 days'),
    );
  } catch (err) {
    console.warn('API load failed — dashboard will show empty state until main-server is running:', err);
  }

  return {
    hosts,
    fleetCategories,
    strategic30d,
    criticalViolationRows,
    criticalViolationFilters,
    overview: null,
    runs: [],
  };
}

export async function initApp() {
  const initialPage = parseInitialPageId();
  const [, boot] = await Promise.all([loadShell(initialPage), loadBootData()]);

  const { initGlobalSearch } = await import('../pages/search.js');
  initGlobalSearch();

  const { fetchStrategicForRange, reloadFleetCategories } = await import('./strategic-loader.js');
  window.__SHIELD_API__ = {
    fetchStrategic: fetchStrategicForRange,
    reloadFleetCategories,
  };

  window.__SHIELD_BOOT__ = boot;

  await import('./prototype-app.js');
  const root = document.getElementById('app-root');
  if (root) {
    root.removeAttribute('aria-busy');
    root.setAttribute('aria-busy', 'false');
  }
}
