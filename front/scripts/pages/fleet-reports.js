import { initInactiveUsersReportPage } from './inactive-users-report.js';
import { initCommonUsersReportPage } from './common-users-report.js';
import { initUniqueIPReportPage } from './unique-ip-report.js';
import { initUnusedLinesReportPage } from './unused-lines-report.js';
import { initPasswordLeakReportPage } from './password-leak-report.js';

/** @typedef {'inactive-users' | 'common-users' | 'unique-ip' | 'unused-lines' | 'password-leak'} FleetReportTabId */

export const LEGACY_FLEET_REPORT_PAGE_TO_TAB = {
  'inactive-users-report': 'inactive-users',
  'common-users-report': 'common-users',
  'unique-ip-report': 'unique-ip',
  'unused-lines-report': 'unused-lines',
  'password-leak-report': 'password-leak',
};

export const FLEET_REPORT_TABS = [
  {
    id: 'inactive-users',
    label: 'Inactive Users',
    lead: 'Stale DB accounts from pg_log · eligible for access review',
  },
  {
    id: 'common-users',
    label: 'Common Users',
    lead: 'Login-capable roles across the fleet · CIS users report',
  },
  {
    id: 'unique-ip',
    label: 'Unique IPs',
    lead: 'Client addresses seen in connection logs · first-seen tracking',
  },
  {
    id: 'unused-lines',
    label: 'Unused HBA Lines',
    lead: 'pg_hba rules with no matching traffic · removal candidates',
  },
  {
    id: 'password-leak',
    label: 'Password Leaks',
    lead: 'Plaintext credentials captured in pg_log · treat as critical',
  },
];

const TAB_INIT = {
  'inactive-users': initInactiveUsersReportPage,
  'common-users': initCommonUsersReportPage,
  'unique-ip': initUniqueIPReportPage,
  'unused-lines': initUnusedLinesReportPage,
  'password-leak': initPasswordLeakReportPage,
};

const loaded = new Set();
let tabsBound = false;
/** @type {FleetReportTabId} */
let activeTab = 'inactive-users';

export function normalizeFleetReportTab(tab) {
  const id = String(tab || '').trim();
  if (FLEET_REPORT_TABS.some((t) => t.id === id)) return /** @type {FleetReportTabId} */ (id);
  return 'inactive-users';
}

export function fleetReportTabMeta(tabId) {
  return FLEET_REPORT_TABS.find((t) => t.id === tabId) || FLEET_REPORT_TABS[0];
}

export function parseFleetReportTabFromHash(raw) {
  const match = String(raw || '').match(/^fleet-reports(?:\/([^/]+))?$/);
  if (!match) return null;
  return normalizeFleetReportTab(match[1] || 'inactive-users');
}

function syncTabUi(tabId) {
  const meta = fleetReportTabMeta(tabId);
  document.querySelectorAll('#page-fleet-reports .fleet-report-pane').forEach((pane) => {
    const on = pane.getAttribute('data-report-pane') === tabId;
    pane.classList.toggle('is-active', on);
    pane.hidden = !on;
  });
  document.querySelectorAll('#page-fleet-reports .fleet-reports-tab').forEach((btn) => {
    const on = btn.getAttribute('data-report-pane') === tabId;
    btn.classList.toggle('is-active', on);
    btn.setAttribute('aria-selected', on ? 'true' : 'false');
    btn.tabIndex = on ? 0 : -1;
  });
  const lead = document.getElementById('fleet-reports-lead');
  if (lead) lead.textContent = meta.lead;
}

async function loadTabData(tabId, { force = false } = {}) {
  const init = TAB_INIT[tabId];
  if (!init) return;
  if (loaded.has(tabId) && !force) return;
  await init({ force });
  loaded.add(tabId);
}

function bindTabs(onTabChange) {
  if (tabsBound) return;
  tabsBound = true;
  const root = document.getElementById('page-fleet-reports');
  if (!root) return;

  root.addEventListener('click', (ev) => {
    const btn = ev.target.closest('.fleet-reports-tab[data-report-pane]');
    if (!btn || !root.contains(btn)) return;
    ev.preventDefault();
    const tabId = normalizeFleetReportTab(btn.getAttribute('data-report-pane'));
    if (tabId === activeTab) return;
    activeTab = tabId;
    syncTabUi(tabId);
    void loadTabData(tabId);
    if (onTabChange) onTabChange(tabId);
  });

  root.addEventListener('keydown', (ev) => {
    const tabs = [...root.querySelectorAll('.fleet-reports-tab[data-report-pane]')];
    const idx = tabs.findIndex((t) => t.getAttribute('data-report-pane') === activeTab);
    if (idx < 0) return;
    let next = idx;
    if (ev.key === 'ArrowRight') next = (idx + 1) % tabs.length;
    else if (ev.key === 'ArrowLeft') next = (idx - 1 + tabs.length) % tabs.length;
    else if (ev.key === 'Home') next = 0;
    else if (ev.key === 'End') next = tabs.length - 1;
    else return;
    ev.preventDefault();
    tabs[next].focus();
    tabs[next].click();
  });
}

/**
 * @param {{ tab?: string, force?: boolean, onTabChange?: (tab: string) => void }} [opts]
 */
export async function initFleetReportsPage(opts = {}) {
  activeTab = normalizeFleetReportTab(opts.tab);
  bindTabs(opts.onTabChange);
  syncTabUi(activeTab);
  await loadTabData(activeTab, { force: !!opts.force });
}
