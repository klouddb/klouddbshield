/** Auto-synced from dba-console-prototype.html — re-run extract-prototype.mjs after edits */
export const DEFAULT_PAGE = 'strategic-dashboard';

/** Resolve the first page shell to load from the current hash (boot perf). */
export function parseInitialPageId() {
  const raw = (location.hash || '').replace(/^#/, '');
  if (!raw) return DEFAULT_PAGE;
  if (/^critical-violations(?:\/|$)/.test(raw)) return 'critical-violations';
  if (/^critical-checks(?:\/|$)/.test(raw)) return 'critical-violations';
  if (/^top-25-checks(?:\/|$)/.test(raw)) return 'critical-violations';
  if (/^hosts\/critical(?:\/|$)/.test(raw)) return 'critical-violations';
  if (raw === 'hosts') return 'hosts';
  if (raw === 'host-detail' || raw === 'host') return 'host-detail';
  if (/^report\//.test(raw)) return 'html-report';
  if (/^host\//.test(raw)) return 'host-detail';
  if (/^fleet\//.test(raw)) return 'fleet-category';
  if (/^guc-drift(?:\/|$)/.test(raw)) return 'guc-drift';
  if (PAGE_IDS.includes(raw)) return raw;
  return DEFAULT_PAGE;
}

export const PAGE_IDS = [
  "strategic-dashboard",
  "critical-violations",
  "fleet-category",
  "log-readiness",
  "hosts",
  "hba-scanner",
  "ssl-scanner",
  "pii-scanner",
  "backup-compliance",
  "log-parser",
  "host-detail",
  "html-report",
  "guc-drift",
  "inactive-users-report",
  "common-users-report",
  "policies",
  "collector-nodes",
];

export const PAGE_META = {
    'fleet-category': { title: 'Fleet category', crumb: 'Category detail' },
    'log-readiness': { title: 'Log Readiness', crumb: 'GUC Gates · Parser Readiness' },
    hosts: { title: 'Hosts', crumb: 'Monitored PostgreSQL hosts' },
    'host-detail': { title: 'Host Audit', crumb: 'Vertical Report · CIS, Config, Access, Ops' },
    'html-report': { title: 'Full HTML report', crumb: 'KloudDBShield multi-tab export' },
    'guc-drift': { title: 'GUC Drift', crumb: 'Vs Golden Baseline' },
    'inactive-users-report': { title: 'Inactive Users Report', crumb: 'Fleet-Wide · Log Parser Menu 6' },
    'common-users-report': { title: 'Common Users Report', crumb: 'Fleet-Wide · Users Report Menu 9' },
    'strategic-dashboard': { title: 'Fleet Overview', crumb: 'Executive Fleet Dashboard' },
    'critical-violations': { title: 'Critical Violations', crumb: 'Group By Violation' },
    'hba-scanner': { title: 'HBA Scanner', crumb: 'pg_hba.conf Checks · Menu 3' },
    'ssl-scanner': { title: 'SSL Scanner', crumb: 'SSL Audit · Menu 15' },
    'pii-scanner': { title: 'Postgres PII Report', crumb: 'PII Scan · Menu 4' },
    'backup-compliance': { title: 'Backup Compliance', crumb: 'Backup Windows · Extension Audit' },
    'log-parser': { title: 'Log parser', crumb: 'pg_log parser findings' },
    policies: { title: 'Security policies', crumb: 'Templates · groups · schedule · email' },
    'collector-nodes': { title: 'Collector Nodes', crumb: 'Live Fleet · Heartbeat Status' },
};
