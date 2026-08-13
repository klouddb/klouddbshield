import { API_CONFIG } from '../config.js';
import { apiFetch } from '../client.js';

export async function getBackupComplianceSummary() {
  return apiFetch(API_CONFIG.endpoints.backupComplianceSummary);
}

export async function getBackupComplianceHistory(filters = {}) {
  const params = new URLSearchParams();
  if (filters.server && filters.server !== 'all') params.set('server', filters.server);
  if (filters.backup_type) params.set('backup_type', filters.backup_type);
  if (filters.date) params.set('date', filters.date);
  if (filters.from) params.set('from', filters.from);
  if (filters.to) params.set('to', filters.to);
  if (filters.status) params.set('status', filters.status);
  const q = params.toString();
  return apiFetch(`${API_CONFIG.endpoints.backupComplianceHistory}${q ? `?${q}` : ''}`);
}

export async function getBackupCompliancePolicy() {
  return apiFetch(API_CONFIG.endpoints.backupCompliancePolicy);
}

export async function putBackupCompliancePolicy(payload) {
  return apiFetch(API_CONFIG.endpoints.backupCompliancePolicy, {
    method: 'PUT',
    body: JSON.stringify(payload),
  });
}
