import { API_CONFIG } from '../config.js';
import { apiFetch } from '../client.js';

export async function getGucDrift(opts = {}) {
  const params = new URLSearchParams();
  if (opts.groupId) params.set('group_id', opts.groupId);
  if (opts.targetId) params.set('target_id', opts.targetId);
  const qs = params.toString();
  const url = API_CONFIG.endpoints.gucDrift + (qs ? '?' + qs : '');
  return apiFetch(url);
}

export async function getGucBaseline(groupId) {
  const qs = groupId ? ('?group_id=' + encodeURIComponent(groupId)) : '';
  return apiFetch(API_CONFIG.endpoints.gucBaseline + qs);
}

export async function putGucBaseline(payload) {
  return apiFetch(API_CONFIG.endpoints.gucBaseline, {
    method: 'PUT',
    body: JSON.stringify(payload),
  });
}

export async function getGucSnapshots() {
  return apiFetch(API_CONFIG.endpoints.gucSnapshots);
}

export async function putGucIgnore(payload) {
  return apiFetch(API_CONFIG.endpoints.gucIgnores, {
    method: 'PUT',
    body: JSON.stringify(payload),
  });
}

export async function getGucGroups() {
  return apiFetch(API_CONFIG.endpoints.gucGroups);
}

export async function upsertGucGroup(payload) {
  return apiFetch(API_CONFIG.endpoints.gucGroups, {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export async function deleteGucGroup(groupId) {
  return apiFetch(API_CONFIG.endpoints.gucGroup(groupId), {
    method: 'DELETE',
  });
}

export async function putGucGroupMembers(groupId, targetIds) {
  return apiFetch(API_CONFIG.endpoints.gucGroupMembers(groupId), {
    method: 'PUT',
    body: JSON.stringify({ target_ids: targetIds }),
  });
}
