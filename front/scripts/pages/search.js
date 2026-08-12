/** Topbar hostname/IP search — navigates to Hosts and filters the table. */

let hostsSearchFilter = '';

export function getHostsSearchFilter() {
  return hostsSearchFilter;
}

export function setHostsSearchFilter(value) {
  hostsSearchFilter = String(value || '').trim().toLowerCase();
}

function emitHostsSearch() {
  window.dispatchEvent(new CustomEvent('shield:hosts-search', { detail: hostsSearchFilter }));
}

export function initGlobalSearch() {
  const input = document.getElementById('global-host-search') || document.querySelector('.topbar input[type="search"]');
  if (!input) return;
  if (!input.id) input.id = 'global-host-search';
  if (!input.getAttribute('aria-label')) {
    input.setAttribute('aria-label', 'Search hostname or IP');
  }
  input.addEventListener('input', () => {
    setHostsSearchFilter(input.value);
    emitHostsSearch();
  });
  input.addEventListener('keydown', (e) => {
    if (e.key !== 'Enter') return;
    e.preventDefault();
    setHostsSearchFilter(input.value);
    emitHostsSearch();
  });
  input.addEventListener('search', () => {
    setHostsSearchFilter(input.value);
    emitHostsSearch();
  });
}
