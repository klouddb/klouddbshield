import { loadHtml } from './dom.js';

const pageHtmlCache = new Map();
const pageLoadPromises = new Map();

function mountPageHtml(pageId, html) {
  if (document.getElementById(`page-${pageId}`)) return;
  const root = document.getElementById('page-root');
  if (!root) return;
  const wrap = document.createElement('div');
  wrap.innerHTML = html.trim();
  const section = wrap.firstElementChild;
  if (section) root.appendChild(section);
}

/**
 * Load a dashboard page fragment on demand and inject it into #page-root.
 * @param {string} pageId
 * @param {(relativePath: string) => string} assetUrl
 */
export async function ensurePageHtml(pageId, assetUrl) {
  if (document.getElementById(`page-${pageId}`)) return;

  if (pageHtmlCache.has(pageId)) {
    mountPageHtml(pageId, pageHtmlCache.get(pageId));
    return;
  }

  if (pageLoadPromises.has(pageId)) {
    await pageLoadPromises.get(pageId);
    return;
  }

  const promise = loadHtml(assetUrl(`pages/${pageId}.html`))
    .then((html) => {
      pageHtmlCache.set(pageId, html);
      mountPageHtml(pageId, html);
    })
    .finally(() => {
      pageLoadPromises.delete(pageId);
    });

  pageLoadPromises.set(pageId, promise);
  await promise;
}

/** Warm-cache likely next pages after first paint. */
export function prefetchPagesIdle(pageIds, assetUrl) {
  const warm = () => {
    for (const pageId of pageIds) {
      if (document.getElementById(`page-${pageId}`) || pageHtmlCache.has(pageId) || pageLoadPromises.has(pageId)) {
        continue;
      }
      const promise = loadHtml(assetUrl(`pages/${pageId}.html`))
        .then((html) => {
          pageHtmlCache.set(pageId, html);
        })
        .catch(() => {});
      pageLoadPromises.set(pageId, promise);
      promise.finally(() => pageLoadPromises.delete(pageId));
    }
  };

  if (typeof window.requestIdleCallback === 'function') {
    window.requestIdleCallback(warm, { timeout: 4000 });
  } else {
    window.setTimeout(warm, 1500);
  }
}
