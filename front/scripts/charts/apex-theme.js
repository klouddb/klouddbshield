/**
 * ApexCharts dark theme defaults for KloudDB Shield dashboards.
 * Charts are optional — CSS-based strategic visuals remain the default.
 */
const APEX_CDN = 'https://cdn.jsdelivr.net/npm/apexcharts@3.54.1/dist/apexcharts.min.js';
let apexScriptPromise = null;

function loadApexChartsScript() {
  if (typeof window.ApexCharts !== 'undefined') return Promise.resolve();
  if (apexScriptPromise) return apexScriptPromise;
  apexScriptPromise = new Promise((resolve, reject) => {
    const script = document.createElement('script');
    script.src = APEX_CDN;
    script.async = true;
    script.onload = () => resolve();
    script.onerror = () => reject(new Error('Failed to load ApexCharts'));
    document.head.appendChild(script);
  });
  return apexScriptPromise;
}

export function apexDarkTheme() {
  return {
    chart: {
      background: 'transparent',
      foreColor: '#a8b0c4',
      toolbar: { show: false },
      fontFamily: 'inherit',
    },
    grid: { borderColor: '#424a5f' },
    theme: { mode: 'dark' },
    colors: ['#55a3d7', '#88bf57', '#e85d75', '#d4a84b'],
  };
}

export async function mountApexChart(el, options) {
  try {
    await loadApexChartsScript();
  } catch (err) {
    console.warn('ApexCharts not loaded', err);
    return null;
  }
  if (typeof window.ApexCharts === 'undefined') {
    console.warn('ApexCharts not loaded');
    return null;
  }
  const chart = new window.ApexCharts(el, {
    ...apexDarkTheme(),
    ...options,
  });
  chart.render();
  return chart;
}

export function destroyChart(chart) {
  if (chart && typeof chart.destroy === 'function') chart.destroy();
}
