let htmlReportCssLoaded = false;

/** Load html-report.css only when a report view is opened. */
export function ensureHtmlReportCss() {
  if (htmlReportCssLoaded) return;
  htmlReportCssLoaded = true;
  const link = document.createElement('link');
  link.rel = 'stylesheet';
  link.href = '/styles/html-report.css';
  document.head.appendChild(link);
}
