// html.js — escape helper dùng chung cho app.js và dashboard.js
// (tách ra để tránh import vòng: dashboard.js cần esc, app.js cần dashboard.js).
export function esc(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
