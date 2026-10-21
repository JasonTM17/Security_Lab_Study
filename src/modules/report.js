// report.js — sinh báo cáo quét (.md và .html) vào thư mục reports/.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const SEV_ORDER = { high: 0, medium: 1, low: 2, info: 3 };

// Thư mục báo cáo là HẰNG SỐ trong project — không nhận đường dẫn từ bên ngoài
// (mitigation path-traversal: không có input nào chạm vào fs.write).
const PROJECT_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const REPORTS_DIR = path.join(PROJECT_ROOT, 'reports');

export function writeReport(scan) {
  fs.mkdirSync(REPORTS_DIR, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const base = path.join(REPORTS_DIR, `scan-${stamp}`);
  const mdPath = `${base}.md`;
  const htmlPath = `${base}.html`;
  fs.writeFileSync(mdPath, buildMarkdown(scan), 'utf8');
  fs.writeFileSync(htmlPath, buildHtml(scan), 'utf8');
  return { mdPath, htmlPath };
}

export function buildMarkdown(scan) {
  const lines = [];
  lines.push(`# Báo cáo quét SecLab`);
  lines.push('');
  lines.push(`- **Mục tiêu:** ${scan.target} (phạm vi: ${scan.scope})`);
  lines.push(`- **Thời gian:** ${scan.startedAt} → ${scan.finishedAt}`);
  lines.push(`- **Tổng kết:** 🔴 High: ${scan.summary.high} · 🟠 Medium: ${scan.summary.medium} · ✅ Đạt: ${scan.summary.passed}`);
  lines.push('');
  lines.push(`| ID | Mức độ | Phát hiện |`);
  lines.push(`|---|---|---|`);
  for (const f of [...scan.findings].sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity])) {
    const icon = f.vulnerable === true ? '🔴' : f.vulnerable === false ? '✅' : 'ℹ️';
    lines.push(`| ${f.id} | ${icon} ${f.severity} | ${f.title} |`);
  }
  lines.push('');
  lines.push(`## Chi tiết`);
  for (const f of [...scan.findings].sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity])) {
    lines.push('');
    lines.push(`### ${f.id} — ${f.title} [${f.severity}]`);
    if (f.evidence) lines.push(`- **Bằng chứng:** ${f.evidence}`);
    if (f.detail) lines.push(`- **Khái niệm:** ${f.detail}`);
    if (f.fix) lines.push(`- **Cách vá:** ${f.fix}`);
  }
  lines.push('');
  lines.push('> SecLab chỉ dùng cho hệ thống bạn sở hữu. Mọi dữ liệu trong lab là giả lập.');
  return lines.join('\n');
}

export function buildHtml(scan) {
  const rows = [...scan.findings]
    .sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity])
    .map(
      (f) => `<tr class="${f.vulnerable === true ? 'vuln' : f.vulnerable === false ? 'ok' : 'info'}">
      <td>${f.id}</td><td>${f.severity}</td><td>${f.title}</td></tr>`
    )
    .join('\n');
  const details = [...scan.findings]
    .sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity])
    .map(
      (f) => `<section><h3>${f.id} — ${f.title}</h3>
      ${f.evidence ? `<p><b>Bằng chứng:</b> ${escapeHtml(f.evidence)}</p>` : ''}
      ${f.detail ? `<p><b>Khái niệm:</b> ${escapeHtml(f.detail)}</p>` : ''}
      ${f.fix ? `<p><b>Cách vá:</b> ${escapeHtml(f.fix)}</p>` : ''}</section>`
    )
    .join('\n');
  return `<!doctype html><html lang="vi"><head><meta charset="utf-8"><title>SecLab Report — ${escapeHtml(scan.target)}</title>
<style>body{font-family:system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem}
table{border-collapse:collapse;width:100%}td,th{border:1px solid #ddd;padding:8px;text-align:left}
.vuln{background:#fef2f2}.ok{background:#f0fdf4}.info{background:#f8fafc}
h2{border-bottom:2px solid #0a6}</style></head><body>
<h1>Báo cáo quét SecLab</h1>
<p>Mục tiêu: <b>${escapeHtml(scan.target)}</b> (phạm vi ${scan.scope})<br>
Thời gian: ${scan.startedAt}<br>
🔴 High: ${scan.summary.high} · 🟠 Medium: ${scan.summary.medium} · ✅ Đạt: ${scan.summary.passed}</p>
<table><tr><th>ID</th><th>Mức độ</th><th>Phát hiện</th></tr>${rows}</table>
<h2>Chi tiết</h2>${details}
<p><i>SecLab chỉ dùng cho hệ thống bạn sở hữu. Dữ liệu lab là giả lập.</i></p></body></html>`;
}

function escapeHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
