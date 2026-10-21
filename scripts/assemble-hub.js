#!/usr/bin/env node
// assemble-hub.js — Ghép hub/index.html từ hub/shell.html + hub/sections/*.html
// Chạy lại bất cứ lúc nào sau khi sửa một chuyên mục:  node scripts/assemble-hub.js
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const HUB = path.join(ROOT, 'hub');
const SECTIONS = path.join(HUB, 'sections');

const shell = fs.readFileSync(path.join(HUB, 'shell.html'), 'utf8');
const files = fs
  .readdirSync(SECTIONS)
  .filter((f) => f.endsWith('.html'))
  .sort();
if (!files.length) {
  console.error('Không có chuyên mục nào trong hub/sections/');
  process.exit(1);
}

// Tiêu đề mục lục: bỏ "0N · " ở đầu h2 (số thứ tự + dấu chấm giữa)
const cleanTitle = (raw) =>
  raw
    .replace(/<[^>]*>/g, '')
    .replace(/^\s*\d+\s*·\s*/, '')
    .trim();

let sections = [];
let toc = [];
for (const f of files) {
  const html = fs.readFileSync(path.join(SECTIONS, f), 'utf8').trim();
  sections.push(html);
  const id = (html.match(/<section[^>]*id="([^"]+)"/) || [])[1] || '';
  const h2 = (html.match(/<h2[^>]*>([\s\S]*?)<\/h2>/) || [])[1] || '';
  if (id) toc.push(`<a href="#${id}">${cleanTitle(h2)}</a>`);
}

// Chuyên mục 10 — catalog 20 bài LAB, sinh tự động từ src/lab/dashboard.js
// (một nguồn dữ liệu duy nhất → hub không bao giờ lệch với lab).
const { renderCatalog } = await import(pathToFileURL(path.join(ROOT, 'src/lab/dashboard.js')));
const labSection = `<section class="topic" id="chuong-10">
<h2><span class="num">10</span> · Chọn bài LAB — Catalog 20 lỗ hổng thực hành</h2>

<p>Đây là <strong>bản đồ đầy đủ 20 bài lab</strong> của SecLab — mỗi bài gồm endpoint tương ứng, mục tiêu khai thác, thử thách CTF liên quan và file bài tập đi kèm. Khi chạy lab thật (<code>npm run serve</code>), cùng catalog này xuất hiện dưới dạng <strong>dashboard tương tác</strong> tại <code>http://127.0.0.1:3000/lab</code> — có lọc theo nhóm/độ khó, tìm kiếm, theo tiến độ làm bài (lưu trình duyệt) và nộp cờ CTF trực tiếp.</p>

<div class="card danger">
<h4>⚠️ Nhắc lại ranh giới</h4>
<p>Mọi endpoint dưới đây chỉ tồn tại trên <code>127.0.0.1</code> của máy bạn. Đừng bao giờ thử payload này trên website người khác — <strong>Điều 287 BLHS 2015</strong>.</p>
</div>

${renderCatalog()}

<p><em>Lời giải chi tiết (SPOILER — chỉ đối chiếu sau khi tự làm): <code>solutions/</code> trong repo — writeup 10 CTF + answer key 17 bài tập + solver 4 ngôn ngữ.</em></p>
</section>`;
sections.push(labSection);
toc.push('<a href="#chuong-10">Chọn bài LAB — Catalog 20 lỗ hổng</a>');

const out = shell
  .replace('<!--SECTIONS-->', sections.join('\n'))
  .replace('<!--TOC-->', toc.join('\n    '));

fs.writeFileSync(path.join(HUB, 'index.html'), out);
console.log(`assembled ${sections.length} sections (${files.length} file + catalog LAB tự sinh) -> hub/index.html (${out.length} chars)`);
