#!/usr/bin/env node
// assemble-hub.js — Ghép hub/index.html từ hub/shell.html + hub/sections/*.html
// Chạy lại bất cứ lúc nào sau khi sửa một chuyên mục:  node scripts/assemble-hub.js
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

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

const out = shell
  .replace('<!--SECTIONS-->', sections.join('\n'))
  .replace('<!--TOC-->', toc.join('\n    '));

fs.writeFileSync(path.join(HUB, 'index.html'), out);
console.log(`assembled ${files.length} sections -> hub/index.html (${out.length} chars)`);
