#!/usr/bin/env node
// SecLab CLI — điểm vào của toàn bộ công cụ.
// Mọi lệnh "chủ động" (recon/scan/loadtest/slowloris) đều đi qua guard.js:
//   • mục tiêu public trên Internet → TỪ CHỐI CỨNG;
//   • dải riêng → bắt buộc có --i-own-this-target;
//   • loopback → tự do (lab chạy trên máy bạn).
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import fs from 'node:fs';
import { banner, c } from './utils/color.js';
import { assertAuthorizedTarget, SecurityError } from './guard.js';
import { startLabServer } from './lab/serve.js';
import { runRecon } from './modules/recon.js';
import { runScan } from './modules/vulnscan.js';
import { runLoadTest } from './modules/loadtest.js';
import { runSlowloris } from './modules/slowloris.js';
import { runCrawl } from './modules/scraper.js';
import { runFlowTest } from './modules/flowload.js';
import { runDetect } from './modules/detect.js';
import { listChallenges, submitFlag } from './modules/challenge.js';
import { runCodec, hashText, explain } from './modules/codec.js';
import { jwtDecode, jwtSign, jwtVerify, crackJwt, loadWordlist, DEFAULT_WORDLIST } from './modules/jwttool.js';
import { createHubServer, hubBanner } from './hub/serve.js';
import { writeReport } from './modules/report.js';

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));

function usage() {
  console.log(`  ${c.bold('CÁC LỆNH')}

  ${c.cyan('serve')}   [--port 3000] [--hardened]
        Khởi động lab web trên http://127.0.0.1:3000
        (mặc định: bản CỐ Ý DỄ TỔN THƯƠNG; --hardened: bản đã vá)

  ${c.cyan('recon')}   <target>
        Thu thập thông tin: headers, tech fingerprint, ports, robots.txt

  ${c.cyan('scan')}    <target> [--json]
        Quét lỗ hổng: SQLi (+ blind), XSS (reflected/stored/DOM), IDOR, CMDI, CSRF,
        JWT, open redirect, upload, XXE, proto pollution, mass assignment…
        Báo cáo .md + .html luôn ghi vào thư mục reports/ của project

  ${c.cyan('loadtest')}  <target> [--rps 100] [--duration 10] [--concurrency N] [--path=slow]
        Mô phỏng tải — đo RPS/latency, chứng minh tác động DoS trên lab
        (dùng dấu "=" cho --path để Git Bash không biến "/slow" thành đường dẫn Windows)

  ${c.cyan('slowloris')} <target> [--sockets 100] [--duration 20]
        Mô phỏng tấn công kết nối chậm trên lab

  ${c.cyan('flowtest')} <target> [--users 5] [--iterations 10] [--think 150] [--ramp 100]
        Mô phỏng LUỒNG NGƯỜI DÙNG THẬT: trang chủ → tìm kiếm → xem chi tiết,
        có think-time + ramp-up. Đo latency từng bước để thấy bước nào nghẽn.
        (chỉ lab cục bộ / server bạn sở hữu — như mọi lệnh tạo tải)

  ${c.cyan('crawl')}    --url=<https://site-công-khai> [--max-pages 30] [--depth 2] [--delay-ms 800]
        Cào dữ liệu web CÔNG KHAI một cách lịch sự: tôn trọng robots.txt,
        rate-limit, chỉ cùng-origin. Trích title/heading/link → reports/.
        (muốn cào lab cục bộ để tập: thêm --i-own-this-target)

  ${c.cyan('detect')}  <target>
        BLUE-TEAM: đọc /_lab/log của lab, nhận diện SQLi/XSS/traversal/dò admin/
        scanner từ log request, kèm BIỆN PHÁP PHÒNG THỦ tương ứng từng phát hiện

  ${c.cyan('challenge')} <target> [--submit=N --flag='FLAG{...}']
        Chế độ CTF: 10 thử thách (SQLi/Traversal/IDOR/Admin/CmdInj/JWT/XXE/ProtoPoll/MassAssign/BlindSQLi),
        cờ sinh ngẫu nhiên THEO PHIÊN lab — phải tự khai thác lỗ hổng để lấy cờ rồi nộp về server.
        Bản hardened từ chối nộp cờ: đã vá thì không còn đường lấy.

  ${c.cyan('codec')}   <op> <text>
        Bộ mã hoá nền tảng: b64enc/b64dec/hexenc/hexdec/urlenc/urldec/rot13,
        hoặc: codec hash sha256 <text>. Mỗi kết quả kèm bài học nó dạy.

  ${c.cyan('jwt')}     <decode|forge|verify|crack> ...
        Công cụ JWT cho bài LAB-11 (chạy cục bộ, không mạng):
          jwt decode <token>
          jwt forge --payload='{"sub":"ctfsvc"}' [--alg none] [--secret k]
          jwt verify <token> --secret=k
          jwt crack  <token> [--wordlist file.txt]   (từ điển secret yếu)

  ${c.cyan('hub')}      [--port 4000]
        Mở Hub học an toàn thông tin (SecHub) — 9 chuyên mục + mục lục,
        phục vụ tĩnh tại http://127.0.0.1:4000 (chỉ truy cập được từ máy này)

  ${c.cyan('doctor')}    Kiểm tra môi trường (Node, node:sqlite, port lab)
  ${c.cyan('labs')}      Danh sách bài thực hành trong exercises/

  ${c.bold('CỜ AN TOÀN')}
  ${c.yellow('--i-own-this-target')}   Bắt buộc khi nhắm dải IP riêng (10.x/172.16-31.x/192.168.x).
  Mục tiêu public trên Internet bị chặn cứng ở mọi lệnh — không có lối tắt.

  ${c.bold('QUY TRÌNH GỢI Ý')}
  1) npm run serve            → lab vuln chạy ở 127.0.0.1:3000
  2) node src/cli.js recon http://127.0.0.1:3000
  3) node src/cli.js scan http://127.0.0.1:3000
  4) node src/cli.js loadtest http://127.0.0.1:3000 --path /slow --rps 50 --duration 8
  5) npm run serve:hardened   → chạy bản đã vá ở port khác, scan lại và so sánh
`);
}

function argParse(rest) {
  const flags = {};
  const positional = [];
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (a.startsWith('--')) {
      const eq = a.indexOf('=');
      if (eq > 2) {
        // hỗ trợ cú pháp --key=value (an toàn với Git Bash: --path=slow không bị biến thành đường dẫn Windows)
        flags[a.slice(2, eq)] = a.slice(eq + 1);
        continue;
      }
      const key = a.slice(2);
      const next = rest[i + 1];
      if (next !== undefined && !next.startsWith('--')) {
        flags[key] = next;
        i += 1;
      } else {
        flags[key] = true;
      }
    } else {
      positional.push(a);
    }
  }
  return { flags, positional };
}

const num = (v, dflt) => (v === undefined || v === true ? dflt : Number(v) || dflt);
const str = (v, dflt) => (v === undefined || v === true ? dflt : String(v));

function printFindings(scan) {
  const sev = (s) => (s === 'high' ? c.red(s) : s === 'medium' ? c.yellow(s) : c.gray(s));
  console.log(`\n  ${c.bold('KẾT QUẢ QUÉT')} ${c.gray(scan.target)} (phạm vi: ${scan.scope})`);
  console.log(
    `  🔴 High: ${c.red(String(scan.summary.high))}   🟠 Medium: ${c.yellow(String(scan.summary.medium))}   ✅ Đạt: ${c.green(String(scan.summary.passed))}\n`
  );
  for (const f of scan.findings) {
    const icon = f.vulnerable === true ? '🔴' : f.vulnerable === false ? '✅' : 'ℹ️ ';
    console.log(`  ${icon} [${sev(f.severity)}] ${c.bold(f.id)} — ${f.title}`);
    if (f.evidence) console.log(`       ${c.dim('bằng chứng:')} ${f.evidence}`);
    if (f.detail) console.log(`       ${c.dim('khái niệm:')} ${f.detail}`);
    if (f.fix) console.log(`       ${c.green('cách vá:')} ${f.fix}`);
    console.log('');
  }
}

async function cmdDoctor() {
  console.log(`\n  ${c.bold('SECLAB DOCTOR')}`);
  const nodeOk = Number(process.versions.node.split('.')[0]) >= 22;
  console.log(`  Node.js ${process.versions.node} ${nodeOk ? c.green('(≥22 OK)') : c.red('(cần ≥22.5)')}`);
  try {
    await import('node:sqlite');
    console.log(`  node:sqlite          ${c.green('khả dụng')} — lab dùng SQL thật (SQL injection minh hoạ chuẩn)`);
  } catch {
    console.log(`  node:sqlite          ${c.yellow('không có')} — lab tự chuyển sang bộ mô phỏng trong bộ nhớ`);
  }
  const { default: net } = await import('node:net');
  const portFree = (p) =>
    new Promise((resolve) => {
      const s = net.createServer();
      s.once('error', () => resolve(false));
      s.listen(p, '127.0.0.1', () => s.close(() => resolve(true)));
    });
  for (const p of [3000, 3001]) {
    console.log(`  Port ${p}              ${(await portFree(p)) ? c.green('rảnh') : c.yellow('đang bị chiếm (lab có thể đã chạy)')}`);
  }
  console.log(`  Thư mục project      ${ROOT}`);
  console.log(`  Kiểm tra CI          ${fs.existsSync(path.join(ROOT, '.github/workflows/ci.yml')) ? c.green('có workflow') : c.red('thiếu')}`);
  console.log('');
}

async function cmdLabs() {
  const dir = path.join(ROOT, 'exercises');
  const files = fs.existsSync(dir) ? fs.readdirSync(dir).filter((f) => f.endsWith('.md')).sort() : [];
  console.log(`\n  ${c.bold('BÀI THỰC HÀNH')} (${dir})\n`);
  for (const f of files) {
    const first = fs.readFileSync(path.join(dir, f), 'utf8').split('\n').find((l) => l.startsWith('# ')) || '';
    console.log(`  ${c.cyan(f.padEnd(34))} ${first.replace(/^#\s*/, '')}`);
  }
  console.log('');
}

async function main() {
  const [, , cmd, ...rest] = process.argv;
  const { flags, positional } = argParse(rest);
  banner();

  const authOpts = { consent: flags['i-own-this-target'] === true };
  const target = positional[0];

  try {
    switch (cmd) {
      case undefined:
      case 'help':
      case '--help':
        usage();
        break;

      case 'doctor':
        await cmdDoctor();
        break;

      case 'hub': {
        const port = num(flags.port, 4000);
        const server = await createHubServer({ port });
        console.log(hubBanner(port));
        server.on('error', (e) => console.error(c.red(`server error: ${e.message}`)));
        break;
      }

      case 'labs':
        await cmdLabs();
        break;

      case 'serve': {
        const mode = flags.hardened ? 'hardened' : 'vuln';
        const port = num(flags.port, 3000);
        const server = await startLabServer({ mode, port });
        const kind = mode === 'hardened' ? c.green('HARDENED (đã vá)') : c.red('VULN (cố ý dễ tổn thương)');
        console.log(`  Lab web [${kind}] đang chạy tại ${c.bold(`http://127.0.0.1:${port}`)}`);
        console.log(`  Bind: 127.0.0.1 — KHÔNG thể truy cập từ máy khác.`);
        console.log(`  Mở trình duyệt hoặc: node src/cli.js scan http://127.0.0.1:${port}`);
        console.log(c.gray('  Nhấn Ctrl+C để dừng.\n'));
        server.on('error', (e) => console.error(c.red(`server error: ${e.message}`)));
        break;
      }

      case 'recon': {
        // Mitigation SSRF: mục tiêu được kiểm duyệt TẠI ENTRY và một lần nữa
        // bên trong module (runRecon gọi assertAuthorizedTarget trước khi fetch).
        // Mục tiêu public bị từ chối ở cả hai lớp.
        await assertAuthorizedTarget(target, authOpts);
        const r = await runRecon(target, authOpts);
        console.log(`\n  ${c.bold('RECON')} ${c.gray(r.target)}`);
        console.log(`  Host: ${r.host}  →  IP: ${r.addresses.join(', ')}  (phạm vi: ${c.green(r.scope)})`);
        console.log(`  GET / → ${r.status} (${r.responseMs}ms)`);
        if (r.ports.length) console.log(`  Port mở (quét ${'80,443,3000…8888'}): ${r.ports.join(', ')}`);
        console.log(`  ${c.bold('Fingerprint:')}`);
        for (const t of r.tech) console.log(`    • ${t.from}: ${t.value}`);
        if (!r.tech.length) console.log(`    ${c.gray('(headers nghèo nàn — server giấu thông tin, tốt)')}`);
        console.log(`  robots.txt: ${r.robots ? c.gray(r.robots.split('\n').slice(0, 3).join(' | ')) : c.gray('không có')}`);
        console.log(`  Lab metrics endpoint: ${r.hasLabMetrics ? 'có (_lab/metrics)' : 'không'}\n`);
        break;
      }

      case 'scan': {
        // Mitigation SSRF: kiểm duyệt mục tiêu tại entry (lớp 1) + trong runScan (lớp 2).
        // Báo cáo luôn ghi vào <project>/reports (hằng số) — không nhận đường dẫn từ CLI.
        await assertAuthorizedTarget(target, authOpts);
        const scan = await runScan(target, authOpts);
        printFindings(scan);
        if (flags.json) console.log(JSON.stringify(scan, null, 2));
        const { mdPath, htmlPath } = writeReport(scan);
        console.log(`  ${c.green('✔')} Báo cáo: ${path.relative(ROOT, mdPath)} và ${path.relative(ROOT, htmlPath)}\n`);
        break;
      }

      case 'loadtest': {
        // Mitigation SSRF: entry-guard (lớp 1) + guard trong runLoadTest (lớp 2).
        await assertAuthorizedTarget(target, authOpts);
        const res = await runLoadTest(target, {
          rps: num(flags.rps, 100),
          duration: num(flags.duration, 10),
          concurrency: flags.concurrency !== undefined ? num(flags.concurrency, undefined) : undefined,
          path: str(flags.path, '/'),
          onProgress: ({ sent }) => process.stdout.write(c.gray(`\r  đã gửi ${sent} request…`)),
          ...authOpts,
        });
        process.stdout.write('\n');
        console.log(`\n  ${c.bold('LOADTEST')} ${c.gray(res.target)}`);
        console.log(`  Gửi ${c.bold(String(res.sent))} request trong ${res.durationSec}s → ${c.bold(String(res.actualRps))} req/s thực tế (yêu cầu ${res.requestedRps})`);
        console.log(`  HTTP: ${Object.entries(res.statusCounts).map(([k, v]) => `${k}×${v}`).join('  ')}${res.errors ? `  (${res.errors} lỗi mạng/timeout)` : ''}`);
        console.log(`  Latency (ms): avg=${res.latency.avg}  p50=${res.latency.p50}  p90=${res.latency.p90}  p95=${res.latency.p95}  p99=${res.latency.p99}  max=${res.latency.max}`);
        if (res.serverReceived !== null) console.log(`  Server xác nhận đã nhận: ${res.serverReceived} request (theo /_lab/metrics)`);
        console.log(
          c.gray(
            `\n  💡 Đọc kết quả: nếu p95 tăng vọt và xuất hiện lỗi/timeout → endpoint đang nghẽn.\n     Chạy lại trên bản hardened (--hardened) sẽ thấy 429 dồn dập nhưng server không sập.\n`
          )
        );
        break;
      }

      case 'slowloris': {
        // Mitigation SSRF: entry-guard (lớp 1) + guard trong runSlowloris (lớp 2).
        await assertAuthorizedTarget(target, authOpts);
        const res = await runSlowloris(target, {
          sockets: num(flags.sockets, 100),
          durationMs: num(flags.duration, 20) * 1000,
          onProgress: ({ alive }) => process.stdout.write(c.gray(`\r  kết nối còn giữ: ${alive}   `)),
          ...authOpts,
        });
        process.stdout.write('\n');
        console.log(`\n  ${c.bold('SLOWLORIS')} ${c.gray(res.target)}`);
        console.log(`  Đã mở ${res.opened}/${res.requested} kết nối "nửa request".`);
        console.log(`  Bị server đóng sớm: ${res.earlyClosed}.  Còn giữ đến cuối: ${res.stillConnected}.`);
        console.log(`  Kết luận: ${res.stillConnected > res.requested * 0.5 ? c.red(res.conclusion) : c.green(res.conclusion)}\n`);
        break;
      }

      case 'flowtest': {
        // Mitigation SSRF: entry-guard (lớp 1) + guard trong runFlowTest (lớp 2).
        await assertAuthorizedTarget(target, authOpts);
        const res = await runFlowTest(target, {
          users: num(flags.users, 5),
          iterations: num(flags.iterations, 10),
          thinkMs: num(flags.think, 150),
          rampUpMs: num(flags.ramp, 100),
          onProgress: ({ doneIters, totalIters }) =>
            process.stdout.write(c.gray(`\r  hoàn thành ${doneIters}/${totalIters} chuỗi luồng…`)),
          ...authOpts,
        });
        process.stdout.write('\n');
        console.log(`\n  ${c.bold('FLOWTEST')} ${c.gray(res.target)}`);
        console.log(`  ${res.users} virtual user × ${res.iterations} vòng · luồng: ${res.flow.join(' → ')}`);
        console.log(`  Tổng ${res.totals.sent} request trong ${res.totals.durationSec}s (${res.totals.rps} req/s) · lỗi: ${res.totals.errors}`);
        console.log(`  HTTP: ${Object.entries(res.statusCounts).map(([k, v]) => `${k}×${v}`).join('  ')}`);
        console.log(`  Thời gian 1 chuỗi luồng: avg=${res.chainMs.avg}ms  p95=${res.chainMs.p95}ms  max=${res.chainMs.max}ms`);
        console.log(`  ${c.bold('Theo từng bước:')}`);
        for (const s of res.steps) {
          const bad = s.errors > 0 || (s.statusCounts['429'] ?? 0) > s.count / 2;
          const color = bad ? c.yellow : c.green;
          console.log(
            `   ${color('•')} ${s.name.padEnd(20)} ${String(s.count).padStart(4)} req  avg=${String(s.avg).padStart(5)}ms  p95=${String(s.p95).padStart(5)}ms  ` +
              `HTTP ${Object.entries(s.statusCounts).map(([k, v]) => `${k}×${v}`).join(',')}${s.errors ? ` (lỗi ${s.errors})` : ''}`
          );
        }
        console.log(
          c.gray(`\n  💡 Bước nào p95 tăng vọt hoặc 429 nhiều → bước nghẽn đầu tiên khi có tải thật.\n`)
        );
        break;
      }

      case 'crawl': {
        // Mitigation SSRF: guard riêng của scraper (lớp duy nhất, ngược chiều với
        // module tấn công) — cho phép web PUBLIC, chặn loopback/dải riêng trừ khi
        // có --i-own-this-target (thực hành trên lab bạn sở hữu).
        const crawlUrl = flags.url && flags.url !== true ? flags.url : target;
        const res = await runCrawl(crawlUrl, {
          maxPages: num(flags['max-pages'], 30),
          depth: num(flags.depth, 2),
          delayMs: num(flags['delay-ms'], 800),
          consent: authOpts.consent,
          onProgress: ({ done, last }) =>
            process.stdout.write(c.gray(`\r  ${done} trang… (HTTP ${last?.status ?? last?.error ?? '?'})   `)),
        });
        process.stdout.write('\n');
        console.log(`\n  ${c.bold('CRAWL')} ${c.gray(res.target)} (phạm vi: ${res.scope})`);
        console.log(`  robots.txt: ${res.robotsFound ? c.green('có — đã tôn trọng') : c.gray('không có')}${res.crawlDelayMs ? c.gray(` · delay ${res.crawlDelayMs}ms`) : ''}`);
        console.log(`  Lấy ${c.bold(String(res.stats.fetched))} trang · ${res.stats.robotsSkipped} URL bị robots chặn · ${res.stats.errors} lỗi · latency TB ${res.stats.avgMs}ms`);
        for (const p of res.pages.slice(0, 12)) {
          console.log(`   ${c.green('•')} [${p.status}] ${p.url}`);
          if (p.title) console.log(`       ${c.dim(p.title)}  (${p.textLength} chars)`);
        }
        if (res.pages.length > 12) console.log(`   ${c.gray(`… và ${res.pages.length - 12} trang nữa trong báo cáo`)}`);
        console.log(`  ${c.green('✔')} Báo cáo: ${path.relative(ROOT, res.reportPaths.mdPath)} · ${path.relative(ROOT, res.reportPaths.jsonPath)}\n`);
        break;
      }

      case 'detect': {
        // Mitigation SSRF: entry-guard (lớp 1) + guard trong runDetect (lớp 2).
        await assertAuthorizedTarget(target, authOpts);
        const res = await runDetect(target, authOpts);
        console.log(`\n  ${c.bold('DETECT — phân tích log blue-team')} ${c.gray(res.target)}`);
        console.log(`  ${res.totalRequests} request trong bộ nhớ server · phát hiện ${c.bold(String(res.attacksDetected))} nhóm dấu hiệu\n`);
        if (!res.findings.length) {
          console.log(`  ${c.green('✓')} Không thấy mẫu tấn công trong log. Hãy chạy loadtest/scan/slowloris rồi detect lại để thấy chúng xuất hiện.\n`);
          break;
        }
        for (const f of res.findings) {
          const icon = f.severity === 'high' ? '🔴' : '🟠';
          console.log(`  ${icon} [${f.severity}] ${c.bold(f.label)} — ${f.count} request`);
          for (const s of f.samples) console.log(`       ${c.dim('mẫu:')} ${s}`);
          console.log(`       ${c.green('phòng thủ:')} ${f.defense}`);
        }
        console.log(c.gray(`\n  💡 Ý nghĩa: tấn công luôn "to tiếng" trong log — blue-team phát hiện được là nhờ thấy MẪU, không phải thấy một request lạ lẻ tẻ.\n`));
        break;
      }

      case 'challenge': {
        // Mitigation SSRF: entry-guard + guard trong module (loopback/lab).
        await assertAuthorizedTarget(target, authOpts);
        const submitId = flags.submit !== undefined ? num(flags.submit, 0) : null;
        if (submitId !== null) {
          const flag = str(flags.flag, '');
          if (!flag) throw new Error('Nộp cờ cần cả --submit=<id> và --flag=\'FLAG{...}\'');
          const r = await submitFlag(target, submitId, flag, authOpts);
          if (r.disabled) {
            console.log(`\n  ${c.yellow('🔒')} ${r.message}\n`);
            break;
          }
          if (r.ok) {
            console.log(`\n  ${c.green('✔ CHÍNH XÁC!')} Cờ thử thách #${submitId} được chấp nhận.`);
            const n = r.count || 10;
            console.log(`  Điểm: ${c.bold(String(r.score))}/${r.total} · đã giải: ${r.solved.length}/${n} thử thách`);
            if (r.solved.length === n) console.log(`  ${c.green('🏆 HOÀN THÀNH TOÀN BỘ CTF — bạn đã khai thác đủ ' + n + ' lớp lỗ hổng web!')}`);
            console.log('');
          } else {
            console.log(`\n  ${c.red('✖ Cờ chưa đúng')} cho thử thách #${submitId}. Dùng lệnh challenge (không có --submit) để xem gợi ý.\n`);
            process.exitCode = 1;
          }
          break;
        }
        const list = await listChallenges(target, authOpts);
        console.log(`\n  ${c.bold('CHẾ ĐỘ CTF')} ${c.gray(list.target)} — ${list.enabled ? c.green('ĐANG BẬT (bản vuln)') : c.yellow('TẮT (bản hardened)')}`);
        console.log(`  Điểm hiện tại: ${c.bold(String(list.score))}/${list.total}\n`);
        for (const ch of list.challenges) {
          const done = ch.solved ? c.green('✔ đã giải') : c.gray('… chưa');
          console.log(`  #${ch.id} [${ch.points} điểm] ${ch.title} ${done}`);
          console.log(`       ${c.dim('gợi ý:')} ${ch.hint}`);
        }
        console.log(c.gray(`\n  💡 Cờ có dạng FLAG{ten-hash} và MỖI LẦN CHẠY LAB MỘT MẪU — tự khai thác, đừng tìm cờ của lần chạy khác.\n`));
        break;
      }

      case 'jwt': {
        const sub = str(positional[0], '');
        const tokenArg = str(positional[1], '');
        if (sub === 'decode') {
          const d = jwtDecode(tokenArg);
          if (!d) throw new Error('Token không hợp lệ (cần 3 phần base64url ngăn bởi dấu chấm).');
          console.log(`\n  ${c.bold('JWT DECODE')} ${c.gray('(chỉ giải mã — KHÔNG xác minh chữ ký)')}`);
          console.log(`  ${c.cyan('header   :')} ${JSON.stringify(d.header)}`);
          console.log(`  ${c.cyan('payload  :')} ${JSON.stringify(d.payload)}`);
          console.log(`  ${c.cyan('signature:')} ${d.signature || c.yellow('(rỗng — alg=none)')}`);
          console.log(c.gray('\n  💡 Payload JWT chỉ là base64url — ai cũng đọc được. Đừng bao giờ nhét bí mật vào JWT.\n'));
        } else if (sub === 'forge') {
          const payloadText = str(flags.payload, '');
          if (!payloadText) throw new Error('Cú pháp: jwt forge --payload=\'{"sub":"ctfsvc"}\' [--alg none] [--secret k]');
          let payload;
          try {
            payload = JSON.parse(payloadText);
          } catch {
            throw new Error('--payload phải là JSON hợp lệ. Ví dụ: --payload=\'{"sub":"ctfsvc","role":"svc"}\'');
          }
          const alg = str(flags.alg, 'HS256');
          const token = jwtSign(payload, str(flags.secret, ''), { alg });
          console.log(`\n  ${c.bold('JWT FORGE')} (alg=${alg}${alg === 'HS256' ? `, secret=${str(flags.secret, '') || c.yellow('(rỗng!)')}` : ''})`);
          console.log(`  ${c.green(token)}\n`);
          console.log(c.gray('  💡 alg=none + chữ ký rỗng: server cấu hình sai sẽ chấp nhận token không ký. Thử GET /api/profile?token=<này> trên lab vuln.\n'));
        } else if (sub === 'verify') {
          const secret = str(flags.secret, '');
          const v = jwtVerify(tokenArg, secret);
          console.log(`\n  ${c.bold('JWT VERIFY')} (HS256)`);
          console.log(`  ${v.ok ? c.green('✔ chữ ký hợp lệ') : c.red('✖ ' + v.error)}`);
          if (v.payload) console.log(`  payload: ${JSON.stringify(v.payload)}\n`);
        } else if (sub === 'crack') {
          const wl = flags.wordlist ? loadWordlist(str(flags.wordlist, '')) : DEFAULT_WORDLIST;
          console.log(`\n  ${c.bold('JWT CRACK')} — thử ${wl.length} secret trong từ điển…`);
          const r = crackJwt(tokenArg, wl);
          if (r.secret) {
            console.log(`  ${c.green('✔ TÌM THẤY secret:')} ${c.bold(r.secret)} (sau ${r.tried} lần thử)`);
            console.log(c.gray('  💡 Bài học: khoá HMAC yếu → attacker tải token về và brute-force OFFLINE. Chữ ký JWT không "giấu" gì cả.\n'));
          } else {
            console.log(`  ${c.yellow('✖')} Không crack được sau ${r.tried} lần thử${r.reason ? ` (${r.reason})` : ''} — secret đủ mạnh. Thử --wordlist=rockyou.txt.\n`);
          }
        } else {
          throw new Error('Cú pháp: jwt <decode|forge|verify|crack> … (xem help)');
        }
        break;
      }

      case 'codec': {
        const op = str(positional[0], '');
        const argText = positional.slice(1).join(' ');
        let result;
        if (op === 'hash') {
          const algo = str(positional[1], 'sha256');
          const text = positional.slice(2).join(' ');
          if (!text) throw new Error('Cú pháp: codec hash <sha256|sha1|md5> <văn bản>');
          result = hashText(algo, text);
          console.log(`\n  ${c.bold('HASH')} (${algo})`);
          console.log(`  input : ${text}`);
          console.log(`  output: ${c.bold(result)}`);
        } else {
          if (!op || !argText) {
            throw new Error('Cú pháp: codec <b64enc|b64dec|hexenc|hexdec|urlenc|urldec|rot13> <văn bản>  hoặc: codec hash <algo> <văn bản>');
          }
          result = runCodec(op, argText);
          console.log(`\n  ${c.bold('CODEC')} (${op})`);
          console.log(`  input : ${argText}`);
          console.log(`  output: ${c.bold(result)}`);
        }
        console.log(`\n  ${c.dim('📖 ' + explain(op === 'hash' ? 'hash' : op))}\n`);
        break;
      }

      default:
        console.log(c.red(`  Lệnh không rõ: "${cmd}". Dùng "node src/cli.js help" để xem danh sách.\n`));
        process.exitCode = 1;
    }
  } catch (e) {
    if (e instanceof SecurityError) {
      console.error(e.message + '\n');
      process.exitCode = 2;
    } else {
      console.error(c.red(`  Lỗi: ${e.message}`));
      process.exitCode = 1;
    }
  }
}

// Health-check nội bộ cho auth guard khi import (dùng bởi tests)
export async function checkTarget(target, opts) {
  return assertAuthorizedTarget(target, opts);
}

await main();
