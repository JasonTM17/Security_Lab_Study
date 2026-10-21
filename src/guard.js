// guard.js — "Cửa ủy quyền" của toàn bộ công cụ.
// MỌI module chủ động (recon/scan/loadtest/slowloris) phải gọi assertAuthorizedTarget()
// trước khi gửi gói tin nào. Nguyên tắc:
//   - loopback (127.0.0.1, ::1, localhost): luôn cho phép (lab chạy trên máy mình).
//   - dải riêng RFC1918: chỉ cho phép khi có cờ --i-own-this-target (bạn khẳng định sở hữu).
//   - địa chỉ public Internet: TỪ CHỐI cứng, không có lối tắt.
import dns from 'node:dns/promises';
import net from 'node:net';
import { c } from './utils/color.js';

export class SecurityError extends Error {
  constructor(message) {
    super(message);
    this.name = 'SecurityError';
  }
}

/** Phân loại một địa chỉ IP: 'loopback' | 'private' | 'public'. */
export function classifyIp(ip) {
  if (net.isIPv4(ip)) {
    const o = ip.split('.').map(Number);
    if (o[0] === 127 || ip === '0.0.0.0') return 'loopback';
    if (o[0] === 10) return 'private';
    if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) return 'private';
    if (o[0] === 192 && o[1] === 168) return 'private';
    if (o[0] === 169 && o[1] === 254) return 'private';
    return 'public';
  }
  const low = String(ip).toLowerCase();
  if (low === '::1' || low === '::' || low.startsWith('::ffff:127.')) return 'loopback';
  if (low.startsWith('fc') || low.startsWith('fd') || low.startsWith('fe80')) return 'private';
  return 'public';
}

/** Chuẩn hoá input thành URL http/https. Ném SecurityError nếu sai cú pháp. */
export function parseTarget(raw) {
  let text = String(raw || '').trim();
  if (!text) throw new SecurityError('Chưa nhập mục tiêu. Ví dụ: http://127.0.0.1:3000');
  if (!/^https?:\/\//i.test(text)) text = `http://${text}`;
  let url;
  try {
    url = new URL(text);
  } catch {
    throw new SecurityError(`URL không hợp lệ: ${raw}`);
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new SecurityError('Chỉ hỗ trợ mục tiêu http:// hoặc https://');
  }
  return url;
}

const PUBLIC_REFUSE = (host, addrs) => [
  '',
  c.red('  ✖ TỪ CHỐI mục tiêu public trên Internet (chính sách cứng của SecLab).'),
  '',
  `  Mục tiêu "${host}" phân giải về địa chỉ công khai: ${addrs.join(', ')}`,
  '',
  '  Vì sao bị chặn:',
  '   • Quét/tạo tải/khai thác hệ thống KHÔNG thuộc sở hữu của bạn là hành vi bất hợp pháp.',
  '   • Tại Việt Nam: Điều 287 Bộ luật Hình sự 2015 (sửa đổi 2017) — tội gây cản trở',
  '     hoặc làm tê liệt hoạt động của mạng máy tính, mạng viễn thông — khung hình phạt',
  '     cao nhất lên tới nhiều năm tù. Luật An ninh mạng 2018 và Luật Giao dịch điện tử',
  '     cũng xử lý hành vi xâm nhập, cản trở hệ thống.',
  '',
  '  Cách học đúng đắn với SecLab:',
  '   1) npm run serve            → khởi động lab web có lỗ hổng chủ đích trên 127.0.0.1',
  '   2) nhắm mọi module vào       → http://127.0.0.1:3000',
  '   3) xem exercises/ để thực hành theo bài',
  '',
].join('\n');

/**
 * Kiểm tra và ủy quyền một mục tiêu. Trả về { url, host, port, addresses, scope }.
 * scope: 'loopback' | 'private'
 * @param {string} raw URL hoặc host:port
 * @param {{consent?: boolean}} opts consent=true tương ứng cờ --i-own-this-target
 */
export async function assertAuthorizedTarget(raw, { consent = false } = {}) {
  const url = parseTarget(raw);
  const host = url.hostname;
  const port = url.port ? Number(url.port) : url.protocol === 'https:' ? 443 : 80;

  let addresses;
  if (net.isIP(host)) {
    addresses = [host];
  } else {
    try {
      addresses = (await dns.lookup(host, { all: true })).map((a) => a.address);
    } catch {
      throw new SecurityError(
        `Không phân giải được tên miền "${host}". Với lab cục bộ hãy dùng http://127.0.0.1:3000`
      );
    }
  }

  const classes = addresses.map(classifyIp);

  if (classes.includes('public')) {
    throw new SecurityError(PUBLIC_REFUSE(host, addresses));
  }

  if (classes.includes('private') && !consent) {
    throw new SecurityError(
      [
        '',
        c.yellow(`  ⚠ Mục tiêu "${host}" thuộc dải mạng RIÊNG (${addresses.join(', ')}).`),
        '  Nếu bạn SỞ HỮU hoặc được quản trị viên cho phép kiểm thử hệ thống này,',
        '  chạy lại lệnh với cờ xác nhận:  --i-own-this-target',
        '',
      ].join('\n')
    );
  }

  const scope = classes.includes('loopback') ? 'loopback' : 'private';
  return { url, host, port, addresses, scope };
}
