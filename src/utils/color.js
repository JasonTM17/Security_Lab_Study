// Helper màu ANSI cho console. Tôn trọng NO_COLOR và pipe (không TTY).
const enabled = process.stdout.isTTY && !process.env.NO_COLOR;

const wrap = (code, s) => (enabled ? `\x1b[${code}m${String(s)}\x1b[0m` : String(s));

export const c = {
  red: (s) => wrap(31, s),
  green: (s) => wrap(32, s),
  yellow: (s) => wrap(33, s),
  blue: (s) => wrap(34, s),
  magenta: (s) => wrap(35, s),
  cyan: (s) => wrap(36, s),
  gray: (s) => wrap(90, s),
  bold: (s) => wrap(1, s),
  dim: (s) => wrap(2, s),
};

export function banner() {
  const lines = [
    '',
    '  ╔══════════════════════════════════════════════════════════╗',
    '  ║   SecLab — Bộ công cụ HỌC an toàn thông tin (lab cục bộ)  ║',
    '  ╚══════════════════════════════════════════════════════════╝',
    '',
  ];
  console.log(lines.map((l) => c.cyan(l)).join('\n'));
  console.log(
    c.yellow(
      '  ⚠  CHỈ dùng với hệ thống BẠN SỞ HỮU hoặc ĐƯỢC PHÉP kiểm thử.\n' +
        '     Công cụ tự chặn mọi mục tiêu public trên Internet (Điều 287 BLHS 2015).\n'
    )
  );
}
