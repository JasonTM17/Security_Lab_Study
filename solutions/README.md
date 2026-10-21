# Lời giải (Solutions) — ⚠ SPOILER, chỉ dành cho người dạy / tự kiểm chứng

> **Đọc sau khi đã tự thử.** Toàn bộ đáp án CTF + tiêu chí hoàn thành của các
> bài tập nằm ở đây. Nếu bạn đang học — làm `exercises/` trước, quay lại đây
> để đối chiếu. Nếu bạn là người dạy — đây là answer key chuẩn chỉnh kèm
> script chạy-được để demo trên lớp.

## Cấu trúc

```
solutions/
├── ctf/                      # 10 writeup + 4 solver ngôn ngữ khác nhau
│   ├── ctf-01..10-*.md       # writeup từng thử thách: recon → root cause →
│   │                         #   exploit → cờ → vá hardened → bài học
│   └── scripts/              # solver CHẠY ĐƯỢC, đã kiểm chứng 10/10 × 4 lần
│       ├── solve-all.mjs     # Node.js (fetch, không dependency)
│       ├── solve_all.py      # Python ≥3.8 (chỉ urllib + stdlib)
│       ├── solve-all.sh      # bash + curl (Git Bash/Linux/macOS)
│       └── Solve-All.ps1     # PowerShell ≥5.1 (Windows built-in)
└── exercises/                # answer key 17 bài tập (3 file theo nhóm)
    ├── answers-01-06.md      # nền tảng: khởi động, recon, scan, tấn công, tải, vá
    ├── answers-07-12.md      # trung cấp: crawl/flow, e2e, CTF, cmdinj, jwt, csrf
    └── answers-13-17.md      # nâng cao: upload/xxe/sxss, proto/mass, blind, reset/dom, detect-eng
```

## Chạy solver (chọn ngôn ngữ bạn thích)

```bash
npm run serve          # terminal 1: bật lab VULN ở :3000

# terminal 2 — 4 cách, cùng giải 10/10 và tự nộp cờ:
node   solutions/ctf/scripts/solve-all.mjs
python solutions/ctf/scripts/solve_all.py
bash   solutions/ctf/scripts/solve-all.sh
powershell -ExecutionPolicy Bypass -File solutions/ctf/scripts/Solve-All.ps1
```

Mỗi script in ra cờ thật (per-session → mỗi lần chạy lab là cờ khác) và điểm
tích luỹ tới **265/265**. Exit code 0 khi đủ 10/10 — dùng được trong CI làm
smoke-test "lab có giải được không".

## Tại sao cờ khác nhau mỗi lần?

Cờ sinh ngẫu nhiên theo phiên `createLabApp()` — không thể chép đáp án chữ
`FLAG{...}` từ repo này; phải **khai thác thật** trên phiên lab của bạn.
Writeup mô tả *cách lấy*, không chứa cờ thật.

## Kiến trúc solver (dùng lại cho CTF khác)

Mọi script đều cùng khung:

```
get/post → extract flag bằng regex FLAG\{<prefix>-[0-9a-f]+\}
       → GET /_lab/verify?id=N&flag=<urlencoded>
       → cộng điểm
```

Phần khó nhất — Blind SQLi (#10) — là vòng oracle 200/404 rút từng ký tự
(substr). Mỗi ngôn ngữ hiện đúng pattern đó: Python `HTTPError.code`, bash
`curl -w %{http_code}`, PowerShell `$_.Exception.Response.StatusCode`, Node
`res.status`.
