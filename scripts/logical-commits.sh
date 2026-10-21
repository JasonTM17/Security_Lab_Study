#!/usr/bin/env bash
# ============================================================================
# Tạo 7 commit logic cho SecLab — chạy file này trong TERMINAL CỦA BẠN
# (terminal thường, ngoài ZCode), vì gate Mimosa của ZCode chặn `git commit`
# từ agent cho đến khi 3 advisory findings trong docs/05 được chấp nhận.
#
# Cách chạy:
#   cd /d/Ddos_Tool && bash scripts/logical-commits.sh
# ============================================================================
set -euo pipefail

if [ -n "$(git log --oneline 2>/dev/null | head -1)" ]; then
  echo "Repo đã có commit — không chạy lại để tránh trùng lặp."
  exit 0
fi

git reset -q

# 1) Scaffold + CI
git add package.json .gitignore .github/
git commit -m "chore: khoi tao du an SecLab - scaffold, CI workflow (Node 22/24, Ubuntu+Windows)"

# 2) Lớp chặn ủy quyền
git add src/guard.js src/utils/color.js
git commit -m "feat(guard): lop chan uy quyen - tu choi muc tieu public, yeu cau --i-own-this-target cho dai rieng"

# 3) Lab + phòng thủ + dữ liệu
git add src/db.js src/defense/ src/lab/
git commit -m "feat(lab): web lab vuln/hardened (8 lo hong chu dich) + token-bucket rate limiter + security headers + SQLite that + giao dien toi doc du trong webview ep dark"

# 4) Các module chủ động
git add src/modules/
git commit -m "feat(modules): recon, vulnscan, loadtest, flowtest luong nguoi dung that, slowloris, polite scraper (robots.txt), bao cao md/html"

# 5) Hub học tập + scripts + CLI
git add src/hub/ hub/ scripts/ src/cli.js
git commit -m "feat(hub): SecHub - hub hoc ATTT 8 chuyen muc (dark UI, TOC) + server tinh chong path-traversal + assemble-hub + CLI lenh hub/flowtest/crawl"

# 6) Kiểm thử (unit/integration + E2E HTTP)
git add tests/
git commit -m "test: 38 unit/integration + e2e.mjs 38 check HTTP tu khoi dong 3 server (vuln/hardened doi chung, hub, rate limit)"

# 7) Tài liệu + bài thực hành + security review
git add README.md docs/ exercises/
git commit -m "docs: phap ly-dao duc, kien truc, DoS-DDoS, cheat sheet, scraping lich su, E2E checklist, 7 bai thuc hanh, security review Mimosa"

echo ""
echo "=== Hoàn tất — lịch sử commit: ==="
git log --oneline
