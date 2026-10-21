# Bài 10 · Command Injection — khi input trở thành lệnh hệ thống (LAB-09)

**Mục tiêu:** hiểu vì sao nối chuỗi input vào shell là lỗ hổng nặng nhất nhóm
injection — attacker chạy được **lệnh OS tuỳ ý** với quyền của tiến trình server.

Lab vuln ở `http://127.0.0.1:3000` (bản hardened ở `:3001` để đối chứng).

## 1. Endpoint chẩn đoán "ping"

```
http://127.0.0.1:3000/tools/ping?host=127.0.0.1     # hợp lệ: ping chạy bình thường
```

Code bị lỗi (`src/lab/app.js`): `exec("ping -n 2 " + host)` — `host` nằm thẳng
trong chuỗi lệnh của shell. Dấu `&` (Windows cmd) hoặc `;` `|` `&&` (POSIX sh)
cho phép **nối thêm lệnh**.

## 2. Khai thác bằng tay

Windows (Git Bash / trình duyệt đều được):

```
/tools/ping?host=127.0.0.1%20%26%20whoami       → output có username của bạn
/tools/ping?host=127.0.0.1%20%26%20set%20SECLAB → lộ biến môi trường (có CTF flag!)
```

Linux/macOS:

```
/tools/ping?host=127.0.0.1; id
/tools/ping?host=127.0.0.1; env | grep SECLAB
```

**Đây cũng là cách lấy cờ CTF #5** — biến `SECLAB_CTF_CMD` chỉ tồn tại trong
môi trường tiến trình lab, không có file nào chứa nó.

## 3. Vì sao đây là "game over"

- Đọc file: `type package.json` / `cat /etc/passwd`
- Liệt kê: `dir` / `ls -la` — do thám hệ thống
- Lộ secrets: `set` / `env` — biến môi trường thường chứa API key, DB password
- Tiền đề cho reverse shell, cài mã độc, leo thang đặc quyền

## 4. Đối chứng bản đã vá

```
http://127.0.0.1:3001/tools/ping?host=127.0.0.1%20%26%20whoami   → 400
```

Bản hardened làm **hai** việc: (1) whitelist `^[a-zA-Z0-9.-]{1,64}$`, (2)
`execFile('ping', ['-n','2',host])` — không qua shell nên `&`/`;` chỉ là chuỗi
tham số, không còn nghĩa "nối lệnh". Chỉ whitelist thôi cũng đủ, nhưng bỏ shell
là chắc chắn ở gốc.

## ✅ Hoàn thành khi

- [ ] Tự tay chêm lệnh `whoami`/`id` thành công trên bản vuln
- [ ] Lấy được cờ `FLAG{cmd-...}` từ biến môi trường và nộp (`challenge --submit=5`)
- [ ] Chạy `detect` trên lab và thấy nhóm "Command injection probe" trong log
- [ ] Trả lời: vì sao `execFile` (không shell) chắn chắn hơn escape input?
