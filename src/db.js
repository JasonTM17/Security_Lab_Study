// Lớp dữ liệu của lab. Hai backend:
//  1) node:sqlite (có sẵn từ Node 22.5+) — SQL thật để minh hoạ SQL Injection.
//  2) bộ nhớ trong (fallback) — mô phỏng đúng ngữ nghĩa SQLi khi sqlite không khả dụng.
//
// mode = 'vuln': truy vấn được NỐI CHUỖI thẳng (đúng lỗi SQL injection thật).
// mode = 'safe': parameterized query + escape wildcard (cách viết đúng).
import crypto from 'node:crypto';

const USERS = [
  { id: 1, name: 'alice', password: 'alice123', role: 'admin', email: 'alice@lab.local', apiKey: 'LAB-KEY-ALICE-0001' },
  { id: 2, name: 'bob', password: 'bob45678', role: 'user', email: 'bob@lab.local', apiKey: 'LAB-KEY-BOB-0002' },
  { id: 3, name: 'carol', password: 'carol90ab', role: 'user', email: 'carol@lab.local', apiKey: 'LAB-KEY-CAROL-0003' },
  { id: 4, name: 'dave', password: 'dave-cd34', role: 'user', email: 'dave@lab.local', apiKey: 'LAB-KEY-DAVE-0004' },
];

const hash = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');

// Mã vận đơn giả lập cho bài Blind SQLi (LAB-18) — oracle chỉ trả found/không found.
const SHIPMENTS = ['AB-100', 'CD-200', 'EF-300'];

async function hasSqlite() {
  try {
    await import('node:sqlite');
    return true;
  } catch {
    return false;
  }
}

function escapeLike(q) {
  return String(q).replace(/[\\%_]/g, (ch) => '\\' + ch);
}

export async function createLabDb({ mode = 'vuln' } = {}) {
  const vuln = mode === 'vuln';

  if (await hasSqlite()) {
    const { DatabaseSync } = await import('node:sqlite');
    const db = new DatabaseSync(':memory:');
    db.exec('CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, password TEXT, role TEXT, email TEXT, apiKey TEXT)');
    const ins = db.prepare('INSERT INTO users (id,name,password,role,email,apiKey) VALUES (?,?,?,?,?,?)');
    for (const u of USERS) ins.run(u.id, u.name, hash(u.password), u.role, u.email, u.apiKey);
    db.exec('CREATE TABLE shipments (code TEXT)');
    const insShip = db.prepare('INSERT INTO shipments (code) VALUES (?)');
    for (const s of SHIPMENTS) insShip.run(s);
    // Bảng cờ cho Blind SQLi — chỉ được đổ vào bởi chế độ CTF của lab (setBlindFlag).
    db.exec('CREATE TABLE ctf_blind (flag TEXT)');

    return {
      backend: 'node:sqlite',

      // ⚠ CHỦ ĐÍCH DỄ TỔN THƯƠNG: nối chuỗi input vào câu SQL.
      searchUsers(q) {
        const sql = `SELECT id, name, role, email FROM users WHERE name LIKE '%${q}%'`;
        try {
          return { rows: db.prepare(sql).all() };
        } catch (e) {
          return { rows: [], error: String(e.message || e) };
        }
      },

      // Đã vá: tham số hoá + escape ký tự wildcard của LIKE.
      searchUsersSafe(q) {
        try {
          const rows = db
            .prepare("SELECT id, name, role, email FROM users WHERE name LIKE ? ESCAPE '\\'")
            .all(`%${escapeLike(q)}%`);
          return { rows };
        } catch (e) {
          return { rows: [], error: String(e.message || e) };
        }
      },

      // ⚠ CHỦ ĐÍCH DỄ TỔN THƯƠNG: login nối chuỗi → bypass bằng ' OR 1=1 --
      login(username, password) {
        const sql = `SELECT id, name, role, email FROM users WHERE name='${username}' AND password='${hash(password)}'`;
        try {
          const row = db.prepare(sql).get();
          return row ? { ok: true, user: row } : { ok: false };
        } catch (e) {
          return { ok: false, error: String(e.message || e) };
        }
      },

      loginSafe(username, password) {
        const row = db
          .prepare('SELECT id, name, role, email FROM users WHERE name = ? AND password = ?')
          .get(username, hash(password));
        return row ? { ok: true, user: row } : { ok: false };
      },

      getUserById(id) {
        return db.prepare('SELECT id, name, role, email, apiKey FROM users WHERE id = ?').get(Number(id));
      },
      countUsers() {
        return db.prepare('SELECT COUNT(*) AS n FROM users').get().n;
      },
      // Dùng bởi chế độ CTF của lab: thêm người dùng cờ / đổi apiKey theo phiên.
      addUser(u) {
        ins.run(u.id, u.name, hash(u.password), u.role, u.email, u.apiKey);
      },
      setApiKey(id, key) {
        db.prepare('UPDATE users SET apiKey = ? WHERE id = ?').run(key, Number(id));
      },
      // ⚠ CHỦ ĐÍCH DỄ TỔN THƯƠNG (LAB-18): nối chuỗi mã vận đơn → boolean oracle.
      // Attacker không thấy dữ liệu — chỉ thấy found/không found — nhưng suy ra
      // được dữ liệu qua subselect: ' AND (SELECT substr(flag,N,1) FROM ctf_blind)='X'
      trackShipment(code) {
        const sql = `SELECT code FROM shipments WHERE code='${code}'`;
        try {
          const row = db.prepare(sql).get();
          return { found: !!row, code: row?.code };
        } catch (e) {
          return { found: false, error: String(e.message || e) };
        }
      },
      trackShipmentSafe(code) {
        try {
          const row = db.prepare('SELECT code FROM shipments WHERE code = ?').get(String(code));
          return { found: !!row, code: row?.code };
        } catch (e) {
          return { found: false, error: String(e.message || e) };
        }
      },
      setBlindFlag(flag) {
        db.exec('DELETE FROM ctf_blind');
        db.prepare('INSERT INTO ctf_blind (flag) VALUES (?)').run(flag);
      },
      // Tra user theo tên (không cần mật khẩu) — bài reset token LAB-19.
      findUser(name) {
        const u = db.prepare('SELECT id, name, role, email, apiKey FROM users WHERE name = ?').get(String(name));
        return u;
      },
      setPassword(name, newpass) {
        db.prepare('UPDATE users SET password = ? WHERE name = ?').run(hash(newpass), String(name));
      },
    };
  }

  // ---- Fallback: mô phỏng SQLi trên dữ liệu trong bộ nhớ ----
  // Clone per-instance: mỗi lab có dữ liệu riêng (chế độ CTF mutate apiKey/user
  // theo phiên — nếu dùng mảng module-level sẽ nhiễm chéo giữa các instance).
  const users = USERS.map((u) => ({ ...u }));
  let blindFlag = null; // cờ LAB-18 — set bởi lab qua setBlindFlag (chỉ bản vuln)
  return {
    backend: 'memory-simulator',
    searchUsers(q) {
      const where = `name LIKE '%${q}%'`;
      // payload ' OR 1=1 -- hoặc ' OR '1'='1 → mệnh đề luôn đúng
      if (/OR\s+1\s*=\s*1/i.test(where) || where.includes("' OR '1'='1")) {
        return { rows: users.map(({ id, name, role, email }) => ({ id, name, role, email })) };
      }
      const m = where.match(/^name LIKE '%(.*)%'$/s);
      if (!m) {
        return { rows: [], error: `SQLITE_ERROR: near "${(q.split(' ')[0] || "'").slice(0, 20)}": syntax error` };
      }
      const term = m[1].replace(/--.*$/, '').trim().toLowerCase();
      return {
        rows: users.filter((u) => u.name.toLowerCase().includes(term)).map(({ id, name, role, email }) => ({
          id,
          name,
          role,
          email,
        })),
      };
    },
    searchUsersSafe(q) {
      const term = escapeLike(q).toLowerCase();
      return {
        rows: users.filter((u) => u.name.toLowerCase().includes(term)).map(({ id, name, role, email }) => ({
          id,
          name,
          role,
          email,
        })),
      };
    },
    login(username, password) {
      const where = `name='${username}' AND password='${hash(password)}'`;
      if (/OR\s+1\s*=\s*1/i.test(where) || where.includes("' OR '1'='1")) {
        const u = users[0];
        return { ok: true, user: { id: u.id, name: u.name, role: u.role, email: u.email } };
      }
      const name = (username.match(/^([^']*)/) || [])[1] || username;
      const u = users.find((x) => x.name === name && hash(password) === hash(users.find((v) => v.name === name)?.password || ''));
      return u ? { ok: true, user: { id: u.id, name: u.name, role: u.role, email: u.email } } : { ok: false };
    },
    loginSafe(username, password) {
      const u = users.find((x) => x.name === username && x.password === password);
      return u ? { ok: true, user: { id: u.id, name: u.name, role: u.role, email: u.email } } : { ok: false };
    },
    getUserById(id) {
      const u = users.find((x) => x.id === Number(id));
      return u ? { id: u.id, name: u.name, role: u.role, email: u.email, apiKey: u.apiKey } : undefined;
    },
    countUsers() {
      return users.length;
    },
    addUser(u) {
      users.push({ ...u, password: u.password });
    },
    setApiKey(id, key) {
      const u = users.find((x) => x.id === Number(id));
      if (u) u.apiKey = key;
    },
    // ---- LAB-18 Blind SQLi: mô phỏng oracle boolean trên bộ nhớ ----
    // Nhận diện 3 dạng payload: exact match; ' AND '1'='1|'2 (luôn đúng/sai);
    // ' AND (SELECT substr(flag,N,1) FROM ctf_blind)='X' -- (so sánh từng ký tự).
    trackShipment(code) {
      const q2 = String(code);
      if (!q2.includes("'")) {
        return { found: SHIPMENTS.includes(q2), code: SHIPMENTS.includes(q2) ? q2 : undefined };
      }
      const inj = q2.match(/^([^']*)'\s*AND\s*(.+?)\s*--\s*$/is);
      if (!inj) {
        return { found: false, error: `SQLITE_ERROR: near "${q2.slice(0, 20)}": syntax error` };
      }
      const [, base, cond] = inj;
      if (!SHIPMENTS.includes(base)) return { found: false };
      const sub = cond.match(/^\(?\s*SELECT\s+substr\(flag\s*,\s*(\d+)\s*,\s*1\)\s+FROM\s+ctf_blind\)?\s*=\s*'(.)'\s*$/i);
      if (sub) {
        return { found: blindFlag !== null && blindFlag[Number(sub[1]) - 1] === sub[2] };
      }
      if (/^'?1'?\s*=\s*'?1'?$/.test(cond.trim())) return { found: true, code: base };
      if (/^'?1'?\s*=\s*'?2'?$/.test(cond.trim())) return { found: false };
      return { found: false, error: 'SQLITE_ERROR: unsupported injection (simulator)' };
    },
    trackShipmentSafe(code) {
      const q2 = String(code);
      return { found: SHIPMENTS.includes(q2), code: SHIPMENTS.includes(q2) ? q2 : undefined };
    },
    setBlindFlag(flag) {
      blindFlag = flag;
    },
    findUser(name) {
      const u = users.find((x) => x.name === String(name));
      return u ? { id: u.id, name: u.name, role: u.role, email: u.email, apiKey: u.apiKey } : undefined;
    },
    setPassword(name, newpass) {
      const u = users.find((x) => x.name === String(name));
      if (u) u.password = String(newpass);
    },
  };
}
