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
    };
  }

  // ---- Fallback: mô phỏng SQLi trên dữ liệu trong bộ nhớ ----
  // Clone per-instance: mỗi lab có dữ liệu riêng (chế độ CTF mutate apiKey/user
  // theo phiên — nếu dùng mảng module-level sẽ nhiễm chéo giữa các instance).
  const users = USERS.map((u) => ({ ...u }));
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
  };
}
