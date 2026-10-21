// serve.js — khởi động lab server (vuln hoặc hardened), CHỈ bind loopback.
import { createLabApp } from './app.js';

export async function startLabServer({ mode = 'vuln', port = 3000 } = {}) {
  const server = await createLabApp({ mode });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    // QUAN TRỌNG: bind cứng '127.0.0.1' — lab không bao giờ lộ ra mạng ngoài.
    server.listen(port, '127.0.0.1', () => resolve(server));
  });
}
