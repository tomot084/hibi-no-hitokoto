import { DurableObject } from "cloudflare:workers";

const ORIGIN = "https://tomot084.github.io";
const DAY = 86_400_000;
const RETENTION = 30 * DAY;
const LIMIT = 500;
const KEY = /^[A-Za-z0-9_-]{43}$/;
const EVENT_ID = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i;

function sameKey(header, key) {
  if (!KEY.test(key ?? "")) return false;
  const value = header?.slice(7);
  if (!header?.startsWith("Bearer ") || value.length !== key.length) return false;
  let different = 0;
  for (let index = 0; index < key.length; index += 1) {
    different |= value.charCodeAt(index) ^ key.charCodeAt(index);
  }
  return different === 0;
}

function response(status, result) {
  const headers = {
    "Access-Control-Allow-Origin": ORIGIN,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Authorization, Content-Type",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff"
  };
  return result === undefined ? new Response(null, { status, headers }) : Response.json(result, { status, headers });
}

export default {
  async fetch(request, env) {
    if (new URL(request.url).pathname !== "/views" || request.headers.get("Origin") !== ORIGIN) return response(404);
    if (request.method === "OPTIONS") return response(204);
    if (!KEY.test(env.VIEW_ADMIN_KEY ?? "") || !KEY.test(env.VIEW_WRITE_KEY ?? "")
      || env.VIEW_ADMIN_KEY === env.VIEW_WRITE_KEY) return response(503);
    const auth = request.headers.get("Authorization");
    if (request.method === "GET") {
      if (!sameKey(auth, env.VIEW_ADMIN_KEY)) return response(401);
      const log = env.VIEW_LOG.get(env.VIEW_LOG.idFromName("diary"));
      return response(200, await log.history());
    }
    if (request.method !== "POST") return response(405);
    if (!sameKey(auth, env.VIEW_WRITE_KEY)) return response(401);
    // Set by Cloudflare at the ingress. Do not take an address from the body.
    const ip = request.headers.get("CF-Connecting-IP");
    if (!ip || !/^[0-9a-f:.]{3,45}$/i.test(ip)) return response(400);
    if (Number(request.headers.get("Content-Length")) > 36 || !request.body) return response(400);
    const reader = request.body.getReader();
    let eventId = "";
    const decoder = new TextDecoder();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value.length > 36 - eventId.length || value.some((byte) => byte > 127)) {
        await reader.cancel();
        return response(400);
      }
      eventId += decoder.decode(value);
    }
    if (!EVENT_ID.test(eventId)) return response(400);
    const log = env.VIEW_LOG.get(env.VIEW_LOG.idFromName("diary"));
    await log.add(eventId.toLowerCase(), ip);
    return response(204);
  }
};

export class ViewLog extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    this.sql.exec("CREATE TABLE IF NOT EXISTS views (id TEXT PRIMARY KEY, ip TEXT NOT NULL, at INTEGER NOT NULL)");
    this.sql.exec("CREATE INDEX IF NOT EXISTS views_at ON views(at)");
  }

  async add(id, ip) {
    const now = Date.now();
    this.sql.exec("INSERT OR IGNORE INTO views (id, ip, at) VALUES (?, ?, ?)", id, ip, now);
    if (await this.ctx.storage.getAlarm() === null) await this.ctx.storage.setAlarm(now + RETENTION);
  }

  history() {
    const cutoff = Date.now() - RETENTION;
    const { count: total } = this.sql.exec("SELECT COUNT(*) AS count FROM views WHERE at > ?", cutoff).one();
    const latest = this.sql.exec("SELECT ip, at FROM views WHERE at > ? ORDER BY at DESC LIMIT ?", cutoff, LIMIT).toArray();
    const counts = new Map(this.sql.exec("SELECT ip, COUNT(*) AS count FROM views WHERE at > ? GROUP BY ip", cutoff)
      .toArray().map(({ ip, count }) => [ip, count]));
    const groups = new Map();
    for (const { ip, at } of latest) {
      if (!groups.has(ip)) groups.set(ip, { ip, count: counts.get(ip), times: [] });
      groups.get(ip).times.push(at);
    }
    return { total, shown: latest.length, groups: [...groups.values()] };
  }

  async alarm() {
    const now = Date.now();
    this.sql.exec("DELETE FROM views WHERE at <= ?", now - RETENTION);
    const { oldest } = this.sql.exec("SELECT MIN(at) AS oldest FROM views").one();
    if (oldest !== null) await this.ctx.storage.setAlarm(oldest + RETENTION);
  }
}

