const crypto = require("crypto");
const path = require("path");
const express = require("express");
const { Pool } = require("pg");

const PORT = process.env.PORT || 10000;
const DATABASE_URL = process.env.DATABASE_URL || "";
const APP_PASSWORD = process.env.APP_PASSWORD || "";
const SESSION_SECRET = process.env.SESSION_SECRET || "";
const STATE_ID = "default";
const TOKEN_TTL_MS = 1000 * 60 * 60 * 24 * 30;

const app = express();
const pool = DATABASE_URL
  ? new Pool({
      connectionString: DATABASE_URL,
      ssl: DATABASE_URL.includes("localhost") || process.env.PGSSLMODE === "disable"
        ? false
        : { rejectUnauthorized: false }
    })
  : null;

let schemaReady = false;

app.use(express.json({ limit: "10mb" }));

async function ensureSchema() {
  if (!pool) throw new Error("DATABASE_URL is not configured");
  if (schemaReady) return;
  await pool.query(`
    CREATE TABLE IF NOT EXISTS app_state (
      id TEXT PRIMARY KEY,
      data JSONB NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  schemaReady = true;
}

function signPayload(payload) {
  return crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(payload)
    .digest("base64url");
}

function createToken() {
  const payload = Buffer.from(JSON.stringify({
    exp: Date.now() + TOKEN_TTL_MS,
    nonce: crypto.randomBytes(16).toString("hex")
  })).toString("base64url");
  return `${payload}.${signPayload(payload)}`;
}

function verifyToken(token) {
  if (!SESSION_SECRET || !token || !token.includes(".")) return false;
  const [payload, signature] = token.split(".");
  const expected = signPayload(payload);
  const safeLength = Buffer.byteLength(signature || "") === Buffer.byteLength(expected);
  if (!safeLength || !crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) return false;
  try {
    const parsed = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    return Number(parsed.exp) > Date.now();
  } catch (error) {
    return false;
  }
}

function requireAuth(req, res, next) {
  const header = req.get("authorization") || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!verifyToken(token)) {
    return res.status(401).json({ error: "Authentication required" });
  }
  return next();
}

function checkServerConfig(res) {
  if (!pool) {
    res.status(503).json({ error: "DATABASE_URL is not configured" });
    return false;
  }
  if (!APP_PASSWORD || !SESSION_SECRET) {
    res.status(503).json({ error: "APP_PASSWORD or SESSION_SECRET is not configured" });
    return false;
  }
  return true;
}

app.get("/api/health", async (req, res) => {
  try {
    if (!pool) return res.json({ ok: true, database: false });
    await ensureSchema();
    return res.json({ ok: true, database: true });
  } catch (error) {
    return res.status(503).json({ ok: false, error: "Database unavailable" });
  }
});

app.post("/api/login", (req, res) => {
  if (!checkServerConfig(res)) return;
  const password = String(req.body?.password || "");
  const validLength = Buffer.byteLength(password) === Buffer.byteLength(APP_PASSWORD);
  const valid = validLength && crypto.timingSafeEqual(Buffer.from(password), Buffer.from(APP_PASSWORD));
  if (!valid) return res.status(401).json({ error: "Wrong password" });
  return res.json({
    token: createToken(),
    expiresInDays: Math.round(TOKEN_TTL_MS / (1000 * 60 * 60 * 24))
  });
});

app.get("/api/data", requireAuth, async (req, res) => {
  if (!checkServerConfig(res)) return;
  try {
    await ensureSchema();
    const result = await pool.query(
      "SELECT data, updated_at FROM app_state WHERE id = $1",
      [STATE_ID]
    );
    const row = result.rows[0];
    return res.json({
      data: row?.data || null,
      updatedAt: row?.updated_at || null
    });
  } catch (error) {
    return res.status(500).json({ error: "Could not load data" });
  }
});

app.put("/api/data", requireAuth, async (req, res) => {
  if (!checkServerConfig(res)) return;
  const snapshot = req.body?.data;
  if (!snapshot || typeof snapshot !== "object" || Array.isArray(snapshot)) {
    return res.status(400).json({ error: "Invalid data" });
  }
  try {
    await ensureSchema();
    const result = await pool.query(
      `INSERT INTO app_state (id, data, updated_at)
       VALUES ($1, $2, NOW())
       ON CONFLICT (id)
       DO UPDATE SET data = EXCLUDED.data, updated_at = NOW()
       RETURNING updated_at`,
      [STATE_ID, snapshot]
    );
    return res.json({ ok: true, updatedAt: result.rows[0].updated_at });
  } catch (error) {
    return res.status(500).json({ error: "Could not save data" });
  }
});

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.listen(PORT, () => {
  console.log(`Programme sport server listening on port ${PORT}`);
});
