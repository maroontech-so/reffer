/**
 * backend.js — core backend module
 * - Local SQLite (fast, synchronous)
 * - Turso (libSQL) async mirror with restore-on-boot
 * - PalPluss for both collections (STK Push) and disbursements (B2C)
 * - Idempotent transactional payment processing
 * - Realtime referral notifications via SSE bus
 */
"use strict";

require("dotenv").config();
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");
const Database = require("better-sqlite3");

const palpluss = require("./palpluss");

// ============================================================================
// CONFIG
// ============================================================================
const CONFIG = {
  nodeEnv: process.env.NODE_ENV || "development",
  appUrl: process.env.APP_URL || "http://localhost:3000",
  appName: process.env.APP_NAME || "Referal Kenya",
  jwtSecret: process.env.JWT_SECRET || "dev-jwt-secret-change-in-production",
  jwtExpiresIn: process.env.JWT_EXPIRES_IN || "7d",

  palpluss: {
    enabled:
      String(process.env.PAYMENT_PROVIDER || "palpluss").toLowerCase() ===
      "palpluss",
    channelId: process.env.PALPLUSS_CHANNEL_ID || "",
    serviceWalletTopupKes: parseInt(
      process.env.PALPLUSS_TOPUP_KES || "1000",
      10,
    ),
  },

  turso: {
    url: process.env.TURSO_DATABASE_URL || "",
    authToken: process.env.TURSO_AUTH_TOKEN || "",
    enabled: !!process.env.TURSO_DATABASE_URL && !!process.env.TURSO_AUTH_TOKEN,
  },

  business: {
    registrationFeeKobo: parseInt(
      process.env.REGISTRATION_FEE_KOBO || "10000",
      10,
    ),
    referralCommissionKobo: parseInt(
      process.env.REFERRAL_COMMISSION_KOBO || "5000",
      10,
    ),
    platformAllocationKobo: parseInt(
      process.env.PLATFORM_ALLOCATION_KOBO || "5000",
      10,
    ),
    minWithdrawalKobo: parseInt(process.env.MIN_WITHDRAWAL_KOBO || "20000", 10),
    maxWithdrawalKobo: parseInt(
      process.env.MAX_WITHDRAWAL_KOBO || "1000000",
      10,
    ),
    commissionSettlementDelayHours: parseInt(
      process.env.COMMISSION_SETTLEMENT_DELAY_HOURS || "24",
      10,
    ),
    referralAttributionDays: parseInt(
      process.env.REFERRAL_ATTRIBUTION_DAYS || "30",
      10,
    ),
  },

  admin: {
    email: process.env.ADMIN_EMAIL || "admin@referal.co.ke",
    password: process.env.ADMIN_PASSWORD || "",
    phone: process.env.ADMIN_PHONE || "",
  },

  features: {
    registrationEnabled:
      String(process.env.REGISTRATION_ENABLED).toLowerCase() !== "false",
    referralsEnabled:
      String(process.env.REFERRALS_ENABLED).toLowerCase() !== "false",
    withdrawalsEnabled:
      String(process.env.WITHDRAWALS_ENABLED).toLowerCase() !== "false",
    maintenanceMode:
      String(process.env.MAINTENANCE_MODE).toLowerCase() === "true",
  },
};

// ============================================================================
// TURSO CLIENT + SYNC QUEUE  (unchanged — identical to your original)
// ============================================================================
let tursoClient = null;
let suppressTursoSync = false;
const syncQueue = [];
let syncBuffer = null;
let flushing = false;
let flushScheduled = false;

function makeTursoClient() {
  if (!CONFIG.turso.enabled) return null;
  try {
    const { createClient } = require("@libsql/client");
    const client = createClient({
      url: CONFIG.turso.url,
      authToken: CONFIG.turso.authToken,
    });
    console.log("[turso] client ready");
    return client;
  } catch (e) {
    console.error("[turso] init failed:", e.message);
    return null;
  }
}

function queueWrite(sql, params) {
  if (suppressTursoSync || !tursoClient) return;
  const item = { sql, params: params || [] };
  if (syncBuffer) {
    syncBuffer.push(item);
  } else {
    syncQueue.push(item);
    scheduleFlush();
  }
}

function scheduleFlush() {
  if (flushScheduled || !tursoClient) return;
  flushScheduled = true;
  setImmediate(() => {
    flushScheduled = false;
    flushQueue().catch((e) => console.error("[turso] flush err:", e.message));
  });
}

async function flushQueue() {
  if (flushing || !tursoClient || syncQueue.length === 0) return;
  flushing = true;
  const batch = syncQueue.splice(0, 500);
  for (let i = 0; i < batch.length; i++) {
    const item = batch[i];
    try {
      await tursoClient.execute({ sql: item.sql, args: item.params });
    } catch (e) {
      const msg = String(e.message || "");
      const isConnection =
        /fetch|network|ECONN|ETIMEDOUT|ENOTFOUND|timeout|503|502|504/i.test(
          msg,
        );
      if (isConnection) {
        syncQueue.unshift(item, ...batch.slice(i + 1));
        flushing = false;
        await new Promise((r) => setTimeout(r, 3000));
        scheduleFlush();
        return;
      }
      console.error("[turso] SQL error:", msg.slice(0, 200));
    }
  }
  flushing = false;
  if (syncQueue.length > 0) scheduleFlush();
}

async function restoreFromTurso() {
  if (!tursoClient) return { restored: false };
  const database = getDb();
  try {
    const row = database.prepare("SELECT COUNT(*) AS c FROM users").get();
    if (row.c > 0) return { restored: false, reason: "local_not_empty" };

    console.log("[turso] local empty, restoring from Turso…");
    const tables = [
      "settings",
      "users",
      "membership",
      "referral_clicks",
      "payments",
      "webhook_events",
      "ledger_entries",
      "commissions",
      "withdrawals",
      "payout_transfers",
      "audit_logs",
      "notifications",
      "reconciliation_runs",
      "reconciliation_exceptions",
      "terms_acceptances",
    ];
    suppressTursoSync = true;
    let total = 0;
    for (const t of tables) {
      let rs;
      try {
        rs = await tursoClient.execute(`SELECT * FROM ${t}`);
      } catch (e) {
        continue;
      }
      for (const r of rs.rows) {
        const cols = Object.keys(r);
        const placeholders = cols.map(() => "?").join(",");
        const values = cols.map((c) => r[c]);
        try {
          database
            .prepare(
              `INSERT OR REPLACE INTO ${t} (${cols.join(",")}) VALUES (${placeholders})`,
            )
            .run(...values);
          total++;
        } catch (e) {
          console.error(`[turso] restore ${t} row failed:`, e.message);
        }
      }
    }
    suppressTursoSync = false;
    console.log(`[turso] restored ${total} rows`);
    return { restored: true, rows: total };
  } catch (e) {
    suppressTursoSync = false;
    console.error("[turso] restore failed:", e.message);
    return { restored: false, error: e.message };
  } finally {
    suppressTursoSync = false;
  }
}

// ============================================================================
// DB WRAPPER (sync to Turso on write)
// ============================================================================
const DATA_DIR = path.join(__dirname, "data");
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const DB_PATH =
  process.env.DATABASE_URL && process.env.DATABASE_URL.startsWith("file:")
    ? process.env.DATABASE_URL.replace("file:", "")
    : path.join(DATA_DIR, "referal.db");

let db;
const WRITE_RX = /^\s*(INSERT|UPDATE|DELETE|REPLACE)\b/i;

function wrapDbForSync(database) {
  const origPrepare = database.prepare.bind(database);
  database.prepare = function (sql) {
    const stmt = origPrepare(sql);
    if (!WRITE_RX.test(sql)) return stmt;

    const origRun = stmt.run.bind(stmt);
    stmt.run = function (...args) {
      const result = origRun(...args);
      queueWrite(sql, args);
      return result;
    };
    return stmt;
  };

  const origTransaction = database.transaction.bind(database);
  database.transaction = function (fn) {
    const inner = origTransaction(fn);
    return function (...args) {
      const prevBuffer = syncBuffer;
      syncBuffer = [];
      try {
        const result = inner(...args);
        const batch = syncBuffer;
        syncBuffer = prevBuffer;
        if (prevBuffer) {
          prevBuffer.push(...batch);
        } else {
          syncQueue.push(...batch);
          scheduleFlush();
        }
        return result;
      } catch (e) {
        syncBuffer = prevBuffer;
        throw e;
      }
    };
  };
}

function getDb() {
  if (!db) {
    db = new Database(DB_PATH);
    db.pragma("journal_mode = WAL");
    db.pragma("foreign_keys = ON");
    db.pragma("busy_timeout = 5000");
    wrapDbForSync(db);
  }
  return db;
}

// ============================================================================
// SSE NOTIFICATION BUS
// ============================================================================
const sseNotifiers = new Set();

function registerSSENotifier(fn) {
  sseNotifiers.add(fn);
}

function pushSSE(userId, event) {
  for (const fn of sseNotifiers) {
    try {
      fn(userId, event);
    } catch (e) {}
  }
}

// ============================================================================
// SCHEMA  (unchanged — keep your original schema exactly)
// ============================================================================
const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE,
  phone TEXT UNIQUE NOT NULL,
  full_name TEXT NOT NULL,
  password_hash TEXT,
  role TEXT NOT NULL DEFAULT 'member',
  status TEXT NOT NULL DEFAULT 'unverified',
  email_verified INTEGER NOT NULL DEFAULT 0,
  phone_verified INTEGER NOT NULL DEFAULT 0,
  payout_phone TEXT,
  payout_phone_verified INTEGER NOT NULL DEFAULT 0,
  referral_code TEXT UNIQUE,
  referred_by_user_id TEXT,
  referral_attributed_at TEXT,
  last_login_at TEXT,
  suspended_reason TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (referred_by_user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_users_referral_code ON users(referral_code);
CREATE INDEX IF NOT EXISTS idx_users_referred_by ON users(referred_by_user_id);
CREATE INDEX IF NOT EXISTS idx_users_phone ON users(phone);

CREATE TABLE IF NOT EXISTS referral_clicks (
  id TEXT PRIMARY KEY,
  referral_code TEXT NOT NULL,
  referrer_user_id TEXT,
  ip_hash TEXT,
  user_agent TEXT,
  visitor_fingerprint TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_clicks_code ON referral_clicks(referral_code);
CREATE INDEX IF NOT EXISTS idx_clicks_referrer ON referral_clicks(referrer_user_id);

CREATE TABLE IF NOT EXISTS membership (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL DEFAULT 'inactive',
  activated_at TEXT,
  activated_by_payment_id TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS payments (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  internal_reference TEXT NOT NULL UNIQUE,
  provider_reference TEXT UNIQUE,
  provider TEXT NOT NULL DEFAULT 'palpluss',
  expected_amount_kobo INTEGER NOT NULL,
  actual_amount_kobo INTEGER,
  currency TEXT NOT NULL DEFAULT 'KES',
  status TEXT NOT NULL DEFAULT 'pending',
  channel TEXT,
  provider_fee_kobo INTEGER,
  provider_payload TEXT,
  verification_attempts INTEGER NOT NULL DEFAULT 0,
  verified_at TEXT,
  failure_reason TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_payments_user ON payments(user_id);
CREATE INDEX IF NOT EXISTS idx_payments_status ON payments(status);
CREATE INDEX IF NOT EXISTS idx_payments_provider_ref ON payments(provider_reference);

CREATE TABLE IF NOT EXISTS webhook_events (
  id TEXT PRIMARY KEY,
  provider TEXT NOT NULL,
  event_type TEXT NOT NULL,
  provider_event_id TEXT,
  signature_valid INTEGER NOT NULL DEFAULT 0,
  payload TEXT NOT NULL,
  processed INTEGER NOT NULL DEFAULT 0,
  processed_at TEXT,
  processing_error TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_webhook_provider_event
  ON webhook_events(provider, provider_event_id)
  WHERE provider_event_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS ledger_entries (
  id TEXT PRIMARY KEY,
  entry_type TEXT NOT NULL,
  direction TEXT NOT NULL,
  amount_kobo INTEGER NOT NULL,
  currency TEXT NOT NULL DEFAULT 'KES',
  user_id TEXT,
  payment_id TEXT,
  commission_id TEXT,
  payout_id TEXT,
  reference TEXT,
  description TEXT,
  metadata TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id),
  FOREIGN KEY (payment_id) REFERENCES payments(id)
);
CREATE INDEX IF NOT EXISTS idx_ledger_user ON ledger_entries(user_id);
CREATE INDEX IF NOT EXISTS idx_ledger_payment ON ledger_entries(payment_id);
CREATE INDEX IF NOT EXISTS idx_ledger_type ON ledger_entries(entry_type);

CREATE TABLE IF NOT EXISTS commissions (
  id TEXT PRIMARY KEY,
  beneficiary_user_id TEXT NOT NULL,
  source_user_id TEXT NOT NULL,
  source_payment_id TEXT NOT NULL UNIQUE,
  amount_kobo INTEGER NOT NULL,
  currency TEXT NOT NULL DEFAULT 'KES',
  status TEXT NOT NULL DEFAULT 'pending',
  eligible_at TEXT,
  available_at TEXT,
  reversed_at TEXT,
  reversal_reason TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (beneficiary_user_id) REFERENCES users(id),
  FOREIGN KEY (source_user_id) REFERENCES users(id),
  FOREIGN KEY (source_payment_id) REFERENCES payments(id)
);
CREATE INDEX IF NOT EXISTS idx_commissions_beneficiary ON commissions(beneficiary_user_id);
CREATE INDEX IF NOT EXISTS idx_commissions_status ON commissions(status);

CREATE TABLE IF NOT EXISTS withdrawals (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  amount_kobo INTEGER NOT NULL,
  currency TEXT NOT NULL DEFAULT 'KES',
  status TEXT NOT NULL DEFAULT 'requested',
  payout_phone TEXT NOT NULL,
  provider_recipient_code TEXT,
  provider_transfer_code TEXT,
  provider_reference TEXT UNIQUE,
  fee_kobo INTEGER NOT NULL DEFAULT 0,
  failure_reason TEXT,
  approved_by TEXT,
  approved_at TEXT,
  processed_at TEXT,
  paid_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_withdrawals_user ON withdrawals(user_id);
CREATE INDEX IF NOT EXISTS idx_withdrawals_status ON withdrawals(status);

CREATE TABLE IF NOT EXISTS payout_transfers (
  id TEXT PRIMARY KEY,
  withdrawal_id TEXT NOT NULL,
  provider TEXT NOT NULL DEFAULT 'palpluss',
  provider_transfer_code TEXT UNIQUE,
  provider_reference TEXT,
  amount_kobo INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'initiated',
  raw_response TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (withdrawal_id) REFERENCES withdrawals(id)
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id TEXT PRIMARY KEY,
  actor_user_id TEXT,
  actor_role TEXT,
  action TEXT NOT NULL,
  entity_type TEXT,
  entity_id TEXT,
  ip_address TEXT,
  user_agent TEXT,
  details TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_logs(actor_user_id);
CREATE INDEX IF NOT EXISTS idx_audit_entity ON audit_logs(entity_type, entity_id);

CREATE TABLE IF NOT EXISTS notifications (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  type TEXT NOT NULL,
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  read INTEGER NOT NULL DEFAULT 0,
  metadata TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id, read);

CREATE TABLE IF NOT EXISTS reconciliation_runs (
  id TEXT PRIMARY KEY,
  run_by TEXT,
  status TEXT NOT NULL DEFAULT 'running',
  summary TEXT,
  started_at TEXT NOT NULL DEFAULT (datetime('now')),
  finished_at TEXT
);

CREATE TABLE IF NOT EXISTS reconciliation_exceptions (
  id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  exception_type TEXT NOT NULL,
  payment_id TEXT,
  withdrawal_id TEXT,
  description TEXT,
  resolved INTEGER NOT NULL DEFAULT 0,
  resolved_by TEXT,
  resolved_at TEXT,
  resolution_notes TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (run_id) REFERENCES reconciliation_runs(id)
);

CREATE TABLE IF NOT EXISTS terms_acceptances (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  document_type TEXT NOT NULL,
  document_version TEXT NOT NULL,
  ip_address TEXT,
  accepted_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id)
);
`;

function migrate() {
  getDb().exec(SCHEMA_SQL);
  console.log("[db] schema migrated");
}

// ============================================================================
// SEEDS / HELPERS  (unchanged)
// ============================================================================
function seedSettings() {
  const database = getDb();
  const defaults = {
    registration_fee_kobo: String(CONFIG.business.registrationFeeKobo),
    referral_commission_kobo: String(CONFIG.business.referralCommissionKobo),
    platform_allocation_kobo: String(CONFIG.business.platformAllocationKobo),
    min_withdrawal_kobo: String(CONFIG.business.minWithdrawalKobo),
    max_withdrawal_kobo: String(CONFIG.business.maxWithdrawalKobo),
    commission_settlement_delay_hours: String(
      CONFIG.business.commissionSettlementDelayHours,
    ),
    referral_attribution_days: String(CONFIG.business.referralAttributionDays),
    registration_enabled: String(CONFIG.features.registrationEnabled),
    referrals_enabled: String(CONFIG.features.referralsEnabled),
    withdrawals_enabled: String(CONFIG.features.withdrawalsEnabled),
    maintenance_mode: String(CONFIG.features.maintenanceMode),
    terms_version: "1.0",
    privacy_version: "1.0",
    programme_version: "1.0",
  };

  const force =
    String(process.env.RESEED_SETTINGS || "").toLowerCase() === "true";

  const stmt = force
    ? database.prepare(
        `INSERT INTO settings (key, value, updated_at) VALUES (?, ?, datetime('now'))
         ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
      )
    : database.prepare(
        "INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)",
      );

  const tx = database.transaction(() => {
    for (const [k, v] of Object.entries(defaults)) stmt.run(k, v);
  });
  tx();
  console.log(`[db] settings seeded${force ? " (forced from env)" : ""}`);
}

function seedAdmin() {
  const database = getDb();
  if (!CONFIG.admin.password) {
    console.log("[seed] ADMIN_PASSWORD not set, skipping admin seed");
    return;
  }
  const existing = database
    .prepare("SELECT id FROM users WHERE role = ? LIMIT 1")
    .get("admin");
  if (existing) return;
  const id = uuidv4();
  const hash = bcrypt.hashSync(CONFIG.admin.password, 12);
  const phone = normalizePhone(CONFIG.admin.phone) || "254700000000";
  database
    .prepare(
      `INSERT INTO users (id, email, phone, full_name, password_hash, role, status, phone_verified, email_verified)
       VALUES (?, ?, ?, ?, ?, 'admin', 'active', 1, 1)`,
    )
    .run(id, CONFIG.admin.email.toLowerCase(), phone, "Administrator", hash);
  database
    .prepare(
      `INSERT INTO membership (id, user_id, status, activated_at) VALUES (?, ?, 'active', datetime('now'))`,
    )
    .run(uuidv4(), id);
  console.log("[seed] admin created:", CONFIG.admin.email);
}

function nowIso() {
  return new Date().toISOString();
}

function normalizePhone(input) {
  if (!input) return null;
  const digits = String(input).replace(/\D/g, "");
  if (digits.length === 0) return null;
  let s = digits;
  if (s.startsWith("0") && s.length === 10) s = "254" + s.slice(1);
  else if (s.startsWith("7") && s.length === 9) s = "254" + s;
  else if (s.startsWith("1") && s.length === 9) s = "254" + s;
  else if (s.startsWith("254") && s.length === 12) {
    /* ok */
  } else if (s.length < 10 || s.length > 15) return null;
  if (!/^254[17]\d{8}$/.test(s)) return null;
  return s;
}

function validateEmail(email) {
  if (!email) return false;
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email));
}

function generateReferralCode() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let code = "";
  const bytes = crypto.randomBytes(8);
  for (let i = 0; i < 8; i++) code += alphabet[bytes[i] % alphabet.length];
  return code;
}

function hashIp(ip) {
  if (!ip) return null;
  return crypto
    .createHash("sha256")
    .update(String(ip))
    .digest("hex")
    .slice(0, 32);
}

function getSetting(key) {
  const row = getDb()
    .prepare("SELECT value FROM settings WHERE key = ?")
    .get(key);
  return row ? row.value : null;
}

function getSettingInt(key, fallback) {
  const v = getSetting(key);
  const n = parseInt(v, 10);
  return Number.isFinite(n) ? n : fallback;
}

function getSettingBool(key, fallback) {
  const v = getSetting(key);
  if (v === null) return fallback;
  return String(v).toLowerCase() === "true";
}

function setSetting(key, value, actorId) {
  getDb()
    .prepare(
      `INSERT INTO settings (key, value, updated_at) VALUES (?, ?, datetime('now'))
       ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
    )
    .run(key, String(value));
  audit(actorId, "admin", "setting.update", "settings", key, null, null, {
    key,
    value: String(value),
  });
}

function audit(
  actorUserId,
  actorRole,
  action,
  entityType,
  entityId,
  ip,
  ua,
  details,
) {
  try {
    getDb()
      .prepare(
        `INSERT INTO audit_logs (id, actor_user_id, actor_role, action, entity_type, entity_id, ip_address, user_agent, details)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        uuidv4(),
        actorUserId || null,
        actorRole || null,
        action,
        entityType || null,
        entityId || null,
        ip || null,
        ua || null,
        details ? JSON.stringify(details) : null,
      );
  } catch (e) {
    console.error("[audit] failed:", e.message);
  }
}

function notify(userId, type, title, body, metadata) {
  try {
    getDb()
      .prepare(
        `INSERT INTO notifications (id, user_id, type, title, body, metadata)
         VALUES (?, ?, ?, ?, ?, ?)`,
      )
      .run(
        uuidv4(),
        userId,
        type,
        title,
        body,
        metadata ? JSON.stringify(metadata) : null,
      );
  } catch (e) {
    console.error("[notify] failed:", e.message);
  }
}

function generateToken(user) {
  return jwt.sign(
    { sub: user.id, role: user.role, email: user.email },
    CONFIG.jwtSecret,
    {
      expiresIn: CONFIG.jwtExpiresIn,
    },
  );
}

function verifyToken(token) {
  try {
    return jwt.verify(token, CONFIG.jwtSecret);
  } catch (e) {
    return null;
  }
}

// ============================================================================
// USERS / AUTH  (unchanged)
// ============================================================================
function findUserByPhone(phone) {
  return getDb().prepare("SELECT * FROM users WHERE phone = ?").get(phone);
}
function findUserByEmail(email) {
  if (!email) return null;
  return getDb()
    .prepare("SELECT * FROM users WHERE email = ?")
    .get(String(email).toLowerCase());
}
function findUserById(id) {
  return getDb().prepare("SELECT * FROM users WHERE id = ?").get(id);
}
function findUserByReferralCode(code) {
  if (!code) return null;
  return getDb()
    .prepare("SELECT * FROM users WHERE referral_code = ?")
    .get(String(code).toUpperCase());
}

function registerUser(input, ip, ua) {
  const database = getDb();
  const {
    fullName,
    email,
    phone,
    password,
    payoutPhone,
    referralCode,
    acceptTerms,
  } = input || {};

  if (!CONFIG.features.registrationEnabled)
    return { error: "Registration is currently disabled" };
  if (!fullName || String(fullName).trim().length < 2)
    return { error: "Full name is required" };
  const normalizedPhone = normalizePhone(phone);
  if (!normalizedPhone)
    return {
      error: "Invalid Kenyan phone number (e.g. 0712345678 or 254712345678)",
    };
  if (email && !validateEmail(email)) return { error: "Invalid email address" };
  if (!password || String(password).length < 8)
    return { error: "Password must be at least 8 characters" };
  if (!acceptTerms)
    return { error: "You must accept the terms and conditions" };
  const normalizedPayout = normalizePhone(payoutPhone || phone);
  if (!normalizedPayout) return { error: "Invalid M-Pesa payout number" };

  if (findUserByPhone(normalizedPhone))
    return { error: "An account with this phone number already exists" };
  if (email && findUserByEmail(email))
    return { error: "An account with this email address already exists" };

  let referrer = null;
  if (referralCode && CONFIG.features.referralsEnabled) {
    const candidate = findUserByReferralCode(referralCode);
    if (
      candidate &&
      candidate.status === "active" &&
      candidate.role === "member" &&
      normalizePhone(candidate.phone) !== normalizedPhone
    ) {
      referrer = candidate;
    }
  }

  const userId = uuidv4();
  const passwordHash = bcrypt.hashSync(String(password), 12);
  let userReferralCode = generateReferralCode();
  let attempts = 0;
  while (findUserByReferralCode(userReferralCode) && attempts < 10) {
    userReferralCode = generateReferralCode();
    attempts++;
  }

  const tx = database.transaction(() => {
    database
      .prepare(
        `INSERT INTO users
         (id, email, phone, full_name, password_hash, role, status, payout_phone, referral_code,
          referred_by_user_id, referral_attributed_at)
         VALUES (?, ?, ?, ?, ?, 'member', 'pending_payment', ?, ?, ?, ?)`,
      )
      .run(
        userId,
        email ? String(email).toLowerCase() : null,
        normalizedPhone,
        String(fullName).trim(),
        passwordHash,
        normalizedPayout,
        userReferralCode,
        referrer ? referrer.id : null,
        referrer ? nowIso() : null,
      );

    database
      .prepare(
        `INSERT INTO membership (id, user_id, status) VALUES (?, ?, 'inactive')`,
      )
      .run(uuidv4(), userId);

    database
      .prepare(
        `INSERT INTO terms_acceptances (id, user_id, document_type, document_version, ip_address)
         VALUES (?, ?, 'combined_terms', ?, ?)`,
      )
      .run(uuidv4(), userId, getSetting("terms_version") || "1.0", ip || null);
  });
  tx();

  audit(userId, "member", "user.register", "user", userId, ip, ua, {
    referralCode: referrer ? referrer.referral_code : null,
  });

  if (referrer) {
    pushSSE(referrer.id, {
      type: "referral_signup",
      name: maskName(String(fullName).trim()),
      at: nowIso(),
    });
    notify(
      referrer.id,
      "referral_signup",
      "New referral signed up",
      `${maskName(String(fullName).trim())} just signed up using your referral link.`,
      { refereeId: userId },
    );
  }

  return { user: findUserById(userId) };
}

function authenticateUser(phoneOrEmail, password) {
  let user = null;
  const norm = normalizePhone(phoneOrEmail);
  if (norm) user = findUserByPhone(norm);
  else if (validateEmail(phoneOrEmail)) user = findUserByEmail(phoneOrEmail);
  if (!user || !user.password_hash) return null;
  if (user.status === "suspended" || user.status === "closed") return null;
  const ok = bcrypt.compareSync(String(password), user.password_hash);
  if (!ok) return null;
  try {
    getDb()
      .prepare("UPDATE users SET last_login_at = datetime('now') WHERE id = ?")
      .run(user.id);
  } catch (e) {}
  return user;
}

// ============================================================================
// REFERRAL TRACKING  (unchanged)
// ============================================================================
function recordReferralClick(referralCode, ip, ua, fingerprint) {
  if (!CONFIG.features.referralsEnabled) return null;
  const code = String(referralCode || "").toUpperCase();
  if (!code) return null;
  const referrer = findUserByReferralCode(code);
  getDb()
    .prepare(
      `INSERT INTO referral_clicks
       (id, referral_code, referrer_user_id, ip_hash, user_agent, visitor_fingerprint)
       VALUES (?, ?, ?, ?, ?, ?)`,
    )
    .run(
      uuidv4(),
      code,
      referrer ? referrer.id : null,
      hashIp(ip),
      ua ? String(ua).slice(0, 500) : null,
      fingerprint ? String(fingerprint).slice(0, 100) : null,
    );
  return { referrer };
}

function getReferralStats(userId) {
  const database = getDb();
  const clicks = database
    .prepare(
      "SELECT COUNT(*) AS c FROM referral_clicks WHERE referrer_user_id = ?",
    )
    .get(userId).c;
  const uniqueVisitors = database
    .prepare(
      `SELECT COUNT(DISTINCT visitor_fingerprint) AS c FROM referral_clicks
       WHERE referrer_user_id = ? AND visitor_fingerprint IS NOT NULL`,
    )
    .get(userId).c;
  const paidReferrals = database
    .prepare(
      `SELECT COUNT(*) AS c FROM users u
       JOIN membership m ON m.user_id = u.id
       WHERE u.referred_by_user_id = ? AND m.status = 'active'`,
    )
    .get(userId).c;
  const commissionRows = database
    .prepare(
      `SELECT status, SUM(amount_kobo) AS total FROM commissions
       WHERE beneficiary_user_id = ? GROUP BY status`,
    )
    .all(userId);
  const byStatus = {
    pending: 0,
    eligible: 0,
    available: 0,
    payout_processing: 0,
    paid: 0,
    reversed: 0,
  };
  for (const r of commissionRows)
    if (r.status in byStatus) byStatus[r.status] = r.total || 0;
  const totalEarnings = Object.entries(byStatus)
    .filter(([k]) => k !== "reversed")
    .reduce((s, [, v]) => s + v, 0);

  return {
    clicks,
    uniqueVisitors,
    paidReferrals,
    conversionRate: clicks > 0 ? paidReferrals / clicks : 0,
    commissions: {
      pendingKobo: byStatus.pending + byStatus.eligible,
      availableKobo: byStatus.available,
      processingKobo: byStatus.payout_processing,
      paidKobo: byStatus.paid,
      reversedKobo: byStatus.reversed,
      totalEarningsKobo: totalEarnings,
    },
  };
}

function listReferrals(userId, page, pageSize) {
  const database = getDb();
  const limit = Math.min(Math.max(parseInt(pageSize || 20, 10), 1), 100);
  const p = Math.max(parseInt(page || 1, 10), 1);
  const offset = (p - 1) * limit;
  const total = database
    .prepare("SELECT COUNT(*) AS c FROM users WHERE referred_by_user_id = ?")
    .get(userId).c;
  const rows = database
    .prepare(
      `SELECT u.id, u.full_name, u.phone, u.status, u.created_at,
              m.status AS membership_status,
              p.status AS payment_status,
              c.amount_kobo AS commission_kobo, c.status AS commission_status
       FROM users u
       LEFT JOIN membership m ON m.user_id = u.id
       LEFT JOIN payments p ON p.user_id = u.id AND p.status = 'success'
       LEFT JOIN commissions c ON c.source_user_id = u.id AND c.beneficiary_user_id = ?
       WHERE u.referred_by_user_id = ?
       ORDER BY u.created_at DESC
       LIMIT ? OFFSET ?`,
    )
    .all(userId, userId, limit, offset);
  return {
    page: p,
    pageSize: limit,
    total,
    items: rows.map((r) => ({
      id: r.id,
      name: maskName(r.full_name),
      phone: maskPhone(r.phone),
      membershipStatus: r.membership_status,
      joinedAt: r.created_at,
      paymentStatus: r.payment_status,
      commissionKobo: r.commission_kobo || 0,
      commissionStatus: r.commission_status,
    })),
  };
}

function maskName(name) {
  if (!name) return "***";
  return String(name)
    .trim()
    .split(/\s+/)
    .map((p) => (p.length <= 1 ? p : p[0] + "*".repeat(p.length - 1)))
    .join(" ");
}
function maskPhone(phone) {
  if (!phone) return "***";
  const s = String(phone);
  if (s.length < 6) return "***";
  return s.slice(0, 4) + "***" + s.slice(-2);
}

// ============================================================================
// PAYMENTS — PALPLUSS STK PUSH
// ============================================================================
async function chargeMpesa(userId, phone, ip, ua) {
  const database = getDb();
  const user = findUserById(userId);
  if (!user) return { error: "User not found" };
  if (user.status === "suspended" || user.status === "closed")
    return { error: "Account is not eligible for payment" };
  if (user.status === "active") return { error: "Account is already active" };

  const normalized = normalizePhone(phone);
  if (!normalized)
    return { error: "Enter a valid M-Pesa number (e.g. 0712345678)" };

  const feeKobo = getSettingInt(
    "registration_fee_kobo",
    CONFIG.business.registrationFeeKobo,
  );
  const feeKes = feeKobo / 100;
  // PalPluss requires accountReference ≤ 12 characters.
  // "RG" + 8-char base36 timestamp + 2-char random = exactly 12.
  const internalRef =
    "RG" +
    Date.now().toString(36).toUpperCase() +
    crypto.randomBytes(1).toString("hex").toUpperCase();

  const paymentId = uuidv4();
  database
    .prepare(
      `INSERT INTO payments
       (id, user_id, internal_reference, provider, expected_amount_kobo, currency, status, channel)
       VALUES (?, ?, ?, 'palpluss', ?, 'KES', 'pending', 'mobile_money')`,
    )
    .run(paymentId, userId, internalRef, feeKobo);

  const callbackUrl = `${CONFIG.appUrl}/api/webhooks/palpluss`;

  try {
    const result = await palpluss.initiateStkPush({
      amountKes: feeKes,
      phone: normalized,
      callbackUrl,
      accountReference: internalRef,
      // transactionDesc must be ≤ 13 characters (shown on the PIN prompt)
      description: "Membership",
      channelId: CONFIG.palpluss.channelId || undefined,
    });

    database
      .prepare(
        `UPDATE payments SET status='initialized', provider_reference=?, provider_payload=? WHERE id=?`,
      )
      .run(result.transactionId, JSON.stringify(result), paymentId);

    audit(userId, "member", "payment.charge", "payment", paymentId, ip, ua, {
      provider: "palpluss",
      reference: internalRef,
      transactionId: result.transactionId,
      phone: normalized,
      amountKobo: feeKobo,
    });

    return {
      paymentId,
      reference: result.transactionId, // frontend polls this
      status: "pending",
      displayText: "Check your phone for the M-Pesa prompt and enter your PIN.",
    };
  } catch (e) {
    database
      .prepare(
        `UPDATE payments SET status='failed', failure_reason=? WHERE id=?`,
      )
      .run(String(e.message).slice(0, 500), paymentId);
    console.error("[palpluss] STK error:", e.message);
    return { error: "Unable to charge M-Pesa: " + e.message };
  }
}

/**
 * Handle a PalPluss webhook for STK Push or B2C payout.
 * Called from server.js at POST /api/webhooks/palpluss.
 */
function handlePalPlussWebhook(body, ip, ua) {
  const database = getDb();
  const event = body || {};
  const eventType = event.event_type;
  const tx = event.transaction || {};

  if (!tx.id) return { ok: true, ignored: true };

  // ----- STK Push (collections) -----
  if (tx.type === "STK") {
    const internalRef = tx.external_reference;
    const payment = database
      .prepare(`SELECT * FROM payments WHERE internal_reference = ? LIMIT 1`)
      .get(internalRef);
    if (!payment) {
      console.error("[palpluss] webhook: unknown STK ref", internalRef);
      return { ok: true, ignored: true };
    }

    if (payment.status === "success") {
      return { ok: true, alreadyProcessed: true };
    }

    if (eventType === "transaction.success") {
      const verifiedData = {
        reference: tx.id,
        amount: String(Math.round(Number(tx.amount) * 100)),
        currency: tx.currency || "KES",
        status: "success",
        channel: "mobile_money",
        fees: Math.round(Number(tx.transaction_fee || 0) * 100),
        metadata: {
          payment_id: payment.id,
          internal_reference: payment.internal_reference,
          user_id: payment.user_id,
          mpesa_receipt: tx.mpesa_receipt,
        },
      };
      const result = processSuccessfulPayment(verifiedData, ip, ua);
      return { ok: true, ...result };
    }

    if (
      eventType === "transaction.failed" ||
      eventType === "transaction.cancelled" ||
      eventType === "transaction.expired"
    ) {
      database
        .prepare(
          `UPDATE payments SET status='failed', failure_reason=?, provider_payload=?, verified_at=datetime('now'), updated_at=datetime('now')
           WHERE id=?`,
        )
        .run(tx.result_desc || eventType, JSON.stringify(tx), payment.id);
      return { ok: true, status: "failed" };
    }
  }

  // ----- B2C Payout (disbursements) -----
  if (tx.type === "B2C") {
    const reference = tx.external_reference;
    const withdrawal = database
      .prepare(`SELECT * FROM withdrawals WHERE provider_reference = ? LIMIT 1`)
      .get(reference);
    if (!withdrawal) {
      console.error("[palpluss] webhook: unknown B2C ref", reference);
      return { ok: true, ignored: true };
    }

    if (withdrawal.status === "paid") return { ok: true, alreadyPaid: true };

    if (eventType === "transaction.success") {
      finalizePayoutSuccess(withdrawal, tx, null, ip, ua);
      return { ok: true, status: "paid" };
    }

    if (
      eventType === "transaction.failed" ||
      eventType === "transaction.cancelled" ||
      eventType === "transaction.expired"
    ) {
      finalizePayoutFailure(
        withdrawal,
        tx.result_desc || eventType,
        tx,
        null,
        ip,
        ua,
      );
      return { ok: true, status: "failed" };
    }
  }

  return { ok: true, ignored: true };
}

// ============================================================================
// PAYMENT PROCESSING (idempotent, transactional)
// ============================================================================
function processSuccessfulPayment(verifiedData, ip, ua) {
  const database = getDb();
  const reference = verifiedData.reference;
  const amountKobo = parseInt(verifiedData.amount, 10);
  const currency = verifiedData.currency || "KES";
  const status = verifiedData.status;
  const channel = verifiedData.channel;
  const fees = parseInt(verifiedData.fees || 0, 10);
  const metadata = verifiedData.metadata || {};
  const internalReference = metadata.internal_reference;

  const paymentRow = database
    .prepare(
      `SELECT * FROM payments
       WHERE provider_reference = ? OR internal_reference = ? OR id = ?
       LIMIT 1`,
    )
    .get(reference, internalReference || "", metadata.payment_id || "");

  if (!paymentRow) return { error: "Payment record not found" };

  if (paymentRow.status === "success") {
    const commission = database
      .prepare("SELECT * FROM commissions WHERE source_payment_id = ?")
      .get(paymentRow.id);
    return { alreadyProcessed: true, paymentId: paymentRow.id, commission };
  }

  if (status !== "success") {
    database
      .prepare(
        `UPDATE payments SET status = ?, failure_reason = ?, provider_payload = ?, verified_at = datetime('now'), updated_at = datetime('now')
         WHERE id = ?`,
      )
      .run(
        status === "failed" ? "failed" : "abandoned",
        "provider_status:" + status,
        JSON.stringify(verifiedData),
        paymentRow.id,
      );
    return { error: "Payment not successful", status };
  }

  if (currency !== "KES") return { error: "Unexpected currency: " + currency };
  if (amountKobo !== paymentRow.expected_amount_kobo)
    return {
      error: `Amount mismatch: expected ${paymentRow.expected_amount_kobo}, got ${amountKobo}`,
    };

  const result = database.transaction(() => {
    const fresh = database
      .prepare("SELECT * FROM payments WHERE id = ?")
      .get(paymentRow.id);
    if (fresh.status === "success")
      return { alreadyProcessed: true, paymentId: fresh.id };

    database
      .prepare(
        `UPDATE payments
         SET status = 'success', provider_reference = ?, actual_amount_kobo = ?, provider_fee_kobo = ?,
             channel = ?, provider_payload = ?, verified_at = datetime('now'), updated_at = datetime('now'),
             verification_attempts = verification_attempts + 1
         WHERE id = ?`,
      )
      .run(
        reference,
        amountKobo,
        fees || null,
        channel || null,
        JSON.stringify(verifiedData),
        fresh.id,
      );

    const membership = database
      .prepare("SELECT * FROM membership WHERE user_id = ?")
      .get(fresh.user_id);
    if (membership && membership.status !== "active") {
      database
        .prepare(
          `UPDATE membership SET status = 'active', activated_at = datetime('now'),
             activated_by_payment_id = ?, updated_at = datetime('now')
           WHERE user_id = ?`,
        )
        .run(fresh.id, fresh.user_id);
      database
        .prepare(
          `UPDATE users SET status = 'active', updated_at = datetime('now') WHERE id = ? AND status != 'suspended'`,
        )
        .run(fresh.user_id);
    }

    const platformAllocationKobo = getSettingInt(
      "platform_allocation_kobo",
      CONFIG.business.platformAllocationKobo,
    );
    const commissionKobo = getSettingInt(
      "referral_commission_kobo",
      CONFIG.business.referralCommissionKobo,
    );

    insertLedger({
      entryType: "payment_collection",
      direction: "credit",
      amountKobo,
      userId: fresh.user_id,
      paymentId: fresh.id,
      reference: fresh.internal_reference,
      description: "Registration payment collected",
    });
    if (fees) {
      insertLedger({
        entryType: "processing_fee",
        direction: "debit",
        amountKobo: fees,
        userId: fresh.user_id,
        paymentId: fresh.id,
        reference: fresh.internal_reference,
        description: "Payment processor fee",
      });
    }
    insertLedger({
      entryType: "platform_allocation",
      direction: "debit",
      amountKobo: platformAllocationKobo,
      userId: null,
      paymentId: fresh.id,
      reference: fresh.internal_reference,
      description: "Nominal platform allocation",
    });

    let commission = null;
    const user = database
      .prepare("SELECT * FROM users WHERE id = ?")
      .get(fresh.user_id);
    const referrer =
      user && user.referred_by_user_id
        ? database
            .prepare("SELECT * FROM users WHERE id = ?")
            .get(user.referred_by_user_id)
        : null;
    const referralsEnabled = getSettingBool(
      "referrals_enabled",
      CONFIG.features.referralsEnabled,
    );
    const eligibleReferrer =
      referrer &&
      referralsEnabled &&
      referrer.status === "active" &&
      referrer.role === "member" &&
      referrer.id !== user.id &&
      normalizePhone(referrer.phone) !== normalizePhone(user.phone);

    if (eligibleReferrer) {
      const existing = database
        .prepare("SELECT * FROM commissions WHERE source_payment_id = ?")
        .get(fresh.id);
      if (!existing) {
        const commissionId = uuidv4();
        const delayHours = getSettingInt(
          "commission_settlement_delay_hours",
          CONFIG.business.commissionSettlementDelayHours,
        );
        const eligibleAt = new Date(
          Date.now() + delayHours * 3600 * 1000,
        ).toISOString();
        database
          .prepare(
            `INSERT INTO commissions
             (id, beneficiary_user_id, source_user_id, source_payment_id, amount_kobo, currency, status, eligible_at)
             VALUES (?, ?, ?, ?, ?, 'KES', 'pending', ?)`,
          )
          .run(
            commissionId,
            referrer.id,
            user.id,
            fresh.id,
            commissionKobo,
            eligibleAt,
          );
        insertLedger({
          entryType: "referral_commission_liability",
          direction: "credit",
          amountKobo: commissionKobo,
          userId: referrer.id,
          paymentId: fresh.id,
          commissionId,
          reference: fresh.internal_reference,
          description: "Referral commission liability",
        });
        commission = database
          .prepare("SELECT * FROM commissions WHERE id = ?")
          .get(commissionId);
      }
    }

    return { alreadyProcessed: false, paymentId: fresh.id, commission };
  })();

  // Side-effects that must NOT run inside the DB transaction:
  // SSE to the browser and notification rows — if the tx rolls back,
  // the user should never see "payment confirmed".
  try {
    audit(
      result.paymentId,
      "system",
      "payment.success",
      "payment",
      result.paymentId,
      ip,
      ua,
      {
        reference,
        amountKobo,
        commissionId: result.commission ? result.commission.id : null,
      },
    );
  } catch (e) {
    console.error("[post-tx audit]", e.message);
  }
  try {
    notify(
      paymentRow.user_id,
      "payment_success",
      "Payment received",
      `Your registration payment of KSh ${(amountKobo / 100).toFixed(2)} has been confirmed. Membership is active.`,
      { paymentId: result.paymentId },
    );
  } catch (e) {
    console.error("[post-tx notify]", e.message);
  }
  if (result.commission) {
    try {
      notify(
        result.commission.beneficiary_user_id,
        "commission_credited",
        "Referral commission pending",
        `You earned KSh ${(result.commission.amount_kobo / 100).toFixed(2)} from a referral. It becomes available after the settlement period.`,
        { commissionId: result.commission.id },
      );
    } catch (e) {
      console.error("[post-tx notify-commission]", e.message);
    }
    try {
      pushSSE(result.commission.beneficiary_user_id, {
        type: "commission_credited",
        amountKobo: result.commission.amount_kobo,
        amount: `KSh ${(result.commission.amount_kobo / 100).toFixed(2)}`,
        at: nowIso(),
      });
    } catch (e) {
      console.error("[post-tx sse-commission]", e.message);
    }
  }
  try {
    pushSSE(paymentRow.user_id, {
      type: "payment_success",
      paymentId: result.paymentId,
      amountKobo,
      at: nowIso(),
    });
  } catch (e) {
    console.error("[post-tx sse]", e.message);
  }

  return result;
}

function insertLedger(entry) {
  getDb()
    .prepare(
      `INSERT INTO ledger_entries
       (id, entry_type, direction, amount_kobo, currency, user_id, payment_id, commission_id, payout_id, reference, description, metadata)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .run(
      uuidv4(),
      entry.entryType,
      entry.direction,
      entry.amountKobo,
      entry.currency || "KES",
      entry.userId || null,
      entry.paymentId || null,
      entry.commissionId || null,
      entry.payoutId || null,
      entry.reference || null,
      entry.description || null,
      entry.metadata ? JSON.stringify(entry.metadata) : null,
    );
}

// ============================================================================
// WALLET  (unchanged)
// ============================================================================
function recomputeWallet(userId) {
  const database = getDb();
  const commissions = database
    .prepare(
      `SELECT status, SUM(amount_kobo) AS total FROM commissions
       WHERE beneficiary_user_id = ? GROUP BY status`,
    )
    .all(userId);
  const byStatus = {
    pending: 0,
    eligible: 0,
    available: 0,
    payout_processing: 0,
    paid: 0,
    reversed: 0,
  };
  for (const r of commissions)
    if (r.status in byStatus) byStatus[r.status] = r.total || 0;

  const withdrawals = database
    .prepare(
      `SELECT status, SUM(amount_kobo) AS total FROM withdrawals WHERE user_id = ? GROUP BY status`,
    )
    .all(userId);
  const wByStatus = {
    requested: 0,
    approved: 0,
    processing: 0,
    paid: 0,
    failed: 0,
    rejected: 0,
    cancelled: 0,
  };
  for (const w of withdrawals)
    if (w.status in wByStatus) wByStatus[w.status] = w.total || 0;

  const reserved =
    wByStatus.requested + wByStatus.approved + wByStatus.processing;
  const available = byStatus.available - reserved;

  return {
    pendingKobo: byStatus.pending + byStatus.eligible,
    availableKobo: Math.max(available, 0),
    processingKobo: byStatus.payout_processing,
    reservedKobo: reserved,
    paidKobo: byStatus.paid,
    withdrawnKobo: wByStatus.paid,
    reversedKobo: byStatus.reversed,
    totalEarningsKobo:
      byStatus.pending +
      byStatus.eligible +
      byStatus.available +
      byStatus.payout_processing +
      byStatus.paid,
  };
}

function promoteEligibleCommissions() {
  const database = getDb();
  const now = nowIso();
  const rows = database
    .prepare(
      `SELECT id, beneficiary_user_id FROM commissions
       WHERE (status = 'pending' AND eligible_at IS NOT NULL AND eligible_at <= ?)
          OR status = 'eligible'`,
    )
    .all(now);
  if (rows.length === 0) return 0;

  const update = database.prepare(
    `UPDATE commissions SET status = 'available', available_at = datetime('now'), updated_at = datetime('now') WHERE id = ?`,
  );
  const tx = database.transaction(() => {
    for (const r of rows) update.run(r.id);
  });
  tx();
  for (const r of rows) {
    if (r.beneficiary_user_id) {
      pushSSE(r.beneficiary_user_id, {
        type: "commission_eligible",
        at: nowIso(),
      });
    }
  }
  return rows.length;
}

function listCommissions(userId, page, pageSize) {
  const database = getDb();
  const limit = Math.min(Math.max(parseInt(pageSize || 20, 10), 1), 100);
  const p = Math.max(parseInt(page || 1, 10), 1);
  const offset = (p - 1) * limit;
  const total = database
    .prepare(
      "SELECT COUNT(*) AS c FROM commissions WHERE beneficiary_user_id = ?",
    )
    .get(userId).c;
  const items = database
    .prepare(
      `SELECT c.*, u.full_name AS source_name, u.phone AS source_phone
       FROM commissions c JOIN users u ON u.id = c.source_user_id
       WHERE c.beneficiary_user_id = ?
       ORDER BY c.created_at DESC LIMIT ? OFFSET ?`,
    )
    .all(userId, limit, offset);
  return {
    page: p,
    pageSize: limit,
    total,
    items: items.map((c) => ({
      id: c.id,
      amountKobo: c.amount_kobo,
      status: c.status,
      sourceName: maskName(c.source_name),
      sourcePhone: maskPhone(c.source_phone),
      createdAt: c.created_at,
      eligibleAt: c.eligible_at,
      availableAt: c.available_at,
      reversedAt: c.reversed_at,
    })),
  };
}

function listWalletTransactions(userId, page, pageSize) {
  const database = getDb();
  const limit = Math.min(Math.max(parseInt(pageSize || 20, 10), 1), 100);
  const p = Math.max(parseInt(page || 1, 10), 1);
  const offset = (p - 1) * limit;
  const total = database
    .prepare("SELECT COUNT(*) AS c FROM ledger_entries WHERE user_id = ?")
    .get(userId).c;
  const items = database
    .prepare(
      "SELECT * FROM ledger_entries WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
    )
    .all(userId, limit, offset);
  return { page: p, pageSize: limit, total, items };
}

// ============================================================================
// WITHDRAWALS — PALPLUSS B2C PAYOUTS
// ============================================================================
function requestWithdrawal(userId, amountKobo, ip, ua) {
  const database = getDb();
  if (
    !getSettingBool("withdrawals_enabled", CONFIG.features.withdrawalsEnabled)
  )
    return { error: "Withdrawals are currently disabled" };
  const user = findUserById(userId);
  if (!user) return { error: "User not found" };
  if (user.status !== "active") return { error: "Account is not active" };
  if (!user.payout_phone) return { error: "No M-Pesa payout number on file" };

  const amt = parseInt(amountKobo, 10);
  const min = getSettingInt(
    "min_withdrawal_kobo",
    CONFIG.business.minWithdrawalKobo,
  );
  const max = getSettingInt(
    "max_withdrawal_kobo",
    CONFIG.business.maxWithdrawalKobo,
  );
  if (!Number.isFinite(amt) || amt <= 0) return { error: "Invalid amount" };
  if (amt < min)
    return { error: `Minimum withdrawal is KSh ${(min / 100).toFixed(2)}` };
  if (amt > max)
    return { error: `Maximum withdrawal is KSh ${(max / 100).toFixed(2)}` };

  promoteEligibleCommissions();
  const wallet = recomputeWallet(userId);
  if (wallet.availableKobo < amt)
    return { error: "Insufficient available balance" };

  const tx = database.transaction(() => {
    const fresh = database
      .prepare("SELECT * FROM users WHERE id = ?")
      .get(userId);
    if (!fresh || fresh.status !== "active")
      throw new Error("Account not eligible");
    const wallet2 = recomputeWallet(userId);
    if (wallet2.availableKobo < amt)
      throw new Error("Insufficient available balance");

    const withdrawalId = uuidv4();
    database
      .prepare(
        `INSERT INTO withdrawals
         (id, user_id, amount_kobo, currency, status, payout_phone)
         VALUES (?, ?, ?, 'KES', 'requested', ?)`,
      )
      .run(withdrawalId, userId, amt, fresh.payout_phone);
    reserveCommissionFunds(userId, amt);
    audit(
      userId,
      "member",
      "withdrawal.request",
      "withdrawal",
      withdrawalId,
      ip,
      ua,
      {
        amountKobo: amt,
        payoutPhone: fresh.payout_phone,
      },
    );
    notify(
      userId,
      "withdrawal_requested",
      "Withdrawal request received",
      `Your withdrawal of KSh ${(amt / 100).toFixed(2)} is pending review.`,
      { withdrawalId },
    );
    return withdrawalId;
  });

  try {
    return { withdrawalId: tx() };
  } catch (e) {
    return { error: e.message };
  }
}

function reserveCommissionFunds(userId, amountKobo) {
  const database = getDb();
  const rows = database
    .prepare(
      `SELECT id, amount_kobo FROM commissions
       WHERE beneficiary_user_id = ? AND status = 'available'
       ORDER BY created_at ASC`,
    )
    .all(userId);

  // Greedy fill — we must consume whole commissions exactly.
  let remaining = amountKobo;
  const toReserve = [];
  for (const r of rows) {
    if (remaining <= 0) break;
    toReserve.push(r);
    remaining -= r.amount_kobo;
  }

  if (remaining !== 0) {
    const unit = rows.length ? rows[0].amount_kobo : 0;
    throw new Error(
      `Withdrawal amount must exactly match whole commissions (each KSh ${(unit / 100).toFixed(2)})`,
    );
  }

  const update = database.prepare(
    `UPDATE commissions SET status = 'payout_processing', updated_at = datetime('now') WHERE id = ?`,
  );
  for (const r of toReserve) update.run(r.id);
}

async function processPayouts(actorId, ip, ua) {
  const database = getDb();
  const pending = database
    .prepare(
      `SELECT * FROM withdrawals
       WHERE status IN ('requested', 'approved') AND provider_transfer_code IS NULL
       ORDER BY created_at ASC LIMIT 20`,
    )
    .all();
  const results = [];
  for (const w of pending) {
    try {
      results.push(await executePayout(w, actorId, ip, ua));
    } catch (e) {
      results.push({ withdrawalId: w.id, error: e.message });
    }
  }
  return { results };
}

async function executePayout(withdrawal, actorId, ip, ua) {
  const database = getDb();
  const user = findUserById(withdrawal.user_id);
  if (!user) return { withdrawalId: withdrawal.id, error: "user_missing" };

  const existing = database
    .prepare("SELECT * FROM payout_transfers WHERE withdrawal_id = ?")
    .get(withdrawal.id);
  if (existing)
    return {
      withdrawalId: withdrawal.id,
      error: "transfer_already_initiated",
      transferId: existing.id,
    };

  const amountKes = withdrawal.amount_kobo / 100;
  const reference =
    "WTH-" +
    withdrawal.id.slice(0, 8).toUpperCase() +
    "-" +
    Date.now().toString(36).toUpperCase();
  const callbackUrl = `${CONFIG.appUrl}/api/webhooks/palpluss`;

  try {
    const result = await palpluss.initiateB2CPayout({
      amountKes,
      phone: withdrawal.payout_phone,
      reference,
      description: "Referral commission withdrawal",
      callbackUrl,
      idempotencyKey: reference,
    });

    const transactionId = result.transactionId;
    database
      .prepare(
        `INSERT INTO payout_transfers
         (id, withdrawal_id, provider, provider_transfer_code, provider_reference, amount_kobo, status, raw_response)
         VALUES (?, ?, 'palpluss', ?, ?, ?, 'initiated', ?)`,
      )
      .run(
        uuidv4(),
        withdrawal.id,
        String(transactionId),
        reference,
        withdrawal.amount_kobo,
        JSON.stringify(result),
      );

    database
      .prepare(
        `UPDATE withdrawals
         SET status = 'processing', provider_transfer_code = ?, provider_reference = ?, processed_at = datetime('now'), updated_at = datetime('now')
         WHERE id = ?`,
      )
      .run(String(transactionId), reference, withdrawal.id);

    audit(
      actorId || null,
      "system",
      "payout.initiated",
      "withdrawal",
      withdrawal.id,
      ip,
      ua,
      {
        transactionId,
        reference,
        amountKobo: withdrawal.amount_kobo,
      },
    );
    notify(
      withdrawal.user_id,
      "withdrawal_processing",
      "Withdrawal processing",
      `Your withdrawal of KSh ${(withdrawal.amount_kobo / 100).toFixed(2)} is being processed.`,
      { withdrawalId: withdrawal.id },
    );
    pushSSE(withdrawal.user_id, {
      type: "withdrawal_processing",
      withdrawalId: withdrawal.id,
      at: nowIso(),
    });

    return { withdrawalId: withdrawal.id, transactionId, reference };
  } catch (e) {
    database
      .prepare(
        `UPDATE withdrawals SET status = 'failed', failure_reason = ?, updated_at = datetime('now') WHERE id = ?`,
      )
      .run(String(e.message).slice(0, 400), withdrawal.id);
    database
      .prepare(
        `UPDATE commissions SET status = 'available', updated_at = datetime('now')
         WHERE beneficiary_user_id = ? AND status = 'payout_processing'`,
      )
      .run(withdrawal.user_id);
    return { withdrawalId: withdrawal.id, error: e.message };
  }
}

function finalizePayoutSuccess(w, txData, actorId, ip, ua) {
  const database = getDb();
  database.transaction(() => {
    const fresh = database
      .prepare("SELECT * FROM withdrawals WHERE id = ?")
      .get(w.id);
    if (fresh.status === "paid") return;
    database
      .prepare(
        `UPDATE withdrawals SET status = 'paid', paid_at = datetime('now'), updated_at = datetime('now') WHERE id = ?`,
      )
      .run(fresh.id);
    database
      .prepare(
        `UPDATE payout_transfers SET status = 'success', raw_response = ?, updated_at = datetime('now') WHERE withdrawal_id = ?`,
      )
      .run(JSON.stringify(txData), fresh.id);
    database
      .prepare(
        `UPDATE commissions SET status = 'paid', updated_at = datetime('now')
         WHERE beneficiary_user_id = ? AND status = 'payout_processing'`,
      )
      .run(fresh.user_id);
    insertLedger({
      entryType: "payout",
      direction: "debit",
      amountKobo: fresh.amount_kobo,
      userId: fresh.user_id,
      payoutId: fresh.id,
      reference: fresh.provider_transfer_code,
      description: "M-Pesa payout completed",
    });
    audit(
      actorId || null,
      "system",
      "payout.success",
      "withdrawal",
      fresh.id,
      ip,
      ua,
      {
        amountKobo: fresh.amount_kobo,
      },
    );
    notify(
      fresh.user_id,
      "payout_success",
      "Withdrawal paid",
      `Your withdrawal of KSh ${(fresh.amount_kobo / 100).toFixed(2)} has been paid to M-Pesa.`,
      { withdrawalId: fresh.id },
    );
    pushSSE(fresh.user_id, {
      type: "payout_paid",
      withdrawalId: fresh.id,
      amountKobo: fresh.amount_kobo,
      at: nowIso(),
    });
  })();
}

function finalizePayoutFailure(w, reason, raw, actorId, ip, ua) {
  const database = getDb();
  database.transaction(() => {
    const fresh = database
      .prepare("SELECT * FROM withdrawals WHERE id = ?")
      .get(w.id);
    if (fresh.status === "paid") return;
    database
      .prepare(
        `UPDATE withdrawals SET status = 'failed', failure_reason = ?, updated_at = datetime('now') WHERE id = ?`,
      )
      .run(String(reason).slice(0, 400), fresh.id);
    database
      .prepare(
        `UPDATE payout_transfers SET status = 'failed', raw_response = ?, updated_at = datetime('now') WHERE withdrawal_id = ?`,
      )
      .run(JSON.stringify(raw || {}), fresh.id);
    database
      .prepare(
        `UPDATE commissions SET status = 'available', updated_at = datetime('now')
         WHERE beneficiary_user_id = ? AND status = 'payout_processing'`,
      )
      .run(fresh.user_id);
    audit(
      actorId || null,
      "system",
      "payout.failed",
      "withdrawal",
      fresh.id,
      ip,
      ua,
      { reason },
    );
    notify(
      fresh.user_id,
      "payout_failed",
      "Withdrawal failed",
      `Your withdrawal of KSh ${(fresh.amount_kobo / 100).toFixed(2)} could not be processed. Funds are back in your balance.`,
      { withdrawalId: fresh.id, reason },
    );
    pushSSE(fresh.user_id, {
      type: "payout_failed",
      withdrawalId: fresh.id,
      at: nowIso(),
    });
  })();
}

function listWithdrawals(userId, page, pageSize) {
  const database = getDb();
  const limit = Math.min(Math.max(parseInt(pageSize || 20, 10), 1), 100);
  const p = Math.max(parseInt(page || 1, 10), 1);
  const offset = (p - 1) * limit;
  const total = database
    .prepare("SELECT COUNT(*) AS c FROM withdrawals WHERE user_id = ?")
    .get(userId).c;
  const items = database
    .prepare(
      "SELECT * FROM withdrawals WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
    )
    .all(userId, limit, offset);
  return { page: p, pageSize: limit, total, items };
}

// ============================================================================
// RECONCILIATION — adapted for PalPluss
// ============================================================================
async function runReconciliation(actorId, ip, ua) {
  const database = getDb();
  const runId = uuidv4();
  database
    .prepare(
      `INSERT INTO reconciliation_runs (id, run_by, status) VALUES (?, ?, 'running')`,
    )
    .run(runId, actorId || null);

  const exceptions = [];

  // 1. Stale STK payments — re-query PalPluss
  const stalePayments = database
    .prepare(
      `SELECT * FROM payments
       WHERE status IN ('pending', 'initialized')
         AND datetime(created_at) <= datetime('now', '-30 minutes')`,
    )
    .all();
  for (const p of stalePayments) {
    if (!p.provider_reference) continue;
    try {
      const tx = await palpluss.getTransaction(p.provider_reference);
      if (tx.status === "SUCCESS") {
        const verifiedData = {
          reference: tx.transactionId,
          amount: String(Math.round(Number(tx.amount) * 100)),
          currency: tx.currency || "KES",
          status: "success",
          channel: "mobile_money",
          fees: Math.round(Number(tx.transactionFee || 0) * 100),
          metadata: {
            payment_id: p.id,
            internal_reference: p.internal_reference,
            user_id: p.user_id,
            mpesa_receipt: tx.mpesaReceipt,
          },
        };
        processSuccessfulPayment(verifiedData, ip, ua);
      } else if (
        tx.status === "FAILED" ||
        tx.status === "EXPIRED" ||
        tx.status === "CANCELLED"
      ) {
        database
          .prepare(
            `UPDATE payments SET status = 'failed', failure_reason = ?, updated_at = datetime('now') WHERE id = ?`,
          )
          .run(tx.resultDesc || tx.status, p.id);
      }
    } catch (e) {
      exceptions.push({
        type: "verification_error",
        paymentId: p.id,
        description: `PalPluss query failed: ${e.message}`,
      });
    }
  }

  // 2. Stale B2C payouts — re-query PalPluss
  const stalePayouts = database
    .prepare(
      `SELECT * FROM withdrawals w
       WHERE w.status IN ('processing', 'approved') AND w.provider_transfer_code IS NOT NULL
         AND datetime(w.updated_at) <= datetime('now', '-15 minutes')`,
    )
    .all();
  for (const w of stalePayouts) {
    try {
      const tx = await palpluss.getTransaction(w.provider_transfer_code);
      if (tx.status === "SUCCESS") {
        finalizePayoutSuccess(w, tx, actorId, ip, ua);
      } else if (
        tx.status === "FAILED" ||
        tx.status === "EXPIRED" ||
        tx.status === "CANCELLED"
      ) {
        finalizePayoutFailure(
          w,
          tx.resultDesc || tx.status,
          tx,
          actorId,
          ip,
          ua,
        );
      }
    } catch (e) {
      exceptions.push({
        type: "payout_unknown",
        withdrawalId: w.id,
        description: `PalPluss query failed: ${e.message}`,
      });
    }
  }

  const insertException = database.prepare(
    `INSERT INTO reconciliation_exceptions
     (id, run_id, exception_type, payment_id, withdrawal_id, description)
     VALUES (?, ?, ?, ?, ?, ?)`,
  );
  database.transaction(() => {
    for (const ex of exceptions) {
      insertException.run(
        uuidv4(),
        runId,
        ex.type,
        ex.paymentId || null,
        ex.withdrawalId || null,
        ex.description || null,
      );
    }
    database
      .prepare(
        `UPDATE reconciliation_runs SET status = 'completed', summary = ?, finished_at = datetime('now') WHERE id = ?`,
      )
      .run(JSON.stringify({ exceptions: exceptions.length }), runId);
  })();

  audit(
    actorId || null,
    "admin",
    "reconciliation.run",
    "reconciliation_run",
    runId,
    ip,
    ua,
    {
      exceptions: exceptions.length,
    },
  );
  return { runId, exceptions };
}

// ============================================================================
// ADMIN  (unchanged except provider references)
// ============================================================================
function adminOverview() {
  const database = getDb();
  const totalUsers = database
    .prepare("SELECT COUNT(*) AS c FROM users WHERE role = 'member'")
    .get().c;
  const activeMembers = database
    .prepare(
      "SELECT COUNT(*) AS c FROM users WHERE role='member' AND status='active'",
    )
    .get().c;
  const pendingMembers = database
    .prepare(
      "SELECT COUNT(*) AS c FROM users WHERE role='member' AND status='pending_payment'",
    )
    .get().c;
  const payments = database
    .prepare(
      "SELECT status, COUNT(*) AS c, SUM(actual_amount_kobo) AS amt FROM payments GROUP BY status",
    )
    .all();
  const pStats = {
    pending: 0,
    initialized: 0,
    success: 0,
    failed: 0,
    abandoned: 0,
    reversed: 0,
    refunded: 0,
  };
  const pAmounts = {
    pending: 0,
    initialized: 0,
    success: 0,
    failed: 0,
    abandoned: 0,
    reversed: 0,
    refunded: 0,
  };
  for (const p of payments)
    if (p.status in pStats) {
      pStats[p.status] = p.c;
      pAmounts[p.status] = p.amt || 0;
    }
  const commissions = database
    .prepare(
      "SELECT status, COUNT(*) AS c, SUM(amount_kobo) AS amt FROM commissions GROUP BY status",
    )
    .all();
  const cStats = {
    pending: 0,
    eligible: 0,
    available: 0,
    payout_processing: 0,
    paid: 0,
    reversed: 0,
  };
  const cAmounts = {
    pending: 0,
    eligible: 0,
    available: 0,
    payout_processing: 0,
    paid: 0,
    reversed: 0,
  };
  for (const c of commissions)
    if (c.status in cStats) {
      cStats[c.status] = c.c;
      cAmounts[c.status] = c.amt || 0;
    }
  const withdrawals = database
    .prepare(
      "SELECT status, COUNT(*) AS c, SUM(amount_kobo) AS amt FROM withdrawals GROUP BY status",
    )
    .all();
  const wStats = {
    requested: 0,
    approved: 0,
    processing: 0,
    paid: 0,
    failed: 0,
    rejected: 0,
    cancelled: 0,
  };
  const wAmounts = {
    requested: 0,
    approved: 0,
    processing: 0,
    paid: 0,
    failed: 0,
    rejected: 0,
    cancelled: 0,
  };
  for (const w of withdrawals)
    if (w.status in wStats) {
      wStats[w.status] = w.c;
      wAmounts[w.status] = w.amt || 0;
    }
  const fees = database
    .prepare(
      "SELECT COALESCE(SUM(amount_kobo), 0) AS t FROM ledger_entries WHERE entry_type = 'processing_fee'",
    )
    .get().t;
  const platformAlloc = database
    .prepare(
      "SELECT COALESCE(SUM(amount_kobo), 0) AS t FROM ledger_entries WHERE entry_type = 'platform_allocation'",
    )
    .get().t;
  const openExceptions = database
    .prepare(
      "SELECT COUNT(*) AS c FROM reconciliation_exceptions WHERE resolved = 0",
    )
    .get().c;
  return {
    totalUsers,
    activeMembers,
    pendingMembers,
    payments: { counts: pStats, amountsKobo: pAmounts },
    commissions: { counts: cStats, amountsKobo: cAmounts },
    withdrawals: { counts: wStats, amountsKobo: wAmounts },
    processingFeesKobo: fees,
    platformAllocationKobo: platformAlloc,
    openReconciliationExceptions: openExceptions,
  };
}

function adminListUsers({ q, status, page, pageSize }) {
  const database = getDb();
  const limit = Math.min(Math.max(parseInt(pageSize || 20, 10), 1), 100);
  const p = Math.max(parseInt(page || 1, 10), 1);
  const offset = (p - 1) * limit;
  let where = `WHERE role = 'member'`;
  const params = [];
  if (q) {
    where += ` AND (full_name LIKE ? OR phone LIKE ? OR email LIKE ? OR referral_code LIKE ?)`;
    const like = "%" + q + "%";
    params.push(like, like, like, like);
  }
  if (status) {
    where += ` AND status = ?`;
    params.push(status);
  }
  const total = database
    .prepare(`SELECT COUNT(*) AS c FROM users ${where}`)
    .get(...params).c;
  const items = database
    .prepare(
      `SELECT * FROM users ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`,
    )
    .all(...params, limit, offset);
  return { page: p, pageSize: limit, total, items };
}

function adminUserDetail(userId) {
  const database = getDb();
  const user = findUserById(userId);
  if (!user) return null;
  return {
    user,
    membership: database
      .prepare("SELECT * FROM membership WHERE user_id = ?")
      .get(userId),
    payments: database
      .prepare(
        "SELECT * FROM payments WHERE user_id = ? ORDER BY created_at DESC",
      )
      .all(userId),
    commissions: database
      .prepare(
        `SELECT c.*, u.full_name AS source_name FROM commissions c
         JOIN users u ON u.id = c.source_user_id
         WHERE c.beneficiary_user_id = ? ORDER BY c.created_at DESC`,
      )
      .all(userId),
    withdrawals: database
      .prepare(
        "SELECT * FROM withdrawals WHERE user_id = ? ORDER BY created_at DESC",
      )
      .all(userId),
    wallet: recomputeWallet(userId),
  };
}

function adminSetUserStatus(userId, status, reason, actorId, ip, ua) {
  const database = getDb();
  if (
    ![
      "active",
      "suspended",
      "closed",
      "pending_payment",
      "unverified",
    ].includes(status)
  )
    return { error: "Invalid status" };
  const user = findUserById(userId);
  if (!user) return { error: "User not found" };
  database
    .prepare(
      `UPDATE users SET status = ?, suspended_reason = ?, updated_at = datetime('now') WHERE id = ?`,
    )
    .run(
      status,
      status === "suspended" ? reason || "Suspended by admin" : null,
      userId,
    );
  if (status === "suspended" || status === "closed") {
    database
      .prepare(
        `UPDATE membership SET status = ?, updated_at = datetime('now') WHERE user_id = ?`,
      )
      .run(status === "suspended" ? "suspended" : "cancelled", userId);
  }
  audit(actorId, "admin", "user.status_change", "user", userId, ip, ua, {
    status,
    reason,
  });
  return { ok: true };
}

function adminListPayments({ status, page, pageSize }) {
  const database = getDb();
  const limit = Math.min(Math.max(parseInt(pageSize || 20, 10), 1), 100);
  const p = Math.max(parseInt(page || 1, 10), 1);
  const offset = (p - 1) * limit;
  let where = "WHERE 1=1";
  const params = [];
  if (status) {
    where += " AND p.status = ?";
    params.push(status);
  }
  const total = database
    .prepare(`SELECT COUNT(*) AS c FROM payments p ${where}`)
    .get(...params).c;
  const items = database
    .prepare(
      `SELECT p.*, u.full_name, u.phone FROM payments p JOIN users u ON u.id = p.user_id ${where}
       ORDER BY p.created_at DESC LIMIT ? OFFSET ?`,
    )
    .all(...params, limit, offset);
  return { page: p, pageSize: limit, total, items };
}

function adminListCommissions({ status, page, pageSize }) {
  const database = getDb();
  const limit = Math.min(Math.max(parseInt(pageSize || 20, 10), 1), 100);
  const p = Math.max(parseInt(page || 1, 10), 1);
  const offset = (p - 1) * limit;
  let where = "WHERE 1=1";
  const params = [];
  if (status) {
    where += " AND c.status = ?";
    params.push(status);
  }
  const total = database
    .prepare(`SELECT COUNT(*) AS c FROM commissions c ${where}`)
    .get(...params).c;
  const items = database
    .prepare(
      `SELECT c.*, b.full_name AS beneficiary_name, s.full_name AS source_name
       FROM commissions c JOIN users b ON b.id = c.beneficiary_user_id
       JOIN users s ON s.id = c.source_user_id ${where}
       ORDER BY c.created_at DESC LIMIT ? OFFSET ?`,
    )
    .all(...params, limit, offset);
  return { page: p, pageSize: limit, total, items };
}

function adminListWithdrawals({ status, page, pageSize }) {
  const database = getDb();
  const limit = Math.min(Math.max(parseInt(pageSize || 20, 10), 1), 100);
  const p = Math.max(parseInt(page || 1, 10), 1);
  const offset = (p - 1) * limit;
  let where = "WHERE 1=1";
  const params = [];
  if (status) {
    where += " AND w.status = ?";
    params.push(status);
  }
  const total = database
    .prepare(`SELECT COUNT(*) AS c FROM withdrawals w ${where}`)
    .get(...params).c;
  const items = database
    .prepare(
      `SELECT w.*, u.full_name, u.phone FROM withdrawals w JOIN users u ON u.id = w.user_id ${where}
       ORDER BY w.created_at DESC LIMIT ? OFFSET ?`,
    )
    .all(...params, limit, offset);
  return { page: p, pageSize: limit, total, items };
}

function adminListAudit({ page, pageSize }) {
  const database = getDb();
  const limit = Math.min(Math.max(parseInt(pageSize || 50, 10), 1), 200);
  const p = Math.max(parseInt(page || 1, 10), 1);
  const offset = (p - 1) * limit;
  const total = database
    .prepare("SELECT COUNT(*) AS c FROM audit_logs")
    .get().c;
  const items = database
    .prepare(
      "SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT ? OFFSET ?",
    )
    .all(limit, offset);
  return { page: p, pageSize: limit, total, items };
}

function adminListSettings() {
  return getDb().prepare("SELECT * FROM settings ORDER BY key").all();
}
function adminUpdateSetting(key, value, actorId, ip, ua) {
  setSetting(key, value, actorId);
  audit(actorId, "admin", "setting.update", "settings", key, ip, ua, {
    key,
    value,
  });
  return { ok: true };
}
function adminListReconciliation() {
  const database = getDb();
  return {
    runs: database
      .prepare(
        "SELECT * FROM reconciliation_runs ORDER BY started_at DESC LIMIT 20",
      )
      .all(),
    exceptions: database
      .prepare(
        "SELECT * FROM reconciliation_exceptions ORDER BY created_at DESC LIMIT 100",
      )
      .all(),
  };
}

// ============================================================================
// BOOTSTRAP  (unchanged)
// ============================================================================
async function bootstrap() {
  migrate();
  tursoClient = makeTursoClient();
  if (tursoClient) {
    await restoreFromTurso();
  } else {
    console.log("[turso] not configured — local-only mode");
  }
  seedSettings();
  seedAdmin();
}

// ============================================================================
// EXPORTS
// ============================================================================
module.exports = {
  CONFIG,
  getDb,
  migrate,
  seedSettings,
  seedAdmin,
  bootstrap,
  normalizePhone,
  validateEmail,
  generateReferralCode,
  registerUser,
  authenticateUser,
  findUserById,
  findUserByPhone,
  findUserByEmail,
  findUserByReferralCode,
  generateToken,
  verifyToken,
  recordReferralClick,
  getReferralStats,
  listReferrals,
  chargeMpesa,
  handlePalPlussWebhook,
  processSuccessfulPayment,
  recomputeWallet,
  promoteEligibleCommissions,
  listCommissions,
  listWalletTransactions,
  requestWithdrawal,
  processPayouts,
  finalizePayoutSuccess,
  finalizePayoutFailure,
  listWithdrawals,
  runReconciliation,
  adminOverview,
  adminListUsers,
  adminUserDetail,
  adminSetUserStatus,
  adminListPayments,
  adminListCommissions,
  adminListWithdrawals,
  adminListAudit,
  adminListSettings,
  adminUpdateSetting,
  adminListReconciliation,
  getSetting,
  getSettingInt,
  getSettingBool,
  setSetting,
  audit,
  notify,
  registerSSENotifier,
  pushSSE,
};
