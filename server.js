/**
 * server.js — Express entry, auth, member + admin API, SSE, PalPluss webhooks
 */
"use strict";

require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const morgan = require("morgan");
const rateLimit = require("express-rate-limit");
const path = require("path");

const backend = require("./backend");
const palpluss = require("./palpluss");

const app = express();
const PORT = process.env.PORT || 3000;

app.set("trust proxy", 1);

app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        "default-src": ["'self'"],
        "script-src": [
          "'self'",
          "'unsafe-inline'",
          "https://js.paystack.co",
          "https://cdn.tailwindcss.com",
        ],
        "script-src-attr": ["'unsafe-inline'"],
        "connect-src": ["'self'", "https://api.palpluss.com"],
        "frame-src": ["'self'", "https://checkout.paystack.com"],
        "img-src": ["'self'", "data:", "https:"],
        "style-src": ["'self'", "'unsafe-inline'"],
      },
    },
    crossOriginEmbedderPolicy: false,
  }),
);

app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true, limit: "2mb" }));
app.use(cookieParser());
app.use(morgan("combined"));

app.use(
  rateLimit({
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || "900000", 10),
    max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || "300", 10),
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: "Too many requests, please slow down" },
  }),
);

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: parseInt(process.env.AUTH_RATE_LIMIT_MAX || "20", 10),
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many authentication attempts" },
});

// ============================================================================
// SSE REGISTRY
// ============================================================================
const sseClients = new Map();

backend.registerSSENotifier((userId, event) => {
  const set = sseClients.get(userId);
  if (!set || set.size === 0) return;
  const payload = `data: ${JSON.stringify(event)}\n\n`;
  for (const res of set) {
    try {
      res.write(payload);
    } catch (e) {}
  }
});

// ============================================================================
// AUTH MIDDLEWARE
// ============================================================================
function extractToken(req) {
  if (req.cookies && req.cookies.token) return req.cookies.token;
  const auth = req.headers.authorization;
  if (auth && auth.startsWith("Bearer ")) return auth.slice(7);
  return null;
}

function requireAuth(req, res, next) {
  const token = extractToken(req);
  if (!token) return res.status(401).json({ error: "Authentication required" });
  const payload = backend.verifyToken(token);
  if (!payload)
    return res.status(401).json({ error: "Invalid or expired session" });
  const user = backend.findUserById(payload.sub);
  if (!user) return res.status(401).json({ error: "User not found" });
  if (user.status === "suspended" || user.status === "closed")
    return res.status(403).json({ error: "Account is not active" });
  req.user = user;
  next();
}

function requireAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (req.user.role !== "admin")
      return res.status(403).json({ error: "Administrator access required" });
    next();
  });
}

function setAuthCookie(res, token) {
  res.cookie("token", token, {
    httpOnly: true,
    secure: backend.CONFIG.nodeEnv === "production",
    sameSite: "lax",
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });
}

function safeUser(user) {
  return {
    id: user.id,
    email: user.email,
    phone: user.phone,
    fullName: user.full_name,
    role: user.role,
    status: user.status,
    payoutPhone: user.payout_phone,
    referralCode: user.referral_code,
    createdAt: user.created_at,
  };
}

// ============================================================================
// STATIC
// ============================================================================
const PUBLIC_DIR = __dirname;
app.use("/data", (req, res) => res.status(404).end());
app.use(
  express.static(PUBLIC_DIR, { extensions: ["html"], index: "index.html" }),
);

// ============================================================================
// HEALTH / CONFIG
// ============================================================================
app.get("/api/health", (req, res) =>
  res.json({
    ok: true,
    service: "referal-kenya",
    time: new Date().toISOString(),
  }),
);

app.get("/api/config", (req, res) => {
  res.set("Cache-Control", "public, max-age=60");
  res.json({
    appName: backend.CONFIG.appName,
    registrationFeeKobo: backend.getSettingInt(
      "registration_fee_kobo",
      backend.CONFIG.business.registrationFeeKobo,
    ),
    referralCommissionKobo: backend.getSettingInt(
      "referral_commission_kobo",
      backend.CONFIG.business.referralCommissionKobo,
    ),
    minWithdrawalKobo: backend.getSettingInt(
      "min_withdrawal_kobo",
      backend.CONFIG.business.minWithdrawalKobo,
    ),
    paystackPublicKey: "",
    registrationEnabled: backend.getSettingBool(
      "registration_enabled",
      backend.CONFIG.features.registrationEnabled,
    ),
    referralsEnabled: backend.getSettingBool(
      "referrals_enabled",
      backend.CONFIG.features.referralsEnabled,
    ),
    withdrawalsEnabled: backend.getSettingBool(
      "withdrawals_enabled",
      backend.CONFIG.features.withdrawalsEnabled,
    ),
    maintenanceMode: backend.getSettingBool(
      "maintenance_mode",
      backend.CONFIG.features.maintenanceMode,
    ),
  });
});

// ============================================================================
// REFERRAL CLICK
// ============================================================================
app.post("/api/referral/click", (req, res) => {
  const { code, fingerprint } = req.body || {};
  const result = backend.recordReferralClick(
    code,
    req.ip,
    req.get("user-agent"),
    fingerprint,
  );
  if (!result) return res.status(400).json({ ok: false });
  res.json({ ok: true, code });
});

// ============================================================================
// AUTH
// ============================================================================
app.post("/api/auth/register", authLimiter, (req, res) => {
  try {
    const result = backend.registerUser(
      req.body || {},
      req.ip,
      req.get("user-agent"),
    );
    if (result.error) return res.status(400).json({ error: result.error });
    const token = backend.generateToken(result.user);
    setAuthCookie(res, token);
    res.status(201).json({ ok: true, token, user: safeUser(result.user) });
  } catch (e) {
    console.error("[register] error:", e);
    res.status(500).json({ error: "Registration failed" });
  }
});

app.post("/api/auth/login", authLimiter, (req, res) => {
  const { identifier, password } = req.body || {};
  const user = backend.authenticateUser(identifier, password);
  if (!user) return res.status(401).json({ error: "Invalid credentials" });
  const token = backend.generateToken(user);
  setAuthCookie(res, token);
  backend.audit(
    user.id,
    user.role,
    "auth.login",
    "user",
    user.id,
    req.ip,
    req.get("user-agent"),
    null,
  );
  res.json({ ok: true, token, user: safeUser(user) });
});

app.post("/api/auth/logout", (req, res) => {
  res.clearCookie("token");
  res.json({ ok: true });
});

app.get("/api/auth/me", requireAuth, (req, res) =>
  res.json({ user: safeUser(req.user) }),
);

// ============================================================================
// SSE
// ============================================================================
app.get("/api/events", requireAuth, (req, res) => {
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache, no-transform");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");
  res.flushHeaders();
  res.write(": connected\n\n");

  const userId = req.user.id;
  if (!sseClients.has(userId)) sseClients.set(userId, new Set());
  sseClients.get(userId).add(res);

  const ping = setInterval(() => {
    try {
      res.write(": ping\n\n");
    } catch (e) {}
  }, 25000);

  req.on("close", () => {
    clearInterval(ping);
    const set = sseClients.get(userId);
    if (set) set.delete(res);
    try {
      res.end();
    } catch (e) {}
  });
});

// ============================================================================
// MEMBER
// ============================================================================
app.get("/api/member/overview", requireAuth, (req, res) => {
  try {
    backend.promoteEligibleCommissions();
    const database = backend.getDb();
    const wallet = backend.recomputeWallet(req.user.id);
    const stats = backend.getReferralStats(req.user.id);
    const membership = database
      .prepare("SELECT * FROM membership WHERE user_id = ?")
      .get(req.user.id);
    const recentPayments = database
      .prepare(
        "SELECT id, internal_reference, status, actual_amount_kobo, created_at FROM payments WHERE user_id = ? ORDER BY created_at DESC LIMIT 5",
      )
      .all(req.user.id);
    const referralUrl = `${backend.CONFIG.appUrl}/?ref=${req.user.referral_code}`;
    res.json({
      user: safeUser(req.user),
      membership,
      wallet,
      referralStats: stats,
      referralUrl,
      recentPayments,
    });
  } catch (e) {
    console.error("[member/overview]", e);
    res.status(500).json({ error: "Failed to load overview" });
  }
});

app.get("/api/member/referrals", requireAuth, (req, res) => {
  const { page, pageSize } = req.query;
  res.json(backend.listReferrals(req.user.id, page, pageSize));
});

app.get("/api/member/commissions", requireAuth, (req, res) => {
  const { page, pageSize } = req.query;
  res.json(backend.listCommissions(req.user.id, page, pageSize));
});

app.get("/api/member/wallet/transactions", requireAuth, (req, res) => {
  const { page, pageSize } = req.query;
  res.json(backend.listWalletTransactions(req.user.id, page, pageSize));
});

app.get("/api/member/payments", requireAuth, (req, res) => {
  const database = backend.getDb();
  const page = Math.max(parseInt(req.query.page || "1", 10), 1);
  const pageSize = Math.min(
    Math.max(parseInt(req.query.pageSize || "20", 10), 1),
    100,
  );
  const offset = (page - 1) * pageSize;
  const total = database
    .prepare("SELECT COUNT(*) AS c FROM payments WHERE user_id = ?")
    .get(req.user.id).c;
  const items = database
    .prepare(
      "SELECT * FROM payments WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
    )
    .all(req.user.id, pageSize, offset);
  res.json({ page, pageSize, total, items });
});

app.get("/api/member/withdrawals", requireAuth, (req, res) => {
  const { page, pageSize } = req.query;
  res.json(backend.listWithdrawals(req.user.id, page, pageSize));
});

app.post("/api/member/withdrawals", requireAuth, (req, res) => {
  const { amountKobo } = req.body || {};
  const result = backend.requestWithdrawal(
    req.user.id,
    amountKobo,
    req.ip,
    req.get("user-agent"),
  );
  if (result.error) return res.status(400).json({ error: result.error });
  res.status(201).json({ ok: true, withdrawalId: result.withdrawalId });
});

app.get("/api/member/notifications", requireAuth, (req, res) => {
  const database = backend.getDb();
  const items = database
    .prepare(
      "SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 50",
    )
    .all(req.user.id);
  const unread = database
    .prepare(
      "SELECT COUNT(*) AS c FROM notifications WHERE user_id = ? AND read = 0",
    )
    .get(req.user.id).c;
  res.json({ items, unread });
});

app.post("/api/member/notifications/read", requireAuth, (req, res) => {
  backend
    .getDb()
    .prepare("UPDATE notifications SET read = 1 WHERE user_id = ?")
    .run(req.user.id);
  res.json({ ok: true });
});

app.post("/api/member/profile", requireAuth, (req, res) => {
  const { fullName, email, payoutPhone } = req.body || {};
  const database = backend.getDb();
  const updates = [];
  const params = [];
  if (fullName) {
    updates.push("full_name = ?");
    params.push(String(fullName).trim());
  }
  if (email) {
    if (!backend.validateEmail(email))
      return res.status(400).json({ error: "Invalid email" });
    updates.push("email = ?");
    params.push(String(email).toLowerCase());
  }
  if (payoutPhone) {
    const normalized = backend.normalizePhone(payoutPhone);
    if (!normalized)
      return res.status(400).json({ error: "Invalid M-Pesa number" });
    updates.push("payout_phone = ?");
    params.push(normalized);
  }
  if (updates.length === 0)
    return res.status(400).json({ error: "No changes provided" });
  updates.push("updated_at = datetime('now')");
  params.push(req.user.id);
  try {
    database
      .prepare(`UPDATE users SET ${updates.join(", ")} WHERE id = ?`)
      .run(...params);
    backend.audit(
      req.user.id,
      req.user.role,
      "profile.update",
      "user",
      req.user.id,
      req.ip,
      req.get("user-agent"),
      req.body,
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ error: "Update failed: " + e.message });
  }
});

// ============================================================================
// PAYMENTS — PalPluss
// ============================================================================
app.post("/api/payments/charge", requireAuth, async (req, res) => {
  const { phone } = req.body || {};
  try {
    const result = await backend.chargeMpesa(
      req.user.id,
      phone,
      req.ip,
      req.get("user-agent"),
    );
    if (result.error) return res.status(400).json({ error: result.error });
    res.json(result);
  } catch (e) {
    console.error("[payments/charge]", e);
    res.status(500).json({ error: "Charge failed" });
  }
});

/**
 * Webhook endpoint for PalPluss.
 * Both STK Push and B2C payout results arrive here.
 * Return 2xx immediately; processing is synchronous but lightweight.
 */
app.post("/api/webhooks/palpluss", (req, res) => {
  try {
    const result = backend.handlePalPlussWebhook(
      req.body,
      req.ip,
      req.get("user-agent"),
    );
    res.status(200).json({ ok: true, ...result });
  } catch (e) {
    console.error("[palpluss webhook]", e);
    res.status(200).json({ ok: true }); // PalPluss retries on non-2xx; still return 200 to avoid spam
  }
});

/**
 * Poll a payment by its PalPluss transaction ID (frontend polling).
 */
app.get("/api/payments/verify/:reference", requireAuth, async (req, res) => {
  const ref = req.params.reference;
  const database = backend.getDb();
  const payment = database
    .prepare(
      `SELECT * FROM payments WHERE provider_reference = ? AND user_id = ? LIMIT 1`,
    )
    .get(ref, req.user.id);

  if (!payment) return res.status(404).json({ error: "Payment not found" });

  if (payment.status === "success")
    return res.json({ status: "success", alreadyProcessed: true });
  if (payment.status === "failed" || payment.status === "abandoned")
    return res.json({ status: payment.status, error: payment.failure_reason });

  // Optionally query PalPluss for a fresher status (webhook may be delayed)
  try {
    const tx = await palpluss.getTransaction(ref);
    if (tx.status === "SUCCESS") {
      const verifiedData = {
        reference: tx.transactionId,
        amount: String(Math.round(Number(tx.amount) * 100)),
        currency: tx.currency || "KES",
        status: "success",
        channel: "mobile_money",
        fees: Math.round(Number(tx.transactionFee || 0) * 100),
        metadata: {
          payment_id: payment.id,
          internal_reference: payment.internal_reference,
          user_id: payment.user_id,
          mpesa_receipt: tx.mpesaReceipt,
        },
      };
      const result = backend.processSuccessfulPayment(
        verifiedData,
        req.ip,
        req.get("user-agent"),
      );
      if (result.error) return res.status(400).json({ error: result.error });
      return res.json({ ...result, status: "success" });
    }
    if (
      tx.status === "FAILED" ||
      tx.status === "EXPIRED" ||
      tx.status === "CANCELLED"
    ) {
      return res.json({ status: "failed", error: tx.resultDesc || tx.status });
    }
  } catch (e) {
    // Ignore — return pending so the frontend keeps polling
  }

  return res.json({ status: "pending", pending: true });
});

// ============================================================================
// ADMIN
// ============================================================================
app.get("/api/admin/overview", requireAdmin, (req, res) =>
  res.json(backend.adminOverview()),
);
app.get("/api/admin/users", requireAdmin, (req, res) =>
  res.json(backend.adminListUsers(req.query)),
);
app.get("/api/admin/users/:id", requireAdmin, (req, res) => {
  const data = backend.adminUserDetail(req.params.id);
  if (!data) return res.status(404).json({ error: "User not found" });
  res.json(data);
});
app.post("/api/admin/users/:id/status", requireAdmin, (req, res) => {
  const { status, reason } = req.body || {};
  const result = backend.adminSetUserStatus(
    req.params.id,
    status,
    reason,
    req.user.id,
    req.ip,
    req.get("user-agent"),
  );
  if (result.error) return res.status(400).json({ error: result.error });
  res.json({ ok: true });
});
app.get("/api/admin/payments", requireAdmin, (req, res) =>
  res.json(backend.adminListPayments(req.query)),
);
app.get("/api/admin/commissions", requireAdmin, (req, res) =>
  res.json(backend.adminListCommissions(req.query)),
);
app.get("/api/admin/withdrawals", requireAdmin, (req, res) =>
  res.json(backend.adminListWithdrawals(req.query)),
);

app.post("/api/admin/withdrawals/process", requireAdmin, async (req, res) => {
  try {
    res.json(
      await backend.processPayouts(req.user.id, req.ip, req.get("user-agent")),
    );
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/admin/withdrawals/:id/reconcile", requireAdmin, async (req, res) => {
  try {
    const database = backend.getDb();
    const w = database
      .prepare("SELECT * FROM withdrawals WHERE id = ?")
      .get(req.params.id);
    if (!w) return res.status(404).json({ error: "Withdrawal not found" });
    if (!w.provider_transfer_code)
      return res
        .status(400)
        .json({ error: "No provider transfer code to reconcile" });

    const tx = await palpluss.getTransaction(w.provider_transfer_code);
    if (tx.status === "SUCCESS") {
      backend.finalizePayoutSuccess(
        w,
        tx,
        req.user.id,
        req.ip,
        req.get("user-agent"),
      );
      return res.json({ ok: true, status: "paid" });
    }
    if (["FAILED", "EXPIRED", "CANCELLED"].includes(tx.status)) {
      backend.finalizePayoutFailure(
        w,
        tx.resultDesc || tx.status,
        tx,
        req.user.id,
        req.ip,
        req.get("user-agent"),
      );
      return res.json({ ok: true, status: "failed" });
    }
    return res.json({ ok: true, status: "pending", providerStatus: tx.status });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/api/admin/audit", requireAdmin, (req, res) =>
  res.json(backend.adminListAudit(req.query)),
);
app.get("/api/admin/settings", requireAdmin, (req, res) =>
  res.json({ items: backend.adminListSettings() }),
);
app.post("/api/admin/settings", requireAdmin, (req, res) => {
  const { key, value } = req.body || {};
  if (!key) return res.status(400).json({ error: "Missing key" });
  const result = backend.adminUpdateSetting(
    key,
    value,
    req.user.id,
    req.ip,
    req.get("user-agent"),
  );
  if (result.error) return res.status(400).json({ error: result.error });
  res.json({ ok: true });
});
app.get("/api/admin/reconciliation", requireAdmin, (req, res) =>
  res.json(backend.adminListReconciliation()),
);
app.post("/api/admin/reconciliation/run", requireAdmin, async (req, res) => {
  try {
    res.json(
      await backend.runReconciliation(
        req.user.id,
        req.ip,
        req.get("user-agent"),
      ),
    );
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ============================================================================
// FALLBACKS
// ============================================================================
app.get("/", (req, res) => res.sendFile(path.join(PUBLIC_DIR, "index.html")));
app.get("/admin", (req, res) =>
  res.sendFile(path.join(PUBLIC_DIR, "admin.html")),
);
app.get("/account", (req, res) =>
  res.sendFile(path.join(PUBLIC_DIR, "account.html")),
);

// ============================================================================
// ERRORS
// ============================================================================
app.use((err, req, res, next) => {
  console.error("[error]", err);
  if (res.headersSent) return next(err);
  res.status(500).json({ error: "Internal server error" });
});

// ============================================================================
// BOOT
// ============================================================================
async function boot() {
  await backend.bootstrap();
  app.listen(PORT, () => {
    console.log(`\n✅ Referal Kenya running at http://localhost:${PORT}`);
    console.log(`   Environment: ${backend.CONFIG.nodeEnv}`);
    console.log(`   PalPluss: ${Boolean(process.env.PALPLUSS_API_KEY)}`);
    console.log(`   Turso: ${backend.CONFIG.turso.enabled}`);
    console.log(
      `   Admin login: ${backend.CONFIG.admin.email || "(not seeded)"}\n`,
    );
  });
}

if (require.main === module) {
  boot().catch((e) => {
    console.error("Boot failed:", e);
    process.exit(1);
  });
}

module.exports = app;
