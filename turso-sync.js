// turso-sync.js
// FK-aware, ordered, idempotent, deferring sync between local SQLite and Turso.
"use strict";

const crypto = require("crypto");

// ---------------------------------------------------------------------------
// Table push order — PARENTS BEFORE CHILDREN.
// ---------------------------------------------------------------------------
const PUSH_ORDER = [
  "settings",
  "users",
  "membership",
  "payments",
  "webhook_events",
  "ledger_entries",
  "commissions",
  "withdrawals",
  "payout_transfers",
  "referral_clicks",
  "audit_logs",
  "notifications",
  "reconciliation_runs",
  "reconciliation_exceptions",
  "terms_acceptances",
];

// Per-table primary key column. Defaults to "id" if not listed.
const PK_COLUMN = {
  settings: "key",
};

function pkOf(table) {
  return PK_COLUMN[table] || "id";
}

// Child table -> parent FK column(s). Used to skip rows whose parent is
// not yet present on Turso.
const FK_PARENT = {
  membership: [{ table: "users", col: "user_id" }],
  payments: [{ table: "users", col: "user_id" }],
  terms_acceptances: [{ table: "users", col: "user_id" }],
  referral_clicks: [{ table: "users", col: "referrer_user_id" }],
  ledger_entries: [{ table: "users", col: "user_id" }],
  commissions: [
    { table: "users", col: "beneficiary_user_id" },
    { table: "users", col: "source_user_id" },
  ],
  withdrawals: [{ table: "users", col: "user_id" }],
  notifications: [{ table: "users", col: "user_id" }],
  audit_logs: [{ table: "users", col: "actor_user_id" }],
  payout_transfers: [{ table: "withdrawals", col: "withdrawal_id" }],
  reconciliation_exceptions: [{ table: "reconciliation_runs", col: "run_id" }],
};

// Tables pulled from Turso -> local (parents first).
const PULL_ORDER = [
  "settings",
  "users",
  "membership",
  "payments",
  "webhook_events",
  "ledger_entries",
  "commissions",
  "withdrawals",
  "payout_transfers",
  "referral_clicks",
  "audit_logs",
  "notifications",
  "reconciliation_runs",
  "reconciliation_exceptions",
  "terms_acceptances",
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function tableHasColumn(db, table, col) {
  try {
    const cols = db.prepare(`PRAGMA table_info(${quoteIdent(table)})`).all();
    return cols.some((c) => c.name === col);
  } catch {
    return false;
  }
}

function quoteIdent(name) {
  return `"${String(name).replace(/"/g, '""')}"`;
}

function hashRow(row) {
  const ordered = {};
  Object.keys(row)
    .sort()
    .forEach((k) => (ordered[k] = row[k]));
  return crypto
    .createHash("sha1")
    .update(JSON.stringify(ordered))
    .digest("hex");
}

function selectPending(db, table, cursor) {
  if (tableHasColumn(db, table, "dirty")) {
    return db
      .prepare(`SELECT * FROM ${quoteIdent(table)} WHERE dirty = 1`)
      .all();
  }
  if (cursor && cursor[table] && tableHasColumn(db, table, "updated_at")) {
    return db
      .prepare(`SELECT * FROM ${quoteIdent(table)} WHERE updated_at > ?`)
      .all(cursor[table]);
  }
  return db.prepare(`SELECT * FROM ${quoteIdent(table)}`).all();
}

function markClean(db, table, pkValue) {
  if (tableHasColumn(db, table, "dirty")) {
    const pk = pkOf(table);
    db.prepare(
      `UPDATE ${quoteIdent(table)} SET dirty = 0 WHERE ${quoteIdent(pk)} = ?`,
    ).run(pkValue);
  }
}

// Build an idempotent upsert statement for `table` based on its PK column.
function buildUpsert(table, row) {
  const pk = pkOf(table);
  const cols = Object.keys(row);
  const placeholders = cols.map(() => "?").join(", ");
  const updates = cols
    .filter((c) => c !== pk)
    .map((c) => `${quoteIdent(c)} = excluded.${quoteIdent(c)}`)
    .join(", ");

  const sql =
    `INSERT INTO ${quoteIdent(table)} (${cols.map(quoteIdent).join(", ")}) ` +
    `VALUES (${placeholders}) ` +
    (updates
      ? `ON CONFLICT(${quoteIdent(pk)}) DO UPDATE SET ${updates}`
      : `ON CONFLICT(${quoteIdent(pk)}) DO NOTHING`);
  return { sql, args: cols.map((c) => row[c]) };
}

async function upsertRemote(turso, table, row) {
  const { sql, args } = buildUpsert(table, row);
  await turso.execute({ sql, args });
}

// ---------------------------------------------------------------------------
// PUSH  (local -> Turso)
// ---------------------------------------------------------------------------
async function pushAll(db, turso, opts = {}) {
  const log = opts.log || console.log;
  const warn = opts.warn || console.warn;
  const cursor = opts.cursor || null;

  let written = 0;
  let errors = 0;
  const deferred = [];

  // Cache of user ids known to be on Turso (kept up-to-date as we push).
  const remoteUserIds = new Set();
  try {
    const res = await turso.execute("SELECT id FROM users");
    for (const r of res.rows) remoteUserIds.add(r.id);
  } catch (e) {
    warn("[turso] could not preload remote user ids:", e.message);
  }

  // Cache for other parent tables we care about (withdrawals, runs).
  const remoteParentIds = new Map(); // table -> Set
  async function parentSet(table) {
    if (!remoteParentIds.has(table)) {
      const s = new Set();
      try {
        const r = await turso.execute(
          `SELECT ${quoteIdent(pkOf(table))} AS pk FROM ${quoteIdent(table)}`,
        );
        for (const row of r.rows) s.add(row.pk);
      } catch (_) {}
      remoteParentIds.set(table, s);
    }
    return remoteParentIds.get(table);
  }

  for (const table of PUSH_ORDER) {
    let rows;
    try {
      rows = selectPending(db, table, cursor);
    } catch (e) {
      warn(`[turso] could not read local ${table}:`, e.message);
      continue;
    }
    if (!rows.length) continue;

    for (const row of rows) {
      const fks = FK_PARENT[table] || [];
      let missingParent = false;
      for (const fk of fks) {
        let has;
        if (fk.table === "users") {
          has = remoteUserIds.has(row[fk.col]);
        } else {
          const set = await parentSet(fk.table);
          has = set.has(row[fk.col]);
        }
        if (!has) {
          missingParent = true;
          break;
        }
      }

      if (missingParent) {
        deferred.push({ table, row });
        continue;
      }

      try {
        await upsertRemote(turso, table, row);
        markClean(db, table, row[pkOf(table)]);
        written++;
        if (table === "users") remoteUserIds.add(row.id);
        if (remoteParentIds.has(table))
          remoteParentIds.get(table).add(row[pkOf(table)]);
      } catch (e) {
        errors++;
        warn(`[turso] push ${table} row failed: ${e.message}`);
      }
    }
  }

  // Second pass: retry deferred rows now that parents exist.
  const stillDeferred = [];
  for (const { table, row } of deferred) {
    const fks = FK_PARENT[table] || [];
    let missingParent = false;
    for (const fk of fks) {
      let has;
      if (fk.table === "users") {
        has = remoteUserIds.has(row[fk.col]);
      } else {
        const set = await parentSet(fk.table);
        has = set.has(row[fk.col]);
      }
      if (!has) {
        missingParent = true;
        break;
      }
    }
    if (missingParent) {
      stillDeferred.push({ table, row });
      continue;
    }
    try {
      await upsertRemote(turso, table, row);
      markClean(db, table, row[pkOf(table)]);
      written++;
    } catch (e) {
      errors++;
      warn(`[turso] retry ${table} row failed: ${e.message}`);
    }
  }

  log(
    `[turso] pushed ${written} rows (${errors} errors, ${stillDeferred.length} deferred)`,
  );

  if (stillDeferred.length) {
    const summary = stillDeferred
      .map((d) => {
        const pk = d.row[pkOf(d.table)];
        return `${d.table}#${pk}`;
      })
      .join(", ");
    warn(`[turso] deferred orphans: ${summary}`);
  }

  return { written, errors, deferred: stillDeferred.length };
}

// ---------------------------------------------------------------------------
// PULL  (Turso -> local)
// ---------------------------------------------------------------------------
async function pullAll(db, turso, opts = {}) {
  const log = opts.log || console.log;
  const warn = opts.warn || console.warn;
  let pulled = 0;

  for (const table of PULL_ORDER) {
    let res;
    try {
      res = await turso.execute(`SELECT * FROM ${quoteIdent(table)}`);
    } catch (e) {
      warn(`[turso] pull ${table} failed:`, e.message);
      continue;
    }
    if (!res.rows.length) continue;

    const pk = pkOf(table);
    const stmtCache = new Map();

    const tx = db.transaction((rows) => {
      for (const r of rows) {
        const cols = Object.keys(r);
        const key = cols.join("|");
        let stmt = stmtCache.get(key);
        if (!stmt) {
          const placeholders = cols.map(() => "?").join(", ");
          const updates = cols
            .filter((c) => c !== pk)
            .map((c) => `${quoteIdent(c)} = excluded.${quoteIdent(c)}`)
            .join(", ");
          const sql =
            `INSERT INTO ${quoteIdent(table)} (${cols.map(quoteIdent).join(", ")}) ` +
            `VALUES (${placeholders}) ` +
            (updates
              ? `ON CONFLICT(${quoteIdent(pk)}) DO UPDATE SET ${updates}`
              : `ON CONFLICT(${quoteIdent(pk)}) DO NOTHING`);
          stmt = db.prepare(sql);
          stmtCache.set(key, stmt);
        }
        stmt.run(...cols.map((c) => r[c]));
      }
    });

    try {
      tx(res.rows);
      pulled += res.rows.length;
    } catch (e) {
      warn(`[turso] pull ${table} apply failed:`, e.message);
    }
  }

  log(`[turso] pulled ${pulled} rows`);
  return { pulled };
}

// ---------------------------------------------------------------------------
// BOOT SYNC
// ---------------------------------------------------------------------------
async function bootSync(db, turso, opts = {}) {
  const log = opts.log || console.log;
  const warn = opts.warn || console.warn;
  const env = opts.env || process.env.NODE_ENV || "development";

  // 1. Ensure Turso schema (caller-supplied so it can reuse backend's SCHEMA_SQL)
  let created = false;
  let reason = "schema_exists";
  let schemaErrors = 0;
  try {
    if (typeof opts.ensureRemoteSchema === "function") {
      const r = await opts.ensureRemoteSchema();
      created = !!r.created;
      reason = r.reason || reason;
      schemaErrors = r.errors || 0;
    }
  } catch (e) {
    warn("[turso] schema check failed:", e.message);
  }
  log(
    `[turso] schema: created=${created}, reason=${reason}, errors=${schemaErrors}`,
  );

  const localCount = db.prepare("SELECT COUNT(*) AS n FROM users").get().n;
  let remoteCount = 0;
  try {
    const r = await turso.execute("SELECT COUNT(*) AS n FROM users");
    remoteCount = Number(r.rows[0]?.n || 0);
  } catch (e) {
    warn("[turso] remote count failed:", e.message);
  }

  log(`[turso] boot: local=${localCount}, turso=${remoteCount}, env=${env}`);

  let pulled = 0;
  let pushResult = { written: 0, errors: 0, deferred: 0 };

  // 2. Pull decision
  const shouldPull =
    (env === "production" && remoteCount > 0) ||
    (env !== "production" && localCount === 0 && remoteCount > 0);

  if (shouldPull) {
    log(`[turso] pull: pulling from Turso (${remoteCount} users on remote)…`);
    const prevFK = db.pragma("foreign_keys", { simple: true });
    db.pragma("foreign_keys = OFF");
    try {
      const p = await pullAll(db, turso, { log, warn });
      pulled = p.pulled;
      log(`[turso] pull: restored=true, rows=${pulled}`);
    } finally {
      db.pragma(`foreign_keys = ${prevFK ? "ON" : "OFF"}`);
    }
  } else {
    log(`[turso] boot: skipping pull (env=${env})`);
  }

  // 3. Push (FK-aware, ordered)
  pushResult = await pushAll(db, turso, { log, warn });

  log(
    `[turso] boot sync complete — schema=${schemaErrors ? "error" : "ok"}, ` +
      `pulled=${pulled}, pushed=${pushResult.written}, ` +
      `deferred=${pushResult.deferred}, errors=${pushResult.errors}`,
  );

  return {
    pulled: { restored: pulled > 0, rows: pulled },
    pushed: pushResult.written,
    deferred: pushResult.deferred,
    errors: pushResult.errors,
    schema: { created, reason, errors: schemaErrors },
  };
}

module.exports = {
  PUSH_ORDER,
  PULL_ORDER,
  FK_PARENT,
  PK_COLUMN,
  pkOf,
  pushAll,
  pullAll,
  bootSync,
  hashRow,
};
