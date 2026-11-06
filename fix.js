// fix-orphans.js  — run ONCE, then delete this file.
"use strict";
const path = require("path");
require("dotenv").config();
const Database = require("better-sqlite3");

const DB_PATH =
  process.env.DATABASE_URL && process.env.DATABASE_URL.startsWith("file:")
    ? process.env.DATABASE_URL.replace("file:", "")
    : path.join(__dirname, "data", "referal.db");

const db = new Database(DB_PATH);

console.log("--- orphan scan ---");
const orphans = db
  .prepare(
    `SELECT 'membership' AS tbl, id, user_id FROM membership
       WHERE user_id NOT IN (SELECT id FROM users)
     UNION ALL
     SELECT 'terms_acceptances', id, user_id FROM terms_acceptances
       WHERE user_id NOT IN (SELECT id FROM users)`,
  )
  .all();

if (!orphans.length) {
  console.log("No orphans. Nothing to do.");
  process.exit(0);
}
console.table(orphans);

// The FK constraint will also fail on Turso if these children reference a
// user that exists locally but was never pushed (e.g. a dirty=0 user). The
// simplest safe fix is to delete the orphan children; their parent user will
// still be pushed on the next boot if it's actually a live user.
for (const uid of new Set(orphans.map((o) => o.user_id))) {
  db.prepare("DELETE FROM membership        WHERE user_id = ?").run(uid);
  db.prepare("DELETE FROM terms_acceptances WHERE user_id = ?").run(uid);
  console.log(`deleted orphan children for user_id=${uid}`);
}
console.log("--- done — restart server ---");
