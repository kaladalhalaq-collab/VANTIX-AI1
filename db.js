const Database = require('better-sqlite3');
const db = new Database(process.env.DB_PATH || './vantix.db');
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user',
  plan TEXT NOT NULL DEFAULT 'free',
  plan_expires TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS codes(
  code TEXT PRIMARY KEY,
  plan TEXT NOT NULL,
  days INTEGER NOT NULL,
  used_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
  used_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS analyses(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  market TEXT, timeframe TEXT, style TEXT,
  result TEXT, tokens_in INTEGER DEFAULT 0, tokens_out INTEGER DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS chats(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role TEXT NOT NULL, content TEXT NOT NULL,
  tokens_in INTEGER DEFAULT 0, tokens_out INTEGER DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS trades(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  market TEXT NOT NULL, side TEXT NOT NULL, entry REAL NOT NULL,
  exit_price REAL, pnl REAL, status TEXT NOT NULL DEFAULT 'open',
  created_at TEXT NOT NULL DEFAULT (datetime('now')), closed_at TEXT
);
CREATE TABLE IF NOT EXISTS watchlist(
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  market TEXT NOT NULL, PRIMARY KEY(user_id, market)
);
CREATE TABLE IF NOT EXISTS lessons(
  id INTEGER PRIMARY KEY AUTOINCREMENT, level TEXT NOT NULL,
  title TEXT NOT NULL, body TEXT, media_url TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS news(
  id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, body TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS notifications(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, -- NULL = للجميع
  title TEXT NOT NULL, body TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS signals(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  market TEXT NOT NULL, timeframe TEXT NOT NULL, price REAL,
  result TEXT NOT NULL, tokens_in INTEGER DEFAULT 0, tokens_out INTEGER DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS ix_sig ON signals(market, id);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_an_user ON analyses(user_id, created_at);
CREATE INDEX IF NOT EXISTS ix_chat_user ON chats(user_id, created_at);
`);

// ترحيل: إضافة أعمدة الملف الشخصي دون المساس بالبيانات الموجودة
const have = db.prepare('PRAGMA table_info(users)').all().map(c => c.name);
for (const [n, t] of [['full_name', 'TEXT'], ['phone', 'TEXT'], ['username', 'TEXT'], ['avatar', 'BLOB'], ['avatar_type', 'TEXT'],
  ['points', 'INTEGER NOT NULL DEFAULT 0'], ['email_verified', 'INTEGER NOT NULL DEFAULT 0'], ['pwd_at', 'TEXT']])
  if (!have.includes(n)) db.exec(`ALTER TABLE users ADD COLUMN ${n} ${t}`);
db.exec('CREATE UNIQUE INDEX IF NOT EXISTS ux_username ON users(username)');

const defaults = {
  analyses_free: 3, analyses_pro: 100, analyses_vip: 500, // لكل شهر
  chat_free: 10, chat_pro: 100, chat_vip: 500,             // لكل يوم
  price_in_per_m: 3, price_out_per_m: 15                   // دولار لكل مليون توكن (لتقدير التكلفة)
};
const ins = db.prepare('INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)');
for (const [k, v] of Object.entries(defaults)) ins.run(k, String(v));

db.setting = k => Number(db.prepare('SELECT value FROM settings WHERE key=?').get(k)?.value);
db.defaultSettingKeys = Object.keys(defaults);
module.exports = db;
