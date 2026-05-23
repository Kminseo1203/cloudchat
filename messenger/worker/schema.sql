-- D1 데이터베이스 스키마
-- wrangler d1 execute messenger-db --file=schema.sql 로 실행

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  public_key TEXT DEFAULT '',
  google_id TEXT UNIQUE,
  email TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS rooms (
  id TEXT PRIMARY KEY,
  name TEXT,
  type TEXT CHECK(type IN ('dm','group')) DEFAULT 'dm',
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS room_members (
  room_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  PRIMARY KEY (room_id, user_id),
  FOREIGN KEY (room_id) REFERENCES rooms(id),
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS messages (
  id TEXT PRIMARY KEY,
  room_id TEXT NOT NULL,
  sender_id TEXT NOT NULL,
  sender_name TEXT,
  type TEXT DEFAULT 'text',
  file_name TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (room_id) REFERENCES rooms(id)
);

CREATE TABLE IF NOT EXISTS message_payloads (
  message_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  encrypted_key TEXT NOT NULL,
  encrypted_body TEXT NOT NULL,
  iv TEXT NOT NULL,
  PRIMARY KEY (message_id, user_id),
  FOREIGN KEY (message_id) REFERENCES messages(id)
);

CREATE INDEX IF NOT EXISTS idx_messages_room ON messages(room_id, created_at);
CREATE INDEX IF NOT EXISTS idx_room_members_user ON room_members(user_id);
