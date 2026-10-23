'use strict';

const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

const DB_NAME = 'totally_not_my_privateKeys.db';

function deserialize(row) {
  if (!row) return undefined;
  const privateKey = crypto.createPrivateKey(Buffer.from(row.key));
  return {
    kid: String(row.kid),
    expiresAt: Number(row.exp),
    privateKey,
    publicKey: crypto.createPublicKey(privateKey),
  };
}

function openStore(path = DB_NAME) {
  const db = new DatabaseSync(path);
  db.exec(`CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
  )`);
  // SQL structure is fixed; all values are bound separately as parameters.
  const insert = db.prepare('INSERT INTO keys (key, exp) VALUES (?, ?)');
  const valid = db.prepare('SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY kid');
  const unexpired = db.prepare('SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY exp DESC, kid LIMIT 1');
  const expired = db.prepare('SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY exp DESC, kid LIMIT 1');
  return {
    insert(key) {
      const pem = key.privateKey.export({ type: 'pkcs1', format: 'pem' });
      return String(insert.run(Buffer.from(pem), key.expiresAt).lastInsertRowid);
    },
    select(isExpired, now) {
      return deserialize((isExpired ? expired : unexpired).get(now));
    },
    valid(now) {
      return valid.all(now).map(deserialize);
    },
    close() { db.close(); },
  };
}

module.exports = { openStore, DB_NAME };
