'use strict';
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { mkdtempSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const { DatabaseSync } = require('node:sqlite');
const { createApp, createKey, startServer } = require('../src/server');
const { openStore } = require('../src/storage');

test('PKCS1 BLOBs and IDs persist across restarts', () => {
  const dir = mkdtempSync(join(tmpdir(), 'jwks-'));
  const path = join(dir, 'totally_not_my_privateKeys.db');
  try {
    const first = createApp({ dbPath: path });
    const now = Math.floor(Date.now() / 1000);
    const original = first.store.valid(now)[0];
    first.close();
    const second = createApp({ dbPath: path });
    assert.equal(second.store.valid(now)[0].kid, original.kid);
    assert.deepEqual(second.store.valid(now)[0].publicKey.export({ format: 'jwk' }), original.publicKey.export({ format: 'jwk' }));
    second.close();
    const db = new DatabaseSync(path);
    assert.equal(db.prepare('SELECT count(*) AS n FROM keys').get().n, 2);
    const row = db.prepare('SELECT key, typeof(key) AS type FROM keys LIMIT 1').get();
    assert.equal(row.type, 'blob');
    assert.match(Buffer.from(row.key).toString(), /BEGIN RSA PRIVATE KEY/);
    db.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('expiry boundary and all valid rows', () => {
  const store = openStore(':memory:');
  try {
    assert.equal(store.select(false, 100), undefined);
    for (const exp of [100, 101, 102]) {
      const key = createKey();
      key.expiresAt = exp;
      store.insert(key);
    }
    assert.equal(store.select(true, 100).expiresAt, 100);
    assert.equal(store.select(false, 100).expiresAt, 102);
    assert.equal(store.valid(100).length, 2);
  } finally { store.close(); }
});

test('missing signing key returns 503', () => {
  const app = createApp({ dbPath: ':memory:' });
  app.store.select = () => undefined;
  let status;
  app.handler({ url: '/auth', headers: {}, method: 'POST' }, {
    writeHead(code) { status = code; },
    end(data) { assert.match(JSON.parse(data).error, /No matching/); },
  });
  assert.equal(status, 503);
  app.close();
});

test('server lifecycle', async () => {
  const server = startServer(0, { dbPath: ':memory:' });
  await new Promise((resolve) => server.on('listening', resolve));
  await new Promise((resolve) => server.close(resolve));
});
