'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const http = require('node:http');
const { after, before, describe, test } = require('node:test');
const { createApp, publicJwk, signJwt } = require('../src/server');

let server;
let baseUrl;
let app;

function decodeJwt(token) {
  const [encodedHeader, encodedPayload] = token.split('.');
  return {
    header: JSON.parse(Buffer.from(encodedHeader, 'base64url').toString()),
    payload: JSON.parse(Buffer.from(encodedPayload, 'base64url').toString()),
  };
}

before(async () => {
  app = createApp({ dbPath: ':memory:' });
  app.validKey = app.store.select(false, Math.floor(Date.now() / 1000));
  app.expiredKey = app.store.select(true, Math.floor(Date.now() / 1000));
  server = http.createServer(app.handler);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  await new Promise((resolve) => server.close(resolve));
  app.close();
});

describe('JWKS endpoint', () => {
  test('GET returns only the unexpired public key in JWKS format', async () => {
    const response = await fetch(`${baseUrl}/.well-known/jwks.json`);
    const body = await response.json();
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('content-type'), 'application/json');
    assert.equal(body.keys.length, 1);
    assert.equal(body.keys[0].kid, app.validKey.kid);
    assert.notEqual(body.keys[0].kid, app.expiredKey.kid);
    assert.deepEqual(Object.keys(body.keys[0]).sort(), ['alg', 'e', 'kid', 'kty', 'n', 'use']);
  });

  test('rejects incorrect methods', async () => {
    const response = await fetch(`${baseUrl}/.well-known/jwks.json`, { method: 'POST' });
    assert.equal(response.status, 405);
  });
});

describe('authentication endpoint', () => {
  test('POST returns a valid unexpired RS256 JWT', async () => {
    const response = await fetch(`${baseUrl}/auth`, { method: 'POST' });
    const token = await response.text();
    const { header, payload } = decodeJwt(token);
    assert.equal(response.status, 200);
    assert.equal(header.kid, app.validKey.kid);
    assert.equal(header.alg, 'RS256');
    assert.ok(payload.exp > Math.floor(Date.now() / 1000));
    assert.equal(payload.sub, 'userABC');
    assert.equal(crypto.verify('RSA-SHA256', Buffer.from(token.split('.').slice(0, 2).join('.')), app.validKey.publicKey, Buffer.from(token.split('.')[2], 'base64url')), true);
  });

  test('expired query parameter returns a JWT signed by the expired key', async () => {
    const response = await fetch(`${baseUrl}/auth?expired=true`, { method: 'POST' });
    const token = await response.text();
    const { header, payload } = decodeJwt(token);
    assert.equal(header.kid, app.expiredKey.kid);
    assert.ok(payload.exp < Math.floor(Date.now() / 1000));
  });

  test('rejects incorrect methods', async () => {
    const response = await fetch(`${baseUrl}/auth`);
    assert.equal(response.status, 405);
  });
});

test('unknown paths return 404', async () => {
  const response = await fetch(`${baseUrl}/missing`);
  assert.equal(response.status, 404);
});

test('helper functions expose a public JWK and create signed tokens', () => {
  const jwk = publicJwk(app.validKey);
  const token = signJwt(app.validKey);
  assert.equal(jwk.kty, 'RSA');
  assert.equal(token.split('.').length, 3);
});


test('Basic and JSON mock credentials both return signed tokens', async () => {
  for (const options of [
    { headers: { Authorization: 'Basic ' + Buffer.from('userABC:password123').toString('base64') } },
    { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'userABC', password: 'password123' }) },
  ]) {
    const response = await fetch(`${baseUrl}/auth`, { method: 'POST', ...options });
    assert.equal(response.status, 200);
    assert.equal(decodeJwt(await response.text()).payload.sub, 'userABC');
  }
});

test('expired parameter is triggered by presence, including false and empty', async () => {
  for (const query of ['expired', 'expired=false', 'expired=%27%20OR%201=1--']) {
    const response = await fetch(`${baseUrl}/auth?${query}`, { method: 'POST' });
    assert.equal(decodeJwt(await response.text()).header.kid, app.expiredKey.kid);
  }
  assert.equal(app.store.valid(Math.floor(Date.now() / 1000)).length, 1);
});
