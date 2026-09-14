'use strict';

const http = require('node:http');
const crypto = require('node:crypto');

const PORT = Number(process.env.PORT || 8080);
const ISSUER = 'csce3550-jwks-server';

function toBase64Url(value) {
  return Buffer.from(value).toString('base64url');
}

function createKey(expired = false) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicExponent: 0x10001,
  });
  const kid = crypto.randomUUID();
  const now = Math.floor(Date.now() / 1000);
  return {
    kid,
    publicKey,
    privateKey,
    expiresAt: expired ? now - 3600 : now + 3600,
  };
}

function publicJwk(key) {
  const jwk = key.publicKey.export({ format: 'jwk' });
  return {
    kty: 'RSA',
    kid: key.kid,
    use: 'sig',
    alg: 'RS256',
    n: jwk.n,
    e: jwk.e,
  };
}

function signJwt(key, expired = false) {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'RS256', typ: 'JWT', kid: key.kid };
  const payload = {
    sub: 'fake-user',
    iss: ISSUER,
    iat: expired ? now - 7200 : now,
    exp: expired ? key.expiresAt : now + 3600,
  };
  const signingInput = `${toBase64Url(JSON.stringify(header))}.${toBase64Url(JSON.stringify(payload))}`;
  const signature = crypto.sign('RSA-SHA256', Buffer.from(signingInput), key.privateKey);
  return `${signingInput}.${signature.toString('base64url')}`;
}

function sendJson(response, statusCode, body) {
  const data = JSON.stringify(body);
  response.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(data),
  });
  response.end(data);
}

function createApp(options = {}) {
  const validKey = options.validKey || createKey(false);
  const expiredKey = options.expiredKey || createKey(true);

  const handler = (request, response) => {
    const url = new URL(request.url, `http://${request.headers.host || 'localhost'}`);

    if (url.pathname === '/.well-known/jwks.json') {
      if (request.method !== 'GET') {
        sendJson(response, 405, { error: 'Method Not Allowed' });
        return;
      }
      const now = Math.floor(Date.now() / 1000);
      const keys = [validKey, expiredKey]
        .filter((key) => key.expiresAt > now)
        .map(publicJwk);
      sendJson(response, 200, { keys });
      return;
    }

    if (url.pathname === '/auth') {
      if (request.method !== 'POST') {
        sendJson(response, 405, { error: 'Method Not Allowed' });
        return;
      }
      const wantsExpiredToken = url.searchParams.has('expired');
      const selectedKey = wantsExpiredToken ? expiredKey : validKey;
      response.writeHead(200, { 'Content-Type': 'application/jwt' });
      response.end(signJwt(selectedKey, wantsExpiredToken));
      return;
    }

    sendJson(response, 404, { error: 'Not Found' });
  };

  return { handler, validKey, expiredKey };
}

function startServer(port = PORT) {
  const app = createApp();
  const server = http.createServer(app.handler);
  server.listen(port, () => {
    console.log(`JWKS server listening on http://localhost:${port}`);
  });
  return server;
}

if (require.main === module) {
  startServer();
}

module.exports = { createApp, createKey, publicJwk, signJwt, startServer };
