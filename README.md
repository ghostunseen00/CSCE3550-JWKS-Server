# CSCE 3550 Project 1 — JWKS Server

Author: Gerald Cofie  
Course: CSCE 3550 — Foundations of Cybersecurity

This Node.js project implements a basic RESTful JWKS server. It generates one valid and one expired 2048-bit RSA key pair, assigns each a unique `kid`, serves only the valid public key, and issues either a valid or expired RS256 JWT.

## Requirements

- Node.js 20 or later
- No third-party packages are required

## Run the server

```bash
npm start
```

The server listens on `http://localhost:8080`.

## Endpoints

| Method | Endpoint | Result |
| --- | --- | --- |
| `GET` | `/.well-known/jwks.json` | Returns unexpired public keys in JWKS format |
| `POST` | `/auth` | Returns a valid signed JWT |
| `POST` | `/auth?expired=true` | Returns an expired JWT signed by the expired key |

Unsupported methods return `405 Method Not Allowed`. Unknown routes return `404 Not Found`.

## Run tests and coverage

```bash
npm test
npm run coverage
npm run lint
```

## Black-box client

1. Download the correct test client for Windows from the release link supplied in Canvas.
2. Open one terminal in this repository and run `npm start`.
3. Open a second terminal and run the downloaded test client against `http://localhost:8080` using its documented command.
4. Capture the full passing output with the identifying-information banner below visible.

## Required screenshots

Before each screenshot, run this in Command Prompt:

```text
echo Gerald Cofie - CSCE 3550 - Project 1
```

Include these image files in the repository:

- `screenshots/blackbox-test.png` — official test client passing against the running server.
- `screenshots/coverage.png` — `npm run coverage` showing coverage above 80%.

Do not submit placeholder screenshots. Add the actual screenshots after running the project on your computer.

## Design notes

- RSA private keys remain server-side and are never included in JWKS output.
- Every JWT header contains the `kid` of the signing key.
- The JWKS endpoint filters keys by expiry time.
- Query-parameter presence triggers the expired-token behavior, as required.
