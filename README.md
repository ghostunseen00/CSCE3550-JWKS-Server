# CSCE 3550 Project 2 — SQLite JWKS Server

Author: Gerald Cofie  
Course: CSCE 3550 — Foundations of Cybersecurity

## Setup
Install Node.js 22.13 or newer (Node.js 24 LTS recommended). No external packages are needed. From the project folder run:

```text
npm start
```

The server listens on http://localhost:8080 and creates `totally_not_my_privateKeys.db` in the current working directory.

## API
- `GET /.well-known/jwks.json`: public JWKs for every database key with exp greater than the current Unix timestamp.
- `POST /auth`: RS256 JWT signed with an unexpired database key.
- `POST /auth?expired`: JWT signed with an expired database key. Parameter presence triggers this even for `expired=false`.

Authentication is mocked. Basic auth and JSON credentials are accepted without verification; the subject is `userABC`. Unsupported methods return 405; unknown paths return 404; unavailable signing keys return 503.

## Storage and SQL safety
The exact required schema is created on startup:

```sql
CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
);
```

RSA private keys are stored as PKCS1 PEM BLOBs. Database IDs become string JWT/JWK kid values. All inserted and queried values use bound parameters. No request input is interpolated into SQL. Public responses never contain private key fields.

Startup preserves stored keys and adds an expired key if absent and a new key if none remains valid for at least another hour. New valid keys last two hours. Each request reads from SQLite; JWT expiration equals the selected key expiration. The database is local development data and is excluded from Git.

## Tests
```text
npm test
npm run coverage
npm run lint
```

Tests cover signatures, Basic/JSON mock requests, expired query presence, HTTP methods, persistence across restarts, PKCS1 BLOB storage, multiple valid keys, expiry boundary, and unavailable keys. Coverage enforces more than 80% for lines, branches, and functions. `lint` currently performs Node syntax checks on all source/test files.

Verified on Node.js 24.19.0: 13 tests passed; line coverage 98.82%, branch coverage 97.30%, function coverage 100%. See `coverage-output.txt` for actual output.

## Gradebot and submission evidence
Run the instructor-provided test client with its `project2` command from this project directory while the server runs in a second terminal. Both must use this directory so the client can access the database. Use the instructor's documented executable/flags; the client is not included here and has not been run for this update.

Before capturing screenshots in Windows Command Prompt, print:
```text
echo Gerald Cofie - CSCE 3550 - Project 2
```

Add real screenshots to `screenshots/`:
- `gradebot-project2.png`: Gradebot rubric table and awarded points with identification visible.
- `coverage-project2.png`: `npm run coverage` output with identification visible.

Do not reuse Project 1 evidence. Old screenshots are retained under `screenshots/project1/` only as historical evidence. Project 2 is not submission-ready until the new screenshots and official test are completed. Submit the github.com repository URL in Canvas.

## AI acknowledgement
OpenAI ChatGPT assisted with the SQLite extension, tests, and documentation. Gerald Cofie should review and understand the implementation before submission.
