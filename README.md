# Secret Transfer: ephemeral E2EE secret handoff

A small, anonymous service for handing one secret (an API key, password, token or short message) from one browser to another **in real time**. The secret is encrypted in the sender's browser and decrypted in the receiver's browser. The server only relays ciphertext, stores nothing on disk, and forgets the session as soon as it ends.

- No accounts, no database, no message history, no queues, no cookies, no third-party scripts or fonts.
- Java 21, Spring Boot 3, raw Spring WebSocket. The frontend is vanilla JS using the native Web Crypto API, with no dependencies.
- One transfer per link. Links expire after 5 minutes.

---

## 1. Overview

```
Sender browser                       Server (blind relay, RAM only)            Receiver browser
──────────────                       ──────────────────────────────            ────────────────
types secret
generates sessionId + key K
link = /t/{sessionId}#k=K  ───────── shared out-of-band (chat, etc.) ─────────▶ opens link
                                                                               reads K from #fragment,
                                                                               strips it from address bar
JOIN(sender, verifier) ─────────────▶ creates session (WAITING)
                                      ◀───────────── JOIN(receiver, token) ──── 
                                      checks SHA-256(token)==verifier
                                      (CONNECTED)
          ◀──────────────── READY(nonce, HMAC_recv) ◀──────────────────────────
verifies HMAC → "Receiver connected"
[Send Secret]
ENCRYPTED_MESSAGE(AES-GCM) ────────▶ relays once (TRANSFERRING) ─────────────▶ decrypts + verifies
          ◀──────────────── ACK(HMAC_recv over transfer) ◀──────────────────── shows secret
verifies ACK → "Transfer completed"   COMPLETED → closes both, deletes session
```

## 2. Architecture

```
src/main/java/com/example/securetransfer
├── SecureTransferApplication.java
├── config/      WebSocketConfig (endpoint, origin allowlist, size/idle limits),
│                SecurityConfig (CSP + security headers), AppProperties, ClockConfig
├── websocket/   TransferWebSocketHandler (blind relay, role and state enforcement, expiry, pings)
├── session/     TransferSession (atomic state machine), SessionManager (ConcurrentHashMap), SessionState, Role
├── protocol/    TransferMessage (strict JSON schema), ProtocolException
├── security/    RateLimiter, RateLimitHandshakeInterceptor
├── web/         PageController (/, /t/{id}, /health)
└── exception/   TransferExceptionHandler (generic errors, no leakage)

src/main/resources/static
├── index.html   all screens (home, waiting, connected, sending, receiving, received, notice)
├── css/style.css
└── js/crypto.js key derivation, AES-GCM, HMAC, sender/receiver protocol state machines
    js/app.js    UI controller
```

**Endpoints**

| Endpoint | Purpose |
|---|---|
| `GET /` | Sender page |
| `GET /t/{sessionId}` | Receiver page (same HTML; the key stays in the fragment, so the server never sees it) |
| `GET /health` | `{"status":"UP"}` |
| `WS /ws/transfer/{sessionId}` | Relay channel |

No extra registration endpoint is needed. The sender's first WebSocket message (`JOIN`, role `sender`) creates the session and registers the receiver verifier in one atomic step.

### Session states

`CREATED → WAITING → CONNECTED → TRANSFERRING → COMPLETED`, plus `EXPIRED` (TTL elapsed) and `CLOSED` (cancelled or a participant left, delivery not confirmed). `CLOSED` is an addition to the specified state list, so an unconfirmed transfer is never reported as `COMPLETED` or `EXPIRED`.

- `CONNECTED → WAITING` happens only when the receiver disconnects **before** anything was sent, so the receiver can reopen the link.
- Every transition is a `synchronized` compare-and-set on the session, so two receivers racing for the slot can never both win (this is tested).
- The server lets the sender send `ENCRYPTED_MESSAGE` only after the receiver's `READY`, and only once. Only the authorized receiver connection can move the session to `COMPLETED`.

## 3. How the end-to-end encryption works

All cryptography runs in the browser through `crypto.subtle`. There are no custom primitives.

1. **Keys.** The sender generates a random 128-bit `sessionId` and a random 256-bit master key `K` (`crypto.getRandomValues`).
2. **Key separation (HKDF-SHA-256).** The salt is `"st1/session/" + sessionId`. Each derived value has its own `info` label:

   | Label | Output | Used for |
   |---|---|---|
   | `st1/aes-256-gcm/sender-to-receiver` | AES-256-GCM key | encrypting the secret |
   | `st1/hmac/sender` | HMAC-SHA-256 key | sender's `CANCEL` |
   | `st1/hmac/receiver` | HMAC-SHA-256 key | receiver's `READY`, `ACK`, `CANCEL` |
   | `st1/join-token/receiver` | 256-bit token | proving to the server that the receiver holds the link |

   All derived CryptoKeys are non-extractable.
3. **Server authorization without the key.** The sender registers `verifier = SHA-256(joinToken)`. The receiver presents `joinToken`, and the server compares hashes in constant time. The token comes from `K` through a one-way HKDF with its own label, so it reveals nothing about `K` or the encryption and MAC keys. Knowing only the session ID is not enough to join.
4. **Freshness.** The receiver sends `READY{nonce, mac}`, where `mac = HMAC_recv(["st1", sid, "receiver", "READY", nonce])`. The sender shows "Receiver connected" only after this verifies. A server notice alone is never trusted for that.
5. **Encryption.** `ENCRYPTED_MESSAGE{transferId, iv, ct}` uses AES-256-GCM with a fresh random 96-bit IV and a 128-bit tag. The AAD is `["st1", sid, "sender", "ENCRYPTED_MESSAGE", transferId, receiverNonce]`. Any change to the ciphertext, IV, transfer ID, session, role or nonce makes decryption fail.
6. **Authenticated acknowledgment.** Only after successful decryption does the receiver send `ACK{transferId, mac}`, with `mac = HMAC_recv(["st1", sid, "receiver", "ACK", transferId, SHA-256(iv.ct), receiverNonce])`. The sender shows "Transfer completed" only if the MAC verifies against the exact ciphertext it sent.
7. **Replay protection.**
   - Across sessions: keys differ per session, because `K` and the salt are both fresh.
   - Within a session: the server relays one secret. The receiver decrypts at most one message and fails closed afterwards. The sender accepts one `ACK`, bound to its own random `transferId`, its ciphertext digest and the receiver's nonce.
   - Message contexts are JSON arrays of strings, which gives an unambiguous encoding and keeps one message type from being passed off as another (a `READY` MAC is not a valid `ACK` MAC).

**Wire protocol.** All fields are base64url without padding. The server rejects unknown fields, wrong types and wrong lengths.

| Message | Direction | Trust |
|---|---|---|
| `JOIN {role:"sender", verifier}` / `JOIN {role:"receiver", token}` | client → server | server-validated |
| `READY {nonce, mac}` | receiver → sender | **end-to-end authenticated** (HMAC) |
| `ENCRYPTED_MESSAGE {transferId, iv, ct}` | sender → receiver | **end-to-end authenticated encryption** (AES-GCM) |
| `ACK {transferId, mac}` | receiver → sender | **end-to-end authenticated** (HMAC) |
| `CANCEL {mac}` | either → peer | server acts on it for the authorized socket; peer verifies the HMAC |
| `STATUS {state, peer, expiresIn}` | server → client | **untrusted relay notice**, used only for UI hints |
| `ERROR {code}` | server → client | untrusted relay notice |

The server re-serializes relayed messages from validated fields only, so a client cannot smuggle extra fields through it.

## 4. Running locally

```bash
docker compose up --build
# open http://localhost:8080 in two browsers (or one normal + one private window)
```

Without Docker (needs JDK 21 and Maven):

```bash
mvn spring-boot:run
```

`navigator.clipboard` and Web Crypto need a secure context. `http://localhost` qualifies, but a LAN IP over plain HTTP does not. Use HTTPS when testing from a phone.

### Tests

```bash
mvn test              # 52 Java unit + WebSocket integration tests
npm test              # 15 crypto/protocol tests on Node >= 18 (runs the shipped crypto.js; no npm deps)
mvn verify -Pfull     # all of the above + real-browser E2E (Playwright/Chromium)
```

The first `-Pfull` run downloads Chromium. On a bare Linux host, install the browser's system libraries once:

```bash
mvn -Pfull exec:java -Dexec.mainClass=com.microsoft.playwright.CLI -Dexec.classpathScope=test -Dexec.args="install --with-deps chromium"
```

| Requirement | Where it is tested |
|---|---|
| AES-256-GCM encrypt/decrypt, unique IVs, non-extractable keys | `crypto.test.mjs` |
| Incorrect key | `crypto.test.mjs`, `BrowserTransferIT.wrongKeyInLinkCannotJoin` |
| Modified or truncated ciphertext, IV, transfer ID | `crypto.test.mjs` |
| Replayed messages (in-session, cross-session, stale nonce, replayed ACK) | `crypto.test.mjs`, `TransferWebSocketIntegrationTest.replayedEncryptedMessageRejected`, `SessionManagerTest` |
| Forged acknowledgments | `crypto.test.mjs`, `TransferWebSocketIntegrationTest.forgedAckFromWrongRoleOrStateIsIgnored` |
| Unauthorized participants and session-ID-only attackers | `TransferWebSocketIntegrationTest.sessionIdAloneDoesNotAuthorizeReceiver`, `unjoinedSocketCannotSendProtocolMessages` |
| Third participant rejection | `TransferWebSocketIntegrationTest.thirdParticipantRejected`, `SessionManagerTest` |
| Session expiration and cleanup, join timeout | `SessionLimitsTest`, `SessionManagerTest.sessionsExpireAndAreSwept` |
| Concurrency (receiver race, create race) | `SessionManagerTest`, `TransferWebSocketIntegrationTest.concurrentReceiverAttemptsExactlyOneWins` |
| Receiver disconnect (before and during transfer), sender disconnect | `TransferWebSocketIntegrationTest` |
| Sender cancellation | `TransferWebSocketIntegrationTest.senderCancellation` |
| Oversized and malformed payloads | `TransferWebSocketIntegrationTest`, `TransferMessageTest` |
| Origin allowlist, rate limiting | `TransferWebSocketIntegrationTest`, `RateLimitTest` |
| Successful one-time transfer, single-use link | `TransferWebSocketIntegrationTest`, `BrowserTransferIT` |
| **Server never receives plaintext or key** | `BrowserTransferIT`: two real Chromium contexts (one mobile) do a full transfer while the server records every HTTP request line and header and every inbound WebSocket frame. The test asserts that neither the secret nor the key appears in raw, hex, base64 or base64url form. It also checks for no storage or cookies, no CSP violations, and no horizontal overflow on mobile. |

## 5. Deploying

Browser-delivered E2EE is only as trustworthy as the page delivery, so **always serve over HTTPS** in production. Run the app behind a TLS-terminating reverse proxy:

1. Set the environment (see `.env.example`):
   ```bash
   APP_ALLOWED_ORIGINS=https://secrets.example.com
   SERVER_FORWARD_HEADERS_STRATEGY=native   # only behind a trusted proxy
   HOST_BIND=127.0.0.1                      # app reachable only via the proxy
   ```
2. `docker compose up -d --build`
3. Put a proxy in front:
   - **Caddy** (automatic certificates): `deploy/Caddyfile`
   - **nginx**: `deploy/nginx.conf`. It must forward `Upgrade`/`Connection` headers for WSS, set `proxy_read_timeout` above the session TTL (the server also pings every 20 s), **overwrite** `X-Forwarded-For` and turn access logs off.
4. The page connects with `wss://` automatically when it is served over `https://`. The CSP `connect-src` is built from `APP_ALLOWED_ORIGINS`, and HSTS is sent on HTTPS requests.

**Scaling:** sessions live in one JVM's memory. Run a **single instance**, or use sticky routing by `sessionId` path. There is deliberately no Redis or other shared store.

**Hardening in place:**
- **CSP:** `default-src 'none'`, `script-src 'self'`, `style-src 'self'`, `connect-src 'self' <ws origins>`, `frame-ancestors 'none'`, `base-uri 'none'`, `form-action 'none'`. No inline script or style.
- **Headers:** `Referrer-Policy: no-referrer`, `Cache-Control: no-store`, `X-Frame-Options: DENY`, COOP, CORP, `Permissions-Policy`.
- **Container:** non-root user, read-only filesystem, all capabilities dropped, `no-new-privileges`, core dumps disabled, heap dumps and the attach API disabled.
- **WebSocket:** exact origin allowlist (HTTP 403 otherwise), 64 KB frame limit (close code 1009), 10 s join timeout, idle timeout, per-IP limits on connections and session creation, a global session cap, and strict schema validation (close code 1008).
- **Logging and errors:** no payloads or session IDs are logged, and error responses are generic.

## 6. Security assumptions

- The sender and receiver use an up-to-date browser with a working CSPRNG and Web Crypto.
- The link is shared over a channel that only the intended receiver can read.
- The server operator and the TLS layer deliver the genuine JavaScript (see the threat model below).
- The endpoints (devices) are not compromised.

## 7. Threat model

| Adversary | Protected? | Notes |
|---|---|---|
| Network eavesdropper | ✅ | TLS, plus the payload is E2E-encrypted inside it. |
| Honest-but-curious server / relay operator, logs, memory dumps | ✅ | The server sees only ciphertext, the join token and verifier, and HMAC tags. It never gets `K`, the AES key or the MAC keys, and cannot decrypt (section 10). |
| Active malicious relay that tampers with, replays, reorders or injects messages | ✅ integrity / ⚠️ availability | AES-GCM with bound AAD and HMAC-authenticated READY and ACK detect any tampering. A forged ACK can't produce "Transfer completed". The relay can always drop messages or close the connection (denial of service), which shows up as **"Delivery not confirmed"**. |
| Someone who knows only the session ID (from proxy logs, a shoulder glance, etc.) | ✅ | Can't join (no join token), can't take the sender role (session already exists), and can't ack, cancel or close (unjoined sockets are rejected). |
| Third party joining after the receiver | ✅ | Two-participant limit enforced atomically. |
| Anyone who has the **complete link**, including the `#k=` part | ❌ by design | **The full link is a bearer secret.** Whoever opens it first gets the secret. If an attacker wins the race, the intended receiver sees "Someone else has already opened this link", and you should rotate the secret. |
| **Compromised or malicious web server, or a compromised TLS certificate or CDN** | ❌ | **Browser-delivered E2EE cannot protect against a malicious code-delivery endpoint.** Whoever controls the server can serve modified JavaScript that reads the secret or the fragment key before encryption. E2EE here protects against a relay that is passive or tampers with messages, *not* against the party that supplies the code. Mitigations: self-host, pin a reviewed build, serve only over HTTPS with HSTS, and audit the three static files (`index.html`, `app.js`, `crypto.js`). |
| Malicious browser extensions, malware, screen capture, clipboard managers | ❌ | Out of scope: these run with page or OS privileges. |

## 8. Known limitations

- **Both parties must be online at the same time.** Nothing is queued for a disconnected receiver.
- **Reloading the receiver page loses the key** (the fragment is removed from the address bar on load). Ask the sender for a new link, or reopen the original link if the transfer hasn't happened yet.
- **Message length is not hidden.** The ciphertext reveals the approximate size of the secret. The secret is limited to 32 KB.
- **No guaranteed erasure.** JavaScript strings, browser memory, the OS clipboard and the Java heap can't be reliably zeroed. Deleting the server-side session drops references so the GC can reclaim memory, but it does **not** securely erase data from the receiver's device or the JVM heap. Clearing buffers in the code is best-effort only.
- **The origin check is a browser control.** Non-browser clients can send any `Origin` header. The join token, not the origin, is what authorizes a participant.
- **Rate limits are per process and per IP.** Use an edge rate limiter or WAF for serious abuse resistance. The limiter trusts `X-Forwarded-For` only when `SERVER_FORWARD_HEADERS_STRATEGY=native`.
- **No key confirmation by the sender of *who* the receiver is,** only that the receiver holds the link. Identity rests entirely on how the link was shared.
- **Single node.** There is no horizontal scaling without sticky routing.

## 9. How sessions expire

- Every session has a hard deadline of `APP_SESSION_TTL` (default **5 minutes**) from creation. A background sweep runs every second: it moves expired sessions to `EXPIRED`, sends both peers `STATUS EXPIRED`, closes them with code `4408` and removes the session from the map. Lookups also treat sessions past their deadline as gone, even before the sweep runs.
- After a successful `ACK` the session moves to `COMPLETED`, is removed from the map, and both sockets close with code `1000`. The link can't be used again.
- After a cancel, a sender disconnect, or a receiver disconnect during transfer, the session moves to `CLOSED`, is removed, and the peer is notified (`4410` / `4411`). The sender then sees **"Delivery not confirmed"** unless a valid ACK had already been verified.
- Sockets that don't send `JOIN` within `APP_JOIN_TIMEOUT` (10 s) are closed.

## 10. Why the server cannot decrypt the ciphertext in normal operation

- The key `K` exists only in the URL **fragment** (`#k=…`). Browsers never send fragments in HTTP requests, `Referer` headers or WebSocket handshakes, and `Referrer-Policy: no-referrer` is set as well. The browser E2E test verifies that neither `K` nor the plaintext appears in any request or frame the server receives.
- The server receives `SHA-256(joinToken)` from the sender and `joinToken` from the receiver. Both are outputs of HKDF under the `st1/join-token/receiver` label. HKDF output is one-way and the labels are independent, so these values give no information about `K` or about the AES-GCM and HMAC keys, which come from different labels. A brute-force attack would face a 256-bit key space.
- The AES-GCM and HMAC keys are derived in the browser as non-extractable CryptoKeys and never serialized.
- The ciphertext is therefore AES-256-GCM output under a key the server has never seen. Decrypting it without the key is infeasible under standard assumptions.

"Normal operation" means the server is serving the genuine frontend code. Section 7 explains why a malicious code-serving server is outside what browser E2EE can defend against.
