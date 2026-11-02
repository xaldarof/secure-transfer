// Ephemeral E2EE secret transfer — browser cryptography and authenticated protocol.
//
// Uses only the native Web Crypto API. No custom primitives.
//
//   master key K (256 bit, random, lives only in the URL fragment and browser memory)
//   HKDF-SHA256(ikm=K, salt="st1/session/<sessionId>", info=<label>) derives independent keys:
//     "st1/aes-256-gcm/sender-to-receiver" -> AES-256-GCM key (secret payload)
//     "st1/hmac/sender"                    -> HMAC-SHA256 key for sender-authored control messages
//     "st1/hmac/receiver"                  -> HMAC-SHA256 key for receiver-authored messages (READY, ACK)
//     "st1/join-token/receiver"            -> 256-bit join token; server stores only SHA-256(token)
//
// Every authenticated message binds: protocol version, session ID, author role, message type, and
// (where applicable) transfer ID, receiver nonce and ciphertext digest. Replays across sessions fail
// because keys differ per session; replays within a session fail because both ends are single-use.

const subtle = globalThis.crypto.subtle;
const te = new TextEncoder();

export const PROTOCOL = 'st1';
export const MAX_SECRET_BYTES = 32 * 1024;
export const SESSION_ID_RE = /^[A-Za-z0-9_-]{22}$/;

// ---------------------------------------------------------------- encoding

export function b64uEncode(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Strict base64url decode: rejects bad alphabet, non-canonical encodings and wrong lengths. */
export function b64uDecode(str, expectedLength) {
  if (typeof str !== 'string' || !/^[A-Za-z0-9_-]*$/.test(str)) throw new Error('invalid encoding');
  const padded = str.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((str.length + 3) % 4);
  let bin;
  try { bin = atob(padded); } catch { throw new Error('invalid encoding'); }
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  if (b64uEncode(out) !== str) throw new Error('invalid encoding');
  if (expectedLength !== undefined && out.length !== expectedLength) throw new Error('invalid length');
  return out;
}

export function randomBytes(n) {
  return globalThis.crypto.getRandomValues(new Uint8Array(n));
}

export function newSessionId() {
  return b64uEncode(randomBytes(16));
}

export function newMasterKey() {
  return randomBytes(32);
}

/** Canonical, unambiguous byte encoding of a message context (JSON array of strings). */
function context(sessionId, role, type, ...fields) {
  return te.encode(JSON.stringify([PROTOCOL, sessionId, role, type, ...fields]));
}

async function sha256b64u(str) {
  return b64uEncode(new Uint8Array(await subtle.digest('SHA-256', te.encode(str))));
}

async function sign(key, data) {
  return b64uEncode(new Uint8Array(await subtle.sign('HMAC', key, data)));
}

async function verify(key, mac, data) {
  let sig;
  try { sig = b64uDecode(mac, 32); } catch { return false; }
  return subtle.verify('HMAC', key, sig, data); // constant-time inside Web Crypto
}

// ---------------------------------------------------------------- key derivation

export async function deriveTransferKeys(masterKey, sessionId) {
  if (!(masterKey instanceof Uint8Array) || masterKey.length !== 32) throw new Error('invalid key');
  if (!SESSION_ID_RE.test(sessionId)) throw new Error('invalid session');
  const ikm = await subtle.importKey('raw', masterKey, 'HKDF', false, ['deriveKey', 'deriveBits']);
  const salt = te.encode(`${PROTOCOL}/session/${sessionId}`);
  const hkdf = (label) => ({ name: 'HKDF', hash: 'SHA-256', salt, info: te.encode(`${PROTOCOL}/${label}`) });
  const hmac = { name: 'HMAC', hash: 'SHA-256', length: 256 };

  const encKey = await subtle.deriveKey(hkdf('aes-256-gcm/sender-to-receiver'), ikm,
    { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  const senderMac = await subtle.deriveKey(hkdf('hmac/sender'), ikm, hmac, false, ['sign', 'verify']);
  const receiverMac = await subtle.deriveKey(hkdf('hmac/receiver'), ikm, hmac, false, ['sign', 'verify']);
  const token = new Uint8Array(await subtle.deriveBits(hkdf('join-token/receiver'), ikm, 256));
  const verifier = new Uint8Array(await subtle.digest('SHA-256', token));

  return Object.freeze({
    sessionId,
    encKey,
    senderMac,
    receiverMac,
    joinToken: b64uEncode(token),       // sent by receiver to prove possession of the link
    joinVerifier: b64uEncode(verifier), // registered by sender; reveals nothing about K
  });
}

// ---------------------------------------------------------------- protocol roles

export class ProtocolError extends Error {}

/** Sender side. Single use: one READY binding, one secret, one ACK. */
export class SenderProtocol {
  #k; #receiverNonce = null; #sent = null; #acked = false;

  constructor(keys) { this.#k = keys; }

  get receiverVerified() { return this.#receiverNonce !== null; }
  get sent() { return this.#sent !== null; }
  get acknowledged() { return this.#acked; }

  joinMessage() {
    return { type: 'JOIN', role: 'sender', verifier: this.#k.joinVerifier };
  }

  /** Verifies the receiver's authenticated READY (proves the peer holds the link key). */
  async acceptReady(msg) {
    if (this.#sent) return false;
    if (typeof msg?.nonce !== 'string') return false;
    try { b64uDecode(msg.nonce, 16); } catch { return false; }
    const ok = await verify(this.#k.receiverMac, msg.mac,
      context(this.#k.sessionId, 'receiver', 'READY', msg.nonce));
    if (ok) this.#receiverNonce = msg.nonce;
    return ok;
  }

  /** Encrypts the secret with AES-256-GCM, fresh 96-bit IV, AAD bound to session/role/type/transfer/nonce. */
  async seal(plaintext) {
    if (this.#sent) throw new ProtocolError('already sent');
    if (!this.#receiverNonce) throw new ProtocolError('receiver not verified');
    const data = te.encode(plaintext);
    if (data.length === 0 || data.length > MAX_SECRET_BYTES) throw new ProtocolError('invalid size');
    const transferId = b64uEncode(randomBytes(16));
    const ivBytes = randomBytes(12);
    const aad = context(this.#k.sessionId, 'sender', 'ENCRYPTED_MESSAGE', transferId, this.#receiverNonce);
    const ct = new Uint8Array(await subtle.encrypt(
      { name: 'AES-GCM', iv: ivBytes, additionalData: aad, tagLength: 128 }, this.#k.encKey, data));
    data.fill(0); // best effort; JS strings cannot be wiped
    const iv = b64uEncode(ivBytes);
    const ctB64 = b64uEncode(ct);
    this.#sent = { transferId, digest: await sha256b64u(`${iv}.${ctB64}`) };
    return { type: 'ENCRYPTED_MESSAGE', transferId, iv, ct: ctB64 };
  }

  /** Accepts exactly one ACK, which must be bound to this transfer, this ciphertext and this receiver. */
  async verifyAck(msg) {
    if (!this.#sent || this.#acked) return false;
    if (msg?.transferId !== this.#sent.transferId) return false;
    const ok = await verify(this.#k.receiverMac, msg.mac, context(this.#k.sessionId, 'receiver', 'ACK',
      this.#sent.transferId, this.#sent.digest, this.#receiverNonce));
    if (ok) this.#acked = true;
    return ok;
  }

  async cancelMessage() {
    return { type: 'CANCEL', mac: await sign(this.#k.senderMac, context(this.#k.sessionId, 'sender', 'CANCEL')) };
  }

  /** True only if the CANCEL was authored by the receiver (not forged by the relay). */
  async verifyPeerCancel(msg) {
    return verify(this.#k.receiverMac, msg?.mac, context(this.#k.sessionId, 'receiver', 'CANCEL'));
  }
}

/** Receiver side. Single use: decrypts at most one message. */
export class ReceiverProtocol {
  #k; #nonce = null; #consumed = false;

  constructor(keys) { this.#k = keys; }

  get consumed() { return this.#consumed; }

  joinMessage() {
    return { type: 'JOIN', role: 'receiver', token: this.#k.joinToken };
  }

  /**
   * Authenticated READY carrying a fresh nonce that the sender must bind into the ciphertext.
   * The nonce is fixed per receiver instance, so a relay that triggers READY twice cannot
   * desynchronize an in-flight ciphertext.
   */
  async readyMessage() {
    if (this.#consumed) throw new ProtocolError('already received');
    this.#nonce ??= b64uEncode(randomBytes(16));
    const mac = await sign(this.#k.receiverMac, context(this.#k.sessionId, 'receiver', 'READY', this.#nonce));
    return { type: 'READY', nonce: this.#nonce, mac };
  }

  /**
   * Decrypts the one and only secret. Throws on replay, tampering, wrong key or wrong binding.
   * Fails closed: after the first ENCRYPTED_MESSAGE (valid or not) nothing else is accepted.
   * Returns the plaintext and an authenticated ACK to send.
   */
  async open(msg) {
    if (this.#consumed) throw new ProtocolError('replay rejected');
    if (!this.#nonce) throw new ProtocolError('not ready');
    this.#consumed = true;
    let iv, ct;
    try {
      b64uDecode(msg.transferId, 16);
      iv = b64uDecode(msg.iv, 12);
      ct = b64uDecode(msg.ct);
    } catch { throw new ProtocolError('malformed'); }
    const aad = context(this.#k.sessionId, 'sender', 'ENCRYPTED_MESSAGE', msg.transferId, this.#nonce);
    let plainBytes;
    try {
      plainBytes = new Uint8Array(await subtle.decrypt(
        { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, this.#k.encKey, ct));
    } catch {
      throw new ProtocolError('authentication failed');
    }
    let plaintext;
    try { plaintext = new TextDecoder('utf-8', { fatal: true }).decode(plainBytes); }
    finally { plainBytes.fill(0); }
    const digest = await sha256b64u(`${msg.iv}.${msg.ct}`);
    const mac = await sign(this.#k.receiverMac,
      context(this.#k.sessionId, 'receiver', 'ACK', msg.transferId, digest, this.#nonce));
    return { plaintext, ack: { type: 'ACK', transferId: msg.transferId, mac } };
  }

  async cancelMessage() {
    return { type: 'CANCEL', mac: await sign(this.#k.receiverMac, context(this.#k.sessionId, 'receiver', 'CANCEL')) };
  }

  async verifyPeerCancel(msg) {
    return verify(this.#k.senderMac, msg?.mac, context(this.#k.sessionId, 'sender', 'CANCEL'));
  }
}

/** Parses "#k=<base64url 32 bytes>". Returns the key bytes or null. */
export function parseFragment(hash) {
  const m = /^#k=([A-Za-z0-9_-]{43})$/.exec(hash || '');
  if (!m) return null;
  try { return b64uDecode(m[1], 32); } catch { return null; }
}
