// Run: node --test src/test/js/
// Exercises the exact module shipped to browsers (src/main/resources/static/js/crypto.js).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';

if (!globalThis.crypto?.subtle) globalThis.crypto = webcrypto;
const C = await import('../../main/resources/static/js/crypto.js');

async function pair({ senderKey, receiverKey, sessionId } = {}) {
  const sid = sessionId ?? C.newSessionId();
  const k = senderKey ?? C.newMasterKey();
  const sender = new C.SenderProtocol(await C.deriveTransferKeys(k, sid));
  const receiver = new C.ReceiverProtocol(await C.deriveTransferKeys(receiverKey ?? k, sid));
  return { sid, k, sender, receiver };
}

async function handshake(sender, receiver) {
  const ready = await receiver.readyMessage();
  assert.equal(await sender.acceptReady(ready), true);
  return ready;
}

function flip(b64u) {
  const bytes = C.b64uDecode(b64u);
  bytes[Math.floor(bytes.length / 2)] ^= 0x01;
  return C.b64uEncode(bytes);
}

test('AES-256-GCM round trip with authenticated ACK (successful one-time transfer)', async () => {
  const { sender, receiver } = await pair();
  await handshake(sender, receiver);
  const msg = await sender.seal('sk_live_🔑_secret');
  assert.equal(C.b64uDecode(msg.iv).length, 12, '96-bit nonce');
  assert.ok(!JSON.stringify(msg).includes('sk_live'), 'no plaintext on the wire');
  const { plaintext, ack } = await receiver.open(msg);
  assert.equal(plaintext, 'sk_live_🔑_secret');
  assert.equal(await sender.verifyAck(ack), true);
  assert.equal(sender.acknowledged, true);
});

test('derived keys are 256-bit AES-GCM, non-extractable, and domain separated', async () => {
  const keys = await C.deriveTransferKeys(C.newMasterKey(), C.newSessionId());
  assert.equal(keys.encKey.algorithm.name, 'AES-GCM');
  assert.equal(keys.encKey.algorithm.length, 256);
  assert.equal(keys.encKey.extractable, false);
  assert.equal(keys.senderMac.extractable, false);
  assert.notEqual(keys.joinToken, keys.joinVerifier);
  // join verifier = SHA-256(join token)
  const h = new Uint8Array(await crypto.subtle.digest('SHA-256', C.b64uDecode(keys.joinToken)));
  assert.equal(C.b64uEncode(h), keys.joinVerifier);
});

test('unique IV per encryption', async () => {
  const ivs = new Set();
  for (let i = 0; i < 50; i++) {
    const { sender, receiver } = await pair();
    await handshake(sender, receiver);
    ivs.add((await sender.seal('x')).iv);
  }
  assert.equal(ivs.size, 50);
});

test('incorrect encryption key is rejected', async () => {
  const { sender, receiver } = await pair({ receiverKey: C.newMasterKey() });
  const ready = await receiver.readyMessage();
  // Sender refuses a READY from someone without the key...
  assert.equal(await sender.acceptReady(ready), false);
  // ...and even a forced ciphertext cannot be decrypted with the wrong key.
  const { sender: s2, receiver: r2 } = await pair();
  await handshake(s2, r2);
  const msg = await s2.seal('top secret');
  await assert.rejects(receiver.open(msg), /authentication failed|not ready/);
});

test('modified ciphertext, IV, transferId are rejected', async () => {
  for (const field of ['ct', 'iv', 'transferId']) {
    const { sender, receiver } = await pair();
    await handshake(sender, receiver);
    const msg = await sender.seal('top secret');
    await assert.rejects(receiver.open({ ...msg, [field]: flip(msg[field]) }), /authentication failed/);
  }
});

test('truncated ciphertext is rejected', async () => {
  const { sender, receiver } = await pair();
  await handshake(sender, receiver);
  const msg = await sender.seal('top secret');
  const bytes = C.b64uDecode(msg.ct);
  await assert.rejects(receiver.open({ ...msg, ct: C.b64uEncode(bytes.slice(0, -1)) }), /authentication failed/);
});

test('replayed ENCRYPTED_MESSAGE is rejected by the receiver', async () => {
  const { sender, receiver } = await pair();
  await handshake(sender, receiver);
  const msg = await sender.seal('once');
  await receiver.open(msg);
  await assert.rejects(receiver.open(msg), /replay rejected/);
});

test('ciphertext replayed into another session (same key) fails: bound to session and receiver nonce', async () => {
  const k = C.newMasterKey();
  const a = await pair({ senderKey: k });
  await handshake(a.sender, a.receiver);
  const msg = await a.sender.seal('bound');
  // Same key, new session ID
  const b = await pair({ senderKey: k });
  await b.receiver.readyMessage();
  await assert.rejects(b.receiver.open(msg), /authentication failed/);
  // Same session, fresh receiver (new nonce): stale ciphertext fails too
  const r3 = new C.ReceiverProtocol(await C.deriveTransferKeys(k, a.sid));
  await r3.readyMessage();
  await assert.rejects(r3.open(msg), /authentication failed/);
});

test('sender seals only once and only after a verified READY', async () => {
  const { sender, receiver } = await pair();
  await assert.rejects(sender.seal('x'), /receiver not verified/);
  await handshake(sender, receiver);
  await sender.seal('x');
  await assert.rejects(sender.seal('x'), /already sent/);
});

test('forged acknowledgments are rejected', async () => {
  const { sender, receiver, sid } = await pair();
  await handshake(sender, receiver);
  const msg = await sender.seal('secret');

  // 1. Random MAC (e.g. forged by the relay)
  assert.equal(await sender.verifyAck({ type: 'ACK', transferId: msg.transferId, mac: C.b64uEncode(C.randomBytes(32)) }), false);
  // 2. ACK from a different key holder
  const other = new C.ReceiverProtocol(await C.deriveTransferKeys(C.newMasterKey(), sid));
  await other.readyMessage();
  // craft via a full transfer on the other key; its ACK must not verify here
  const o = await pair();
  await handshake(o.sender, o.receiver);
  const oAck = (await o.receiver.open(await o.sender.seal('z'))).ack;
  assert.equal(await sender.verifyAck({ ...oAck, transferId: msg.transferId }), false);
  // 3. READY MAC reused as ACK MAC (type confusion)
  const readyLike = await receiver.readyMessage().catch(() => null);
  if (readyLike) assert.equal(await sender.verifyAck({ type: 'ACK', transferId: msg.transferId, mac: readyLike.mac }), false);
  // 4. Malformed MAC
  assert.equal(await sender.verifyAck({ type: 'ACK', transferId: msg.transferId, mac: 'not-base64!' }), false);
  // 5. Wrong transferId
  const { ack } = await receiver.open(msg);
  assert.equal(await sender.verifyAck({ ...ack, transferId: C.b64uEncode(C.randomBytes(16)) }), false);
  // Genuine ACK still accepted exactly once
  assert.equal(await sender.verifyAck(ack), true);
  assert.equal(await sender.verifyAck(ack), false, 'replayed ACK rejected');
});

test('ACK is bound to the exact ciphertext the sender sent', async () => {
  const k = C.newMasterKey();
  const sid = C.newSessionId();
  const s1 = new C.SenderProtocol(await C.deriveTransferKeys(k, sid));
  const r1 = new C.ReceiverProtocol(await C.deriveTransferKeys(k, sid));
  await handshake(s1, r1);
  const m1 = await s1.seal('one');
  // A second sender instance (same key, same receiver nonce) yields a different ciphertext.
  const s2 = new C.SenderProtocol(await C.deriveTransferKeys(k, sid));
  const r2 = new C.ReceiverProtocol(await C.deriveTransferKeys(k, sid));
  const ready2 = await r2.readyMessage();
  await s2.acceptReady(ready2);
  const m2 = await s2.seal('two');
  const ack2 = (await r2.open(m2)).ack;
  assert.equal(await s1.verifyAck({ ...ack2, transferId: m1.transferId }), false);
});

test('forged READY (no key) is rejected', async () => {
  const { sender } = await pair();
  assert.equal(await sender.acceptReady({ type: 'READY', nonce: C.b64uEncode(C.randomBytes(16)), mac: C.b64uEncode(C.randomBytes(32)) }), false);
  assert.equal(await sender.acceptReady({ type: 'READY', nonce: 'short', mac: 'x' }), false);
  assert.equal(sender.receiverVerified, false);
});

test('CANCEL is role-bound and authenticated', async () => {
  const { sender, receiver } = await pair();
  const sc = await sender.cancelMessage();
  const rc = await receiver.cancelMessage();
  assert.equal(await receiver.verifyPeerCancel(sc), true);
  assert.equal(await sender.verifyPeerCancel(rc), true);
  assert.equal(await sender.verifyPeerCancel(sc), false, 'own cancel reflected back is not the peer');
  assert.equal(await receiver.verifyPeerCancel({ type: 'CANCEL', mac: C.b64uEncode(C.randomBytes(32)) }), false);
});

test('oversized and empty secrets are refused before encryption', async () => {
  const { sender, receiver } = await pair();
  await handshake(sender, receiver);
  await assert.rejects(sender.seal(''), /invalid size/);
  await assert.rejects(sender.seal('a'.repeat(C.MAX_SECRET_BYTES + 1)), /invalid size/);
  const max = await sender.seal('a'.repeat(C.MAX_SECRET_BYTES));
  assert.ok(JSON.stringify(max).length < 64 * 1024, 'max secret fits the 64 KB frame limit');
});

test('fragment parsing and strict base64url', () => {
  const k = C.newMasterKey();
  assert.deepEqual(C.parseFragment('#k=' + C.b64uEncode(k)), k);
  assert.equal(C.parseFragment(''), null);
  assert.equal(C.parseFragment('#k=abc'), null);
  assert.equal(C.parseFragment('#x=' + C.b64uEncode(k)), null);
  assert.throws(() => C.b64uDecode('ab+/'), /invalid encoding/);
  assert.throws(() => C.b64uDecode('AB', 1), /invalid encoding/); // non-canonical trailing bits
  assert.throws(() => C.b64uDecode(C.b64uEncode(k), 16), /invalid length/);
});
