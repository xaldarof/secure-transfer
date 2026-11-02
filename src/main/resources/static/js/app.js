// UI controller. All cryptography lives in crypto.js. Server STATUS/ERROR messages are treated as
// untrusted hints; "Receiver connected" and "Transfer completed" are shown only after verifying
// messages authenticated with keys the server never sees.
//
// Secrets and keys are kept only in JS memory: never in localStorage, sessionStorage, cookies or IndexedDB.

import {
  MAX_SECRET_BYTES, SESSION_ID_RE, ReceiverProtocol, SenderProtocol,
  b64uEncode, deriveTransferKeys, newMasterKey, newSessionId, parseFragment,
} from './crypto.js';

const $ = (id) => document.getElementById(id);
const te = new TextEncoder();

// ---------------------------------------------------------------- UI helpers

function show(screen) {
  for (const el of document.querySelectorAll('[data-screen]')) el.hidden = el.dataset.screen !== screen;
}

const NOTICE_TONES = { ok: ['ok', 'dot-ok'], warn: ['warn', 'dot-warn'], bad: ['bad', 'dot-bad'] };

function notice({ tone = 'warn', label, title, text, newButton = true }) {
  stopCountdown();
  const [cls, dot] = NOTICE_TONES[tone];
  $('notice-status').className = `status ${cls}`;
  $('notice-dot').className = `dot ${dot}`;
  $('notice-label').textContent = label;
  $('notice-title').textContent = title;
  $('notice-text').textContent = text;
  $('notice-new').hidden = !newButton;
  show('notice');
}

let toastTimer;
function toast(msg) {
  const t = $('toast');
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.hidden = true; }, 1800);
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    // Fallback for browsers without async clipboard permission.
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    let ok = false;
    try { ok = document.execCommand('copy'); } catch { ok = false; }
    ta.value = '';
    ta.remove();
    return ok;
  }
}

let countdownTimer = null;
let deadline = 0;
function startCountdown(expiresInSeconds, onExpire) {
  deadline = Date.now() + expiresInSeconds * 1000;
  stopCountdown();
  const tick = () => {
    const left = Math.max(0, Math.round((deadline - Date.now()) / 1000));
    const txt = `${Math.floor(left / 60)}:${String(left % 60).padStart(2, '0')}`;
    for (const id of ['countdown-waiting', 'countdown-connected']) $(id).textContent = txt;
    if (left === 0) { stopCountdown(); onExpire(); }
  };
  tick();
  countdownTimer = setInterval(tick, 1000);
}
function stopCountdown() {
  if (countdownTimer) clearInterval(countdownTimer);
  countdownTimer = null;
}

function wsUrl(sessionId) {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${proto}//${location.host}/ws/transfer/${sessionId}`;
}

function parse(data) {
  try {
    const m = JSON.parse(data);
    return m && typeof m === 'object' && typeof m.type === 'string' ? m : null;
  } catch { return null; }
}

const ERROR_TEXT = {
  UNAUTHORIZED: 'This link is not valid for this transfer.',
  NOT_FOUND: 'This transfer does not exist. It may have been completed, cancelled or expired.',
  SESSION_FULL: 'Someone else has already opened this link. If that was not you, the link may be compromised.',
  SESSION_EXISTS: 'Session collision. Please create a new transfer.',
  RATE_LIMITED: 'Too many attempts. Please wait a minute and try again.',
  CAPACITY: 'The service is busy. Please try again shortly.',
  TOO_LARGE: 'The message is too large.',
};

function expiredNotice() {
  notice({ tone: 'warn', label: 'Expired', title: 'Session expired',
    text: 'Transfers are available for 5 minutes. Nothing was delivered. Create a new transfer to try again.' });
}

// ---------------------------------------------------------------- sender

function initSender() {
  show('home');
  const secretEl = $('secret');
  const sizeEl = $('secret-size');
  const errEl = $('home-error');

  secretEl.addEventListener('input', () => {
    const n = te.encode(secretEl.value).length;
    sizeEl.textContent = n >= 1024 ? `${(n / 1024).toFixed(1)} KB` : `${n} B`;
    sizeEl.classList.toggle('error', n > MAX_SECRET_BYTES);
  });

  $('create-btn').addEventListener('click', async () => {
    errEl.hidden = true;
    const bytes = te.encode(secretEl.value).length;
    if (!secretEl.value.trim()) { errEl.textContent = 'Enter a secret first.'; errEl.hidden = false; return; }
    if (bytes > MAX_SECRET_BYTES) { errEl.textContent = 'Secret is larger than 32 KB.'; errEl.hidden = false; return; }
    if (!globalThis.crypto?.subtle) {
      errEl.textContent = 'Web Crypto is unavailable. Use a modern browser over HTTPS.'; errEl.hidden = false; return;
    }
    $('create-btn').disabled = true;
    try {
      await startSenderSession(secretEl);
    } catch {
      $('create-btn').disabled = false;
      errEl.textContent = 'Could not create transfer.';
      errEl.hidden = false;
    }
  });
}

async function startSenderSession(secretEl) {
  const sessionId = newSessionId();
  const master = newMasterKey();
  const keys = await deriveTransferKeys(master, sessionId);
  const link = `${location.origin}/t/${sessionId}#k=${b64uEncode(master)}`;
  master.fill(0);
  const proto = new SenderProtocol(keys);
  // Locked in at link creation so the behaviour can't change while the link is out.
  const autoSend = $('auto-send').checked;

  let finished = false;
  const finish = (opts) => { finished = true; notice(opts); try { ws.close(); } catch { /* ignore */ } };

  $('share-link').textContent = link;
  $('copy-link-btn').onclick = async () => toast((await copyText(link)) ? 'Link copied' : 'Copy failed — select the link manually');
  if (navigator.share) {
    $('share-btn').hidden = false;
    $('share-btn').onclick = () => navigator.share({ url: link }).catch(() => {});
  }
  $('waiting-label').textContent = 'Connecting…';
  $('waiting-help').textContent = autoSend
    ? 'Keep this tab open. Auto-send is on: the secret is encrypted and sent as soon as the receiver opens the link.'
    : 'Keep this tab open. The secret stays on your device until the receiver connects and you press send.';
  show('waiting');

  const ws = new WebSocket(wsUrl(sessionId));
  ws.onopen = () => ws.send(JSON.stringify(proto.joinMessage()));

  const cancel = async () => {
    try { ws.send(JSON.stringify(await proto.cancelMessage())); } catch { /* ignore */ }
    secretEl.value = '';
    finish({ tone: 'warn', label: 'Cancelled', title: 'Transfer cancelled', text: 'Nothing was sent. The link no longer works.' });
  };
  $('cancel-waiting-btn').onclick = cancel;
  $('cancel-connected-btn').onclick = cancel;

  let sending = false;
  const send = async () => {
    if (sending || proto.sent || finished) return;
    sending = true;
    $('send-btn').disabled = true;
    try {
      const msg = await proto.seal(secretEl.value);
      ws.send(JSON.stringify(msg));
      secretEl.value = '';
      stopCountdown();
      show('sending');
    } catch {
      sending = false;
      $('send-btn').disabled = false;
      show('connected');
      toast('Could not send');
    }
  };
  $('send-btn').onclick = send;

  ws.onmessage = async (ev) => {
    const m = parse(ev.data);
    if (!m || finished) return;
    switch (m.type) {
      case 'STATUS': // untrusted hint from the relay
        if (typeof m.expiresIn === 'number' && m.expiresIn > 0 && !proto.sent) startCountdown(m.expiresIn, () => {});
        if (m.state === 'WAITING') {
          $('waiting-label').textContent = 'Waiting for receiver';
          if (!proto.sent) show('waiting');
        } else if (m.state === 'CONNECTED') {
          $('waiting-label').textContent = 'Receiver joining — verifying…';
        } else if (m.state === 'EXPIRED') {
          finished = true; expiredNotice();
        }
        break;
      case 'READY':
        // Auto-send fires only after the receiver's READY HMAC verifies, never on a relay STATUS hint.
        if (await proto.acceptReady(m)) {
          if (autoSend) {
            await send();
          } else {
            $('send-btn').disabled = false;
            show('connected');
          }
        }
        break;
      case 'ACK':
        if (await proto.verifyAck(m)) {
          finish({ tone: 'ok', label: 'Transfer completed', title: 'Delivered',
            text: 'The receiver decrypted the secret and returned a signed confirmation. The session has been removed from the server.' });
        } else {
          finish({ tone: 'bad', label: 'Delivery not confirmed', title: 'Invalid acknowledgment',
            text: 'An acknowledgment arrived but failed verification. Assume the secret may not have been delivered to the intended receiver; rotate it if in doubt.' });
        }
        break;
      case 'CANCEL': {
        const verified = await proto.verifyPeerCancel(m);
        finish({ tone: 'warn', label: 'Cancelled', title: 'Receiver cancelled',
          text: proto.sent
            ? `The receiver rejected the message${verified ? '' : ' (unverified notice)'}. Delivery not confirmed.`
            : `The receiver cancelled${verified ? '' : ' (unverified notice)'}. Nothing was sent.` });
        break;
      }
      case 'ERROR':
        if (m.code === 'INVALID_STATE' && !proto.sent) break;
        if (m.code === 'INVALID_STATE') {
          finish({ tone: 'bad', label: 'Delivery not confirmed', title: 'Send rejected',
            text: 'The relay refused the message (the receiver may have disconnected). Nothing was confirmed. Create a new transfer.' });
          break;
        }
        finish({ tone: 'bad', label: 'Error', title: 'Transfer failed', text: ERROR_TEXT[m.code] || 'The transfer could not continue.' });
        break;
      default:
        break;
    }
  };

  ws.onclose = (ev) => {
    if (finished) return;
    finished = true;
    if (proto.acknowledged) return;
    secretEl.value = '';
    if (ev.code === 4408) return expiredNotice();
    if (proto.sent) {
      notice({ tone: 'bad', label: 'Delivery not confirmed', title: 'Delivery not confirmed',
        text: 'The connection closed before the receiver confirmed decryption. The secret may or may not have been read; rotate it if in doubt.' });
    } else {
      notice({ tone: 'warn', label: 'Disconnected', title: 'Connection closed',
        text: 'The session ended before anything was sent. Create a new transfer.' });
    }
  };
}

// ---------------------------------------------------------------- receiver

async function initReceiver(sessionId) {
  // Retain the key in memory, then immediately strip it from the address bar and history entry.
  const master = parseFragment(location.hash);
  history.replaceState(null, '', location.pathname);

  if (!master) {
    notice({ tone: 'bad', label: 'Invalid link', title: 'This link is incomplete',
      text: 'The decryption key (the part after #) is missing or damaged. Ask the sender for the full link. Note: reloading this page removes the key.' });
    return;
  }
  if (!globalThis.crypto?.subtle) {
    notice({ tone: 'bad', label: 'Unsupported', title: 'Browser not supported', text: 'Web Crypto is unavailable. Use a modern browser over HTTPS.' });
    return;
  }
  const keys = await deriveTransferKeys(master, sessionId);
  master.fill(0);
  const proto = new ReceiverProtocol(keys);

  show('receiving');
  let finished = false;
  let plaintext = null;
  let acked = false;
  const finish = (opts) => { finished = true; notice(opts); try { ws.close(); } catch { /* ignore */ } };

  const ws = new WebSocket(wsUrl(sessionId));
  ws.onopen = () => ws.send(JSON.stringify(proto.joinMessage()));

  ws.onmessage = async (ev) => {
    const m = parse(ev.data);
    if (!m || finished) return;
    switch (m.type) {
      case 'STATUS':
        if (m.state === 'CONNECTED' && !proto.consumed) {
          ws.send(JSON.stringify(await proto.readyMessage()));
          $('receiving-label').textContent = 'Connected — waiting for sender';
        } else if (m.state === 'COMPLETED' && acked) {
          $('received-label').textContent = 'Transfer completed';
        } else if (m.state === 'EXPIRED') {
          finish({ tone: 'warn', label: 'Expired', title: 'Session expired', text: 'This transfer expired before a secret was received.', newButton: true });
        }
        break;
      case 'ENCRYPTED_MESSAGE':
        try {
          const res = await proto.open(m);
          plaintext = res.plaintext;
          ws.send(JSON.stringify(res.ack)); // only after successful decryption
          acked = true;
          renderSecret(() => plaintext, () => { plaintext = null; });
        } catch {
          try { ws.send(JSON.stringify(await proto.cancelMessage())); } catch { /* ignore */ }
          finish({ tone: 'bad', label: 'Rejected', title: 'Message failed verification',
            text: 'The encrypted message was modified, replayed, or encrypted with a different key. It was discarded and not acknowledged.' });
        }
        break;
      case 'CANCEL': {
        const verified = await proto.verifyPeerCancel(m);
        finish({ tone: 'warn', label: 'Cancelled', title: 'Sender cancelled the transfer',
          text: verified ? 'Nothing was sent.' : 'The transfer was closed (unverified notice).' });
        break;
      }
      case 'ERROR':
        if (m.code === 'INVALID_STATE') break;
        finish({ tone: 'bad', label: 'Unavailable', title: 'Cannot open transfer', text: ERROR_TEXT[m.code] || 'The transfer could not continue.' });
        break;
      default:
        break;
    }
  };

  ws.onclose = (ev) => {
    if (finished) return;
    finished = true;
    if (acked) {
      $('received-label').textContent = ev.code === 1000 ? 'Transfer completed' : 'Received — confirmation may not have reached sender';
      return;
    }
    if (ev.code === 4408) {
      notice({ tone: 'warn', label: 'Expired', title: 'Session expired', text: 'This transfer expired before a secret was received.' });
    } else {
      notice({ tone: 'warn', label: 'Disconnected', title: 'Connection closed',
        text: 'The sender left or the connection dropped before a secret was received. Ask the sender for a new link.' });
    }
  };
}

function renderSecret(getSecret, wipe) {
  const out = $('secret-out');
  const toggle = $('toggle-secret-btn');
  let visible = false;
  const render = () => {
    const s = getSecret();
    if (s === null) { out.textContent = '(cleared)'; out.classList.add('masked'); return; }
    out.textContent = visible ? s : '•'.repeat(Math.min(Math.max(s.length, 8), 32));
    out.classList.toggle('masked', !visible);
    toggle.textContent = visible ? 'Hide' : 'Show';
    toggle.setAttribute('aria-pressed', String(visible));
  };
  toggle.onclick = () => { visible = !visible; render(); };
  $('copy-secret-btn').onclick = async () => {
    const s = getSecret();
    if (s !== null) toast((await copyText(s)) ? 'Secret copied' : 'Copy failed — use Show and select');
  };
  $('clear-secret-btn').onclick = () => {
    wipe();
    visible = false;
    toggle.disabled = true;
    $('copy-secret-btn').disabled = true;
    render();
  };
  render();
  show('received');
}

// ---------------------------------------------------------------- boot

const match = /^\/t\/([^/]+)$/.exec(location.pathname);
if (match && SESSION_ID_RE.test(match[1])) {
  initReceiver(match[1]).catch(() => notice({ tone: 'bad', label: 'Error', title: 'Something went wrong', text: 'Could not open this transfer.' }));
} else {
  initSender();
}
