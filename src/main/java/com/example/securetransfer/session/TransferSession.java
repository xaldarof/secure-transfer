package com.example.securetransfer.session;

import java.security.MessageDigest;
import java.time.Instant;
import org.springframework.web.socket.WebSocketSession;

/**
 * In-memory state of one transfer. All mutating operations are synchronized on the instance,
 * which makes every state transition atomic with respect to the participant slots.
 *
 * <p>The server stores only {@code receiverVerifier = SHA-256(joinToken)}, where joinToken is
 * HKDF-derived in the browser from the transfer key with its own label. It reveals nothing about the
 * encryption or MAC keys, and lets the server refuse receivers who only know the session ID.
 */
public final class TransferSession {

    private final String id;
    private final byte[] receiverVerifier;
    private final Instant expiresAt;

    private SessionState state = SessionState.CREATED;
    private WebSocketSession sender;
    private WebSocketSession receiver;
    private boolean receiverReadySent;

    TransferSession(String id, byte[] receiverVerifier, Instant expiresAt) {
        this.id = id;
        this.receiverVerifier = receiverVerifier.clone();
        this.expiresAt = expiresAt;
    }

    public String id() { return id; }

    public Instant expiresAt() { return expiresAt; }

    public synchronized SessionState state() { return state; }

    public synchronized WebSocketSession participant(Role role) {
        return role == Role.SENDER ? sender : receiver;
    }

    public synchronized Role roleOf(WebSocketSession ws) {
        if (ws == null) return null;
        if (sender != null && sender.getId().equals(ws.getId())) return Role.SENDER;
        if (receiver != null && receiver.getId().equals(ws.getId())) return Role.RECEIVER;
        return null;
    }

    /** CREATED -> WAITING, attaching the sender. */
    synchronized boolean attachSender(WebSocketSession ws) {
        if (state != SessionState.CREATED || sender != null) return false;
        sender = ws;
        state = SessionState.WAITING;
        return true;
    }

    /**
     * WAITING -> CONNECTED, attaching the receiver if its token matches. Constant-time comparison.
     */
    public synchronized JoinResult attachReceiver(WebSocketSession ws, byte[] tokenHash) {
        if (!MessageDigest.isEqual(receiverVerifier, tokenHash)) return JoinResult.UNAUTHORIZED;
        if (state != SessionState.WAITING || receiver != null) return JoinResult.FULL;
        receiver = ws;
        receiverReadySent = false;
        state = SessionState.CONNECTED;
        return JoinResult.OK;
    }

    /** Receiver may announce itself (authenticated READY) once per connection, before transfer. */
    public synchronized boolean markReady(WebSocketSession ws) {
        if (state != SessionState.CONNECTED || roleOf(ws) != Role.RECEIVER || receiverReadySent) return false;
        receiverReadySent = true;
        return true;
    }

    /** CONNECTED -> TRANSFERRING. At most one secret per session. */
    public synchronized boolean beginTransfer(WebSocketSession ws) {
        if (state != SessionState.CONNECTED || roleOf(ws) != Role.SENDER || !receiverReadySent) return false;
        state = SessionState.TRANSFERRING;
        return true;
    }

    /** TRANSFERRING -> COMPLETED. Only the authorized receiver connection may acknowledge. */
    public synchronized boolean complete(WebSocketSession ws) {
        if (state != SessionState.TRANSFERRING || roleOf(ws) != Role.RECEIVER) return false;
        state = SessionState.COMPLETED;
        return true;
    }

    /** Receiver dropped before any secret was sent: CONNECTED -> WAITING so it may rejoin. */
    public synchronized boolean detachReceiverBeforeTransfer(WebSocketSession ws) {
        if (state != SessionState.CONNECTED || roleOf(ws) != Role.RECEIVER) return false;
        receiver = null;
        receiverReadySent = false;
        state = SessionState.WAITING;
        return true;
    }

    /** Moves a non-terminal session to EXPIRED. */
    synchronized boolean expire() {
        if (state.isTerminal()) return false;
        state = SessionState.EXPIRED;
        return true;
    }

    /** Moves a non-terminal session to CLOSED (cancel / participant left). Blocks further joins. */
    public synchronized boolean close() {
        if (state.isTerminal()) return false;
        state = SessionState.CLOSED;
        return true;
    }

    public enum JoinResult { OK, UNAUTHORIZED, FULL }
}
