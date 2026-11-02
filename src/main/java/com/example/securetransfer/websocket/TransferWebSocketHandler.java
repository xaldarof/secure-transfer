package com.example.securetransfer.websocket;

import com.example.securetransfer.config.AppProperties;
import com.example.securetransfer.protocol.ProtocolException;
import com.example.securetransfer.protocol.TransferMessage;
import com.example.securetransfer.security.RateLimitHandshakeInterceptor;
import com.example.securetransfer.session.Role;
import com.example.securetransfer.session.SessionManager;
import com.example.securetransfer.session.SessionState;
import com.example.securetransfer.session.TransferSession;
import jakarta.annotation.PreDestroy;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.CloseStatus;
import org.springframework.web.socket.PingMessage;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.handler.ConcurrentWebSocketSessionDecorator;
import org.springframework.web.socket.handler.TextWebSocketHandler;

/**
 * Blind relay between exactly one sender and one receiver. It enforces roles, state transitions, sizes and
 * rate limits; it never sees keys or plaintext, and never logs payloads or session identifiers.
 */
@Component
public class TransferWebSocketHandler extends TextWebSocketHandler {

    private static final Logger log = LoggerFactory.getLogger(TransferWebSocketHandler.class);
    private static final String ATTR_JOINED = "joined";

    // Application close codes (4000-4999 are reserved for applications by RFC 6455).
    public static final CloseStatus CLOSE_COMPLETED = new CloseStatus(1000, "completed");
    public static final CloseStatus CLOSE_UNAUTHORIZED = new CloseStatus(4401, "unauthorized");
    public static final CloseStatus CLOSE_NOT_FOUND = new CloseStatus(4404, "not found");
    public static final CloseStatus CLOSE_EXPIRED = new CloseStatus(4408, "expired");
    public static final CloseStatus CLOSE_FULL = new CloseStatus(4409, "full");
    public static final CloseStatus CLOSE_CANCELLED = new CloseStatus(4410, "cancelled");
    public static final CloseStatus CLOSE_PEER_LEFT = new CloseStatus(4411, "peer left");
    public static final CloseStatus CLOSE_RATE_LIMITED = new CloseStatus(4429, "rate limited");

    private final SessionManager sessions;
    private final RateLimitHandshakeInterceptor limits;
    private final AppProperties props;
    private final Map<String, WebSocketSession> connections = new ConcurrentHashMap<>();
    private final ScheduledExecutorService timers = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "ws-join-timeout");
        t.setDaemon(true);
        return t;
    });

    public TransferWebSocketHandler(SessionManager sessions, RateLimitHandshakeInterceptor limits, AppProperties props) {
        this.sessions = sessions;
        this.limits = limits;
        this.props = props;
    }

    @PreDestroy
    void shutdown() {
        timers.shutdownNow();
    }

    // ------------------------------------------------------------------ lifecycle

    @Override
    public void afterConnectionEstablished(WebSocketSession raw) {
        WebSocketSession ws = new ConcurrentWebSocketSessionDecorator(raw, 10_000, 2 * TransferMessage.MAX_MESSAGE_BYTES);
        if (connections.size() >= props.maxSessions() * 2 + 100) {
            close(ws, CloseStatus.SERVICE_OVERLOAD);
            return;
        }
        connections.put(raw.getId(), ws);
        // Connections that do not complete JOIN quickly are dropped (slot-squatting / resource protection).
        timers.schedule(() -> {
            if (ws.isOpen() && !Boolean.TRUE.equals(ws.getAttributes().get(ATTR_JOINED))) {
                close(ws, CloseStatus.POLICY_VIOLATION);
            }
        }, props.joinTimeout().toMillis(), TimeUnit.MILLISECONDS);
    }

    @Override
    protected void handleTextMessage(WebSocketSession raw, TextMessage message) {
        WebSocketSession ws = connections.get(raw.getId());
        if (ws == null) return;
        String payload = message.getPayload();
        if (payload.length() > TransferMessage.MAX_MESSAGE_BYTES) {
            fail(ws, "TOO_LARGE", CloseStatus.TOO_BIG_TO_PROCESS);
            return;
        }
        TransferMessage m;
        try {
            m = TransferMessage.parseClient(payload);
        } catch (ProtocolException e) {
            fail(ws, e.code(), CloseStatus.POLICY_VIOLATION);
            return;
        }
        String sessionId = (String) ws.getAttributes().get(RateLimitHandshakeInterceptor.ATTR_SESSION_ID);
        boolean joined = Boolean.TRUE.equals(ws.getAttributes().get(ATTR_JOINED));

        if (TransferMessage.JOIN.equals(m.type())) {
            if (joined) fail(ws, "ALREADY_JOINED", CloseStatus.POLICY_VIOLATION);
            else if ("sender".equals(m.role())) joinSender(ws, sessionId, m);
            else joinReceiver(ws, sessionId, m);
            return;
        }
        if (!joined) {
            fail(ws, "JOIN_REQUIRED", CloseStatus.POLICY_VIOLATION);
            return;
        }
        TransferSession s = sessions.find(sessionId).orElse(null);
        Role role = s == null ? null : s.roleOf(ws);
        if (role == null) {
            fail(ws, "NOT_FOUND", CLOSE_NOT_FOUND);
            return;
        }
        switch (m.type()) {
            case TransferMessage.READY -> {
                if (s.markReady(ws)) relay(s, Role.SENDER, m);
                else reject(ws);
            }
            case TransferMessage.ENCRYPTED_MESSAGE -> {
                if (s.beginTransfer(ws)) relay(s, Role.RECEIVER, m);
                else reject(ws);
            }
            case TransferMessage.ACK -> {
                if (s.complete(ws)) {
                    sessions.remove(s);
                    relay(s, Role.SENDER, m);
                    send(ws, TransferMessage.status(SessionState.COMPLETED.name(), true, 0));
                    close(s.participant(Role.SENDER), CLOSE_COMPLETED);
                    close(s.participant(Role.RECEIVER), CLOSE_COMPLETED);
                    log.debug("transfer completed; active sessions={}", sessions.size());
                } else {
                    reject(ws);
                }
            }
            case TransferMessage.CANCEL -> {
                if (s.close()) {
                    sessions.remove(s);
                    relay(s, role.peer(), m);
                    close(s.participant(Role.SENDER), CLOSE_CANCELLED);
                    close(s.participant(Role.RECEIVER), CLOSE_CANCELLED);
                } else {
                    reject(ws);
                }
            }
            default -> fail(ws, "MALFORMED", CloseStatus.POLICY_VIOLATION);
        }
    }

    @Override
    public void afterConnectionClosed(WebSocketSession raw, CloseStatus status) {
        WebSocketSession ws = connections.remove(raw.getId());
        if (ws == null) ws = raw;
        String sessionId = (String) raw.getAttributes().get(RateLimitHandshakeInterceptor.ATTR_SESSION_ID);
        if (sessionId == null) return;
        TransferSession s = sessions.findAny(sessionId).orElse(null);
        if (s == null) return;
        Role role = s.roleOf(ws);
        if (role == null) return;

        if (role == Role.RECEIVER && s.detachReceiverBeforeTransfer(ws)) {
            // Nothing was sent yet; the sender keeps waiting and a receiver may (re)join.
            send(s.participant(Role.SENDER),
                    TransferMessage.status(SessionState.WAITING.name(), false, sessions.secondsRemaining(s)));
            return;
        }
        // Sender left, or receiver left mid-transfer: delivery is NOT confirmed. Tear down.
        if (s.close()) {
            sessions.remove(s);
            WebSocketSession peer = s.participant(role.peer());
            send(peer, TransferMessage.status(SessionState.CLOSED.name(), false, 0));
            close(peer, CLOSE_PEER_LEFT);
        }
    }

    @Override
    public void handleTransportError(WebSocketSession raw, Throwable exception) {
        log.debug("transport error: {}", exception.getClass().getSimpleName());
        WebSocketSession ws = connections.getOrDefault(raw.getId(), raw);
        close(ws, CloseStatus.SERVER_ERROR);
    }

    // ------------------------------------------------------------------ join

    private void joinSender(WebSocketSession ws, String sessionId, TransferMessage m) {
        String ip = (String) ws.getAttributes().get(RateLimitHandshakeInterceptor.ATTR_CLIENT_IP);
        if (!limits.allowSessionCreation(ip)) {
            fail(ws, "RATE_LIMITED", CLOSE_RATE_LIMITED);
            return;
        }
        byte[] verifier = Base64.getUrlDecoder().decode(m.verifier());
        switch (sessions.create(sessionId, verifier, ws)) {
            case OK -> {
                ws.getAttributes().put(ATTR_JOINED, true);
                TransferSession s = sessions.find(sessionId).orElseThrow();
                send(ws, TransferMessage.status(s.state().name(), false, sessions.secondsRemaining(s)));
            }
            case EXISTS -> fail(ws, "SESSION_EXISTS", CLOSE_FULL);
            case CAPACITY -> fail(ws, "CAPACITY", CloseStatus.SERVICE_OVERLOAD);
        }
    }

    private void joinReceiver(WebSocketSession ws, String sessionId, TransferMessage m) {
        TransferSession s = sessions.find(sessionId).orElse(null);
        if (s == null) {
            fail(ws, "NOT_FOUND", CLOSE_NOT_FOUND);
            return;
        }
        byte[] tokenHash = sha256(Base64.getUrlDecoder().decode(m.token()));
        switch (s.attachReceiver(ws, tokenHash)) {
            case OK -> {
                ws.getAttributes().put(ATTR_JOINED, true);
                long remaining = sessions.secondsRemaining(s);
                TransferMessage status = TransferMessage.status(SessionState.CONNECTED.name(), true, remaining);
                send(ws, status);
                send(s.participant(Role.SENDER), status);
            }
            case UNAUTHORIZED -> fail(ws, "UNAUTHORIZED", CLOSE_UNAUTHORIZED);
            case FULL -> fail(ws, "SESSION_FULL", CLOSE_FULL);
        }
    }

    // ------------------------------------------------------------------ housekeeping

    @Scheduled(fixedDelay = 1_000)
    public void expireSessions() {
        for (TransferSession s : sessions.sweepExpired()) {
            for (Role r : Role.values()) {
                WebSocketSession p = s.participant(r);
                send(p, TransferMessage.status(SessionState.EXPIRED.name(), false, 0));
                close(p, CLOSE_EXPIRED);
            }
        }
    }

    /** Keeps reverse proxies from dropping idle-but-valid connections. */
    @Scheduled(fixedDelay = 20_000)
    public void ping() {
        for (TransferSession s : sessions.all()) {
            for (Role r : Role.values()) {
                WebSocketSession p = s.participant(r);
                if (p != null && p.isOpen()) {
                    try {
                        p.sendMessage(new PingMessage(ByteBuffer.allocate(0)));
                    } catch (Exception ignored) {
                        // closed concurrently
                    }
                }
            }
        }
    }

    // ------------------------------------------------------------------ helpers

    private void relay(TransferSession s, Role to, TransferMessage m) {
        send(s.participant(to), m.relayCopy());
    }

    private void reject(WebSocketSession ws) {
        send(ws, TransferMessage.error("INVALID_STATE"));
    }

    private void fail(WebSocketSession ws, String code, CloseStatus status) {
        send(ws, TransferMessage.error(code));
        close(ws, status);
    }

    private static void send(WebSocketSession ws, TransferMessage m) {
        if (ws == null || !ws.isOpen()) return;
        try {
            ws.sendMessage(new TextMessage(m.toJson()));
        } catch (Exception e) {
            log.debug("send failed: {}", e.getClass().getSimpleName());
        }
    }

    private static void close(WebSocketSession ws, CloseStatus status) {
        if (ws == null || !ws.isOpen()) return;
        try {
            ws.close(status);
        } catch (Exception e) {
            log.debug("close failed: {}", e.getClass().getSimpleName());
        }
    }

    private static byte[] sha256(byte[] in) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(in);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable");
        }
    }
}
