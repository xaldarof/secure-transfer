package com.example.securetransfer.session;

import com.example.securetransfer.config.AppProperties;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.WebSocketSession;

/**
 * Thread-safe RAM-only registry of transfer sessions. Nothing is persisted, queued or replicated.
 */
@Component
public class SessionManager {

    private final ConcurrentMap<String, TransferSession> sessions = new ConcurrentHashMap<>();
    private final AppProperties props;
    private final Clock clock;

    public SessionManager(AppProperties props, Clock clock) {
        this.props = props;
        this.clock = clock;
    }

    public enum CreateResult { OK, EXISTS, CAPACITY }

    /** Creates the session and attaches the sender atomically. */
    public CreateResult create(String id, byte[] receiverVerifier, WebSocketSession senderWs) {
        if (sessions.size() >= props.maxSessions()) return CreateResult.CAPACITY;
        TransferSession s = new TransferSession(id, receiverVerifier, clock.instant().plus(props.sessionTtl()));
        if (sessions.putIfAbsent(id, s) != null) return CreateResult.EXISTS;
        s.attachSender(senderWs);
        return CreateResult.OK;
    }

    public Optional<TransferSession> find(String id) {
        TransferSession s = sessions.get(id);
        if (s == null || isExpired(s)) return Optional.empty();
        return Optional.of(s);
    }

    /** Lookup including sessions whose TTL elapsed but that have not been swept yet. */
    public Optional<TransferSession> findAny(String id) {
        return Optional.ofNullable(sessions.get(id));
    }

    /** Removes the session only if it is still the same instance (avoids races with re-creation). */
    public boolean remove(TransferSession s) {
        return sessions.remove(s.id(), s);
    }

    public boolean isExpired(TransferSession s) {
        return !clock.instant().isBefore(s.expiresAt());
    }

    public long secondsRemaining(TransferSession s) {
        return Math.max(0, s.expiresAt().getEpochSecond() - clock.instant().getEpochSecond());
    }

    /** Marks expired sessions EXPIRED, removes them, and returns them so connections can be closed. */
    public List<TransferSession> sweepExpired() {
        Instant now = clock.instant();
        List<TransferSession> expired = new ArrayList<>();
        for (TransferSession s : sessions.values()) {
            if (!now.isBefore(s.expiresAt()) && remove(s)) {
                s.expire();
                expired.add(s);
            }
        }
        return expired;
    }

    public List<TransferSession> all() {
        return List.copyOf(sessions.values());
    }

    public int size() {
        return sessions.size();
    }
}
