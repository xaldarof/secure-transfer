package com.example.securetransfer.session;

/**
 * Lifecycle of a transfer session.
 *
 * <pre>
 * CREATED -> WAITING -> CONNECTED -> TRANSFERRING -> COMPLETED
 *               ^            |
 *               +------------+  (receiver left before a secret was sent)
 * any non-terminal state -> EXPIRED (TTL elapsed)
 * any non-terminal state -> CLOSED  (cancelled, or a participant left; delivery NOT confirmed)
 * </pre>
 * Only an acknowledgment from the authorized receiver connection leads to COMPLETED.
 */
public enum SessionState {
    CREATED,
    WAITING,
    CONNECTED,
    TRANSFERRING,
    COMPLETED,
    EXPIRED,
    CLOSED;

    public boolean isTerminal() {
        return this == COMPLETED || this == EXPIRED || this == CLOSED;
    }
}
