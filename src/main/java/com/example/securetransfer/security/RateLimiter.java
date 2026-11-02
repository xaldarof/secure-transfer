package com.example.securetransfer.security;

import java.time.Clock;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Minimal fixed-window per-key counter (in memory). Good enough to blunt brute force and flooding from a
 * single address; put a real edge rate limiter / WAF in front for anything larger.
 */
public final class RateLimiter {

    private static final int MAX_TRACKED_KEYS = 100_000;

    private final int limit;
    private final long windowMillis;
    private final Clock clock;
    private final ConcurrentMap<String, Window> windows = new ConcurrentHashMap<>();

    public RateLimiter(int limit, long windowMillis, Clock clock) {
        this.limit = limit;
        this.windowMillis = windowMillis;
        this.clock = clock;
    }

    public boolean tryAcquire(String key) {
        long now = clock.millis();
        if (windows.size() > MAX_TRACKED_KEYS) evictStale(now);
        Window w = windows.compute(key, (k, old) ->
                old == null || now - old.start >= windowMillis ? new Window(now, 1) : new Window(old.start, old.count + 1));
        return w.count <= limit;
    }

    public void evictStale(long now) {
        windows.entrySet().removeIf(e -> now - e.getValue().start >= windowMillis);
    }

    public void evictStale() {
        evictStale(clock.millis());
    }

    private record Window(long start, int count) {
    }
}
