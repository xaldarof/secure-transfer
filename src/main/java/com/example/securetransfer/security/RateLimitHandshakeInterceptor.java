package com.example.securetransfer.security;

import com.example.securetransfer.config.AppProperties;
import com.example.securetransfer.protocol.TransferMessage;
import java.time.Clock;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.WebSocketHandler;
import org.springframework.web.socket.server.HandshakeInterceptor;

/**
 * Validates the session ID shape and rate-limits WebSocket handshakes per client address.
 * Client address comes from the servlet container, which honours X-Forwarded-For only when
 * SERVER_FORWARD_HEADERS_STRATEGY=native is set (i.e. behind a trusted reverse proxy).
 */
@Component
public class RateLimitHandshakeInterceptor implements HandshakeInterceptor {

    public static final String ATTR_SESSION_ID = "transferSessionId";
    public static final String ATTR_CLIENT_IP = "clientIp";

    private final RateLimiter connectionLimiter;
    private final RateLimiter sessionCreationLimiter;

    public RateLimitHandshakeInterceptor(AppProperties props, Clock clock) {
        this.connectionLimiter = new RateLimiter(props.connectionsPerMinutePerIp(), 60_000, clock);
        this.sessionCreationLimiter = new RateLimiter(props.sessionsPerMinutePerIp(), 60_000, clock);
    }

    @Override
    public boolean beforeHandshake(ServerHttpRequest request, ServerHttpResponse response,
                                   WebSocketHandler wsHandler, Map<String, Object> attributes) {
        String path = request.getURI().getPath();
        String id = path.substring(path.lastIndexOf('/') + 1);
        if (!TransferMessage.SESSION_ID.matcher(id).matches()) {
            response.setStatusCode(HttpStatus.NOT_FOUND);
            return false;
        }
        String ip = clientIp(request);
        if (!connectionLimiter.tryAcquire(ip)) {
            response.setStatusCode(HttpStatus.TOO_MANY_REQUESTS);
            return false;
        }
        attributes.put(ATTR_SESSION_ID, id);
        attributes.put(ATTR_CLIENT_IP, ip);
        return true;
    }

    @Override
    public void afterHandshake(ServerHttpRequest request, ServerHttpResponse response,
                               WebSocketHandler wsHandler, Exception exception) {
    }

    public boolean allowSessionCreation(String ip) {
        return sessionCreationLimiter.tryAcquire(ip);
    }

    @Scheduled(fixedDelay = 60_000)
    public void evictStale() {
        connectionLimiter.evictStale();
        sessionCreationLimiter.evictStale();
    }

    private static String clientIp(ServerHttpRequest request) {
        if (request instanceof ServletServerHttpRequest servlet) {
            return servlet.getServletRequest().getRemoteAddr();
        }
        return request.getRemoteAddress() == null ? "unknown" : request.getRemoteAddress().getAddress().getHostAddress();
    }
}
