package com.example.securetransfer.config;

import java.time.Duration;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * Environment-driven configuration. See application.yml / .env.example.
 */
@ConfigurationProperties(prefix = "app")
public record AppProperties(
        @DefaultValue("http://localhost:8080") List<String> allowedOrigins,
        @DefaultValue("5m") Duration sessionTtl,
        @DefaultValue("10s") Duration joinTimeout,
        @DefaultValue("10000") int maxSessions,
        @DefaultValue("30") int sessionsPerMinutePerIp,
        @DefaultValue("60") int connectionsPerMinutePerIp) {
}
