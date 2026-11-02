package com.example.securetransfer.config;

import com.example.securetransfer.protocol.TransferMessage;
import com.example.securetransfer.security.RateLimitHandshakeInterceptor;
import com.example.securetransfer.websocket.TransferWebSocketHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.socket.config.annotation.EnableWebSocket;
import org.springframework.web.socket.config.annotation.WebSocketConfigurer;
import org.springframework.web.socket.config.annotation.WebSocketHandlerRegistry;
import org.springframework.web.socket.server.standard.ServletServerContainerFactoryBean;

@Configuration
@EnableWebSocket
public class WebSocketConfig implements WebSocketConfigurer {

    private final TransferWebSocketHandler handler;
    private final RateLimitHandshakeInterceptor rateLimitInterceptor;
    private final AppProperties props;

    public WebSocketConfig(TransferWebSocketHandler handler,
                           RateLimitHandshakeInterceptor rateLimitInterceptor,
                           AppProperties props) {
        this.handler = handler;
        this.rateLimitInterceptor = rateLimitInterceptor;
        this.props = props;
    }

    @Override
    public void registerWebSocketHandlers(WebSocketHandlerRegistry registry) {
        registry.addHandler(handler, "/ws/transfer/{sessionId}")
                .addInterceptors(rateLimitInterceptor)
                // Explicit allowlist; never "*". Requests with a non-listed Origin get HTTP 403.
                .setAllowedOrigins(props.allowedOrigins().toArray(String[]::new));
    }

    @Bean
    public ServletServerContainerFactoryBean webSocketContainer() {
        ServletServerContainerFactoryBean container = new ServletServerContainerFactoryBean();
        // Frames above the limit are rejected by the container (close code 1009).
        container.setMaxTextMessageBufferSize(TransferMessage.MAX_MESSAGE_BYTES);
        container.setMaxBinaryMessageBufferSize(1024);
        // Idle connections are dropped; the server pings participants to keep proxies happy.
        container.setMaxSessionIdleTimeout(props.sessionTtl().plusSeconds(30).toMillis());
        container.setAsyncSendTimeout(10_000L);
        return container;
    }
}
