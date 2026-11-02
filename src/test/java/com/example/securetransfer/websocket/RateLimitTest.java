package com.example.securetransfer.websocket;

import static com.example.securetransfer.support.WsTestClient.joinSender;
import static com.example.securetransfer.support.WsTestClient.random;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.securetransfer.support.WsTestClient;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT, properties = {
        "server.port=18082", "app.allowed-origins=http://localhost:18082",
        "app.connections-per-minute-per-ip=4", "app.sessions-per-minute-per-ip=2"})
class RateLimitTest {

    @LocalServerPort int port;

    @Test
    void sessionCreationAndConnectionsAreRateLimited() throws Exception {
        try (WsTestClient a = WsTestClient.connect(port, WsTestClient.sessionId());
             WsTestClient b = WsTestClient.connect(port, WsTestClient.sessionId());
             WsTestClient c = WsTestClient.connect(port, WsTestClient.sessionId())) {
            a.send(joinSender(random(32)));
            assertThat(a.next().path("state").asText()).isEqualTo("WAITING");
            b.send(joinSender(random(32)));
            assertThat(b.next().path("state").asText()).isEqualTo("WAITING");
            c.send(joinSender(random(32)));
            assertThat(c.next().path("code").asText()).isEqualTo("RATE_LIMITED");
            assertThat(c.awaitClose().getCode()).isEqualTo(4429);

            try (WsTestClient d = WsTestClient.connect(port, WsTestClient.sessionId())) {
                assertThat(d.isOpen()).isTrue(); // 4th connection still allowed
            }
            assertThatThrownBy(() -> WsTestClient.connect(port, WsTestClient.sessionId()))
                    .hasStackTraceContaining("429");
        }
    }
}
