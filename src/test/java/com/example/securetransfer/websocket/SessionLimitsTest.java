package com.example.securetransfer.websocket;

import static com.example.securetransfer.support.WsTestClient.joinSender;
import static com.example.securetransfer.support.WsTestClient.random;
import static org.assertj.core.api.Assertions.assertThat;

import com.example.securetransfer.session.SessionManager;
import com.example.securetransfer.support.WsTestClient;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;

/** Short TTL / join timeout to exercise expiry and cleanup. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT, properties = {
        "server.port=18081", "app.allowed-origins=http://localhost:18081",
        "app.session-ttl=2s", "app.join-timeout=1s"})
class SessionLimitsTest {

    @LocalServerPort int port;
    @Autowired SessionManager sessions;

    @Test
    void sessionExpiresAndIsCleanedUp() throws Exception {
        String sid = WsTestClient.sessionId();
        try (WsTestClient sender = WsTestClient.connect(port, sid)) {
            sender.send(joinSender(random(32)));
            assertThat(sender.next().path("expiresIn").asLong()).isBetween(1L, 2L);
            assertThat(sender.nextOfType("STATUS").path("state").asText()).isEqualTo("EXPIRED");
            assertThat(sender.awaitClose().getCode()).isEqualTo(4408);
            assertThat(sessions.findAny(sid)).isEmpty();
        }
    }

    @Test
    void connectionsThatNeverJoinAreDropped() throws Exception {
        try (WsTestClient idle = WsTestClient.connect(port, WsTestClient.sessionId())) {
            assertThat(idle.awaitClose().getCode()).isEqualTo(1008);
        }
    }
}
