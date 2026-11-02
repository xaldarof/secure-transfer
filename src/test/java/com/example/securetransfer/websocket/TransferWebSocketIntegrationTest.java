package com.example.securetransfer.websocket;

import static com.example.securetransfer.support.WsTestClient.ack;
import static com.example.securetransfer.support.WsTestClient.cancel;
import static com.example.securetransfer.support.WsTestClient.encrypted;
import static com.example.securetransfer.support.WsTestClient.joinReceiver;
import static com.example.securetransfer.support.WsTestClient.joinSender;
import static com.example.securetransfer.support.WsTestClient.random;
import static com.example.securetransfer.support.WsTestClient.ready;
import static com.example.securetransfer.support.WsTestClient.verifierFor;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.securetransfer.session.SessionManager;
import com.example.securetransfer.support.WsTestClient;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.socket.CloseStatus;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT,
        properties = {"server.port=18080", "app.connections-per-minute-per-ip=100000",
                "app.sessions-per-minute-per-ip=100000"})
class TransferWebSocketIntegrationTest {

    @DynamicPropertySource
    static void origins(DynamicPropertyRegistry r) {
        r.add("app.allowed-origins", () -> "http://localhost:18080");
    }

    @LocalServerPort int port;
    @Autowired SessionManager sessions;

    private final List<WsTestClient> clients = new ArrayList<>();

    @AfterEach
    void cleanup() throws Exception {
        for (WsTestClient c : clients) c.close();
    }

    private WsTestClient connect(String sid) throws Exception {
        WsTestClient c = WsTestClient.connect(port, sid);
        clients.add(c);
        return c;
    }

    /** Sender + authorized receiver, connected and READY exchanged. */
    private record Pair(String sid, String token, WsTestClient sender, WsTestClient receiver) {}

    private Pair connectedPair() throws Exception {
        String sid = WsTestClient.sessionId();
        String token = random(32);
        WsTestClient sender = connect(sid);
        sender.send(joinSender(verifierFor(token)));
        assertThat(sender.next().path("state").asText()).isEqualTo("WAITING");
        WsTestClient receiver = connect(sid);
        receiver.send(joinReceiver(token));
        assertThat(receiver.next().path("state").asText()).isEqualTo("CONNECTED");
        assertThat(sender.next().path("state").asText()).isEqualTo("CONNECTED");
        String readyMsg = ready();
        receiver.send(readyMsg);
        JsonNode relayed = sender.nextOfType("READY");
        assertThat(relayed.path("nonce").asText()).isNotEmpty();
        return new Pair(sid, token, sender, receiver);
    }

    @Test
    void successfulOneTimeTransfer() throws Exception {
        Pair p = connectedPair();
        String tid = random(16);
        String enc = encrypted(tid);
        p.sender.send(enc);
        JsonNode got = p.receiver.nextOfType("ENCRYPTED_MESSAGE");
        assertThat(got.path("transferId").asText()).isEqualTo(tid);
        assertThat(got.has("role")).isFalse();

        p.receiver.send(ack(tid));
        assertThat(p.sender.nextOfType("ACK").path("transferId").asText()).isEqualTo(tid);
        assertThat(p.sender.awaitClose().getCode()).isEqualTo(1000);
        assertThat(p.receiver.awaitClose().getCode()).isEqualTo(1000);
        assertThat(sessions.find(p.sid)).as("session destroyed after completion").isEmpty();

        // The link cannot be reused.
        WsTestClient again = connect(p.sid);
        again.send(joinReceiver(p.token));
        assertThat(again.next().path("code").asText()).isEqualTo("NOT_FOUND");
        assertThat(again.awaitClose().getCode()).isEqualTo(4404);
    }

    @Test
    void sessionIdAloneDoesNotAuthorizeReceiver() throws Exception {
        String sid = WsTestClient.sessionId();
        String token = random(32);
        WsTestClient sender = connect(sid);
        sender.send(joinSender(verifierFor(token)));
        sender.next();

        WsTestClient attacker = connect(sid);
        attacker.send(joinReceiver(random(32)));
        assertThat(attacker.next().path("code").asText()).isEqualTo("UNAUTHORIZED");
        assertThat(attacker.awaitClose().getCode()).isEqualTo(4401);

        // Attacker cannot take over the sender role either.
        WsTestClient attacker2 = connect(sid);
        attacker2.send(joinSender(random(32)));
        assertThat(attacker2.next().path("code").asText()).isEqualTo("SESSION_EXISTS");

        // The legitimate receiver still gets in.
        WsTestClient receiver = connect(sid);
        receiver.send(joinReceiver(token));
        assertThat(receiver.next().path("state").asText()).isEqualTo("CONNECTED");
    }

    @Test
    void thirdParticipantRejected() throws Exception {
        Pair p = connectedPair();
        WsTestClient third = connect(p.sid);
        third.send(joinReceiver(p.token)); // even with the full link
        assertThat(third.next().path("code").asText()).isEqualTo("SESSION_FULL");
        assertThat(third.awaitClose().getCode()).isEqualTo(4409);
        assertThat(p.receiver.isOpen()).isTrue();
    }

    @Test
    void unjoinedSocketCannotSendProtocolMessages() throws Exception {
        Pair p = connectedPair();
        WsTestClient stranger = connect(p.sid);
        stranger.send(ack(random(16)));
        assertThat(stranger.next().path("code").asText()).isEqualTo("JOIN_REQUIRED");
        assertThat(stranger.awaitClose().getCode()).isEqualTo(CloseStatus.POLICY_VIOLATION.getCode());
        WsTestClient stranger2 = connect(p.sid);
        stranger2.send(cancel());
        assertThat(stranger2.awaitClose().getCode()).isEqualTo(CloseStatus.POLICY_VIOLATION.getCode());
        assertThat(p.sender.isOpen()).isTrue();
        assertThat(sessions.find(p.sid)).isPresent();
    }

    @Test
    void forgedAckFromWrongRoleOrStateIsIgnored() throws Exception {
        Pair p = connectedPair();
        String tid = random(16);
        p.receiver.send(ack(tid)); // before any secret
        assertThat(p.receiver.next().path("code").asText()).isEqualTo("INVALID_STATE");
        p.sender.send(encrypted(tid));
        p.receiver.nextOfType("ENCRYPTED_MESSAGE");
        p.sender.send(ack(tid)); // sender trying to complete its own transfer
        assertThat(p.sender.next().path("code").asText()).isEqualTo("INVALID_STATE");
        assertThat(sessions.find(p.sid).orElseThrow().state().name()).isEqualTo("TRANSFERRING");
    }

    @Test
    void replayedEncryptedMessageRejected() throws Exception {
        Pair p = connectedPair();
        String enc = encrypted(random(16));
        p.sender.send(enc);
        p.receiver.nextOfType("ENCRYPTED_MESSAGE");
        p.sender.send(enc);
        assertThat(p.sender.next().path("code").asText()).isEqualTo("INVALID_STATE");
        assertThat(p.receiver.inbox.poll(300, TimeUnit.MILLISECONDS)).as("receiver gets only one").isNull();
    }

    @Test
    void secretBeforeAuthenticatedReadyRejected() throws Exception {
        String sid = WsTestClient.sessionId();
        String token = random(32);
        WsTestClient sender = connect(sid);
        sender.send(joinSender(verifierFor(token)));
        sender.next();
        sender.send(encrypted(random(16)));
        assertThat(sender.next().path("code").asText()).isEqualTo("INVALID_STATE");
    }

    @Test
    void senderCancellation() throws Exception {
        Pair p = connectedPair();
        p.sender.send(cancel());
        assertThat(p.receiver.nextOfType("CANCEL").path("mac").asText()).hasSize(43);
        assertThat(p.receiver.awaitClose().getCode()).isEqualTo(4410);
        assertThat(p.sender.awaitClose().getCode()).isEqualTo(4410);
        assertThat(sessions.find(p.sid)).isEmpty();
    }

    @Test
    void receiverDisconnectBeforeTransferKeepsSessionOpen() throws Exception {
        Pair p = connectedPair();
        p.receiver.close();
        JsonNode st = p.sender.nextOfType("STATUS");
        assertThat(st.path("state").asText()).isEqualTo("WAITING");
        assertThat(st.path("peer").asBoolean()).isFalse();
        WsTestClient r2 = connect(p.sid);
        r2.send(joinReceiver(p.token));
        assertThat(r2.next().path("state").asText()).isEqualTo("CONNECTED");
    }

    @Test
    void receiverDisconnectDuringTransferIsNotCompleted() throws Exception {
        Pair p = connectedPair();
        p.sender.send(encrypted(random(16)));
        p.receiver.nextOfType("ENCRYPTED_MESSAGE");
        p.receiver.close();
        assertThat(p.sender.nextOfType("STATUS").path("state").asText()).isEqualTo("CLOSED");
        assertThat(p.sender.awaitClose().getCode()).isEqualTo(4411);
        assertThat(sessions.find(p.sid)).isEmpty();
    }

    @Test
    void senderDisconnectTearsDownSession() throws Exception {
        Pair p = connectedPair();
        p.sender.close();
        assertThat(p.receiver.awaitClose().getCode()).isEqualTo(4411);
        assertThat(sessions.find(p.sid)).isEmpty();
    }

    @Test
    void oversizedPayloadRejected() throws Exception {
        Pair p = connectedPair();
        String huge = "{\"type\":\"ENCRYPTED_MESSAGE\",\"transferId\":\"" + random(16) + "\",\"iv\":\"" + random(12)
                + "\",\"ct\":\"" + "A".repeat(70_000) + "\"}";
        p.sender.send(huge);
        assertThat(p.sender.awaitClose().getCode()).isEqualTo(CloseStatus.TOO_BIG_TO_PROCESS.getCode());
        assertThat(p.receiver.awaitClose().getCode()).as("no delivery; session torn down").isEqualTo(4411);
    }

    @Test
    void malformedMessageRejected() throws Exception {
        String sid = WsTestClient.sessionId();
        WsTestClient c = connect(sid);
        c.send("{\"type\":\"JOIN\",\"role\":\"sender\",\"verifier\":\"x\",\"key\":\"y\"}");
        assertThat(c.next().path("code").asText()).isEqualTo("MALFORMED");
        assertThat(c.awaitClose().getCode()).isEqualTo(CloseStatus.POLICY_VIOLATION.getCode());
    }

    @Test
    void concurrentReceiverAttemptsExactlyOneWins() throws Exception {
        String sid = WsTestClient.sessionId();
        String token = random(32);
        WsTestClient sender = connect(sid);
        sender.send(joinSender(verifierFor(token)));
        sender.next();
        int n = 12;
        List<WsTestClient> rs = new ArrayList<>();
        for (int i = 0; i < n; i++) rs.add(connect(sid));
        ExecutorService pool = Executors.newFixedThreadPool(n);
        CountDownLatch go = new CountDownLatch(1);
        List<Future<String>> results = new ArrayList<>();
        for (WsTestClient r : rs) {
            results.add(pool.submit(() -> {
                go.await();
                r.send(joinReceiver(token));
                JsonNode m = r.next();
                return m.has("state") ? m.path("state").asText() : m.path("code").asText();
            }));
        }
        go.countDown();
        int connected = 0, full = 0;
        for (Future<String> f : results) {
            String res = f.get(10, TimeUnit.SECONDS);
            if (res.equals("CONNECTED")) connected++;
            if (res.equals("SESSION_FULL")) full++;
        }
        pool.shutdown();
        assertThat(connected).isEqualTo(1);
        assertThat(full).isEqualTo(n - 1);
    }

    @Test
    void disallowedOriginRejectedAtHandshake() {
        assertThatThrownBy(() -> WsTestClient.connect(port, WsTestClient.sessionId(), "https://evil.example"))
                .hasStackTraceContaining("403");
    }

    @Test
    void invalidSessionIdRejectedAtHandshake() {
        assertThatThrownBy(() -> WsTestClient.connect(port, "short"))
                .hasStackTraceContaining("404");
    }
}
