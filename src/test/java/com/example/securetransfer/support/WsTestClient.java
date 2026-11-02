package com.example.securetransfer.support;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import org.springframework.web.socket.CloseStatus;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketHttpHeaders;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.client.standard.StandardWebSocketClient;
import org.springframework.web.socket.handler.TextWebSocketHandler;

/** Minimal blocking WebSocket test client. */
public final class WsTestClient implements AutoCloseable {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final SecureRandom RNG = new SecureRandom();

    public final BlockingQueue<JsonNode> inbox = new LinkedBlockingQueue<>();
    public final CompletableFuture<CloseStatus> closed = new CompletableFuture<>();
    private final WebSocketSession session;

    private WsTestClient(WebSocketSession session) {
        this.session = session;
    }

    public static WsTestClient connect(int port, String sessionId) throws Exception {
        return connect(port, sessionId, "http://localhost:" + port);
    }

    public static WsTestClient connect(int port, String sessionId, String origin) throws Exception {
        StandardWebSocketClient client = new StandardWebSocketClient();
        WebSocketHttpHeaders headers = new WebSocketHttpHeaders();
        if (origin != null) headers.setOrigin(origin);
        Holder holder = new Holder();
        WebSocketSession s = client.execute(holder, headers, URI.create("ws://localhost:" + port + "/ws/transfer/" + sessionId))
                .get(5, TimeUnit.SECONDS);
        s.setTextMessageSizeLimit(256 * 1024);
        WsTestClient c = new WsTestClient(s);
        holder.owner = c;
        return c;
    }

    public void send(String json) throws Exception {
        synchronized (session) {
            session.sendMessage(new TextMessage(json));
        }
    }

    public JsonNode next() throws InterruptedException {
        JsonNode n = inbox.poll(5, TimeUnit.SECONDS);
        if (n == null) throw new AssertionError("no message received");
        return n;
    }

    public JsonNode nextOfType(String type) throws InterruptedException {
        while (true) {
            JsonNode n = next();
            if (type.equals(n.path("type").asText())) return n;
        }
    }

    public CloseStatus awaitClose() throws Exception {
        return closed.get(5, TimeUnit.SECONDS);
    }

    public boolean isOpen() {
        return session.isOpen();
    }

    @Override
    public void close() throws Exception {
        if (session.isOpen()) session.close();
    }

    // ------------------------------------------------------------ protocol helpers

    public static String b64u(byte[] b) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    public static String random(int bytes) {
        byte[] b = new byte[bytes];
        RNG.nextBytes(b);
        return b64u(b);
    }

    public static String sessionId() {
        return random(16);
    }

    /** token -> SHA-256(token), mirroring the browser's join token/verifier. */
    public static String verifierFor(String token) throws Exception {
        return b64u(MessageDigest.getInstance("SHA-256").digest(Base64.getUrlDecoder().decode(token)));
    }

    public static String joinSender(String verifier) {
        return "{\"type\":\"JOIN\",\"role\":\"sender\",\"verifier\":\"" + verifier + "\"}";
    }

    public static String joinReceiver(String token) {
        return "{\"type\":\"JOIN\",\"role\":\"receiver\",\"token\":\"" + token + "\"}";
    }

    public static String ready() {
        return "{\"type\":\"READY\",\"nonce\":\"" + random(16) + "\",\"mac\":\"" + random(32) + "\"}";
    }

    public static String encrypted(String transferId) {
        return "{\"type\":\"ENCRYPTED_MESSAGE\",\"transferId\":\"" + transferId + "\",\"iv\":\"" + random(12)
                + "\",\"ct\":\"" + random(64) + "\"}";
    }

    public static String ack(String transferId) {
        return "{\"type\":\"ACK\",\"transferId\":\"" + transferId + "\",\"mac\":\"" + random(32) + "\"}";
    }

    public static String cancel() {
        return "{\"type\":\"CANCEL\",\"mac\":\"" + random(32) + "\"}";
    }

    private static final class Holder extends TextWebSocketHandler {
        volatile WsTestClient owner;
        private final BlockingQueue<JsonNode> early = new LinkedBlockingQueue<>();

        @Override
        protected void handleTextMessage(WebSocketSession session, TextMessage message) throws Exception {
            JsonNode n = JSON.readTree(message.getPayload());
            WsTestClient o = owner;
            if (o == null) early.add(n);
            else {
                early.drainTo(o.inbox);
                o.inbox.add(n);
            }
        }

        @Override
        public void afterConnectionClosed(WebSocketSession session, CloseStatus status) {
            WsTestClient o = owner;
            while (o == null) {
                Thread.onSpinWait();
                o = owner;
            }
            early.drainTo(o.inbox);
            o.closed.complete(status);
        }
    }
}
