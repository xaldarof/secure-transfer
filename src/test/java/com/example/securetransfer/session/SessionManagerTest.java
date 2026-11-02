package com.example.securetransfer.session;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.example.securetransfer.config.AppProperties;
import com.example.securetransfer.session.SessionManager.CreateResult;
import com.example.securetransfer.session.TransferSession.JoinResult;
import com.example.securetransfer.support.MutableClock;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.socket.WebSocketSession;

class SessionManagerTest {

    private final MutableClock clock = new MutableClock();
    private SessionManager manager;
    private final byte[] token = "0123456789abcdef0123456789abcdef".getBytes();
    private byte[] verifier;

    @BeforeEach
    void setUp() throws Exception {
        manager = new SessionManager(new AppProperties(List.of("http://localhost"), Duration.ofMinutes(5),
                Duration.ofSeconds(10), 3, 100, 100), clock);
        verifier = MessageDigest.getInstance("SHA-256").digest(token);
    }

    private static WebSocketSession ws() {
        WebSocketSession s = mock(WebSocketSession.class);
        String id = UUID.randomUUID().toString();
        when(s.getId()).thenReturn(id);
        return s;
    }

    private TransferSession created(String id) {
        assertThat(manager.create(id, verifier, ws())).isEqualTo(CreateResult.OK);
        return manager.find(id).orElseThrow();
    }

    @Test
    void createAttachesSenderAndWaits() {
        TransferSession s = created("a");
        assertThat(s.state()).isEqualTo(SessionState.WAITING);
        assertThat(s.participant(Role.SENDER)).isNotNull();
        assertThat(manager.create("a", verifier, ws())).isEqualTo(CreateResult.EXISTS);
    }

    @Test
    void capacityIsEnforced() {
        created("a");
        created("b");
        created("c");
        assertThat(manager.create("d", verifier, ws())).isEqualTo(CreateResult.CAPACITY);
    }

    @Test
    void receiverNeedsCorrectToken() throws Exception {
        TransferSession s = created("a");
        byte[] wrong = MessageDigest.getInstance("SHA-256").digest("nope".getBytes());
        assertThat(s.attachReceiver(ws(), wrong)).isEqualTo(JoinResult.UNAUTHORIZED);
        assertThat(s.state()).isEqualTo(SessionState.WAITING);
        assertThat(s.attachReceiver(ws(), verifier)).isEqualTo(JoinResult.OK);
        assertThat(s.state()).isEqualTo(SessionState.CONNECTED);
    }

    @Test
    void thirdParticipantIsRejected() {
        TransferSession s = created("a");
        assertThat(s.attachReceiver(ws(), verifier)).isEqualTo(JoinResult.OK);
        assertThat(s.attachReceiver(ws(), verifier)).isEqualTo(JoinResult.FULL);
    }

    @Test
    void fullLifecycleAndRoleChecks() {
        TransferSession s = created("a");
        WebSocketSession sender = s.participant(Role.SENDER);
        WebSocketSession receiver = ws();
        WebSocketSession stranger = ws();
        s.attachReceiver(receiver, verifier);

        assertThat(s.beginTransfer(sender)).as("needs READY first").isFalse();
        assertThat(s.markReady(sender)).as("sender cannot send READY").isFalse();
        assertThat(s.markReady(stranger)).isFalse();
        assertThat(s.markReady(receiver)).isTrue();
        assertThat(s.markReady(receiver)).as("once per connection").isFalse();

        assertThat(s.beginTransfer(receiver)).as("receiver cannot send secret").isFalse();
        assertThat(s.beginTransfer(stranger)).isFalse();
        assertThat(s.beginTransfer(sender)).isTrue();
        assertThat(s.state()).isEqualTo(SessionState.TRANSFERRING);
        assertThat(s.beginTransfer(sender)).as("one secret per session (replay)").isFalse();

        assertThat(s.complete(sender)).as("sender cannot forge ACK").isFalse();
        assertThat(s.complete(stranger)).isFalse();
        assertThat(s.complete(receiver)).isTrue();
        assertThat(s.state()).isEqualTo(SessionState.COMPLETED);
        assertThat(s.complete(receiver)).isFalse();
        assertThat(s.close()).as("terminal").isFalse();
    }

    @Test
    void receiverLeavingBeforeTransferReopensSlot() {
        TransferSession s = created("a");
        WebSocketSession r1 = ws();
        s.attachReceiver(r1, verifier);
        s.markReady(r1);
        assertThat(s.detachReceiverBeforeTransfer(r1)).isTrue();
        assertThat(s.state()).isEqualTo(SessionState.WAITING);
        WebSocketSession r2 = ws();
        assertThat(s.attachReceiver(r2, verifier)).isEqualTo(JoinResult.OK);
        assertThat(s.beginTransfer(s.participant(Role.SENDER))).as("new receiver must send READY").isFalse();
    }

    @Test
    void receiverLeavingDuringTransferDoesNotReopen() {
        TransferSession s = created("a");
        WebSocketSession r = ws();
        s.attachReceiver(r, verifier);
        s.markReady(r);
        s.beginTransfer(s.participant(Role.SENDER));
        assertThat(s.detachReceiverBeforeTransfer(r)).isFalse();
        assertThat(s.close()).isTrue();
        assertThat(s.state()).isEqualTo(SessionState.CLOSED);
        assertThat(s.attachReceiver(ws(), verifier)).isEqualTo(JoinResult.FULL);
    }

    @Test
    void sessionsExpireAndAreSwept() {
        TransferSession s = created("a");
        clock.advance(Duration.ofMinutes(4));
        assertThat(manager.sweepExpired()).isEmpty();
        assertThat(manager.secondsRemaining(s)).isEqualTo(60);
        clock.advance(Duration.ofMinutes(1));
        assertThat(manager.find("a")).as("hidden once TTL elapsed").isEmpty();
        assertThat(manager.sweepExpired()).containsExactly(s);
        assertThat(s.state()).isEqualTo(SessionState.EXPIRED);
        assertThat(manager.size()).isZero();
        assertThat(s.attachReceiver(ws(), verifier)).isEqualTo(JoinResult.FULL);
    }

    @Test
    void concurrentReceiversExactlyOneWins() throws Exception {
        for (int round = 0; round < 50; round++) {
            TransferSession s = created("r" + round);
            int threads = 16;
            ExecutorService pool = Executors.newFixedThreadPool(threads);
            CountDownLatch start = new CountDownLatch(1);
            AtomicInteger ok = new AtomicInteger();
            List<Future<?>> futures = new ArrayList<>();
            for (int i = 0; i < threads; i++) {
                futures.add(pool.submit(() -> {
                    start.await();
                    if (s.attachReceiver(ws(), verifier) == JoinResult.OK) ok.incrementAndGet();
                    return null;
                }));
            }
            start.countDown();
            for (Future<?> f : futures) f.get();
            pool.shutdown();
            assertThat(ok.get()).isEqualTo(1);
            manager.remove(s);
        }
    }

    @Test
    void concurrentCreateSameIdExactlyOneWins() throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(8);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<CreateResult>> futures = new ArrayList<>();
        for (int i = 0; i < 8; i++) {
            futures.add(pool.submit(() -> {
                start.await();
                return manager.create("same", verifier, ws());
            }));
        }
        start.countDown();
        int ok = 0;
        for (Future<CreateResult> f : futures) if (f.get() == CreateResult.OK) ok++;
        pool.shutdown();
        assertThat(ok).isEqualTo(1);
    }

    @Test
    void removeOnlyRemovesSameInstance() {
        TransferSession s = created("a");
        assertThat(manager.remove(s)).isTrue();
        TransferSession s2 = created("a");
        assertThat(manager.remove(s)).isFalse();
        assertThat(manager.find("a")).contains(s2);
    }
}
