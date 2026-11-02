package com.example.securetransfer.protocol;

import static com.example.securetransfer.support.WsTestClient.random;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.securetransfer.support.WsTestClient;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.api.Test;

class TransferMessageTest {

    @Test
    void acceptsWellFormedMessages() {
        assertThat(TransferMessage.parseClient(WsTestClient.joinSender(random(32))).role()).isEqualTo("sender");
        assertThat(TransferMessage.parseClient(WsTestClient.joinReceiver(random(32))).role()).isEqualTo("receiver");
        assertThat(TransferMessage.parseClient(WsTestClient.ready()).type()).isEqualTo("READY");
        assertThat(TransferMessage.parseClient(WsTestClient.encrypted(random(16))).type()).isEqualTo("ENCRYPTED_MESSAGE");
        assertThat(TransferMessage.parseClient(WsTestClient.ack(random(16))).type()).isEqualTo("ACK");
        assertThat(TransferMessage.parseClient(WsTestClient.cancel()).type()).isEqualTo("CANCEL");
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "",
            "not json",
            "[]",
            "null",
            "{}",
            "{\"type\":\"NOPE\"}",
            "{\"type\":\"JOIN\",\"role\":\"admin\",\"token\":\"x\"}",
            "{\"type\":\"JOIN\",\"role\":\"receiver\"}",
            "{\"type\":\"JOIN\",\"role\":\"receiver\",\"token\":\"tooShort\"}",
            "{\"type\":\"JOIN\",\"role\":\"sender\",\"verifier\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"key\":\"leak\"}",
            "{\"type\":\"READY\",\"nonce\":123,\"mac\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}",
            "{\"type\":\"STATUS\",\"state\":\"COMPLETED\"}",
            "{\"type\":\"ACK\",\"type\":\"ACK\"}",
            "{\"type\":\"CANCEL\",\"mac\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"} trailing",
            "{\"type\":\"ENCRYPTED_MESSAGE\",\"transferId\":\"AAAAAAAAAAAAAAAAAAAAAA\",\"iv\":\"AAAAAAAAAAAAAAAA\",\"ct\":\"has+plus/slash\"}"
    })
    void rejectsMalformed(String json) {
        assertThatThrownBy(() -> TransferMessage.parseClient(json)).isInstanceOf(ProtocolException.class);
    }

    @Test
    void rejectsOversizedCiphertextAndFrames() {
        String bigCt = "A".repeat(TransferMessage.MAX_CT_CHARS + 1);
        String msg = "{\"type\":\"ENCRYPTED_MESSAGE\",\"transferId\":\"" + random(16) + "\",\"iv\":\"" + random(12)
                + "\",\"ct\":\"" + bigCt + "\"}";
        assertThatThrownBy(() -> TransferMessage.parseClient(msg)).isInstanceOf(ProtocolException.class);
        assertThatThrownBy(() -> TransferMessage.parseClient("x".repeat(TransferMessage.MAX_MESSAGE_BYTES + 1)))
                .hasMessage("TOO_LARGE");
    }

    @Test
    void relayCopyContainsOnlyRelayFields() {
        TransferMessage m = TransferMessage.parseClient(WsTestClient.encrypted(random(16)));
        String json = m.relayCopy().toJson();
        assertThat(json).contains("\"transferId\"", "\"iv\"", "\"ct\"").doesNotContain("role", "token", "verifier");
    }
}
