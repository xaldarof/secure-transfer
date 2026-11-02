package com.example.securetransfer.protocol;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import java.util.regex.Pattern;

/**
 * Compact JSON wire protocol. The server is an <b>untrusted relay</b>:
 *
 * <ul>
 *   <li><b>Server-validated</b> (server can check): {@code JOIN} (sender registers the receiver verifier,
 *       receiver proves knowledge of the HKDF-derived join token), {@code CANCEL}.</li>
 *   <li><b>End-to-end authenticated</b> (server only relays, peers verify with keys it never sees):
 *       {@code READY} (HMAC by receiver), {@code ENCRYPTED_MESSAGE} (AES-256-GCM with bound AAD),
 *       {@code ACK} (HMAC by receiver), {@code CANCEL.mac} (HMAC by either side).</li>
 *   <li><b>Untrusted server notices</b>: {@code STATUS}, {@code ERROR}. Clients must never treat these as
 *       proof of delivery.</li>
 * </ul>
 *
 * All binary values are base64url without padding. Unknown fields, wrong types or lengths are rejected.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record TransferMessage(
        String type,
        String role,
        String verifier,
        String token,
        String nonce,
        String mac,
        String transferId,
        String iv,
        String ct,
        String state,
        Boolean peer,
        Long expiresIn,
        String code) {

    /** Hard limit for any inbound WebSocket text frame (also enforced by the container). */
    public static final int MAX_MESSAGE_BYTES = 64 * 1024;
    /** Ciphertext field limit, leaving room for JSON overhead within MAX_MESSAGE_BYTES. */
    public static final int MAX_CT_CHARS = 60_000;

    public static final String JOIN = "JOIN";
    public static final String READY = "READY";
    public static final String ENCRYPTED_MESSAGE = "ENCRYPTED_MESSAGE";
    public static final String ACK = "ACK";
    public static final String CANCEL = "CANCEL";
    public static final String STATUS = "STATUS";
    public static final String ERROR = "ERROR";

    private static final Pattern B64U_16 = Pattern.compile("^[A-Za-z0-9_-]{22}$");   // 128 bit
    private static final Pattern B64U_32 = Pattern.compile("^[A-Za-z0-9_-]{43}$");   // 256 bit
    private static final Pattern B64U_12 = Pattern.compile("^[A-Za-z0-9_-]{16}$");   // 96 bit nonce
    private static final Pattern B64U = Pattern.compile("^[A-Za-z0-9_-]+$");
    public static final Pattern SESSION_ID = B64U_16;

    private static final ObjectMapper STRICT = JsonMapper.builder()
            .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .enable(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES)
            .disable(MapperFeature.ALLOW_COERCION_OF_SCALARS)
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .build();

    /** Parses and validates an inbound client message; throws {@link ProtocolException} on anything odd. */
    public static TransferMessage parseClient(String json) {
        if (json == null || json.length() > MAX_MESSAGE_BYTES) throw new ProtocolException("TOO_LARGE");
        TransferMessage m;
        try {
            m = STRICT.readValue(json, TransferMessage.class);
        } catch (JsonProcessingException e) {
            throw new ProtocolException("MALFORMED");
        }
        if (m == null || m.type == null) throw new ProtocolException("MALFORMED");
        if (m.state != null || m.peer != null || m.expiresIn != null || m.code != null) {
            throw new ProtocolException("MALFORMED");
        }
        switch (m.type) {
            case JOIN -> {
                require(m.nonce == null && m.mac == null && m.transferId == null && m.iv == null && m.ct == null);
                if ("sender".equals(m.role)) {
                    require(matches(B64U_32, m.verifier) && m.token == null);
                } else if ("receiver".equals(m.role)) {
                    require(matches(B64U_32, m.token) && m.verifier == null);
                } else {
                    throw new ProtocolException("MALFORMED");
                }
            }
            case READY -> {
                noJoinFields(m);
                require(matches(B64U_16, m.nonce) && matches(B64U_32, m.mac)
                        && m.transferId == null && m.iv == null && m.ct == null);
            }
            case ENCRYPTED_MESSAGE -> {
                noJoinFields(m);
                require(matches(B64U_16, m.transferId) && matches(B64U_12, m.iv)
                        && m.ct != null && m.ct.length() >= 22 && m.ct.length() <= MAX_CT_CHARS
                        && B64U.matcher(m.ct).matches()
                        && m.nonce == null && m.mac == null);
            }
            case ACK -> {
                noJoinFields(m);
                require(matches(B64U_16, m.transferId) && matches(B64U_32, m.mac)
                        && m.nonce == null && m.iv == null && m.ct == null);
            }
            case CANCEL -> {
                noJoinFields(m);
                require(matches(B64U_32, m.mac)
                        && m.nonce == null && m.transferId == null && m.iv == null && m.ct == null);
            }
            default -> throw new ProtocolException("MALFORMED");
        }
        return m;
    }

    /** The minimal relay form: only the fields the peer needs, re-serialized (no smuggled fields). */
    public TransferMessage relayCopy() {
        return switch (type) {
            case READY -> new TransferMessage(READY, null, null, null, nonce, mac, null, null, null, null, null, null, null);
            case ENCRYPTED_MESSAGE -> new TransferMessage(ENCRYPTED_MESSAGE, null, null, null, null, null, transferId, iv, ct, null, null, null, null);
            case ACK -> new TransferMessage(ACK, null, null, null, null, mac, transferId, null, null, null, null, null, null);
            case CANCEL -> new TransferMessage(CANCEL, null, null, null, null, mac, null, null, null, null, null, null, null);
            default -> throw new IllegalStateException("not relayable");
        };
    }

    public static TransferMessage status(String state, boolean peer, long expiresIn) {
        return new TransferMessage(STATUS, null, null, null, null, null, null, null, null, state, peer, expiresIn, null);
    }

    public static TransferMessage error(String code) {
        return new TransferMessage(ERROR, null, null, null, null, null, null, null, null, null, null, null, code);
    }

    public String toJson() {
        try {
            return STRICT.writeValueAsString(this);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("serialization failed");
        }
    }

    private static void noJoinFields(TransferMessage m) {
        require(m.role == null && m.verifier == null && m.token == null);
    }

    private static boolean matches(Pattern p, String v) {
        return v != null && p.matcher(v).matches();
    }

    private static void require(boolean ok) {
        if (!ok) throw new ProtocolException("MALFORMED");
    }
}
