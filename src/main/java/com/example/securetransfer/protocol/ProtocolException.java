package com.example.securetransfer.protocol;

/** Carries only a short machine-readable code; never message contents. */
public class ProtocolException extends RuntimeException {
    private final String code;

    public ProtocolException(String code) {
        super(code, null, false, false);
        this.code = code;
    }

    public String code() {
        return code;
    }
}
