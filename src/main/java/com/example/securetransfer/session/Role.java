package com.example.securetransfer.session;

public enum Role {
    SENDER, RECEIVER;

    public Role peer() {
        return this == SENDER ? RECEIVER : SENDER;
    }
}
