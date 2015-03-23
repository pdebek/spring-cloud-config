package org.springframework.cloud.config.server;

public class KeyChainException extends RuntimeException {
    public KeyChainException(Exception e) {
        super(e);
    }
}
