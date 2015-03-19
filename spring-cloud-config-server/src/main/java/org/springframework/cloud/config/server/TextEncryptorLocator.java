package org.springframework.cloud.config.server;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.config.encrypt.EncryptorFactory;
import org.springframework.cloud.config.environment.Environment;
import org.springframework.security.crypto.encrypt.TextEncryptor;

public class TextEncryptorLocator {

    private EncryptorFactory encryptorFactory;

    private KeyChain keyChain;

    @Autowired
    public TextEncryptorLocator(EncryptorFactory encryptorFactory, KeyChain keyChain) {
        this.encryptorFactory = encryptorFactory;
        this.keyChain = keyChain;
    }

    public TextEncryptor locate() {
        return locate(keyChain.getDefault());
    }

    public TextEncryptor locate(Environment environment) {
        return locate(keyChain.get(environment));
    }

    private TextEncryptor locate(String key) {
        return encryptorFactory.create(key);
    }
}
