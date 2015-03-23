package org.springframework.cloud.config.server;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.config.environment.Environment;
import org.springframework.cloud.context.encrypt.EncryptorFactory;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.util.StringUtils;

public class TextEncryptorLocator {

    private EncryptorFactory encryptorFactory;

    private KeyChain KeyChain;

    @Autowired
    public TextEncryptorLocator(EncryptorFactory encryptorFactory, KeyChain KeyChain) {
        this.encryptorFactory = encryptorFactory;
        this.KeyChain = KeyChain;
    }

    public TextEncryptor locate() {
        return locate(KeyChain.getDefault());
    }

    public TextEncryptor locate(Environment environment) {
        return locate(environment.getName(), environment.getName());
    }

    public TextEncryptor locate(String application, String name) {
        return locate(KeyChain.get(EnvironmentAlias.of(application, name)));
    }

    private TextEncryptor locate(String key) {
        checkKeyNotEmpty(key);
        return encryptorFactory.create(key);
    }

    private void checkKeyNotEmpty(String key) {
        if (StringUtils.isEmpty(key)) {
            throw new KeyNotInstalledException();
        }
    }
}
