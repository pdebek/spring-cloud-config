package org.springframework.cloud.config.server;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.config.encrypt.EncryptorFactory;
import org.springframework.cloud.config.environment.Environment;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.stereotype.Component;

@Component
public class TextEncryptorLocator {

    private EncryptorFactory encryptorFactory;

    private IKeyChain IKeyChain;

    @Autowired
    public TextEncryptorLocator(EncryptorFactory encryptorFactory, IKeyChain IKeyChain) {
        this.encryptorFactory = encryptorFactory;
        this.IKeyChain = IKeyChain;
    }

    public TextEncryptor locate() {
        return locate(IKeyChain.getDefault());
    }

    public TextEncryptor locate(Environment environment) {
        return locate(environment.getApplication(), environment.getName());
    }

    private TextEncryptor locate(String key) {
        return encryptorFactory.create(key);
    }

    public TextEncryptor locate(String application, String name) {
        return locate(IKeyChain.get(application + "-" + name));
    }
}
