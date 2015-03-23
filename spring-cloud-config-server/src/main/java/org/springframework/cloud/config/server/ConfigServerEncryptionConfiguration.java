package org.springframework.cloud.config.server;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.cloud.bootstrap.encrypt.EncryptionBootstrapConfiguration;
import org.springframework.cloud.bootstrap.encrypt.KeyProperties;
import org.springframework.cloud.config.environment.Environment;
import org.springframework.cloud.context.encrypt.EncryptorFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@AutoConfigureAfter(EncryptionBootstrapConfiguration.class)
public class ConfigServerEncryptionConfiguration {

    @Autowired
    private KeyProperties keyProperties;

    @Bean
    public EncryptorFactory encryptorFactory() {
        return new EncryptorFactory();
    }

    @Bean
    public KeyChain keyChain() {
        return keyStoreEnabled() ? aesKeyChain() : new InMemoryKeyChain();
    }

    public KeyChain aesKeyChain() {
        return new AESKeyChain(keyProperties.getKeyStore());
    }

    @Bean
    public TextEncryptorLocator textEncryptorLocator(EncryptorFactory encryptorFactory, KeyChain keyChain) {
        return new TextEncryptorLocator(encryptorFactory, keyChain);
    }

    @Bean
    public EnvironmentEncryptor environmentEncryptor(TextEncryptorLocator locator) {
        return keyStoreEnabled() ? new CipherPlaceholderEnvironmentEncryptor(locator) : noOpEnvironmentEncryptor();
    }

    private boolean keyStoreEnabled() {
        return keyProperties.getKeyStore().getLocation() != null;
    }

    public EnvironmentEncryptor noOpEnvironmentEncryptor() {
        return new EnvironmentEncryptor() {
            @Override
            public Environment decrypt(Environment environment) {
                return environment;
            }
        };
    }
}
