package org.springframework.cloud.config.server;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.cloud.bootstrap.encrypt.EncryptionBootstrapConfiguration;
import org.springframework.cloud.bootstrap.encrypt.KeyProperties;
import org.springframework.cloud.config.environment.Environment;
import org.springframework.cloud.context.encrypt.EncryptorFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.HashMap;
import java.util.Map;

@Configuration
@AutoConfigureAfter(EncryptionBootstrapConfiguration.class)
public class ConfigServerEncryptionConfiguration {

    @Autowired
    private KeyProperties key;

    @Bean
    public EncryptorFactory encryptorFactory() {
        return new EncryptorFactory();
    }

    @Bean
    @ConditionalOnProperty(value = "encrypt.keystoreEnabled", havingValue = "true")
    public IKeyChain keyChain() {
        return new KeyChain(key.getKeyStore());
    }

    @Bean
    @ConditionalOnMissingBean
    public IKeyChain noOpKeyChain() {
        return new IKeyChain() {

            private Map<String, String> keyStorage = new HashMap<>();

            @Override
            public void add(String alias, String key) {
                keyStorage.put(alias, key);
            }

            @Override
            public void addDefault(String key) {
                keyStorage.put("default", key);
            }

            @Override
            public String get(String alias) {
                return keyStorage.get(alias);
            }

            @Override
            public String getDefault() {
                return keyStorage.get("default");
            }
        };
    }

    @Bean
    public TextEncryptorLocator textEncryptorLocator(EncryptorFactory encryptorFactory, IKeyChain keyChain) {
        return new TextEncryptorLocator(encryptorFactory, keyChain);
    }

    @Bean
    @ConditionalOnProperty("encrypt.keystoreEnabled")
    public EnvironmentEncryptor environmentEncryptor(TextEncryptorLocator textEncryptorLocator) {
        return new EnvironmentEncryptorImpl(textEncryptorLocator);
    }

    @Bean
    @ConditionalOnProperty(value = "!encrypt.keystoreEnabled", matchIfMissing = true)
    public EnvironmentEncryptor noOpEnvironmentEncryptor() {
        return new EnvironmentEncryptor() {
            @Override
            public Environment decrypt(Environment environment) {
                return environment;
            }
        };
    }
}
