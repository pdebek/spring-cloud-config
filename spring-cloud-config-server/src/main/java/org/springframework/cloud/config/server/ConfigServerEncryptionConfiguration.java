package org.springframework.cloud.config.server;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.cloud.bootstrap.encrypt.KeyProperties;
import org.springframework.cloud.config.encrypt.EncryptorFactory;
import org.springframework.cloud.config.environment.Environment;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.HashMap;
import java.util.Map;

@Configuration
public class ConfigServerEncryptionConfiguration {

    @Bean
    public EncryptorFactory encryptorFactory() {
        return new EncryptorFactory();
    }

//    @Bean
//    @ConditionalOnProperty("encrypt.keyStore.location")
//    public IKeyChain keyChain(KeyProperties keyProperties) {
//        return new KeyChain(keyProperties.getKeyStore());
//    }

    @Bean
//    @ConditionalOnProperty(value ="encrypt.keyStore.location", matchIfMissing = true)
    public IKeyChain keyChain() {
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

//    @Bean
//    @ConditionalOnProperty("encrypt.keyStore.location")
//    public EnvironmentEncryptor environmentEncryptor(TextEncryptorLocator textEncryptorLocator) {
//        return new EnvironmentEncryptorImpl(textEncryptorLocator);
//    }

    @Bean
//    @ConditionalOnProperty(value = "encrypt.keyStore.location", matchIfMissing = true)
    public EnvironmentEncryptor environmentEncryptor() {
        return new EnvironmentEncryptor() {
            @Override
            public Environment decrypt(Environment environment) {
                return environment;
            }
        };
    }
}
