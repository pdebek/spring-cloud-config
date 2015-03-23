package org.springframework.cloud.config.server;

import org.springframework.cloud.bootstrap.encrypt.KeyProperties;
import org.springframework.cloud.context.encrypt.KeyFormatException;

import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

public class AESKeyChain implements KeyChain {

    public static final String SYMMETRIC_KEY_STORE = "JCEKS";
    public static final String DEFAULT_ALGORYTHM = "AES";

    private KeyStore keyStore;
    private KeyProperties.KeyStore properties;

    public AESKeyChain(KeyProperties.KeyStore properties) {
        try {
            keyStore = KeyStore.getInstance(SYMMETRIC_KEY_STORE);
            keyStore.load(properties.getLocation().getInputStream(), properties.getPassword().toCharArray());
            this.properties = properties;
        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
            throw new KeyChainException(e);
        }
    }

    @Override
    public void add(String alias, String key) {
        try {
            SecretKeySpec spec = new SecretKeySpec(key.getBytes(), DEFAULT_ALGORYTHM);
            this.keyStore.setKeyEntry(alias, spec, properties.getPassword().toCharArray(), null);
        } catch (KeyStoreException e) {
            throw new KeyFormatException();
        }
    }

    @Override
    public void addDefault(String key) {
        add(properties.getAlias(), key);
    }

    @Override
    public String get(String alias) {
        try {
            return keyStore.getKey(alias, properties.getPassword().toCharArray()).toString();
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            throw new KeyChainException(e);
        }
    }

    @Override
    public String getDefault() {
        return get(properties.getAlias());
    }
}
