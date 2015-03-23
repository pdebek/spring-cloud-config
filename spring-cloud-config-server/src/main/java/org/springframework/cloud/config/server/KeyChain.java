package org.springframework.cloud.config.server;

import org.springframework.cloud.bootstrap.encrypt.KeyProperties;
import org.springframework.cloud.config.encrypt.KeyFormatException;

import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

public class KeyChain implements IKeyChain {

    private KeyStore keyStore;
    private KeyProperties.KeyStore properties;

    public KeyChain(KeyProperties.KeyStore properties) {
        try {
            this.keyStore = KeyStore.getInstance("JCEKS");
            keyStore.load(properties.getLocation().getInputStream(), properties.getPassword().toCharArray());
            this.properties = properties;
        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void add(String alias, String key) {
        try {
            SecretKeySpec spec = new SecretKeySpec(key.getBytes(), "AES");
            this.keyStore.setKeyEntry(alias, spec, "password".toCharArray(), null);
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
            return keyStore.getKey(alias, "password".toCharArray()).toString();
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            return "";
        }
    }

    @Override
    public String getDefault() {
        try {
            return keyStore.getKey(properties.getAlias(), "password".toCharArray()).toString();
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            return "";
        }
    }
}
