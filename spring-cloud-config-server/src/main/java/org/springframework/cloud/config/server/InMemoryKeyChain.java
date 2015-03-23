package org.springframework.cloud.config.server;

import java.util.HashMap;
import java.util.Map;

public class InMemoryKeyChain implements KeyChain {
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
        if (keyStorage.containsKey(alias)) {
            return keyStorage.get(alias);
        }
        throw new KeyNotInstalledException();
    }

    @Override
    public String getDefault() {
        return get("default");
    }

}
