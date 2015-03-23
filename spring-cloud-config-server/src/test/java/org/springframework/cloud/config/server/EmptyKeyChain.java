package org.springframework.cloud.config.server;

public class EmptyKeyChain implements KeyChain {
    @Override
    public void add(String alias, String key) {
    }

    @Override
    public void addDefault(String key) {
    }

    @Override
    public String get(String alias) {
        return "";
    }

    @Override
    public String getDefault() {
        return "";
    }
}
