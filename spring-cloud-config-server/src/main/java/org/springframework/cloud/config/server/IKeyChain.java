package org.springframework.cloud.config.server;

/**
 * Created by przemyslaw.debek on 19.03.15.
 */
public interface IKeyChain {
    void add(String alias, String key);

    void addDefault(String key);

    String get(String alias);

    String getDefault();
}
