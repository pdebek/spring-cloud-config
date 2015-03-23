package org.springframework.cloud.config.server;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.cloud.config.environment.Environment;
import org.springframework.cloud.config.environment.PropertySource;
import org.springframework.security.crypto.encrypt.TextEncryptor;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;

public class CipherPlaceholderEnvironmentEncryptor implements EnvironmentEncryptor {

    private static Log logger = LogFactory.getLog(CipherPlaceholderEnvironmentEncryptor.class);

    private TextEncryptorLocator locator;

    public CipherPlaceholderEnvironmentEncryptor(TextEncryptorLocator locator) {
        this.locator = locator;
    }

    @Override
    public Environment decrypt(Environment environment) {
        Environment result = new Environment(environment.getName(), environment.getProfiles(),
                environment.getLabel());
        for (PropertySource source : environment.getPropertySources()) {
            Map<Object, Object> map = new LinkedHashMap<Object, Object>(
                    source.getSource());
            for (Map.Entry<Object, Object> entry : new LinkedHashSet<Map.Entry<Object, Object>>(map.entrySet())) {
                Object key = entry.getKey();
                String name = key.toString();
                String value = entry.getValue().toString();
                if (value.startsWith("{cipher}")) {
                    map.remove(key);
                    try {
                        value = value == null ? null : locator.locate(environment).decrypt(value
                                    .substring("{cipher}".length()));
                    } catch (Exception e) {
                        value = "<n/a>";
                        name = "invalid." + name;
                        logger.warn("Cannot decrypt key: " + key + " ("
                                + e.getClass() + ": " + e.getMessage() + ")");
                    }
                    map.put(name, value);
                }
            }
            result.add(new PropertySource(source.getName(), map));
        }
        return result;
    }
}