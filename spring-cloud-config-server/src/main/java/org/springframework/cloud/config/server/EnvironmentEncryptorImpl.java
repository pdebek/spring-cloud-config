package org.springframework.cloud.config.server;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.cloud.config.environment.Environment;
import org.springframework.cloud.config.environment.PropertySource;
import org.springframework.security.crypto.encrypt.TextEncryptor;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;

public class EnvironmentEncryptorImpl implements EnvironmentEncryptor {

    private static Log logger = LogFactory.getLog(EnvironmentEncryptorImpl.class);

    private TextEncryptorLocator locator;

    public EnvironmentEncryptorImpl(TextEncryptorLocator locator) {
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
                    TextEncryptor encryptor = locator.locate(environment);
                    map.remove(key);
                    if (encryptor == null) {
                        map.put(name, value);
                    } else {
                        try {
                            value = value == null ? null : encryptor.decrypt(value
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
            }
            result.add(new PropertySource(source.getName(), map));
        }
        return result;
    }
}