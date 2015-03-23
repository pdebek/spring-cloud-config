package org.springframework.cloud.config.server;

public class EnvironmentAlias {

    public static String of(String application, String profile) {
        return application + "-" + profile;
    }
}
