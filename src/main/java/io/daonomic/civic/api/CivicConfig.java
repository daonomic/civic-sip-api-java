package io.daonomic.civic.api;

public class CivicConfig {
    private final String appId;
    private final String secret;
    private final String privateKey;

    public CivicConfig(String appId, String secret, String privateKey) {
        this.appId = appId;
        this.secret = secret;
        this.privateKey = privateKey;
    }

    public String getAppId() {
        return appId;
    }

    public String getSecret() {
        return secret;
    }

    public String getPrivateKey() {
        return privateKey;
    }
}
