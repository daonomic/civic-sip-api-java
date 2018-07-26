package io.daonomic.civic.api.domain;

import lombok.Value;

@Value
public class AuthorizationHeaderPayload {
    private String method;
    private String path;
}
