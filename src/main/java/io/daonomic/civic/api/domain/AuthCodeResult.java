package io.daonomic.civic.api.domain;

import lombok.Value;

@Value
public class AuthCodeResult {
    private String data;
    private String userId;
    private boolean encrypted;
    private String alg;
}
