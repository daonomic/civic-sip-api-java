package io.daonomic.civic.api.domain;

import lombok.Value;

import java.util.List;

@Value
public class ExchangeCodeResult {
    private String userId;
    private List<UserAttribute> attributes;
}
