package io.daonomic.civic.api.domain;

import lombok.Value;

@Value
public class UserAttribute {
    private String label;
    private String value;
    private boolean isValid;
    private boolean isOwner;
}
