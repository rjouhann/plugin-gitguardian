package io.kestra.plugin.gitguardian.incidents;

import com.fasterxml.jackson.annotation.JsonValue;

/** Reason recorded when ignoring a secret incident, serialized in the lowercase form the GitGuardian API uses. */
public enum IgnoreReason {
    TEST_CREDENTIAL,
    FALSE_POSITIVE,
    LOW_RISK,
    INVALID;

    @JsonValue
    public String apiValue() {
        return name().toLowerCase();
    }
}
