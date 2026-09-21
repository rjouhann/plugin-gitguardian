package io.kestra.plugin.gitguardian.incidents;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

/** Severity of a secret incident, serialized in the lowercase form the GitGuardian API uses. */
public enum Severity {
    CRITICAL,
    HIGH,
    MEDIUM,
    LOW,
    INFO,
    UNKNOWN;

    @JsonValue
    public String apiValue() {
        return name().toLowerCase();
    }

    @JsonCreator
    public static Severity fromString(String value) {
        if (value == null) {
            return UNKNOWN;
        }
        for (var severity : values()) {
            if (severity.name().equalsIgnoreCase(value)) {
                return severity;
            }
        }
        return UNKNOWN;
    }
}
