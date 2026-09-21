package io.kestra.plugin.gitguardian.healthchecks;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

/** Aggregate result of an integration health check run. */
public enum HealthCheckStatus {
    PASS,
    WARN,
    FAIL,
    UNKNOWN;

    @JsonValue
    public String apiValue() {
        return name().toLowerCase();
    }

    @JsonCreator
    public static HealthCheckStatus fromString(String value) {
        if (value == null) {
            return UNKNOWN;
        }
        for (var status : values()) {
            if (status.name().equalsIgnoreCase(value)) {
                return status;
            }
        }
        return UNKNOWN;
    }
}
