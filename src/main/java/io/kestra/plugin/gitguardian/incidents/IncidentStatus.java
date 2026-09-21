package io.kestra.plugin.gitguardian.incidents;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

/** Lifecycle status of a secret incident, serialized in the uppercase form the GitGuardian API uses. */
public enum IncidentStatus {
    TRIGGERED,
    ASSIGNED,
    RESOLVED,
    IGNORED,
    UNKNOWN;

    @JsonValue
    public String apiValue() {
        return name();
    }

    @JsonCreator
    public static IncidentStatus fromString(String value) {
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
