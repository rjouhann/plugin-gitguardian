package io.kestra.plugin.gitguardian.incidents;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

/** Result of GitGuardian's validity check on a secret, serialized in the lowercase form the API uses. */
public enum Validity {
    VALID,
    INVALID,
    FAILED_TO_CHECK,
    NO_CHECKER,
    NOT_CHECKED,
    UNKNOWN;

    @JsonValue
    public String apiValue() {
        return name().toLowerCase();
    }

    @JsonCreator
    public static Validity fromString(String value) {
        if (value == null) {
            return UNKNOWN;
        }
        for (var validity : values()) {
            if (validity.name().equalsIgnoreCase(value)) {
                return validity;
            }
        }
        return UNKNOWN;
    }
}
