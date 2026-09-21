package io.kestra.plugin.gitguardian;

/**
 * User-facing error for any failed GitGuardian API call: HTTP error status or an unparsable response.
 * {@link #getStatusCode()} is {@code null} when the failure was not an HTTP error response.
 */
public class GitGuardianApiException extends Exception {
    private final Integer statusCode;

    public GitGuardianApiException(String message) {
        this(message, null, null);
    }

    public GitGuardianApiException(String message, Throwable cause) {
        this(message, null, cause);
    }

    public GitGuardianApiException(String message, Integer statusCode) {
        this(message, statusCode, null);
    }

    public GitGuardianApiException(String message, Integer statusCode, Throwable cause) {
        super(message, cause);
        this.statusCode = statusCode;
    }

    public Integer getStatusCode() {
        return statusCode;
    }
}
