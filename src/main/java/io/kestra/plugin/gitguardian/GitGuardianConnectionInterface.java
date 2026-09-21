package io.kestra.plugin.gitguardian;

/**
 * Shared {@code @Schema} wording for the GitGuardian connection properties. A task and a trigger cannot
 * share a superclass ({@link io.kestra.core.models.tasks.Task} vs.
 * {@link io.kestra.core.models.triggers.AbstractTrigger}), so both redeclare these fields; keeping the
 * titles and descriptions here stops the two declarations from drifting apart.
 */
public interface GitGuardianConnectionInterface {
    String DEFAULT_API_URL = "https://api.gitguardian.com";

    String API_URL_TITLE = "GitGuardian API URL";
    String API_URL_DESCRIPTION = """
        Base URL of the GitGuardian API for your workspace: `https://api.gitguardian.com` (US, default), \
        `https://api.eu1.gitguardian.com` (EU), or `https://<your-instance>/exposed` for a self-hosted GitGuardian. \
        The `/v1` prefix is appended automatically.
        """;

    String API_KEY_TITLE = "GitGuardian API key";
    String API_KEY_DESCRIPTION = """
        Personal access token or service account token created in the GitGuardian dashboard under API > Personal \
        access tokens / Service accounts. The token needs the scopes required by the tasks and triggers you use, \
        for example `scan`, `incidents:read`, `incidents:write`, or `honeytokens:read`. Sent as \
        `Authorization: Token <key>`; never logged or included in error messages.
        """;
}
