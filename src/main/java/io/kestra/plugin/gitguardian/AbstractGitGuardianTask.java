package io.kestra.plugin.gitguardian;

import io.kestra.core.http.client.HttpClient;
import io.kestra.core.http.client.configurations.HttpConfiguration;
import io.kestra.core.http.client.configurations.TimeoutConfiguration;
import io.kestra.core.models.annotations.PluginProperty;
import io.kestra.core.models.property.Property;
import io.kestra.core.models.tasks.Task;
import io.kestra.core.runners.RunContext;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import lombok.experimental.SuperBuilder;

import java.time.Duration;

/**
 * Base class for every GitGuardian task: holds the connection properties and builds a
 * {@link GitGuardianClient} scoped to a single task run. Not itself exposed as a plugin.
 */
@SuperBuilder
@ToString
@EqualsAndHashCode
@Getter
@NoArgsConstructor
public abstract class AbstractGitGuardianTask extends Task implements GitGuardianConnectionInterface {
    /**
     * Apache HC5 defaults to no timeout at all, so an unresponsive endpoint would block the worker thread
     * indefinitely. The read timeout is an idle timeout, not a cap on the total time of a paginated walk.
     */
    protected static final Duration HTTP_CONNECT_TIMEOUT = Duration.ofSeconds(10);
    protected static final Duration HTTP_READ_IDLE_TIMEOUT = Duration.ofSeconds(60);

    @Schema(title = API_URL_TITLE, description = API_URL_DESCRIPTION)
    @Builder.Default
    @PluginProperty(group = "connection")
    protected Property<String> apiUrl = Property.ofValue(DEFAULT_API_URL);

    @Schema(title = API_KEY_TITLE, description = API_KEY_DESCRIPTION)
    @NotNull
    @PluginProperty(secret = true, group = "connection")
    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    protected Property<String> apiKey;

    /** Opens a client scoped to this task run; always use in try-with-resources. */
    protected GitGuardianClient client(RunContext runContext) throws Exception {
        var rApiUrl = runContext.render(apiUrl).as(String.class).orElse(DEFAULT_API_URL);
        var rApiKey = runContext.render(apiKey).as(String.class)
            .orElseThrow(() -> new IllegalArgumentException("apiKey is required to authenticate with the GitGuardian API."));

        var httpClient = HttpClient.builder()
            .runContext(runContext)
            .configuration(HttpConfiguration.builder()
                .timeout(TimeoutConfiguration.builder()
                    .connectTimeout(Property.ofValue(HTTP_CONNECT_TIMEOUT))
                    .readIdleTimeout(Property.ofValue(HTTP_READ_IDLE_TIMEOUT))
                    .build())
                .build())
            .build();
        return new GitGuardianClient(httpClient, rApiUrl, rApiKey);
    }
}
