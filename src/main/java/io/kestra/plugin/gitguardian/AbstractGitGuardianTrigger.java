package io.kestra.plugin.gitguardian;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.kestra.core.http.client.HttpClient;
import io.kestra.core.http.client.configurations.HttpConfiguration;
import io.kestra.core.http.client.configurations.TimeoutConfiguration;
import io.kestra.core.models.annotations.PluginProperty;
import io.kestra.core.models.property.Property;
import io.kestra.core.models.triggers.AbstractTrigger;
import io.kestra.core.models.triggers.PollingTriggerInterface;
import io.kestra.core.runners.RunContext;
import io.kestra.core.serializers.JacksonMapper;
import io.kestra.core.storages.kv.KVMetadata;
import io.kestra.core.storages.kv.KVStore;
import io.kestra.core.storages.kv.KVValueAndMetadata;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import lombok.experimental.SuperBuilder;

import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

/**
 * Base class for GitGuardian polling triggers: connection properties (duplicated from
 * {@link AbstractGitGuardianTask}, a trigger cannot extend {@code Task}) and the watermark
 * persistence every poller shares so a delivered item is never re-fired.
 */
@SuperBuilder
@ToString
@EqualsAndHashCode
@Getter
@NoArgsConstructor
public abstract class AbstractGitGuardianTrigger extends AbstractTrigger implements PollingTriggerInterface, GitGuardianConnectionInterface {
    private static final ObjectMapper MAPPER = JacksonMapper.ofJson();

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

    @Schema(title = "Polling interval", description = "How often to poll the GitGuardian API. Defaults to `PT5M`.")
    @Builder.Default
    @PluginProperty(group = "execution")
    protected Duration interval = Duration.ofMinutes(5);

    protected GitGuardianClient client(RunContext runContext) throws Exception {
        var rApiUrl = runContext.render(apiUrl).as(String.class).orElse(DEFAULT_API_URL);
        var rApiKey = runContext.render(apiKey).as(String.class)
            .orElseThrow(() -> new IllegalArgumentException("apiKey is required to authenticate with the GitGuardian API."));

        var httpClient = HttpClient.builder()
            .runContext(runContext)
            .configuration(HttpConfiguration.builder()
                .timeout(TimeoutConfiguration.builder()
                    .connectTimeout(Property.ofValue(AbstractGitGuardianTask.HTTP_CONNECT_TIMEOUT))
                    .readIdleTimeout(Property.ofValue(AbstractGitGuardianTask.HTTP_READ_IDLE_TIMEOUT))
                    .build())
                .build())
            .build();
        return new GitGuardianClient(httpClient, rApiUrl, rApiKey);
    }

    /** Length-prefixed so distinct (flowId, triggerId) pairs never produce the same key. */
    protected String watermarkKey(String prefix, String flowId, String triggerId) {
        return prefix + "_watermark_" + flowId.length() + "_" + flowId + "_" + triggerId.length() + "_" + triggerId;
    }

    /**
     * A read failure is never treated as "no watermark yet": that would silently re-seed the baseline
     * and drop every item accumulated since the last successful poll.
     */
    protected Optional<Watermark> readWatermark(KVStore kv, String key) {
        try {
            return kv.getValue(key).map(value -> parse(String.valueOf(value.value())));
        } catch (Exception e) {
            throw new IllegalStateException("Cannot read GitGuardian trigger watermark '%s' from the namespace KV store: %s. Refusing to treat this as a first poll, which would drop the backlog.".formatted(key, e.getMessage()), e);
        }
    }

    /** A write failure must fail the poll loudly, otherwise the next poll re-delivers the same item. */
    protected void persistWatermark(KVStore kv, String key, Watermark watermark) {
        try {
            kv.put(key, new KVValueAndMetadata(new KVMetadata(null, (Instant) null), MAPPER.writeValueAsString(watermark)));
        } catch (Exception e) {
            throw new IllegalStateException("Cannot persist GitGuardian trigger watermark '%s': %s. The next poll would otherwise re-deliver the same item.".formatted(key, e.getMessage()), e);
        }
    }

    private Watermark parse(String raw) {
        try {
            return MAPPER.readValue(raw, Watermark.class);
        } catch (Exception e) {
            throw new IllegalStateException("Unparseable GitGuardian trigger watermark '%s': %s. Delete the KV entry to re-seed the baseline deliberately.".formatted(raw, e.getMessage()), e);
        }
    }

    /**
     * Newest delivered timestamp plus every delivered ID sharing that exact timestamp, so items that tie
     * on the boundary are neither skipped nor re-fired.
     */
    @Getter
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Watermark {
        private Instant timestamp;
        private Set<String> boundaryIds;

        public boolean isDelivered(Instant itemTimestamp, String itemId) {
            if (itemTimestamp == null || timestamp == null) {
                return false;
            }
            if (itemTimestamp.isBefore(timestamp)) {
                return true;
            }
            return itemTimestamp.equals(timestamp) && boundaryIds != null && boundaryIds.contains(itemId);
        }

        public Watermark advance(Instant itemTimestamp, String itemId) {
            if (timestamp != null && itemTimestamp.equals(timestamp)) {
                var merged = new HashSet<>(boundaryIds != null ? boundaryIds : Set.<String>of());
                merged.add(itemId);
                return new Watermark(timestamp, merged);
            }
            return new Watermark(itemTimestamp, Set.of(itemId));
        }
    }
}
