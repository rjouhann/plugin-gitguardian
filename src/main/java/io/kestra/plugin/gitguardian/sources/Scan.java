package io.kestra.plugin.gitguardian.sources;

import io.kestra.core.models.annotations.Example;
import io.kestra.core.models.annotations.Plugin;
import io.kestra.core.models.annotations.PluginProperty;
import io.kestra.core.models.property.Property;
import io.kestra.core.models.tasks.RunnableTask;
import io.kestra.core.runners.RunContext;
import io.kestra.plugin.gitguardian.AbstractGitGuardianTask;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import lombok.experimental.SuperBuilder;

import java.util.Map;

@SuperBuilder
@ToString
@EqualsAndHashCode
@Getter
@NoArgsConstructor
@Schema(
    title = "Launch GitGuardian historical scans on sources",
    description = """
        Enqueues a historical scan for each source ID via `POST /v1/sources/scans`. Scans run asynchronously; GitGuardian \
        silently skips unknown, disabled, already-scanning or plan-restricted sources, and everything when the scan quota \
        is exhausted. Poll `sources.Get` and read `lastScan.status` to follow progress. The endpoint is in beta on the \
        GitGuardian side. Requires the `sources:scan` scope.
        """
)
@Plugin(
    examples = {
        @Example(
            title = "Scan newly onboarded repositories",
            full = true,
            code = """
                id: gitguardian_scan_new_repos
                namespace: company.security

                inputs:
                  - id: source_ids
                    type: ARRAY
                    itemType: INT

                tasks:
                  - id: scan
                    type: io.kestra.plugin.gitguardian.sources.Scan
                    apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"
                    sourceIds: "{{ inputs.source_ids }}"
                """
        )
    }
)
public class Scan extends AbstractGitGuardianTask implements RunnableTask<Scan.Output> {
    private static final String SCOPE = "sources:scan";

    @Schema(title = "IDs of the sources to scan")
    @NotNull
    @PluginProperty(group = "main")
    private Property<java.util.List<Long>> sourceIds;

    @Override
    public Output run(RunContext runContext) throws Exception {
        var rSourceIds = runContext.render(sourceIds).asList(Long.class);
        if (rSourceIds.isEmpty()) {
            throw new IllegalArgumentException("sourceIds must contain at least one source ID to launch GitGuardian scans.");
        }

        runContext.logger().info("Launching GitGuardian historical scans on sources {}", rSourceIds);

        try (var client = client(runContext)) {
            client.post("/sources/scans", Map.of("source_ids", rSourceIds), SCOPE, String.class);
        }
        return Output.builder().requestedCount(rSourceIds.size()).sourceIds(rSourceIds).build();
    }

    @Builder
    @Getter
    public static class Output implements io.kestra.core.models.tasks.Output {
        @Schema(title = "Number of sources the scan was requested for", description = "GitGuardian may skip some of them silently; check each source's `lastScan`.")
        private final Integer requestedCount;

        @Schema(title = "The requested source IDs")
        private final java.util.List<Long> sourceIds;
    }
}
