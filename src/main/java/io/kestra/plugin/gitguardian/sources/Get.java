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

@SuperBuilder
@ToString
@EqualsAndHashCode
@Getter
@NoArgsConstructor
@Schema(
    title = "Get a GitGuardian source",
    description = "Fetches one monitored source by ID from `GET /v1/sources/{id}`, including its `lastScan` status. Requires the `sources:read` scope."
)
@Plugin(
    examples = {
        @Example(
            title = "Wait for a historical scan to finish",
            full = true,
            code = """
                id: gitguardian_wait_scan
                namespace: company.security

                inputs:
                  - id: source_id
                    type: INT

                tasks:
                  - id: scan
                    type: io.kestra.plugin.gitguardian.sources.Scan
                    apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"
                    sourceIds:
                      - "{{ inputs.source_id }}"

                  - id: wait
                    type: io.kestra.plugin.core.flow.WaitFor
                    condition: "{{ outputs.get.source.lastScan.status == 'finished' }}"
                    checkFrequency:
                      interval: PT1M
                      maxDuration: PT2H
                    tasks:
                      - id: get
                        type: io.kestra.plugin.gitguardian.sources.Get
                        apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"
                        sourceId: "{{ inputs.source_id }}"
                """
        )
    }
)
public class Get extends AbstractGitGuardianTask implements RunnableTask<Get.Output> {
    private static final String SCOPE = "sources:read";

    @Schema(title = "Source ID")
    @NotNull
    @PluginProperty(group = "main")
    private Property<Long> sourceId;

    @Override
    public Output run(RunContext runContext) throws Exception {
        var rSourceId = runContext.render(sourceId).as(Long.class)
            .orElseThrow(() -> new IllegalArgumentException("sourceId is required to fetch a GitGuardian source."));

        runContext.logger().info("Fetching GitGuardian source {}", rSourceId);

        try (var client = client(runContext)) {
            var source = client.get("/sources/" + rSourceId, null, SCOPE, Source.class);
            if (source == null) {
                throw new IllegalStateException("Empty response from the GitGuardian API for source %d.".formatted(rSourceId));
            }
            return Output.builder().source(source).build();
        }
    }

    @Builder
    @Getter
    public static class Output implements io.kestra.core.models.tasks.Output {
        @Schema(title = "The source")
        private final Source source;
    }
}
