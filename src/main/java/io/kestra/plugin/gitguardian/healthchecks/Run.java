package io.kestra.plugin.gitguardian.healthchecks;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
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
import lombok.Setter;
import lombok.ToString;
import lombok.experimental.SuperBuilder;

@SuperBuilder
@ToString
@EqualsAndHashCode
@Getter
@NoArgsConstructor
@Schema(
    title = "Run a GitGuardian integration health check",
    description = "Enqueues a health check for one integration instance via `POST /v1/health-checks/{type}/{instanceId}/trigger`. The check runs asynchronously; poll `List` or open `resultUrl` for the outcome. Requires the `health_checks:write` scope."
)
@Plugin(
    examples = {
        @Example(
            title = "Re-check every failing integration, then re-list after a pause",
            full = true,
            code = """
                id: gitguardian_recheck_failing
                namespace: company.security

                tasks:
                  - id: failing
                    type: io.kestra.plugin.gitguardian.healthchecks.List
                    apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"
                    status: FAIL

                  - id: recheck
                    type: io.kestra.plugin.core.flow.ForEach
                    values: "{{ outputs.failing.rows }}"
                    tasks:
                      - id: run
                        type: io.kestra.plugin.gitguardian.healthchecks.Run
                        apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"
                        integrationType: "{{ json(taskrun.value).type }}"
                        instanceId: "{{ json(taskrun.value).instance.id }}"
                """
        )
    }
)
public class Run extends AbstractGitGuardianTask implements RunnableTask<Run.Output> {
    private static final String SCOPE = "health_checks:write";

    @Schema(title = "Integration type", description = "For example `github-installation`, as returned in `type` by the `List` task.")
    @NotNull
    @PluginProperty(group = "main")
    private Property<String> integrationType;

    @Schema(title = "Integration instance ID", description = "As returned in `instance.id` by the `List` task.")
    @NotNull
    @PluginProperty(group = "main")
    private Property<Long> instanceId;

    @Override
    public Output run(RunContext runContext) throws Exception {
        var rType = runContext.render(integrationType).as(String.class)
            .orElseThrow(() -> new IllegalArgumentException("integrationType is required to run a GitGuardian health check."));
        var rInstanceId = runContext.render(instanceId).as(Long.class)
            .orElseThrow(() -> new IllegalArgumentException("instanceId is required to run a GitGuardian health check."));

        runContext.logger().info("Running GitGuardian health check for {} instance {}", rType, rInstanceId);

        try (var client = client(runContext)) {
            var response = client.post("/health-checks/" + rType + "/" + rInstanceId + "/trigger", null, SCOPE, Response.class);
            return Output.builder()
                .detail(response != null ? response.getDetail() : null)
                .resultUrl(response != null ? response.getResultUrl() : null)
                .build();
        }
    }

    @Getter
    @Setter
    @NoArgsConstructor
    @JsonIgnoreProperties(ignoreUnknown = true)
    private static class Response {
        private String detail;
        @JsonAlias("result_url")
        private String resultUrl;
    }

    @Builder
    @Getter
    public static class Output implements io.kestra.core.models.tasks.Output {
        @Schema(title = "Confirmation message from GitGuardian")
        private final String detail;

        @Schema(title = "URL of the instance history, pre-filtered to runs started after this request")
        private final String resultUrl;
    }
}
