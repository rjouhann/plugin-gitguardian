package io.kestra.plugin.gitguardian.honeytokens;

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
    title = "Get a GitGuardian honeytoken",
    description = "Fetches one honeytoken by ID from `GET /v1/honeytokens/{id}`, without its value. Requires the `honeytokens:read` scope."
)
@Plugin(
    examples = {
        @Example(
            title = "Fetch the honeytoken behind an event",
            full = true,
            code = """
                id: gitguardian_honeytoken_details
                namespace: company.security

                tasks:
                  - id: get
                    type: io.kestra.plugin.gitguardian.honeytokens.Get
                    apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"
                    honeytokenId: "{{ trigger.event.honeytokenId }}"

                triggers:
                  - id: on_event
                    type: io.kestra.plugin.gitguardian.honeytokens.Trigger
                    apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"
                """
        )
    }
)
public class Get extends AbstractGitGuardianTask implements RunnableTask<Get.Output> {
    private static final String SCOPE = "honeytokens:read";

    @Schema(title = "Honeytoken ID")
    @NotNull
    @PluginProperty(group = "main")
    private Property<String> honeytokenId;

    @Override
    public Output run(RunContext runContext) throws Exception {
        var rId = runContext.render(honeytokenId).as(String.class)
            .orElseThrow(() -> new IllegalArgumentException("honeytokenId is required to fetch a GitGuardian honeytoken."));

        runContext.logger().info("Fetching GitGuardian honeytoken {}", rId);

        try (var client = client(runContext)) {
            var honeytoken = client.get("/honeytokens/" + rId, null, SCOPE, Honeytoken.class);
            if (honeytoken == null) {
                throw new IllegalStateException("Empty response from the GitGuardian API for honeytoken %s.".formatted(rId));
            }
            return Output.builder().honeytoken(honeytoken).build();
        }
    }

    @Builder
    @Getter
    public static class Output implements io.kestra.core.models.tasks.Output {
        @Schema(title = "The honeytoken, without its value")
        private final Honeytoken honeytoken;
    }
}
