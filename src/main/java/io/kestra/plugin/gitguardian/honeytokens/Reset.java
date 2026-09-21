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
    title = "Reset a GitGuardian honeytoken",
    description = "Resets a triggered honeytoken to active via `POST /v1/honeytokens/{id}/reset` and closes its events, once the investigation is over and the decoy should keep watching. Use `Revoke` instead when the honeytoken is compromised beyond reuse. Requires the `honeytokens:write` scope."
)
@Plugin(
    examples = {
        @Example(
            title = "Reset a honeytoken after the investigation is closed",
            full = true,
            code = """
                id: gitguardian_reset_honeytoken
                namespace: company.security

                inputs:
                  - id: honeytoken_id
                    type: STRING

                tasks:
                  - id: reset
                    type: io.kestra.plugin.gitguardian.honeytokens.Reset
                    apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"
                    honeytokenId: "{{ inputs.honeytoken_id }}"
                """
        )
    }
)
public class Reset extends AbstractGitGuardianTask implements RunnableTask<Reset.Output> {
    private static final String SCOPE = "honeytokens:write";

    @Schema(title = "Honeytoken ID")
    @NotNull
    @PluginProperty(group = "main")
    private Property<String> honeytokenId;

    @Override
    public Output run(RunContext runContext) throws Exception {
        var rId = runContext.render(honeytokenId).as(String.class)
            .orElseThrow(() -> new IllegalArgumentException("honeytokenId is required to reset a GitGuardian honeytoken."));

        runContext.logger().info("Resetting GitGuardian honeytoken {}", rId);

        try (var client = client(runContext)) {
            var honeytoken = client.post("/honeytokens/" + rId + "/reset", null, SCOPE, Honeytoken.class);
            if (honeytoken == null) {
                throw new IllegalStateException("Empty response from the GitGuardian API when resetting honeytoken %s.".formatted(rId));
            }
            return Output.builder().honeytoken(honeytoken).build();
        }
    }

    @Builder
    @Getter
    public static class Output implements io.kestra.core.models.tasks.Output {
        @Schema(title = "The reset honeytoken")
        private final Honeytoken honeytoken;
    }
}
