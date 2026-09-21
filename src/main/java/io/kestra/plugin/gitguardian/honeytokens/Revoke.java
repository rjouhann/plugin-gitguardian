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
    title = "Revoke a GitGuardian honeytoken",
    description = "Revokes an active or triggered honeytoken via `POST /v1/honeytokens/{id}/revoke` and closes its events, for example when the environment it was placed in is decommissioned. Requires the `honeytokens:write` scope."
)
@Plugin(
    examples = {
        @Example(
            title = "Revoke the honeytoken of a torn-down environment",
            full = true,
            code = """
                id: gitguardian_revoke_honeytoken
                namespace: company.security

                inputs:
                  - id: honeytoken_id
                    type: STRING

                tasks:
                  - id: revoke
                    type: io.kestra.plugin.gitguardian.honeytokens.Revoke
                    apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"
                    honeytokenId: "{{ inputs.honeytoken_id }}"
                """
        )
    }
)
public class Revoke extends AbstractGitGuardianTask implements RunnableTask<Revoke.Output> {
    private static final String SCOPE = "honeytokens:write";

    @Schema(title = "Honeytoken ID")
    @NotNull
    @PluginProperty(group = "main")
    private Property<String> honeytokenId;

    @Override
    public Output run(RunContext runContext) throws Exception {
        var rId = runContext.render(honeytokenId).as(String.class)
            .orElseThrow(() -> new IllegalArgumentException("honeytokenId is required to revoke a GitGuardian honeytoken."));

        runContext.logger().info("Revoking GitGuardian honeytoken {}", rId);

        try (var client = client(runContext)) {
            var honeytoken = client.post("/honeytokens/" + rId + "/revoke", null, SCOPE, Honeytoken.class);
            if (honeytoken == null) {
                throw new IllegalStateException("Empty response from the GitGuardian API when revoking honeytoken %s.".formatted(rId));
            }
            return Output.builder().honeytoken(honeytoken).build();
        }
    }

    @Builder
    @Getter
    public static class Output implements io.kestra.core.models.tasks.Output {
        @Schema(title = "The revoked honeytoken")
        private final Honeytoken honeytoken;
    }
}
