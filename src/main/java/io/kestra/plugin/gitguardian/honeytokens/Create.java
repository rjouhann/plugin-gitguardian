package io.kestra.plugin.gitguardian.honeytokens;

import com.fasterxml.jackson.databind.JsonNode;
import io.kestra.core.models.annotations.Example;
import io.kestra.core.models.annotations.Plugin;
import io.kestra.core.models.annotations.PluginProperty;
import io.kestra.core.models.property.Property;
import io.kestra.core.models.tasks.RunnableTask;
import io.kestra.core.models.tasks.common.EncryptedString;
import io.kestra.core.runners.RunContext;
import io.kestra.core.serializers.JacksonMapper;
import io.kestra.plugin.gitguardian.AbstractGitGuardianTask;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import lombok.experimental.SuperBuilder;

import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;

@SuperBuilder
@ToString
@EqualsAndHashCode
@Getter
@NoArgsConstructor
@Schema(
    title = "Create a GitGuardian honeytoken",
    description = """
        Creates a decoy credential via `POST /v1/honeytokens`. The credential itself is returned once, in the \
        `encryptedToken` output, encrypted with Kestra's secret key so it never appears in clear in execution data; \
        decrypt it with `{{ decrypt(outputs.<task>.encryptedToken) }}` only in the task that places it (a repository, \
        a config file, a CI variable). Requires `kestra.encryption.secret-key` to be configured and the \
        `honeytokens:write` scope.
        """
)
@Plugin(
    examples = {
        @Example(
            title = "Create a honeytoken per deployed environment and place it in a config file",
            full = true,
            code = """
                id: gitguardian_place_honeytoken
                namespace: company.security

                inputs:
                  - id: environment
                    type: STRING

                tasks:
                  - id: create
                    type: io.kestra.plugin.gitguardian.honeytokens.Create
                    apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"
                    name: "kestra-{{ inputs.environment }}-{{ execution.startDate | date('yyyyMMdd') }}"
                    honeytokenDescription: "Placed by Kestra flow {{ flow.id }} in {{ inputs.environment }}"
                    customTags:
                      env: "{{ inputs.environment }}"

                  - id: place
                    type: io.kestra.plugin.core.storage.Write
                    content: |
                      AWS_ACCESS_KEY_ID={{ (decrypt(outputs.create.encryptedToken) | json).access_token_id }}
                      AWS_SECRET_ACCESS_KEY={{ (decrypt(outputs.create.encryptedToken) | json).secret_key }}
                    extension: .env
                """
        )
    }
)
public class Create extends AbstractGitGuardianTask implements RunnableTask<Create.Output> {
    private static final String SCOPE = "honeytokens:write";
    private static final String NOT_ENCRYPTED = "Honeytoken '%s' was created (ID %s) but its value cannot be encrypted: %s. Configure `kestra.encryption.secret-key` on the Kestra server, then revoke this honeytoken and create a new one.";

    @Schema(title = "Name of the honeytoken", description = "Must be unique in the workspace.")
    @NotNull
    @PluginProperty(group = "main")
    private Property<String> name;

    @Schema(title = "Description", description = "Say where the honeytoken is placed; it is what responders read when it fires.")
    @PluginProperty(group = "main")
    private Property<String> honeytokenDescription;

    @Schema(title = "Type", description = "Currently only `AWS`. Defaults to `AWS`.")
    @Builder.Default
    @PluginProperty(group = "main")
    private Property<String> honeytokenType = Property.ofValue("AWS");

    @Schema(title = "Custom tags", description = "Map of key to value; missing tags are created in the workspace.")
    @PluginProperty(group = "main")
    private Property<Map<String, String>> customTags;

    @Override
    public Output run(RunContext runContext) throws Exception {
        var rName = runContext.render(name).as(String.class)
            .orElseThrow(() -> new IllegalArgumentException("name is required to create a GitGuardian honeytoken."));
        var body = new LinkedHashMap<String, Object>();
        body.put("name", rName);
        body.put("type", runContext.render(honeytokenType).as(String.class).orElse("AWS"));
        runContext.render(honeytokenDescription).as(String.class).ifPresent(value -> body.put("description", value));
        var rCustomTags = runContext.render(customTags).asMap(String.class, String.class);
        if (!rCustomTags.isEmpty()) {
            var tags = new ArrayList<Map<String, String>>();
            rCustomTags.forEach((key, value) -> {
                var tag = new LinkedHashMap<String, String>();
                tag.put("key", key);
                tag.put("value", value == null || value.isBlank() ? null : value);
                tags.add(tag);
            });
            body.put("custom_tags", tags);
        }

        runContext.logger().info("Creating GitGuardian honeytoken '{}'", rName);

        try (var client = client(runContext)) {
            var node = client.post("/honeytokens", body, SCOPE, JsonNode.class);
            if (node == null) {
                throw new IllegalStateException("Empty response from the GitGuardian API when creating honeytoken '%s'.".formatted(rName));
            }
            var mapper = JacksonMapper.ofJson();
            var honeytoken = mapper.treeToValue(node, Honeytoken.class);
            var token = node.get("token");
            if (token == null || token.isNull()) {
                throw new IllegalStateException("GitGuardian created honeytoken '%s' but returned no token value.".formatted(rName));
            }
            var plainToken = mapper.writeValueAsString(token);
            EncryptedString encryptedToken;
            try {
                encryptedToken = EncryptedString.from(plainToken, runContext);
            } catch (GeneralSecurityException e) {
                throw new IllegalStateException(NOT_ENCRYPTED.formatted(rName, honeytoken.getId(), e.getMessage()), e);
            }
            // Without a configured key, Kestra's encrypt() returns its input unchanged; never let a decoy credential reach the outputs in clear.
            if (plainToken.equals(encryptedToken.getValue())) {
                throw new IllegalStateException(NOT_ENCRYPTED.formatted(rName, honeytoken.getId(), "no encryption key is configured"));
            }
            return Output.builder().honeytoken(honeytoken).encryptedToken(encryptedToken).build();
        }
    }

    @Builder
    @Getter
    public static class Output implements io.kestra.core.models.tasks.Output {
        @Schema(title = "The created honeytoken, without its value")
        private final Honeytoken honeytoken;

        @Schema(title = "The honeytoken value as a JSON object, encrypted", description = "For an AWS honeytoken: `{\"access_token_id\": ..., \"secret_key\": ...}`. Use `{{ decrypt(outputs.<task>.encryptedToken) }}` where it is placed.")
        private final EncryptedString encryptedToken;
    }
}
