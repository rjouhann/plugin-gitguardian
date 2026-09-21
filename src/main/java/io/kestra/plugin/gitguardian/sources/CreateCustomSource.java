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

import java.util.LinkedHashMap;

@SuperBuilder
@ToString
@EqualsAndHashCode
@Getter
@NoArgsConstructor
@Schema(
    title = "Create a GitGuardian custom source",
    description = "Creates a custom source via `POST /v1/sources/custom-sources`. Its `sourceUuid` is what `scan.CreateIncidents` needs to attach incidents to data GitGuardian does not monitor natively. Create it once, store the UUID in the KV store, and reuse it. The endpoint is in beta on the GitGuardian side. Requires the `sources:write` scope."
)
@Plugin(
    examples = {
        @Example(
            title = "Create a custom source once and keep its UUID in the KV store",
            full = true,
            code = """
                id: gitguardian_custom_source_setup
                namespace: company.data

                tasks:
                  - id: create
                    type: io.kestra.plugin.gitguardian.sources.CreateCustomSource
                    apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"
                    name: analytics-warehouse
                    sourceDescription: Nightly exports of support tickets scanned by Kestra

                  - id: remember
                    type: io.kestra.plugin.core.kv.Set
                    key: GITGUARDIAN_WAREHOUSE_SOURCE_UUID
                    value: "{{ outputs.create.source.sourceUuid }}"
                """
        )
    }
)
public class CreateCustomSource extends AbstractGitGuardianTask implements RunnableTask<CreateCustomSource.Output> {
    private static final String SCOPE = "sources:write";

    @Schema(title = "Name of the custom source")
    @NotNull
    @PluginProperty(group = "main")
    private Property<String> name;

    @Schema(title = "Description")
    @PluginProperty(group = "main")
    private Property<String> sourceDescription;

    @Schema(title = "Keep only secrets whose detector has a validity checker", description = "Reduces noise from generic detectors on unstructured data. Defaults to GitGuardian's default (`false`).")
    @PluginProperty(group = "advanced")
    private Property<Boolean> useOnlyDetectorsWithValidators;

    @Override
    public Output run(RunContext runContext) throws Exception {
        var rName = runContext.render(name).as(String.class)
            .orElseThrow(() -> new IllegalArgumentException("name is required to create a GitGuardian custom source."));
        var body = new LinkedHashMap<String, Object>();
        body.put("name", rName);
        runContext.render(sourceDescription).as(String.class).ifPresent(value -> body.put("description", value));
        runContext.render(useOnlyDetectorsWithValidators).as(Boolean.class).ifPresent(value -> body.put("use_only_detectors_with_validators", value));

        runContext.logger().info("Creating GitGuardian custom source '{}'", rName);

        try (var client = client(runContext)) {
            var source = client.post("/sources/custom-sources", body, SCOPE, CustomSource.class);
            if (source == null) {
                throw new IllegalStateException("Empty response from the GitGuardian API when creating custom source '%s'.".formatted(rName));
            }
            return Output.builder().source(source).build();
        }
    }

    @Builder
    @Getter
    public static class Output implements io.kestra.core.models.tasks.Output {
        @Schema(title = "The created custom source, including `sourceUuid`")
        private final CustomSource source;
    }
}
