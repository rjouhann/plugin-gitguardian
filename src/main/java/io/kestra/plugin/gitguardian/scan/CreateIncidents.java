package io.kestra.plugin.gitguardian.scan;

import com.fasterxml.jackson.databind.JsonNode;
import io.kestra.core.models.annotations.Example;
import io.kestra.core.models.annotations.Metric;
import io.kestra.core.models.annotations.Plugin;
import io.kestra.core.models.annotations.PluginProperty;
import io.kestra.core.models.executions.metrics.Counter;
import io.kestra.core.models.property.Property;
import io.kestra.core.models.tasks.RunnableTask;
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

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@SuperBuilder
@ToString
@EqualsAndHashCode
@Getter
@NoArgsConstructor
@Schema(
    title = "Scan content and create GitGuardian incidents for a custom source",
    description = """
        Scans inline `content` and/or internal storage `files` with `POST /v1/scan/create-incidents` and, unlike \
        `Scan`, records every secret found as a real incident on the GitGuardian dashboard, attached to a custom \
        source identified by `sourceUuid` (create one with `sources.CreateCustomSource`). Use it to bring data that \
        GitGuardian cannot monitor natively into the incident workflow: warehouse extracts, ticket exports, object \
        storage dumps, generated artifacts; this is the Kestra counterpart of GitGuardian's Bring Your Own Sources with \
        ggshield `--source-uuid`. Optional `locationUrl` and `authorEmail` are shown on the occurrences. Documents are \
        grouped into requests of at most 1 MB, the endpoint's request body limit, so one document must stay under 1 MB. \
        The endpoint is in beta on the GitGuardian side. Requires the `scan:create-incidents` scope, which includes `scan`.
        """
)
@Plugin(
    examples = {
        @Example(
            title = "Register secrets found in a nightly warehouse export as GitGuardian incidents",
            full = true,
            code = """
                id: gitguardian_warehouse_export_scan
                namespace: company.data

                tasks:
                  - id: export
                    type: io.kestra.plugin.jdbc.postgresql.CopyOut
                    url: jdbc:postgresql://warehouse:5432/analytics
                    username: "{{ secret('PG_USER') }}"
                    password: "{{ secret('PG_PASSWORD') }}"
                    sql: SELECT id, notes FROM support_tickets WHERE updated_at > now() - interval '1 day'
                    format: CSV

                  - id: create_incidents
                    type: io.kestra.plugin.gitguardian.scan.CreateIncidents
                    apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"
                    sourceUuid: "{{ kv('GITGUARDIAN_WAREHOUSE_SOURCE_UUID') }}"
                    files:
                      - "{{ outputs.export.uri }}"
                    locationUrl: https://warehouse.company.com/tables/support_tickets

                triggers:
                  - id: nightly
                    type: io.kestra.plugin.core.trigger.Schedule
                    cron: "0 3 * * *"
                """
        )
    },
    metrics = {
        @Metric(name = "policy.breaks", type = Counter.TYPE, description = "Number of policy breaks (incidents) created or updated."),
        @Metric(name = "documents", type = Counter.TYPE, description = "Number of documents scanned.")
    }
)
public class CreateIncidents extends AbstractGitGuardianTask implements RunnableTask<CreateIncidents.Output> {
    private static final String SCOPE = "scan:create-incidents";
    /** 1 MB request limit minus headroom for JSON escaping, filenames, locations and the envelope. */
    static final int MAX_BATCH_BYTES = 900 * 1024;

    @Schema(title = "UUID of the GitGuardian custom source that owns the incidents", description = "Returned by `sources.CreateCustomSource`; store it in the KV store or a secret.")
    @NotNull
    @PluginProperty(group = "main")
    private Property<String> sourceUuid;

    @Schema(title = "Inline content to scan", description = "Scanned as one document named after `filename`.")
    @PluginProperty(group = "main")
    private Property<String> content;

    @Schema(title = "File name for the inline content", description = "Defaults to `content`.")
    @Builder.Default
    @PluginProperty(group = "main")
    private Property<String> filename = Property.ofValue("content");

    @Schema(title = "Internal storage files to scan", description = "List of `kestra://` URIs, each scanned as one document named after the last segment of its URI, at most 1 MB each.")
    @PluginProperty(group = "main")
    private Property<List<String>> files;

    @Schema(title = "URL shown on the created occurrences", description = "Where the scanned data can be found, for example a warehouse table or bucket URL.")
    @PluginProperty(group = "advanced")
    private Property<String> locationUrl;

    @Schema(title = "Email of the document author, for attribution on the occurrences")
    @PluginProperty(group = "advanced")
    private Property<String> authorEmail;

    @Override
    public Output run(RunContext runContext) throws Exception {
        var rSourceUuid = runContext.render(sourceUuid).as(String.class)
            .orElseThrow(() -> new IllegalArgumentException("sourceUuid is required to create GitGuardian incidents on a custom source."));
        var rLocationUrl = runContext.render(locationUrl).as(String.class).orElse(null);
        var rAuthorEmail = runContext.render(authorEmail).as(String.class).orElse(null);

        var documents = new ArrayList<Map<String, Object>>();
        var rContent = runContext.render(content).as(String.class).orElse(null);
        if (rContent != null) {
            documents.add(document(runContext.render(filename).as(String.class).orElse("content"), rContent, rLocationUrl, rAuthorEmail));
        }
        for (var file : runContext.render(files).asList(String.class)) {
            var uri = URI.create(file);
            byte[] bytes;
            try (var inputStream = runContext.storage().getFile(uri)) {
                bytes = inputStream.readAllBytes();
            }
            var path = uri.getPath();
            var name = path == null || path.isBlank() ? "content" : path.substring(path.lastIndexOf('/') + 1);
            documents.add(document(name.isBlank() ? "content" : name, new String(bytes, StandardCharsets.UTF_8), rLocationUrl, rAuthorEmail));
        }
        if (documents.isEmpty()) {
            throw new IllegalArgumentException("Nothing to scan: set content, files, or both.");
        }

        var results = new ArrayList<ScanResult>();
        try (var client = client(runContext)) {
            for (var batch : batches(documents)) {
                var body = new LinkedHashMap<String, Object>();
                body.put("source_uuid", rSourceUuid);
                body.put("documents", batch);
                var node = client.post("/scan/create-incidents", body, SCOPE, JsonNode.class);
                if (node == null) {
                    throw new IllegalStateException("Empty response from the GitGuardian create-incidents API.");
                }
                var mapper = JacksonMapper.ofJson();
                if (node.isArray()) {
                    for (int i = 0; i < node.size(); i++) {
                        var result = mapper.treeToValue(node.get(i), ScanResult.class);
                        result.setFilename(i < batch.size() ? String.valueOf(batch.get(i).get("filename")) : null);
                        results.add(result);
                    }
                } else {
                    var result = mapper.treeToValue(node, ScanResult.class);
                    result.setFilename(batch.size() == 1 ? String.valueOf(batch.getFirst().get("filename")) : batch.size() + " documents");
                    results.add(result);
                }
            }
        }

        var policyBreakCount = results.stream().mapToInt(result -> result.getPolicyBreakCount() != null ? result.getPolicyBreakCount() : 0).sum();
        runContext.metric(Counter.of("documents", documents.size()));
        runContext.metric(Counter.of("policy.breaks", policyBreakCount));
        runContext.logger().info("GitGuardian scanned {} document(s) for custom source {} and reported {} policy break(s) as incidents", documents.size(), rSourceUuid, policyBreakCount);

        return Output.builder().documentCount(documents.size()).policyBreakCount(policyBreakCount).results(results).build();
    }

    /** Groups documents so each request body stays under the endpoint's 1 MB limit, leaving room for the JSON envelope and escaping. */
    static List<List<Map<String, Object>>> batches(List<Map<String, Object>> documents) {
        var batches = new ArrayList<List<Map<String, Object>>>();
        var current = new ArrayList<Map<String, Object>>();
        var currentBytes = 0;
        for (var document : documents) {
            var bytes = String.valueOf(document.get("document")).getBytes(StandardCharsets.UTF_8).length;
            if (!current.isEmpty() && currentBytes + bytes > MAX_BATCH_BYTES) {
                batches.add(current);
                current = new ArrayList<>();
                currentBytes = 0;
            }
            current.add(document);
            currentBytes += bytes;
        }
        if (!current.isEmpty()) {
            batches.add(current);
        }
        return batches;
    }

    private static Map<String, Object> document(String name, String body, String locationUrl, String authorEmail) {
        var size = body.getBytes(StandardCharsets.UTF_8).length;
        if (size > MAX_BATCH_BYTES) {
            throw new IllegalArgumentException("Document '%s' is %d bytes; the GitGuardian create-incidents request body is limited to 1 MB. Split the content or scan a smaller file.".formatted(name, size));
        }
        var document = new LinkedHashMap<String, Object>();
        document.put("filename", name);
        document.put("document", body);
        if (locationUrl != null) {
            document.put("location", Map.of("url", locationUrl));
        }
        if (authorEmail != null) {
            document.put("author_email", authorEmail);
        }
        return document;
    }

    @Builder
    @Getter
    public static class Output implements io.kestra.core.models.tasks.Output {
        @Schema(title = "Number of documents scanned")
        private final Integer documentCount;

        @Schema(title = "Total number of policy breaks reported as incidents")
        private final Integer policyBreakCount;

        @Schema(title = "Scan results", description = "Detector, validity, known incident URL and match positions. Never the matched secret strings.")
        private final List<ScanResult> results;
    }
}
