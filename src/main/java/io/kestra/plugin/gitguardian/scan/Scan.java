package io.kestra.plugin.gitguardian.scan;

import com.fasterxml.jackson.core.type.TypeReference;
import io.kestra.core.models.annotations.Example;
import io.kestra.core.models.annotations.Metric;
import io.kestra.core.models.annotations.Plugin;
import io.kestra.core.models.annotations.PluginProperty;
import io.kestra.core.models.executions.metrics.Counter;
import io.kestra.core.models.property.Property;
import io.kestra.core.models.tasks.RunnableTask;
import io.kestra.core.runners.RunContext;
import io.kestra.core.serializers.FileSerde;
import io.kestra.core.serializers.JacksonMapper;
import io.kestra.plugin.gitguardian.AbstractGitGuardianTask;
import io.kestra.plugin.gitguardian.GitGuardianClient;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import lombok.experimental.SuperBuilder;
import reactor.core.publisher.Flux;

import java.io.BufferedWriter;
import java.io.FileWriter;
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
    title = "Scan content for secrets with GitGuardian",
    description = """
        Sends inline `content` and/or files from Kestra's internal storage to the GitGuardian secrets detection \
        engine and reports every policy break (detected secret) with its detector, validity and location. Uses \
        `POST /v1/scan` for a single document and `POST /v1/multiscan` in batches of 20 documents otherwise. Each \
        document must be at most 1 MB. Scanning is stateless: GitGuardian stores neither the content nor the \
        secrets, and this task never outputs the matched secret strings, only their positions. Each request counts as one \
        call against the workspace API quota, whatever the number of documents (up to 20). By default the task \
        fails when at least one policy break is found, so a flow stops before leaking data downstream; set \
        `failOnPolicyBreak: false` to inspect the outputs instead. Requires the `scan` scope.
        """
)
@Plugin(
    examples = {
        @Example(
            title = "Fail the flow if a generated configuration file contains a secret",
            full = true,
            code = """
                id: gitguardian_scan_config
                namespace: company.security

                tasks:
                  - id: render_config
                    type: io.kestra.plugin.core.log.Log
                    message: "Rendering config"

                  - id: scan
                    type: io.kestra.plugin.gitguardian.scan.Scan
                    apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"
                    filename: application.yml
                    content: |
                      database:
                        url: jdbc:postgresql://db:5432/app
                        password: "{{ secret('DB_PASSWORD') }}"
                """
        ),
        @Example(
            title = "Scan files produced by previous tasks without failing, then alert on findings",
            full = true,
            code = """
                id: gitguardian_scan_outputs
                namespace: company.security

                tasks:
                  - id: export
                    type: io.kestra.plugin.core.storage.Write
                    content: "AWS_SECRET=example"
                    extension: .env

                  - id: scan
                    type: io.kestra.plugin.gitguardian.scan.Scan
                    apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"
                    apiUrl: https://api.eu1.gitguardian.com
                    files:
                      - "{{ outputs.export.uri }}"
                    failOnPolicyBreak: false

                  - id: alert
                    type: io.kestra.plugin.core.log.Log
                    runIf: "{{ outputs.scan.policyBreakCount > 0 }}"
                    message: "GitGuardian found {{ outputs.scan.policyBreakCount }} secret(s) in {{ outputs.scan.documentCount }} file(s)"
                """
        )
    },
    metrics = {
        @Metric(name = "policy.breaks", type = Counter.TYPE, description = "Number of policy breaks (secrets) found across all scanned documents."),
        @Metric(name = "documents", type = Counter.TYPE, description = "Number of documents scanned.")
    }
)
public class Scan extends AbstractGitGuardianTask implements RunnableTask<Scan.Output> {
    static final int MAX_DOCUMENTS_PER_REQUEST = 20;
    static final int MAX_DOCUMENT_BYTES = 1024 * 1024;
    private static final String SCOPE = "scan";

    @Schema(title = "Inline content to scan", description = "Scanned as one document named after `filename`. Use `files` to scan files from internal storage instead of, or in addition to, inline content.")
    @PluginProperty(group = "main")
    private Property<String> content;

    @Schema(title = "File name for the inline content", description = "Helps GitGuardian detectors that rely on file context (for example `.env` or `id_rsa`). Defaults to `content`.")
    @Builder.Default
    @PluginProperty(group = "main")
    private Property<String> filename = Property.ofValue("content");

    @Schema(title = "Internal storage files to scan", description = "List of `kestra://` URIs, typically outputs of previous tasks. Each file is scanned as one document named after the last segment of its URI and must be at most 1 MB.")
    @PluginProperty(group = "main")
    private Property<List<String>> files;

    @Schema(title = "Fail the task when at least one policy break is found", description = "Defaults to `true`. When `false`, the task succeeds and downstream tasks decide what to do with `policyBreakCount` and `results`.")
    @Builder.Default
    @PluginProperty(group = "execution")
    private Property<Boolean> failOnPolicyBreak = Property.ofValue(true);

    @Override
    public Output run(RunContext runContext) throws Exception {
        var documents = documents(runContext);
        if (documents.isEmpty()) {
            throw new IllegalArgumentException("Nothing to scan: set content, files, or both.");
        }

        var results = new ArrayList<ScanResult>();
        try (var client = client(runContext)) {
            if (documents.size() == 1) {
                var document = documents.getFirst();
                results.add(named(client.post("/scan", document, SCOPE, ScanResult.class), document));
            } else {
                for (int from = 0; from < documents.size(); from += MAX_DOCUMENTS_PER_REQUEST) {
                    var batch = documents.subList(from, Math.min(from + MAX_DOCUMENTS_PER_REQUEST, documents.size()));
                    var batchResults = client.postList("/multiscan", batch, SCOPE, ScanResult.class);
                    if (batchResults.size() != batch.size()) {
                        throw new IllegalStateException("GitGuardian returned %d scan results for %d documents.".formatted(batchResults.size(), batch.size()));
                    }
                    for (int i = 0; i < batch.size(); i++) {
                        results.add(named(batchResults.get(i), batch.get(i)));
                    }
                }
            }
        }

        var policyBreakCount = results.stream().mapToInt(result -> result.getPolicyBreakCount() != null ? result.getPolicyBreakCount() : 0).sum();
        runContext.metric(Counter.of("documents", results.size()));
        runContext.metric(Counter.of("policy.breaks", policyBreakCount));

        var logger = runContext.logger();
        for (var result : results) {
            for (var policyBreak : result.getPolicyBreaks() != null ? result.getPolicyBreaks() : List.<PolicyBreak>of()) {
                logger.warn("Policy break in '{}': {} ({}){}",
                    result.getFilename(),
                    policyBreak.getType(),
                    policyBreak.getValidity() != null ? policyBreak.getValidity().apiValue() : "unknown",
                    Boolean.TRUE.equals(policyBreak.getKnownSecret()) ? ", known incident " + policyBreak.getIncidentUrl() : ""
                );
            }
        }

        if (policyBreakCount > 0 && runContext.render(failOnPolicyBreak).as(Boolean.class).orElse(true)) {
            throw new IllegalStateException("GitGuardian found %d policy break(s) in %d document(s). Set failOnPolicyBreak to false to keep the flow running and inspect the outputs instead.".formatted(policyBreakCount, results.size()));
        }
        logger.info("GitGuardian scanned {} document(s) and found {} policy break(s)", results.size(), policyBreakCount);

        return Output.builder()
            .documentCount(results.size())
            .policyBreakCount(policyBreakCount)
            .results(results)
            .uri(store(runContext, results))
            .build();
    }

    private List<Map<String, String>> documents(RunContext runContext) throws Exception {
        var documents = new ArrayList<Map<String, String>>();

        var rContent = runContext.render(content).as(String.class).orElse(null);
        if (rContent != null) {
            var rFilename = runContext.render(filename).as(String.class).orElse("content");
            documents.add(document(rFilename, rContent));
        }

        for (var file : runContext.render(files).asList(String.class)) {
            var uri = URI.create(file);
            byte[] bytes;
            try (var inputStream = runContext.storage().getFile(uri)) {
                bytes = inputStream.readAllBytes();
            }
            documents.add(document(fileName(uri), new String(bytes, StandardCharsets.UTF_8)));
        }
        return documents;
    }

    private static Map<String, String> document(String name, String body) {
        var size = body.getBytes(StandardCharsets.UTF_8).length;
        if (size > MAX_DOCUMENT_BYTES) {
            throw new IllegalArgumentException("Document '%s' is %d bytes; GitGuardian scans documents of at most 1 MB. Split the content or scan a smaller file.".formatted(name, size));
        }
        var document = new LinkedHashMap<String, String>();
        document.put("filename", name);
        document.put("document", body);
        return document;
    }

    private static String fileName(URI uri) {
        var path = uri.getPath();
        if (path == null || path.isBlank()) {
            return "content";
        }
        var name = path.substring(path.lastIndexOf('/') + 1);
        return name.isBlank() ? "content" : name;
    }

    private static ScanResult named(ScanResult result, Map<String, String> document) {
        if (result == null) {
            throw new IllegalStateException("Empty response from the GitGuardian scan API for document '%s'.".formatted(document.get("filename")));
        }
        result.setFilename(document.get("filename"));
        return result;
    }

    private static URI store(RunContext runContext, List<ScanResult> results) throws Exception {
        var tempFile = runContext.workingDir().createTempFile(".ion").toFile();
        try (var writer = new BufferedWriter(new FileWriter(tempFile), FileSerde.BUFFER_SIZE);
             var sequenceWriter = FileSerde.createSequenceWriter(JacksonMapper.ofIon(), writer, new TypeReference<ScanResult>() {})) {
            FileSerde.writeAll(Flux.fromIterable(results), sequenceWriter).block();
        }
        return runContext.storage().putFile(tempFile);
    }

    @Builder
    @Getter
    public static class Output implements io.kestra.core.models.tasks.Output {
        @Schema(title = "Number of documents scanned")
        private final Integer documentCount;

        @Schema(title = "Total number of policy breaks (secrets) found across all documents")
        private final Integer policyBreakCount;

        @Schema(title = "Per-document scan results", description = "Includes detector, validity and match positions. Never includes the matched secret strings.")
        private final List<ScanResult> results;

        @Schema(title = "Internal storage URI of the results as an Amazon Ion file, one row per document")
        private final URI uri;
    }
}
