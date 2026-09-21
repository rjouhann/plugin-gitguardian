package io.kestra.plugin.gitguardian.scan;

import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import io.kestra.core.junit.annotations.KestraTest;
import io.kestra.core.models.property.Property;
import io.kestra.core.runners.RunContextFactory;
import io.kestra.core.utils.IdUtils;
import io.kestra.core.serializers.FileSerde;
import io.kestra.plugin.gitguardian.GitGuardianApiException;
import io.kestra.plugin.gitguardian.incidents.Validity;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;
import java.util.Map;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.matchingJsonPath;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;

@KestraTest
@WireMockTest
class ScanTest {
    private static final String CLEAN = """
        {"policy_break_count":0,"policies":["Secrets detection"],"policy_breaks":[]}
        """;
    private static final String ONE_BREAK = """
        {"policy_break_count":1,"policies":["Secrets detection"],"policy_breaks":[{"type":"AWS Keys","policy":"Secrets detection",
         "validity":"valid","known_secret":true,"incident_url":"https://dashboard.gitguardian.com/workspace/1/incidents/42",
         "matches":[{"type":"client_id","match":"AKIAEXAMPLE","index_start":10,"index_end":30,"line_start":1,"line_end":1}]}]}
        """;

    @Inject
    private RunContextFactory runContextFactory;

    @Test
    void singleDocumentUsesScanEndpointAndSucceedsWhenClean(WireMockRuntimeInfo wireMock) throws Exception {
        stubFor(post(urlPathEqualTo("/v1/scan"))
            .withHeader("Authorization", equalTo("Token test-key"))
            .withRequestBody(matchingJsonPath("$.filename", equalTo(".env")))
            .willReturn(okJson(CLEAN)));

        var output = task(wireMock)
            .content(Property.ofValue("FOO=bar"))
            .filename(Property.ofValue(".env"))
            .build()
            .run(runContextFactory.of(Map.of()));

        assertThat(output.getDocumentCount(), is(1));
        assertThat(output.getPolicyBreakCount(), is(0));
        assertThat(output.getResults().getFirst().getFilename(), is(".env"));
        assertThat(output.getUri(), notNullValue());
    }

    @Test
    void failsByDefaultOnPolicyBreakWithoutLeakingTheSecret(WireMockRuntimeInfo wireMock) {
        stubFor(post(urlPathEqualTo("/v1/scan")).willReturn(okJson(ONE_BREAK)));

        var task = task(wireMock).content(Property.ofValue("aws_key = AKIAEXAMPLE")).build();

        var exception = assertThrows(IllegalStateException.class, () -> task.run(runContextFactory.of(Map.of())));

        assertThat(exception.getMessage(), containsString("1 policy break(s) in 1 document(s)"));
        assertThat(exception.getMessage().contains("AKIAEXAMPLE"), is(false));
    }

    @Test
    void reportsPolicyBreaksWithoutFailingWhenAsked(WireMockRuntimeInfo wireMock) throws Exception {
        stubFor(post(urlPathEqualTo("/v1/scan")).willReturn(okJson(ONE_BREAK)));

        var output = task(wireMock)
            .content(Property.ofValue("aws_key = AKIAEXAMPLE"))
            .failOnPolicyBreak(Property.ofValue(false))
            .build()
            .run(runContextFactory.of(Map.of()));

        assertThat(output.getPolicyBreakCount(), is(1));
        var policyBreak = output.getResults().getFirst().getPolicyBreaks().getFirst();
        assertThat(policyBreak.getType(), is("AWS Keys"));
        assertThat(policyBreak.getValidity(), is(Validity.VALID));
        assertThat(policyBreak.getKnownSecret(), is(true));
        assertThat(policyBreak.getMatches().getFirst().getIndexStart(), is(10));
        assertThat(policyBreak.getMatches().getFirst().getType(), is("client_id"));
    }

    @Test
    void multipleDocumentsUseMultiscanAndNameResultsAfterFiles(WireMockRuntimeInfo wireMock) throws Exception {
        stubFor(post(urlPathEqualTo("/v1/multiscan"))
            .withRequestBody(matchingJsonPath("$[0].filename", equalTo("content")))
            .withRequestBody(matchingJsonPath("$[1].filename", equalTo("config.yml")))
            .willReturn(okJson("[" + CLEAN + "," + ONE_BREAK + "]")));

        var runContext = runContextFactory.of(Map.of());
        var file = runContext.workingDir().createFile("config.yml", "password: hunter2".getBytes(StandardCharsets.UTF_8)).toFile();
        var uri = runContext.storage().putFile(file, "config.yml");

        var output = task(wireMock)
            .content(Property.ofValue("clean"))
            .files(Property.ofValue(List.of(uri.toString())))
            .failOnPolicyBreak(Property.ofValue(false))
            .build()
            .run(runContext);

        assertThat(output.getDocumentCount(), is(2));
        assertThat(output.getPolicyBreakCount(), is(1));
        assertThat(output.getResults().get(1).getFilename(), is("config.yml"));
        assertThat(output.getResults().get(1).getPolicyBreakCount(), is(1));

        try (var reader = new BufferedReader(new InputStreamReader(runContext.storage().getFile(output.getUri())))) {
            assertThat(reader.lines().toList(), hasSize(2));
        }
        verify(0, postRequestedFor(urlPathEqualTo("/v1/scan")));
    }

    @Test
    void rejectsDocumentsOverOneMegabyte(WireMockRuntimeInfo wireMock) {
        var task = task(wireMock).content(Property.ofValue("x".repeat(Scan.MAX_DOCUMENT_BYTES + 1))).build();

        var exception = assertThrows(IllegalArgumentException.class, () -> task.run(runContextFactory.of(Map.of())));

        assertThat(exception.getMessage(), containsString("at most 1 MB"));
    }

    @Test
    void failsWithScopeHintOn403(WireMockRuntimeInfo wireMock) {
        stubFor(post(urlPathEqualTo("/v1/scan")).willReturn(aResponse().withStatus(403).withBody("{\"detail\":\"You do not have permission to perform this action.\"}")));

        var task = task(wireMock).content(Property.ofValue("FOO=bar")).build();

        var exception = assertThrows(GitGuardianApiException.class, () -> task.run(runContextFactory.of(Map.of())));

        assertThat(exception.getStatusCode(), is(403));
        assertThat(exception.getMessage(), containsString("'scan' scope"));
        assertThat(exception.getMessage(), containsString("You do not have permission"));
    }

    @Test
    void requiresSomethingToScan(WireMockRuntimeInfo wireMock) {
        var task = task(wireMock).build();

        var exception = assertThrows(IllegalArgumentException.class, () -> task.run(runContextFactory.of(Map.of())));

        assertThat(exception.getMessage(), containsString("Nothing to scan"));
    }

    private static Scan.ScanBuilder<?, ?> task(WireMockRuntimeInfo wireMock) {
        return Scan.builder()
            .id(IdUtils.create())
            .type(Scan.class.getName())
            .apiUrl(Property.ofValue(wireMock.getHttpBaseUrl()))
            .apiKey(Property.ofValue("test-key"));
    }
}
