package io.kestra.plugin.gitguardian.scan;

import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import io.kestra.core.junit.annotations.KestraTest;
import io.kestra.core.models.property.Property;
import io.kestra.core.runners.RunContextFactory;
import io.kestra.core.utils.IdUtils;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.matchingJsonPath;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

@KestraTest
@WireMockTest
class CreateIncidentsTest {
    @Inject
    private RunContextFactory runContextFactory;

    @Test
    void batchesBySizeNotByCount() {
        var small = new java.util.LinkedHashMap<String, Object>(Map.of("filename", "a", "document", "x".repeat(400 * 1024)));
        var documents = java.util.List.<Map<String, Object>>of(small, small, small, small, small);

        var batches = CreateIncidents.batches(documents);

        assertThat(batches.size(), is(3));
        assertThat(batches.get(0).size(), is(2));
        assertThat(batches.get(2).size(), is(1));
    }

    @Test
    void sendsSourceUuidAndLocationAndMapsObjectResponse(WireMockRuntimeInfo wireMock) throws Exception {
        stubFor(post(urlPathEqualTo("/v1/scan/create-incidents"))
            .withRequestBody(matchingJsonPath("$.source_uuid", equalTo("550e8400-e29b-41d4-a716-446655440000")))
            .withRequestBody(matchingJsonPath("$.documents[0].filename", equalTo("tickets.csv")))
            .withRequestBody(matchingJsonPath("$.documents[0].location.url", equalTo("https://warehouse/tickets")))
            .willReturn(okJson("""
                {"policy_break_count":1,"policies":["Secrets detection"],"policy_breaks":[{"type":"Slack Bot Token","policy":"Secrets detection","validity":"valid","known_secret":false,"matches":[{"type":"apikey","match":"xoxb","index_start":4,"index_end":9,"line_start":1,"line_end":1}]}]}
                """)));

        var output = CreateIncidents.builder()
            .id(IdUtils.create()).type(CreateIncidents.class.getName())
            .apiUrl(Property.ofValue(wireMock.getHttpBaseUrl())).apiKey(Property.ofValue("k"))
            .sourceUuid(Property.ofValue("550e8400-e29b-41d4-a716-446655440000"))
            .filename(Property.ofValue("tickets.csv"))
            .content(Property.ofValue("id,notes\n1,token xoxb-example"))
            .locationUrl(Property.ofValue("https://warehouse/tickets"))
            .build()
            .run(runContextFactory.of(Map.of()));

        assertThat(output.getDocumentCount(), is(1));
        assertThat(output.getPolicyBreakCount(), is(1));
        assertThat(output.getResults().getFirst().getFilename(), is("tickets.csv"));
        assertThat(output.getResults().getFirst().getPolicyBreaks().getFirst().getType(), is("Slack Bot Token"));
    }
}
