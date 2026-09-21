package io.kestra.plugin.gitguardian.sources;

import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import io.kestra.core.junit.annotations.KestraTest;
import io.kestra.core.models.property.Property;
import io.kestra.core.runners.RunContextFactory;
import io.kestra.core.utils.IdUtils;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.equalToJson;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

@KestraTest
@WireMockTest
class SourcesTest {
    @Inject
    private RunContextFactory runContextFactory;

    private static final String SOURCE = """
        {"id":7,"url":"https://github.com/company/api","type":"github","full_name":"company/api","health":"at_risk","visibility":"private",
         "source_criticality":"critical","monitoring_status":"active","default_branch":"main","external_id":"123","open_incidents_count":3,
         "closed_incidents_count":10,"last_scan":{"date":"2026-09-01T10:00:00Z","status":"finished","failing_reason":""},"deleted":false}
        """;

    @Test
    void listFiltersServerSide(WireMockRuntimeInfo wireMock) throws Exception {
        stubFor(get(urlPathEqualTo("/v1/sources"))
            .withQueryParam("health", equalTo("at_risk"))
            .withQueryParam("source_criticality", equalTo("critical"))
            .withQueryParam("monitoring_status__in", equalTo("active,unreachable"))
            .willReturn(okJson("[" + SOURCE + "]")));

        var output = List.builder()
            .id(IdUtils.create()).type(List.class.getName())
            .apiUrl(Property.ofValue(wireMock.getHttpBaseUrl())).apiKey(Property.ofValue("k"))
            .health(Property.ofValue("at_risk"))
            .sourceCriticality(Property.ofValue("critical"))
            .monitoringStatuses(Property.ofValue(java.util.List.of("active", "unreachable")))
            .build()
            .run(runContextFactory.of(Map.of()));

        assertThat(output.getRows().getFirst().getFullName(), is("company/api"));
        assertThat(output.getRows().getFirst().getLastScan().get("status"), is("finished"));
    }

    @Test
    void getReturnsSource(WireMockRuntimeInfo wireMock) throws Exception {
        stubFor(get(urlPathEqualTo("/v1/sources/7")).willReturn(okJson(SOURCE)));

        var output = Get.builder()
            .id(IdUtils.create()).type(Get.class.getName())
            .apiUrl(Property.ofValue(wireMock.getHttpBaseUrl())).apiKey(Property.ofValue("k"))
            .sourceId(Property.ofValue(7L))
            .build()
            .run(runContextFactory.of(Map.of()));

        assertThat(output.getSource().getOpenIncidentsCount(), is(3));
    }

    @Test
    void scanPostsSourceIdsAndAccepts202(WireMockRuntimeInfo wireMock) throws Exception {
        stubFor(post(urlPathEqualTo("/v1/sources/scans"))
            .withRequestBody(equalToJson("{\"source_ids\":[7,8]}"))
            .willReturn(aResponse().withStatus(202)));

        var output = Scan.builder()
            .id(IdUtils.create()).type(Scan.class.getName())
            .apiUrl(Property.ofValue(wireMock.getHttpBaseUrl())).apiKey(Property.ofValue("k"))
            .sourceIds(Property.ofValue(java.util.List.of(7L, 8L)))
            .build()
            .run(runContextFactory.of(Map.of()));

        assertThat(output.getRequestedCount(), is(2));
    }

    @Test
    void createCustomSourceReturnsUuid(WireMockRuntimeInfo wireMock) throws Exception {
        stubFor(post(urlPathEqualTo("/v1/sources/custom-sources"))
            .withRequestBody(equalToJson("{\"name\":\"warehouse\",\"description\":\"Nightly exports\"}"))
            .willReturn(aResponse().withStatus(201).withHeader("Content-Type", "application/json")
                .withBody("{\"id\":\"9\",\"source_uuid\":\"550e8400-e29b-41d4-a716-446655440000\",\"name\":\"warehouse\",\"description\":\"Nightly exports\",\"use_only_detectors_with_validators\":false}")));

        var output = CreateCustomSource.builder()
            .id(IdUtils.create()).type(CreateCustomSource.class.getName())
            .apiUrl(Property.ofValue(wireMock.getHttpBaseUrl())).apiKey(Property.ofValue("k"))
            .name(Property.ofValue("warehouse"))
            .sourceDescription(Property.ofValue("Nightly exports"))
            .build()
            .run(runContextFactory.of(Map.of()));

        assertThat(output.getSource().getSourceUuid(), is("550e8400-e29b-41d4-a716-446655440000"));
    }
}
