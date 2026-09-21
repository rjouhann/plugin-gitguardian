package io.kestra.plugin.gitguardian.incidents;

import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import io.kestra.core.junit.annotations.KestraTest;
import io.kestra.core.models.property.Property;
import io.kestra.core.models.tasks.common.FetchType;
import io.kestra.core.runners.RunContextFactory;
import io.kestra.core.utils.IdUtils;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Map;

import static com.github.tomakehurst.wiremock.client.WireMock.absent;
import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;

@KestraTest
@WireMockTest
class ListTest {
    @Inject
    private RunContextFactory runContextFactory;

    @Test
    void passesFiltersServerSideAndMapsIncidents(WireMockRuntimeInfo wireMock) throws Exception {
        stubFor(get(urlPathEqualTo("/v1/incidents/secrets"))
            .withQueryParam("status", equalTo("TRIGGERED"))
            .withQueryParam("severity", equalTo("critical"))
            .withQueryParam("validity", equalTo("valid"))
            .withQueryParam("tags", equalTo("PUBLICLY_EXPOSED,FROM_HISTORICAL_SCAN"))
            .withQueryParam("ordering", equalTo("-date"))
            .withQueryParam("per_page", equalTo("100"))
            .willReturn(okJson("[" + incident(1, "2026-09-01T10:00:00Z") + "]")));

        var output = task(wireMock)
            .status(Property.ofValue(IncidentStatus.TRIGGERED))
            .severity(Property.ofValue(Severity.CRITICAL))
            .validity(Property.ofValue(Validity.VALID))
            .tags(Property.ofValue(java.util.List.of("PUBLICLY_EXPOSED", "FROM_HISTORICAL_SCAN")))
            .ordering(Property.ofValue("-date"))
            .build()
            .run(runContextFactory.of(Map.of()));

        assertThat(output.getSize(), is(1L));
        var incident = output.getRows().getFirst();
        assertThat(incident.getId(), is(1L));
        assertThat(incident.getStatus(), is(IncidentStatus.TRIGGERED));
        assertThat(incident.getSeverity(), is(Severity.CRITICAL));
        assertThat(incident.getDetector().getDisplayName(), is("AWS Keys"));
        assertThat(incident.getCustomTags().getFirst().getKey(), is("env"));
    }

    @Test
    void followsLinkHeaderCursorAcrossPages(WireMockRuntimeInfo wireMock) throws Exception {
        stubFor(get(urlPathEqualTo("/v1/incidents/secrets"))
            .withQueryParam("cursor", absent())
            .willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withHeader("Link", "<" + wireMock.getHttpBaseUrl() + "/v1/incidents/secrets?cursor=cD0xNTA%3D&per_page=1>; rel=\"next\"")
                .withBody("[" + incident(1, "2026-09-01T10:00:00Z") + "]")));
        stubFor(get(urlPathEqualTo("/v1/incidents/secrets"))
            .withQueryParam("cursor", equalTo("cD0xNTA="))
            .willReturn(okJson("[" + incident(2, "2026-09-02T10:00:00Z") + "]")));

        var output = task(wireMock).perPage(Property.ofValue(1)).build().run(runContextFactory.of(Map.of()));

        assertThat(output.getRows(), hasSize(2));
        assertThat(output.getRows().get(1).getId(), is(2L));
    }

    @Test
    void stopsPaginatingAtMaxResults(WireMockRuntimeInfo wireMock) throws Exception {
        stubFor(get(urlPathEqualTo("/v1/incidents/secrets"))
            .willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withHeader("Link", "<" + wireMock.getHttpBaseUrl() + "/v1/incidents/secrets?cursor=next>; rel=\"next\"")
                .withBody("[" + incident(1, "2026-09-01T10:00:00Z") + "," + incident(2, "2026-09-02T10:00:00Z") + "," + incident(3, "2026-09-03T10:00:00Z") + "]")));

        var output = task(wireMock).maxResults(Property.ofValue(2)).build().run(runContextFactory.of(Map.of()));

        assertThat(output.getRows(), hasSize(2));
        assertThat(output.getSize(), is(2L));
        verify(1, getRequestedFor(urlPathEqualTo("/v1/incidents/secrets")));
    }

    @Test
    void fetchOneReturnsFirstRowOnly(WireMockRuntimeInfo wireMock) throws Exception {
        stubFor(get(urlPathEqualTo("/v1/incidents/secrets"))
            .willReturn(okJson("[" + incident(7, "2026-09-01T10:00:00Z") + "," + incident(8, "2026-09-02T10:00:00Z") + "]")));

        var output = task(wireMock).fetchType(Property.ofValue(FetchType.FETCH_ONE)).build().run(runContextFactory.of(Map.of()));

        assertThat(output.getRow().getId(), is(7L));
        assertThat(output.getRows(), nullValue());
        assertThat(output.getSize(), is(1L));
    }

    @Test
    void storeWritesOneIonRowPerIncident(WireMockRuntimeInfo wireMock) throws Exception {
        stubFor(get(urlPathEqualTo("/v1/incidents/secrets"))
            .willReturn(okJson("[" + incident(1, "2026-09-01T10:00:00Z") + "," + incident(2, "2026-09-02T10:00:00Z") + "]")));

        var runContext = runContextFactory.of(Map.of());
        var output = task(wireMock).fetchType(Property.ofValue(FetchType.STORE)).build().run(runContext);

        assertThat(output.getSize(), is(2L));
        assertThat(output.getRows(), nullValue());
        try (var reader = new BufferedReader(new InputStreamReader(runContext.storage().getFile(output.getUri())))) {
            assertThat(reader.lines().toList(), hasSize(2));
        }
    }

    static String incident(long id, String date) {
        return """
            {"id":%d,"incident_name":"AWS Keys - %d","date":"%s","triggered_at":"%s","status":"TRIGGERED","severity":"critical",
             "validity":"valid","risk_score":90,"regression":false,"occurrences_count":2,"gitguardian_url":"https://dashboard.gitguardian.com/workspace/1/incidents/%d",
             "detector":{"name":"aws_iam","display_name":"AWS Keys","nature":"specific","family":"apikey","detector_group_name":"aws_iam","detector_group_display_name":"AWS Keys"},
             "tags":["PUBLICLY_EXPOSED"],"custom_tags":[{"id":"d45a123f-b15d-4fea-abf6-ff2a8479de5b","key":"env","value":"prod"}],
             "secret_hash":"ignored","occurrences":[{"id":1}],"some_future_field":true}
            """.formatted(id, id, date, date, id);
    }

    private static List.ListBuilder<?, ?> task(WireMockRuntimeInfo wireMock) {
        return List.builder()
            .id(IdUtils.create())
            .type(List.class.getName())
            .apiUrl(Property.ofValue(wireMock.getHttpBaseUrl()))
            .apiKey(Property.ofValue("test-key"));
    }
}
