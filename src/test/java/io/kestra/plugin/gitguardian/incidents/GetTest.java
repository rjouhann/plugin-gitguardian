package io.kestra.plugin.gitguardian.incidents;

import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import io.kestra.core.junit.annotations.KestraTest;
import io.kestra.core.models.property.Property;
import io.kestra.core.runners.RunContextFactory;
import io.kestra.core.utils.IdUtils;
import io.kestra.plugin.gitguardian.GitGuardianApiException;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;

@KestraTest
@WireMockTest
class GetTest {
    @Inject
    private RunContextFactory runContextFactory;

    @Test
    void fetchesIncidentById(WireMockRuntimeInfo wireMock) throws Exception {
        stubFor(get(urlPathEqualTo("/v1/incidents/secrets/42"))
            .withQueryParam("with_occurrences", equalTo("0"))
            .willReturn(okJson(ListTest.incident(42, "2026-09-01T10:00:00Z"))));

        var output = Get.builder()
            .id(IdUtils.create())
            .type(Get.class.getName())
            .apiUrl(Property.ofValue(wireMock.getHttpBaseUrl()))
            .apiKey(Property.ofValue("test-key"))
            .incidentId(Property.ofValue(42L))
            .build()
            .run(runContextFactory.of(Map.of()));

        assertThat(output.getIncident().getId(), is(42L));
        assertThat(output.getIncident().getIncidentName(), is("AWS Keys - 42"));
        assertThat(output.getIncident().getRiskScore(), is(90));
    }

    @Test
    void mapsNotFoundToActionableError(WireMockRuntimeInfo wireMock) {
        stubFor(get(urlPathEqualTo("/v1/incidents/secrets/999"))
            .willReturn(aResponse().withStatus(404).withBody("{\"detail\":\"Not found.\"}")));

        var task = Get.builder()
            .id(IdUtils.create())
            .type(Get.class.getName())
            .apiUrl(Property.ofValue(wireMock.getHttpBaseUrl()))
            .apiKey(Property.ofValue("test-key"))
            .incidentId(Property.ofValue(999L))
            .build();

        var exception = assertThrows(GitGuardianApiException.class, () -> task.run(runContextFactory.of(Map.of())));

        assertThat(exception.getStatusCode(), is(404));
        assertThat(exception.getMessage(), containsString("HTTP 404: Not found."));
        assertThat(exception.getMessage(), containsString("Check the resource ID"));
    }
}
