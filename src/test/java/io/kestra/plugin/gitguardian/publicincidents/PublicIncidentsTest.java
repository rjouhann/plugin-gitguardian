package io.kestra.plugin.gitguardian.publicincidents;

import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import io.kestra.core.junit.annotations.KestraTest;
import io.kestra.core.models.property.Property;
import io.kestra.core.runners.RunContextFactory;
import io.kestra.core.utils.IdUtils;
import io.kestra.core.utils.TestsUtils;
import io.kestra.plugin.gitguardian.incidents.IncidentStatus;
import io.kestra.plugin.gitguardian.incidents.Severity;
import io.kestra.plugin.gitguardian.incidents.Validity;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Map;

import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.equalToJson;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.matchingJsonPath;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

@KestraTest
@WireMockTest
class PublicIncidentsTest {
    @Inject
    private RunContextFactory runContextFactory;

    static String incident(long id, String date) {
        return """
            {"id":%d,"incident_name":"GitHub Token - %d","date":"%s","triggered_at":"%s","status":"TRIGGERED","severity":"high","validity":"valid",
             "declarative_secret_status":"not_declared","occurrences_count":1,"risk_score":75,"gitguardian_url":"https://dashboard.gitguardian.com/workspace/1/public-incidents/%d",
             "detector":{"name":"github_token","display_name":"GitHub Token","nature":"specific","family":"token","detector_group_name":"github_token","detector_group_display_name":"GitHub Token"},
             "tags":["PUBLICLY_EXPOSED"],"custom_tags":[]}
            """.formatted(id, id, date, date, id);
    }

    private static String base(WireMockRuntimeInfo wireMock) {
        return wireMock.getHttpBaseUrl();
    }

    @Test
    void listUsesPublicEndpointAndFilters(WireMockRuntimeInfo wireMock) throws Exception {
        stubFor(get(urlPathEqualTo("/v1/public-incidents/secrets"))
            .withQueryParam("status", equalTo("TRIGGERED"))
            .withQueryParam("validity", equalTo("valid"))
            .withQueryParam("declarative_secret_status", equalTo("not_declared"))
            .willReturn(okJson("[" + incident(1, "2026-09-01T10:00:00Z") + "]")));

        var output = List.builder()
            .id(IdUtils.create()).type(List.class.getName()).apiUrl(Property.ofValue(base(wireMock))).apiKey(Property.ofValue("k"))
            .status(Property.ofValue(IncidentStatus.TRIGGERED))
            .validity(Property.ofValue(Validity.VALID))
            .declarativeSecretStatus(Property.ofValue("not_declared"))
            .build().run(runContextFactory.of(Map.of()));

        assertThat(output.getSize(), is(1L));
        assertThat(output.getRows().getFirst().getDeclarativeSecretStatus(), is("not_declared"));
        assertThat(output.getRows().getFirst().getSeverity(), is(Severity.HIGH));
    }

    @Test
    void getAssignIgnoreResolveReopenNote(WireMockRuntimeInfo wireMock) throws Exception {
        var ctx = runContextFactory.of(Map.of());
        stubFor(get(urlPathEqualTo("/v1/public-incidents/secrets/9")).willReturn(okJson(incident(9, "2026-09-01T10:00:00Z"))));
        stubFor(post(urlPathEqualTo("/v1/public-incidents/secrets/9/assign")).withRequestBody(equalToJson("{\"email\":\"oncall@company.com\"}"))
            .willReturn(okJson(incident(9, "2026-09-01T10:00:00Z").replace("\"status\":\"TRIGGERED\"", "\"status\":\"ASSIGNED\""))));
        stubFor(post(urlPathEqualTo("/v1/public-incidents/secrets/9/ignore")).withRequestBody(equalToJson("{\"ignore_reason\":\"false_positive,low_risk\"}"))
            .willReturn(okJson(incident(9, "2026-09-01T10:00:00Z").replace("\"status\":\"TRIGGERED\"", "\"status\":\"IGNORED\",\"ignore_reason\":\"false_positive,low_risk\""))));
        stubFor(post(urlPathEqualTo("/v1/public-incidents/secrets/9/resolve")).withRequestBody(equalToJson("{\"resolve_reason\":\"revoked\"}"))
            .willReturn(okJson(incident(9, "2026-09-01T10:00:00Z").replace("\"status\":\"TRIGGERED\"", "\"status\":\"RESOLVED\",\"resolve_reason\":\"revoked\""))));
        stubFor(post(urlPathEqualTo("/v1/public-incidents/secrets/9/reopen")).willReturn(okJson(incident(9, "2026-09-01T10:00:00Z"))));
        stubFor(post(urlPathEqualTo("/v1/public-incidents/secrets/9/notes")).willReturn(okJson("{\"id\":3,\"incident_id\":9,\"comment\":\"hi\",\"created_at\":\"2026-09-21T10:00:00Z\"}")));

        assertThat(Get.builder().id(IdUtils.create()).type(Get.class.getName()).apiUrl(Property.ofValue(base(wireMock))).apiKey(Property.ofValue("k")).incidentId(Property.ofValue(9L)).build().run(ctx).getIncident().getId(), is(9L));
        assertThat(Assign.builder().id(IdUtils.create()).type(Assign.class.getName()).apiUrl(Property.ofValue(base(wireMock))).apiKey(Property.ofValue("k")).incidentId(Property.ofValue(9L)).assigneeEmail(Property.ofValue("oncall@company.com")).build().run(ctx).getIncident().getStatus(), is(IncidentStatus.ASSIGNED));
        assertThat(Ignore.builder().id(IdUtils.create()).type(Ignore.class.getName()).apiUrl(Property.ofValue(base(wireMock))).apiKey(Property.ofValue("k")).incidentId(Property.ofValue(9L)).ignoreReasons(Property.ofValue(java.util.List.of("false_positive", "low_risk"))).build().run(ctx).getIncident().getIgnoreReason(), is("false_positive,low_risk"));
        assertThat(Resolve.builder().id(IdUtils.create()).type(Resolve.class.getName()).apiUrl(Property.ofValue(base(wireMock))).apiKey(Property.ofValue("k")).incidentId(Property.ofValue(9L)).resolveReasons(Property.ofValue(java.util.List.of("revoked"))).build().run(ctx).getIncident().getResolveReason(), is("revoked"));
        assertThat(Reopen.builder().id(IdUtils.create()).type(Reopen.class.getName()).apiUrl(Property.ofValue(base(wireMock))).apiKey(Property.ofValue("k")).incidentId(Property.ofValue(9L)).build().run(ctx).getIncident().getStatus(), is(IncidentStatus.TRIGGERED));
        assertThat(AddNote.builder().id(IdUtils.create()).type(AddNote.class.getName()).apiUrl(Property.ofValue(base(wireMock))).apiKey(Property.ofValue("k")).incidentId(Property.ofValue(9L)).comment(Property.ofValue("hi")).build().run(ctx).getNote().getId(), is(3L));
    }

    @Test
    void updateCallsSetSeverityThenSetCustomTags(WireMockRuntimeInfo wireMock) throws Exception {
        stubFor(post(urlPathEqualTo("/v1/public-incidents/secrets/9/set_severity")).withRequestBody(equalToJson("{\"severity\":\"critical\"}"))
            .willReturn(okJson(incident(9, "2026-09-01T10:00:00Z").replace("\"severity\":\"high\"", "\"severity\":\"critical\""))));
        stubFor(post(urlPathEqualTo("/v1/public-incidents/secrets/9/set_custom_tags")).withRequestBody(matchingJsonPath("$.custom_tags[?(@.key == 'team' && @.value == 'platform')]"))
            .willReturn(okJson(incident(9, "2026-09-01T10:00:00Z").replace("\"severity\":\"high\"", "\"severity\":\"critical\"").replace("\"custom_tags\":[]", "\"custom_tags\":[{\"id\":\"1\",\"key\":\"team\",\"value\":\"platform\"}]"))));

        var output = Update.builder()
            .id(IdUtils.create()).type(Update.class.getName()).apiUrl(Property.ofValue(base(wireMock))).apiKey(Property.ofValue("k"))
            .incidentId(Property.ofValue(9L))
            .severity(Property.ofValue(Severity.CRITICAL))
            .customTags(Property.ofValue(Map.of("team", "platform")))
            .build().run(runContextFactory.of(Map.of()));

        assertThat(output.getIncident().getSeverity(), is(Severity.CRITICAL));
        assertThat(output.getIncident().getCustomTags().getFirst().getValue(), is("platform"));
    }

    @Test
    void triggerFiresOnNewPublicIncident(WireMockRuntimeInfo wireMock) throws Exception {
        stubFor(get(urlPathEqualTo("/v1/public-incidents/secrets")).withQueryParam("ordering", equalTo("-date"))
            .willReturn(okJson("[" + incident(1, "2026-09-01T10:00:00Z") + "]")));
        stubFor(get(urlPathEqualTo("/v1/public-incidents/secrets")).withQueryParam("ordering", equalTo("date"))
            .willReturn(okJson("[" + incident(1, "2026-09-01T10:00:00Z") + "," + incident(2, "2026-09-01T10:10:00Z") + "]")));

        var trigger = Trigger.builder()
            .id(IdUtils.create()).type(Trigger.class.getName()).apiUrl(Property.ofValue(base(wireMock))).apiKey(Property.ofValue("k"))
            .validity(Property.ofValue(Validity.VALID)).interval(Duration.ofMinutes(2)).build();
        var ctx = TestsUtils.mockTrigger(runContextFactory, trigger);

        assertThat(trigger.eval(ctx.getKey(), ctx.getValue().context()).isPresent(), is(false));
        var fired = trigger.eval(ctx.getKey(), ctx.getValue().context());
        assertThat(fired.isPresent(), is(true));
        assertThat(((Map<?, ?>) fired.get().trigger().getVariables().get("incident")).get("id"), is(2L));
        assertThat(trigger.eval(ctx.getKey(), ctx.getValue().context()).isPresent(), is(false));
    }
}
