package io.kestra.plugin.gitguardian.incidents;

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
import static com.github.tomakehurst.wiremock.client.WireMock.equalToJson;
import static com.github.tomakehurst.wiremock.client.WireMock.matchingJsonPath;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.patch;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;

@KestraTest
@WireMockTest
class IncidentActionsTest {
    @Inject
    private RunContextFactory runContextFactory;

    @Test
    void assignByEmailNotifies(WireMockRuntimeInfo wireMock) throws Exception {
        stubFor(post(urlPathEqualTo("/v1/incidents/secrets/42/assign"))
            .withQueryParam("send_email", equalTo("true"))
            .withRequestBody(equalToJson("{\"email\":\"oncall@company.com\"}"))
            .willReturn(okJson(ListTest.incident(42, "2026-09-01T10:00:00Z").replace("\"status\":\"TRIGGERED\"", "\"status\":\"ASSIGNED\",\"assignee_email\":\"oncall@company.com\""))));

        var output = Assign.builder()
            .id(IdUtils.create()).type(Assign.class.getName())
            .apiUrl(Property.ofValue(wireMock.getHttpBaseUrl())).apiKey(Property.ofValue("k"))
            .incidentId(Property.ofValue(42L))
            .assigneeEmail(Property.ofValue("oncall@company.com"))
            .build()
            .run(runContextFactory.of(Map.of()));

        assertThat(output.getIncident().getStatus(), is(IncidentStatus.ASSIGNED));
        assertThat(output.getIncident().getAssigneeEmail(), is("oncall@company.com"));
    }

    @Test
    void assignRequiresExactlyOneAssignee(WireMockRuntimeInfo wireMock) {
        var task = Assign.builder()
            .id(IdUtils.create()).type(Assign.class.getName())
            .apiUrl(Property.ofValue(wireMock.getHttpBaseUrl())).apiKey(Property.ofValue("k"))
            .incidentId(Property.ofValue(42L))
            .build();

        var exception = assertThrows(IllegalArgumentException.class, () -> task.run(runContextFactory.of(Map.of())));

        assertThat(exception.getMessage(), containsString("exactly one of assigneeEmail or assigneeMemberId"));
    }

    @Test
    void resolveSendsSecretRevoked(WireMockRuntimeInfo wireMock) throws Exception {
        stubFor(post(urlPathEqualTo("/v1/incidents/secrets/42/resolve"))
            .withRequestBody(equalToJson("{\"secret_revoked\":true}"))
            .willReturn(okJson(ListTest.incident(42, "2026-09-01T10:00:00Z").replace("\"status\":\"TRIGGERED\"", "\"status\":\"RESOLVED\",\"secret_revoked\":true"))));

        var output = Resolve.builder()
            .id(IdUtils.create()).type(Resolve.class.getName())
            .apiUrl(Property.ofValue(wireMock.getHttpBaseUrl())).apiKey(Property.ofValue("k"))
            .incidentId(Property.ofValue(42L))
            .secretRevoked(Property.ofValue(true))
            .build()
            .run(runContextFactory.of(Map.of()));

        assertThat(output.getIncident().getStatus(), is(IncidentStatus.RESOLVED));
        assertThat(output.getIncident().getSecretRevoked(), is(true));
    }

    @Test
    void ignoreSendsLowercaseReason(WireMockRuntimeInfo wireMock) throws Exception {
        stubFor(post(urlPathEqualTo("/v1/incidents/secrets/42/ignore"))
            .withRequestBody(equalToJson("{\"ignore_reason\":\"test_credential\"}"))
            .willReturn(okJson(ListTest.incident(42, "2026-09-01T10:00:00Z").replace("\"status\":\"TRIGGERED\"", "\"status\":\"IGNORED\",\"ignore_reason\":\"test_credential\""))));

        var output = Ignore.builder()
            .id(IdUtils.create()).type(Ignore.class.getName())
            .apiUrl(Property.ofValue(wireMock.getHttpBaseUrl())).apiKey(Property.ofValue("k"))
            .incidentId(Property.ofValue(42L))
            .ignoreReason(Property.ofValue(IgnoreReason.TEST_CREDENTIAL))
            .build()
            .run(runContextFactory.of(Map.of()));

        assertThat(output.getIncident().getStatus(), is(IncidentStatus.IGNORED));
        assertThat(output.getIncident().getIgnoreReason(), is("test_credential"));
    }

    @Test
    void reopenPostsWithoutBody(WireMockRuntimeInfo wireMock) throws Exception {
        stubFor(post(urlPathEqualTo("/v1/incidents/secrets/42/reopen"))
            .willReturn(okJson(ListTest.incident(42, "2026-09-01T10:00:00Z"))));

        var output = Reopen.builder()
            .id(IdUtils.create()).type(Reopen.class.getName())
            .apiUrl(Property.ofValue(wireMock.getHttpBaseUrl())).apiKey(Property.ofValue("k"))
            .incidentId(Property.ofValue(42L))
            .build()
            .run(runContextFactory.of(Map.of()));

        assertThat(output.getIncident().getStatus(), is(IncidentStatus.TRIGGERED));
    }

    @Test
    void addNoteReturnsCreatedNote(WireMockRuntimeInfo wireMock) throws Exception {
        stubFor(post(urlPathEqualTo("/v1/incidents/secrets/42/notes"))
            .withRequestBody(equalToJson("{\"comment\":\"Handled by Kestra\"}"))
            .willReturn(okJson("""
                {"id":7,"incident_id":42,"member_id":null,"api_token":"Demo Kestra","created_at":"2026-09-21T10:00:00Z","comment":"Handled by Kestra"}
                """)));

        var output = AddNote.builder()
            .id(IdUtils.create()).type(AddNote.class.getName())
            .apiUrl(Property.ofValue(wireMock.getHttpBaseUrl())).apiKey(Property.ofValue("k"))
            .incidentId(Property.ofValue(42L))
            .comment(Property.ofValue("Handled by Kestra"))
            .build()
            .run(runContextFactory.of(Map.of()));

        assertThat(output.getNote().getId(), is(7L));
        assertThat(output.getNote().getIncidentId(), is(42L));
        assertThat(output.getNote().getApiToken(), is("Demo Kestra"));
    }

    @Test
    void updatePatchesSeverityAndCustomTags(WireMockRuntimeInfo wireMock) throws Exception {
        stubFor(patch(urlPathEqualTo("/v1/incidents/secrets/42"))
            .withRequestBody(matchingJsonPath("$.severity", equalTo("critical")))
            .withRequestBody(matchingJsonPath("$.custom_tags[?(@.key == 'team' && @.value == 'platform')]"))
            .withRequestBody(matchingJsonPath("$.custom_tags[?(@.key == 'reviewed')]"))
            .willReturn(okJson(ListTest.incident(42, "2026-09-01T10:00:00Z"))));

        var output = Update.builder()
            .id(IdUtils.create()).type(Update.class.getName())
            .apiUrl(Property.ofValue(wireMock.getHttpBaseUrl())).apiKey(Property.ofValue("k"))
            .incidentId(Property.ofValue(42L))
            .severity(Property.ofValue(Severity.CRITICAL))
            .customTags(Property.ofValue(new java.util.LinkedHashMap<>(Map.of("team", "platform", "reviewed", ""))))
            .build()
            .run(runContextFactory.of(Map.of()));

        assertThat(output.getIncident().getId(), is(42L));
    }

    @Test
    void updateRequiresAChange(WireMockRuntimeInfo wireMock) {
        var task = Update.builder()
            .id(IdUtils.create()).type(Update.class.getName())
            .apiUrl(Property.ofValue(wireMock.getHttpBaseUrl())).apiKey(Property.ofValue("k"))
            .incidentId(Property.ofValue(42L))
            .build();

        var exception = assertThrows(IllegalArgumentException.class, () -> task.run(runContextFactory.of(Map.of())));

        assertThat(exception.getMessage(), containsString("Set severity, customTags, or both"));
    }
}
