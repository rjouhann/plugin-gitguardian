package io.kestra.plugin.gitguardian.healthchecks;

import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import io.kestra.core.junit.annotations.KestraTest;
import io.kestra.core.models.property.Property;
import io.kestra.core.runners.RunContextFactory;
import io.kestra.core.utils.IdUtils;
import io.kestra.core.utils.TestsUtils;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Map;

import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;

@KestraTest
@WireMockTest
class HealthChecksTest {
    @Inject
    private RunContextFactory runContextFactory;

    static String check(long id, long instanceId, String status, String firstStartedAt, String type) {
        return """
            {"id":%d,"status":"%s","started_at":"%s","first_started_at":"%s","type":"%s","instance":{"id":%d,"name":"company/%s","url":"https://github.com/company","status":"active"},
             "results":[{"kind":"api_access_rights","status":"%s","error_code":403,"error_message":"Insufficient permissions"}],"last_successful_check_date":"2026-08-01T00:00:00Z"}
            """.formatted(id, status, firstStartedAt, firstStartedAt, type, instanceId, type, status);
    }

    @Test
    void listMapsNestedInstanceAndResults(WireMockRuntimeInfo wireMock) throws Exception {
        stubFor(get(urlPathEqualTo("/v1/health-checks"))
            .withQueryParam("status", equalTo("fail"))
            .withQueryParam("type", equalTo("github-installation"))
            .willReturn(okJson("[" + check(1, 100, "fail", "2026-09-01T10:00:00Z", "github-installation") + "]")));

        var output = List.builder()
            .id(IdUtils.create()).type(List.class.getName())
            .apiUrl(Property.ofValue(wireMock.getHttpBaseUrl())).apiKey(Property.ofValue("k"))
            .status(Property.ofValue(HealthCheckStatus.FAIL))
            .integrationType(Property.ofValue("github-installation"))
            .build()
            .run(runContextFactory.of(Map.of()));

        var check = output.getRows().getFirst();
        assertThat(check.getStatus(), is(HealthCheckStatus.FAIL));
        assertThat(check.getInstance().getId(), is(100L));
        assertThat(check.getResults().getFirst().getErrorCode(), is(403));
    }

    @Test
    void runEnqueuesCheck(WireMockRuntimeInfo wireMock) throws Exception {
        stubFor(post(urlPathEqualTo("/v1/health-checks/github-installation/100/trigger"))
            .willReturn(okJson("{\"detail\":\"Health check enqueued.\",\"result_url\":\"https://api.gitguardian.com/v1/health-checks/github-installation/100?started_at_after=2026-09-21T10:00:00Z\"}")));

        var output = Run.builder()
            .id(IdUtils.create()).type(Run.class.getName())
            .apiUrl(Property.ofValue(wireMock.getHttpBaseUrl())).apiKey(Property.ofValue("k"))
            .integrationType(Property.ofValue("github-installation"))
            .instanceId(Property.ofValue(100L))
            .build()
            .run(runContextFactory.of(Map.of()));

        assertThat(output.getDetail(), is("Health check enqueued."));
        assertThat(output.getResultUrl().contains("started_at_after"), is(true));
    }

    @Test
    void triggerFiresOncePerFailureStreak(WireMockRuntimeInfo wireMock) throws Exception {
        stubFor(get(urlPathEqualTo("/v1/health-checks")).withQueryParam("status", equalTo("fail"))
            .willReturn(okJson("[" + check(1, 100, "fail", "2099-01-01T10:00:00Z", "github-installation") + "," + check(2, 200, "fail", "2099-01-01T09:00:00Z", "slack-workspace") + "]")));

        var trigger = Trigger.builder()
            .id(IdUtils.create()).type(Trigger.class.getName())
            .apiUrl(Property.ofValue(wireMock.getHttpBaseUrl())).apiKey(Property.ofValue("k"))
            .types(Property.ofValue(java.util.List.of("github-installation")))
            .interval(Duration.ofMinutes(10))
            .build();
        var ctx = TestsUtils.mockTrigger(runContextFactory, trigger);

        assertThat(trigger.eval(ctx.getKey(), ctx.getValue().context()).isPresent(), is(false));

        var fired = trigger.eval(ctx.getKey(), ctx.getValue().context());
        assertThat(fired.isPresent(), is(true));
        var checks = (java.util.List<?>) fired.get().trigger().getVariables().get("checks");
        assertThat(checks, hasSize(1));
        assertThat(((Map<?, ?>) ((Map<?, ?>) checks.getFirst()).get("instance")).get("id"), is(100L));

        stubFor(get(urlPathEqualTo("/v1/health-checks")).withQueryParam("status", equalTo("fail"))
            .willReturn(okJson("[" + check(3, 100, "fail", "2099-01-01T10:00:00Z", "github-installation") + "]")));
        assertThat("same streak, new run id, must not re-fire", trigger.eval(ctx.getKey(), ctx.getValue().context()).isPresent(), is(false));
    }
}
