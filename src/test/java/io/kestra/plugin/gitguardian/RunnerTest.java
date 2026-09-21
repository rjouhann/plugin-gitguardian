package io.kestra.plugin.gitguardian;

import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import io.kestra.core.junit.annotations.ExecuteFlow;
import io.kestra.core.junit.annotations.KestraTest;
import io.kestra.core.models.executions.Execution;
import io.kestra.core.models.flows.State;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;

@KestraTest(startRunner = true)
@WireMockTest(httpPort = 18099)
class RunnerTest {
    @BeforeEach
    void stubs() {
        stubFor(post(urlPathEqualTo("/v1/scan")).willReturn(okJson("""
            {"policy_break_count":0,"policies":["Secrets detection"],"policy_breaks":[]}
            """)));
        stubFor(get(urlPathEqualTo("/v1/incidents/secrets")).willReturn(okJson("""
            [{"id":1,"incident_name":"AWS Keys - 1","date":"2026-09-01T10:00:00Z","status":"TRIGGERED","severity":"critical","validity":"valid"}]
            """)));
    }

    @Test
    @ExecuteFlow("flows/sanity-checks/gitguardian_scan.yaml")
    void gitguardian_scan(Execution execution) {
        assertThat(execution.getTaskRunList(), hasSize(2));
        assertThat(execution.getState().getCurrent(), is(State.Type.SUCCESS));
    }

    @Test
    @ExecuteFlow("flows/sanity-checks/gitguardian_webhook_receive.yaml")
    void gitguardian_webhook_receive(Execution execution) {
        assertThat(execution.getTaskRunList(), hasSize(2));
        assertThat(execution.getState().getCurrent(), is(State.Type.SUCCESS));
    }

    @Test
    @ExecuteFlow("flows/sanity-checks/gitguardian_list_incidents.yaml")
    void gitguardian_list_incidents(Execution execution) {
        assertThat(execution.getTaskRunList(), hasSize(2));
        assertThat(execution.getState().getCurrent(), is(State.Type.SUCCESS));
    }
}
