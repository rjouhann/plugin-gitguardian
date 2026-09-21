package io.kestra.plugin.gitguardian.honeytokens;

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

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.matchingJsonPath;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

@KestraTest
@WireMockTest
class HoneytokensTest {
    @Inject
    private RunContextFactory runContextFactory;

    private static final String HONEYTOKEN = """
        {"id":"a1b2c3","name":"kestra-prod","description":"Placed in prod config","type":"AWS","status":"active","created_at":"2026-09-01T10:00:00Z",
         "gitguardian_url":"https://dashboard.gitguardian.com/workspace/1/honeytokens/a1b2c3","open_events_count":0,"creator_id":5,"tags":[],"custom_tags":[{"id":"x","key":"env","value":"prod"}]}
        """;

    @Test
    void createReturnsEncryptedTokenAndNeverThePlainValue(WireMockRuntimeInfo wireMock) throws Exception {
        var withToken = HONEYTOKEN.replace("\"tags\":[]", "\"tags\":[],\"token\":{\"access_token_id\":\"AKIA_FAKE_ID\",\"secret_key\":\"FAKE_SECRET_VALUE\"}");
        stubFor(post(urlPathEqualTo("/v1/honeytokens"))
            .withRequestBody(matchingJsonPath("$.name", equalTo("kestra-prod")))
            .withRequestBody(matchingJsonPath("$.type", equalTo("AWS")))
            .withRequestBody(matchingJsonPath("$.custom_tags[?(@.key == 'env' && @.value == 'prod')]"))
            .willReturn(aResponse().withStatus(201).withHeader("Content-Type", "application/json").withBody(withToken)));

        var output = Create.builder()
            .id(IdUtils.create()).type(Create.class.getName())
            .apiUrl(Property.ofValue(wireMock.getHttpBaseUrl())).apiKey(Property.ofValue("k"))
            .name(Property.ofValue("kestra-prod"))
            .honeytokenDescription(Property.ofValue("Placed in prod config"))
            .customTags(Property.ofValue(Map.of("env", "prod")))
            .build()
            .run(runContextFactory.of(Map.of()));

        assertThat(output.getHoneytoken().getId(), is("a1b2c3"));
        assertThat(output.getEncryptedToken(), notNullValue());
        assertThat(output.getEncryptedToken().getValue().contains("FAKE_SECRET_VALUE"), is(false));
        assertThat(output.getHoneytoken().toString().contains("FAKE_SECRET_VALUE"), is(false));
    }

    @Test
    void listNeverAsksForTokens(WireMockRuntimeInfo wireMock) throws Exception {
        stubFor(get(urlPathEqualTo("/v1/honeytokens"))
            .withQueryParam("status", equalTo("triggered"))
            .withQueryParam("show_token", equalTo("false"))
            .willReturn(okJson("[" + HONEYTOKEN + "]")));

        var output = List.builder()
            .id(IdUtils.create()).type(List.class.getName())
            .apiUrl(Property.ofValue(wireMock.getHttpBaseUrl())).apiKey(Property.ofValue("k"))
            .status(Property.ofValue("triggered"))
            .build()
            .run(runContextFactory.of(Map.of()));

        assertThat(output.getRows().getFirst().getCustomTags().getFirst().getValue(), is("prod"));
    }

    @Test
    void getAndRevoke(WireMockRuntimeInfo wireMock) throws Exception {
        stubFor(get(urlPathEqualTo("/v1/honeytokens/a1b2c3")).willReturn(okJson(HONEYTOKEN)));
        stubFor(post(urlPathEqualTo("/v1/honeytokens/a1b2c3/revoke")).willReturn(okJson(HONEYTOKEN.replace("\"status\":\"active\"", "\"status\":\"revoked\""))));

        var get = Get.builder()
            .id(IdUtils.create()).type(Get.class.getName())
            .apiUrl(Property.ofValue(wireMock.getHttpBaseUrl())).apiKey(Property.ofValue("k"))
            .honeytokenId(Property.ofValue("a1b2c3"))
            .build()
            .run(runContextFactory.of(Map.of()));
        assertThat(get.getHoneytoken().getName(), is("kestra-prod"));

        stubFor(post(urlPathEqualTo("/v1/honeytokens/a1b2c3/reset")).willReturn(okJson(HONEYTOKEN)));
        var reset = Reset.builder()
            .id(IdUtils.create()).type(Reset.class.getName())
            .apiUrl(Property.ofValue(wireMock.getHttpBaseUrl())).apiKey(Property.ofValue("k"))
            .honeytokenId(Property.ofValue("a1b2c3"))
            .build()
            .run(runContextFactory.of(Map.of()));
        assertThat(reset.getHoneytoken().getStatus(), is("active"));

        var revoke = Revoke.builder()
            .id(IdUtils.create()).type(Revoke.class.getName())
            .apiUrl(Property.ofValue(wireMock.getHttpBaseUrl())).apiKey(Property.ofValue("k"))
            .honeytokenId(Property.ofValue("a1b2c3"))
            .build()
            .run(runContextFactory.of(Map.of()));
        assertThat(revoke.getHoneytoken().getStatus(), is("revoked"));
    }

    @Test
    void triggerFiresPerEventWithHoneytokenDetails(WireMockRuntimeInfo wireMock) throws Exception {
        stubFor(get(urlPathEqualTo("/v1/honeytokens_events")).willReturn(okJson("""
            [{"id":"e1","honeytoken_id":"a1b2c3","triggered_at":"2099-01-01T10:00:00Z","status":"open","ip_address":"203.0.113.9","action":"GetCallerIdentity","gitguardian_url":"https://dashboard/e1","data":{"user_agent":"aws-cli"},"tags":[]}]
            """)));
        stubFor(get(urlPathEqualTo("/v1/honeytokens/a1b2c3")).withQueryParam("show_token", equalTo("false")).willReturn(okJson(HONEYTOKEN)));

        var trigger = Trigger.builder()
            .id(IdUtils.create()).type(Trigger.class.getName())
            .apiUrl(Property.ofValue(wireMock.getHttpBaseUrl())).apiKey(Property.ofValue("k"))
            .interval(Duration.ofMinutes(1))
            .build();
        var ctx = TestsUtils.mockTrigger(runContextFactory, trigger);

        assertThat(trigger.eval(ctx.getKey(), ctx.getValue().context()).isPresent(), is(false));

        var fired = trigger.eval(ctx.getKey(), ctx.getValue().context());
        assertThat(fired.isPresent(), is(true));
        var variables = fired.get().trigger().getVariables();
        assertThat(((Map<?, ?>) variables.get("event")).get("ipAddress"), is("203.0.113.9"));
        assertThat(((Map<?, ?>) variables.get("honeytoken")).get("name"), is("kestra-prod"));
        assertThat(((Map<?, ?>) variables.get("honeytoken")).get("token"), nullValue());

        assertThat(trigger.eval(ctx.getKey(), ctx.getValue().context()).isPresent(), is(false));
    }
}
