package io.kestra.plugin.gitguardian.teams;

import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import io.kestra.core.junit.annotations.KestraTest;
import io.kestra.core.models.property.Property;
import io.kestra.core.models.tasks.common.FetchType;
import io.kestra.core.runners.RunContextFactory;
import io.kestra.core.utils.IdUtils;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

@KestraTest
@WireMockTest
class TeamsAndMembersTest {
    @Inject
    private RunContextFactory runContextFactory;

    @Test
    void teamsFetchOne(WireMockRuntimeInfo wireMock) throws Exception {
        stubFor(get(urlPathEqualTo("/v1/teams")).withQueryParam("search", equalTo("platform"))
            .willReturn(okJson("[{\"id\":3,\"name\":\"platform\",\"description\":\"Platform team\",\"is_global\":false,\"gitguardian_url\":\"https://dashboard/teams/3\"}]")));

        var output = List.builder()
            .id(IdUtils.create()).type(List.class.getName())
            .apiUrl(Property.ofValue(wireMock.getHttpBaseUrl())).apiKey(Property.ofValue("k"))
            .search(Property.ofValue("platform"))
            .fetchType(Property.ofValue(FetchType.FETCH_ONE))
            .build()
            .run(runContextFactory.of(Map.of()));

        assertThat(output.getRow().getId(), is(3L));
        assertThat(output.getRow().getGlobal(), is(false));
    }

    @Test
    void membersFilterActive(WireMockRuntimeInfo wireMock) throws Exception {
        stubFor(get(urlPathEqualTo("/v1/members")).withQueryParam("active", equalTo("true"))
            .willReturn(okJson("[{\"id\":5,\"name\":\"Alice\",\"email\":\"alice@company.com\",\"role\":\"manager\",\"access_level\":\"manager\",\"active\":true,\"created_at\":\"2026-01-01T00:00:00Z\",\"last_login\":null}]")));

        var output = io.kestra.plugin.gitguardian.members.List.builder()
            .id(IdUtils.create()).type(io.kestra.plugin.gitguardian.members.List.class.getName())
            .apiUrl(Property.ofValue(wireMock.getHttpBaseUrl())).apiKey(Property.ofValue("k"))
            .active(Property.ofValue(true))
            .build()
            .run(runContextFactory.of(Map.of()));

        assertThat(output.getRows().getFirst().getEmail(), is("alice@company.com"));
        assertThat(output.getRows().getFirst().getRole(), is("manager"));
    }
}
