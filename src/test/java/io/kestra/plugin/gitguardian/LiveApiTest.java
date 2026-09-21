package io.kestra.plugin.gitguardian;

import io.kestra.core.junit.annotations.KestraTest;
import io.kestra.core.models.property.Property;
import io.kestra.core.runners.RunContextFactory;
import io.kestra.core.utils.IdUtils;
import io.kestra.plugin.gitguardian.incidents.Get;
import io.kestra.plugin.gitguardian.incidents.List;
import io.kestra.plugin.gitguardian.scan.Scan;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;

/**
 * Runs against the real GitGuardian API. Enabled only when GITGUARDIAN_API_KEY is set (token needs
 * `scan` and `incidents:read`); GITGUARDIAN_API_URL overrides the US default for EU or self-hosted.
 */
@KestraTest
@EnabledIfEnvironmentVariable(named = "GITGUARDIAN_API_KEY", matches = ".+")
class LiveApiTest {
    @Inject
    private RunContextFactory runContextFactory;

    @Test
    void scanCleanContentFindsNothing() throws Exception {
        var output = Scan.builder()
            .id(IdUtils.create())
            .type(Scan.class.getName())
            .apiUrl(apiUrl())
            .apiKey(apiKey())
            .filename(Property.ofValue("README.md"))
            .content(Property.ofValue("# Hello\n\nNothing sensitive here.\n"))
            .build()
            .run(runContextFactory.of(Map.of()));

        assertThat(output.getDocumentCount(), is(1));
        assertThat(output.getPolicyBreakCount(), is(0));
    }

    @Test
    void scanDetectsGitGuardianApiDocExampleSecret() throws Exception {
        // The sample document from GitGuardian's own API reference, assembled at runtime so no secret-shaped string sits in the source tree.
        var content = "import urllib.request\n"
            + "url = 'http://" + "jen_barber" + ":" + "correcthorse" + "batterystaple" + "@cake.gitguardian.com/isreal.json'\n"
            + "response = urllib.request.urlopen(url)\n";

        var output = Scan.builder()
            .id(IdUtils.create())
            .type(Scan.class.getName())
            .apiUrl(apiUrl())
            .apiKey(apiKey())
            .filename(Property.ofValue("fetch.py"))
            .content(Property.ofValue(content))
            .failOnPolicyBreak(Property.ofValue(false))
            .build()
            .run(runContextFactory.of(Map.of()));

        assertThat(output.getPolicyBreakCount(), greaterThanOrEqualTo(1));
        var policyBreak = output.getResults().getFirst().getPolicyBreaks().getFirst();
        assertThat(policyBreak.getType(), notNullValue());
        assertThat(policyBreak.getValidity(), notNullValue());
        assertThat(policyBreak.getMatches().getFirst().getLineStart(), notNullValue());
    }

    @Test
    void listThenGetIncident() throws Exception {
        var list = List.builder()
            .id(IdUtils.create())
            .type(List.class.getName())
            .apiUrl(apiUrl())
            .apiKey(apiKey())
            .ordering(Property.ofValue("-date"))
            .maxResults(Property.ofValue(3))
            .perPage(Property.ofValue(2))
            .build()
            .run(runContextFactory.of(Map.of()));

        assertThat(list.getSize(), greaterThanOrEqualTo(0L));
        if (list.getRows().isEmpty()) {
            return;
        }
        var first = list.getRows().getFirst();

        var get = Get.builder()
            .id(IdUtils.create())
            .type(Get.class.getName())
            .apiUrl(apiUrl())
            .apiKey(apiKey())
            .incidentId(Property.ofValue(first.getId()))
            .build()
            .run(runContextFactory.of(Map.of()));

        assertThat(get.getIncident().getId(), is(first.getId()));
        assertThat(get.getIncident().getDetector().getName(), is(first.getDetector().getName()));
        assertThat(get.getIncident().getGitguardianUrl(), notNullValue());
    }

    @Test
    void readOnlyListsAcrossResources() throws Exception {
        var ctx = runContextFactory.of(Map.of());

        var audit = io.kestra.plugin.gitguardian.auditlogs.List.builder()
            .id(IdUtils.create()).type(io.kestra.plugin.gitguardian.auditlogs.List.class.getName())
            .apiUrl(apiUrl()).apiKey(apiKey()).maxResults(Property.ofValue(3)).perPage(Property.ofValue(3)).build().run(ctx);
        assertThat(audit.getSize(), greaterThanOrEqualTo(0L));
        if (!audit.getRows().isEmpty()) {
            assertThat(audit.getRows().getFirst().getEventName(), notNullValue());
            assertThat(audit.getRows().getFirst().getDate(), notNullValue());
        }

        var health = io.kestra.plugin.gitguardian.healthchecks.List.builder()
            .id(IdUtils.create()).type(io.kestra.plugin.gitguardian.healthchecks.List.class.getName())
            .apiUrl(apiUrl()).apiKey(apiKey()).maxResults(Property.ofValue(5)).build().run(ctx);
        assertThat(health.getSize(), greaterThanOrEqualTo(0L));
        if (!health.getRows().isEmpty()) {
            assertThat(health.getRows().getFirst().getStatus(), notNullValue());
            assertThat(health.getRows().getFirst().getInstance(), notNullValue());
        }

        var sources = io.kestra.plugin.gitguardian.sources.List.builder()
            .id(IdUtils.create()).type(io.kestra.plugin.gitguardian.sources.List.class.getName())
            .apiUrl(apiUrl()).apiKey(apiKey()).maxResults(Property.ofValue(3)).build().run(ctx);
        assertThat(sources.getSize(), greaterThanOrEqualTo(0L));
        if (!sources.getRows().isEmpty()) {
            assertThat(sources.getRows().getFirst().getFullName(), notNullValue());
            var one = io.kestra.plugin.gitguardian.sources.Get.builder()
                .id(IdUtils.create()).type(io.kestra.plugin.gitguardian.sources.Get.class.getName())
                .apiUrl(apiUrl()).apiKey(apiKey()).sourceId(Property.ofValue(sources.getRows().getFirst().getId())).build().run(ctx);
            assertThat(one.getSource().getId(), is(sources.getRows().getFirst().getId()));
        }

        var honeytokens = io.kestra.plugin.gitguardian.honeytokens.List.builder()
            .id(IdUtils.create()).type(io.kestra.plugin.gitguardian.honeytokens.List.class.getName())
            .apiUrl(apiUrl()).apiKey(apiKey()).maxResults(Property.ofValue(3)).build().run(ctx);
        assertThat(honeytokens.getSize(), greaterThanOrEqualTo(0L));

        var teams = io.kestra.plugin.gitguardian.teams.List.builder()
            .id(IdUtils.create()).type(io.kestra.plugin.gitguardian.teams.List.class.getName())
            .apiUrl(apiUrl()).apiKey(apiKey()).maxResults(Property.ofValue(3)).build().run(ctx);
        assertThat(teams.getSize(), greaterThanOrEqualTo(1L));
        assertThat(teams.getRows().getFirst().getName(), notNullValue());

        try {
            var publicIncidents = io.kestra.plugin.gitguardian.publicincidents.List.builder()
                .id(IdUtils.create()).type(io.kestra.plugin.gitguardian.publicincidents.List.class.getName())
                .apiUrl(apiUrl()).apiKey(apiKey()).maxResults(Property.ofValue(3)).build().run(ctx);
            assertThat(publicIncidents.getSize(), greaterThanOrEqualTo(0L));
        } catch (GitGuardianApiException e) {
            // Public Monitoring is a separate subscription; a 403 or 404 here only means the workspace does not have it.
            assertThat(e.getStatusCode() == 403 || e.getStatusCode() == 404, is(true));
        }

        var members = io.kestra.plugin.gitguardian.members.List.builder()
            .id(IdUtils.create()).type(io.kestra.plugin.gitguardian.members.List.class.getName())
            .apiUrl(apiUrl()).apiKey(apiKey()).maxResults(Property.ofValue(3)).build().run(ctx);
        assertThat(members.getSize(), greaterThanOrEqualTo(1L));
        assertThat(members.getRows().getFirst().getEmail(), notNullValue());
    }

    private static Property<String> apiKey() {
        return Property.ofValue(System.getenv("GITGUARDIAN_API_KEY"));
    }

    private static Property<String> apiUrl() {
        var url = System.getenv("GITGUARDIAN_API_URL");
        return Property.ofValue(url == null || url.isBlank() ? GitGuardianConnectionInterface.DEFAULT_API_URL : url);
    }
}
