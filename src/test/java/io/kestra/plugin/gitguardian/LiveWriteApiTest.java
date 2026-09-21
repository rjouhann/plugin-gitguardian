package io.kestra.plugin.gitguardian;

import io.kestra.core.junit.annotations.KestraTest;
import io.kestra.core.models.property.Property;
import io.kestra.core.runners.RunContextFactory;
import io.kestra.core.utils.IdUtils;
import io.kestra.core.utils.TestsUtils;
import io.kestra.plugin.gitguardian.incidents.AddNote;
import io.kestra.plugin.gitguardian.incidents.Assign;
import io.kestra.plugin.gitguardian.incidents.Get;
import io.kestra.plugin.gitguardian.incidents.Ignore;
import io.kestra.plugin.gitguardian.incidents.IgnoreReason;
import io.kestra.plugin.gitguardian.incidents.IncidentStatus;
import io.kestra.plugin.gitguardian.incidents.Reopen;
import io.kestra.plugin.gitguardian.incidents.Resolve;
import io.kestra.plugin.gitguardian.incidents.Severity;
import io.kestra.plugin.gitguardian.incidents.Update;
import io.kestra.plugin.gitguardian.scan.CreateIncidents;
import io.kestra.plugin.gitguardian.sources.CreateCustomSource;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import java.time.Duration;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;

/**
 * Mutates the GitGuardian workspace: creates a custom source, an incident, a honeytoken (revoked at the end).
 * Enabled only with GITGUARDIAN_API_KEY and GITGUARDIAN_LIVE_WRITE=true. Token scopes: sources:write,
 * scan:create-incidents, incidents:read, incidents:write, members:read, honeytokens:read, honeytokens:write,
 * health_checks:read, health_checks:write.
 */
@KestraTest
@EnabledIfEnvironmentVariable(named = "GITGUARDIAN_API_KEY", matches = ".+")
@EnabledIfEnvironmentVariable(named = "GITGUARDIAN_LIVE_WRITE", matches = "true")
class LiveWriteApiTest {
    @Inject
    private RunContextFactory runContextFactory;

    @Test
    void customSourceIncidentLifecycle() throws Exception {
        var ctx = runContextFactory.of(Map.of());
        var suffix = IdUtils.create().toLowerCase();

        var source = CreateCustomSource.builder()
            .id(IdUtils.create()).type(CreateCustomSource.class.getName()).apiUrl(apiUrl()).apiKey(apiKey())
            .name(Property.ofValue("kestra-plugin-live-test-" + suffix))
            .sourceDescription(Property.ofValue("Created by the Kestra GitGuardian plugin live test; safe to delete."))
            .build().run(ctx).getSource();
        assertThat(source.getSourceUuid(), notNullValue());

        var content = "import urllib.request\n"
            + "url = 'http://" + "jen_barber" + ":" + "correcthorse" + "batterystaple" + suffix + "@cake.gitguardian.com/isreal.json'\n"
            + "response = urllib.request.urlopen(url)\n";
        var created = CreateIncidents.builder()
            .id(IdUtils.create()).type(CreateIncidents.class.getName()).apiUrl(apiUrl()).apiKey(apiKey())
            .sourceUuid(Property.ofValue(source.getSourceUuid()))
            .filename(Property.ofValue("live-test-" + suffix + ".py"))
            .content(Property.ofValue(content))
            .locationUrl(Property.ofValue("https://kestra.io/plugin-gitguardian/live-test/" + suffix))
            .authorEmail(Property.ofValue("kestra-plugin@example.com"))
            .build().run(ctx);
        assertThat(created.getPolicyBreakCount(), greaterThanOrEqualTo(1));
        var incidentUrl = created.getResults().getFirst().getPolicyBreaks().getFirst().getIncidentUrl();
        assertThat("create-incidents must report the incident URL", incidentUrl, notNullValue());
        var incidentId = Long.parseLong(incidentUrl.substring(incidentUrl.lastIndexOf('/') + 1));

        var incident = Get.builder().id(IdUtils.create()).type(Get.class.getName()).apiUrl(apiUrl()).apiKey(apiKey())
            .incidentId(Property.ofValue(incidentId)).build().run(ctx).getIncident();
        assertThat(incident.getId(), is(incidentId));

        var note = AddNote.builder().id(IdUtils.create()).type(AddNote.class.getName()).apiUrl(apiUrl()).apiKey(apiKey())
            .incidentId(Property.ofValue(incidentId)).comment(Property.ofValue("Kestra plugin live test " + suffix)).build().run(ctx).getNote();
        assertThat(note.getIncidentId(), is(incidentId));

        var updated = Update.builder().id(IdUtils.create()).type(Update.class.getName()).apiUrl(apiUrl()).apiKey(apiKey())
            .incidentId(Property.ofValue(incidentId)).severity(Property.ofValue(Severity.LOW)).customTags(Property.ofValue(Map.of("kestra", "live-test")))
            .build().run(ctx).getIncident();
        assertThat(updated.getSeverity(), is(Severity.LOW));
        assertThat(updated.getCustomTags().stream().anyMatch(tag -> "kestra".equals(tag.getKey()) && "live-test".equals(tag.getValue())), is(true));

        var members = io.kestra.plugin.gitguardian.members.List.builder()
            .id(IdUtils.create()).type(io.kestra.plugin.gitguardian.members.List.class.getName()).apiUrl(apiUrl()).apiKey(apiKey())
            .active(Property.ofValue(true)).maxResults(Property.ofValue(1)).build().run(ctx);
        var assigned = Assign.builder().id(IdUtils.create()).type(Assign.class.getName()).apiUrl(apiUrl()).apiKey(apiKey())
            .incidentId(Property.ofValue(incidentId)).assigneeEmail(Property.ofValue(members.getRows().getFirst().getEmail())).sendEmail(Property.ofValue(false))
            .build().run(ctx).getIncident();
        assertThat(assigned.getStatus(), is(IncidentStatus.ASSIGNED));
        assertThat(assigned.getAssigneeEmail(), is(members.getRows().getFirst().getEmail()));

        var ignored = Ignore.builder().id(IdUtils.create()).type(Ignore.class.getName()).apiUrl(apiUrl()).apiKey(apiKey())
            .incidentId(Property.ofValue(incidentId)).ignoreReason(Property.ofValue(IgnoreReason.TEST_CREDENTIAL)).build().run(ctx).getIncident();
        assertThat(ignored.getStatus(), is(IncidentStatus.IGNORED));

        var reopened = Reopen.builder().id(IdUtils.create()).type(Reopen.class.getName()).apiUrl(apiUrl()).apiKey(apiKey())
            .incidentId(Property.ofValue(incidentId)).build().run(ctx).getIncident();
        // Reopening keeps the assignee, so GitGuardian reports ASSIGNED rather than TRIGGERED.
        assertThat(reopened.getStatus(), is(IncidentStatus.ASSIGNED));

        var resolved = Resolve.builder().id(IdUtils.create()).type(Resolve.class.getName()).apiUrl(apiUrl()).apiKey(apiKey())
            .incidentId(Property.ofValue(incidentId)).secretRevoked(Property.ofValue(false)).build().run(ctx).getIncident();
        assertThat(resolved.getStatus(), is(IncidentStatus.RESOLVED));

        var trigger = io.kestra.plugin.gitguardian.incidents.Trigger.builder()
            .id(IdUtils.create()).type(io.kestra.plugin.gitguardian.incidents.Trigger.class.getName()).apiUrl(apiUrl()).apiKey(apiKey())
            .interval(Duration.ofMinutes(5)).build();
        var triggerCtx = TestsUtils.mockTrigger(runContextFactory, trigger);
        assertThat("first poll seeds the baseline against the live API without firing", trigger.eval(triggerCtx.getKey(), triggerCtx.getValue().context()).isPresent(), is(false));
    }

    @Test
    void honeytokenCreateGetRevoke() throws Exception {
        var ctx = runContextFactory.of(Map.of());
        var name = "kestra-plugin-live-test-" + IdUtils.create().toLowerCase();

        var created = io.kestra.plugin.gitguardian.honeytokens.Create.builder()
            .id(IdUtils.create()).type(io.kestra.plugin.gitguardian.honeytokens.Create.class.getName()).apiUrl(apiUrl()).apiKey(apiKey())
            .name(Property.ofValue(name))
            .honeytokenDescription(Property.ofValue("Kestra plugin live test; revoked by the same test."))
            .customTags(Property.ofValue(Map.of("kestra", "live-test")))
            .build().run(ctx);
        assertThat(created.getHoneytoken().getStatus(), is("active"));
        assertThat(created.getEncryptedToken(), notNullValue());
        assertThat(created.getEncryptedToken().getValue().contains("secret_key"), is(false));

        var fetched = io.kestra.plugin.gitguardian.honeytokens.Get.builder()
            .id(IdUtils.create()).type(io.kestra.plugin.gitguardian.honeytokens.Get.class.getName()).apiUrl(apiUrl()).apiKey(apiKey())
            .honeytokenId(Property.ofValue(created.getHoneytoken().getId())).build().run(ctx).getHoneytoken();
        assertThat(fetched.getName(), is(name));

        var revoked = io.kestra.plugin.gitguardian.honeytokens.Revoke.builder()
            .id(IdUtils.create()).type(io.kestra.plugin.gitguardian.honeytokens.Revoke.class.getName()).apiUrl(apiUrl()).apiKey(apiKey())
            .honeytokenId(Property.ofValue(created.getHoneytoken().getId())).build().run(ctx).getHoneytoken();
        assertThat(revoked.getStatus(), is("revoked"));
    }

    @Test
    void healthCheckRunOnFirstInstance() throws Exception {
        var ctx = runContextFactory.of(Map.of());
        var checks = io.kestra.plugin.gitguardian.healthchecks.List.builder()
            .id(IdUtils.create()).type(io.kestra.plugin.gitguardian.healthchecks.List.class.getName()).apiUrl(apiUrl()).apiKey(apiKey())
            .build().run(ctx);
        var active = checks.getRows().stream()
            .filter(row -> row.getInstance() != null && "active".equals(row.getInstance().getStatus()))
            .findFirst();
        if (active.isEmpty()) {
            return;
        }
        var check = active.get();
        var run = io.kestra.plugin.gitguardian.healthchecks.Run.builder()
            .id(IdUtils.create()).type(io.kestra.plugin.gitguardian.healthchecks.Run.class.getName()).apiUrl(apiUrl()).apiKey(apiKey())
            .integrationType(Property.ofValue(check.getType())).instanceId(Property.ofValue(check.getInstance().getId())).build().run(ctx);
        assertThat(run.getDetail(), notNullValue());
    }

    private static Property<String> apiKey() {
        return Property.ofValue(System.getenv("GITGUARDIAN_API_KEY"));
    }

    private static Property<String> apiUrl() {
        var url = System.getenv("GITGUARDIAN_API_URL");
        return Property.ofValue(url == null || url.isBlank() ? GitGuardianConnectionInterface.DEFAULT_API_URL : url);
    }
}
