package io.kestra.plugin.gitguardian.publicincidents;

import io.kestra.core.models.annotations.Example;
import io.kestra.core.models.annotations.Plugin;
import io.kestra.core.models.annotations.PluginProperty;
import io.kestra.core.models.conditions.ConditionContext;
import io.kestra.core.models.property.Property;
import io.kestra.core.models.triggers.TriggerContext;
import io.kestra.core.models.triggers.TriggerEvaluationResult;
import io.kestra.core.models.triggers.TriggerOutput;
import io.kestra.core.models.triggers.TriggerService;
import io.kestra.core.runners.RunContext;
import io.kestra.plugin.gitguardian.AbstractGitGuardianTrigger;
import io.kestra.plugin.gitguardian.GitGuardianClient;
import io.kestra.plugin.gitguardian.incidents.IncidentStatus;
import io.kestra.plugin.gitguardian.incidents.Severity;
import io.kestra.plugin.gitguardian.incidents.Validity;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import lombok.experimental.SuperBuilder;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

@SuperBuilder
@ToString
@EqualsAndHashCode
@Getter
@NoArgsConstructor
@Schema(
    title = "Trigger a flow when GitGuardian Public Monitoring finds a leaked secret",
    description = """
        Polls `GET /v1/public-incidents/secrets` at `interval` and starts one execution per new (or re-triggered) \
        public incident, oldest first, one per poll cycle, with the incident in `trigger.incident`. Same watermark \
        mechanics as the internal incidents trigger: state in the namespace KV store, baseline seeded on the first \
        poll without firing. Requires the `incidents:read` scope and a Public Monitoring subscription.
        """
)
@Plugin(
    examples = {
        @Example(
            title = "Escalate every valid public leak to the security channel",
            full = true,
            code = """
                id: gitguardian_public_leak_alert
                namespace: company.security

                tasks:
                  - id: notify
                    type: io.kestra.plugin.slack.SlackIncomingWebhook
                    url: "{{ secret('SLACK_WEBHOOK') }}"
                    payload: |
                      {"text": ":warning: Secret leaked publicly: {{ trigger.incident.incidentName }} ({{ trigger.incident.occurrencesCount }} occurrence(s)) {{ trigger.incident.gitguardianUrl }}"}

                triggers:
                  - id: on_public_leak
                    type: io.kestra.plugin.gitguardian.publicincidents.Trigger
                    apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"
                    interval: PT2M
                    validity: VALID
                """
        )
    }
)
public class Trigger extends AbstractGitGuardianTrigger implements TriggerOutput<Trigger.Output> {
    private static final String SCOPE = "incidents:read";
    private static final String PATH = "/public-incidents/secrets";
    private static final int PAGE_SIZE = 100;
    private static final Duration OVERLAP = Duration.ofSeconds(1);

    @Schema(title = "Only incidents in this status")
    @PluginProperty(group = "processing")
    private Property<IncidentStatus> status;

    @Schema(title = "Only incidents at this severity")
    @PluginProperty(group = "processing")
    private Property<Severity> severity;

    @Schema(title = "Only incidents with this secret validity")
    @PluginProperty(group = "processing")
    private Property<Validity> validity;

    @Schema(title = "Only incidents with this declarative secret status", description = "For example `not_declared` or `mine`.")
    @PluginProperty(group = "processing")
    private Property<String> declarativeSecretStatus;

    @Schema(title = "Only incidents from this detector group")
    @PluginProperty(group = "processing")
    private Property<String> detectorGroupName;

    @Schema(title = "Minimum risk score, from 0 to 100")
    @PluginProperty(group = "processing")
    private Property<@Min(0) @Max(100) Integer> riskScoreMin;

    @Override
    public Optional<TriggerEvaluationResult> eval(ConditionContext conditionContext, TriggerContext context) throws Exception {
        var runContext = conditionContext.getRunContext();
        var logger = runContext.logger();
        var kv = runContext.namespaceKv(context.getNamespace());
        var key = watermarkKey("gitguardian_publicincidents", context.getFlowId(), context.getTriggerId());
        var filters = filters(runContext);

        try (var client = client(runContext)) {
            var watermark = readWatermark(kv, key).orElse(null);
            if (watermark == null) {
                var newest = newest(client, filters);
                var baseline = newest != null ? new Watermark(newest.getDate(), Set.of(String.valueOf(newest.getId()))) : new Watermark(Instant.now(), Set.of());
                persistWatermark(kv, key, baseline);
                logger.info("GitGuardian public incidents trigger initialized; baseline {}.", baseline.getTimestamp());
                return Optional.empty();
            }

            var pending = new ArrayList<PublicIncident>();
            var query = new LinkedHashMap<String, Object>(filters);
            query.put("ordering", "date");
            query.put("per_page", PAGE_SIZE);
            query.put("date_after", watermark.getTimestamp().minus(OVERLAP).toString());
            client.walk(PATH, query, SCOPE, PublicIncident.class, page -> {
                for (var incident : page) {
                    if (incident.getDate() == null) {
                        logger.warn("Public incident {} has no date and cannot be delivered", incident.getId());
                    } else if (!watermark.isDelivered(incident.getDate(), String.valueOf(incident.getId()))) {
                        pending.add(incident);
                    }
                }
                return true;
            });
            if (pending.isEmpty()) {
                return Optional.empty();
            }
            pending.sort(Comparator.comparing(PublicIncident::getDate).thenComparing(PublicIncident::getId));
            var next = pending.getFirst();
            persistWatermark(kv, key, watermark.advance(next.getDate(), String.valueOf(next.getId())));
            if (pending.size() > 1) {
                logger.info("GitGuardian public incident {} fires now; {} more pending for the next polls", next.getId(), pending.size() - 1);
            }
            return Optional.of(TriggerService.generateEvaluationResult(this, conditionContext, Output.builder().incident(next).build()));
        }
    }

    private PublicIncident newest(GitGuardianClient client, Map<String, Object> filters) throws Exception {
        var query = new LinkedHashMap<String, Object>(filters);
        query.put("ordering", "-date");
        query.put("per_page", 1);
        var page = client.getPage(PATH, query, null, SCOPE, PublicIncident.class);
        return page.items().isEmpty() ? null : page.items().getFirst();
    }

    private Map<String, Object> filters(RunContext runContext) throws Exception {
        var filters = new LinkedHashMap<String, Object>();
        filters.put("status", runContext.render(status).as(IncidentStatus.class).map(IncidentStatus::apiValue).orElse(null));
        filters.put("severity", runContext.render(severity).as(Severity.class).map(Severity::apiValue).orElse(null));
        filters.put("validity", runContext.render(validity).as(Validity.class).map(Validity::apiValue).orElse(null));
        filters.put("declarative_secret_status", runContext.render(declarativeSecretStatus).as(String.class).orElse(null));
        filters.put("detector_group_name", runContext.render(detectorGroupName).as(String.class).orElse(null));
        filters.put("risk_score_min", runContext.render(riskScoreMin).as(Integer.class).orElse(null));
        filters.values().removeIf(value -> value == null);
        return filters;
    }

    @Builder
    @Getter
    public static class Output implements io.kestra.core.models.tasks.Output {
        @Schema(title = "The public incident that fired this execution")
        private final PublicIncident incident;
    }
}
