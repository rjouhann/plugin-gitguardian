package io.kestra.plugin.gitguardian.honeytokens;

import io.kestra.core.models.annotations.Example;
import io.kestra.core.models.annotations.Plugin;
import io.kestra.core.models.annotations.PluginProperty;
import io.kestra.core.models.conditions.ConditionContext;
import io.kestra.core.models.property.Property;
import io.kestra.core.models.triggers.TriggerContext;
import io.kestra.core.models.triggers.TriggerEvaluationResult;
import io.kestra.core.models.triggers.TriggerOutput;
import io.kestra.core.models.triggers.TriggerService;
import io.kestra.plugin.gitguardian.AbstractGitGuardianTrigger;
import io.swagger.v3.oas.annotations.media.Schema;
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
import java.util.Optional;
import java.util.Set;

@SuperBuilder
@ToString
@EqualsAndHashCode
@Getter
@NoArgsConstructor
@Schema(
    title = "Trigger a flow when a GitGuardian honeytoken is used",
    description = """
        Polls `GET /v1/honeytokens_events` at `interval` and starts one execution per new event, oldest first, one \
        per poll cycle, with the event in `trigger.event` and the honeytoken it belongs to in `trigger.honeytoken` \
        (without its value). A honeytoken firing means someone used a decoy credential: treat it as an active \
        intrusion signal. The watermark is kept in the flow namespace KV store and seeded at the current time on the \
        first poll. Requires the `honeytokens:read` scope.
        """
)
@Plugin(
    examples = {
        @Example(
            title = "Page security and open a ticket when a honeytoken fires",
            full = true,
            code = """
                id: gitguardian_honeytoken_alert
                namespace: company.security

                tasks:
                  - id: page
                    type: io.kestra.plugin.pagerduty.Alert
                    integrationKey: "{{ secret('PAGERDUTY_KEY') }}"
                    payloadSummary: "Honeytoken {{ trigger.honeytoken.name }} used from {{ trigger.event.ipAddress }} ({{ trigger.event.action }})"
                    payloadSeverity: CRITICAL

                  - id: ticket
                    type: io.kestra.plugin.jira.issues.Create
                    baseUrl: https://company.atlassian.net
                    username: "{{ secret('JIRA_USER') }}"
                    password: "{{ secret('JIRA_TOKEN') }}"
                    projectKey: SEC
                    summary: "Honeytoken triggered: {{ trigger.honeytoken.name }}"
                    description: "{{ trigger.honeytoken.description }} - {{ trigger.event.gitguardianUrl }}"

                triggers:
                  - id: on_honeytoken_event
                    type: io.kestra.plugin.gitguardian.honeytokens.Trigger
                    apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"
                    interval: PT1M
                """
        )
    }
)
public class Trigger extends AbstractGitGuardianTrigger implements TriggerOutput<Trigger.Output> {
    private static final String SCOPE = "honeytokens:read";
    private static final int PAGE_SIZE = 100;
    private static final Duration OVERLAP = Duration.ofSeconds(1);

    @Schema(title = "Only events of this honeytoken ID", description = "All honeytokens when omitted.")
    @PluginProperty(group = "processing")
    private Property<String> honeytokenId;

    @Override
    public Optional<TriggerEvaluationResult> eval(ConditionContext conditionContext, TriggerContext context) throws Exception {
        var runContext = conditionContext.getRunContext();
        var kv = runContext.namespaceKv(context.getNamespace());
        var key = watermarkKey("gitguardian_honeytokens", context.getFlowId(), context.getTriggerId());

        var watermark = readWatermark(kv, key).orElse(null);
        if (watermark == null) {
            persistWatermark(kv, key, new Watermark(Instant.now(), Set.of()));
            runContext.logger().info("GitGuardian honeytokens trigger initialized; only events after now will fire.");
            return Optional.empty();
        }

        try (var client = client(runContext)) {
            var pending = new ArrayList<HoneytokenEvent>();
            var query = new LinkedHashMap<String, Object>();
            query.put("honeytoken_id", runContext.render(honeytokenId).as(String.class).orElse(null));
            query.put("status", "open");
            query.put("ordering", "-triggered_at");
            query.put("per_page", PAGE_SIZE);
            query.values().removeIf(value -> value == null);
            // The events endpoint has no date filter; newest first lets the walk stop at the first event older than the watermark.
            var cutoff = watermark.getTimestamp().minus(OVERLAP);
            client.walk("/honeytokens_events", query, SCOPE, HoneytokenEvent.class, page -> {
                for (var event : page) {
                    if (event.getTriggeredAt() == null) {
                        runContext.logger().warn("Honeytoken event {} has no triggered_at date and cannot be delivered", event.getId());
                        continue;
                    }
                    if (event.getTriggeredAt().isBefore(cutoff)) {
                        return false;
                    }
                    if (!watermark.isDelivered(event.getTriggeredAt(), event.getId())) {
                        pending.add(event);
                    }
                }
                return true;
            });
            if (pending.isEmpty()) {
                return Optional.empty();
            }
            pending.sort(Comparator.comparing(HoneytokenEvent::getTriggeredAt).thenComparing(HoneytokenEvent::getId));
            var next = pending.getFirst();

            Honeytoken honeytoken = null;
            try {
                honeytoken = client.get("/honeytokens/" + next.getHoneytokenId(), java.util.Map.of("show_token", false), SCOPE, Honeytoken.class);
            } catch (Exception e) {
                runContext.logger().warn("Honeytoken event {} fires without honeytoken details: {}", next.getId(), e.getMessage());
            }

            persistWatermark(kv, key, watermark.advance(next.getTriggeredAt(), next.getId()));
            if (pending.size() > 1) {
                runContext.logger().info("Honeytoken event {} fires now; {} more pending for the next polls", next.getId(), pending.size() - 1);
            }
            return Optional.of(TriggerService.generateEvaluationResult(this, conditionContext, Output.builder().event(next).honeytoken(honeytoken).build()));
        }
    }

    @Builder
    @Getter
    public static class Output implements io.kestra.core.models.tasks.Output {
        @Schema(title = "The honeytoken event that fired this execution")
        private final HoneytokenEvent event;

        @Schema(title = "The honeytoken that was used, without its value", description = "Null if it could not be fetched.")
        private final Honeytoken honeytoken;
    }
}
