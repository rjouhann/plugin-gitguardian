package io.kestra.plugin.gitguardian.auditlogs;

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
    title = "Trigger a flow on new GitGuardian audit log events",
    description = """
        Polls `GET /v1/audit_logs` at `interval` and starts one execution per poll carrying every new event since \
        the last poll (`trigger.events`), so a burst of activity produces one execution, not one per event. \
        Optionally restrict to `eventNames`. The watermark (newest delivered date plus the IDs sharing it) is kept \
        in the flow namespace KV store; on the first poll it is seeded at the current time and nothing fires. \
        Requires the `audit_logs:read` scope.
        """
)
@Plugin(
    examples = {
        @Example(
            title = "Alert when an incident is ignored or an API token is created",
            full = true,
            code = """
                id: gitguardian_sensitive_actions
                namespace: company.security

                tasks:
                  - id: alert
                    type: io.kestra.plugin.slack.SlackIncomingWebhook
                    url: "{{ secret('SLACK_WEBHOOK') }}"
                    payload: |
                      {"text": "GitGuardian: {{ trigger.count }} sensitive action(s): {{ trigger.events | jq('[.[] | .eventName + \\" by \\" + (.memberEmail // .apiTokenId)]') | first }}"}

                triggers:
                  - id: on_audit_event
                    type: io.kestra.plugin.gitguardian.auditlogs.Trigger
                    apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"
                    interval: PT5M
                    eventNames:
                      - incident.ignored
                      - api_token.created
                """
        )
    }
)
public class Trigger extends AbstractGitGuardianTrigger implements TriggerOutput<Trigger.Output> {
    private static final String SCOPE = "audit_logs:read";
    private static final int PAGE_SIZE = 100;
    private static final Duration OVERLAP = Duration.ofSeconds(1);

    @Schema(title = "Only these event names", description = "For example `incident.ignored`. All events when omitted. Filtered server-side one name at a time.")
    @PluginProperty(group = "processing")
    private Property<java.util.List<String>> eventNames;

    @Override
    public Optional<TriggerEvaluationResult> eval(ConditionContext conditionContext, TriggerContext context) throws Exception {
        var runContext = conditionContext.getRunContext();
        var kv = runContext.namespaceKv(context.getNamespace());
        var key = watermarkKey("gitguardian_auditlogs", context.getFlowId(), context.getTriggerId());
        var rEventNames = runContext.render(eventNames).asList(String.class);

        var watermark = readWatermark(kv, key).orElse(null);
        if (watermark == null) {
            persistWatermark(kv, key, new Watermark(Instant.now(), Set.of()));
            runContext.logger().info("GitGuardian audit logs trigger initialized; only events after now will fire.");
            return Optional.empty();
        }

        var pending = new ArrayList<AuditLog>();
        try (var client = client(runContext)) {
            var names = rEventNames.isEmpty() ? java.util.Collections.<String>singletonList(null) : rEventNames;
            for (var name : names) {
                var query = new LinkedHashMap<String, Object>();
                query.put("event_name", name);
                query.put("per_page", PAGE_SIZE);
                query.put("date_after", watermark.getTimestamp().minus(OVERLAP).toString());
                query.values().removeIf(value -> value == null);
                client.walk("/audit_logs", query, SCOPE, AuditLog.class, page -> {
                    for (var event : page) {
                        if (event.getDate() == null) {
                            runContext.logger().warn("Audit log event {} has no date and cannot be delivered", event.getId());
                        } else if (!watermark.isDelivered(event.getDate(), String.valueOf(event.getId()))) {
                            pending.add(event);
                        }
                    }
                    return true;
                });
            }
        }

        if (pending.isEmpty()) {
            return Optional.empty();
        }
        pending.sort(Comparator.comparing(AuditLog::getDate).thenComparing(AuditLog::getId));
        var next = watermark;
        for (var event : pending) {
            next = next.advance(event.getDate(), String.valueOf(event.getId()));
        }
        persistWatermark(kv, key, next);

        return Optional.of(TriggerService.generateEvaluationResult(this, conditionContext, Output.builder().events(pending).count(pending.size()).build()));
    }

    @Builder
    @Getter
    public static class Output implements io.kestra.core.models.tasks.Output {
        @Schema(title = "New audit log events since the previous poll, oldest first")
        private final java.util.List<AuditLog> events;

        @Schema(title = "Number of new events")
        private final Integer count;
    }
}
