package io.kestra.plugin.gitguardian.healthchecks;

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
    title = "Trigger a flow when a GitGuardian integration starts failing",
    description = """
        Polls `GET /v1/health-checks` at `interval` for integration instances whose latest run has one of `statuses` \
        (default `FAIL`) and starts one execution per poll listing the instances that entered that state since the \
        previous poll (`trigger.checks`). An integration that keeps failing does not re-fire: the watermark tracks \
        `firstStartedAt`, the start of the current streak, so only new streaks fire. On the first poll the watermark \
        is seeded at the current time and nothing fires. Requires the `health_checks:read` scope.
        """
)
@Plugin(
    examples = {
        @Example(
            title = "Page the platform team when a GitHub or GitLab integration breaks",
            full = true,
            code = """
                id: gitguardian_integration_down
                namespace: company.security

                tasks:
                  - id: page
                    type: io.kestra.plugin.pagerduty.Alert
                    integrationKey: "{{ secret('PAGERDUTY_KEY') }}"
                    payloadSummary: "GitGuardian integration failing: {{ trigger.checks | jq('[.[].instance.name]') | first }}"
                    payloadSeverity: ERROR

                triggers:
                  - id: on_failure
                    type: io.kestra.plugin.gitguardian.healthchecks.Trigger
                    apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"
                    interval: PT10M
                    types:
                      - github-installation
                      - gitlab-installation
                """
        )
    }
)
public class Trigger extends AbstractGitGuardianTrigger implements TriggerOutput<Trigger.Output> {
    private static final String SCOPE = "health_checks:read";
    private static final int PAGE_SIZE = 100;

    @Schema(title = "Statuses that fire", description = "Any of `FAIL`, `WARN`, `PASS`. Defaults to `FAIL` only.")
    @Builder.Default
    @PluginProperty(group = "processing")
    private Property<java.util.List<HealthCheckStatus>> statuses = Property.ofValue(java.util.List.of(HealthCheckStatus.FAIL));

    @Schema(title = "Only these integration types", description = "For example `github-installation`. All types when omitted.")
    @PluginProperty(group = "processing")
    private Property<java.util.List<String>> types;

    @Override
    public Optional<TriggerEvaluationResult> eval(ConditionContext conditionContext, TriggerContext context) throws Exception {
        var runContext = conditionContext.getRunContext();
        var kv = runContext.namespaceKv(context.getNamespace());
        var key = watermarkKey("gitguardian_healthchecks", context.getFlowId(), context.getTriggerId());
        var rStatuses = runContext.render(statuses).asList(HealthCheckStatus.class);
        var rTypes = runContext.render(types).asList(String.class);

        var watermark = readWatermark(kv, key).orElse(null);
        if (watermark == null) {
            persistWatermark(kv, key, new Watermark(Instant.now(), Set.of()));
            runContext.logger().info("GitGuardian health checks trigger initialized; only failures starting after now will fire.");
            return Optional.empty();
        }

        var pending = new ArrayList<HealthCheck>();
        try (var client = client(runContext)) {
            for (var status : rStatuses.isEmpty() ? java.util.List.of(HealthCheckStatus.FAIL) : rStatuses) {
                var query = new LinkedHashMap<String, Object>();
                query.put("status", status.apiValue());
                query.put("per_page", PAGE_SIZE);
                client.walk("/health-checks", query, SCOPE, HealthCheck.class, page -> {
                    for (var check : page) {
                        var streakStart = check.getFirstStartedAt() != null ? check.getFirstStartedAt() : check.getStartedAt();
                        var instanceId = check.getInstance() != null ? check.getType() + ":" + check.getInstance().getId() : check.getType() + ":" + check.getId();
                        if (streakStart != null
                            && (rTypes.isEmpty() || rTypes.contains(check.getType()))
                            && !watermark.isDelivered(streakStart, instanceId)) {
                            pending.add(check);
                        }
                    }
                    return true;
                });
            }
        }

        if (pending.isEmpty()) {
            return Optional.empty();
        }
        pending.sort(Comparator.comparing((HealthCheck check) -> check.getFirstStartedAt() != null ? check.getFirstStartedAt() : check.getStartedAt()));
        var next = watermark;
        for (var check : pending) {
            var streakStart = check.getFirstStartedAt() != null ? check.getFirstStartedAt() : check.getStartedAt();
            var instanceId = check.getInstance() != null ? check.getType() + ":" + check.getInstance().getId() : check.getType() + ":" + check.getId();
            next = next.advance(streakStart, instanceId);
        }
        persistWatermark(kv, key, next);

        return Optional.of(TriggerService.generateEvaluationResult(this, conditionContext, Output.builder().checks(pending).count(pending.size()).build()));
    }

    @Builder
    @Getter
    public static class Output implements io.kestra.core.models.tasks.Output {
        @Schema(title = "Integration instances that entered a matching status since the previous poll")
        private final java.util.List<HealthCheck> checks;

        @Schema(title = "Number of instances")
        private final Integer count;
    }
}
