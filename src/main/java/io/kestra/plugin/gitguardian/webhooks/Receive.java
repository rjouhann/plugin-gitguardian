package io.kestra.plugin.gitguardian.webhooks;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.kestra.core.models.annotations.Example;
import io.kestra.core.models.annotations.Plugin;
import io.kestra.core.models.annotations.PluginProperty;
import io.kestra.core.models.property.Property;
import io.kestra.core.models.tasks.RunnableTask;
import io.kestra.core.models.tasks.Task;
import io.kestra.core.runners.RunContext;
import io.kestra.core.serializers.JacksonMapper;
import io.kestra.plugin.gitguardian.honeytokens.Honeytoken;
import io.kestra.plugin.gitguardian.honeytokens.HoneytokenEvent;
import io.kestra.plugin.gitguardian.incidents.Incident;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import lombok.experimental.SuperBuilder;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;

@SuperBuilder
@ToString
@EqualsAndHashCode
@Getter
@NoArgsConstructor
@Schema(
    title = "Verify and parse a GitGuardian custom webhook event",
    description = """
        Companion of Kestra's core `Webhook` trigger for GitGuardian [custom webhooks](https://docs.gitguardian.com/platform/configure-alerting/notifiers-integrations/custom-webhook): \
        pass it `{{ trigger.body }}` and `{{ trigger.headers }}` and it returns the event's `action`, `timestamp`, \
        `message` and the typed `incident` (same shape as the incident tasks, camelCase). When `signatureToken` is set, \
        it verifies the `Gitguardian-Signature` header (HMAC-SHA256 keyed with the `Timestamp` header plus the token) \
        and rejects stale timestamps beyond `maxClockSkew`. Kestra delivers the webhook body already parsed, so the \
        signature is checked against the canonical re-serializations GitGuardian is known to use; pass `rawBody` when \
        you have the exact bytes for a strict check. Fails the flow on an invalid signature unless \
        `failOnInvalidSignature: false`. No GitGuardian API call, no scope needed.
        """
)
@Plugin(
    examples = {
        @Example(
            title = "Real-time incident response from a GitGuardian custom webhook",
            full = true,
            code = """
                id: gitguardian_webhook
                namespace: company.security

                tasks:
                  - id: event
                    type: io.kestra.plugin.gitguardian.webhooks.Receive
                    body: "{{ trigger.body }}"
                    headers: "{{ trigger.headers }}"
                    signatureToken: "{{ secret('GITGUARDIAN_WEBHOOK_SIGNATURE_TOKEN') }}"

                  - id: on_new_incident
                    type: io.kestra.plugin.core.flow.If
                    condition: "{{ outputs.event.action == 'incident_triggered' }}"
                    then:
                      - id: assign
                        type: io.kestra.plugin.gitguardian.incidents.Assign
                        apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"
                        incidentId: "{{ outputs.event.incident.id }}"
                        assigneeEmail: security-oncall@company.com

                triggers:
                  - id: webhook
                    type: io.kestra.plugin.core.trigger.Webhook
                    key: "{{ secret('GITGUARDIAN_WEBHOOK_KEY') }}"
                """
        )
    }
)
@SuppressWarnings("unchecked")
public class Receive extends Task implements RunnableTask<Receive.Output> {
    private static final ObjectMapper MAPPER = JacksonMapper.ofJson();
    private static final List<String> SIGNATURE_HEADERS = List.of("gitguardian-signature", "x-gitguardian-signature");
    private static final String TIMESTAMP_HEADER = "timestamp";

    @Schema(title = "Webhook body", description = "`{{ trigger.body }}` from the core Webhook trigger, already parsed as JSON.")
    @PluginProperty(group = "main")
    private Property<Map<String, Object>> body;

    @Schema(title = "Raw webhook body", description = "Exact request body as a string, when available (for example from a stored `trigger.uri`). Used instead of `body` for a strict signature check and parsed when `body` is omitted.")
    @PluginProperty(group = "main")
    private Property<String> rawBody;

    @Schema(title = "Webhook headers", description = "`{{ trigger.headers }}` from the core Webhook trigger.")
    @PluginProperty(group = "main")
    private Property<Map<String, List<String>>> headers;

    @Schema(title = "Signature token", description = "The signature token configured on the GitGuardian custom webhook. Signature verification is skipped when omitted.")
    @PluginProperty(secret = true, group = "main")
    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    private Property<String> signatureToken;

    @Schema(title = "Maximum accepted age of the event", description = "Difference allowed between the `Timestamp` header and now. Defaults to `PT5M`.")
    @Builder.Default
    @PluginProperty(group = "advanced")
    private Property<Duration> maxClockSkew = Property.ofValue(Duration.ofMinutes(5));

    @Schema(title = "Fail when the signature or timestamp is invalid", description = "Defaults to `true`. When `false`, the task succeeds and exposes the result in `verified`.")
    @Builder.Default
    @PluginProperty(group = "advanced")
    private Property<Boolean> failOnInvalidSignature = Property.ofValue(true);

    @Override
    public Output run(RunContext runContext) throws Exception {
        var rRawBody = runContext.render(rawBody).as(String.class).orElse(null);
        var rBody = runContext.render(body).asMap(String.class, Object.class);
        if (rBody.isEmpty() && rRawBody != null) {
            rBody = MAPPER.readValue(rRawBody, MAPPER.getTypeFactory().constructMapType(Map.class, String.class, Object.class));
        }
        if (rBody.isEmpty()) {
            throw new IllegalArgumentException("body (or rawBody) is required to parse a GitGuardian webhook event.");
        }
        Map<String, List<String>> rHeaders = runContext.render(headers).asMap(String.class, List.class);
        var rToken = runContext.render(signatureToken).as(String.class).orElse(null);

        Boolean verified = null;
        if (rToken != null) {
            var failure = verify(rBody, rRawBody, rHeaders, rToken, runContext.render(maxClockSkew).as(Duration.class).orElse(Duration.ofMinutes(5)));
            verified = failure == null;
            if (!verified) {
                if (runContext.render(failOnInvalidSignature).as(Boolean.class).orElse(true)) {
                    throw new IllegalStateException("GitGuardian webhook rejected: " + failure);
                }
                runContext.logger().warn("GitGuardian webhook signature check failed: {}", failure);
            }
        }

        var timestamp = rBody.get("timestamp") instanceof String value ? parseInstant(value) : null;

        return Output.builder()
            .verified(verified)
            .action(stringOf(rBody.get("action")))
            .timestamp(timestamp)
            .message(stringOf(rBody.get("message")))
            .targetUser(stringOf(rBody.get("target_user")))
            .targetTeam(stringOf(rBody.get("target_team")))
            .webhookName(stringOf(rBody.get("custom_webhook_name")))
            .incident(convert(rBody.get("incident"), Incident.class))
            .honeytoken(convert(rBody.get("honeytoken"), Honeytoken.class))
            .honeytokenEvent(convert(rBody.get("honeytoken_event"), HoneytokenEvent.class))
            .occurrence(rBody.get("occurrence") instanceof Map<?, ?> occurrence ? (Map<String, Object>) occurrence : null)
            .payload(rBody)
            .build();
    }

    /** Returns {@code null} when valid, otherwise a plain-language reason. */
    private static String verify(Map<String, Object> body, String rawBody, Map<String, List<String>> headers, String token, Duration maxClockSkew) throws Exception {
        var signature = header(headers, SIGNATURE_HEADERS);
        if (signature == null) {
            return "no Gitguardian-Signature header. Enable the signature token on the GitGuardian custom webhook or remove signatureToken from the task.";
        }
        var timestamp = header(headers, List.of(TIMESTAMP_HEADER));
        if (timestamp == null) {
            return "no Timestamp header, cannot compute the signature.";
        }
        var sent = parseInstant(timestamp);
        if (sent == null) {
            return "unparseable Timestamp header '%s'.".formatted(timestamp);
        }
        var skew = Duration.between(sent, Instant.now()).abs();
        if (skew.compareTo(maxClockSkew) > 0) {
            return "event timestamp %s is %s away from now, above maxClockSkew %s (possible replay).".formatted(sent, skew, maxClockSkew);
        }

        var expected = signature.toLowerCase(Locale.ROOT).startsWith("sha256=") ? signature.substring(7) : signature;
        var candidates = rawBody != null ? List.of(rawBody) : canonicalForms(body);
        var mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec((timestamp + token).getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        for (var candidate : candidates) {
            var digest = HexFormat.of().formatHex(mac.doFinal(candidate.getBytes(StandardCharsets.UTF_8)));
            if (MessageDigest.isEqual(digest.getBytes(StandardCharsets.UTF_8), expected.toLowerCase(Locale.ROOT).getBytes(StandardCharsets.UTF_8))) {
                return null;
            }
            mac.reset();
        }
        return rawBody != null
            ? "signature does not match the raw body. Check signatureToken."
            : "signature matches none of the canonical serializations of the parsed body. Check signatureToken, or pass rawBody for a strict check.";
    }

    /** GitGuardian serializes with Python's json.dumps defaults (", " and ": " separators, ASCII-escaped, insertion order); the compact Jackson form is tried too. */
    private static List<String> canonicalForms(Map<String, Object> body) throws Exception {
        var python = new StringBuilder();
        writePython(body, python);
        return List.of(python.toString(), MAPPER.writeValueAsString(body));
    }

    private static void writePython(Object value, StringBuilder out) {
        switch (value) {
            case null -> out.append("null");
            case Map<?, ?> map -> {
                out.append('{');
                var first = true;
                for (var entry : map.entrySet()) {
                    if (!first) {
                        out.append(", ");
                    }
                    first = false;
                    writePythonString(String.valueOf(entry.getKey()), out);
                    out.append(": ");
                    writePython(entry.getValue(), out);
                }
                out.append('}');
            }
            case Iterable<?> iterable -> {
                out.append('[');
                var first = true;
                for (var item : iterable) {
                    if (!first) {
                        out.append(", ");
                    }
                    first = false;
                    writePython(item, out);
                }
                out.append(']');
            }
            case String string -> writePythonString(string, out);
            case Boolean bool -> out.append(bool ? "true" : "false");
            case Number number -> out.append(number);
            default -> writePythonString(String.valueOf(value), out);
        }
    }

    private static void writePythonString(String value, StringBuilder out) {
        out.append('"');
        for (int i = 0; i < value.length(); i++) {
            var ch = value.charAt(i);
            switch (ch) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                case '\b' -> out.append("\\b");
                case '\f' -> out.append("\\f");
                default -> {
                    if (ch < 0x20 || ch > 0x7e) {
                        out.append(String.format("\\u%04x", (int) ch));
                    } else {
                        out.append(ch);
                    }
                }
            }
        }
        out.append('"');
    }

    private static String header(Map<String, List<String>> headers, List<String> names) {
        if (headers == null) {
            return null;
        }
        for (var entry : headers.entrySet()) {
            if (entry.getKey() != null && names.contains(entry.getKey().toLowerCase(Locale.ROOT)) && entry.getValue() != null && !entry.getValue().isEmpty()) {
                return String.valueOf(entry.getValue().getFirst());
            }
        }
        return null;
    }

    private static Instant parseInstant(String value) {
        try {
            return Instant.parse(value);
        } catch (Exception e) {
            try {
                return java.time.OffsetDateTime.parse(value).toInstant();
            } catch (Exception ignored) {
                return null;
            }
        }
    }

    private static <T> T convert(Object node, Class<T> type) {
        return node instanceof Map<?, ?> ? MAPPER.convertValue(node, type) : null;
    }

    private static String stringOf(Object value) {
        return value == null ? null : String.valueOf(value);
    }

    @Builder
    @Getter
    public static class Output implements io.kestra.core.models.tasks.Output {
        @Schema(title = "Whether the signature and timestamp were verified", description = "Null when `signatureToken` is not set.")
        private final Boolean verified;

        @Schema(title = "Event action", description = "For example `incident_triggered`, `new_occurrence`, `incident_validity_changed`, `incident_severity_changed`, `incident_resolved`, `incident_ignored`, `incident_reopened`, `incident_regression`, `incident_assigned`, `incident_note_created`, `honeytoken_triggered`, or `new_honeytoken_event`.")
        private final String action;

        @Schema(title = "Event timestamp")
        private final Instant timestamp;

        @Schema(title = "Human-readable message")
        private final String message;

        @Schema(title = "Target user email, when the event concerns a user")
        private final String targetUser;

        @Schema(title = "Target team name")
        private final String targetTeam;

        @Schema(title = "Name of the custom webhook that sent the event")
        private final String webhookName;

        @Schema(title = "The incident, typed like the incident tasks", description = "Null for events without an incident, such as honeytoken events.")
        private final Incident incident;

        @Schema(title = "The honeytoken, for `honeytoken_triggered` events")
        private final Honeytoken honeytoken;

        @Schema(title = "The honeytoken event, for `new_honeytoken_event` events")
        private final HoneytokenEvent honeytokenEvent;

        @Schema(title = "The occurrence, for `new_occurrence` events", description = "Raw GitGuardian fields: `id`, `incident_id`, `kind`, `sha`, `author_name`, `date`, `url`, `source`, and match positions.")
        private final Map<String, Object> occurrence;

        @Schema(title = "The full event payload as sent by GitGuardian")
        private final Map<String, Object> payload;
    }
}
