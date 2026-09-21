package io.kestra.plugin.gitguardian.webhooks;

import io.kestra.core.junit.annotations.KestraTest;
import io.kestra.core.models.property.Property;
import io.kestra.core.runners.RunContextFactory;
import io.kestra.core.utils.IdUtils;
import io.kestra.core.serializers.JacksonMapper;
import io.kestra.plugin.gitguardian.incidents.IncidentStatus;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;

@KestraTest
class ReceiveTest {
    private static final String TOKEN = "webhook-signature-token";

    @Inject
    private RunContextFactory runContextFactory;

    /** Python json.dumps default formatting, as GitGuardian sends it. */
    private static String pythonPayload(String timestamp) {
        return "{\"source\": \"GitGuardian\", \"timestamp\": \"" + timestamp + "\", \"action\": \"incident_triggered\", \"message\": \"A new incident has been detected.\", "
            + "\"target_user\": null, \"target_team\": \"S\\u00e9curit\\u00e9\", \"custom_webhook_name\": \"kestra\", "
            + "\"incident\": {\"id\": 31542, \"date\": \"2026-09-21T07:45:31.666462Z\", \"detector\": {\"name\": \"generic_password\", \"display_name\": \"Generic Password\", \"nature\": \"generic\", \"family\": \"Other\", \"detector_group_name\": \"generic_password\", \"detector_group_display_name\": \"Generic Password\"}, "
            + "\"secret_hash\": \"xxx\", \"secret_revoked\": false, \"validity\": \"no_checker\", \"occurrence_count\": 2, \"status\": \"triggered\", \"regression\": false, \"assignee_email\": null, \"severity\": \"unknown\", "
            + "\"gitguardian_url\": \"https://dashboard.gitguardian.com/workspace/1/incidents/31542\", \"share_url\": null, \"feedbacks\": []}}";
    }

    private static String sign(String timestamp, String payload) throws Exception {
        var mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec((timestamp + TOKEN).getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        return "sha256=" + HexFormat.of().formatHex(mac.doFinal(payload.getBytes(StandardCharsets.UTF_8)));
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> parsed(String payload) throws Exception {
        return JacksonMapper.ofJson().readValue(payload, Map.class);
    }

    @Test
    void verifiesPythonFormattedPayloadFromParsedBodyAndTypesTheIncident() throws Exception {
        var timestamp = Instant.now().toString();
        var payload = pythonPayload(timestamp);

        var output = Receive.builder()
            .id(IdUtils.create()).type(Receive.class.getName())
            .body(Property.ofValue(parsed(payload)))
            .headers(Property.ofValue(Map.of("Gitguardian-Signature", List.of(sign(timestamp, payload)), "Timestamp", List.of(timestamp))))
            .signatureToken(Property.ofValue(TOKEN))
            .build()
            .run(runContextFactory.of(Map.of()));

        assertThat(output.getVerified(), is(true));
        assertThat(output.getAction(), is("incident_triggered"));
        assertThat(output.getTargetTeam(), is("Sécurité"));
        assertThat(output.getIncident().getId(), is(31542L));
        assertThat(output.getIncident().getStatus(), is(IncidentStatus.TRIGGERED));
        assertThat(output.getIncident().getOccurrencesCount(), is(2));
        assertThat(output.getIncident().getDetector().getName(), is("generic_password"));
    }

    @Test
    void verifiesStrictlyFromRawBody() throws Exception {
        var timestamp = Instant.now().toString();
        var payload = pythonPayload(timestamp);

        var output = Receive.builder()
            .id(IdUtils.create()).type(Receive.class.getName())
            .rawBody(Property.ofValue(payload))
            .headers(Property.ofValue(Map.of("x-gitguardian-signature", List.of(sign(timestamp, payload)), "timestamp", List.of(timestamp))))
            .signatureToken(Property.ofValue(TOKEN))
            .build()
            .run(runContextFactory.of(Map.of()));

        assertThat(output.getVerified(), is(true));
        assertThat(output.getIncident().getId(), is(31542L));
    }

    @Test
    void rejectsTamperedPayload() throws Exception {
        var timestamp = Instant.now().toString();
        var payload = pythonPayload(timestamp);
        var tampered = parsed(payload);
        ((Map<String, Object>) tampered.get("incident")).put("id", 1);

        var task = Receive.builder()
            .id(IdUtils.create()).type(Receive.class.getName())
            .body(Property.ofValue(tampered))
            .headers(Property.ofValue(Map.of("Gitguardian-Signature", List.of(sign(timestamp, payload)), "Timestamp", List.of(timestamp))))
            .signatureToken(Property.ofValue(TOKEN))
            .build();

        var exception = assertThrows(IllegalStateException.class, () -> task.run(runContextFactory.of(Map.of())));

        assertThat(exception.getMessage(), containsString("signature matches none"));
    }

    @Test
    void rejectsStaleTimestampUnlessAsked() throws Exception {
        var timestamp = Instant.now().minus(Duration.ofHours(1)).toString();
        var payload = pythonPayload(timestamp);
        var headers = Map.of("Gitguardian-Signature", List.of(sign(timestamp, payload)), "Timestamp", List.of(timestamp));

        var strict = Receive.builder()
            .id(IdUtils.create()).type(Receive.class.getName())
            .body(Property.ofValue(parsed(payload))).headers(Property.ofValue(headers)).signatureToken(Property.ofValue(TOKEN))
            .build();
        var exception = assertThrows(IllegalStateException.class, () -> strict.run(runContextFactory.of(Map.of())));
        assertThat(exception.getMessage(), containsString("possible replay"));

        var lenient = Receive.builder()
            .id(IdUtils.create()).type(Receive.class.getName())
            .body(Property.ofValue(parsed(payload))).headers(Property.ofValue(headers)).signatureToken(Property.ofValue(TOKEN))
            .failOnInvalidSignature(Property.ofValue(false))
            .build()
            .run(runContextFactory.of(Map.of()));
        assertThat(lenient.getVerified(), is(false));
        assertThat(lenient.getAction(), is("incident_triggered"));
    }

    @Test
    void typesHoneytokenAndEventPayloads() throws Exception {
        var triggered = parsed("""
            {"source":"GitGuardian","timestamp":"2026-09-21T08:22:19.913732Z","action":"honeytoken_triggered","message":"This honeytoken has been triggered.","target_user":null,
             "honeytoken":{"id":"12d14831","name":"ht27","description":"","created_at":"2026-04-12T10:21:28.972903Z","gitguardian_url":"https://dashboard/ht/12d14831","status":"triggered","triggered_at":"2026-09-21T08:22:19.838234Z","revoked_at":null,"open_events_count":1,"type":"AWS","creator_id":397542}}
            """);
        var event = parsed("""
            {"source":"GitGuardian","timestamp":"2026-09-21T15:56:42.171075Z","action":"new_honeytoken_event","message":"A new honeytoken event has been received.","target_user":null,
             "honeytoken_event":{"id":"2bdc644e","honeytoken_id":"12d14831","triggered_at":"2026-09-21T15:56:37Z","status":"open","ip_address":"54.39.187.211","action":"GetCallerIdentity","data":{"user_agent":"python-requests/2.28.2"},"tags":[]}}
            """);

        var first = Receive.builder().id(IdUtils.create()).type(Receive.class.getName()).body(Property.ofValue(triggered)).build().run(runContextFactory.of(Map.of()));
        assertThat(first.getHoneytoken().getName(), is("ht27"));
        assertThat(first.getHoneytoken().getStatus(), is("triggered"));
        assertThat(first.getIncident(), nullValue());

        var second = Receive.builder().id(IdUtils.create()).type(Receive.class.getName()).body(Property.ofValue(event)).build().run(runContextFactory.of(Map.of()));
        assertThat(second.getHoneytokenEvent().getIpAddress(), is("54.39.187.211"));
        assertThat(second.getHoneytokenEvent().getAction(), is("GetCallerIdentity"));
    }

    @Test
    void parsesWithoutVerificationWhenNoTokenConfigured() throws Exception {
        var output = Receive.builder()
            .id(IdUtils.create()).type(Receive.class.getName())
            .body(Property.ofValue(parsed(pythonPayload(Instant.now().toString()))))
            .build()
            .run(runContextFactory.of(Map.of()));

        assertThat(output.getVerified(), nullValue());
        assertThat(output.getWebhookName(), is("kestra"));
        assertThat(output.getPayload().get("source"), is("GitGuardian"));
    }
}
