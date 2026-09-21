package io.kestra.plugin.gitguardian.auditlogs;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/** One workspace audit log entry, as returned by `GET /v1/audit_logs`. */
@Getter
@Setter
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class AuditLog {
    @Schema(title = "Audit log entry ID")
    private Long id;

    @Schema(title = "Event date")
    private Instant date;

    @Schema(title = "Event name", description = "For example `incident.ignored`, `api_token.created`, or `member.invited`. `GET /v1/audit_logs/event_names` lists them all.")
    @JsonAlias("event_name")
    private String eventName;

    @Schema(title = "Action type", description = "For example `create`, `update`, or `delete`.")
    @JsonAlias("action_type")
    private String actionType;

    @Schema(title = "Email of the member who performed the action")
    @JsonAlias("member_email")
    private String memberEmail;

    @Schema(title = "Name of the member at the time of the action")
    @JsonAlias("member_name")
    private String memberName;

    @Schema(title = "ID of the member who performed the action", description = "Null when the member was deleted or the action came from an API token.")
    @JsonAlias("member_id")
    private Long memberId;

    @Schema(title = "ID of the API token used, when the action came through the API")
    @JsonAlias("api_token_id")
    private String apiTokenId;

    @Schema(title = "Source IP address")
    @JsonAlias("ip_address")
    private String ipAddress;

    @Schema(title = "IDs of the objects targeted by the action")
    @JsonAlias("target_ids")
    private List<Object> targetIds;

    @Schema(title = "Additional event data")
    private Map<String, Object> data;
}
