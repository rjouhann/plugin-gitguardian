package io.kestra.plugin.gitguardian.honeytokens;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/** One use of a honeytoken, as returned by `GET /v1/honeytokens_events`. */
@Getter
@Setter
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class HoneytokenEvent {
    @Schema(title = "Event ID")
    private String id;

    @Schema(title = "ID of the honeytoken that was used")
    @JsonAlias("honeytoken_id")
    private String honeytokenId;

    @Schema(title = "When the honeytoken was used")
    @JsonAlias("triggered_at")
    private Instant triggeredAt;

    @Schema(title = "Event status", description = "`open` or `closed`.")
    private String status;

    @Schema(title = "Source IP address")
    @JsonAlias("ip_address")
    private String ipAddress;

    @Schema(title = "Action performed with the honeytoken", description = "For example `GetCallerIdentity`.")
    private String action;

    @Schema(title = "Event URL on the GitGuardian dashboard")
    @JsonAlias("gitguardian_url")
    private String gitguardianUrl;

    @Schema(title = "Additional event data", description = "For example user agent, AWS region, or geolocation.")
    private Map<String, Object> data;

    @Schema(title = "GitGuardian tags")
    private List<String> tags;
}
