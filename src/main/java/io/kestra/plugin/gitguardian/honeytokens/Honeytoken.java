package io.kestra.plugin.gitguardian.honeytokens;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import io.kestra.plugin.gitguardian.incidents.CustomTag;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;
import java.util.List;

/**
 * A honeytoken as returned by the `/v1/honeytokens` endpoints. The `token` object (the decoy credential
 * itself) is deliberately not mapped here; `Create` returns it once, encrypted, in its own output.
 */
@Getter
@Setter
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class Honeytoken {
    @Schema(title = "Honeytoken ID")
    private String id;

    @Schema(title = "Name")
    private String name;

    @Schema(title = "Description")
    private String description;

    @Schema(title = "Type", description = "Currently `AWS`.")
    private String type;

    @Schema(title = "Status", description = "`active`, `triggered`, or `revoked`.")
    private String status;

    @Schema(title = "Creation date")
    @JsonAlias("created_at")
    private Instant createdAt;

    @Schema(title = "Last date the honeytoken switched from active to triggered")
    @JsonAlias("triggered_at")
    private Instant triggeredAt;

    @Schema(title = "Revocation date")
    @JsonAlias("revoked_at")
    private Instant revokedAt;

    @Schema(title = "Honeytoken URL on the GitGuardian dashboard")
    @JsonAlias("gitguardian_url")
    private String gitguardianUrl;

    @Schema(title = "Number of open events")
    @JsonAlias("open_events_count")
    private Integer openEventsCount;

    @Schema(title = "ID of the member who created it")
    @JsonAlias("creator_id")
    private Long creatorId;

    @Schema(title = "GitGuardian tags")
    private List<String> tags;

    @Schema(title = "Custom tags")
    @JsonAlias("custom_tags")
    private List<CustomTag> customTags;
}
