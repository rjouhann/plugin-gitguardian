package io.kestra.plugin.gitguardian.teams;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** A workspace team, as returned by `GET /v1/teams`. */
@Getter
@Setter
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class Team {
    @Schema(title = "Team ID")
    private Long id;

    @Schema(title = "Name")
    private String name;

    @Schema(title = "Description")
    private String description;

    @Schema(title = "Whether this is the global (all members) team")
    @JsonAlias("is_global")
    private Boolean global;

    @Schema(title = "Team URL on the GitGuardian dashboard")
    @JsonAlias("gitguardian_url")
    private String gitguardianUrl;

    @Schema(title = "ID of the linked external provider group, when synced from an identity provider")
    @JsonAlias("external_provider_id")
    private String externalProviderId;

    @Schema(title = "Type of the linked external provider")
    @JsonAlias("external_provider_type")
    private String externalProviderType;
}
