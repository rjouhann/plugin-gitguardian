package io.kestra.plugin.gitguardian.incidents;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;

/** A note (comment) on a secret incident. */
@Getter
@Setter
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class IncidentNote {
    @Schema(title = "Note ID")
    private Long id;

    @Schema(title = "Incident ID")
    @JsonAlias("incident_id")
    private Long incidentId;

    @Schema(title = "ID of the member who wrote the note", description = "Null when written with an API token.")
    @JsonAlias("member_id")
    private Long memberId;

    @Schema(title = "Name of the API token that wrote the note", description = "Null when written by a member.")
    @JsonAlias("api_token")
    private String apiToken;

    @Schema(title = "Creation date")
    @JsonAlias("created_at")
    private Instant createdAt;

    @Schema(title = "Note content")
    private String comment;
}
