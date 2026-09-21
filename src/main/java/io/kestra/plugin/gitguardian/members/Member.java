package io.kestra.plugin.gitguardian.members;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;

/** A workspace member, as returned by `GET /v1/members`. */
@Getter
@Setter
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class Member {
    @Schema(title = "Member ID")
    private Long id;

    @Schema(title = "Name")
    private String name;

    @Schema(title = "Email")
    private String email;

    @Schema(title = "Role", description = "For example `owner`, `manager`, `member`, or `restricted`.")
    private String role;

    @Schema(title = "Access level", description = "Legacy name of the role.")
    @JsonAlias("access_level")
    private String accessLevel;

    @Schema(title = "Whether the member is active on the workspace")
    private Boolean active;

    @Schema(title = "Creation date")
    @JsonAlias("created_at")
    private Instant createdAt;

    @Schema(title = "Last login date")
    @JsonAlias("last_login")
    private Instant lastLogin;
}
