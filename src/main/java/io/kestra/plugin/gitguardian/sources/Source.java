package io.kestra.plugin.gitguardian.sources;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Map;

/** A monitored source (repository, project, bucket, channel) as returned by `GET /v1/sources`. */
@Getter
@Setter
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class Source {
    @Schema(title = "Source ID")
    private Long id;

    @Schema(title = "Source URL")
    private String url;

    @Schema(title = "Source type", description = "For example `github`, `gitlab`, `bitbucket`, `azure_devops`, `slack`, `jira_cloud`, or `custom`.")
    private String type;

    @Schema(title = "Full name", description = "For example `org/repository`.")
    @JsonAlias("full_name")
    private String fullName;

    @Schema(title = "Health", description = "`safe`, `unknown`, or `at_risk`, based on open incidents.")
    private String health;

    @Schema(title = "Visibility", description = "`public`, `private`, or `internal`.")
    private String visibility;

    @Schema(title = "Criticality", description = "`critical`, `high`, `medium`, `low`, or `unknown`.")
    @JsonAlias("source_criticality")
    private String sourceCriticality;

    @Schema(title = "Real-time monitoring status", description = "`active`, `disabled`, `unreachable`, `archived`, or `deleted_on_remote`.")
    @JsonAlias("monitoring_status")
    private String monitoringStatus;

    @Schema(title = "Default branch")
    @JsonAlias("default_branch")
    private String defaultBranch;

    @Schema(title = "Provider identifier of the source")
    @JsonAlias("external_id")
    private String externalId;

    @Schema(title = "Number of open secret incidents")
    @JsonAlias("open_incidents_count")
    private Integer openIncidentsCount;

    @Schema(title = "Number of closed secret incidents")
    @JsonAlias("closed_incidents_count")
    private Integer closedIncidentsCount;

    @Schema(title = "Last historical scan", description = "Object with `date`, `status`, and `failing_reason`.")
    @JsonAlias("last_scan")
    private Map<String, Object> lastScan;

    @Schema(title = "Whether the source was deleted")
    private Boolean deleted;
}
