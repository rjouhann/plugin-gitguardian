package io.kestra.plugin.gitguardian.incidents;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** The GitGuardian detector that found a secret. */
@Getter
@Setter
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class Detector {
    @Schema(title = "Detector name", description = "For example `aws_iam`.")
    private String name;

    @Schema(title = "Detector display name", description = "For example `AWS Keys`.")
    @JsonAlias("display_name")
    private String displayName;

    @Schema(title = "Detector nature", description = "`specific` or `generic`.")
    private String nature;

    @Schema(title = "Detector family", description = "For example `apikey`, `token`, or `private_key`.")
    private String family;

    @Schema(title = "Detector group name")
    @JsonAlias("detector_group_name")
    private String detectorGroupName;

    @Schema(title = "Detector group display name")
    @JsonAlias("detector_group_display_name")
    private String detectorGroupDisplayName;
}
