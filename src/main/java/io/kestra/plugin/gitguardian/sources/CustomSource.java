package io.kestra.plugin.gitguardian.sources;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** A custom source, the container for incidents created through `scan.CreateIncidents`. */
@Getter
@Setter
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class CustomSource {
    @Schema(title = "Source ID")
    private String id;

    @Schema(title = "Source UUID to pass as `sourceUuid` to `scan.CreateIncidents`")
    @JsonAlias("source_uuid")
    private String sourceUuid;

    @Schema(title = "Name")
    private String name;

    @Schema(title = "Description")
    private String description;

    @Schema(title = "Whether scans keep only secrets whose detector has a validity checker")
    @JsonAlias("use_only_detectors_with_validators")
    private Boolean useOnlyDetectorsWithValidators;
}
