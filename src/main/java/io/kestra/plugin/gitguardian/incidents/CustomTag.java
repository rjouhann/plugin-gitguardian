package io.kestra.plugin.gitguardian.incidents;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** A user-defined key/value tag set on an incident or honeytoken. */
@Getter
@Setter
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class CustomTag {
    @Schema(title = "Custom tag ID")
    private String id;

    @Schema(title = "Custom tag key")
    private String key;

    @Schema(title = "Custom tag value", description = "Null for key-only tags.")
    private String value;
}
