package io.kestra.plugin.gitguardian.scan;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

/** Scan result of one document, as returned by `POST /v1/scan` (one) or `POST /v1/multiscan` (one per input document). */
@Getter
@Setter
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class ScanResult {
    @Schema(title = "Name of the scanned document", description = "Set by the task from the input `filename` or file name; GitGuardian does not echo it back.")
    private String filename;

    @Schema(title = "Number of policy breaks in this document")
    @JsonAlias("policy_break_count")
    private Integer policyBreakCount;

    @Schema(title = "Policies checked", description = "For example `Secrets detection`.")
    private List<String> policies;

    @Schema(title = "Policy breaks found in this document")
    @JsonAlias("policy_breaks")
    private List<PolicyBreak> policyBreaks;
}
