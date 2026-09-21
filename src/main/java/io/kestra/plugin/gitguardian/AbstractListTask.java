package io.kestra.plugin.gitguardian;

import io.kestra.core.models.annotations.PluginProperty;
import io.kestra.core.models.property.Property;
import io.kestra.core.models.tasks.common.FetchType;
import io.kestra.core.runners.RunContext;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import lombok.experimental.SuperBuilder;

import java.util.LinkedHashMap;
import java.util.Map;

/** Base for every list task: the shared pagination and `fetchType` properties, resolved once in {@link #list}. */
@SuperBuilder
@ToString
@EqualsAndHashCode
@Getter
@NoArgsConstructor
public abstract class AbstractListTask extends AbstractGitGuardianTask {
    @Schema(title = "Maximum number of items to return", description = "Stops paginating once reached. Unlimited when omitted.")
    @PluginProperty(group = "processing")
    protected Property<@Min(1) Integer> maxResults;

    @Schema(title = "Page size", description = "Internal pagination page size, from 1 to 100. Defaults to `100`.")
    @Builder.Default
    @PluginProperty(group = "advanced")
    protected Property<@Min(1) @Max(100) Integer> perPage = Property.ofValue(100);

    @Schema(
        title = "Fetch type",
        description = "`FETCH_ONE` outputs the first matching item as `row`, `FETCH` outputs every matching item as `rows`, `STORE` streams every matching item to internal storage and returns a `uri`, `NONE` only counts. Defaults to `FETCH`."
    )
    @Builder.Default
    @PluginProperty(group = "execution")
    protected Property<FetchType> fetchType = Property.ofValue(FetchType.FETCH);

    /** Adds `per_page`, drops null filters, and runs the list with the rendered `fetchType` and `maxResults`. */
    protected <T> ListRunner.Result<T> list(RunContext runContext, GitGuardianClient client, String path, Map<String, Object> filters, String scope, Class<T> itemType) throws Exception {
        var query = new LinkedHashMap<String, Object>(filters);
        query.put("per_page", runContext.render(perPage).as(Integer.class).orElse(100));
        query.values().removeIf(value -> value == null);
        var rFetchType = runContext.render(fetchType).as(FetchType.class).orElse(FetchType.FETCH);
        var rMaxResults = runContext.render(maxResults).as(Integer.class).orElse(null);
        runContext.logger().info("Listing GitGuardian {} with filters {}", path, query);
        return ListRunner.run(runContext, client, path, query, scope, itemType, rFetchType, rMaxResults);
    }
}
