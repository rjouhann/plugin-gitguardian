package io.kestra.plugin.gitguardian;

import java.util.List;

/** One page of a cursor-paginated GitGuardian list endpoint; {@code nextCursor} is {@code null} on the last page. */
public record GitGuardianPage<T>(List<T> items, String nextCursor) {
    public boolean hasNext() {
        return nextCursor != null;
    }
}
