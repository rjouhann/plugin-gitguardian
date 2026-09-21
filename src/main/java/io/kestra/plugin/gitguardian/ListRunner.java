package io.kestra.plugin.gitguardian;

import com.fasterxml.jackson.core.type.TypeReference;
import io.kestra.core.models.tasks.common.FetchType;
import io.kestra.core.runners.RunContext;
import io.kestra.core.serializers.FileSerde;
import io.kestra.core.serializers.JacksonMapper;
import reactor.core.publisher.Flux;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.lang.reflect.Type;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Shared implementation of the `fetchType` contract for every list task: walks a cursor-paginated
 * endpoint, caps at {@code maxResults}, and either returns rows, the first row, a count, or an Ion
 * file in internal storage.
 */
public final class ListRunner {
    private ListRunner() {
    }

    public record Result<T>(T row, List<T> rows, URI uri, long size) {
    }

    public static <T> Result<T> run(RunContext runContext, GitGuardianClient client, String path, Map<String, Object> query, String scope, Class<T> itemType, FetchType fetchType, Integer maxResults) throws Exception {
        var cap = fetchType == FetchType.FETCH_ONE ? 1 : (maxResults != null ? maxResults : Integer.MAX_VALUE);
        return switch (fetchType) {
            case FETCH_ONE -> {
                var rows = fetch(client, path, query, scope, itemType, 1);
                yield new Result<>(rows.isEmpty() ? null : rows.getFirst(), null, null, rows.size());
            }
            case FETCH -> {
                var rows = fetch(client, path, query, scope, itemType, cap);
                yield new Result<>(null, rows, null, rows.size());
            }
            case STORE -> store(runContext, client, path, query, scope, itemType, cap);
            case NONE -> {
                var count = new AtomicLong();
                walk(client, path, query, scope, itemType, cap, page -> count.addAndGet(page.size()));
                yield new Result<>(null, null, null, count.get());
            }
        };
    }

    private static <T> List<T> fetch(GitGuardianClient client, String path, Map<String, Object> query, String scope, Class<T> itemType, int cap) throws Exception {
        var rows = new ArrayList<T>();
        walk(client, path, query, scope, itemType, cap, rows::addAll);
        return rows;
    }

    private static <T> Result<T> store(RunContext runContext, GitGuardianClient client, String path, Map<String, Object> query, String scope, Class<T> itemType, int cap) throws Exception {
        var tempFile = runContext.workingDir().createTempFile(".ion").toFile();
        long size;
        var typeReference = new TypeReference<T>() {
            @Override
            public Type getType() {
                return itemType;
            }
        };
        try (var writer = new BufferedWriter(new FileWriter(tempFile), FileSerde.BUFFER_SIZE);
             var sequenceWriter = FileSerde.createSequenceWriter(JacksonMapper.ofIon(), writer, typeReference)) {
            size = walk(client, path, query, scope, itemType, cap, page -> {
                if (!page.isEmpty()) {
                    FileSerde.writeAll(Flux.fromIterable(page), sequenceWriter).block();
                }
            });
        }
        return new Result<>(null, null, runContext.storage().putFile(tempFile), size);
    }

    /** Walks pages, truncating the last one so no more than {@code cap} items reach {@code consumer}. */
    private static <T> long walk(GitGuardianClient client, String path, Map<String, Object> query, String scope, Class<T> itemType, int cap, PageConsumer<T> consumer) throws Exception {
        var delivered = new AtomicLong();
        client.walk(path, query, scope, itemType, page -> {
            var remaining = cap - delivered.get();
            var slice = page.size() > remaining ? page.subList(0, (int) remaining) : page;
            consumer.accept(slice);
            delivered.addAndGet(slice.size());
            return delivered.get() < cap;
        });
        return delivered.get();
    }

    @FunctionalInterface
    private interface PageConsumer<T> {
        void accept(List<T> page) throws Exception;
    }
}
