package io.kestra.plugin.gitguardian;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.kestra.core.http.HttpRequest;
import io.kestra.core.http.HttpResponse;
import io.kestra.core.http.client.HttpClient;
import io.kestra.core.http.client.HttpClientResponseException;
import io.kestra.core.serializers.JacksonMapper;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.io.Closeable;
import java.io.IOException;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Wraps a Kestra {@link HttpClient} with GitGuardian's token authentication, query-string building,
 * `Link`-header cursor pagination, 429 retries and non-2xx error mapping. One instance is scoped to a
 * single task run or trigger poll and must be closed by its owner.
 */
public final class GitGuardianClient implements Closeable {
    public static final String USER_AGENT = "kestra-plugin-gitguardian";

    private static final ObjectMapper MAPPER = JacksonMapper.ofJson();
    private static final Pattern LINK_NEXT = Pattern.compile("<([^>]+)>\\s*;\\s*rel=\"next\"");
    private static final int MAX_RATE_LIMIT_RETRIES = 3;
    private static final long DEFAULT_RETRY_AFTER_SECONDS = 2;
    private static final long MAX_RETRY_AFTER_SECONDS = 60;
    private static final int MAX_PAGES = 1000;

    private final HttpClient httpClient;
    private final String apiBaseUrl;
    private final String apiKey;

    public GitGuardianClient(HttpClient httpClient, String apiUrl, String apiKey) {
        this.httpClient = httpClient;
        var normalized = apiUrl.endsWith("/") ? apiUrl.substring(0, apiUrl.length() - 1) : apiUrl;
        this.apiBaseUrl = normalized.endsWith("/v1") ? normalized : normalized + "/v1";
        this.apiKey = apiKey;
    }

    public <T> T get(String path, Map<String, Object> query, String scope, Class<T> type) throws Exception {
        return parse(raw("GET", path, query, null, scope).getBody(), type);
    }

    public <T> GitGuardianPage<T> getPage(String path, Map<String, Object> query, String cursor, String scope, Class<T> itemType) throws Exception {
        var pageQuery = new LinkedHashMap<String, Object>(query != null ? query : Map.of());
        if (cursor != null) {
            pageQuery.put("cursor", cursor);
        }
        var response = raw("GET", path, pageQuery, null, scope);
        return new GitGuardianPage<>(parseList(response.getBody(), itemType), nextCursor(response));
    }

    /** Streams every page of a list endpoint to {@code consumer} and returns the number of items seen. */
    public <T> long walk(String path, Map<String, Object> query, String scope, Class<T> itemType, PageConsumer<T> consumer) throws Exception {
        String cursor = null;
        long total = 0;
        for (int pages = 0; ; pages++) {
            if (pages >= MAX_PAGES) {
                throw new GitGuardianApiException("GitGuardian pagination exceeded %d pages on %s. Narrow the query with filters.".formatted(MAX_PAGES, path));
            }
            var page = getPage(path, query, cursor, scope, itemType);
            total += page.items().size();
            if (!consumer.accept(page.items()) || !page.hasNext()) {
                return total;
            }
            cursor = page.nextCursor();
        }
    }

    public <T> T post(String path, Object jsonBody, String scope, Class<T> type) throws Exception {
        return parse(raw("POST", path, null, jsonBody, scope).getBody(), type);
    }

    public <T> List<T> postList(String path, Object jsonBody, String scope, Class<T> itemType) throws Exception {
        return parseList(raw("POST", path, null, jsonBody, scope).getBody(), itemType);
    }

    public <T> T patch(String path, Object jsonBody, String scope, Class<T> type) throws Exception {
        return parse(raw("PATCH", path, null, jsonBody, scope).getBody(), type);
    }

    @Override
    public void close() throws IOException {
        httpClient.close();
    }

    @FunctionalInterface
    public interface PageConsumer<T> {
        /** Returns {@code false} to stop walking after this page. */
        boolean accept(List<T> page) throws Exception;
    }

    private <T> T parse(String body, Class<T> type) throws IOException {
        if (body == null || body.isBlank()) {
            return null;
        }
        return MAPPER.readValue(body, type);
    }

    private <T> List<T> parseList(String body, Class<T> itemType) throws IOException {
        if (body == null || body.isBlank()) {
            return List.of();
        }
        var listType = MAPPER.getTypeFactory().constructCollectionType(List.class, itemType);
        return MAPPER.readValue(body, listType);
    }

    private HttpResponse<String> raw(String method, String path, Map<String, Object> query, Object jsonBody, String scope) throws Exception {
        return raw(method, path, query, jsonBody, scope, 0);
    }

    private HttpResponse<String> raw(String method, String path, Map<String, Object> query, Object jsonBody, String scope, int rateLimitRetries) throws Exception {
        var builder = HttpRequest.builder()
            .method(method)
            .uri(buildUri(path, query))
            .addHeader("Authorization", "Token " + apiKey)
            .addHeader("Accept", "application/json")
            .addHeader("User-Agent", USER_AGENT);

        if (jsonBody != null) {
            builder
                .addHeader("Content-Type", "application/json")
                .body(HttpRequest.JsonRequestBody.builder().content(jsonBody).build());
        }

        try {
            return httpClient.request(builder.build(), String.class);
        } catch (HttpClientResponseException e) {
            var status = e.getResponse().getStatus().getCode();
            if (status == 429 && rateLimitRetries < MAX_RATE_LIMIT_RETRIES) {
                Thread.sleep(Math.max(retryAfterSeconds(e), 1) * 1000L);
                return raw(method, path, query, jsonBody, scope, rateLimitRetries + 1);
            }
            throw mapError(e, method, path, scope);
        }
    }

    private URI buildUri(String path, Map<String, Object> query) {
        var uri = apiBaseUrl + path;
        if (query == null || query.isEmpty()) {
            return URI.create(uri);
        }
        var params = query.entrySet().stream()
            .filter(entry -> entry.getValue() != null)
            .map(entry -> encode(entry.getKey()) + "=" + encode(queryValue(entry.getValue())))
            .collect(Collectors.joining("&"));
        return URI.create(params.isEmpty() ? uri : uri + "?" + params);
    }

    private static String queryValue(Object value) {
        if (value instanceof Collection<?> collection) {
            return collection.stream().map(String::valueOf).collect(Collectors.joining(","));
        }
        return String.valueOf(value);
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static String nextCursor(HttpResponse<String> response) {
        var link = response.getHeaders().firstValue("Link").orElse(null);
        if (link == null) {
            return null;
        }
        var matcher = LINK_NEXT.matcher(link);
        if (!matcher.find()) {
            return null;
        }
        var nextUri = URI.create(matcher.group(1));
        var rawQuery = nextUri.getRawQuery();
        if (rawQuery == null) {
            return null;
        }
        for (var param : rawQuery.split("&")) {
            var separator = param.indexOf('=');
            if (separator > 0 && "cursor".equals(param.substring(0, separator))) {
                return URLDecoder.decode(param.substring(separator + 1), StandardCharsets.UTF_8);
            }
        }
        return null;
    }

    private long retryAfterSeconds(HttpClientResponseException e) {
        try {
            var header = e.getResponse().getHeaders().firstValue("Retry-After").orElse(String.valueOf(DEFAULT_RETRY_AFTER_SECONDS));
            return Math.min(Long.parseLong(header.trim()), MAX_RETRY_AFTER_SECONDS);
        } catch (NumberFormatException nfe) {
            return DEFAULT_RETRY_AFTER_SECONDS;
        }
    }

    private GitGuardianApiException mapError(HttpClientResponseException e, String method, String path, String scope) {
        var status = e.getResponse().getStatus().getCode();
        var detail = errorDetail(e);

        var hint = switch (status) {
            case 401 -> " Check that apiKey is a valid GitGuardian token and that apiUrl matches your workspace region (US: api.gitguardian.com, EU: api.eu1.gitguardian.com).";
            case 403 -> scope != null
                ? " Check that the token has the '%s' scope.".formatted(scope)
                : " Check the token scopes.";
            case 404 -> " Check the resource ID and that the token's workspace owns it.";
            case 429 -> " GitGuardian rate limit or quota exceeded; reduce call frequency or the polling interval.";
            default -> "";
        };

        return new GitGuardianApiException(
            "GitGuardian API %s %s failed with HTTP %d: %s.%s".formatted(method, path, status, detail.endsWith(".") ? detail.substring(0, detail.length() - 1) : detail, hint),
            status
        );
    }

    /** Only ever includes the response body GitGuardian returned, never the request or its headers. */
    private String errorDetail(HttpClientResponseException e) {
        var rawBody = e.getResponse().getBody();
        var body = switch (rawBody) {
            case null -> "";
            case byte[] bytes -> new String(bytes, StandardCharsets.UTF_8);
            default -> String.valueOf(rawBody);
        };
        if (body.isBlank()) {
            return e.getResponse().getStatus().getReason();
        }
        try {
            var envelope = MAPPER.readValue(body, ErrorEnvelope.class);
            if (envelope.getDetail() != null && !envelope.getDetail().isBlank()) {
                return envelope.getDetail();
            }
        } catch (IOException ignored) {
            // Not the {"detail": ...} envelope; fall through to the raw body.
        }
        return body.length() > 500 ? body.substring(0, 500) + "..." : body;
    }

    @Getter
    @Setter
    @NoArgsConstructor
    @JsonIgnoreProperties(ignoreUnknown = true)
    private static class ErrorEnvelope {
        private String detail;
    }
}
