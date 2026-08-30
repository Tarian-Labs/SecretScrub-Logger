package secretscrublogger;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Applies the intentionally lossy guarantees of Strict Safety Mode after standard redaction.
 * Non-empty bodies are omitted, all URL query/fragment values are removed, common identifier-like
 * path segments are hidden, and non-allowlisted header values fail closed to [REDACTED].
 */
final class StrictSafetySanitizer {

    static final String OMITTED_BODY = "[OMITTED BY STRICT SAFETY MODE]";

    private static final Pattern UUID_PATTERN = Pattern.compile(
            "(?i)[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}");
    private static final Pattern LONG_NUMBER_PATTERN = Pattern.compile("[0-9]{6,}");
    private static final Pattern LONG_HEX_PATTERN = Pattern.compile("(?i)[0-9a-f]{16,}");

    private static final Set<String> URL_HEADERS = Set.of(
            "location", "content-location", "origin", "referer", "access-control-allow-origin"
    );

    private static final Set<String> SAFE_HEADER_VALUES = Set.of(
            "host", "content-type", "content-encoding", "content-length", "transfer-encoding",
            "connection", "date", "accept", "accept-encoding", "accept-language", "allow",
            "cache-control", "pragma", "expires", "age", "vary", "etag", "last-modified",
            "server", "x-powered-by", "content-range", "retry-after", "upgrade",
            "strict-transport-security", "x-frame-options", "x-content-type-options",
            "referrer-policy", "access-control-allow-methods", "access-control-allow-headers",
            "access-control-expose-headers", "access-control-allow-credentials",
            "access-control-max-age"
    );

    private StrictSafetySanitizer() {
    }

    static BodyOmissionResult omitBody(String rawMessage) {
        if (rawMessage == null) {
            return new BodyOmissionResult(null, false);
        }
        MessageParts parts = splitMessage(rawMessage);
        boolean bodyOmitted = !parts.body().isEmpty();
        return new BodyOmissionResult(
                bodyOmitted
                        ? parts.head() + parts.separator() + OMITTED_BODY
                        : rawMessage,
                bodyOmitted);
    }

    static MessageResult sanitizeMessage(String rawMessage) {
        if (rawMessage == null) {
            return new MessageResult(null, 0, false);
        }

        MessageParts parts = splitMessage(rawMessage);
        String sanitizedHead = sanitizeHead(parts.head());
        int redactionCount = Math.max(0,
                countMarkers(sanitizedHead) - countMarkers(parts.head()));
        boolean bodyOmitted = !parts.body().isEmpty();
        String body = bodyOmitted ? OMITTED_BODY : parts.body();
        return new MessageResult(
                sanitizedHead + parts.separator() + body,
                redactionCount,
                bodyOmitted);
    }

    static UrlResult sanitizeUrl(String url) {
        if (url == null) {
            return new UrlResult(null, 0);
        }

        int hash = url.indexOf('#');
        String beforeFragment = hash >= 0 ? url.substring(0, hash) : url;
        String fragment = hash >= 0 ? url.substring(hash + 1) : null;
        int query = beforeFragment.indexOf('?');
        String path = query >= 0 ? beforeFragment.substring(0, query) : beforeFragment;
        String queryText = query >= 0 ? beforeFragment.substring(query + 1) : null;

        StringBuilder result = new StringBuilder(url.length());
        result.append(sanitizePath(sanitizeAuthorityUserInfo(path)));
        if (queryText != null) {
            result.append('?').append(sanitizeQuery(queryText));
        }
        if (fragment != null) {
            result.append('#');
            result.append(fragment.isEmpty() || fragment.equals(SecretRedactor.REDACTED)
                    ? fragment
                    : SecretRedactor.REDACTED);
        }

        String sanitized = result.toString();
        return new UrlResult(
                sanitized,
                Math.max(0, countMarkers(sanitized) - countMarkers(url)));
    }

    private static String sanitizeHead(String head) {
        String lineBreak = head.contains("\r\n") ? "\r\n" : "\n";
        String[] lines = head.split(Pattern.quote(lineBreak), -1);
        if (lines.length == 0) {
            return head;
        }

        StringBuilder result = new StringBuilder(head.length());
        result.append(sanitizeFirstLine(lines[0]));
        for (int i = 1; i < lines.length; i++) {
            String line = lines[i];
            result.append(lineBreak);
            int colon = line.indexOf(':');
            if (colon < 1) {
                result.append(line.isEmpty() ? line : SecretRedactor.REDACTED);
                continue;
            }

            String originalName = line.substring(0, colon).trim();
            String name = originalName.toLowerCase(Locale.ROOT);
            String value = line.substring(colon + 1).strip();
            result.append(originalName).append(": ").append(sanitizeHeaderValue(name, value));
        }
        return result.toString();
    }

    private static String sanitizeFirstLine(String line) {
        if (line.regionMatches(true, 0, "HTTP/", 0, 5)) {
            return line;
        }
        int firstSpace = line.indexOf(' ');
        int lastSpace = line.lastIndexOf(' ');
        if (firstSpace < 0 || lastSpace <= firstSpace) {
            return SecretRedactor.REDACTED;
        }
        return line.substring(0, firstSpace + 1)
                + sanitizeUrl(line.substring(firstSpace + 1, lastSpace)).text()
                + line.substring(lastSpace);
    }

    private static String sanitizeHeaderValue(String name, String value) {
        if (value.isEmpty() || value.equals(SecretRedactor.REDACTED)) {
            return value;
        }
        if ((name.equals("authorization") || name.equals("authentication"))
                && isRedactedAuthValue(value)) {
            return value;
        }
        if (name.equals("cookie") || name.equals("set-cookie")) {
            return SecretRedactor.REDACTED;
        }
        if (URL_HEADERS.contains(name)) {
            if (!isRecognizedUrlShape(value)) {
                return SecretRedactor.REDACTED;
            }
            return sanitizeUrl(value).text();
        }
        if (SAFE_HEADER_VALUES.contains(name)) {
            return value;
        }
        return SecretRedactor.REDACTED;
    }

    private static boolean isRedactedAuthValue(String value) {
        int space = value.indexOf(' ');
        return space > 0
                && value.substring(0, space).chars().allMatch(Character::isLetter)
                && value.substring(space + 1).equals(SecretRedactor.REDACTED);
    }

    private static boolean isRecognizedUrlShape(String value) {
        return value.equals("*") || value.equals("null")
                || value.startsWith("/") || value.contains("://");
    }

    private static String sanitizeAuthorityUserInfo(String value) {
        int scheme = value.indexOf("://");
        if (scheme < 0) {
            return value;
        }
        int authorityStart = scheme + 3;
        int authorityEnd = value.indexOf('/', authorityStart);
        if (authorityEnd < 0) {
            authorityEnd = value.length();
        }
        int at = value.lastIndexOf('@', authorityEnd);
        if (at < authorityStart) {
            return value;
        }
        return value.substring(0, authorityStart) + SecretRedactor.REDACTED
                + value.substring(at);
    }

    private static String sanitizePath(String value) {
        int pathStart = findPathStart(value);
        if (pathStart < 0) {
            return value;
        }
        String prefix = value.substring(0, pathStart);
        String[] segments = value.substring(pathStart).split("/", -1);
        for (int i = 0; i < segments.length; i++) {
            String decoded = decodeUrlComponent(segments[i]);
            if (!decoded.equals(SecretRedactor.REDACTED) && isIdentifierLike(decoded)) {
                segments[i] = SecretRedactor.REDACTED;
            }
        }
        return prefix + String.join("/", segments);
    }

    private static int findPathStart(String value) {
        int scheme = value.indexOf("://");
        if (scheme >= 0) {
            return value.indexOf('/', scheme + 3);
        }
        return value.startsWith("/") ? 0 : -1;
    }

    private static boolean isIdentifierLike(String segment) {
        return segment.contains("@")
                || UUID_PATTERN.matcher(segment).matches()
                || LONG_NUMBER_PATTERN.matcher(segment).matches()
                || LONG_HEX_PATTERN.matcher(segment).matches();
    }

    private static String sanitizeQuery(String query) {
        String[] pairs = query.split("&", -1);
        StringBuilder result = new StringBuilder(query.length());
        for (int i = 0; i < pairs.length; i++) {
            if (i > 0) {
                result.append('&');
            }
            String pair = pairs[i];
            int equals = pair.indexOf('=');
            if (equals < 0 || equals == pair.length() - 1) {
                result.append(pair);
                continue;
            }
            String value = pair.substring(equals + 1);
            result.append(pair, 0, equals + 1);
            result.append(value.equals(SecretRedactor.REDACTED)
                    ? value
                    : SecretRedactor.REDACTED);
        }
        return result.toString();
    }

    private static String decodeUrlComponent(String value) {
        try {
            return URLDecoder.decode(value, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return value;
        }
    }

    private static int countMarkers(String value) {
        int count = 0;
        int from = 0;
        while (value != null && (from = value.indexOf(SecretRedactor.REDACTED, from)) >= 0) {
            count++;
            from += SecretRedactor.REDACTED.length();
        }
        return count;
    }

    private static MessageParts splitMessage(String raw) {
        int crlf = raw.indexOf("\r\n\r\n");
        int lf = raw.indexOf("\n\n");
        if (crlf >= 0 && (lf < 0 || crlf <= lf)) {
            return new MessageParts(raw.substring(0, crlf), "\r\n\r\n", raw.substring(crlf + 4));
        }
        if (lf >= 0) {
            return new MessageParts(raw.substring(0, lf), "\n\n", raw.substring(lf + 2));
        }
        return new MessageParts(raw, "", "");
    }

    record MessageResult(String text, int redactionCount, boolean bodyOmitted) {
    }

    record UrlResult(String text, int redactionCount) {
    }

    record BodyOmissionResult(String text, boolean bodyOmitted) {
    }

    private record MessageParts(String head, String separator, String body) {
    }
}
