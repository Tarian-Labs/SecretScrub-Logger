package secretscrublogger;

import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Set;

/**
 * Produces a lower-noise HTTP representation for AI analysis. Callers must redact the message
 * first: compacting is deliberately presentation-only and never substitutes for redaction.
 */
final class HttpMessageCompactor {

    private static final Set<String> REQUEST_HEADERS = Set.of(
            "host", "accept", "content-type", "content-encoding", "content-disposition",
            "authorization", "authentication", "cookie", "origin", "referer", "forwarded",
            "if-match", "if-none-match", "if-modified-since", "if-unmodified-since",
            "if-range", "range", "upgrade", "sec-websocket-key", "sec-websocket-protocol",
            "sec-websocket-version"
    );

    private static final Set<String> RESPONSE_HEADERS = Set.of(
            "content-type", "content-encoding", "content-disposition", "content-range",
            "location", "set-cookie", "www-authenticate", "proxy-authenticate", "allow",
            "cache-control", "expires", "age", "vary", "etag", "last-modified",
            "server", "x-powered-by", "content-security-policy",
            "content-security-policy-report-only", "strict-transport-security",
            "x-frame-options", "x-content-type-options", "referrer-policy",
            "permissions-policy", "clear-site-data", "retry-after", "upgrade"
    );

    private HttpMessageCompactor() {
    }

    static CompactResult compact(String rawMessage) {
        return compact(rawMessage, TrafficLoggerConfig.COMPACT_MAX_BODY_BYTES);
    }

    static CompactResult compact(String rawMessage, int maxBodyBytes) {
        if (rawMessage == null) {
            return new CompactResult(null, false);
        }
        if (maxBodyBytes < 0) {
            throw new IllegalArgumentException("Compact body limit cannot be negative");
        }

        MessageParts parts = splitMessage(rawMessage);
        String compactHead = compactHead(parts.head());
        BodyResult body = truncateBody(parts.body(), maxBodyBytes);
        return new CompactResult(compactHead + parts.separator() + body.text(), body.truncated());
    }

    private static String compactHead(String head) {
        String lineBreak = head.contains("\r\n") ? "\r\n" : "\n";
        String[] lines = head.split(java.util.regex.Pattern.quote(lineBreak), -1);
        if (lines.length == 0) {
            return head;
        }

        boolean response = lines[0].regionMatches(true, 0, "HTTP/", 0, 5);
        StringBuilder result = new StringBuilder(head.length());
        result.append(lines[0]);
        boolean previousHeaderKept = false;
        for (int i = 1; i < lines.length; i++) {
            String line = lines[i];
            boolean continuation = !line.isEmpty() && Character.isWhitespace(line.charAt(0));
            if (continuation) {
                if (previousHeaderKept) {
                    result.append(lineBreak).append(line);
                }
                continue;
            }

            int colon = line.indexOf(':');
            if (colon < 1) {
                previousHeaderKept = true;
                result.append(lineBreak).append(line);
                continue;
            }

            String name = line.substring(0, colon).trim().toLowerCase(Locale.ROOT);
            String value = line.substring(colon + 1);
            previousHeaderKept = keepHeader(name, value, response);
            if (previousHeaderKept) {
                result.append(lineBreak).append(line);
            }
        }
        return result.toString();
    }

    private static boolean keepHeader(String name, String value, boolean response) {
        if (value.contains(SecretRedactor.REDACTED)) {
            return true;
        }
        if (name.startsWith("x-") || name.startsWith("access-control-")
                || name.startsWith("cross-origin-")) {
            return true;
        }
        return (response ? RESPONSE_HEADERS : REQUEST_HEADERS).contains(name);
    }

    private static BodyResult truncateBody(String body, int maxBodyBytes) {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        if (bytes.length <= maxBodyBytes) {
            return new BodyResult(body, false);
        }

        int end = maxBodyBytes;
        while (end > 0 && end < bytes.length && (bytes[end] & 0xC0) == 0x80) {
            end--;
        }
        String truncated = new String(bytes, 0, end, StandardCharsets.UTF_8);
        return new BodyResult(truncated + TrafficLoggerConfig.TRUNCATION_MARKER, true);
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

    record CompactResult(String text, boolean bodyTruncated) {
    }

    private record BodyResult(String text, boolean truncated) {
    }

    private record MessageParts(String head, String separator, String body) {
    }
}
