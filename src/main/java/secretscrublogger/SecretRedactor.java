package secretscrublogger;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Removes sensitive values from HTTP requests/responses before they are persisted, returned
 * through any API, or displayed anywhere, replacing each secret with a fixed {@link #REDACTED}
 * placeholder. Headers, cookies, URL query parameters, and JSON/form-encoded bodies are parsed
 * structurally so nested and array values are covered; unparseable or unrecognized bodies fall
 * back to defensive text scanning. Key/header/parameter names are matched case-insensitively
 * against a list of sensitive terms, and token-shaped values (JWTs, bearer tokens) are redacted
 * even when found under a non-sensitive name.
 */
final class SecretRedactor {

    static final String REDACTED = "[REDACTED]";

    /** The redacted text and the number of replacement markers introduced by this pass. */
    record RedactionResult(String text, int redactionCount) {
    }

    record ExclusionConfig(boolean enabled, Set<String> fields) {
    }

    private record ExclusionPolicy(boolean enabled, Set<String> fields) {
    }

    // Sensitive terms are matched as a "contains" check against the normalized (lowercased,
    // separator-stripped) key/header/parameter name, so e.g. "accessToken" and "api_key" match.
    private static final List<String> SENSITIVE_TERMS = List.of(
            "authorization", "authentication", "token", "accesstoken", "refreshtoken", "idtoken",
            "jwt", "bearer", "apikey", "secret", "password", "passcode", "cookie", "session",
            "credential", "csrf", "xsrf", "clientsecret", "privatekey", "signingkey",
            "encryptionkey", "recoverycode", "verificationcode", "mfacode", "totp"
    );

    private static final Set<String> SENSITIVE_EXACT_KEYS = Set.of(
            "pin", "otp", "cvv", "cvc", "ssn"
    );

    private static final Set<String> SENSITIVE_PATH_MARKERS = Set.of(
            "reset", "resetpassword", "passwordreset", "recover", "recovery", "verify",
            "verification", "activate", "activation", "invite", "invitation", "magiclink"
    );

    // Three base64url segments separated by periods: the shape of a JWT, wherever it appears.
    private static final Pattern JWT_PATTERN =
            Pattern.compile("[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}");

    private static final Pattern BEARER_TOKEN_PATTERN =
            Pattern.compile("(?i)(Bearer\\s+)([A-Za-z0-9\\-_.+/=]{8,})");

    private static final Pattern MULTIPART_BOUNDARY_PATTERN = Pattern.compile(
            "(?i)(?:^|;)\\s*boundary\\s*=\\s*(?:\"([^\"]+)\"|([^;\\s]+))");

    private static final Pattern MULTIPART_NAME_PATTERN = Pattern.compile(
            "(?i)(?:^|;)\\s*name\\s*=\\s*(?:\"([^\"]*)\"|([^;\\s]*))");

    private static final Pattern XML_ELEMENT_PATTERN = Pattern.compile(
            "(?is)(<([A-Za-z_][\\w.:-]*)\\b[^>]*>)(.*?)(</\\2\\s*>)");

    private static final Pattern XML_START_TAG_PATTERN = Pattern.compile(
            "(?s)<[A-Za-z_][\\w.:-]*\\b[^>]*>");

    private static final Pattern XML_ATTRIBUTE_PATTERN = Pattern.compile(
            "(?s)([A-Za-z_][\\w.:-]*)(\\s*=\\s*)([\"'])(.*?)(\\3)");

    // Defensive fallback for bodies that cannot be structurally parsed: matches "key": "value" or
    // key=value where the key contains a sensitive term, quoted or not.
    private static final Pattern FALLBACK_KV_PATTERN = Pattern.compile(
            "(?i)(\"?([\\w-]*(?:authorization|authenticat\\w*|accesstoken|refreshtoken|idtoken|token|jwt|"
                    + "bearer|api[_-]?key|secret|password|cookie|session|credential)[\\w-]*)\"?"
                    + "\\s*[:=]\\s*\"?)([^\"'&,\\r\\n}]+)(\"?)");

    private static final Pattern GENERIC_FALLBACK_KV_PATTERN = Pattern.compile(
            "(?i)(\"?([\\w-]+)\"?\\s*[:=]\\s*\"?)([^\"'&,\\r\\n}]+)(\"?)");

    // Framework responses sometimes embed JSON inside JavaScript strings, escaping each quote
    // with one or more backslashes. Treat those fields structurally during fallback scanning too.
    private static final Pattern ESCAPED_QUOTED_KV_PATTERN = Pattern.compile(
            "(?i)((?:\\\\+\"|&quot;)([\\w-]+)(?:\\\\+\"|&quot;)\\s*:\\s*"
                    + "(?:\\\\+\"|&quot;))(.*?)((?:\\\\+\"|&quot;))");

    private static final List<String> KNOWN_COOKIE_ATTRIBUTES = List.of(
            "path", "domain", "expires", "maxage", "samesite", "secure", "httponly", "partitioned"
    );

    private volatile Set<String> customSensitiveFields = Set.of();
    private volatile ExclusionPolicy exclusionPolicy = new ExclusionPolicy(false, Set.of());

    void setCustomSensitiveFields(Collection<String> fields) {
        customSensitiveFields = normalizeFields(fields);
    }

    Set<String> customSensitiveFields() {
        return customSensitiveFields;
    }

    void setExcludedFields(Collection<String> fields) {
        Set<String> normalized = normalizeFields(fields);
        ExclusionPolicy current = exclusionPolicy;
        exclusionPolicy = new ExclusionPolicy(current.enabled(), normalized);
    }

    void setExclusionsEnabled(boolean enabled) {
        ExclusionPolicy current = exclusionPolicy;
        exclusionPolicy = new ExclusionPolicy(enabled, current.fields());
    }

    ExclusionConfig exclusionConfig() {
        ExclusionPolicy current = exclusionPolicy;
        return new ExclusionConfig(current.enabled(), current.fields());
    }

    private Set<String> normalizeFields(Collection<String> fields) {
        if (fields == null || fields.isEmpty()) {
            return Set.of();
        }
        java.util.HashSet<String> normalized = new java.util.HashSet<>();
        for (String field : fields) {
            String value = normalizeKey(field);
            if (!value.isEmpty()) {
                normalized.add(value);
            }
        }
        return Set.copyOf(normalized);
    }

    /**
     * Redacts a raw HTTP request or response message (request/status line + headers + blank line
     * + body).
     */
    String redact(String rawMessage) {
        return redactWithMetadata(rawMessage).text();
    }

    RedactionResult redactWithMetadata(String rawMessage) {
        if (rawMessage == null) {
            return new RedactionResult(null, 0);
        }
        String redacted = redactMessage(rawMessage);
        return resultFor(rawMessage, redacted);
    }

    private String redactMessage(String rawMessage) {
        String[] split = splitHeadAndBody(rawMessage);
        String head = split[0];
        String separator = split[1];
        String body = split[2];

        String lineBreak = head.contains("\r\n") ? "\r\n" : "\n";
        String[] lines = head.split(Pattern.quote(lineBreak), -1);

        StringBuilder newHead = new StringBuilder(head.length());
        String contentType = null;
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            String newLine;
            if (i == 0) {
                newLine = redactFirstLine(line);
            } else {
                int colon = line.indexOf(':');
                if (colon < 0) {
                    newLine = line;
                } else {
                    String name = line.substring(0, colon).trim();
                    String value = line.substring(colon + 1).strip();
                    if (normalizeKey(name).equals("contenttype")) {
                        contentType = value;
                    }
                    newLine = name + ": " + redactHeaderLine(name, value);
                }
            }
            newHead.append(newLine);
            if (i < lines.length - 1) {
                newHead.append(lineBreak);
            }
        }

        String newBody = redactBody(contentType, body);
        return newHead + separator + newBody;
    }

    /** Redacts sensitive path segments and query parameters in a URL or request-target. */
    String redactUrl(String url) {
        return redactUrlWithMetadata(url).text();
    }

    RedactionResult redactUrlWithMetadata(String url) {
        if (url == null) {
            return new RedactionResult(null, 0);
        }
        String redacted = redactUrlValue(url);
        return resultFor(url, redacted);
    }

    private String redactUrlValue(String url) {
        int hashIdx = url.indexOf('#');
        String beforeHash = hashIdx >= 0 ? url.substring(0, hashIdx) : url;
        String fragment = hashIdx >= 0 ? url.substring(hashIdx) : "";
        int queryIdx = beforeHash.indexOf('?');
        if (queryIdx < 0) {
            return redactUrlPath(beforeHash) + fragment;
        }
        String base = redactUrlPath(beforeHash.substring(0, queryIdx));
        String query = beforeHash.substring(queryIdx + 1);
        return base + "?" + redactEncodedPairs(query, '&') + fragment;
    }

    private RedactionResult resultFor(String original, String redacted) {
        int introducedMarkers = countOccurrences(redacted, REDACTED)
                - countOccurrences(original, REDACTED);
        return new RedactionResult(redacted, Math.max(0, introducedMarkers));
    }

    private static int countOccurrences(String value, String target) {
        int count = 0;
        int fromIndex = 0;
        while (value != null && (fromIndex = value.indexOf(target, fromIndex)) >= 0) {
            count++;
            fromIndex += target.length();
        }
        return count;
    }

    private String redactUrlPath(String value) {
        int pathStart = findPathStart(value);
        if (pathStart < 0) {
            return value;
        }
        String prefix = value.substring(0, pathStart);
        String path = value.substring(pathStart);
        String[] segments = path.split("/", -1);
        boolean redactNext = false;
        for (int i = 0; i < segments.length; i++) {
            String segment = segments[i];
            if (segment.isEmpty()) {
                continue;
            }
            String decoded = decodeUrlComponent(segment);
            if (redactNext || JWT_PATTERN.matcher(decoded).matches()) {
                segments[i] = REDACTED;
                redactNext = false;
                continue;
            }
            redactNext = isSensitivePathMarker(decoded);
        }
        return prefix + String.join("/", segments);
    }

    private int findPathStart(String value) {
        int scheme = value.indexOf("://");
        if (scheme >= 0) {
            return value.indexOf('/', scheme + 3);
        }
        return value.startsWith("/") ? 0 : -1;
    }

    private boolean isSensitivePathMarker(String segment) {
        int matrixParameter = segment.indexOf(';');
        String name = matrixParameter >= 0 ? segment.substring(0, matrixParameter) : segment;
        if (isExcludedKey(name)) {
            return false;
        }
        String normalized = normalizeKey(name);
        return isSensitiveKey(name) || SENSITIVE_PATH_MARKERS.contains(normalized);
    }

    private String redactFirstLine(String line) {
        if (line.regionMatches(true, 0, "HTTP/", 0, 5)) {
            // Status line: "HTTP/1.1 200 OK" - status code/reason are safe context, keep as-is.
            return line;
        }
        int firstSpace = line.indexOf(' ');
        int lastSpace = line.lastIndexOf(' ');
        if (firstSpace < 0 || lastSpace <= firstSpace) {
            return line;
        }
        String method = line.substring(0, firstSpace);
        String target = line.substring(firstSpace + 1, lastSpace);
        String version = line.substring(lastSpace + 1);
        return method + " " + redactUrl(target) + " " + version;
    }

    private String redactHeaderLine(String name, String value) {
        if (isExcludedKey(name)) {
            return value;
        }
        String norm = normalizeKey(name);
        if (norm.equals("cookie") || norm.equals("setcookie")) {
            return redactCookieHeaderValue(norm, value);
        }
        if (norm.equals("authorization") || norm.equals("authentication")) {
            return redactSchemeValue(value);
        }
        if (isSensitiveKey(name)) {
            return REDACTED;
        }
        return scanAndRedactTokens(value);
    }

    /** Keeps a leading auth scheme word (e.g. "Bearer") as safe context, redacts the credential. */
    private String redactSchemeValue(String value) {
        int sp = value.indexOf(' ');
        if (sp > 0) {
            String scheme = value.substring(0, sp);
            boolean allLetters = !scheme.isEmpty() && scheme.chars().allMatch(Character::isLetter);
            if (allLetters) {
                return scheme + " " + REDACTED;
            }
        }
        return REDACTED;
    }

    private String redactCookieHeaderValue(String norm, String value) {
        boolean isSetCookie = norm.equals("setcookie");
        String[] parts = value.split(";", -1);
        StringBuilder sb = new StringBuilder(value.length());
        for (int i = 0; i < parts.length; i++) {
            if (i > 0) {
                sb.append(';');
            }
            String part = parts[i];
            String trimmed = part.strip();
            if (trimmed.isEmpty()) {
                sb.append(part);
                continue;
            }
            if (isSetCookie && i > 0 && isKnownCookieAttribute(trimmed)) {
                sb.append(part);
                continue;
            }
            int eq = trimmed.indexOf('=');
            String leadingWs = part.substring(0, part.length() - part.stripLeading().length());
            if (eq < 0) {
                sb.append(part);
            } else {
                String cookieName = trimmed.substring(0, eq);
                if (isExcludedKey(cookieName)) {
                    sb.append(part);
                } else {
                    sb.append(leadingWs).append(cookieName).append('=').append(REDACTED);
                }
            }
        }
        return sb.toString();
    }

    private boolean isKnownCookieAttribute(String part) {
        int eq = part.indexOf('=');
        String name = eq >= 0 ? part.substring(0, eq) : part;
        return KNOWN_COOKIE_ATTRIBUTES.contains(normalizeKey(name));
    }

    private String redactBody(String contentType, String body) {
        if (body == null || body.isEmpty()) {
            return body;
        }
        String ct = contentType == null ? "" : contentType.toLowerCase(Locale.ROOT);
        String leading = body.stripLeading();
        boolean looksJson = !leading.isEmpty() && (leading.charAt(0) == '{' || leading.charAt(0) == '[');

        if (ct.contains("multipart/form-data")) {
            return redactMultipartBody(contentType, body);
        }
        if (ct.contains("json") || (ct.isEmpty() && looksJson)) {
            try {
                Object parsed = MiniJson.parse(body);
                return MiniJson.write(redactJsonValue(parsed));
            } catch (MiniJson.ParseException e) {
                return fallbackTextRedact(body);
            }
        }
        if (ct.contains("x-www-form-urlencoded")) {
            return redactEncodedPairs(body, '&');
        }
        if (ct.contains("xml")) {
            return redactXml(body);
        }
        return fallbackTextRedact(body);
    }

    private String redactMultipartBody(String contentType, String body) {
        Matcher boundaryMatcher = MULTIPART_BOUNDARY_PATTERN.matcher(contentType);
        if (!boundaryMatcher.find()) {
            return fallbackTextRedact(body);
        }
        String boundary = boundaryMatcher.group(1) != null
                ? boundaryMatcher.group(1)
                : boundaryMatcher.group(2);
        if (boundary == null || boundary.isEmpty()) {
            return fallbackTextRedact(body);
        }

        String delimiter = "--" + boundary;
        String[] parts = body.split(Pattern.quote(delimiter), -1);
        StringBuilder result = new StringBuilder(body.length());
        for (int i = 0; i < parts.length; i++) {
            if (i > 0) {
                result.append(delimiter);
            }
            result.append(redactMultipartPart(parts[i]));
        }
        return result.toString();
    }

    private String redactMultipartPart(String part) {
        String[] split = splitHeadAndBody(part);
        if (split[1].isEmpty()) {
            return part;
        }
        String fieldName = multipartFieldName(split[0]);
        if (fieldName != null && isExcludedKey(fieldName)) {
            return part;
        }
        if (fieldName == null || !isSensitiveKey(fieldName)) {
            return split[0] + split[1] + fallbackTextRedact(split[2]);
        }

        String trailingLineBreak = split[2].endsWith("\r\n")
                ? "\r\n"
                : split[2].endsWith("\n") ? "\n" : "";
        return split[0] + split[1] + REDACTED + trailingLineBreak;
    }

    private String multipartFieldName(String partHeaders) {
        String[] lines = partHeaders.split("\\r?\\n");
        for (String line : lines) {
            int colon = line.indexOf(':');
            if (colon < 0 || !normalizeKey(line.substring(0, colon)).equals("contentdisposition")) {
                continue;
            }
            Matcher nameMatcher = MULTIPART_NAME_PATTERN.matcher(line.substring(colon + 1));
            if (nameMatcher.find()) {
                return nameMatcher.group(1) != null ? nameMatcher.group(1) : nameMatcher.group(2);
            }
        }
        return null;
    }

    private String redactXml(String body) {
        ProtectedValues protectedValues = new ProtectedValues(body);
        String result = redactXmlElements(body, protectedValues);
        result = XML_START_TAG_PATTERN.matcher(result).replaceAll(match ->
                Matcher.quoteReplacement(redactXmlAttributes(match.group(), protectedValues)));
        return protectedValues.restore(scanAndRedactTokens(result));
    }

    private String redactXmlElements(String xml, ProtectedValues protectedValues) {
        return XML_ELEMENT_PATTERN.matcher(xml).replaceAll(match -> {
            String elementName = localXmlName(match.group(2));
            if (isExcludedKey(elementName)) {
                return Matcher.quoteReplacement(match.group(1)
                        + protectedValues.protect(match.group(3)) + match.group(4));
            }
            if (!isSensitiveKey(elementName)) {
                return Matcher.quoteReplacement(match.group(1)
                        + redactXmlElements(match.group(3), protectedValues) + match.group(4));
            }
            return Matcher.quoteReplacement(match.group(1) + REDACTED + match.group(4));
        });
    }

    private String redactXmlAttributes(String tag, ProtectedValues protectedValues) {
        return XML_ATTRIBUTE_PATTERN.matcher(tag).replaceAll(match -> {
            String attributeName = localXmlName(match.group(1));
            if (isExcludedKey(attributeName)) {
                return Matcher.quoteReplacement(match.group(1) + match.group(2)
                        + match.group(3) + protectedValues.protect(match.group(4)) + match.group(5));
            }
            if (!isSensitiveKey(attributeName)) {
                return Matcher.quoteReplacement(match.group());
            }
            return Matcher.quoteReplacement(match.group(1) + match.group(2)
                    + match.group(3) + REDACTED + match.group(5));
        });
    }

    private String localXmlName(String name) {
        int colon = name.lastIndexOf(':');
        return colon >= 0 ? name.substring(colon + 1) : name;
    }

    @SuppressWarnings("unchecked")
    private Object redactJsonValue(Object node) {
        if (node instanceof Map) {
            Map<String, Object> in = (Map<String, Object>) node;
            Map<String, Object> out = new LinkedHashMap<>(in.size());
            for (Map.Entry<String, Object> entry : in.entrySet()) {
                if (isExcludedKey(entry.getKey())) {
                    out.put(entry.getKey(), entry.getValue());
                } else if (isSensitiveKey(entry.getKey())) {
                    out.put(entry.getKey(), REDACTED);
                } else {
                    out.put(entry.getKey(), redactJsonValue(entry.getValue()));
                }
            }
            return out;
        }
        if (node instanceof List) {
            List<Object> in = (List<Object>) node;
            List<Object> out = new ArrayList<>(in.size());
            for (Object item : in) {
                out.add(redactJsonValue(item));
            }
            return out;
        }
        if (node instanceof String) {
            return scanAndRedactTokens((String) node);
        }
        return node;
    }

    /** Redacts sensitive-named parameters in "a=1&b=2" data, used for both query strings and forms. */
    private String redactEncodedPairs(String data, char separator) {
        if (data.isEmpty()) {
            return data;
        }
        String[] pairs = data.split(Pattern.quote(String.valueOf(separator)), -1);
        StringBuilder sb = new StringBuilder(data.length());
        for (int i = 0; i < pairs.length; i++) {
            if (i > 0) {
                sb.append(separator);
            }
            sb.append(redactEncodedPair(pairs[i]));
        }
        return sb.toString();
    }

    private String redactEncodedPair(String pair) {
        if (pair.isEmpty()) {
            return pair;
        }
        int eq = pair.indexOf('=');
        if (eq < 0) {
            return pair;
        }
        String rawName = pair.substring(0, eq);
        String rawValue = pair.substring(eq + 1);
        String decodedName = decodeUrlComponent(rawName);
        if (isExcludedKey(decodedName)) {
            return pair;
        }
        if (isSensitiveKey(decodedName)) {
            return rawName + "=" + REDACTED;
        }
        String decodedValue = decodeUrlComponent(rawValue);
        String scanned = scanAndRedactTokens(decodedValue);
        if (!scanned.equals(decodedValue)) {
            return rawName + "=" + encodeUrlComponent(scanned);
        }
        return pair;
    }

    /** Redacts JWT-shaped or bearer-prefixed values inside otherwise non-sensitive text. */
    private String scanAndRedactTokens(String value) {
        if (value == null || value.isEmpty()) {
            return value;
        }
        if (JWT_PATTERN.matcher(value).matches()) {
            return REDACTED;
        }
        String result = BEARER_TOKEN_PATTERN.matcher(value)
                .replaceAll(mr -> Matcher.quoteReplacement(mr.group(1) + REDACTED));
        result = JWT_PATTERN.matcher(result).replaceAll(Matcher.quoteReplacement(REDACTED));
        return result;
    }

    /** Defensive text-based redaction used only when a body cannot be structurally parsed. */
    private String fallbackTextRedact(String text) {
        ProtectedValues protectedValues = new ProtectedValues(text);
        String result = ESCAPED_QUOTED_KV_PATTERN.matcher(text).replaceAll(mr -> {
            if (isExcludedKey(mr.group(2))) {
                return Matcher.quoteReplacement(mr.group(1)
                        + protectedValues.protect(mr.group(3)) + mr.group(4));
            }
            if (!isSensitiveKey(mr.group(2))) {
                return Matcher.quoteReplacement(mr.group());
            }
            return Matcher.quoteReplacement(mr.group(1) + REDACTED + mr.group(4));
        });
        result = FALLBACK_KV_PATTERN.matcher(result).replaceAll(mr -> {
            if (isExcludedKey(mr.group(2))) {
                return Matcher.quoteReplacement(mr.group(1)
                        + protectedValues.protect(mr.group(3)) + mr.group(4));
            }
            return Matcher.quoteReplacement(mr.group(1) + REDACTED + mr.group(4));
        });
        result = GENERIC_FALLBACK_KV_PATTERN.matcher(result).replaceAll(mr -> {
            if (isExcludedKey(mr.group(2))) {
                return Matcher.quoteReplacement(mr.group(1)
                        + protectedValues.protect(mr.group(3)) + mr.group(4));
            }
            if (!isSensitiveKey(mr.group(2))) {
                return Matcher.quoteReplacement(mr.group());
            }
            return Matcher.quoteReplacement(mr.group(1) + REDACTED + mr.group(4));
        });
        result = BEARER_TOKEN_PATTERN.matcher(result)
                .replaceAll(mr -> Matcher.quoteReplacement(mr.group(1) + REDACTED));
        result = JWT_PATTERN.matcher(result).replaceAll(Matcher.quoteReplacement(REDACTED));
        return protectedValues.restore(result);
    }

    private static String decodeUrlComponent(String s) {
        try {
            return URLDecoder.decode(s, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return s;
        }
    }

    private static String encodeUrlComponent(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    private static String normalizeKey(String key) {
        if (key == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(key.length());
        for (int i = 0; i < key.length(); i++) {
            char c = key.charAt(i);
            if (Character.isLetterOrDigit(c)) {
                sb.append(Character.toLowerCase(c));
            }
        }
        return sb.toString();
    }

    private boolean isExcludedKey(String key) {
        ExclusionPolicy current = exclusionPolicy;
        return current.enabled() && current.fields().contains(normalizeKey(key));
    }

    private boolean isSensitiveKey(String key) {
        String normalized = normalizeKey(key);
        if (normalized.isEmpty()) {
            return false;
        }
        if (customSensitiveFields.contains(normalized)) {
            return true;
        }
        if (SENSITIVE_EXACT_KEYS.contains(normalized)) {
            return true;
        }
        for (String term : SENSITIVE_TERMS) {
            if (normalized.contains(term)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Splits a raw HTTP message into {head, separator, body}. The separator is empty when no body is present.
     */
    private String[] splitHeadAndBody(String raw) {
        int crlf = raw.indexOf("\r\n\r\n");
        int lf = raw.indexOf("\n\n");
        if (crlf >= 0 && (lf < 0 || crlf <= lf)) {
            return new String[]{raw.substring(0, crlf), "\r\n\r\n", raw.substring(crlf + 4)};
        }
        if (lf >= 0) {
            return new String[]{raw.substring(0, lf), "\n\n", raw.substring(lf + 2)};
        }
        return new String[]{raw, "", ""};
    }

    private static final class ProtectedValues {
        private final String source;
        private final List<ProtectedValue> values = new ArrayList<>();
        private String placeholderPrefix;

        private ProtectedValues(String source) {
            this.source = source;
        }

        private String protect(String value) {
            ensurePlaceholderPrefix();
            String placeholder = placeholderPrefix + values.size() + "__";
            values.add(new ProtectedValue(placeholder, value));
            return placeholder;
        }

        private void ensurePlaceholderPrefix() {
            if (placeholderPrefix != null) {
                return;
            }
            String candidate;
            do {
                candidate = "__SECRET_SCRUB_EXCLUDED_"
                        + UUID.randomUUID().toString().replace("-", "") + "_";
            } while (source.contains(candidate));
            placeholderPrefix = candidate;
        }

        private String restore(String text) {
            String result = text;
            for (int i = values.size() - 1; i >= 0; i--) {
                ProtectedValue value = values.get(i);
                result = result.replace(value.placeholder(), value.original());
            }
            return result;
        }
    }

    private record ProtectedValue(String placeholder, String original) {
    }
}
