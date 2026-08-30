package secretscrublogger;

/**
 * Builds a single-line JSON object for one logged HTTP transaction.
 * Hand-rolled to avoid pulling a JSON library into the extension jar.
 */
final class TrafficJson {

    static final int SCHEMA_VERSION = 1;
    static final String SOURCE = "burp-http";
    static final String CONTENT_TRUST = "untrusted";
    static final String REDACTION_POLICY = "standard-v1";
    static final String STRICT_REDACTION_POLICY = "strict-v1";
    static final String REDACTION_ASSURANCE = "best-effort";

    private TrafficJson() {
    }

    static String build(String timestamp, String method, String url, int statusCode, String request,
                        String response, SafetyMetadata metadata) {
        StringBuilder sb = new StringBuilder(request.length() + response.length() + 384);
        sb.append('{');
        appendStringField(sb, "t", timestamp);
        sb.append(',');
        appendStringField(sb, "method", method);
        sb.append(',');
        appendStringField(sb, "url", url);
        sb.append(',');
        sb.append("\"status\":").append(statusCode).append(',');
        appendStringField(sb, "request", request);
        sb.append(',');
        appendStringField(sb, "response", response);
        sb.append(',');
        appendMetadata(sb, metadata);
        sb.append('}');
        return sb.toString();
    }

    private static void appendMetadata(StringBuilder sb, SafetyMetadata metadata) {
        sb.append("\"meta\":{");
        sb.append("\"schemaVersion\":").append(SCHEMA_VERSION).append(',');
        appendStringField(sb, "source", SOURCE);
        sb.append(',');
        sb.append("\"inScope\":true,");
        appendStringField(sb, "contentTrust", CONTENT_TRUST);
        sb.append(',');
        appendStringField(sb, "captureMode", metadata.compactMode() ? "compact" : "full");
        sb.append(',');
        appendStringField(sb, "safetyMode", metadata.strictMode() ? "strict" : "standard");
        sb.append(',');
        sb.append("\"redaction\":{");
        sb.append("\"performed\":true,");
        appendStringField(sb, "policy",
                metadata.strictMode() ? STRICT_REDACTION_POLICY : REDACTION_POLICY);
        sb.append(',');
        appendStringField(sb, "assurance", REDACTION_ASSURANCE);
        sb.append(',');
        appendStringField(sb, "marker", SecretRedactor.REDACTED);
        sb.append(',');
        sb.append("\"count\":").append(metadata.totalRedactions()).append(',');
        sb.append("\"urlCount\":").append(metadata.urlRedactions()).append(',');
        sb.append("\"requestCount\":").append(metadata.requestRedactions()).append(',');
        sb.append("\"responseCount\":").append(metadata.responseRedactions()).append(',');
        sb.append("\"exclusions\":{");
        sb.append("\"configuredFieldCount\":").append(metadata.redactionExclusionCount()).append(',');
        sb.append("\"enabled\":").append(metadata.redactionBypassEnabled()).append(',');
        sb.append("\"active\":").append(metadata.exclusionsActive());
        sb.append('}');
        sb.append("},");
        sb.append("\"truncation\":{");
        sb.append("\"request\":").append(metadata.requestTruncated()).append(',');
        sb.append("\"response\":").append(metadata.responseTruncated());
        sb.append("},");
        sb.append("\"omission\":{");
        sb.append("\"requestBody\":").append(metadata.requestBodyOmitted()).append(',');
        sb.append("\"responseBody\":").append(metadata.responseBodyOmitted());
        sb.append("}}");
    }

    record SafetyMetadata(int urlRedactions, int requestRedactions, int responseRedactions,
                          boolean requestTruncated, boolean responseTruncated,
                          boolean compactMode, boolean strictMode,
                          boolean requestBodyOmitted, boolean responseBodyOmitted,
                          boolean redactionBypassEnabled, int redactionExclusionCount) {

        SafetyMetadata {
            if (urlRedactions < 0 || requestRedactions < 0 || responseRedactions < 0
                    || redactionExclusionCount < 0) {
                throw new IllegalArgumentException("Redaction and exclusion counts cannot be negative");
            }
        }

        int totalRedactions() {
            return urlRedactions + requestRedactions + responseRedactions;
        }

        boolean exclusionsActive() {
            return redactionBypassEnabled && redactionExclusionCount > 0 && !strictMode;
        }
    }

    private static void appendStringField(StringBuilder sb, String name, String value) {
        sb.append('"').append(name).append("\":");
        appendJsonString(sb, value);
    }

    private static void appendJsonString(StringBuilder sb, String value) {
        sb.append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"':
                    sb.append("\\\"");
                    break;
                case '\\':
                    sb.append("\\\\");
                    break;
                case '\n':
                    sb.append("\\n");
                    break;
                case '\r':
                    sb.append("\\r");
                    break;
                case '\t':
                    sb.append("\\t");
                    break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append('"');
    }
}
