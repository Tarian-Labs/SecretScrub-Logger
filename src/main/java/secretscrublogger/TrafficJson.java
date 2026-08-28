package secretscrublogger;

/**
 * Builds a single-line JSON object for one logged HTTP transaction.
 * Hand-rolled to avoid pulling a JSON library into the extension jar.
 */
final class TrafficJson {

    private TrafficJson() {
    }

    static String build(String timestamp, String method, String url, int statusCode, String request, String response) {
        StringBuilder sb = new StringBuilder(request.length() + response.length() + 128);
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
        sb.append('}');
        return sb.toString();
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
