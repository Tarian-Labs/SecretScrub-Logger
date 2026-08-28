package secretscrublogger;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal recursive-descent JSON parser/serializer used for structural secret redaction.
 * Hand-rolled to avoid pulling a JSON library into the extension jar. Objects preserve key
 * order (LinkedHashMap); numbers/booleans/null are kept as raw literal text so re-serialization
 * is lossless for non-string values.
 */
final class MiniJson {

    /** Holds the raw text of a JSON number, boolean, or null literal so it round-trips exactly. */
    static final class JsonLiteral {
        final String raw;

        JsonLiteral(String raw) {
            this.raw = raw;
        }
    }

    static final class ParseException extends Exception {
        ParseException(String message) {
            super(message);
        }
    }

    private final String s;
    private int pos;

    private MiniJson(String s) {
        this.s = s;
    }

    static Object parse(String text) throws ParseException {
        MiniJson parser = new MiniJson(text);
        parser.skipWs();
        Object value = parser.parseValue();
        parser.skipWs();
        if (parser.pos != parser.s.length()) {
            throw new ParseException("Unexpected trailing content at " + parser.pos);
        }
        return value;
    }

    static String write(Object value) {
        StringBuilder sb = new StringBuilder();
        writeValue(sb, value);
        return sb.toString();
    }

    private Object parseValue() throws ParseException {
        if (pos >= s.length()) {
            throw new ParseException("Unexpected end of input");
        }
        char c = s.charAt(pos);
        switch (c) {
            case '{':
                return parseObject();
            case '[':
                return parseArray();
            case '"':
                return parseString();
            default:
                if (c == '-' || (c >= '0' && c <= '9')) {
                    return parseNumber();
                }
                if (s.startsWith("true", pos)) {
                    pos += 4;
                    return new JsonLiteral("true");
                }
                if (s.startsWith("false", pos)) {
                    pos += 5;
                    return new JsonLiteral("false");
                }
                if (s.startsWith("null", pos)) {
                    pos += 4;
                    return new JsonLiteral("null");
                }
                throw new ParseException("Unexpected character '" + c + "' at " + pos);
        }
    }

    private Map<String, Object> parseObject() throws ParseException {
        Map<String, Object> map = new LinkedHashMap<>();
        expect('{');
        skipWs();
        if (peek() == '}') {
            pos++;
            return map;
        }
        while (true) {
            skipWs();
            if (peek() != '"') {
                throw new ParseException("Expected string key at " + pos);
            }
            String key = parseString();
            skipWs();
            expect(':');
            skipWs();
            map.put(key, parseValue());
            skipWs();
            char next = peek();
            if (next == ',') {
                pos++;
                continue;
            }
            if (next == '}') {
                pos++;
                break;
            }
            throw new ParseException("Expected ',' or '}' at " + pos);
        }
        return map;
    }

    private List<Object> parseArray() throws ParseException {
        List<Object> list = new ArrayList<>();
        expect('[');
        skipWs();
        if (peek() == ']') {
            pos++;
            return list;
        }
        while (true) {
            skipWs();
            list.add(parseValue());
            skipWs();
            char next = peek();
            if (next == ',') {
                pos++;
                continue;
            }
            if (next == ']') {
                pos++;
                break;
            }
            throw new ParseException("Expected ',' or ']' at " + pos);
        }
        return list;
    }

    private String parseString() throws ParseException {
        expect('"');
        StringBuilder sb = new StringBuilder();
        while (true) {
            if (pos >= s.length()) {
                throw new ParseException("Unterminated string");
            }
            char c = s.charAt(pos++);
            if (c == '"') {
                break;
            }
            if (c == '\\') {
                if (pos >= s.length()) {
                    throw new ParseException("Unterminated escape sequence");
                }
                char escaped = s.charAt(pos++);
                switch (escaped) {
                    case '"':
                        sb.append('"');
                        break;
                    case '\\':
                        sb.append('\\');
                        break;
                    case '/':
                        sb.append('/');
                        break;
                    case 'b':
                        sb.append('\b');
                        break;
                    case 'f':
                        sb.append('\f');
                        break;
                    case 'n':
                        sb.append('\n');
                        break;
                    case 'r':
                        sb.append('\r');
                        break;
                    case 't':
                        sb.append('\t');
                        break;
                    case 'u':
                        if (pos + 4 > s.length()) {
                            throw new ParseException("Invalid unicode escape at " + pos);
                        }
                        sb.append((char) Integer.parseInt(s.substring(pos, pos + 4), 16));
                        pos += 4;
                        break;
                    default:
                        throw new ParseException("Invalid escape '\\" + escaped + "' at " + pos);
                }
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    private JsonLiteral parseNumber() throws ParseException {
        int start = pos;
        if (peek() == '-') {
            pos++;
        }
        while (pos < s.length() && Character.isDigit(s.charAt(pos))) {
            pos++;
        }
        if (pos < s.length() && s.charAt(pos) == '.') {
            pos++;
            while (pos < s.length() && Character.isDigit(s.charAt(pos))) {
                pos++;
            }
        }
        if (pos < s.length() && (s.charAt(pos) == 'e' || s.charAt(pos) == 'E')) {
            pos++;
            if (pos < s.length() && (s.charAt(pos) == '+' || s.charAt(pos) == '-')) {
                pos++;
            }
            while (pos < s.length() && Character.isDigit(s.charAt(pos))) {
                pos++;
            }
        }
        if (pos == start) {
            throw new ParseException("Invalid number at " + pos);
        }
        return new JsonLiteral(s.substring(start, pos));
    }

    private char peek() throws ParseException {
        if (pos >= s.length()) {
            throw new ParseException("Unexpected end of input");
        }
        return s.charAt(pos);
    }

    private void expect(char c) throws ParseException {
        if (pos >= s.length() || s.charAt(pos) != c) {
            throw new ParseException("Expected '" + c + "' at " + pos);
        }
        pos++;
    }

    private void skipWs() {
        while (pos < s.length() && Character.isWhitespace(s.charAt(pos))) {
            pos++;
        }
    }

    private static void writeValue(StringBuilder sb, Object value) {
        if (value instanceof Map) {
            sb.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> entry : ((Map<?, ?>) value).entrySet()) {
                if (!first) {
                    sb.append(',');
                }
                first = false;
                writeString(sb, String.valueOf(entry.getKey()));
                sb.append(':');
                writeValue(sb, entry.getValue());
            }
            sb.append('}');
        } else if (value instanceof List) {
            sb.append('[');
            boolean first = true;
            for (Object item : (List<?>) value) {
                if (!first) {
                    sb.append(',');
                }
                first = false;
                writeValue(sb, item);
            }
            sb.append(']');
        } else if (value instanceof JsonLiteral) {
            sb.append(((JsonLiteral) value).raw);
        } else if (value == null) {
            sb.append("null");
        } else {
            writeString(sb, String.valueOf(value));
        }
    }

    private static void writeString(StringBuilder sb, String value) {
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
