package secretscrublogger;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HttpMessageCompactorTest {

    @Test
    void removesRoutineRequestNoiseButKeepsSecurityContextAndRedactionEvidence() {
        SecretRedactor redactor = new SecretRedactor();
        redactor.setCustomSensitiveFields(List.of("usr_pwd"));
        String raw = "POST /login HTTP/1.1\r\n"
                + "Host: example.com\r\n"
                + "User-Agent: very-long-browser-description\r\n"
                + "Accept-Encoding: gzip, br\r\n"
                + "Sec-Fetch-Mode: cors\r\n"
                + "Next-Router-State-Tree: noisy-framework-state\r\n"
                + "Authorization: Bearer request-header-secret\r\n"
                + "Usr-Pwd: custom-header-secret\r\n"
                + "Origin: https://example.com\r\n"
                + "X-Request-ID: useful-correlation-id\r\n"
                + "Content-Type: application/json\r\n\r\n"
                + "{\"password\":\"request-body-secret\",\"name\":\"Alice\"}";

        String redacted = redactor.redact(raw);
        HttpMessageCompactor.CompactResult result = HttpMessageCompactor.compact(redacted, 1024);

        for (String secret : List.of(
                "request-header-secret", "custom-header-secret", "request-body-secret")) {
            assertFalse(result.text().contains(secret));
        }
        assertTrue(result.text().contains("POST /login HTTP/1.1"));
        assertTrue(result.text().contains("Host: example.com"));
        assertTrue(result.text().contains("Authorization: Bearer [REDACTED]"));
        assertTrue(result.text().contains("Usr-Pwd: [REDACTED]"));
        assertTrue(result.text().contains("Origin: https://example.com"));
        assertTrue(result.text().contains("X-Request-ID: useful-correlation-id"));
        assertTrue(result.text().contains("\"name\":\"Alice\""));
        assertFalse(result.text().contains("User-Agent:"));
        assertFalse(result.text().contains("Accept-Encoding:"));
        assertFalse(result.text().contains("Sec-Fetch-Mode:"));
        assertFalse(result.text().contains("Next-Router-State-Tree:"));
        assertFalse(result.bodyTruncated());
    }

    @Test
    void keepsSecurityAndCachingResponseHeadersWhileDroppingTransportNoise() {
        SecretRedactor redactor = new SecretRedactor();
        String raw = "HTTP/1.1 302 Found\r\n"
                + "Date: Sun, 30 Aug 2026 12:00:00 GMT\r\n"
                + "Connection: keep-alive\r\n"
                + "Content-Length: 12345\r\n"
                + "Link: </large-framework-chunk.js>; rel=preload\r\n"
                + "Location: /account\r\n"
                + "Set-Cookie: session=response-cookie-secret; Path=/; HttpOnly\r\n"
                + "Content-Security-Policy: default-src 'self'\r\n"
                + "Access-Control-Allow-Origin: https://example.com\r\n"
                + "Cache-Control: no-store\r\n"
                + "X-Frame-Options: DENY\r\n"
                + "Content-Type: application/json\r\n\r\n"
                + "{\"result\":\"redirecting\"}";

        String compacted = HttpMessageCompactor.compact(redactor.redact(raw), 1024).text();

        assertFalse(compacted.contains("response-cookie-secret"));
        assertTrue(compacted.contains("Set-Cookie: session=[REDACTED]; Path=/; HttpOnly"));
        assertTrue(compacted.contains("Content-Security-Policy:"));
        assertTrue(compacted.contains("Access-Control-Allow-Origin:"));
        assertTrue(compacted.contains("Cache-Control: no-store"));
        assertTrue(compacted.contains("X-Frame-Options: DENY"));
        assertTrue(compacted.contains("Location: /account"));
        assertTrue(compacted.contains("\"result\":\"redirecting\""));
        assertFalse(compacted.contains("Date:"));
        assertFalse(compacted.contains("Connection:"));
        assertFalse(compacted.contains("Content-Length:"));
        assertFalse(compacted.contains("Link:"));
    }

    @Test
    void capsBodiesWithoutSplittingUtf8CharactersAndReportsTheOmission() {
        String raw = "HTTP/1.1 200 OK\nContent-Type: text/plain\n\n"
                + "a".repeat(9) + "€" + "tail-that-is-omitted";

        HttpMessageCompactor.CompactResult result = HttpMessageCompactor.compact(raw, 10);

        assertTrue(result.bodyTruncated());
        assertTrue(result.text().endsWith("a".repeat(9) + TrafficLoggerConfig.TRUNCATION_MARKER));
        assertFalse(result.text().contains("€"));
        assertFalse(result.text().contains("tail-that-is-omitted"));
        assertFalse(result.text().contains("�"));
    }

    @Test
    void rejectsInvalidBodyLimits() {
        assertThrows(IllegalArgumentException.class,
                () -> HttpMessageCompactor.compact("GET / HTTP/1.1", -1));
    }
}
