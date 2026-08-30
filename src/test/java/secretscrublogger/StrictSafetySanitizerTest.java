package secretscrublogger;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class StrictSafetySanitizerTest {

    @Test
    void redactsAllUrlValuesFragmentsAndIdentifierLikePathSegments() {
        String url = "https://api-user:api-pass@example.com/users/alice%40example.com/orders/123456"
                + "?view=full&token=[REDACTED]&empty=#session-fragment";

        StrictSafetySanitizer.UrlResult result = StrictSafetySanitizer.sanitizeUrl(url);

        assertEquals("https://[REDACTED]@example.com/users/[REDACTED]/orders/[REDACTED]"
                + "?view=[REDACTED]&token=[REDACTED]&empty=#[REDACTED]", result.text());
        assertEquals(5, result.redactionCount());
        assertFalse(result.text().contains("api-user"));
        assertFalse(result.text().contains("api-pass"));
        assertFalse(result.text().contains("alice%40example.com"));
        assertFalse(result.text().contains("123456"));
        assertFalse(result.text().contains("session-fragment"));
    }

    @Test
    void omitsRequestBodyAndFailsUnknownHeadersClosed() {
        SecretRedactor redactor = new SecretRedactor();
        String raw = "POST /accounts/123456?tab=settings&token=query-secret#fragment HTTP/1.1\r\n"
                + "Host: example.com\r\n"
                + "Content-Type: application/json\r\n"
                + "Authorization: Bearer request-auth-secret\r\n"
                + "X-Request-ID: private-correlation-value\r\n"
                + " folded-continuation-secret\r\n"
                + "X-Marker-Bypass: [REDACTED]marker-bypass-secret\r\n"
                + "Referer: https://example.com/users/alice%40example.com?page=2\r\n\r\n"
                + "{\"name\":\"Alice\",\"privateNote\":\"body-secret-value\"}";

        StrictSafetySanitizer.MessageResult result =
                StrictSafetySanitizer.sanitizeMessage(redactor.redact(raw));

        for (String sensitive : new String[]{
                "123456", "settings", "query-secret", "fragment", "request-auth-secret",
                "private-correlation-value", "folded-continuation-secret", "marker-bypass-secret",
                "alice%40example.com", "body-secret-value"}) {
            assertFalse(result.text().contains(sensitive), sensitive + " must not survive strict mode");
        }
        assertTrue(result.text().contains("Host: example.com"));
        assertTrue(result.text().contains("Content-Type: application/json"));
        assertTrue(result.text().contains("Authorization: Bearer [REDACTED]"));
        assertTrue(result.text().contains("X-Request-ID: [REDACTED]"));
        assertTrue(result.text().endsWith(StrictSafetySanitizer.OMITTED_BODY));
        assertTrue(result.bodyOmitted());
        assertTrue(result.redactionCount() >= 5);
    }

    @Test
    void sanitizesResponseRedirectsAndUnknownValuesBeforeOmittingBody() {
        SecretRedactor redactor = new SecretRedactor();
        String raw = "HTTP/1.1 302 Found\r\n"
                + "Content-Type: text/html\r\n"
                + "Location: /continue?code=response-code&state=response-state\r\n"
                + "Content-Location: opaque-redirect-secret\r\n"
                + "Set-Cookie: session=response-cookie-secret; Path=/; HttpOnly\r\n"
                + "Content-Security-Policy: script-src 'nonce-response-nonce'\r\n"
                + "X-Frame-Options: DENY\r\n"
                + "X-Internal-Trace: private-trace-value\r\n\r\n"
                + "<html>private response body</html>";

        StrictSafetySanitizer.MessageResult result =
                StrictSafetySanitizer.sanitizeMessage(redactor.redact(raw));

        for (String sensitive : new String[]{
                "response-code", "response-state", "response-cookie-secret", "response-nonce",
                "opaque-redirect-secret", "private-trace-value", "private response body"}) {
            assertFalse(result.text().contains(sensitive), sensitive + " must not survive strict mode");
        }
        assertTrue(result.text().contains("Location: /continue?code=[REDACTED]&state=[REDACTED]"));
        assertTrue(result.text().contains("Content-Location: [REDACTED]"));
        assertTrue(result.text().contains("Set-Cookie: [REDACTED]"));
        assertTrue(result.text().contains("Content-Security-Policy: [REDACTED]"));
        assertTrue(result.text().contains("X-Frame-Options: DENY"));
        assertTrue(result.text().contains("X-Internal-Trace: [REDACTED]"));
        assertTrue(result.bodyOmitted());
    }

    @Test
    void compactAndStrictModesComposeWithoutRetainingNoiseOrReportingTruncation() {
        SecretRedactor redactor = new SecretRedactor();
        String raw = "POST /submit?mode=private HTTP/1.1\r\n"
                + "Host: example.com\r\n"
                + "User-Agent: noisy-browser-value\r\n"
                + "X-Internal-Trace: private-trace-value\r\n"
                + "Content-Type: text/plain\r\n\r\n"
                + "x".repeat(TrafficLoggerConfig.COMPACT_MAX_BODY_BYTES + 100);

        TrafficLoggerHttpHandler.PreparedMessage result = TrafficLoggerHttpHandler.prepareMessage(
                raw, redactor, true, true);

        assertFalse(result.text().contains("User-Agent:"));
        assertFalse(result.text().contains("noisy-browser-value"));
        assertFalse(result.text().contains("private-trace-value"));
        assertTrue(result.text().contains("X-Internal-Trace: [REDACTED]"));
        assertTrue(result.text().contains("mode=[REDACTED]"));
        assertTrue(result.text().endsWith(StrictSafetySanitizer.OMITTED_BODY));
        assertTrue(result.bodyOmitted());
        assertFalse(result.truncated(), "omission supersedes the compact body truncation");
    }

    @Test
    void standardModeStillRetainsBodiesAndOrdinaryHeaderValues() {
        SecretRedactor redactor = new SecretRedactor();
        String raw = "POST /submit?mode=normal HTTP/1.1\r\n"
                + "Host: example.com\r\n"
                + "X-Request-ID: visible-correlation-value\r\n"
                + "Content-Type: application/json\r\n\r\n"
                + "{\"password\":\"standard-mode-secret\",\"name\":\"Alice\"}";

        TrafficLoggerHttpHandler.PreparedMessage result = TrafficLoggerHttpHandler.prepareMessage(
                raw, redactor, false, false);

        assertFalse(result.text().contains("standard-mode-secret"));
        assertTrue(result.text().contains("mode=normal"));
        assertTrue(result.text().contains("X-Request-ID: visible-correlation-value"));
        assertTrue(result.text().contains("\"name\":\"Alice\""));
        assertFalse(result.bodyOmitted());
        assertFalse(result.truncated());
        assertEquals(1, result.redactionCount());
    }

    @Test
    void doesNotReportAnOmissionWhenNoBodyExists() {
        StrictSafetySanitizer.MessageResult result = StrictSafetySanitizer.sanitizeMessage(
                "GET /health?detail=full HTTP/1.1\r\nHost: example.com\r\n\r\n");

        assertFalse(result.bodyOmitted());
        assertTrue(result.text().endsWith("\r\n\r\n"));
        assertTrue(result.text().contains("detail=[REDACTED]"));
    }

    @Test
    void failsMalformedRequestLinesClosed() {
        StrictSafetySanitizer.MessageResult result =
                StrictSafetySanitizer.sanitizeMessage("malformed-line-with-private-value");

        assertEquals(SecretRedactor.REDACTED, result.text());
        assertEquals(1, result.redactionCount());
    }
}
