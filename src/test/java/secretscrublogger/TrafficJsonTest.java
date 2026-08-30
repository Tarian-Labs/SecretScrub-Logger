package secretscrublogger;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TrafficJsonTest {

    @Test
    @SuppressWarnings("unchecked")
    void addsMachineReadableSafetyAndTrustMetadataWithoutChangingExistingFields()
            throws MiniJson.ParseException {
        TrafficJson.SafetyMetadata metadata =
                new TrafficJson.SafetyMetadata(
                        1, 2, 3, false, true, false, false, false, false,
                        false, 0);

        String json = TrafficJson.build(
                "2026-08-30T12:00:00Z",
                "POST",
                "https://example.com/reset/[REDACTED]",
                200,
                "request [REDACTED]",
                "response [TRUNCATED]",
                metadata
        );

        Map<String, Object> record = (Map<String, Object>) MiniJson.parse(json);
        Map<String, Object> meta = (Map<String, Object>) record.get("meta");
        Map<String, Object> redaction = (Map<String, Object>) meta.get("redaction");
        Map<String, Object> exclusions = (Map<String, Object>) redaction.get("exclusions");
        Map<String, Object> truncation = (Map<String, Object>) meta.get("truncation");
        Map<String, Object> omission = (Map<String, Object>) meta.get("omission");

        assertEquals("POST", record.get("method"));
        assertLiteral("200", record.get("status"));
        assertLiteral("1", meta.get("schemaVersion"));
        assertEquals("burp-http", meta.get("source"));
        assertLiteral("true", meta.get("inScope"));
        assertEquals("untrusted", meta.get("contentTrust"));
        assertEquals("full", meta.get("captureMode"));
        assertEquals("standard", meta.get("safetyMode"));
        assertLiteral("true", redaction.get("performed"));
        assertEquals("standard-v1", redaction.get("policy"));
        assertEquals("best-effort", redaction.get("assurance"));
        assertEquals("[REDACTED]", redaction.get("marker"));
        assertLiteral("6", redaction.get("count"));
        assertLiteral("1", redaction.get("urlCount"));
        assertLiteral("2", redaction.get("requestCount"));
        assertLiteral("3", redaction.get("responseCount"));
        assertLiteral("0", exclusions.get("configuredFieldCount"));
        assertLiteral("false", exclusions.get("enabled"));
        assertLiteral("false", exclusions.get("active"));
        assertLiteral("false", truncation.get("request"));
        assertLiteral("true", truncation.get("response"));
        assertLiteral("false", omission.get("requestBody"));
        assertLiteral("false", omission.get("responseBody"));
    }

    @Test
    void rejectsImpossibleNegativeRedactionCounts() {
        assertThrows(IllegalArgumentException.class,
                () -> new TrafficJson.SafetyMetadata(
                        0, -1, 0, false, false, false, false, false, false,
                        false, 0));
        assertThrows(IllegalArgumentException.class,
                () -> new TrafficJson.SafetyMetadata(
                        0, 0, 0, false, false, false, false, false, false,
                        true, -1));
    }

    @Test
    @SuppressWarnings("unchecked")
    void identifiesCompactCapturesInMetadata() throws MiniJson.ParseException {
        String json = TrafficJson.build(
                "2026-08-30T12:00:00Z", "GET", "https://example.com/", 200,
                "request", "response",
                new TrafficJson.SafetyMetadata(
                        0, 0, 0, false, false, true, false, false, false,
                        false, 0));

        Map<String, Object> record = (Map<String, Object>) MiniJson.parse(json);
        Map<String, Object> meta = (Map<String, Object>) record.get("meta");

        assertEquals("compact", meta.get("captureMode"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void identifiesStrictSafetyAndBodyOmissionsInMetadata() throws MiniJson.ParseException {
        String json = TrafficJson.build(
                "2026-08-30T12:00:00Z", "POST", "https://example.com/", 200,
                "request", "response",
                new TrafficJson.SafetyMetadata(
                        0, 1, 2, false, false, false, true, true, true,
                        true, 2));

        Map<String, Object> record = (Map<String, Object>) MiniJson.parse(json);
        Map<String, Object> meta = (Map<String, Object>) record.get("meta");
        Map<String, Object> redaction = (Map<String, Object>) meta.get("redaction");
        Map<String, Object> exclusions = (Map<String, Object>) redaction.get("exclusions");
        Map<String, Object> omission = (Map<String, Object>) meta.get("omission");

        assertEquals("strict", meta.get("safetyMode"));
        assertEquals("strict-v1", redaction.get("policy"));
        assertLiteral("2", exclusions.get("configuredFieldCount"));
        assertLiteral("true", exclusions.get("enabled"));
        assertLiteral("false", exclusions.get("active"));
        assertLiteral("true", omission.get("requestBody"));
        assertLiteral("true", omission.get("responseBody"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void disclosesAppliedStandardModeExclusionsWithoutNamingFields()
            throws MiniJson.ParseException {
        String json = TrafficJson.build(
                "2026-08-30T12:00:00Z", "POST", "https://example.com/", 200,
                "request", "response",
                new TrafficJson.SafetyMetadata(
                        0, 0, 0, false, false, false, false, false, false,
                        true, 3));

        Map<String, Object> record = (Map<String, Object>) MiniJson.parse(json);
        Map<String, Object> meta = (Map<String, Object>) record.get("meta");
        Map<String, Object> redaction = (Map<String, Object>) meta.get("redaction");
        Map<String, Object> exclusions = (Map<String, Object>) redaction.get("exclusions");

        assertLiteral("3", exclusions.get("configuredFieldCount"));
        assertLiteral("true", exclusions.get("enabled"));
        assertLiteral("true", exclusions.get("active"));
        assertFalse(json.contains("usr_pwd"));
    }

    @Test
    void parsesPersistedCompactModeConservatively() {
        assertTrue(SecretScrubLoggerExtension.parseCompactMode("true"));
        assertTrue(SecretScrubLoggerExtension.parseCompactMode(" TRUE "));
        assertFalse(SecretScrubLoggerExtension.parseCompactMode(null));
        assertFalse(SecretScrubLoggerExtension.parseCompactMode("yes"));
        assertFalse(SecretScrubLoggerExtension.parseCompactMode("invalid"));
    }

    @Test
    void parsesPersistedStrictModeConservatively() {
        assertTrue(SecretScrubLoggerExtension.parseStrictMode("true"));
        assertTrue(SecretScrubLoggerExtension.parseStrictMode(" TRUE "));
        assertFalse(SecretScrubLoggerExtension.parseStrictMode(null));
        assertFalse(SecretScrubLoggerExtension.parseStrictMode("yes"));
        assertFalse(SecretScrubLoggerExtension.parseStrictMode("invalid"));
    }

    @Test
    void parsesPersistedRedactionBypassConservatively() {
        assertTrue(SecretScrubLoggerExtension.parseRedactionBypass("true"));
        assertTrue(SecretScrubLoggerExtension.parseRedactionBypass(" TRUE "));
        assertFalse(SecretScrubLoggerExtension.parseRedactionBypass(null));
        assertFalse(SecretScrubLoggerExtension.parseRedactionBypass("yes"));
        assertFalse(SecretScrubLoggerExtension.parseRedactionBypass("invalid"));
    }

    @Test
    void truncationResultAccuratelyReportsWhetherTextWasShortened() {
        TrafficLoggerHttpHandler.TruncationResult shortResult =
                TrafficLoggerHttpHandler.truncate("short message");
        String oversized = "x".repeat(TrafficLoggerConfig.MAX_BODY_BYTES + 1);
        TrafficLoggerHttpHandler.TruncationResult longResult =
                TrafficLoggerHttpHandler.truncate(oversized);

        assertFalse(shortResult.truncated());
        assertEquals("short message", shortResult.text());
        assertTrue(longResult.truncated());
        assertTrue(longResult.text().endsWith(TrafficLoggerConfig.TRUNCATION_MARKER));
        assertFalse(longResult.text().contains(oversized));
    }

    private static void assertLiteral(String expected, Object actual) {
        assertTrue(actual instanceof MiniJson.JsonLiteral);
        assertEquals(expected, ((MiniJson.JsonLiteral) actual).raw);
    }
}
