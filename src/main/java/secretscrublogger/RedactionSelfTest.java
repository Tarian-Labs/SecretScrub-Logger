package secretscrublogger;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/** Runs synthetic canaries through the in-memory redaction pipeline without sending or logging. */
final class RedactionSelfTest {

    private static final String REDACTION_MARKER = SecretRedactor.REDACTED;

    private RedactionSelfTest() {
    }

    static Result run(SecretRedactor redactor) {
        SecretRedactor.ExclusionConfig exclusions = redactor.exclusionConfig();
        if (!exclusions.enabled()) {
            return run(redactor::redactWithMetadata, redactor::redactUrlWithMetadata,
                    redactor.customSensitiveFields());
        }

        SecretRedactor baselineRedactor = new SecretRedactor();
        baselineRedactor.setCustomSensitiveFields(redactor.customSensitiveFields());
        Result baseline = run(
                baselineRedactor::redactWithMetadata,
                baselineRedactor::redactUrlWithMetadata,
                baselineRedactor.customSensitiveFields());
        Audit bypassAudit = new Audit();
        String nonce = UUID.randomUUID().toString().replace("-", "");
        try {
            testConfiguredExclusions(
                    redactor::redactWithMetadata, bypassAudit, nonce, exclusions.fields());
        } catch (RuntimeException e) {
            bypassAudit.fail("exclusion self-test execution ("
                    + e.getClass().getSimpleName() + ")");
        }

        List<String> failures = new ArrayList<>(baseline.failures());
        failures.addAll(bypassAudit.failures);
        return new Result(
                failures.isEmpty(),
                baseline.checks() + bypassAudit.checks,
                List.copyOf(failures),
                baseline.customFieldsChecked(),
                exclusions.fields().size(),
                true);
    }

    static Result run(RedactionOperation messageRedactor, RedactionOperation urlRedactor,
                      Set<String> customFields) {
        Audit audit = new Audit();
        String nonce = UUID.randomUUID().toString().replace("-", "");
        try {
            testUrl(urlRedactor, audit, nonce);
            testHeadersAndJson(messageRedactor, audit, nonce);
            testForm(messageRedactor, audit, nonce);
            testXml(messageRedactor, audit, nonce);
            testMultipart(messageRedactor, audit, nonce);
            testMalformedAndEscapedData(messageRedactor, audit, nonce);
            testCustomFields(messageRedactor, audit, nonce, customFields);
        } catch (RuntimeException e) {
            audit.fail("self-test execution (" + e.getClass().getSimpleName() + ")");
        }
        return new Result(audit.failures.isEmpty(), audit.checks, List.copyOf(audit.failures),
                customFields.size(), 0, false);
    }

    private static void testUrl(RedactionOperation redactor, Audit audit, String nonce) {
        String pathSecret = canary("PATH", nonce);
        String querySecret = canary("QUERY", nonce);
        SecretRedactor.RedactionResult result = redactor.apply(
                "https://self-test.invalid/reset-password/" + pathSecret
                        + "?token=" + querySecret + "&view=public");

        audit.removed("URL path canary", result.text(), pathSecret);
        audit.removed("URL query canary", result.text(), querySecret);
        audit.contains("URL structure", result.text(), "https://self-test.invalid/reset-password/");
        audit.markerCount("URL redaction count", result, 2);
    }

    private static void testHeadersAndJson(RedactionOperation redactor, Audit audit, String nonce) {
        String querySecret = canary("MESSAGEQUERY", nonce);
        String authorizationSecret = canary("AUTHORIZATION", nonce);
        String cookieSecret = canary("COOKIE", nonce);
        String passwordSecret = canary("PASSWORD", nonce);
        String apiKeySecret = canary("APIKEY", nonce);
        String jwtSecret = jwtCanary(nonce);
        String raw = "POST /self-test?token=" + querySecret + " HTTP/1.1\r\n"
                + "Host: self-test.invalid\r\n"
                + "Authorization: Bearer " + authorizationSecret + "\r\n"
                + "Cookie: sid=" + cookieSecret + "\r\n"
                + "Content-Type: application/json\r\n\r\n"
                + "{\"password\":\"" + passwordSecret + "\","
                + "\"nested\":{\"apiKey\":\"" + apiKeySecret + "\"},"
                + "\"opaqueValue\":\"" + jwtSecret + "\"}";
        SecretRedactor.RedactionResult result = redactor.apply(raw);

        audit.removed("request query canary", result.text(), querySecret);
        audit.removed("authorization canary", result.text(), authorizationSecret);
        audit.removed("cookie canary", result.text(), cookieSecret);
        audit.removed("JSON password canary", result.text(), passwordSecret);
        audit.removed("nested JSON API key canary", result.text(), apiKeySecret);
        audit.removed("JWT-shaped canary", result.text(), jwtSecret);
        audit.contains("request structure", result.text(), "POST /self-test?");
        audit.contains("authorization scheme", result.text(), "Authorization: Bearer " + REDACTION_MARKER);
        audit.markerCount("request redaction count", result, 6);
    }

    private static void testForm(RedactionOperation redactor, Audit audit, String nonce) {
        String passwordSecret = canary("FORMPASSWORD", nonce);
        String csrfSecret = canary("FORMCSRF", nonce);
        String raw = "POST /self-test/form HTTP/1.1\r\n"
                + "Content-Type: application/x-www-form-urlencoded\r\n\r\n"
                + "password=" + passwordSecret + "&csrf_token=" + csrfSecret + "&mode=test";
        SecretRedactor.RedactionResult result = redactor.apply(raw);

        audit.removed("form password canary", result.text(), passwordSecret);
        audit.removed("form CSRF canary", result.text(), csrfSecret);
        audit.contains("form request structure", result.text(), "POST /self-test/form HTTP/1.1");
        audit.markerCount("form redaction count", result, 2);
    }

    private static void testXml(RedactionOperation redactor, Audit audit, String nonce) {
        String passwordSecret = canary("XMLPASSWORD", nonce);
        String clientSecret = canary("XMLATTRIBUTE", nonce);
        String raw = "POST /self-test/xml HTTP/1.1\r\nContent-Type: application/xml\r\n\r\n"
                + "<request client_secret=\"" + clientSecret + "\"><password>"
                + passwordSecret + "</password><mode>test</mode></request>";
        SecretRedactor.RedactionResult result = redactor.apply(raw);

        audit.removed("XML element canary", result.text(), passwordSecret);
        audit.removed("XML attribute canary", result.text(), clientSecret);
        audit.contains("XML request structure", result.text(), "POST /self-test/xml HTTP/1.1");
        audit.markerCount("XML redaction count", result, 2);
    }

    private static void testMultipart(RedactionOperation redactor, Audit audit, String nonce) {
        String passwordSecret = canary("MULTIPART", nonce);
        String boundary = "SecretScrubSelfTestBoundary";
        String body = "--" + boundary + "\r\n"
                + "Content-Disposition: form-data; name=\"password\"\r\n\r\n"
                + passwordSecret + "\r\n"
                + "--" + boundary + "--\r\n";
        String raw = "POST /self-test/multipart HTTP/1.1\r\n"
                + "Content-Type: multipart/form-data; boundary=" + boundary + "\r\n\r\n"
                + body;
        SecretRedactor.RedactionResult result = redactor.apply(raw);

        audit.removed("multipart canary", result.text(), passwordSecret);
        audit.contains("multipart request structure", result.text(),
                "POST /self-test/multipart HTTP/1.1");
        audit.markerCount("multipart redaction count", result, 1);
    }

    private static void testMalformedAndEscapedData(RedactionOperation redactor, Audit audit,
                                                     String nonce) {
        String malformedSecret = canary("MALFORMED", nonce);
        String malformed = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
                + "{\"accessToken\":\"" + malformedSecret + "\", broken";
        SecretRedactor.RedactionResult malformedResult = redactor.apply(malformed);
        audit.removed("malformed JSON canary", malformedResult.text(), malformedSecret);
        audit.contains("response status structure", malformedResult.text(), "HTTP/1.1 200 OK");
        audit.markerCount("malformed JSON redaction count", malformedResult, 1);

        String escapedSecret = canary("ESCAPED", nonce);
        String escaped = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
                + "<script>{\\\"token\\\":\\\"" + escapedSecret + "\\\"}</script>";
        SecretRedactor.RedactionResult escapedResult = redactor.apply(escaped);
        audit.removed("escaped framework canary", escapedResult.text(), escapedSecret);
        audit.contains("escaped response status structure", escapedResult.text(), "HTTP/1.1 200 OK");
        audit.markerCount("escaped framework redaction count", escapedResult, 1);
    }

    private static void testCustomFields(RedactionOperation redactor, Audit audit, String nonce,
                                         Set<String> customFields) {
        if (customFields.isEmpty()) {
            return;
        }
        StringBuilder body = new StringBuilder("{");
        List<String> secrets = new ArrayList<>(customFields.size());
        int index = 0;
        for (String field : customFields) {
            if (index > 0) {
                body.append(',');
            }
            String secret = canary("CUSTOM" + index, nonce);
            secrets.add(secret);
            body.append('"').append(field).append("\":\"").append(secret).append('"');
            index++;
        }
        body.append('}');
        String raw = "POST /self-test/custom HTTP/1.1\r\n"
                + "Content-Type: application/json\r\n\r\n" + body;
        SecretRedactor.RedactionResult result = redactor.apply(raw);

        for (int i = 0; i < secrets.size(); i++) {
            audit.removed("custom field canary " + (i + 1), result.text(), secrets.get(i));
        }
        audit.contains("custom-field request structure", result.text(),
                "POST /self-test/custom HTTP/1.1");
        audit.markerCount("custom-field redaction count", result, customFields.size());
    }

    private static void testConfiguredExclusions(RedactionOperation redactor, Audit audit,
                                                 String nonce, Set<String> excludedFields) {
        if (excludedFields.isEmpty()) {
            return;
        }
        StringBuilder body = new StringBuilder("{");
        List<String> values = new ArrayList<>(excludedFields.size());
        int index = 0;
        for (String field : excludedFields) {
            if (index > 0) {
                body.append(',');
            }
            String rotatedNonce = nonce.substring(index % 16) + nonce.substring(0, index % 16);
            String value = jwtCanary(rotatedNonce);
            values.add(value);
            body.append('"').append(field).append("\":\"").append(value).append('"');
            index++;
        }
        body.append('}');
        String raw = "POST /self-test/exclusions HTTP/1.1\r\n"
                + "Content-Type: application/json\r\n\r\n" + body;
        SecretRedactor.RedactionResult result = redactor.apply(raw);

        for (int i = 0; i < values.size(); i++) {
            audit.preserved("configured exclusion " + (i + 1), result.text(), values.get(i));
        }
        audit.contains("exclusion request structure", result.text(),
                "POST /self-test/exclusions HTTP/1.1");
    }

    private static String canary(String label, String nonce) {
        return "SSCANARY" + label + nonce;
    }

    private static String jwtCanary(String nonce) {
        return nonce.substring(0, 12) + "." + nonce.substring(8, 24) + "." + nonce.substring(16);
    }

    @FunctionalInterface
    interface RedactionOperation {
        SecretRedactor.RedactionResult apply(String input);
    }

    record Result(boolean passed, int checks, List<String> failures, int customFieldsChecked,
                  int excludedFieldsChecked, boolean bypassEnabled) {
    }

    private static final class Audit {
        private int checks;
        private final List<String> failures = new ArrayList<>();

        void removed(String name, String output, String secret) {
            check(name + " complete value", output != null && !output.contains(secret));
            check(name + " prefix", output != null && !output.contains(secret.substring(0, 8)));
            check(name + " suffix", output != null
                    && !output.contains(secret.substring(secret.length() - 8)));
        }

        void contains(String name, String output, String expected) {
            check(name, output != null && output.contains(expected));
        }

        void preserved(String name, String output, String expected) {
            check(name, output != null && output.contains(expected));
        }

        void markerCount(String name, SecretRedactor.RedactionResult result, int minimum) {
            check(name, result != null && result.redactionCount() >= minimum
                    && result.text() != null && result.text().contains(REDACTION_MARKER));
        }

        void check(String name, boolean passed) {
            checks++;
            if (!passed) {
                failures.add(name);
            }
        }

        void fail(String name) {
            checks++;
            failures.add(name);
        }
    }
}
