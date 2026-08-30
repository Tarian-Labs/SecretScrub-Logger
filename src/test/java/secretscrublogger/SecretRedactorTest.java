package secretscrublogger;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Proves that secret values never appear anywhere in the redacted output, across every capture
 * surface (headers, bodies, query params, cookies, forms) and that safe context (methods, paths,
 * status codes, header/key names) is preserved.
 */
class SecretRedactorTest {

    private static final String JWT =
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";

    private final SecretRedactor redactor = new SecretRedactor();

    @Test
    void reportsIntroducedRedactionMarkersWithoutCountingExistingPlaceholders() {
        String raw = "POST /login?token=query-secret&safe=yes HTTP/1.1\r\n"
                + "Authorization: Bearer header-secret-value\r\n"
                + "Content-Type: application/json\r\n\r\n"
                + "{\"password\":\"body-secret\",\"note\":\"[REDACTED]\"}";

        SecretRedactor.RedactionResult result = redactor.redactWithMetadata(raw);
        SecretRedactor.RedactionResult urlResult = redactor.redactUrlWithMetadata(
                "https://example.com/login?token=query-secret&safe=yes");

        assertEquals(3, result.redactionCount());
        assertEquals(1, urlResult.redactionCount());
        assertFalse(result.text().contains("query-secret"));
        assertFalse(result.text().contains("header-secret-value"));
        assertFalse(result.text().contains("body-secret"));
        assertTrue(result.text().contains("\"note\":\"[REDACTED]\""));
    }

    @Test
    void redactsAuthorizationBearerHeaderButKeepsScheme() {
        String raw = "GET /api/data HTTP/1.1\r\n"
                + "Host: example.com\r\n"
                + "Authorization: Bearer " + JWT + "\r\n\r\n";

        String result = redactor.redact(raw);

        assertFalse(result.contains(JWT), "raw secret must not appear in output");
        assertTrue(result.contains("GET /api/data HTTP/1.1"), "method/path must be preserved");
        assertTrue(result.contains("Authorization: Bearer " + SecretRedactor.REDACTED));
    }

    @Test
    void redactsJsonAccessAndRefreshTokenFieldsIncludingNested() {
        String body = "{\"accessToken\":\"" + JWT + "\",\"user\":{\"refreshToken\":\"abc.def.ghi-secret\","
                + "\"name\":\"Alice\"},\"tokens\":[\"nested-secret-1\",\"nested-secret-2\"]}";
        String raw = "POST /login HTTP/1.1\r\n"
                + "Content-Type: application/json\r\n\r\n"
                + body;

        String result = redactor.redact(raw);

        assertFalse(result.contains(JWT));
        assertFalse(result.contains("abc.def.ghi-secret"));
        assertFalse(result.contains("nested-secret-1"));
        assertFalse(result.contains("nested-secret-2"));
        assertTrue(result.contains("\"name\":\"Alice\""), "non-sensitive nested value must be preserved");
        assertTrue(result.contains("\"accessToken\":\"" + SecretRedactor.REDACTED + "\""));
        assertTrue(result.contains("\"refreshToken\":\"" + SecretRedactor.REDACTED + "\""));
        assertTrue(result.contains("\"tokens\":\"" + SecretRedactor.REDACTED + "\""));
    }

    @Test
    void redactsTokenFieldsWithMixedCasing() {
        String body = "{\"AccessToken\":\"secret-value-1\",\"REFRESH_TOKEN\":\"secret-value-2\","
                + "\"ApiKey\":\"secret-value-3\"}";
        String raw = "POST /login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n" + body;

        String result = redactor.redact(raw);

        assertFalse(result.contains("secret-value-1"));
        assertFalse(result.contains("secret-value-2"));
        assertFalse(result.contains("secret-value-3"));
        assertTrue(result.contains("\"AccessToken\":\"" + SecretRedactor.REDACTED + "\""));
    }

    @Test
    void redactsQueryParametersLikeAccessAndRefreshToken() {
        String raw = "GET /callback?access_token=super-secret-abc&refresh_token=another-secret&state=xyz HTTP/1.1\r\n"
                + "Host: example.com\r\n\r\n";

        String result = redactor.redact(raw);

        assertFalse(result.contains("super-secret-abc"));
        assertFalse(result.contains("another-secret"));
        assertTrue(result.contains("state=xyz"), "non-sensitive query param must be preserved");
        assertTrue(result.contains("access_token=" + SecretRedactor.REDACTED));
        assertTrue(result.contains("refresh_token=" + SecretRedactor.REDACTED));
    }

    @Test
    void redactsCookieAndSetCookieHeaders() {
        String raw = "GET /home HTTP/1.1\r\n"
                + "Cookie: sessionid=super-secret-session; theme=dark\r\n\r\n";
        String result = redactor.redact(raw);
        assertFalse(result.contains("super-secret-session"));
        assertFalse(result.contains("dark"), "the Cookie header is treated as sensitive as a whole");
        assertTrue(result.contains("sessionid=" + SecretRedactor.REDACTED));
        assertTrue(result.contains("theme=" + SecretRedactor.REDACTED));

        String rawResponse = "HTTP/1.1 200 OK\r\n"
                + "Set-Cookie: sid=super-secret-set-cookie; Path=/; HttpOnly; Secure\r\n\r\n";
        String responseResult = redactor.redact(rawResponse);
        assertFalse(responseResult.contains("super-secret-set-cookie"));
        assertTrue(responseResult.contains("Path=/"), "cookie attributes must be preserved");
        assertTrue(responseResult.contains("HttpOnly"));
        assertTrue(responseResult.contains("sid=" + SecretRedactor.REDACTED));
        assertTrue(responseResult.contains("200 OK"), "status code must be preserved");
    }

    @Test
    void redactsFormEncodedBodies() {
        String body = "username=alice&password=super-secret-pw&remember=true";
        String raw = "POST /login HTTP/1.1\r\n"
                + "Content-Type: application/x-www-form-urlencoded\r\n\r\n"
                + body;

        String result = redactor.redact(raw);

        assertFalse(result.contains("super-secret-pw"));
        assertTrue(result.contains("username=alice"), "non-sensitive form field must be preserved");
        assertTrue(result.contains("remember=true"));
        assertTrue(result.contains("password=" + SecretRedactor.REDACTED));
    }

    @Test
    void redactsJwtShapedValuesUnderArbitraryJsonKeys() {
        String body = "{\"weirdFieldName\":\"" + JWT + "\",\"other\":\"plain-value\"}";
        String raw = "POST /whatever HTTP/1.1\r\nContent-Type: application/json\r\n\r\n" + body;

        String result = redactor.redact(raw);

        assertFalse(result.contains(JWT));
        assertTrue(result.contains("\"other\":\"plain-value\""));
        assertTrue(result.contains(SecretRedactor.REDACTED));
    }

    @Test
    void fallsBackToTextRedactionForMalformedJson() {
        String body = "{\"accessToken\": \"" + JWT + "\", invalid json here";
        String raw = "POST /broken HTTP/1.1\r\nContent-Type: application/json\r\n\r\n" + body;

        String result = redactor.redact(raw);

        assertFalse(result.contains(JWT));
    }

    @Test
    void fallsBackToTextRedactionForUnknownContentType() {
        String body = "some-binary-ish-blob token=" + JWT + " trailing";
        String raw = "POST /upload HTTP/1.1\r\nContent-Type: application/octet-stream\r\n\r\n" + body;

        String result = redactor.redact(raw);

        assertFalse(result.contains(JWT));
    }

    @Test
    void redactsSensitiveFieldsInsideEscapedFrameworkResponseData() {
        String escapedQuote = "\\" + "\"";
        String doubleEscapedQuote = "\\" + escapedQuote;
        String body = "<script>self.__next_f.push([1,\"__PAGE__?{"
                + escapedQuote + "token" + escapedQuote + ":"
                + escapedQuote + "escaped-query-secret" + escapedQuote + ","
                + escapedQuote + "mode" + escapedQuote + ":"
                + escapedQuote + "positive" + escapedQuote + "}\"]);</script>"
                + "<script>{"
                + doubleEscapedQuote + "apiKey" + doubleEscapedQuote + ":"
                + doubleEscapedQuote + "double-escaped-secret" + doubleEscapedQuote
                + "}</script>";
        String raw = "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\r\n" + body;

        String result = redactor.redact(raw);

        assertFalse(result.contains("escaped-query-secret"));
        assertFalse(result.contains("double-escaped-secret"));
        assertTrue(result.contains("positive"), "ordinary escaped fields must be preserved");
    }

    @Test
    void neverLeaksPartialTokenPrefixOrSuffix() {
        String secret = "test-token-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        String body = "{\"apiKey\":\"" + secret + "\"}";
        String raw = "POST /pay HTTP/1.1\r\nContent-Type: application/json\r\n\r\n" + body;

        String result = redactor.redact(raw);

        assertFalse(result.contains(secret));
        assertFalse(result.contains(secret.substring(0, 8)), "no prefix leakage");
        assertFalse(result.contains(secret.substring(secret.length() - 8)), "no suffix leakage");
    }

    @Test
    void redactsConfiguredCustomFieldInRequestAndResponseJson() {
        redactor.setCustomSensitiveFields(java.util.List.of("usr_pwd"));
        String rawRequest = "POST /login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n"
                + "{\"username\":\"alice\",\"usr_pwd\":\"custom-request-secret\"}";
        String rawResponse = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
                + "{\"USR-PWD\":\"custom-response-secret\",\"result\":\"ok\"}";

        String requestResult = redactor.redact(rawRequest);
        String responseResult = redactor.redact(rawResponse);

        assertFalse(requestResult.contains("custom-request-secret"));
        assertFalse(responseResult.contains("custom-response-secret"));
        assertTrue(requestResult.contains("\"usr_pwd\":\"" + SecretRedactor.REDACTED + "\""));
        assertTrue(responseResult.contains("\"USR-PWD\":\"" + SecretRedactor.REDACTED + "\""));
        assertTrue(requestResult.contains("\"username\":\"alice\""));
        assertTrue(responseResult.contains("\"result\":\"ok\""));
    }

    @Test
    void customFieldUsesExactNormalizedMatchingAndCanBeCleared() {
        redactor.setCustomSensitiveFields(java.util.List.of("usr_pwd"));
        String raw = "POST / HTTP/1.1\r\nContent-Type: application/json\r\n\r\n"
                + "{\"usrPwd\":\"hide-me\",\"usr_pwd_hint\":\"keep-me\"}";

        String configuredResult = redactor.redact(raw);
        assertFalse(configuredResult.contains("hide-me"));
        assertTrue(configuredResult.contains("keep-me"));

        redactor.setCustomSensitiveFields(java.util.List.of());
        String clearedResult = redactor.redact(raw);
        assertTrue(clearedResult.contains("hide-me"));
    }

    @Test
    void configuredExclusionsDoNothingUntilBypassIsEnabled() {
        redactor.setExcludedFields(java.util.List.of("token", "password", "authorization"));
        String raw = "POST /login?token=query-secret HTTP/1.1\r\n"
                + "Authorization: Bearer header-secret-value\r\n"
                + "Content-Type: application/json\r\n\r\n"
                + "{\"password\":\"body-secret-value\"}";

        String result = redactor.redact(raw);

        for (String secret : java.util.List.of(
                "query-secret", "header-secret-value", "body-secret-value")) {
            assertFalse(result.contains(secret));
        }
        assertFalse(redactor.exclusionConfig().enabled());
        assertEquals(3, redactor.exclusionConfig().fields().size());
    }

    @Test
    void enabledExclusionsBypassHeaderQueryCookieJsonAndFormRedactionExactly() {
        redactor.setCustomSensitiveFields(java.util.List.of("usr_pwd"));
        redactor.setExcludedFields(java.util.List.of("usr_pwd", "token"));
        redactor.setExclusionsEnabled(true);
        String excludedJwt = JWT;
        String request = "POST /login?token=" + excludedJwt
                + "&token_hint=control-query-secret HTTP/1.1\r\n"
                + "Usr-Pwd: Bearer EXCLUDED-HEADER-SECRET-123456789\r\n"
                + "Cookie: usr_pwd=EXCLUDED-COOKIE-SECRET-123456789; sid=control-cookie-secret\r\n"
                + "Content-Type: application/json\r\n\r\n"
                + "{\"USR-PWD\":{\"token\":\"EXCLUDED-NESTED-SECRET-123456789\"},"
                + "\"token_hint\":\"control-json-secret\"}";
        String form = "POST /form HTTP/1.1\r\n"
                + "Content-Type: application/x-www-form-urlencoded\r\n\r\n"
                + "usrPwd=EXCLUDED-FORM-SECRET-123456789&password=control-form-secret";

        String requestResult = redactor.redact(request);
        String formResult = redactor.redact(form);

        for (String preserved : java.util.List.of(
                excludedJwt,
                "EXCLUDED-HEADER-SECRET-123456789",
                "EXCLUDED-COOKIE-SECRET-123456789",
                "EXCLUDED-NESTED-SECRET-123456789",
                "EXCLUDED-FORM-SECRET-123456789")) {
            assertTrue((requestResult + formResult).contains(preserved),
                    preserved + " should be intentionally preserved");
        }
        for (String redacted : java.util.List.of(
                "control-query-secret", "control-cookie-secret",
                "control-json-secret", "control-form-secret")) {
            assertFalse((requestResult + formResult).contains(redacted),
                    redacted + " must remain redacted");
        }
    }

    @Test
    void enabledExclusionsBypassMultipartXmlAndMalformedFallbackScanning() {
        redactor.setExcludedFields(java.util.List.of("usr_pwd", "private_token"));
        redactor.setExclusionsEnabled(true);
        String multipartSecret = "EXCLUDED-MULTIPART-SECRET-123456789";
        String boundary = "SecretScrubExclusionBoundary";
        String multipart = "POST /upload HTTP/1.1\r\n"
                + "Content-Type: multipart/form-data; boundary=" + boundary + "\r\n\r\n"
                + "--" + boundary + "\r\n"
                + "Content-Disposition: form-data; name=\"usr_pwd\"\r\n\r\n"
                + multipartSecret + "\r\n--" + boundary + "--\r\n";
        String xmlElementSecret = JWT;
        String xmlAttributeSecret = "EXCLUDED-XML-ATTRIBUTE-SECRET-123456789";
        String xml = "POST /xml HTTP/1.1\r\nContent-Type: application/xml\r\n\r\n"
                + "<request private_token=\"" + xmlAttributeSecret + "\">"
                + "<usr_pwd>" + xmlElementSecret + "</usr_pwd>"
                + "<password>control-xml-secret</password></request>";
        String malformedSecret = "EXCLUDED-MALFORMED-SECRET-123456789";
        String malformed = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
                + "{\"usr_pwd\":\"" + malformedSecret + "\","
                + "\"password\":\"control-malformed-secret\", broken";
        String escapedSecret = "EXCLUDED-ESCAPED-SECRET-123456789";
        String escaped = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
                + "<script>{\\\"usr_pwd\\\":\\\"" + escapedSecret + "\\\","
                + "\\\"token\\\":\\\"control-escaped-secret\\\"}</script>";

        String output = redactor.redact(multipart) + redactor.redact(xml)
                + redactor.redact(malformed) + redactor.redact(escaped);

        for (String preserved : java.util.List.of(
                multipartSecret, xmlElementSecret, xmlAttributeSecret,
                malformedSecret, escapedSecret)) {
            assertTrue(output.contains(preserved), preserved + " should be intentionally preserved");
        }
        for (String redacted : java.util.List.of(
                "control-xml-secret", "control-malformed-secret", "control-escaped-secret")) {
            assertFalse(output.contains(redacted), redacted + " must remain redacted");
        }
    }

    @Test
    void strictSafetyStillFailsClosedWhenRedactionBypassIsEnabled() {
        redactor.setExcludedFields(java.util.List.of("usr_pwd", "token", "x-private-id"));
        redactor.setExclusionsEnabled(true);
        String querySecret = "STRICT-BYPASS-QUERY-SECRET-123456789";
        String headerSecret = "STRICT-BYPASS-HEADER-SECRET-123456789";
        String bodySecret = "STRICT-BYPASS-BODY-SECRET-123456789";
        String raw = "POST /strict?token=" + querySecret + " HTTP/1.1\r\n"
                + "X-Private-ID: " + headerSecret + "\r\n"
                + "Content-Type: application/json\r\n\r\n"
                + "{\"usr_pwd\":\"" + bodySecret + "\"}";

        TrafficLoggerHttpHandler.PreparedMessage result =
                TrafficLoggerHttpHandler.prepareMessage(raw, redactor, false, true);

        for (String secret : java.util.List.of(querySecret, headerSecret, bodySecret)) {
            assertFalse(result.text().contains(secret));
            assertFalse(result.text().contains(secret.substring(0, 8)));
            assertFalse(result.text().contains(secret.substring(secret.length() - 8)));
        }
        assertTrue(result.bodyOmitted());
        assertTrue(result.text().endsWith("[OMITTED BY STRICT SAFETY MODE]"));
    }

    @Test
    void redactsCustomFieldAcrossHeaderQueryFormAndMalformedResponse() {
        redactor.setCustomSensitiveFields(java.util.List.of("usr_pwd"));
        String rawRequest = "POST /login?usr_pwd=query-secret&safe=yes HTTP/1.1\r\n"
                + "Usr-Pwd: header-secret\r\n"
                + "Content-Type: application/x-www-form-urlencoded\r\n\r\n"
                + "usr_pwd=form-secret&safe=visible";
        String malformedResponse = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
                + "{\"usr_pwd\":\"response-secret\", broken";

        String requestResult = redactor.redact(rawRequest);
        String responseResult = redactor.redact(malformedResponse);

        for (String secret : java.util.List.of(
                "query-secret", "header-secret", "form-secret", "response-secret")) {
            assertFalse((requestResult + responseResult).contains(secret), secret + " must be redacted");
        }
        assertTrue(requestResult.contains("safe=yes"));
        assertTrue(requestResult.contains("safe=visible"));
    }

    @Test
    void redactsCommonCsrfKeyAndShortExactSensitiveKeys() {
        String raw = "POST /verify HTTP/1.1\r\nContent-Type: application/json\r\n\r\n"
                + "{\"_csrf\":\"csrf-secret\",\"client_secret\":\"client-secret\","
                + "\"otp\":\"123456\",\"pin\":\"4321\",\"shipping\":\"preserve-me\"}";

        String result = redactor.redact(raw);

        for (String secret : java.util.List.of("csrf-secret", "client-secret", "123456", "4321")) {
            assertFalse(result.contains(secret), secret + " must be redacted");
        }
        assertTrue(result.contains("\"shipping\":\"preserve-me\""));
    }

    @Test
    void redactsSecretFollowingSensitiveUrlPathMarkerAndJwtSegments() {
        String resetSecret = "reset-value-ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        String raw = "GET /reset-password/" + resetSecret + "/confirm?view=full HTTP/1.1\r\n"
                + "Host: example.com\r\n\r\n";

        String result = redactor.redact(raw);
        String jwtUrl = redactor.redactUrl("https://example.com/download/" + JWT + "?safe=yes");

        assertFalse(result.contains(resetSecret));
        assertTrue(result.contains("GET /reset-password/" + SecretRedactor.REDACTED
                + "/confirm?view=full HTTP/1.1"));
        assertFalse(jwtUrl.contains(JWT));
        assertTrue(jwtUrl.contains("/download/" + SecretRedactor.REDACTED + "?safe=yes"));
    }

    @Test
    void preservesOrdinaryUrlPathSegments() {
        String raw = "GET /users/alice/profile?tab=settings HTTP/1.1\r\nHost: example.com\r\n\r\n";

        String result = redactor.redact(raw);

        assertTrue(result.contains("/users/alice/profile?tab=settings"));
    }

    @Test
    void redactsSensitiveMultipartFieldsAndPreservesSafeParts() {
        redactor.setCustomSensitiveFields(java.util.List.of("usr_pwd"));
        String boundary = "----SecretScrubBoundary";
        String body = "--" + boundary + "\r\n"
                + "Content-Disposition: form-data; name=\"username\"\r\n\r\n"
                + "alice\r\n"
                + "--" + boundary + "\r\n"
                + "Content-Disposition: form-data; name=\"usr_pwd\"\r\n\r\n"
                + "multipart-password-secret\r\n"
                + "--" + boundary + "\r\n"
                + "Content-Disposition: form-data; name=\"csrf_token\"\r\n\r\n"
                + "multipart-csrf-secret\r\n"
                + "--" + boundary + "--\r\n";
        String raw = "POST /upload HTTP/1.1\r\n"
                + "Content-Type: multipart/form-data; boundary=\"" + boundary + "\"\r\n\r\n"
                + body;

        String result = redactor.redact(raw);

        assertFalse(result.contains("multipart-password-secret"));
        assertFalse(result.contains("multipart-csrf-secret"));
        assertTrue(result.contains("name=\"username\"\r\n\r\nalice"));
        assertTrue(result.contains("name=\"usr_pwd\"\r\n\r\n" + SecretRedactor.REDACTED));
        assertTrue(result.contains("--" + boundary + "--"));
    }

    @Test
    void redactsSensitiveXmlElementsCdataAndAttributesInResponses() {
        redactor.setCustomSensitiveFields(java.util.List.of("usr_pwd"));
        String body = "<response apiKey=\"xml-attribute-secret\">"
                + "<username>alice</username>"
                + "<usr_pwd>xml-element-secret</usr_pwd>"
                + "<auth:csrf_token><![CDATA[xml-cdata-secret]]></auth:csrf_token>"
                + "<privateKey><encoded>xml-nested-secret</encoded></privateKey>"
                + "</response>";
        String raw = "HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\n\r\n" + body;

        String result = redactor.redact(raw);

        assertFalse(result.contains("xml-attribute-secret"));
        assertFalse(result.contains("xml-element-secret"));
        assertFalse(result.contains("xml-cdata-secret"));
        assertFalse(result.contains("xml-nested-secret"));
        assertTrue(result.contains("apiKey=\"" + SecretRedactor.REDACTED + "\""));
        assertTrue(result.contains("<usr_pwd>" + SecretRedactor.REDACTED + "</usr_pwd>"));
        assertTrue(result.contains("<username>alice</username>"));
        assertTrue(result.contains("<privateKey>" + SecretRedactor.REDACTED + "</privateKey>"));
    }
}
