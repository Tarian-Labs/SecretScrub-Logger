package secretscrublogger;

import org.junit.jupiter.api.Test;

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
    void neverLeaksPartialTokenPrefixOrSuffix() {
        String secret = "test-token-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        String body = "{\"apiKey\":\"" + secret + "\"}";
        String raw = "POST /pay HTTP/1.1\r\nContent-Type: application/json\r\n\r\n" + body;

        String result = redactor.redact(raw);

        assertFalse(result.contains(secret));
        assertFalse(result.contains(secret.substring(0, 8)), "no prefix leakage");
        assertFalse(result.contains(secret.substring(secret.length() - 8)), "no suffix leakage");
    }
}
