package secretscrublogger;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Locale;

/**
 * Observes completed HTTP transactions and logs the in-scope, non-static-asset ones.
 */
final class TrafficLoggerHttpHandler implements HttpHandler {

    private final MontoyaApi api;
    private final JsonlLogWriter logWriter;
    private final SecretRedactor redactor;

    TrafficLoggerHttpHandler(MontoyaApi api, JsonlLogWriter logWriter, SecretRedactor redactor) {
        this.api = api;
        this.logWriter = logWriter;
        this.redactor = redactor;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        try {
            logIfApplicable(responseReceived);
        } catch (RuntimeException e) {
            api.logging().logToError(SecretScrubLoggerExtension.EXTENSION_NAME + " failed to log a transaction: " + e.getMessage());
        }
        return ResponseReceivedAction.continueWith(responseReceived);
    }

    private void logIfApplicable(HttpResponseReceived responseReceived) {
        HttpRequest request = responseReceived.initiatingRequest();
        String url = request.url();

        if (!api.scope().isInScope(url)) {
            return;
        }
        if (isIgnoredResource(request.path())) {
            return;
        }

        String requestText = truncate(redactor.redact(request.toString()));
        String responseText = truncate(redactor.redact(responseReceived.toString()));
        String redactedUrl = redactor.redactUrl(url);

        String json = TrafficJson.build(
                Instant.now().toString(),
                request.method(),
                redactedUrl,
                responseReceived.statusCode(),
                requestText,
                responseText
        );

        logWriter.write(json);
    }

    private boolean isIgnoredResource(String path) {
        if (path == null) {
            return false;
        }
        String lowerPath = path.toLowerCase(Locale.ROOT);
        int queryIndex = lowerPath.indexOf('?');
        String pathOnly = queryIndex >= 0 ? lowerPath.substring(0, queryIndex) : lowerPath;
        for (String extension : TrafficLoggerConfig.IGNORED_EXTENSIONS) {
            if (pathOnly.endsWith(extension)) {
                return true;
            }
        }
        return false;
    }

    private String truncate(String text) {
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        if (bytes.length <= TrafficLoggerConfig.MAX_BODY_BYTES) {
            return text;
        }
        String truncated = new String(bytes, 0, TrafficLoggerConfig.MAX_BODY_BYTES, StandardCharsets.UTF_8);
        return truncated + TrafficLoggerConfig.TRUNCATION_MARKER;
    }
}
