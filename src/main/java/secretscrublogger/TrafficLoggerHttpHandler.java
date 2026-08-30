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
    private volatile boolean compactMode;
    private volatile boolean strictMode;

    TrafficLoggerHttpHandler(MontoyaApi api, JsonlLogWriter logWriter, SecretRedactor redactor,
                             boolean compactMode, boolean strictMode) {
        this.api = api;
        this.logWriter = logWriter;
        this.redactor = redactor;
        this.compactMode = compactMode;
        this.strictMode = strictMode;
    }

    void setCompactMode(boolean compactMode) {
        this.compactMode = compactMode;
    }

    void setStrictMode(boolean strictMode) {
        this.strictMode = strictMode;
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

        SecretRedactor.ExclusionConfig exclusionConfig = redactor.exclusionConfig();
        SecretRedactor.RedactionResult redactedUrl = redactor.redactUrlWithMetadata(url);
        boolean compactCapture = compactMode;
        boolean strictCapture = strictMode;
        PreparedMessage requestText = prepareMessage(
                request.toString(), redactor, compactCapture, strictCapture);
        PreparedMessage responseText = prepareMessage(
                responseReceived.toString(), redactor, compactCapture, strictCapture);
        String loggedUrl = redactedUrl.text();
        int urlRedactions = redactedUrl.redactionCount();
        if (strictCapture) {
            StrictSafetySanitizer.UrlResult strictUrl =
                    StrictSafetySanitizer.sanitizeUrl(loggedUrl);
            loggedUrl = strictUrl.text();
            urlRedactions += strictUrl.redactionCount();
        }

        TrafficJson.SafetyMetadata metadata = new TrafficJson.SafetyMetadata(
                urlRedactions,
                requestText.redactionCount(),
                responseText.redactionCount(),
                requestText.truncated(),
                responseText.truncated(),
                compactCapture,
                strictCapture,
                requestText.bodyOmitted(),
                responseText.bodyOmitted(),
                exclusionConfig.enabled(),
                exclusionConfig.fields().size()
        );

        String json = TrafficJson.build(
                Instant.now().toString(),
                request.method(),
                loggedUrl,
                responseReceived.statusCode(),
                requestText.text(),
                responseText.text(),
                metadata
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

    static TruncationResult truncate(String text) {
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        if (bytes.length <= TrafficLoggerConfig.MAX_BODY_BYTES) {
            return new TruncationResult(text, false);
        }
        String truncated = new String(bytes, 0, TrafficLoggerConfig.MAX_BODY_BYTES, StandardCharsets.UTF_8);
        return new TruncationResult(truncated + TrafficLoggerConfig.TRUNCATION_MARKER, true);
    }

    record TruncationResult(String text, boolean truncated) {
    }

    static PreparedMessage prepareMessage(String rawMessage, SecretRedactor redactor,
                                          boolean compactCapture, boolean strictCapture) {
        boolean bodyOmittedBeforeRedaction = false;
        if (strictCapture) {
            StrictSafetySanitizer.BodyOmissionResult omission =
                    StrictSafetySanitizer.omitBody(rawMessage);
            rawMessage = omission.text();
            bodyOmittedBeforeRedaction = omission.bodyOmitted();
        }

        SecretRedactor.RedactionResult redacted = redactor.redactWithMetadata(rawMessage);
        String text = redacted.text();
        boolean compactTruncated = false;
        if (compactCapture) {
            HttpMessageCompactor.CompactResult compacted = HttpMessageCompactor.compact(text);
            text = compacted.text();
            compactTruncated = compacted.bodyTruncated();
        }
        int redactionCount = redacted.redactionCount();
        boolean bodyOmitted = false;
        if (strictCapture) {
            StrictSafetySanitizer.MessageResult strict =
                    StrictSafetySanitizer.sanitizeMessage(text);
            text = strict.text();
            redactionCount += strict.redactionCount();
            bodyOmitted = bodyOmittedBeforeRedaction || strict.bodyOmitted();
            if (bodyOmitted) {
                compactTruncated = false;
            }
        }
        TruncationResult capped = truncate(text);
        return new PreparedMessage(
                capped.text(), compactTruncated || capped.truncated(),
                redactionCount, bodyOmitted);
    }

    record PreparedMessage(String text, boolean truncated, int redactionCount,
                           boolean bodyOmitted) {
    }
}
