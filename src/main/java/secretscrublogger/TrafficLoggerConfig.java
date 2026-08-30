package secretscrublogger;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Central, tweakable settings for the extension.
 * The log directory and file prefix are user-configurable at runtime via the extension's suite
 * tab (see {@link LoggerSettingsPanel}) and persisted via Montoya's {@code PersistedObject}; the
 * values here are only the fallbacks used the first time the extension runs. Max file size can
 * still be overridden with -Dsecretscrublogger.maxBytes=...
 */
final class TrafficLoggerConfig {

    private TrafficLoggerConfig() {
    }

    // Key used to persist the user-configured log directory across Burp restarts.
    static final String PERSISTED_DIRECTORY_KEY = "secretscrublogger.dir";

    // Key used to persist the user-configured file prefix across Burp restarts.
    static final String PERSISTED_PREFIX_KEY = "secretscrublogger.prefix";

    // Comma-separated custom field names that the user wants treated as sensitive.
    static final String PERSISTED_CUSTOM_FIELDS_KEY = "secretscrublogger.customFields";

    static final Path DEFAULT_LOG_DIRECTORY = Paths.get(System.getProperty("secretscrublogger.dir", "C:\\SecretScrubLogs"));

    static final String DEFAULT_FILE_PREFIX = "secretscrub";

    // Restricts prefixes to safe filename characters so they can't escape the log directory.
    static final Pattern VALID_FILE_PREFIX = Pattern.compile("[A-Za-z0-9._-]+");

    static final long MAX_FILE_SIZE_BYTES = Long.getLong("secretscrublogger.maxBytes", 1024L * 1024L);

    static final int MAX_BODY_BYTES = 100 * 1024;

    static final String TRUNCATION_MARKER = "[TRUNCATED]";

    // File extensions that are skipped even when the request is in scope.
    static final Set<String> IGNORED_EXTENSIONS = Set.of(
            ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
            ".ico", ".woff", ".woff2", ".map", ".mp4", ".pdf", ".zip"
    );
}
