package secretscrublogger;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.PersistedObject;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

/**
 * Entry point loaded by Burp Suite. Registers an HTTP handler that logs in-scope
 * traffic as JSONL, with secrets redacted, to rotating files under the configured directory,
 * and a suite tab for changing that directory at runtime.
 */
public class SecretScrubLoggerExtension implements BurpExtension {

    static final String EXTENSION_NAME = "SecretScrub Logger";

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName(EXTENSION_NAME);

        PersistedObject persistedData = loadPersistedData(api);
        Path configuredDirectory = loadConfiguredDirectory(persistedData);
        String configuredPrefix = loadConfiguredPrefix(persistedData);
        String configuredCustomFields = loadConfiguredCustomFields(persistedData);
        String configuredExcludedFields = loadConfiguredExcludedFields(persistedData);
        boolean configuredRedactionBypass = loadConfiguredRedactionBypass(persistedData);
        boolean configuredCompactMode = loadConfiguredCompactMode(persistedData);
        boolean configuredStrictMode = loadConfiguredStrictMode(persistedData);
        int configuredRetentionFiles = loadConfiguredRetentionFiles(persistedData);

        JsonlLogWriter logWriter = new JsonlLogWriter(
                api, configuredDirectory, configuredPrefix, TrafficLoggerConfig.MAX_FILE_SIZE_BYTES,
                configuredRetentionFiles);
        SecretRedactor redactor = new SecretRedactor();
        redactor.setCustomSensitiveFields(parseCustomFields(configuredCustomFields));
        redactor.setExcludedFields(parseCustomFields(configuredExcludedFields));
        redactor.setExclusionsEnabled(configuredRedactionBypass);
        TrafficLoggerHttpHandler handler = new TrafficLoggerHttpHandler(
                api, logWriter, redactor, configuredCompactMode, configuredStrictMode);

        api.http().registerHttpHandler(handler);

        LoggerSettingsPanel settingsPanel = new LoggerSettingsPanel(
                api, logWriter, redactor, handler, persistedData,
                configuredCustomFields, configuredExcludedFields, configuredRedactionBypass,
                configuredCompactMode, configuredStrictMode, configuredRetentionFiles);
        api.userInterface().registerSuiteTab(EXTENSION_NAME, settingsPanel);
        api.extension().registerUnloadingHandler(() -> {
            settingsPanel.stopHealthUpdates();
            logWriter.close();
        });

        JsonlLogWriter.WriterHealth writerHealth = logWriter.health();
        if (writerHealth.available()) {
            api.logging().logToOutput(EXTENSION_NAME + " loaded. Logging in-scope traffic to "
                    + logWriter.getDirectory());
        } else {
            api.logging().logToError(EXTENSION_NAME + " loaded, but logging is unavailable: "
                    + writerHealth.lastError());
        }
        SecretRedactor.ExclusionConfig exclusionConfig = redactor.exclusionConfig();
        if (exclusionConfig.enabled() && !exclusionConfig.fields().isEmpty()) {
            api.logging().logToError(EXTENSION_NAME + " loaded with redaction bypass enabled for "
                    + exclusionConfig.fields().size() + " configured field(s)");
        }
    }

    private PersistedObject loadPersistedData(MontoyaApi api) {
        try {
            return api.persistence().extensionData();
        } catch (RuntimeException e) {
            api.logging().logToError(EXTENSION_NAME + " could not access extension settings; using defaults for this session: " + e.getMessage());
            return null;
        }
    }

    private Path loadConfiguredDirectory(PersistedObject persistedData) {
        String saved = persistedData == null ? null : persistedData.getString(TrafficLoggerConfig.PERSISTED_DIRECTORY_KEY);
        return saved != null ? Paths.get(saved) : TrafficLoggerConfig.DEFAULT_LOG_DIRECTORY;
    }

    private String loadConfiguredPrefix(PersistedObject persistedData) {
        String saved = persistedData == null ? null : persistedData.getString(TrafficLoggerConfig.PERSISTED_PREFIX_KEY);
        return saved != null ? saved : TrafficLoggerConfig.DEFAULT_FILE_PREFIX;
    }

    private String loadConfiguredCustomFields(PersistedObject persistedData) {
        String saved = persistedData == null
                ? null
                : persistedData.getString(TrafficLoggerConfig.PERSISTED_CUSTOM_FIELDS_KEY);
        return saved == null ? "" : saved;
    }

    private String loadConfiguredExcludedFields(PersistedObject persistedData) {
        String saved = persistedData == null
                ? null
                : persistedData.getString(TrafficLoggerConfig.PERSISTED_EXCLUDED_FIELDS_KEY);
        return saved == null ? "" : saved;
    }

    private boolean loadConfiguredRedactionBypass(PersistedObject persistedData) {
        String saved = persistedData == null
                ? null
                : persistedData.getString(TrafficLoggerConfig.PERSISTED_REDACTION_BYPASS_KEY);
        return parseRedactionBypass(saved);
    }

    static boolean parseRedactionBypass(String value) {
        return value != null && Boolean.parseBoolean(value.trim());
    }

    private boolean loadConfiguredCompactMode(PersistedObject persistedData) {
        String saved = persistedData == null
                ? null
                : persistedData.getString(TrafficLoggerConfig.PERSISTED_COMPACT_MODE_KEY);
        return parseCompactMode(saved);
    }

    static boolean parseCompactMode(String value) {
        return value != null && Boolean.parseBoolean(value.trim());
    }

    private boolean loadConfiguredStrictMode(PersistedObject persistedData) {
        String saved = persistedData == null
                ? null
                : persistedData.getString(TrafficLoggerConfig.PERSISTED_STRICT_MODE_KEY);
        return parseStrictMode(saved);
    }

    static boolean parseStrictMode(String value) {
        return value != null && Boolean.parseBoolean(value.trim());
    }

    private int loadConfiguredRetentionFiles(PersistedObject persistedData) {
        String saved = persistedData == null
                ? null
                : persistedData.getString(TrafficLoggerConfig.PERSISTED_RETENTION_FILES_KEY);
        return parseRetentionFiles(saved);
    }

    static int parseRetentionFiles(String value) {
        if (value == null || value.isBlank()) {
            return TrafficLoggerConfig.DEFAULT_RETENTION_FILES;
        }
        try {
            int parsed = Integer.parseInt(value.trim());
            return parsed >= 0 && parsed <= TrafficLoggerConfig.MAX_RETENTION_FILES
                    ? parsed
                    : TrafficLoggerConfig.DEFAULT_RETENTION_FILES;
        } catch (NumberFormatException ignored) {
            return TrafficLoggerConfig.DEFAULT_RETENTION_FILES;
        }
    }

    static List<String> parseCustomFields(String value) {
        if (value == null || value.isBlank()) {
            return List.of();
        }
        return java.util.Arrays.stream(value.split("[,\\r\\n]+"))
                .map(String::trim)
                .filter(field -> !field.isEmpty())
                .distinct()
                .toList();
    }
}
