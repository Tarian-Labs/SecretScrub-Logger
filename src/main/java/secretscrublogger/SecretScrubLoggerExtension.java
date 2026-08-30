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

        JsonlLogWriter logWriter = new JsonlLogWriter(api, configuredDirectory, configuredPrefix, TrafficLoggerConfig.MAX_FILE_SIZE_BYTES);
        SecretRedactor redactor = new SecretRedactor();
        redactor.setCustomSensitiveFields(parseCustomFields(configuredCustomFields));
        TrafficLoggerHttpHandler handler = new TrafficLoggerHttpHandler(api, logWriter, redactor);

        api.http().registerHttpHandler(handler);

        LoggerSettingsPanel settingsPanel = new LoggerSettingsPanel(
                api, logWriter, redactor, persistedData, configuredCustomFields);
        api.userInterface().registerSuiteTab(EXTENSION_NAME, settingsPanel);

        api.logging().logToOutput(EXTENSION_NAME + " loaded. Logging in-scope traffic to " + logWriter.getDirectory());
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
