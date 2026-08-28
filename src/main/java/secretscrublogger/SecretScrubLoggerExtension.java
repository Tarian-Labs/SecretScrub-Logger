package secretscrublogger;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.PersistedObject;

import java.nio.file.Path;
import java.nio.file.Paths;

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

        PersistedObject persistedData = api.persistence().extensionData();
        Path configuredDirectory = loadConfiguredDirectory(persistedData);
        String configuredPrefix = loadConfiguredPrefix(persistedData);

        JsonlLogWriter logWriter = new JsonlLogWriter(api, configuredDirectory, configuredPrefix, TrafficLoggerConfig.MAX_FILE_SIZE_BYTES);
        SecretRedactor redactor = new SecretRedactor();
        TrafficLoggerHttpHandler handler = new TrafficLoggerHttpHandler(api, logWriter, redactor);

        api.http().registerHttpHandler(handler);

        LoggerSettingsPanel settingsPanel = new LoggerSettingsPanel(api, logWriter, persistedData);
        api.userInterface().registerSuiteTab(EXTENSION_NAME, settingsPanel);

        api.logging().logToOutput(EXTENSION_NAME + " loaded. Logging in-scope traffic to " + logWriter.getDirectory());
    }

    private Path loadConfiguredDirectory(PersistedObject persistedData) {
        String saved = persistedData.getString(TrafficLoggerConfig.PERSISTED_DIRECTORY_KEY);
        return saved != null ? Paths.get(saved) : TrafficLoggerConfig.DEFAULT_LOG_DIRECTORY;
    }

    private String loadConfiguredPrefix(PersistedObject persistedData) {
        String saved = persistedData.getString(TrafficLoggerConfig.PERSISTED_PREFIX_KEY);
        return saved != null ? saved : TrafficLoggerConfig.DEFAULT_FILE_PREFIX;
    }
}
