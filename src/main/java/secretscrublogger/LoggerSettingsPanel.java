package secretscrublogger;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.PersistedObject;

import javax.swing.Box;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JSpinner;
import javax.swing.JTextField;
import javax.swing.SpinnerNumberModel;
import javax.swing.Timer;
import java.awt.Color;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.io.File;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Suite tab that lets the user view and change the JSONL log output directory and file name
 * prefix at runtime, persisting the choices so they survive Burp restarts. Changing the prefix
 * and clicking "Start New File" begins a fresh numbered file under that prefix immediately,
 * which is handy for starting a new investigation without waiting for size-based rotation.
 */
final class LoggerSettingsPanel extends JPanel {

    private final MontoyaApi api;
    private final JsonlLogWriter logWriter;
    private final SecretRedactor redactor;
    private final TrafficLoggerHttpHandler handler;
    private final PersistedObject persistedData;
    private final JTextField directoryField;
    private final JTextField prefixField;
    private final JTextField customFieldsField;
    private final JTextField excludedFieldsField;
    private final JCheckBox redactionBypassCheckBox;
    private final JCheckBox compactModeCheckBox;
    private final JCheckBox strictModeCheckBox;
    private final JSpinner retentionFilesSpinner;
    private final JLabel writerHealthLabel;
    private final JLabel redactionSelfTestLabel;
    private final JLabel statusLabel;
    private final Timer healthTimer;

    LoggerSettingsPanel(MontoyaApi api, JsonlLogWriter logWriter, SecretRedactor redactor,
                        TrafficLoggerHttpHandler handler, PersistedObject persistedData,
                        String configuredCustomFields, String configuredExcludedFields,
                        boolean configuredRedactionBypass, boolean configuredCompactMode,
                        boolean configuredStrictMode, int configuredRetentionFiles) {
        super(new GridBagLayout());
        this.api = api;
        this.logWriter = logWriter;
        this.redactor = redactor;
        this.handler = handler;
        this.persistedData = persistedData;

        directoryField = new JTextField(logWriter.getDirectory().toString(), 40);
        JButton browseButton = new JButton("Browse...");
        JButton applyDirectoryButton = new JButton("Apply Directory");
        prefixField = new JTextField(logWriter.getFilePrefix(), 20);
        JButton startNewFileButton = new JButton("Start New File");
        customFieldsField = new JTextField(configuredCustomFields, 40);
        JButton applyCustomFieldsButton = new JButton("Apply Custom Fields");
        excludedFieldsField = new JTextField(configuredExcludedFields, 40);
        JButton applyExcludedFieldsButton = new JButton("Apply Exclusions");
        redactionBypassCheckBox = new JCheckBox(
                "Enable redaction bypass for excluded fields", configuredRedactionBypass);
        compactModeCheckBox = new JCheckBox("Enable AI Compact Mode", configuredCompactMode);
        strictModeCheckBox = new JCheckBox("Enable Strict Safety Mode", configuredStrictMode);
        retentionFilesSpinner = new JSpinner(new SpinnerNumberModel(
                configuredRetentionFiles, 0, TrafficLoggerConfig.MAX_RETENTION_FILES, 1));
        JButton applyRetentionButton = new JButton("Apply Retention");
        writerHealthLabel = new JLabel(" ");
        JButton retryWriterButton = new JButton("Retry Writer");
        JButton refreshHealthButton = new JButton("Refresh Health");
        redactionSelfTestLabel = new JLabel("Not run for this extension session.");
        JButton runRedactionSelfTestButton = new JButton("Run Redaction Self-Test");
        JLabel bypassWarningLabel = new JLabel(
                "Warning: matching values may be written to disk in plaintext. Strict Safety Mode still fails closed.");
        bypassWarningLabel.setForeground(new Color(180, 80, 0));
        statusLabel = new JLabel(" ");

        browseButton.addActionListener(e -> browseForDirectory());
        applyDirectoryButton.addActionListener(e -> applyDirectory());
        startNewFileButton.addActionListener(e -> startNewFile());
        applyCustomFieldsButton.addActionListener(e -> applyCustomFields());
        applyExcludedFieldsButton.addActionListener(e -> applyExcludedFields());
        redactionBypassCheckBox.addActionListener(e -> applyRedactionBypass());
        compactModeCheckBox.addActionListener(e -> applyCompactMode());
        strictModeCheckBox.addActionListener(e -> applyStrictMode());
        applyRetentionButton.addActionListener(e -> applyRetention());
        retryWriterButton.addActionListener(e -> retryWriter());
        refreshHealthButton.addActionListener(e -> refreshWriterHealth());
        runRedactionSelfTestButton.addActionListener(e -> runRedactionSelfTest());

        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(8, 8, 4, 8);
        c.anchor = GridBagConstraints.WEST;

        c.gridx = 0;
        c.gridy = 0;
        add(new JLabel("Log output directory:"), c);

        c.gridx = 1;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.weightx = 1;
        add(directoryField, c);

        c.gridx = 2;
        c.fill = GridBagConstraints.NONE;
        c.weightx = 0;
        add(browseButton, c);

        c.gridx = 1;
        c.gridy = 1;
        add(applyDirectoryButton, c);

        c.gridx = 0;
        c.gridy = 2;
        add(new JLabel("Log file name prefix:"), c);

        c.gridx = 1;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.weightx = 1;
        add(prefixField, c);

        c.gridx = 1;
        c.gridy = 3;
        c.fill = GridBagConstraints.NONE;
        c.weightx = 0;
        add(startNewFileButton, c);

        c.gridx = 0;
        c.gridy = 4;
        add(new JLabel("Custom sensitive fields:"), c);

        c.gridx = 1;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.weightx = 1;
        add(customFieldsField, c);

        c.gridx = 2;
        c.fill = GridBagConstraints.NONE;
        c.weightx = 0;
        add(applyCustomFieldsButton, c);

        c.gridx = 1;
        c.gridy = 5;
        add(new JLabel("Comma-separated, e.g. usr_pwd, privateNote"), c);

        c.gridx = 0;
        c.gridy = 6;
        add(new JLabel("Fields excluded from redaction:"), c);

        c.gridx = 1;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.weightx = 1;
        add(excludedFieldsField, c);

        c.gridx = 2;
        c.fill = GridBagConstraints.NONE;
        c.weightx = 0;
        add(applyExcludedFieldsButton, c);

        c.gridx = 1;
        c.gridy = 7;
        c.gridwidth = 2;
        add(new JLabel("Comma-separated exact field names. Exclusions apply only when bypass is enabled."), c);

        c.gridx = 0;
        c.gridy = 8;
        c.gridwidth = 1;
        add(new JLabel("Redaction bypass:"), c);

        c.gridx = 1;
        c.gridwidth = 2;
        add(redactionBypassCheckBox, c);

        c.gridy = 9;
        add(bypassWarningLabel, c);

        c.gridx = 0;
        c.gridy = 10;
        c.gridwidth = 1;
        add(new JLabel("AI output:"), c);

        c.gridx = 1;
        add(compactModeCheckBox, c);

        c.gridy = 11;
        add(new JLabel("Keeps security context while reducing noisy headers and large bodies."), c);

        c.gridx = 0;
        c.gridy = 12;
        add(new JLabel("Maximum safety:"), c);

        c.gridx = 1;
        add(strictModeCheckBox, c);

        c.gridy = 13;
        add(new JLabel("Omits bodies and redacts query values, identifiers and unknown headers."), c);

        c.gridx = 0;
        c.gridy = 14;
        add(new JLabel("Maximum log files:"), c);

        c.gridx = 1;
        add(retentionFilesSpinner, c);

        c.gridx = 2;
        add(applyRetentionButton, c);

        c.gridx = 1;
        c.gridy = 15;
        c.gridwidth = 2;
        add(new JLabel("Maximum number of log files per filename prefix. 0 means no limit; "
                + "1 keeps one log file (1 MB by default); 2 keeps two."), c);

        c.gridx = 1;
        c.gridy = 16;
        c.gridwidth = 2;
        add(new JLabel("Once the limit is exceeded, the oldest matching log file is deleted."), c);

        c.gridwidth = 1;

        c.gridx = 0;
        c.gridy = 17;
        add(new JLabel("Writer health:"), c);

        c.gridx = 1;
        c.gridwidth = 2;
        add(writerHealthLabel, c);

        c.gridy = 18;
        c.gridwidth = 1;
        add(refreshHealthButton, c);

        c.gridx = 2;
        add(retryWriterButton, c);

        c.gridx = 0;
        c.gridy = 19;
        add(new JLabel("Redaction self-test:"), c);

        c.gridx = 1;
        c.gridwidth = 2;
        add(redactionSelfTestLabel, c);

        c.gridy = 20;
        c.gridwidth = 1;
        add(runRedactionSelfTestButton, c);

        c.gridx = 2;
        add(new JLabel("Runs locally in memory; sends and writes nothing."), c);

        c.gridx = 1;
        c.gridy = 21;
        c.gridwidth = 2;
        add(statusLabel, c);

        c.gridx = 0;
        c.gridy = 22;
        c.gridwidth = 3;
        c.weighty = 1;
        add(Box.createGlue(), c);

        refreshWriterHealth();
        healthTimer = new Timer(2_000, e -> refreshWriterHealth());
        healthTimer.start();
    }

    void stopHealthUpdates() {
        healthTimer.stop();
    }

    private void applyRetention() {
        int limit = ((Number) retentionFilesSpinner.getValue()).intValue();
        try {
            logWriter.setRetentionFileLimit(limit);
            if (persistedData != null) {
                persistedData.setString(
                        TrafficLoggerConfig.PERSISTED_RETENTION_FILES_KEY,
                        Integer.toString(limit));
            }
            showStatus(limit == 0
                    ? "Automatic retention disabled; all rotations will be kept."
                    : "Retention applied: keeping the newest " + limit + " file(s) per prefix.",
                    false);
            api.logging().logToOutput(SecretScrubLoggerExtension.EXTENSION_NAME
                    + " retention set to " + (limit == 0 ? "unlimited" : limit + " file(s) per prefix"));
            refreshWriterHealth();
        } catch (RuntimeException e) {
            showStatus("Failed to apply retention: " + e.getMessage(), true);
            api.logging().logToError(SecretScrubLoggerExtension.EXTENSION_NAME
                    + " failed to apply retention: " + e.getMessage());
        }
    }

    private void retryWriter() {
        boolean recovered = logWriter.retry();
        refreshWriterHealth();
        showStatus(recovered
                ? "Writer reopened successfully."
                : "Writer is still unavailable; see Burp's extension errors.",
                !recovered);
    }

    private void refreshWriterHealth() {
        JsonlLogWriter.WriterHealth health = logWriter.health();
        if (health.available() && health.lastError() == null) {
            writerHealthLabel.setForeground(new Color(0, 128, 0));
            String fileName = health.currentFile() == null
                    ? "no file"
                    : health.currentFile().getFileName().toString();
            writerHealthLabel.setText("Healthy — " + fileName
                    + " — " + health.currentFileSize() + " bytes — "
                    + health.successfulWrites() + " writes");
        } else if (health.available()) {
            writerHealthLabel.setForeground(new Color(180, 110, 0));
            writerHealthLabel.setText("Degraded — writing continues — " + health.lastError());
        } else {
            writerHealthLabel.setForeground(Color.RED);
            String error = health.lastError() == null ? "unknown error" : health.lastError();
            writerHealthLabel.setText("Unavailable — " + error);
        }
        writerHealthLabel.setToolTipText(health.lastError());
    }

    private void runRedactionSelfTest() {
        RedactionSelfTest.Result result = RedactionSelfTest.run(redactor);
        if (result.passed()) {
            redactionSelfTestLabel.setForeground(result.bypassEnabled()
                    ? new Color(180, 80, 0)
                    : new Color(0, 128, 0));
            String bypassSummary = result.bypassEnabled()
                    ? " — bypass active for " + result.excludedFieldsChecked() + " field(s)"
                    : "";
            redactionSelfTestLabel.setText("PASS — " + result.checks() + " checks — "
                    + result.customFieldsChecked() + " custom field(s)" + bypassSummary);
            redactionSelfTestLabel.setToolTipText(result.bypassEnabled()
                    ? "Baseline redaction passed and configured exclusions preserved their synthetic canaries."
                    : "All synthetic canaries and their tested prefixes/suffixes were absent.");
            api.logging().logToOutput(SecretScrubLoggerExtension.EXTENSION_NAME
                    + " redaction self-test passed (" + result.checks() + " checks, "
                    + result.customFieldsChecked() + " custom field(s), "
                    + result.excludedFieldsChecked() + " active exclusion(s))");
        } else {
            String failures = String.join(", ", result.failures());
            redactionSelfTestLabel.setForeground(Color.RED);
            redactionSelfTestLabel.setText("FAIL — " + result.failures().size()
                    + " of " + result.checks() + " checks failed; see tooltip/output");
            redactionSelfTestLabel.setToolTipText(failures);
            api.logging().logToError(SecretScrubLoggerExtension.EXTENSION_NAME
                    + " redaction self-test failed: " + failures);
        }
    }

    private void resetRedactionSelfTestStatus() {
        redactionSelfTestLabel.setForeground(Color.DARK_GRAY);
        redactionSelfTestLabel.setText("Not run since redaction configuration changed.");
        redactionSelfTestLabel.setToolTipText(null);
    }

    private void applyExcludedFields() {
        String value = excludedFieldsField.getText().trim();
        try {
            java.util.List<String> fields = SecretScrubLoggerExtension.parseCustomFields(value);
            redactor.setExcludedFields(fields);
            String persistedValue = String.join(", ", fields);
            if (persistedData != null) {
                persistedData.setString(
                        TrafficLoggerConfig.PERSISTED_EXCLUDED_FIELDS_KEY, persistedValue);
            }
            excludedFieldsField.setText(persistedValue);
            resetRedactionSelfTestStatus();
            boolean enabled = redactionBypassCheckBox.isSelected();
            showStatus("Applied " + fields.size() + " redaction exclusion(s); bypass is "
                    + (enabled ? "enabled." : "disabled."), enabled);
            api.logging().logToOutput(SecretScrubLoggerExtension.EXTENSION_NAME
                    + " updated redaction exclusions (" + fields.size() + ", bypass "
                    + (enabled ? "enabled" : "disabled") + ")");
        } catch (RuntimeException e) {
            showStatus("Failed to apply exclusions: " + e.getMessage(), true);
            api.logging().logToError(SecretScrubLoggerExtension.EXTENSION_NAME
                    + " failed to update redaction exclusions: " + e.getMessage());
        }
    }

    private void applyRedactionBypass() {
        boolean enabled = redactionBypassCheckBox.isSelected();
        try {
            redactor.setExclusionsEnabled(enabled);
            if (persistedData != null) {
                persistedData.setString(
                        TrafficLoggerConfig.PERSISTED_REDACTION_BYPASS_KEY,
                        Boolean.toString(enabled));
            }
            resetRedactionSelfTestStatus();
            showStatus(enabled
                    ? "WARNING: redaction bypass enabled for configured exclusions."
                    : "Redaction bypass disabled; exclusions are not active.",
                    enabled);
            if (enabled) {
                api.logging().logToError(SecretScrubLoggerExtension.EXTENSION_NAME
                        + " redaction bypass enabled for configured exclusions");
            } else {
                api.logging().logToOutput(SecretScrubLoggerExtension.EXTENSION_NAME
                        + " redaction bypass disabled");
            }
        } catch (RuntimeException e) {
            showStatus("Failed to update redaction bypass: " + e.getMessage(), true);
            api.logging().logToError(SecretScrubLoggerExtension.EXTENSION_NAME
                    + " failed to update redaction bypass: " + e.getMessage());
        }
    }

    private void applyStrictMode() {
        boolean enabled = strictModeCheckBox.isSelected();
        try {
            handler.setStrictMode(enabled);
            if (persistedData != null) {
                persistedData.setString(
                        TrafficLoggerConfig.PERSISTED_STRICT_MODE_KEY,
                        Boolean.toString(enabled));
            }
            showStatus("Strict Safety Mode " + (enabled ? "enabled." : "disabled."), false);
            api.logging().logToOutput(SecretScrubLoggerExtension.EXTENSION_NAME
                    + " Strict Safety Mode " + (enabled ? "enabled" : "disabled"));
        } catch (RuntimeException e) {
            showStatus("Failed to update Strict Safety Mode: " + e.getMessage(), true);
            api.logging().logToError(SecretScrubLoggerExtension.EXTENSION_NAME
                    + " failed to update Strict Safety Mode: " + e.getMessage());
        }
    }

    private void applyCompactMode() {
        boolean enabled = compactModeCheckBox.isSelected();
        try {
            handler.setCompactMode(enabled);
            if (persistedData != null) {
                persistedData.setString(
                        TrafficLoggerConfig.PERSISTED_COMPACT_MODE_KEY,
                        Boolean.toString(enabled));
            }
            showStatus("AI Compact Mode " + (enabled ? "enabled." : "disabled."), false);
            api.logging().logToOutput(SecretScrubLoggerExtension.EXTENSION_NAME
                    + " AI Compact Mode " + (enabled ? "enabled" : "disabled"));
        } catch (RuntimeException e) {
            showStatus("Failed to update AI Compact Mode: " + e.getMessage(), true);
            api.logging().logToError(SecretScrubLoggerExtension.EXTENSION_NAME
                    + " failed to update AI Compact Mode: " + e.getMessage());
        }
    }

    private void applyCustomFields() {
        String value = customFieldsField.getText().trim();
        try {
            java.util.List<String> fields = SecretScrubLoggerExtension.parseCustomFields(value);
            redactor.setCustomSensitiveFields(fields);
            String persistedValue = String.join(", ", fields);
            if (persistedData != null) {
                persistedData.setString(TrafficLoggerConfig.PERSISTED_CUSTOM_FIELDS_KEY, persistedValue);
            }
            customFieldsField.setText(persistedValue);
            resetRedactionSelfTestStatus();
            showStatus("Applied " + fields.size() + " custom sensitive field(s).", false);
            api.logging().logToOutput(SecretScrubLoggerExtension.EXTENSION_NAME
                    + " updated custom sensitive fields (" + fields.size() + ")");
        } catch (RuntimeException e) {
            showStatus("Failed to apply custom fields: " + e.getMessage(), true);
            api.logging().logToError(SecretScrubLoggerExtension.EXTENSION_NAME
                    + " failed to update custom sensitive fields: " + e.getMessage());
        }
    }

    private void browseForDirectory() {
        JFileChooser chooser = new JFileChooser(currentFieldDirectoryOrFallback());
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        chooser.setDialogTitle("Select log output directory");
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            directoryField.setText(chooser.getSelectedFile().getAbsolutePath());
        }
    }

    private File currentFieldDirectoryOrFallback() {
        try {
            return Paths.get(directoryField.getText().trim()).toFile();
        } catch (InvalidPathException e) {
            return logWriter.getDirectory().toFile();
        }
    }

    private void applyDirectory() {
        String text = directoryField.getText().trim();
        if (text.isEmpty()) {
            showStatus("Directory cannot be empty.", true);
            return;
        }
        try {
            Path newDirectory = Paths.get(text);
            logWriter.setDirectory(newDirectory);
            requireAvailableWriter();
            if (persistedData != null) {
                persistedData.setString(TrafficLoggerConfig.PERSISTED_DIRECTORY_KEY, newDirectory.toString());
            }
            directoryField.setText(newDirectory.toString());
            showStatus("Now logging to: " + newDirectory, false);
            api.logging().logToOutput(SecretScrubLoggerExtension.EXTENSION_NAME + " log directory changed to " + newDirectory);
            refreshWriterHealth();
        } catch (RuntimeException e) {
            showStatus("Failed to change directory: " + e.getMessage(), true);
            api.logging().logToError(SecretScrubLoggerExtension.EXTENSION_NAME + " failed to change log directory: " + e.getMessage());
        }
    }

    private void startNewFile() {
        String prefix = prefixField.getText().trim();
        if (prefix.isEmpty()) {
            showStatus("File prefix cannot be empty.", true);
            return;
        }
        if (!TrafficLoggerConfig.VALID_FILE_PREFIX.matcher(prefix).matches()) {
            showStatus("File prefix can only contain letters, digits, '.', '_' and '-'.", true);
            return;
        }
        try {
            logWriter.startNewFile(prefix);
            requireAvailableWriter();
            if (persistedData != null) {
                persistedData.setString(TrafficLoggerConfig.PERSISTED_PREFIX_KEY, prefix);
            }
            prefixField.setText(prefix);
            showStatus("Started new file: " + logWriter.getDirectory().resolve(prefix + "-####.jsonl"), false);
            api.logging().logToOutput(SecretScrubLoggerExtension.EXTENSION_NAME + " started a new log file with prefix \"" + prefix + "\"");
            refreshWriterHealth();
        } catch (RuntimeException e) {
            showStatus("Failed to start new file: " + e.getMessage(), true);
            api.logging().logToError(SecretScrubLoggerExtension.EXTENSION_NAME + " failed to start new log file: " + e.getMessage());
        }
    }

    private void showStatus(String message, boolean isError) {
        statusLabel.setForeground(isError ? Color.RED : new Color(0, 128, 0));
        statusLabel.setText(message);
    }

    private void requireAvailableWriter() {
        JsonlLogWriter.WriterHealth health = logWriter.health();
        if (!health.available()) {
            throw new IllegalStateException(health.lastError() == null
                    ? "writer is unavailable"
                    : health.lastError());
        }
    }
}
