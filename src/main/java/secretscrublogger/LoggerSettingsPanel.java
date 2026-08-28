package secretscrublogger;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.PersistedObject;

import javax.swing.Box;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
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
    private final PersistedObject persistedData;
    private final JTextField directoryField;
    private final JTextField prefixField;
    private final JLabel statusLabel;

    LoggerSettingsPanel(MontoyaApi api, JsonlLogWriter logWriter, PersistedObject persistedData) {
        super(new GridBagLayout());
        this.api = api;
        this.logWriter = logWriter;
        this.persistedData = persistedData;

        directoryField = new JTextField(logWriter.getDirectory().toString(), 40);
        JButton browseButton = new JButton("Browse...");
        JButton applyDirectoryButton = new JButton("Apply Directory");
        prefixField = new JTextField(logWriter.getFilePrefix(), 20);
        JButton startNewFileButton = new JButton("Start New File");
        statusLabel = new JLabel(" ");

        browseButton.addActionListener(e -> browseForDirectory());
        applyDirectoryButton.addActionListener(e -> applyDirectory());
        startNewFileButton.addActionListener(e -> startNewFile());

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

        c.gridx = 1;
        c.gridy = 4;
        add(statusLabel, c);

        c.gridx = 0;
        c.gridy = 5;
        c.gridwidth = 3;
        c.weighty = 1;
        add(Box.createGlue(), c);
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
            if (persistedData != null) {
                persistedData.setString(TrafficLoggerConfig.PERSISTED_DIRECTORY_KEY, newDirectory.toString());
            }
            directoryField.setText(newDirectory.toString());
            showStatus("Now logging to: " + newDirectory, false);
            api.logging().logToOutput(SecretScrubLoggerExtension.EXTENSION_NAME + " log directory changed to " + newDirectory);
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
            if (persistedData != null) {
                persistedData.setString(TrafficLoggerConfig.PERSISTED_PREFIX_KEY, prefix);
            }
            prefixField.setText(prefix);
            showStatus("Started new file: " + logWriter.getDirectory().resolve(prefix + "-####.jsonl"), false);
            api.logging().logToOutput(SecretScrubLoggerExtension.EXTENSION_NAME + " started a new log file with prefix \"" + prefix + "\"");
        } catch (RuntimeException e) {
            showStatus("Failed to start new file: " + e.getMessage(), true);
            api.logging().logToError(SecretScrubLoggerExtension.EXTENSION_NAME + " failed to start new log file: " + e.getMessage());
        }
    }

    private void showStatus(String message, boolean isError) {
        statusLabel.setForeground(isError ? Color.RED : new Color(0, 128, 0));
        statusLabel.setText(message);
    }
}
