package secretscrublogger;

import burp.api.montoya.MontoyaApi;

import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Writes one JSON object per line to <prefix>-NNNN.jsonl, rotating to a new plain-text file once
 * the current one reaches the configured size limit.
 */
final class JsonlLogWriter {

    private final MontoyaApi api;
    private final long maxFileSizeBytes;
    private final Object lock = new Object();

    private Path directory;
    private String filePrefix;
    private int currentIndex;
    private Path currentFile;
    private long currentFileSize;
    private Writer currentWriter;

    JsonlLogWriter(MontoyaApi api, Path directory, String filePrefix, long maxFileSizeBytes) {
        this.api = api;
        this.maxFileSizeBytes = maxFileSizeBytes;
        this.filePrefix = filePrefix;
        initializeForDirectory(directory);
    }

    Path getDirectory() {
        synchronized (lock) {
            return directory;
        }
    }

    String getFilePrefix() {
        synchronized (lock) {
            return filePrefix;
        }
    }

    /** Switches logging to a new directory, closing the current file and resuming rotation there. */
    void setDirectory(Path newDirectory) {
        synchronized (lock) {
            closeCurrentWriter();
            initializeForDirectory(newDirectory);
        }
    }

    /**
     * Adopts a new file prefix and immediately starts a fresh file under it (e.g. index 0001 the
     * first time that prefix is used in this directory), regardless of the current file's size.
     */
    void startNewFile(String newPrefix) {
        synchronized (lock) {
            closeCurrentWriter();
            this.filePrefix = newPrefix;
            int highest = findHighestExistingIndex();
            openFileForIndex(highest + 1);
        }
    }

    private void initializeForDirectory(Path newDirectory) {
        this.directory = newDirectory;

        try {
            Files.createDirectories(directory);
        } catch (IOException e) {
            api.logging().logToError(SecretScrubLoggerExtension.EXTENSION_NAME + " could not create log directory " + directory + ": " + e.getMessage());
        }

        int highest = findHighestExistingIndex();
        int startIndex = highest == 0 ? 1 : highest;
        openFileForIndex(startIndex);
        if (currentFileSize >= maxFileSizeBytes) {
            closeCurrentWriter();
            openFileForIndex(startIndex + 1);
        }
    }

    void write(String jsonLine) {
        synchronized (lock) {
            byte[] lineBytes = (jsonLine + System.lineSeparator()).getBytes(StandardCharsets.UTF_8);
            if (currentFileSize > 0 && currentFileSize + lineBytes.length > maxFileSizeBytes) {
                rotate();
            }
            try {
                currentWriter.write(jsonLine);
                currentWriter.write(System.lineSeparator());
                currentWriter.flush();
                currentFileSize += lineBytes.length;
            } catch (IOException e) {
                api.logging().logToError(SecretScrubLoggerExtension.EXTENSION_NAME + " failed to write log entry: " + e.getMessage());
            }
        }
    }

    private void rotate() {
        closeCurrentWriter();
        openFileForIndex(currentIndex + 1);
    }

    private void openFileForIndex(int index) {
        currentIndex = index;
        currentFile = directory.resolve(String.format("%s-%04d.jsonl", filePrefix, index));
        currentFileSize = fileSizeOrZero(currentFile);
        try {
            currentWriter = new BufferedWriter(new OutputStreamWriter(
                    new FileOutputStream(currentFile.toFile(), true), StandardCharsets.UTF_8));
        } catch (IOException e) {
            api.logging().logToError(SecretScrubLoggerExtension.EXTENSION_NAME + " could not open log file " + currentFile + ": " + e.getMessage());
        }
    }

    private void closeCurrentWriter() {
        if (currentWriter != null) {
            try {
                currentWriter.flush();
                currentWriter.close();
            } catch (IOException e) {
                api.logging().logToError(SecretScrubLoggerExtension.EXTENSION_NAME + " failed to close log file: " + e.getMessage());
            }
        }
    }

    private long fileSizeOrZero(Path path) {
        try {
            return Files.exists(path) ? Files.size(path) : 0L;
        } catch (IOException e) {
            return 0L;
        }
    }

    private int findHighestExistingIndex() {
        if (!Files.isDirectory(directory)) {
            return 0;
        }
        // Matches .gz too so old compressed files from previous versions don't throw off index detection.
        Pattern fileNamePattern = Pattern.compile(Pattern.quote(filePrefix) + "-(\\d{4})\\.jsonl(?:\\.gz)?");
        int highest = 0;
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(directory, filePrefix + "-*.jsonl*")) {
            for (Path path : stream) {
                Matcher matcher = fileNamePattern.matcher(path.getFileName().toString());
                if (matcher.matches()) {
                    highest = Math.max(highest, Integer.parseInt(matcher.group(1)));
                }
            }
        } catch (IOException e) {
            api.logging().logToError(SecretScrubLoggerExtension.EXTENSION_NAME + " failed to scan log directory: " + e.getMessage());
        }
        return highest;
    }
}
