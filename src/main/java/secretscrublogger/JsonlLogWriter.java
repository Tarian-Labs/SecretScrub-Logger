package secretscrublogger;

import burp.api.montoya.MontoyaApi;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.channels.Channels;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Writes one JSON object per line to {@code <prefix>-NNNN.jsonl}, rotating to a new plain-text file
 * once the current one reaches the configured size limit. On POSIX systems, log directories and
 * files are restricted to the current user. An optional per-prefix retention limit prevents old
 * rotations from accumulating indefinitely.
 */
final class JsonlLogWriter implements AutoCloseable {

    private static final Set<PosixFilePermission> DIRECTORY_PERMISSIONS =
            PosixFilePermissions.fromString("rwx------");
    private static final Set<PosixFilePermission> FILE_PERMISSIONS =
            PosixFilePermissions.fromString("rw-------");
    private static final Set<OpenOption> APPEND_OPTIONS = Set.of(
            StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.APPEND,
            LinkOption.NOFOLLOW_LINKS);

    private final Consumer<String> errorLogger;
    private final long maxFileSizeBytes;
    private final Object lock = new Object();

    private Path directory;
    private String filePrefix;
    private int retentionFileLimit;
    private int currentIndex;
    private Path currentFile;
    private long currentFileSize;
    private Writer currentWriter;
    private long successfulWrites;
    private long failedWrites;
    private String lastError;
    private Instant lastErrorAt;
    private Instant lastSuccessfulWriteAt;

    JsonlLogWriter(MontoyaApi api, Path directory, String filePrefix, long maxFileSizeBytes,
                   int retentionFileLimit) {
        this(directory, filePrefix, maxFileSizeBytes, retentionFileLimit,
                message -> api.logging().logToError(
                        SecretScrubLoggerExtension.EXTENSION_NAME + " " + message));
    }

    JsonlLogWriter(Path directory, String filePrefix, long maxFileSizeBytes,
                   int retentionFileLimit, Consumer<String> errorLogger) {
        this.errorLogger = errorLogger;
        this.maxFileSizeBytes = maxFileSizeBytes;
        this.filePrefix = filePrefix;
        this.retentionFileLimit = validateRetentionLimit(retentionFileLimit);
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

    int getRetentionFileLimit() {
        synchronized (lock) {
            return retentionFileLimit;
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
            clearError();
            int highest = findHighestExistingIndex();
            openFileForIndex(highest + 1);
        }
    }

    /** Sets the maximum retained files for the active prefix. Zero disables automatic deletion. */
    void setRetentionFileLimit(int newLimit) {
        synchronized (lock) {
            retentionFileLimit = validateRetentionLimit(newLimit);
            pruneOldFiles();
        }
    }

    /** Attempts to reopen the active log after an operational failure. */
    boolean retry() {
        synchronized (lock) {
            closeCurrentWriter();
            clearError();
            if (!ensureDirectory()) {
                return false;
            }
            int index = currentIndex > 0 ? currentIndex : Math.max(1, findHighestExistingIndex());
            openFileForIndex(index);
            return currentWriter != null;
        }
    }

    WriterHealth health() {
        synchronized (lock) {
            return new WriterHealth(
                    currentWriter != null,
                    currentFile,
                    currentFileSize,
                    successfulWrites,
                    failedWrites,
                    lastSuccessfulWriteAt,
                    lastError,
                    lastErrorAt,
                    retentionFileLimit);
        }
    }

    @Override
    public void close() {
        synchronized (lock) {
            closeCurrentWriter();
        }
    }

    private void initializeForDirectory(Path newDirectory) {
        this.directory = newDirectory;
        this.currentIndex = 0;
        this.currentFile = null;
        this.currentFileSize = 0;
        clearError();

        if (!ensureDirectory()) {
            return;
        }

        int highest = findHighestExistingIndex();
        int startIndex = highest == 0 ? 1 : highest;
        openFileForIndex(startIndex);
        if (currentWriter != null && currentFileSize >= maxFileSizeBytes) {
            closeCurrentWriter();
            openFileForIndex(startIndex + 1);
        }
    }

    private boolean ensureDirectory() {
        try {
            Files.createDirectories(directory);
            secureDirectoryIfSupported(directory);
            return true;
        } catch (IOException | RuntimeException e) {
            recordError("could not prepare log directory " + directory + ": " + e.getMessage());
            return false;
        }
    }

    boolean write(String jsonLine) {
        synchronized (lock) {
            if (currentWriter == null) {
                failedWrites++;
                recordError("cannot write log entry because the writer is unavailable; use Retry Writer in the extension tab");
                return false;
            }

            byte[] lineBytes = (jsonLine + System.lineSeparator()).getBytes(StandardCharsets.UTF_8);
            if (currentFileSize > 0 && currentFileSize + lineBytes.length > maxFileSizeBytes) {
                rotate();
                if (currentWriter == null) {
                    failedWrites++;
                    return false;
                }
            }
            try {
                currentWriter.write(jsonLine);
                currentWriter.write(System.lineSeparator());
                currentWriter.flush();
                currentFileSize += lineBytes.length;
                successfulWrites++;
                lastSuccessfulWriteAt = Instant.now();
                pruneOldFiles();
                return true;
            } catch (IOException e) {
                failedWrites++;
                closeCurrentWriter();
                recordError("failed to write log entry to " + currentFile + ": " + e.getMessage());
                return false;
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
        currentFileSize = 0;
        SeekableByteChannel channel = null;
        try {
            if (Files.isSymbolicLink(currentFile)) {
                throw new IOException("refusing to follow a symbolic link");
            }
            currentFileSize = Files.exists(currentFile, LinkOption.NOFOLLOW_LINKS)
                    ? Files.size(currentFile)
                    : 0L;
            if (supportsPosixPermissions(directory)) {
                channel = Files.newByteChannel(
                        currentFile,
                        APPEND_OPTIONS,
                        PosixFilePermissions.asFileAttribute(FILE_PERMISSIONS));
                Files.setPosixFilePermissions(currentFile, FILE_PERMISSIONS);
            } else {
                channel = Files.newByteChannel(currentFile, APPEND_OPTIONS);
            }
            currentWriter = new BufferedWriter(new OutputStreamWriter(
                    Channels.newOutputStream(channel), StandardCharsets.UTF_8));
            clearError();
        } catch (IOException | RuntimeException e) {
            closeFailedChannel(channel);
            currentWriter = null;
            recordError("could not securely open log file " + currentFile + ": " + e.getMessage());
        }
    }

    private void closeCurrentWriter() {
        if (currentWriter != null) {
            try {
                currentWriter.flush();
                currentWriter.close();
            } catch (IOException e) {
                recordError("failed to close log file: " + e.getMessage());
            } finally {
                currentWriter = null;
            }
        }
    }

    private void closeFailedChannel(SeekableByteChannel channel) {
        if (channel == null) {
            return;
        }
        try {
            channel.close();
        } catch (IOException ignored) {
            // Preserve the original open/permission failure as the actionable writer error.
        }
    }

    private int findHighestExistingIndex() {
        if (!Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)) {
            return 0;
        }
        int highest = 0;
        for (IndexedLogFile logFile : matchingLogFiles()) {
            highest = Math.max(highest, logFile.index());
        }
        return highest;
    }

    private void pruneOldFiles() {
        if (retentionFileLimit == 0 || !Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)) {
            return;
        }

        List<IndexedLogFile> files = new ArrayList<>(matchingLogFiles());
        files.sort(Comparator.comparingInt(IndexedLogFile::index));
        int toDelete = files.size() - retentionFileLimit;
        for (IndexedLogFile file : files) {
            if (toDelete <= 0) {
                break;
            }
            if (currentFile != null && currentFile.equals(file.path())) {
                continue;
            }
            try {
                Files.deleteIfExists(file.path());
                toDelete--;
            } catch (IOException | RuntimeException e) {
                recordError("could not remove retained log file " + file.path() + ": " + e.getMessage());
            }
        }
    }

    private List<IndexedLogFile> matchingLogFiles() {
        Pattern fileNamePattern = Pattern.compile(
                Pattern.quote(filePrefix) + "-(\\d{4,})\\.jsonl(?:\\.gz)?");
        List<IndexedLogFile> matches = new ArrayList<>();
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(directory, filePrefix + "-*.jsonl*")) {
            for (Path path : stream) {
                if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
                    continue;
                }
                Matcher matcher = fileNamePattern.matcher(path.getFileName().toString());
                if (!matcher.matches()) {
                    continue;
                }
                try {
                    matches.add(new IndexedLogFile(path, Integer.parseInt(matcher.group(1))));
                } catch (NumberFormatException ignored) {
                    // Ignore impossible-to-rotate indexes rather than failing the whole directory scan.
                }
            }
        } catch (IOException | RuntimeException e) {
            recordError("failed to scan log directory: " + e.getMessage());
        }
        return matches;
    }

    private void secureDirectoryIfSupported(Path path) throws IOException {
        if (supportsPosixPermissions(path)) {
            Files.setPosixFilePermissions(path, DIRECTORY_PERMISSIONS);
        }
    }

    private boolean supportsPosixPermissions(Path path) {
        return Files.getFileAttributeView(path, PosixFileAttributeView.class) != null;
    }

    private static int validateRetentionLimit(int limit) {
        if (limit < 0 || limit > TrafficLoggerConfig.MAX_RETENTION_FILES) {
            throw new IllegalArgumentException(
                    "Retention must be between 0 and " + TrafficLoggerConfig.MAX_RETENTION_FILES);
        }
        return limit;
    }

    private void clearError() {
        lastError = null;
        lastErrorAt = null;
    }

    private void recordError(String message) {
        boolean changed = !message.equals(lastError);
        lastError = message;
        lastErrorAt = Instant.now();
        if (changed) {
            try {
                errorLogger.accept(message);
            } catch (RuntimeException ignored) {
                // Writer state remains observable even if Burp's error logger is unavailable.
            }
        }
    }

    record WriterHealth(boolean available, Path currentFile, long currentFileSize,
                        long successfulWrites, long failedWrites, Instant lastSuccessfulWriteAt,
                        String lastError, Instant lastErrorAt, int retentionFileLimit) {
    }

    private record IndexedLogFile(Path path, int index) {
    }
}
