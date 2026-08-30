package secretscrublogger;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JsonlLogWriterTest {

    @TempDir
    Path tempDirectory;

    @Test
    void writesUtf8LinesAndReportsHealth() throws IOException {
        Path logDirectory = tempDirectory.resolve("logs");
        List<String> errors = new ArrayList<>();

        try (JsonlLogWriter writer = new JsonlLogWriter(
                logDirectory, "traffic", 1_024, 0, errors::add)) {
            assertTrue(writer.write("{\"message\":\"hello π\"}"));

            JsonlLogWriter.WriterHealth health = writer.health();
            assertTrue(health.available());
            assertEquals(1, health.successfulWrites());
            assertEquals(0, health.failedWrites());
            assertNotNull(health.lastSuccessfulWriteAt());
            assertNull(health.lastError());
            assertEquals(0, health.retentionFileLimit());
            assertEquals("{\"message\":\"hello π\"}" + System.lineSeparator(),
                    Files.readString(health.currentFile()));
            assertTrue(errors.isEmpty());
        }
    }

    @Test
    void appliesOwnerOnlyPermissionsOnPosixFileSystems() throws IOException {
        Path logDirectory = tempDirectory.resolve("private-logs");
        Files.createDirectories(logDirectory);
        if (Files.getFileAttributeView(
                logDirectory, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS) == null) {
            return;
        }
        Path existingLog = logDirectory.resolve("secure-0001.jsonl");
        Files.writeString(existingLog, "existing" + System.lineSeparator());
        Files.setPosixFilePermissions(logDirectory, PosixFilePermissions.fromString("rwxrwxrwx"));
        Files.setPosixFilePermissions(existingLog, PosixFilePermissions.fromString("rw-rw-rw-"));

        try (JsonlLogWriter writer = new JsonlLogWriter(
                logDirectory, "secure", 1_024, 0, ignored -> { })) {
            Path currentFile = writer.health().currentFile();
            assertEquals(PosixFilePermissions.fromString("rwx------"),
                    Files.getPosixFilePermissions(logDirectory, LinkOption.NOFOLLOW_LINKS));
            assertEquals(PosixFilePermissions.fromString("rw-------"),
                    Files.getPosixFilePermissions(currentFile, LinkOption.NOFOLLOW_LINKS));
        }
    }

    @Test
    void retentionDeletesOnlyOldestMatchingRotations() throws IOException {
        Path logDirectory = tempDirectory.resolve("retained");
        Files.createDirectories(logDirectory);
        Path unrelated = logDirectory.resolve("other-0001.jsonl");
        Files.writeString(unrelated, "keep me");

        try (JsonlLogWriter writer = new JsonlLogWriter(
                logDirectory, "session", 1, 0, ignored -> { })) {
            assertTrue(writer.write("one"));
            assertTrue(writer.write("two"));
            assertTrue(writer.write("three"));
            assertTrue(writer.write("four"));
            assertEquals(List.of(
                            "session-0001.jsonl",
                            "session-0002.jsonl",
                            "session-0003.jsonl",
                            "session-0004.jsonl"),
                    matchingNames(logDirectory, "session-"));

            writer.setRetentionFileLimit(2);

            assertEquals(List.of("session-0003.jsonl", "session-0004.jsonl"),
                    matchingNames(logDirectory, "session-"));
            assertEquals("keep me", Files.readString(unrelated));
            assertEquals(2, writer.health().retentionFileLimit());
        }
    }

    @Test
    void automaticRetentionWaitsForASuccessfulFlushBeforePruning() throws IOException {
        Path logDirectory = tempDirectory.resolve("safe-pruning");
        Files.createDirectories(logDirectory);
        Files.writeString(logDirectory.resolve("session-0001.jsonl"), "older\n");
        Files.writeString(logDirectory.resolve("session-0002.jsonl"), "current\n");

        try (JsonlLogWriter writer = new JsonlLogWriter(
                logDirectory, "session", 1_024, 1, ignored -> { })) {
            assertEquals(List.of("session-0001.jsonl", "session-0002.jsonl"),
                    matchingNames(logDirectory, "session-"));

            assertTrue(writer.write("successfully flushed"));

            assertEquals(List.of("session-0002.jsonl"),
                    matchingNames(logDirectory, "session-"));
        }
    }

    @Test
    void unavailableWriterFailsClosedAndCanRecoverInANewDirectory() throws IOException {
        Path regularFile = tempDirectory.resolve("not-a-directory");
        Files.writeString(regularFile, "occupied");
        List<String> errors = new ArrayList<>();

        try (JsonlLogWriter writer = new JsonlLogWriter(
                regularFile.resolve("logs"), "traffic", 1_024, 0, errors::add)) {
            assertFalse(writer.health().available());
            assertFalse(writer.write("{\"secret\":\"must-not-be-written\"}"));
            assertEquals(1, writer.health().failedWrites());
            assertNotNull(writer.health().lastError());
            assertFalse(errors.isEmpty());

            Path recoveredDirectory = tempDirectory.resolve("recovered");
            writer.setDirectory(recoveredDirectory);

            assertTrue(writer.health().available());
            assertTrue(writer.write("{\"safe\":true}"));
            assertEquals("{\"safe\":true}" + System.lineSeparator(),
                    Files.readString(writer.health().currentFile()));
        }
    }

    @Test
    void refusesToFollowASymbolicLinkForTheActiveLog() throws IOException {
        Path logDirectory = tempDirectory.resolve("symlink-logs");
        Files.createDirectories(logDirectory);
        Path outsideFile = tempDirectory.resolve("outside.jsonl");
        Files.writeString(outsideFile, "outside stays unchanged");
        Files.createSymbolicLink(logDirectory.resolve("traffic-0001.jsonl"), outsideFile);

        try (JsonlLogWriter writer = new JsonlLogWriter(
                logDirectory, "traffic", 1_024, 0, ignored -> { })) {
            assertFalse(writer.health().available());
            assertFalse(writer.write("attacker-controlled"));
            assertEquals("outside stays unchanged", Files.readString(outsideFile));
        }
    }

    private List<String> matchingNames(Path directory, String prefix) throws IOException {
        try (var files = Files.list(directory)) {
            return files
                    .map(path -> path.getFileName().toString())
                    .filter(name -> name.startsWith(prefix))
                    .sorted()
                    .toList();
        }
    }
}
