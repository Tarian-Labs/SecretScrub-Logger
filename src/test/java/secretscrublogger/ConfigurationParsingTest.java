package secretscrublogger;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ConfigurationParsingTest {

    @Test
    void parsesValidRetentionLimits() {
        assertEquals(0, SecretScrubLoggerExtension.parseRetentionFiles(null));
        assertEquals(0, SecretScrubLoggerExtension.parseRetentionFiles(""));
        assertEquals(0, SecretScrubLoggerExtension.parseRetentionFiles(" 0 "));
        assertEquals(25, SecretScrubLoggerExtension.parseRetentionFiles("25"));
        assertEquals(TrafficLoggerConfig.MAX_RETENTION_FILES,
                SecretScrubLoggerExtension.parseRetentionFiles(
                        Integer.toString(TrafficLoggerConfig.MAX_RETENTION_FILES)));
    }

    @Test
    void rejectsMalformedOrOutOfRangeRetentionLimits() {
        assertEquals(TrafficLoggerConfig.DEFAULT_RETENTION_FILES,
                SecretScrubLoggerExtension.parseRetentionFiles("not-a-number"));
        assertEquals(TrafficLoggerConfig.DEFAULT_RETENTION_FILES,
                SecretScrubLoggerExtension.parseRetentionFiles("-1"));
        assertEquals(TrafficLoggerConfig.DEFAULT_RETENTION_FILES,
                SecretScrubLoggerExtension.parseRetentionFiles("10001"));
    }
}
