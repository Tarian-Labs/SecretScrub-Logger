package secretscrublogger;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RedactionSelfTestTest {

    @Test
    void passesTheRealRedactionPipelineWithoutCustomFields() {
        RedactionSelfTest.Result result = RedactionSelfTest.run(new SecretRedactor());

        assertTrue(result.passed(), () -> "Unexpected failures: " + result.failures());
        assertTrue(result.checks() >= 50);
        assertTrue(result.failures().isEmpty());
        assertEquals(0, result.customFieldsChecked());
        assertEquals(0, result.excludedFieldsChecked());
        assertFalse(result.bypassEnabled());
    }

    @Test
    void verifiesEveryConfiguredCustomField() {
        SecretRedactor redactor = new SecretRedactor();
        redactor.setCustomSensitiveFields(List.of("usr_pwd", "private-note", "Mixed_Case"));

        RedactionSelfTest.Result result = RedactionSelfTest.run(redactor);

        assertTrue(result.passed(), () -> "Unexpected failures: " + result.failures());
        assertEquals(3, result.customFieldsChecked());
        assertTrue(result.checks() >= 60);
    }

    @Test
    void passesBaselineAndVerifiesConfiguredBypassBehaviorSeparately() {
        SecretRedactor redactor = new SecretRedactor();
        redactor.setCustomSensitiveFields(List.of("usr_pwd"));
        redactor.setExcludedFields(List.of("password", "token", "usr_pwd"));
        redactor.setExclusionsEnabled(true);

        RedactionSelfTest.Result result = RedactionSelfTest.run(redactor);

        assertTrue(result.passed(), () -> "Unexpected failures: " + result.failures());
        assertTrue(result.bypassEnabled());
        assertEquals(3, result.excludedFieldsChecked());
        assertEquals(1, result.customFieldsChecked());
    }

    @Test
    void failsWhenASecretOrItsRecognisablePrefixSurvives() {
        RedactionSelfTest.RedactionOperation partialLeak = input -> {
            String output = input.replaceAll("SSCANARY[A-Z]+[a-f0-9]{32}", "SSCANARY-prefix-leak")
                    .replaceAll("[a-f0-9]{12}\\.[a-f0-9]{16}\\.[a-f0-9]{16}",
                            SecretRedactor.REDACTED);
            return new SecretRedactor.RedactionResult(output, 1);
        };

        RedactionSelfTest.Result result = RedactionSelfTest.run(
                partialLeak, partialLeak, Set.of());

        assertFalse(result.passed());
        assertTrue(result.failures().stream().anyMatch(failure -> failure.contains("prefix")));
        assertTrue(result.failures().stream().noneMatch(failure -> failure.contains("SSCANARY")),
                "Failure reporting must identify checks without echoing canaries");
    }

    @Test
    void replacingTheWholeMessageDoesNotCountAsAPass() {
        RedactionSelfTest.RedactionOperation eraseEverything = input ->
                new SecretRedactor.RedactionResult(SecretRedactor.REDACTED, 1);

        RedactionSelfTest.Result result = RedactionSelfTest.run(
                eraseEverything, eraseEverything, Set.of());

        assertFalse(result.passed());
        assertTrue(result.failures().stream().anyMatch(failure -> failure.contains("structure")));
    }
}
