package com.shadowopentech.sonar;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.sonar.api.batch.fs.InputFile;
import org.sonar.api.batch.fs.internal.DefaultFileSystem;
import org.sonar.api.batch.fs.internal.TestInputFileBuilder;
import org.sonar.api.batch.sensor.internal.DefaultSensorDescriptor;
import org.sonar.api.batch.sensor.internal.SensorContextTester;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collection;

import static org.junit.jupiter.api.Assertions.*;

class ExpiredCertSensorTest {

    private final ExpiredCertSensor sensor = new ExpiredCertSensor();

    // -------------------------------------------------------------------------
    // describe()
    // -------------------------------------------------------------------------

    @Test
    void descriptorHasName() {
        DefaultSensorDescriptor descriptor = new DefaultSensorDescriptor();
        sensor.describe(descriptor);
        assertEquals("Expired Certificate Sensor", descriptor.name());
    }

    @Test
    void descriptorHasNoLanguageRestriction() {
        DefaultSensorDescriptor descriptor = new DefaultSensorDescriptor();
        sensor.describe(descriptor);
        Collection<String> langs = descriptor.languages();
        assertTrue(langs == null || langs.isEmpty(), "Sensor must be language-agnostic");
    }

    // -------------------------------------------------------------------------
    // PEM scanning
    // -------------------------------------------------------------------------

    @Test
    void raisesIssueForExpiredPem(@TempDir Path tempDir) throws Exception {
        copyResource("expired.pem", tempDir.resolve("expired.pem"));

        SensorContextTester context = SensorContextTester.create(tempDir.toFile());
        addInputFile(context, tempDir, "expired.pem");

        sensor.execute(context);

        assertFalse(context.allExternalIssues().isEmpty(), "Expected issue for expired cert");
        assertTrue(context.allExternalIssues().stream().anyMatch(i ->
                i.ruleId().equals(ExpiredCertRulesDefinition.RULE_EXPIRED)));
    }

    @Test
    void raisesIssueForExpiringSoonPem(@TempDir Path tempDir) throws Exception {
        copyResource("expiring-soon.pem", tempDir.resolve("expiring-soon.pem"));

        SensorContextTester context = SensorContextTester.create(tempDir.toFile());
        addInputFile(context, tempDir, "expiring-soon.pem");

        sensor.execute(context);

        assertTrue(context.allExternalIssues().stream().anyMatch(i ->
                i.ruleId().equals(ExpiredCertRulesDefinition.RULE_EXPIRING_SOON)),
                "Expected expiring-soon issue");
    }

    @Test
    void noIssueForValidPem(@TempDir Path tempDir) throws Exception {
        copyResource("valid.pem", tempDir.resolve("valid.pem"));

        SensorContextTester context = SensorContextTester.create(tempDir.toFile());
        addInputFile(context, tempDir, "valid.pem");

        sensor.execute(context);

        assertTrue(context.allExternalIssues().isEmpty(), "Expected no issues for valid cert");
    }

    @Test
    void raisesIssueForChainPemContainingExpiredCert(@TempDir Path tempDir) throws Exception {
        copyResource("chain.pem", tempDir.resolve("chain.pem"));

        SensorContextTester context = SensorContextTester.create(tempDir.toFile());
        addInputFile(context, tempDir, "chain.pem");

        sensor.execute(context);

        assertTrue(context.allExternalIssues().stream().anyMatch(i ->
                i.ruleId().equals(ExpiredCertRulesDefinition.RULE_EXPIRED)),
                "Expected expired issue from chain PEM");
    }

    // -------------------------------------------------------------------------
    // JKS scanning
    // -------------------------------------------------------------------------

    @Test
    void raisesIssueForExpiredCertInJks(@TempDir Path tempDir) throws Exception {
        copyResource("test-truststore.jks", tempDir.resolve("test-truststore.jks"));

        SensorContextTester context = SensorContextTester.create(tempDir.toFile());
        // JKS is a binary file — intentionally NOT added as InputFile to test module-level fallback

        sensor.execute(context);

        assertTrue(context.allExternalIssues().stream().anyMatch(i ->
                i.ruleId().equals(ExpiredCertRulesDefinition.RULE_EXPIRED)),
                "Expected expired issue from JKS");
    }

    // -------------------------------------------------------------------------
    // Archive scanning
    // -------------------------------------------------------------------------

    @Test
    void raisesIssueForExpiredCertInsideJar(@TempDir Path tempDir) throws Exception {
        copyResource("test-archive.jar", tempDir.resolve("test-archive.jar"));

        SensorContextTester context = SensorContextTester.create(tempDir.toFile());

        sensor.execute(context);

        assertTrue(context.allExternalIssues().stream().anyMatch(i ->
                i.ruleId().equals(ExpiredCertRulesDefinition.RULE_EXPIRED)),
                "Expected expired issue from cert inside JAR");
    }

    @Test
    void raisesIssueForExpiredCertInsideNestedArchive(@TempDir Path tempDir) throws Exception {
        copyResource("nested-archive.zip", tempDir.resolve("nested-archive.zip"));

        SensorContextTester context = SensorContextTester.create(tempDir.toFile());

        sensor.execute(context);

        assertTrue(context.allExternalIssues().stream().anyMatch(i ->
                i.ruleId().equals(ExpiredCertRulesDefinition.RULE_EXPIRED)),
                "Expected expired issue from cert inside nested archive (zip -> jar -> pem)");
    }

    // -------------------------------------------------------------------------
    // Configuration
    // -------------------------------------------------------------------------

    @Test
    void customWarningDaysAffectsThreshold(@TempDir Path tempDir) throws Exception {
        // expiring-soon.pem expires ~30 days from now.
        // With warningDays=10, it should NOT trigger an issue.
        copyResource("expiring-soon.pem", tempDir.resolve("expiring-soon.pem"));

        SensorContextTester context = SensorContextTester.create(tempDir.toFile());
        addInputFile(context, tempDir, "expiring-soon.pem");
        context.settings().setProperty(ExpiredCertRulesDefinition.PROPERTY_WARNING_DAYS, "10");

        sensor.execute(context);

        assertTrue(context.allExternalIssues().isEmpty(),
                "Expected no issue when warningDays=10 and cert expires in ~30 days");
    }

    @Test
    void skipsGitDirectory(@TempDir Path tempDir) throws Exception {
        Path gitDir = tempDir.resolve(".git");
        Files.createDirectories(gitDir);
        copyResource("expired.pem", gitDir.resolve("expired.pem"));

        SensorContextTester context = SensorContextTester.create(tempDir.toFile());

        sensor.execute(context);

        assertTrue(context.allExternalIssues().isEmpty(), "Must not scan inside .git directory");
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private void addInputFile(SensorContextTester context, Path baseDir, String filename) throws Exception {
        InputFile inputFile = TestInputFileBuilder
                .create("", baseDir.toFile(), baseDir.resolve(filename).toFile())
                .setContents(Files.readString(baseDir.resolve(filename)))
                .build();
        ((DefaultFileSystem) context.fileSystem()).add(inputFile);
    }

    private void copyResource(String resourceName, Path dest) throws Exception {
        try (InputStream is = getClass().getClassLoader().getResourceAsStream(resourceName)) {
            assertNotNull(is, "Test resource not found: " + resourceName);
            try (OutputStream os = Files.newOutputStream(dest)) {
                is.transferTo(os);
            }
        }
    }
}
