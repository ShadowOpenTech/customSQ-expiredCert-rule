package com.shadowopentech.sonar;

import com.shadowopentech.sonar.cert.CertificateInfo;
import com.shadowopentech.sonar.cert.KeyStoreParser;
import com.shadowopentech.sonar.cert.PemDerParser;
import org.sonar.api.batch.fs.FileSystem;
import org.sonar.api.batch.fs.InputFile;
import org.sonar.api.batch.rule.Severity;
import org.sonar.api.batch.sensor.Sensor;
import org.sonar.api.batch.sensor.SensorContext;
import org.sonar.api.batch.sensor.SensorDescriptor;
import org.sonar.api.batch.sensor.issue.NewExternalIssue;
import org.sonar.api.batch.sensor.issue.NewIssueLocation;
import org.sonar.api.rules.RuleType;
import org.sonar.api.utils.log.Logger;
import org.sonar.api.utils.log.Loggers;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.time.LocalDate;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Language-agnostic sensor that walks the full project filesystem,
 * parses every certificate it finds (including inside archives),
 * and raises issues for expired or soon-to-expire certificates.
 */
public class ExpiredCertSensor implements Sensor {

    private static final Logger LOG = Loggers.get(ExpiredCertSensor.class);

    // File extensions routed to PemDerParser
    private static final Set<String> CERT_EXTENSIONS = Set.of(
            "pem", "crt", "cer", "cert", "der", "p7b", "p7c"
    );

    // File extensions routed to KeyStoreParser
    private static final Set<String> KEYSTORE_EXTENSIONS = Set.of(
            "jks", "keystore", "p12", "pfx"
    );

    // File extensions treated as archives (recursively extracted)
    private static final Set<String> ARCHIVE_EXTENSIONS = Set.of(
            "jar", "war", "ear", "zip", "aar"
    );

    // Directories skipped entirely during filesystem walk
    private static final Set<String> SKIP_DIRS = Set.of(
            ".git", "node_modules", "target", "build", ".mvn", ".gradle",
            ".idea", ".vscode", "__pycache__", ".tox"
    );

    private final PemDerParser pemDerParser = new PemDerParser();
    private final KeyStoreParser keyStoreParser = new KeyStoreParser();

    @Override
    public void describe(SensorDescriptor descriptor) {
        // No language restriction — runs on every SonarQube project
        descriptor.name("Expired Certificate Sensor");
    }

    @Override
    public void execute(SensorContext context) {
        // ── Graceful top-level guard ──────────────────────────────────────────
        // Any unhandled exception is caught here so the plugin never causes
        // other sensors or the overall scan to fail.
        try {
            doExecute(context);
        } catch (Exception e) {
            LOG.warn("ExpiredCertSensor: unexpected error — plugin will not affect other analysis results. "
                    + "Error: {}", e.getMessage());
            LOG.debug("ExpiredCertSensor: full stack trace", e);
        }
    }

    private void doExecute(SensorContext context) {
        // ── Toggle check ──────────────────────────────────────────────────────
        boolean enabled = context.config()
                .getBoolean(ExpiredCertRulesDefinition.PROPERTY_ENABLED)
                .orElse(true);
        if (!enabled) {
            LOG.info("ExpiredCertSensor: disabled via '{}' — skipping scan.",
                    ExpiredCertRulesDefinition.PROPERTY_ENABLED);
            return;
        }

        int warningDays = context.config()
                .getInt(ExpiredCertRulesDefinition.PROPERTY_WARNING_DAYS)
                .orElse(60);

        List<String> passwords = buildPasswordList(context);
        Path baseDir = context.fileSystem().baseDir().toPath();

        boolean allowProjectOverrides = context.config()
                .getBoolean(ExpiredCertRulesDefinition.PROPERTY_ALLOW_PROJECT_OVERRIDES)
                .orElse(true);

        Severity severityExpired      = resolveSeverity(context,
                ExpiredCertRulesDefinition.PROPERTY_SEVERITY_EXPIRED,
                ExpiredCertRulesDefinition.PROPERTY_SEVERITY_EXPIRED_OVERRIDE,
                allowProjectOverrides, Severity.INFO);
        Severity severityExpiringSoon = resolveSeverity(context,
                ExpiredCertRulesDefinition.PROPERTY_SEVERITY_EXPIRING_SOON,
                ExpiredCertRulesDefinition.PROPERTY_SEVERITY_EXPIRING_SOON_OVERRIDE,
                allowProjectOverrides, Severity.INFO);

        LOG.info("ExpiredCertSensor: scanning {} (warningDays={}, severityExpired={}, severityExpiringSoon={}, allowProjectOverrides={})",
                baseDir, warningDays, severityExpired, severityExpiringSoon, allowProjectOverrides);

        registerAdHocRules(context, severityExpired, severityExpiringSoon);

        try {
            Files.walkFileTree(baseDir, new SimpleFileVisitor<>() {

                @Override
                public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                    if (SKIP_DIRS.contains(dir.getFileName().toString())) {
                        return FileVisitResult.SKIP_SUBTREE;
                    }
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                    String relativePath = baseDir.relativize(file).toString();
                    String ext = extension(file.getFileName().toString());

                    try {
                        if (CERT_EXTENSIONS.contains(ext)) {
                            try (InputStream is = Files.newInputStream(file)) {
                                List<CertificateInfo> certs = pemDerParser.parse(is, relativePath);
                                reportIssues(certs, file, warningDays,
                                        severityExpired, severityExpiringSoon, context);
                            }
                        } else if (KEYSTORE_EXTENSIONS.contains(ext)) {
                            String type = keystoreType(ext);
                            List<String> pw = withFileNamePasswords(file.getFileName().toString(), passwords);
                            try (InputStream is = Files.newInputStream(file)) {
                                List<CertificateInfo> certs =
                                        keyStoreParser.parse(is, relativePath, type, pw);
                                if (certs == null) {
                                    reportPasswordFailure(relativePath, file, context);
                                } else {
                                    reportIssues(certs, file, warningDays,
                                            severityExpired, severityExpiringSoon, context);
                                }
                            }
                        } else if (ARCHIVE_EXTENSIONS.contains(ext)) {
                            try (InputStream is = Files.newInputStream(file)) {
                                processArchiveBytes(is.readAllBytes(), relativePath,
                                        warningDays, passwords, severityExpired, severityExpiringSoon,
                                        context, file);
                            }
                        }
                    } catch (Exception e) {
                        // Isolate per-file failures — one bad file never stops the rest
                        LOG.warn("ExpiredCertSensor: skipping {} — {}", relativePath, e.getMessage());
                        LOG.debug("ExpiredCertSensor: per-file error detail", e);
                    }

                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFileFailed(Path file, IOException exc) {
                    LOG.debug("ExpiredCertSensor: skipping unreadable file {}", file);
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException e) {
            LOG.warn("ExpiredCertSensor: filesystem walk failed — {}", e.getMessage());
        }
    }

    // -------------------------------------------------------------------------
    // Archive handling (recursive, in-memory)
    // -------------------------------------------------------------------------

    /**
     * Recursively extracts a ZIP/JAR/WAR/EAR/AAR byte array and processes each entry.
     * Archives nested inside archives are handled by recursing into this method.
     *
     * @param archiveBytes  raw bytes of the archive
     * @param archivePath   display path of this archive (used in issue messages)
     * @param originalFile  the top-level {@link Path} on disk (for InputFile lookup)
     */
    private void processArchiveBytes(byte[] archiveBytes, String archivePath,
                                     int warningDays, List<String> passwords,
                                     Severity severityExpired, Severity severityExpiringSoon,
                                     SensorContext context, Path originalFile) {
        try (ZipInputStream zip = new ZipInputStream(new ByteArrayInputStream(archiveBytes))) {
            ZipEntry entry;
            while ((entry = zip.getNextEntry()) != null) {
                if (entry.isDirectory()) {
                    zip.closeEntry();
                    continue;
                }

                String entryName  = entry.getName();
                String entryPath  = archivePath + "!/" + entryName;
                String ext        = extension(entryName);
                byte[] entryBytes = readAllBytes(zip);
                zip.closeEntry();

                if (CERT_EXTENSIONS.contains(ext)) {
                    List<CertificateInfo> certs =
                            pemDerParser.parse(new ByteArrayInputStream(entryBytes), entryPath);
                    reportIssues(certs, originalFile, warningDays,
                            severityExpired, severityExpiringSoon, context);

                } else if (KEYSTORE_EXTENSIONS.contains(ext)) {
                    String type = keystoreType(ext);
                    String entryFileName = entryName.substring(entryName.lastIndexOf('/') + 1);
                    List<String> pw = withFileNamePasswords(entryFileName, passwords);
                    List<CertificateInfo> certs = keyStoreParser.parse(
                            new ByteArrayInputStream(entryBytes), entryPath, type, pw);
                    if (certs == null) {
                        reportPasswordFailure(entryPath, originalFile, context);
                    } else {
                        reportIssues(certs, originalFile, warningDays,
                                severityExpired, severityExpiringSoon, context);
                    }

                } else if (ARCHIVE_EXTENSIONS.contains(ext)) {
                    processArchiveBytes(entryBytes, entryPath, warningDays, passwords,
                            severityExpired, severityExpiringSoon, context, originalFile);
                }
            }
        } catch (IOException e) {
            LOG.debug("ExpiredCertSensor: could not process archive {} — {}", archivePath, e.getMessage());
        }
    }

    // -------------------------------------------------------------------------
    // Ad-hoc rule registration (once per scan, language-agnostic)
    // -------------------------------------------------------------------------

    /**
     * Registers rule metadata via NewAdHocRule so SonarQube shows names and
     * descriptions in the UI. These are external rules — no quality profile or
     * language restriction applies. Issues are always raised for every project.
     */
    private void registerAdHocRules(SensorContext context,
                                    Severity severityExpired, Severity severityExpiringSoon) {
        context.newAdHocRule()
                .engineId(ExpiredCertRulesDefinition.ENGINE_ID)
                .ruleId(ExpiredCertRulesDefinition.RULE_EXPIRED)
                .name("Certificates must not be expired")
                .description("An expired certificate was found in the project workspace. "
                        + "Expired certificates are rejected by TLS clients and will cause connection failures. "
                        + "Replace the certificate immediately.")
                .severity(severityExpired)
                .type(RuleType.VULNERABILITY)
                .save();

        context.newAdHocRule()
                .engineId(ExpiredCertRulesDefinition.ENGINE_ID)
                .ruleId(ExpiredCertRulesDefinition.RULE_EXPIRING_SOON)
                .name("Certificates should not be expiring soon")
                .description("A certificate expiring within the configured warning window was found. "
                        + "Renew it before it expires to avoid service disruption. "
                        + "Warning window is controlled by sonar.expiredcert.warningDays (default: 60 days).")
                .severity(severityExpiringSoon)
                .type(RuleType.VULNERABILITY)
                .save();

        context.newAdHocRule()
                .engineId(ExpiredCertRulesDefinition.ENGINE_ID)
                .ruleId(ExpiredCertRulesDefinition.RULE_PASSWORD_FAILED)
                .name("Keystore could not be opened with any known password")
                .description("A keystore file was found but none of the configured or fallback passwords "
                        + "could open it. The certificates inside could not be inspected for expiry. "
                        + "Add the correct password to sonar.expiredcert.keystorePasswords in the admin UI.")
                .severity(Severity.INFO)
                .type(RuleType.VULNERABILITY)
                .save();
    }

    /**
     * Resolves the effective severity for a rule.
     *
     * <p>The global severity (a global-only property) is always read first. When project overrides
     * are allowed and a non-blank override is set for this project, the override wins; otherwise the
     * global severity is used. When overrides are disallowed, the global severity is enforced
     * regardless of any project override.
     */
    private static Severity resolveSeverity(SensorContext context, String globalKey, String overrideKey,
                                            boolean allowProjectOverrides, Severity defaultSeverity) {
        Severity global = parseSeverity(context, globalKey, defaultSeverity);
        if (!allowProjectOverrides) {
            return global;
        }
        return context.config().get(overrideKey)
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .map(s -> parseSeverityValue(s, overrideKey, global))
                .orElse(global);
    }

    private static Severity parseSeverity(SensorContext context, String key, Severity defaultSeverity) {
        return context.config().get(key)
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .map(s -> parseSeverityValue(s, key, defaultSeverity))
                .orElse(defaultSeverity);
    }

    private static Severity parseSeverityValue(String raw, String key, Severity fallback) {
        try {
            return Severity.valueOf(raw.toUpperCase());
        } catch (IllegalArgumentException e) {
            LOG.warn("ExpiredCertSensor: invalid severity '{}' for '{}' — using '{}'", raw, key, fallback);
            return fallback;
        }
    }

    // -------------------------------------------------------------------------
    // Issue reporting
    // -------------------------------------------------------------------------

    private void reportIssues(List<CertificateInfo> certs, Path file,
                               int warningDays, Severity severityExpired,
                               Severity severityExpiringSoon, SensorContext context) {
        LocalDate today     = LocalDate.now();
        LocalDate threshold = today.plusDays(warningDays);
        FileSystem fs       = context.fileSystem();

        for (CertificateInfo cert : certs) {
            LocalDate expiry = cert.getExpiryDate();
            String ruleId;
            Severity severity;
            String message;

            if (!expiry.isAfter(today)) {
                long daysAgo = ChronoUnit.DAYS.between(expiry, today);
                String ago = daysAgo == 0 ? "today" : daysAgo + (daysAgo == 1 ? " day ago" : " days ago");
                ruleId   = ExpiredCertRulesDefinition.RULE_EXPIRED;
                severity = severityExpired;
                message  = buildMessage(cert, "expired " + ago + " (on " + expiry
                        + "). Replace it immediately.");
            } else if (!expiry.isAfter(threshold)) {
                long daysLeft = ChronoUnit.DAYS.between(today, expiry);
                String left = daysLeft == 0 ? "today" : "in " + daysLeft + (daysLeft == 1 ? " day" : " days");
                ruleId   = ExpiredCertRulesDefinition.RULE_EXPIRING_SOON;
                severity = severityExpiringSoon;
                message  = buildMessage(cert, "expires " + left + " (on " + expiry
                        + "). Renew before expiry.");
            } else {
                continue; // Certificate is healthy — no issue
            }

            NewExternalIssue issue = context.newExternalIssue()
                    .engineId(ExpiredCertRulesDefinition.ENGINE_ID)
                    .ruleId(ruleId)
                    .severity(severity)
                    .type(RuleType.VULNERABILITY);

            // Prefer a file-level issue; fall back to module-level for binary/out-of-scope files
            InputFile inputFile = fs.inputFile(fs.predicates().is(file.toFile()));
            NewIssueLocation location = issue.newLocation().message(message);
            if (inputFile != null) {
                location.on(inputFile);
            } else {
                location.on(context.module());
            }

            issue.at(location).save();
        }
    }

    private static String buildMessage(CertificateInfo cert, String suffix) {
        StringBuilder sb = new StringBuilder("Certificate '")
                .append(cert.getSubject())
                .append("'");
        if (cert.getAlias() != null) {
            sb.append(" (alias: '").append(cert.getAlias()).append("')");
        }
        sb.append(" in '").append(cert.getSourcePath()).append("' ").append(suffix);
        return sb.toString();
    }

    /**
     * Raises an INFO-level issue when no password in the dictionary could open a keystore.
     */
    private void reportPasswordFailure(String keystorePath, Path file, SensorContext context) {
        LOG.warn("ExpiredCertSensor: could not open keystore '{}' — no password matched", keystorePath);

        String message = "Keystore '" + keystorePath + "' could not be opened with any known password. "
                + "Certificates inside were not inspected. "
                + "Add the correct password to sonar.expiredcert.keystorePasswords.";

        NewExternalIssue issue = context.newExternalIssue()
                .engineId(ExpiredCertRulesDefinition.ENGINE_ID)
                .ruleId(ExpiredCertRulesDefinition.RULE_PASSWORD_FAILED)
                .severity(Severity.INFO)
                .type(RuleType.VULNERABILITY);

        InputFile inputFile = context.fileSystem()
                .inputFile(context.fileSystem().predicates().is(file.toFile()));
        NewIssueLocation location = issue.newLocation().message(message);
        if (inputFile != null) {
            location.on(inputFile);
        } else {
            location.on(context.module());
        }

        issue.at(location).save();
    }

    // -------------------------------------------------------------------------
    // Password list construction
    // -------------------------------------------------------------------------

    /**
     * Builds the ordered password list:
     * 1. User-configured passwords from sonar.expiredcert.keystorePasswords
     * 2. Fallback list from plugin-config.properties
     */
    private List<String> buildPasswordList(SensorContext context) {
        List<String> passwords = new ArrayList<>();

        context.config().get(ExpiredCertRulesDefinition.PROPERTY_KEYSTORE_PASSWORDS)
                .filter(s -> !s.isBlank())
                .ifPresent(val -> Arrays.stream(val.split(",", -1))
                        .map(String::trim)
                        .forEach(passwords::add));

        try (InputStream is = getClass().getClassLoader()
                .getResourceAsStream("plugin-config.properties")) {
            if (is != null) {
                Properties props = new Properties();
                props.load(is);
                String fallback = props.getProperty("keystore.fallback.passwords", "");
                Arrays.stream(fallback.split(",", -1))
                        .map(String::trim)
                        .filter(p -> !passwords.contains(p))
                        .forEach(passwords::add);
            }
        } catch (IOException e) {
            LOG.warn("ExpiredCertSensor: could not load plugin-config.properties, using minimal fallback");
            List.of("changeit", "changeme", "password", "")
                    .stream()
                    .filter(p -> !passwords.contains(p))
                    .forEach(passwords::add);
        }

        return passwords;
    }

    /**
     * Builds a per-keystore password list that also tries the keystore's own file name and the
     * name without its extension (e.g. "server.jks" → "server.jks", "server"), a common convention,
     * before falling back to the configured/global password list.
     */
    private static List<String> withFileNamePasswords(String fileName, List<String> base) {
        List<String> list = new ArrayList<>();
        list.add(fileName);
        int dot = fileName.lastIndexOf('.');
        if (dot > 0) {
            list.add(fileName.substring(0, dot));
        }
        for (String p : base) {
            if (!list.contains(p)) {
                list.add(p);
            }
        }
        return list;
    }

    // -------------------------------------------------------------------------
    // Utilities
    // -------------------------------------------------------------------------

    private static String extension(String filename) {
        int dot = filename.lastIndexOf('.');
        return dot >= 0 ? filename.substring(dot + 1).toLowerCase(Locale.ROOT) : "";
    }

    private static String keystoreType(String ext) {
        return (ext.equals("p12") || ext.equals("pfx")) ? "PKCS12" : "JKS";
    }

    private static byte[] readAllBytes(InputStream is) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        byte[] block = new byte[8192];
        int len;
        while ((len = is.read(block)) > 0) {
            buf.write(block, 0, len);
        }
        return buf.toByteArray();
    }
}
