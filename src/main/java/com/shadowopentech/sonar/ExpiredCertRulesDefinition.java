package com.shadowopentech.sonar;

import org.sonar.api.PropertyType;
import org.sonar.api.config.PropertyDefinition;
import org.sonar.api.utils.log.Logger;
import org.sonar.api.utils.log.Loggers;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * Holds rule/engine constants and Sonar property definitions.
 *
 * All 5 properties are registered WITHOUT onQualifiers(), which means they appear
 * only in the SonarQube global Administration UI and are not exposed as project-level
 * settings. Default values for warningDays and keystorePasswords are sourced from
 * plugin-config.properties so there is a single place to update them.
 *
 * Rules are registered via NewAdHocRule + NewExternalIssue (not RulesDefinition)
 * so issues are raised for every project regardless of language or quality profile.
 */
public class ExpiredCertRulesDefinition {

    private static final Logger LOG = Loggers.get(ExpiredCertRulesDefinition.class);

    public static final String ENGINE_ID = "expiredcertrule";

    public static final String RULE_EXPIRED       = "CertificateExpired";
    public static final String RULE_EXPIRING_SOON = "CertificateExpiringSoon";

    // ── Property keys ────────────────────────────────────────────────────────
    public static final String PROPERTY_ENABLED              = "sonar.expiredcert.enabled";
    public static final String PROPERTY_SEVERITY_EXPIRED     = "sonar.expiredcert.severity.expired";
    public static final String PROPERTY_SEVERITY_EXPIRING_SOON = "sonar.expiredcert.severity.expiringSoon";
    public static final String PROPERTY_WARNING_DAYS         = "sonar.expiredcert.warningDays";
    public static final String PROPERTY_KEYSTORE_PASSWORDS   = "sonar.expiredcert.keystorePasswords";

    static final String PROPERTY_CATEGORY = "Expired Certificate Rule";

    private ExpiredCertRulesDefinition() {}

    /**
     * Builds all PropertyDefinition beans.
     *
     * - None have onQualifiers() → visible in global admin UI only.
     * - warningDays and keystorePasswords defaults are read from plugin-config.properties.
     * - Severity defaults are INFO.
     */
    public static PropertyDefinition[] propertyDefinitions() {
        Properties config = loadPluginConfig();
        String defaultWarningDays = config.getProperty("expiredcert.warning.days", "60");
        String defaultPasswords   = config.getProperty("keystore.fallback.passwords", "changeit");

        return new PropertyDefinition[]{

                PropertyDefinition.builder(PROPERTY_ENABLED)
                        .name("Enable Expired Certificate Sensor")
                        .description("Set to false to disable the sensor without removing the plugin or "
                                + "restarting SonarQube. Takes effect on the next scan.")
                        .category(PROPERTY_CATEGORY)
                        .type(PropertyType.BOOLEAN)
                        .defaultValue("true")
                        .build(),

                PropertyDefinition.builder(PROPERTY_SEVERITY_EXPIRED)
                        .name("Severity: expired certificate")
                        .description("Severity raised when a certificate has already expired. "
                                + "Accepted values: BLOCKER, CRITICAL, MAJOR, MINOR, INFO.")
                        .category(PROPERTY_CATEGORY)
                        .type(PropertyType.STRING)
                        .defaultValue("INFO")
                        .build(),

                PropertyDefinition.builder(PROPERTY_SEVERITY_EXPIRING_SOON)
                        .name("Severity: certificate expiring soon")
                        .description("Severity raised when a certificate expires within the warning window. "
                                + "Accepted values: BLOCKER, CRITICAL, MAJOR, MINOR, INFO.")
                        .category(PROPERTY_CATEGORY)
                        .type(PropertyType.STRING)
                        .defaultValue("INFO")
                        .build(),

                PropertyDefinition.builder(PROPERTY_WARNING_DAYS)
                        .name("Expiry warning threshold (days)")
                        .description("Days before a certificate's expiry date to raise a warning issue. "
                                + "Default is sourced from plugin-config.properties.")
                        .category(PROPERTY_CATEGORY)
                        .type(PropertyType.INTEGER)
                        .defaultValue(defaultWarningDays)
                        .build(),

                PropertyDefinition.builder(PROPERTY_KEYSTORE_PASSWORDS)
                        .name("Keystore passwords")
                        .description("Comma-separated passwords tried when opening JKS/PKCS12 keystores. "
                                + "These are tried first; the built-in fallback list in plugin-config.properties "
                                + "is always tried afterwards. Default is sourced from plugin-config.properties.")
                        .category(PROPERTY_CATEGORY)
                        .type(PropertyType.STRING)
                        .defaultValue(defaultPasswords)
                        .build()
        };
    }

    private static Properties loadPluginConfig() {
        Properties props = new Properties();
        try (InputStream is = ExpiredCertRulesDefinition.class
                .getClassLoader().getResourceAsStream("plugin-config.properties")) {
            if (is != null) {
                props.load(is);
            }
        } catch (IOException e) {
            LOG.warn("ExpiredCertRulesDefinition: could not load plugin-config.properties, using built-in defaults");
        }
        return props;
    }
}
