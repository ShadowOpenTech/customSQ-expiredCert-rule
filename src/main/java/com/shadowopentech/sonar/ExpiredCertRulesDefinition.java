package com.shadowopentech.sonar;

import org.sonar.api.PropertyType;
import org.sonar.api.config.PropertyDefinition;
import org.sonar.api.resources.Qualifiers;
import org.sonar.api.utils.log.Logger;
import org.sonar.api.utils.log.Loggers;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * Holds rule/engine constants and Sonar property definitions.
 *
 * Property scoping:
 *  - Most settings (enabled, global severities, allowProjectOverrides, warningDays,
 *    keystorePasswords) are GLOBAL-only — they appear in the global Administration UI.
 *  - The two severity OVERRIDE settings are PROJECT-only (onlyOnQualifiers PROJECT) — they
 *    appear solely on a project's settings page.
 *
 * Severity resolution (see {@code ExpiredCertSensor.resolveSeverity}): when
 * allowProjectOverrides is true, a project override wins over the global severity; when it is
 * false, the global severity is enforced for every project and overrides are ignored. The global
 * severities are global-only precisely so their value stays recoverable at scan time even when a
 * project sets an override.
 *
 * Defaults for warningDays and keystorePasswords are sourced from plugin-config.properties so
 * there is a single place to update them.
 *
 * Rules are registered via NewAdHocRule + NewExternalIssue (not RulesDefinition)
 * so issues are raised for every project regardless of language or quality profile.
 */
public class ExpiredCertRulesDefinition {

    private static final Logger LOG = Loggers.get(ExpiredCertRulesDefinition.class);

    public static final String ENGINE_ID = "expiredcertrule";

    public static final String RULE_EXPIRED       = "CertificateExpired";
    public static final String RULE_EXPIRING_SOON = "CertificateExpiringSoon";
    public static final String RULE_PASSWORD_FAILED = "KeystorePasswordFailed";

    // ── Property keys ────────────────────────────────────────────────────────
    public static final String PROPERTY_ENABLED              = "sonar.expiredcert.enabled";
    public static final String PROPERTY_SEVERITY_EXPIRED     = "sonar.expiredcert.severity.expired";
    public static final String PROPERTY_SEVERITY_EXPIRING_SOON = "sonar.expiredcert.severity.expiringSoon";
    public static final String PROPERTY_WARNING_DAYS         = "sonar.expiredcert.warningDays";
    public static final String PROPERTY_KEYSTORE_PASSWORDS   = "sonar.expiredcert.keystorePasswords";

    // Per-project severity overrides (visible only on project settings pages) and the global
    // master toggle that decides whether those overrides are honoured.
    public static final String PROPERTY_SEVERITY_EXPIRED_OVERRIDE       = "sonar.expiredcert.severity.expired.override";
    public static final String PROPERTY_SEVERITY_EXPIRING_SOON_OVERRIDE = "sonar.expiredcert.severity.expiringSoon.override";
    public static final String PROPERTY_ALLOW_PROJECT_OVERRIDES         = "sonar.expiredcert.severity.allowProjectOverrides";

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

                // Global (authoritative) severities. These are global-only so their value is always
                // recoverable at scan time even when a project sets an override — which is what makes
                // the "enforce global" toggle below possible.
                PropertyDefinition.builder(PROPERTY_SEVERITY_EXPIRED)
                        .name("Global severity: expired certificate")
                        .description("Default severity raised when a certificate has already expired. "
                                + "Applies to every project unless a per-project override is set AND project "
                                + "overrides are allowed. Accepted values: BLOCKER, CRITICAL, MAJOR, MINOR, INFO.")
                        .category(PROPERTY_CATEGORY)
                        .type(PropertyType.STRING)
                        .defaultValue("INFO")
                        .build(),

                PropertyDefinition.builder(PROPERTY_SEVERITY_EXPIRING_SOON)
                        .name("Global severity: certificate expiring soon")
                        .description("Default severity raised when a certificate expires within the warning window. "
                                + "Applies to every project unless a per-project override is set AND project "
                                + "overrides are allowed. Accepted values: BLOCKER, CRITICAL, MAJOR, MINOR, INFO.")
                        .category(PROPERTY_CATEGORY)
                        .type(PropertyType.STRING)
                        .defaultValue("INFO")
                        .build(),

                // Master toggle (global-only). When false, all per-project severity overrides are
                // ignored and the global severities above are enforced for every project.
                PropertyDefinition.builder(PROPERTY_ALLOW_PROJECT_OVERRIDES)
                        .name("Allow per-project severity overrides")
                        .description("When enabled, a project may override the expired / expiring-soon severity "
                                + "in its own settings. When disabled, every project uses the global severities "
                                + "above and all per-project overrides are ignored.")
                        .category(PROPERTY_CATEGORY)
                        .type(PropertyType.BOOLEAN)
                        .defaultValue("true")
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
                                + "These are tried first; the keystore's own file name and the built-in fallback "
                                + "list in plugin-config.properties are always tried afterwards. "
                                + "Default is sourced from plugin-config.properties.")
                        .category(PROPERTY_CATEGORY)
                        .type(PropertyType.STRING)
                        .defaultValue(defaultPasswords)
                        .build(),

                // Per-project severity overrides — visible ONLY on project settings pages
                // (onlyOnQualifiers PROJECT). Leave blank to inherit the global value. Honoured only
                // when 'Allow per-project severity overrides' is enabled globally.
                PropertyDefinition.builder(PROPERTY_SEVERITY_EXPIRED_OVERRIDE)
                        .name("Severity override: expired certificate")
                        .description("Overrides the global expired-certificate severity for THIS project only. "
                                + "Leave blank to inherit the global value. Ignored when per-project overrides "
                                + "are disabled globally. Accepted values: BLOCKER, CRITICAL, MAJOR, MINOR, INFO.")
                        .category(PROPERTY_CATEGORY)
                        .type(PropertyType.STRING)
                        .onlyOnQualifiers(Qualifiers.PROJECT)
                        .build(),

                PropertyDefinition.builder(PROPERTY_SEVERITY_EXPIRING_SOON_OVERRIDE)
                        .name("Severity override: certificate expiring soon")
                        .description("Overrides the global expiring-soon severity for THIS project only. "
                                + "Leave blank to inherit the global value. Ignored when per-project overrides "
                                + "are disabled globally. Accepted values: BLOCKER, CRITICAL, MAJOR, MINOR, INFO.")
                        .category(PROPERTY_CATEGORY)
                        .type(PropertyType.STRING)
                        .onlyOnQualifiers(Qualifiers.PROJECT)
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
