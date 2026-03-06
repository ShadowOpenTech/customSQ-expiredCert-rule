package com.shadowopentech.sonar;

import org.sonar.api.PropertyType;
import org.sonar.api.config.PropertyDefinition;

/**
 * Holds rule/engine constants and Sonar property definitions.
 *
 * Rules are no longer registered via RulesDefinition (which is language-scoped).
 * Instead, the sensor uses NewAdHocRule + NewExternalIssue so issues are raised
 * for every project regardless of language or quality profile configuration.
 */
public class ExpiredCertRulesDefinition {

    public static final String ENGINE_ID = "expiredcertrule";

    public static final String RULE_EXPIRED       = "CertificateExpired";
    public static final String RULE_EXPIRING_SOON = "CertificateExpiringSoon";

    public static final String PROPERTY_WARNING_DAYS       = "sonar.expiredcert.warningDays";
    public static final String PROPERTY_KEYSTORE_PASSWORDS = "sonar.expiredcert.keystorePasswords";

    static final String PROPERTY_CATEGORY = "Expired Certificate Rule";

    private ExpiredCertRulesDefinition() {}

    /**
     * Returns the PropertyDefinition beans to be registered in the plugin.
     * Kept here so all rule-related config is co-located.
     */
    public static PropertyDefinition[] propertyDefinitions() {
        return new PropertyDefinition[]{
                PropertyDefinition.builder(PROPERTY_WARNING_DAYS)
                        .name("Expiry warning threshold (days)")
                        .description("Number of days before a certificate's expiry date to raise a warning issue.")
                        .category(PROPERTY_CATEGORY)
                        .type(PropertyType.INTEGER)
                        .defaultValue("60")
                        .build(),

                PropertyDefinition.builder(PROPERTY_KEYSTORE_PASSWORDS)
                        .name("Keystore passwords")
                        .description("Comma-separated list of passwords to try when opening JKS/PKCS12 keystores. "
                                + "Tried before the built-in fallback list in plugin-config.properties.")
                        .category(PROPERTY_CATEGORY)
                        .type(PropertyType.STRING)
                        .defaultValue("")
                        .build()
        };
    }
}
