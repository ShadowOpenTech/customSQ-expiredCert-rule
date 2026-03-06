package com.shadowopentech.sonar;

import org.sonar.api.PropertyType;
import org.sonar.api.config.PropertyDefinition;
import org.sonar.api.rule.RuleStatus;
import org.sonar.api.rule.Severity;
import org.sonar.api.rules.RuleType;
import org.sonar.api.server.rule.RulesDefinition;

public class ExpiredCertRulesDefinition implements RulesDefinition {

    public static final String REPOSITORY_KEY = "expiredcertrule";

    public static final String RULE_EXPIRED      = "CertificateExpired";
    public static final String RULE_EXPIRING_SOON = "CertificateExpiringSoon";

    public static final String PROPERTY_WARNING_DAYS        = "sonar.expiredcert.warningDays";
    public static final String PROPERTY_KEYSTORE_PASSWORDS  = "sonar.expiredcert.keystorePasswords";

    static final String PROPERTY_CATEGORY = "Expired Certificate Rule";

    @Override
    public void define(Context context) {
        NewRepository repo = context.createRepository(REPOSITORY_KEY, "java")
                .setName("ShadowOpentech Certificate Rules");

        repo.createRule(RULE_EXPIRED)
                .setName("Certificates must not be expired")
                .setHtmlDescription(
                        "<p>An <strong>expired certificate</strong> was found in the project workspace. "
                        + "Expired certificates are rejected by TLS clients and will cause connection failures. "
                        + "Replace the certificate immediately.</p>"
                        + "<h2>Impact</h2>"
                        + "<ul><li>Service outages when clients refuse the expired certificate</li>"
                        + "<li>Possible man-in-the-middle exposure if bypass workarounds are applied</li></ul>"
                        + "<h2>Resolution</h2>"
                        + "<p>Renew the certificate from your CA and replace the expired file or keystore entry.</p>")
                .setType(RuleType.VULNERABILITY)
                .setSeverity(Severity.CRITICAL)
                .setStatus(RuleStatus.READY)
                .setTags("security", "ssl", "certificate");

        repo.createRule(RULE_EXPIRING_SOON)
                .setName("Certificates should not be expiring soon")
                .setHtmlDescription(
                        "<p>A certificate expiring within the configured warning window was found. "
                        + "Allowing a certificate to expire causes service disruption. "
                        + "Renew it before it reaches its expiry date.</p>"
                        + "<h2>Configuration</h2>"
                        + "<p>The warning window is controlled by the <code>sonar.expiredcert.warningDays</code> "
                        + "property (default: 60 days).</p>"
                        + "<h2>Resolution</h2>"
                        + "<p>Renew the certificate from your CA and update the file or keystore entry.</p>")
                .setType(RuleType.VULNERABILITY)
                .setSeverity(Severity.MAJOR)
                .setStatus(RuleStatus.READY)
                .setTags("security", "ssl", "certificate");

        repo.done();
    }

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
