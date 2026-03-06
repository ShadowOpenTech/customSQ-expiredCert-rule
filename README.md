# customSQ-expiredCert-rule

A custom SonarQube plugin that scans your entire project workspace for certificates in any format or location — including inside archives and nested archives — and reports certificates that are expired or expiring within a configurable window (default: 60 days).

---

## What It Does

This plugin registers a **language-agnostic file sensor**, meaning it runs on every SonarQube project regardless of the primary language (Java, Python, JavaScript, etc.). It recursively scans all project files, extracts certificates from every supported format, evaluates expiry dates, and raises issues directly on the certificate file.

---

## Rules

| Rule Key | Severity | Description |
|---|---|---|
| `expiredcertrule:CertificateExpired` | CRITICAL | Certificate has already passed its expiry date |
| `expiredcertrule:CertificateExpiringSoon` | MAJOR | Certificate expires within the configured warning window |

Both rules appear under the **ShadowOpentech Certificate Rules** repository in SonarQube Quality Profiles.

---

## Supported Certificate Formats

| Format | Extensions | Notes |
|---|---|---|
| PEM | `.pem`, `.crt`, `.cer`, `.cert` | Supports multi-certificate (certificate chain) PEM files |
| DER | `.der` | Binary encoded X.509 |
| PKCS#12 | `.p12`, `.pfx` | Keystore — all aliases scanned |
| JKS | `.jks`, `.keystore` | Java KeyStore — all aliases scanned |
| PKCS#7 | `.p7b`, `.p7c` | Certificate bundles |
| Archives | `.jar`, `.war`, `.ear`, `.zip`, `.aar` | Recursively extracted and scanned, including archives inside archives |

---

## Issue Messages

Issues are raised at file level with full certificate details:

> **Expired:** `Certificate 'CN=api.example.com, O=Example Corp' (alias: 'server-cert') in 'truststore.jks' expired on 2025-01-15. Replace it immediately.`

> **Expiring Soon:** `Certificate 'CN=api.example.com, O=Example Corp' (alias: 'server-cert') in 'truststore.jks' expires in 42 days on 2026-04-17. Renew before expiry.`

---

## Configuration

### SonarQube Properties

Set these in your `sonar-project.properties` or via the SonarQube UI (Administration > Configuration):

| Property | Default | Description |
|---|---|---|
| `sonar.expiredcert.warningDays` | `60` | Days ahead of expiry to raise a warning issue |
| `sonar.expiredcert.keystorePasswords` | _(see below)_ | Comma-separated list of passwords to try when opening JKS/PKCS12 keystores |

### Keystore Passwords

The plugin tries passwords in this order:

1. Passwords listed in `sonar.expiredcert.keystorePasswords` (user-defined)
2. The built-in hardcoded fallback list (maintained in `src/main/resources/plugin-config.properties`)

To update the hardcoded fallback list, edit the `keystore.fallback.passwords` key in `src/main/resources/plugin-config.properties`. This is the single source of truth for default passwords — no recompilation of logic is needed, only update the config file and rebuild the plugin JAR.

### Example `sonar-project.properties`

```properties
sonar.expiredcert.warningDays=60
sonar.expiredcert.keystorePasswords=myCustomPass,anotherPass
```

---

## Project Structure

```
customSQ-expiredCert-rule/
├── pom.xml
├── README.md
└── src/
    ├── main/
    │   ├── java/com/shadowopentech/sonar/
    │   │   ├── ExpiredCertPlugin.java            # Entry point — registers all extensions
    │   │   ├── ExpiredCertRulesDefinition.java   # Declares the 2 rules + properties
    │   │   ├── ExpiredCertSensor.java            # Core sensor — finds, parses, reports
    │   │   └── cert/
    │   │       ├── CertificateInfo.java          # Data class: subject, alias, expiry, file
    │   │       ├── PemDerParser.java             # Parses PEM / DER / PKCS7
    │   │       └── KeyStoreParser.java           # Parses JKS / PKCS12 with password fallback
    │   └── resources/
    │       └── plugin-config.properties          # Default warning days + fallback passwords
    └── test/
        ├── java/com/shadowopentech/sonar/
        │   └── ExpiredCertSensorTest.java
        └── resources/
            ├── expired.pem
            ├── expiring-soon.pem
            ├── valid.pem
            ├── test-truststore.jks
            └── test-archive.jar
```

---

## Build & Install

**Requirements:** Java 11+, Maven 3.6+

```bash
mvn clean package
```

Copy the generated JAR from `target/` to `$SONARQUBE_HOME/extensions/plugins/` and restart SonarQube.

---

## Compatibility

| Component | Version |
|---|---|
| SonarQube | 9.9 LTS+ |
| SonarJava plugin | 7.30+ |
| Java (build) | 11+ |
| Languages scanned | All (language-agnostic) |
