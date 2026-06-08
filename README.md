# customSQ-expiredCert-rule

A custom SonarQube plugin that scans your entire project workspace for certificates in any format or location — including inside archives and nested archives — and reports certificates that are expired or expiring within a configurable window (default: 60 days).

---

## What It Does

This plugin registers a **language-agnostic file sensor** that runs on every SonarQube project regardless of the primary language (Java, Python, JavaScript, Go, etc.). It recursively scans all project files, extracts certificates from every supported format, evaluates expiry dates, and raises issues directly on the certificate file.

Issues are raised using SonarQube's **External Issue** mechanism (`NewExternalIssue` + `NewAdHocRule`), which means:
- No quality profile activation required
- Works for all languages automatically
- Issues always appear regardless of which rules are enabled

---

## Rules

| Rule Key | Default Severity | Description |
|---|---|---|
| `expiredcertrule:CertificateExpired` | INFO | Certificate has already passed its expiry date |
| `expiredcertrule:CertificateExpiringSoon` | INFO | Certificate expires within the configured warning window |
| `expiredcertrule:KeystorePasswordFailed` | INFO | Keystore could not be opened with any known password |

Severities for `CertificateExpired` and `CertificateExpiringSoon` are configurable globally and, optionally, per project (with a global master toggle to enforce the global value everywhere). See [Configuration](#configuration). `KeystorePasswordFailed` is always raised at INFO level.

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

Issues are raised at file level with full certificate details, including keystore alias and nested archive path where applicable:

> **Expired:** `Certificate 'CN=api.example.com, O=Example Corp' (alias: 'server-cert') in 'truststore.jks' expired on 2025-01-15. Replace it immediately.`

> **Expiring Soon:** `Certificate 'CN=api.example.com, O=Example Corp' (alias: 'server-cert') in 'truststore.jks' expires in 42 days on 2026-04-17. Renew before expiry.`

> **Nested archive:** `Certificate '...' in 'app.war!/WEB-INF/lib/crypto.jar!/certs/server.pem' expired on 2025-01-01. Replace it immediately.`

> **Password failed:** `Keystore 'certs/locked-keystore.jks' could not be opened with any known password. Certificates inside were not inspected. Add the correct password to sonar.expiredcert.keystorePasswords.`

---

## Configuration

### Global settings

Managed through the **SonarQube global Administration UI**:

> **Administration → Configuration → General Settings → Expired Certificate Rule**

| Property | Default | Description |
|---|---|---|
| `sonar.expiredcert.enabled` | `true` | Set to `false` to disable the sensor. Takes effect on the next scan — no restart needed. |
| `sonar.expiredcert.severity.expired` | `INFO` | **Global** severity for already-expired certificates. Accepted: `BLOCKER`, `CRITICAL`, `MAJOR`, `MINOR`, `INFO`. |
| `sonar.expiredcert.severity.expiringSoon` | `INFO` | **Global** severity for certificates expiring within the warning window. Same accepted values. |
| `sonar.expiredcert.severity.allowProjectOverrides` | `true` | **Master toggle.** When `false`, every project uses the global severities above and all per-project overrides are ignored. |
| `sonar.expiredcert.warningDays` | `60` | Days before expiry to raise a warning issue. Default sourced from `plugin-config.properties`. |
| `sonar.expiredcert.keystorePasswords` | _(fallback list)_ | Comma-separated passwords tried when opening JKS/PKCS12 keystores. Default sourced from `plugin-config.properties`. |

### Per-project settings

Set on an individual project: **Project → Administration → General Settings → Expired Certificate Rule**. These appear **only** on project pages (not globally) and are honoured only while `allowProjectOverrides` is `true`.

| Property | Description |
|---|---|
| `sonar.expiredcert.severity.expired.override` | Per-project severity for expired certificates. Leave blank to inherit the global value. |
| `sonar.expiredcert.severity.expiringSoon.override` | Per-project severity for expiring-soon certificates. Leave blank to inherit the global value. |

**Severity resolution:** project override (if set and overrides allowed) → global severity → built-in default (`INFO`). Setting `allowProjectOverrides=false` enforces the global severity everywhere — useful for an org-wide rollout (e.g. flip every project to `CRITICAL` at once).

### Keystore password resolution order

1. Passwords set in `sonar.expiredcert.keystorePasswords` (via admin UI)
2. The keystore's **own file name**, and its name without extension (e.g. `server.jks` → `server.jks`, `server`)
3. Built-in fallback list from `src/main/resources/plugin-config.properties`

If none of the passwords can open a keystore, a `KeystorePasswordFailed` issue (INFO) is raised so that the unopened keystore does not go unnoticed. Add the correct password to `sonar.expiredcert.keystorePasswords` to resolve it.

### Updating defaults without changing logic

`src/main/resources/plugin-config.properties` is the single source of truth for default `warningDays` and the fallback password list. Edit the relevant keys and rebuild the JAR — no logic changes needed:

```properties
expiredcert.warning.days=60
keystore.fallback.passwords=changeit,changeme,password,...
```

---

## Graceful Failure

The plugin is designed to never cause a scan to fail:

- Any unexpected exception during the scan is caught at the top level, logged as a warning, and the sensor exits cleanly
- A corrupted or unreadable file is skipped individually — it never aborts the scan of remaining files
- Other sensors and the overall scan result are always unaffected

---

## CI / CD

GitHub Actions workflow (`.github/workflows/ci.yml`) runs on every push and pull request to `main`:

| Job | Trigger | Description |
|---|---|---|
| **Build & Test** | Push + PR | Runs `mvn clean test` on Java 17 |
| **Pre-release** | Push to `main` only (after tests pass) | Builds plugin JAR and publishes a GitHub pre-release tagged `v{version}-pre.{run_number}` |

### Promoting to an official release

1. Go to **Releases** in this repo
2. Find the pre-release to promote
3. Click **Edit** → uncheck **This is a pre-release** → **Update release**

---

## Project Structure

```
customSQ-expiredCert-rule/
├── .github/workflows/ci.yml             # CI: test + pre-release on every push to main
├── pom.xml
├── README.md
└── src/
    ├── main/
    │   ├── java/com/shadowopentech/sonar/
    │   │   ├── ExpiredCertPlugin.java            # Entry point — registers sensor + properties
    │   │   ├── ExpiredCertRulesDefinition.java   # Constants + all 5 PropertyDefinition beans
    │   │   ├── ExpiredCertSensor.java            # Core sensor — walk, parse, report, graceful failure
    │   │   └── cert/
    │   │       ├── CertificateInfo.java          # Data class: subject, alias, expiry, source path
    │   │       ├── PemDerParser.java             # Parses PEM / DER / PKCS7
    │   │       └── KeyStoreParser.java           # Parses JKS / PKCS12 with ordered password fallback
    │   └── resources/
    │       └── plugin-config.properties          # Default warningDays + fallback keystore passwords
    └── test/
        ├── java/com/shadowopentech/sonar/
        │   ├── ExpiredCertSensorTest.java        # Sensor integration tests (13 tests)
        │   └── cert/
        │       ├── PemDerParserTest.java         # Parser unit tests (6 tests)
        │       └── KeyStoreParserTest.java       # Keystore parser unit tests (6 tests)
        └── resources/
            ├── expired.pem
            ├── expiring-soon.pem
            ├── valid.pem
            ├── chain.pem
            ├── test-truststore.jks
            ├── test-archive.jar
            └── nested-archive.zip
```

---

## Build & Install

**Requirements:** Java 17+, Maven 3.6+

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
| Java (build) | 17+ |
| Languages scanned | All (language-agnostic) |
