# CLAUDE.md

## Project Overview

Custom SonarQube plugin that scans project workspaces for SSL/TLS certificates and raises issues for expired, expiring-soon, or uninspectable certificates. Language-agnostic — runs on every SonarQube project regardless of language.

## Build & Test

```bash
mvn clean package          # build plugin JAR (target/customSQ-expiredCert-rule-1.0.0.jar)
mvn clean test             # run all 25 tests
mvn test -Dtest=ClassName  # run a specific test class
```

**Requirements:** Java 17+, Maven 3.6+

## Deploy to Local SonarQube

```bash
cp target/customSQ-expiredCert-rule-1.0.0.jar /Users/cyberdevil/Tools/SonarQube/plugins/
cd /Users/cyberdevil/Tools/SonarQube && docker compose down && docker compose up -d
```

Test project for manual verification: `/Users/cyberdevil/codeWorkspace/customSQ-expiredCert-rule_test`

## Architecture

### Key Design Decisions

- **External issues, not rules:** Issues use `NewExternalIssue` + `NewAdHocRule` (NOT `RulesDefinition`). This makes them language-agnostic — no quality profile activation needed. Do not switch to the traditional rules API.
- **Sensor must never throw:** Top-level `try/catch` in `execute()`, per-file error isolation in the file walker, per-entry isolation in archive processing. A corrupted file must never abort the scan.
- **`KeyStoreParser.parse()` return contract:** Returns `null` when no password works (caller should raise `KeystorePasswordFailed`). Returns empty list when opened successfully but no certs found. Never confuse the two.
- **Never pass `null` to `KeyStore.load()`:** Passing `null` as the password skips integrity verification, making any keystore appear openable. Always use `new char[0]` for empty/no-password keystores.

### Source Layout

```
src/main/java/com/shadowopentech/sonar/
├── ExpiredCertPlugin.java            # Entry point — registers sensor + properties
├── ExpiredCertRulesDefinition.java   # Rule constants + 5 PropertyDefinition beans
├── ExpiredCertSensor.java            # Core sensor: walk → parse → report
└── cert/
    ├── CertificateInfo.java          # Immutable data class
    ├── PemDerParser.java             # PEM / DER / PKCS#7
    └── KeyStoreParser.java           # JKS / PKCS#12 with password fallback
```

### Three Rules

| Rule ID | Trigger | Severity |
|---|---|---|
| `CertificateExpired` | `notAfter <= today` | Configurable (default INFO) |
| `CertificateExpiringSoon` | `notAfter <= today + warningDays` | Configurable (default INFO) |
| `KeystorePasswordFailed` | No password in dictionary opens the keystore | Always INFO |

### Password Resolution

1. User-configured passwords from `sonar.expiredcert.keystorePasswords`
2. Fallback list from `src/main/resources/plugin-config.properties`

The password list is used for all keystore formats: JKS (`.jks`, `.keystore`) and PKCS#12 (`.p12`, `.pfx`).

### File Routing (by extension)

- `.pem`, `.crt`, `.cer`, `.cert`, `.der`, `.p7b`, `.p7c` → `PemDerParser`
- `.jks`, `.keystore`, `.p12`, `.pfx` → `KeyStoreParser`
- `.jar`, `.war`, `.ear`, `.zip`, `.aar` → recursive in-memory archive extraction

### Directories Skipped

`.git`, `node_modules`, `target`, `build`, `.mvn`, `.gradle`, `.idea`, `.vscode`, `__pycache__`, `.tox`

## Testing

- **`ExpiredCertSensorTest`** — sensor integration tests using `SensorContextTester`
- **`PemDerParserTest`** — PEM/DER parser unit tests
- **`KeyStoreParserTest`** — keystore parser unit tests, including null-return on wrong password

Test resources (certs, keystores, archives) are in `src/test/resources/`.

When adding new certificate formats or rules, always add corresponding test resources and test cases.

## Configuration Properties

All 5 properties are global admin UI only (no project-level). Defined in `ExpiredCertRulesDefinition.propertyDefinitions()`. Defaults sourced from `plugin-config.properties`.

## CI/CD

GitHub Actions (`.github/workflows/ci.yml`): build + test on every push/PR, pre-release JAR on push to main.
