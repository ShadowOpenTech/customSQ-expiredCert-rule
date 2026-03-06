package com.shadowopentech.sonar.cert;

import java.time.LocalDate;

/**
 * Immutable data class representing a parsed certificate and its source location.
 */
public class CertificateInfo {

    private final String subject;
    private final String alias;
    private final LocalDate expiryDate;
    private final String sourcePath;

    /**
     * @param subject    X.500 distinguished name of the certificate subject
     * @param alias      keystore alias, or null for standalone certificate files
     * @param expiryDate the certificate's notAfter date
     * @param sourcePath display path including any archive nesting (e.g. app.war!/WEB-INF/server.pem)
     */
    public CertificateInfo(String subject, String alias, LocalDate expiryDate, String sourcePath) {
        this.subject = subject;
        this.alias = alias;
        this.expiryDate = expiryDate;
        this.sourcePath = sourcePath;
    }

    public String getSubject() {
        return subject;
    }

    /** Returns the keystore alias, or null if this cert came from a standalone file. */
    public String getAlias() {
        return alias;
    }

    public LocalDate getExpiryDate() {
        return expiryDate;
    }

    /** Display path, may include archive nesting separators (!/). */
    public String getSourcePath() {
        return sourcePath;
    }
}
