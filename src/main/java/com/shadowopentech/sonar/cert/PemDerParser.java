package com.shadowopentech.sonar.cert;

import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

/**
 * Parses PEM, DER, and PKCS#7 certificate files.
 *
 * Uses Java's built-in CertificateFactory which handles all three formats
 * through a single generateCertificates() call, including multi-cert PEM chains.
 */
public class PemDerParser {

    /**
     * Parses all X.509 certificates from the given input stream.
     *
     * @param inputStream  raw bytes of a PEM, DER, or PKCS#7 file
     * @param sourcePath   display path used in issue messages
     * @return list of parsed certificates; empty if none found or format unrecognised
     */
    public List<CertificateInfo> parse(InputStream inputStream, String sourcePath) {
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            Collection<? extends java.security.cert.Certificate> certs =
                    factory.generateCertificates(inputStream);

            List<CertificateInfo> result = new ArrayList<>();
            for (java.security.cert.Certificate cert : certs) {
                if (cert instanceof X509Certificate x509) {
                    result.add(toCertificateInfo(x509, null, sourcePath));
                }
            }
            return result;

        } catch (Exception e) {
            // Unrecognised format or corrupted file — skip silently
            return Collections.emptyList();
        }
    }

    static CertificateInfo toCertificateInfo(X509Certificate x509, String alias, String sourcePath) {
        String subject = x509.getSubjectX500Principal().getName();
        java.time.LocalDate expiry = x509.getNotAfter()
                .toInstant()
                .atZone(ZoneId.systemDefault())
                .toLocalDate();
        return new CertificateInfo(subject, alias, expiry, sourcePath);
    }
}
