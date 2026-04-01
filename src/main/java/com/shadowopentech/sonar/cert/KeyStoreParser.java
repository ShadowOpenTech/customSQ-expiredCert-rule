package com.shadowopentech.sonar.cert;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Parses JKS and PKCS#12 keystore files.
 *
 * Tries each provided password in order until one succeeds. Scans every alias
 * in the keystore, including full certificate chains for key entries.
 */
public class KeyStoreParser {

    /**
     * Parses all X.509 certificates from a keystore input stream.
     *
     * @param inputStream   raw bytes of the keystore
     * @param sourcePath    display path used in issue messages
     * @param keystoreType  "JKS" or "PKCS12"
     * @param passwords     ordered list of passwords to try; null/empty string = no-password keystore
     * @return list of parsed certificates; empty if no password succeeded or file is unreadable
     */
    public List<CertificateInfo> parse(InputStream inputStream, String sourcePath,
                                       String keystoreType, List<String> passwords) {
        byte[] data;
        try {
            data = inputStream.readAllBytes();
        } catch (Exception e) {
            return Collections.emptyList();
        }

        for (String password : passwords) {
            List<CertificateInfo> result = tryParse(data, sourcePath, keystoreType, password);
            if (result != null) {
                return result;
            }
        }

        // All passwords failed — return null so the caller can distinguish this
        // from "opened successfully but contained no certificates" (empty list)
        return null;
    }

    /**
     * Attempts to open the keystore with the given password.
     *
     * @return list of certs on success, null if the password is wrong or the type mismatches
     */
    private List<CertificateInfo> tryParse(byte[] data, String sourcePath,
                                           String keystoreType, String password) {
        try {
            KeyStore keyStore = KeyStore.getInstance(keystoreType);
            // Use toCharArray() even for empty strings — passing null to keyStore.load()
            // skips integrity verification, which would make any keystore "openable"
            char[] pwd = password == null ? new char[0] : password.toCharArray();
            keyStore.load(new ByteArrayInputStream(data), pwd);

            List<CertificateInfo> result = new ArrayList<>();

            for (String alias : Collections.list(keyStore.aliases())) {
                // Primary certificate for this alias
                java.security.cert.Certificate cert = keyStore.getCertificate(alias);
                if (cert instanceof X509Certificate x509) {
                    result.add(PemDerParser.toCertificateInfo(x509, alias, sourcePath));
                }

                // Certificate chain entries (index 0 is the leaf, already added above)
                if (keyStore.isKeyEntry(alias)) {
                    java.security.cert.Certificate[] chain = keyStore.getCertificateChain(alias);
                    if (chain != null) {
                        for (int i = 1; i < chain.length; i++) {
                            if (chain[i] instanceof X509Certificate x509Chain) {
                                String chainAlias = alias + "[chain:" + i + "]";
                                result.add(PemDerParser.toCertificateInfo(x509Chain, chainAlias, sourcePath));
                            }
                        }
                    }
                }
            }

            return result;

        } catch (Exception e) {
            return null; // Wrong password or wrong keystore type — caller tries next password
        }
    }
}
