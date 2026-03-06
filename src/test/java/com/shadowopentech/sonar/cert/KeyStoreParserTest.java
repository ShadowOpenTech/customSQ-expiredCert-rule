package com.shadowopentech.sonar.cert;

import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.time.LocalDate;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class KeyStoreParserTest {

    private final KeyStoreParser parser = new KeyStoreParser();

    private InputStream resource(String name) {
        InputStream is = getClass().getClassLoader().getResourceAsStream(name);
        assertNotNull(is, "Test resource not found: " + name);
        return is;
    }

    @Test
    void parsesJksWithCorrectPassword() throws Exception {
        try (InputStream is = resource("test-truststore.jks")) {
            List<CertificateInfo> certs = parser.parse(is, "test-truststore.jks", "JKS",
                    List.of("changeit"));

            assertFalse(certs.isEmpty(), "Expected at least one cert from JKS");
            assertTrue(certs.stream().anyMatch(c -> c.getSubject().contains("jks-expired.example.com")),
                    "Expected expired alias in JKS");
            assertTrue(certs.stream().anyMatch(c -> c.getSubject().contains("jks-valid.example.com")),
                    "Expected valid alias in JKS");
        }
    }

    @Test
    void expiredAliasHasPastExpiryDate() throws Exception {
        try (InputStream is = resource("test-truststore.jks")) {
            List<CertificateInfo> certs = parser.parse(is, "test-truststore.jks", "JKS",
                    List.of("changeit"));

            CertificateInfo expired = certs.stream()
                    .filter(c -> c.getSubject().contains("jks-expired"))
                    .findFirst()
                    .orElseThrow(() -> new AssertionError("Expired cert not found in JKS"));

            assertTrue(expired.getExpiryDate().isBefore(LocalDate.now()),
                    "Expected past expiry, got: " + expired.getExpiryDate());
        }
    }

    @Test
    void aliasIsPopulated() throws Exception {
        try (InputStream is = resource("test-truststore.jks")) {
            List<CertificateInfo> certs = parser.parse(is, "test-truststore.jks", "JKS",
                    List.of("changeit"));

            assertTrue(certs.stream().allMatch(c -> c.getAlias() != null),
                    "All JKS certs should have an alias");
        }
    }

    @Test
    void returnsEmptyOnWrongPassword() throws Exception {
        try (InputStream is = resource("test-truststore.jks")) {
            List<CertificateInfo> certs = parser.parse(is, "test-truststore.jks", "JKS",
                    List.of("wrongpassword", "alsoWrong"));
            assertTrue(certs.isEmpty(), "Expected empty result for wrong passwords");
        }
    }

    @Test
    void triesFallbackPasswordsInOrder() throws Exception {
        try (InputStream is = resource("test-truststore.jks")) {
            // First two passwords wrong, third is correct
            List<CertificateInfo> certs = parser.parse(is, "test-truststore.jks", "JKS",
                    List.of("wrong1", "wrong2", "changeit"));
            assertFalse(certs.isEmpty(), "Expected certs after fallback to 'changeit'");
        }
    }

    @Test
    void returnsEmptyForGarbageBytes() {
        InputStream is = new java.io.ByteArrayInputStream("not a keystore".getBytes());
        List<CertificateInfo> certs = parser.parse(is, "bad.jks", "JKS", List.of("changeit"));
        assertTrue(certs.isEmpty());
    }
}
