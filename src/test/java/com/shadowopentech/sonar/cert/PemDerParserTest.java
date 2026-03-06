package com.shadowopentech.sonar.cert;

import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.time.LocalDate;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class PemDerParserTest {

    private final PemDerParser parser = new PemDerParser();

    private InputStream resource(String name) {
        InputStream is = getClass().getClassLoader().getResourceAsStream(name);
        assertNotNull(is, "Test resource not found: " + name);
        return is;
    }

    @Test
    void parsesExpiredCert() throws Exception {
        try (InputStream is = resource("expired.pem")) {
            List<CertificateInfo> certs = parser.parse(is, "expired.pem");
            assertEquals(1, certs.size());

            CertificateInfo cert = certs.get(0);
            assertTrue(cert.getSubject().contains("expired.example.com"));
            assertNull(cert.getAlias());
            assertTrue(cert.getExpiryDate().isBefore(LocalDate.now()),
                    "Expected expiry date in the past, got: " + cert.getExpiryDate());
        }
    }

    @Test
    void parsesExpiringSoonCert() throws Exception {
        try (InputStream is = resource("expiring-soon.pem")) {
            List<CertificateInfo> certs = parser.parse(is, "expiring-soon.pem");
            assertEquals(1, certs.size());

            LocalDate expiry = certs.get(0).getExpiryDate();
            assertTrue(expiry.isAfter(LocalDate.now()), "Expected future expiry, got: " + expiry);
            assertTrue(expiry.isBefore(LocalDate.now().plusDays(61)),
                    "Expected expiry within 60 days, got: " + expiry);
        }
    }

    @Test
    void parsesValidCert() throws Exception {
        try (InputStream is = resource("valid.pem")) {
            List<CertificateInfo> certs = parser.parse(is, "valid.pem");
            assertEquals(1, certs.size());
            assertTrue(certs.get(0).getExpiryDate().isAfter(LocalDate.now().plusDays(60)),
                    "Expected healthy cert, got: " + certs.get(0).getExpiryDate());
        }
    }

    @Test
    void parsesMultiCertPemChain() throws Exception {
        try (InputStream is = resource("chain.pem")) {
            List<CertificateInfo> certs = parser.parse(is, "chain.pem");
            assertEquals(2, certs.size(), "Expected 2 certs in chain");
        }
    }

    @Test
    void returnsEmptyForGarbage() {
        InputStream is = new java.io.ByteArrayInputStream("not a certificate".getBytes());
        List<CertificateInfo> certs = parser.parse(is, "garbage.pem");
        assertTrue(certs.isEmpty());
    }

    @Test
    void sourcePathPropagated() throws Exception {
        try (InputStream is = resource("expired.pem")) {
            List<CertificateInfo> certs = parser.parse(is, "some/nested/path.pem");
            assertEquals("some/nested/path.pem", certs.get(0).getSourcePath());
        }
    }
}
