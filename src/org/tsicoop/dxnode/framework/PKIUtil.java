package org.tsicoop.dxnode.framework;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.bouncycastle.util.test.FixedSecureRandom;
import org.json.simple.JSONObject;

import java.io.StringReader;
import java.io.StringWriter;
import org.bouncycastle.util.test.FixedSecureRandom.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Date;
import java.util.regex.Pattern;

public class PKIUtil {

    static {
        // Add Bouncy Castle as a security provider
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * Generates a new RSA KeyPair and a Certificate Signing Request (CSR).
     *
     * @param commonName   The Common Name (CN) for the CSR (e.g., dxnode.yourcompany.com).
     * @param organization The Organization (O) for the CSR (e.g., YourCompany Inc.).
     * @return A JSONObject containing the PEM-encoded CSR and the PEM-encoded Private Key.
     * @throws Exception if key generation or CSR creation fails.
     */
    public static JSONObject generateCSR(String commonName, String organization) throws Exception {
        // 1. Generate RSA KeyPair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGenerator.initialize(2048, new SecureRandom()); // 2048-bit RSA key
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // 2. Create X500Name for Subject
        X500Name subject = new X500Name("CN=" + commonName + ", O=" + organization);

        // 3. Create ContentSigner for signing the CSR
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC")
                .build(keyPair.getPrivate());

        // 4. Build the PKCS10CertificationRequest (CSR)
        PKCS10CertificationRequestBuilder csrBuilder = new PKCS10CertificationRequestBuilder(
                subject,
                SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded())
        );
        PKCS10CertificationRequest csr = csrBuilder.build(contentSigner);

        // 5. Encode CSR to PEM format
        StringWriter csrWriter = new StringWriter();
        PemWriter pemWriter = new PemWriter(csrWriter);
        pemWriter.writeObject(new PemObject("CERTIFICATE REQUEST", csr.getEncoded()));
        pemWriter.close();
        String csrPem = csrWriter.toString();

        // 6. Encode Private Key to PEM format (PKCS#8 format is common for Java)
        StringWriter privateKeyWriter = new StringWriter();
        pemWriter = new PemWriter(privateKeyWriter);
        pemWriter.writeObject(new PemObject("PRIVATE KEY", keyPair.getPrivate().getEncoded()));
        pemWriter.close();
        String privateKeyPem = privateKeyWriter.toString();

        JSONObject result = new JSONObject();
        result.put("csr_pem", csrPem);
        result.put("private_key_pem", privateKeyPem);
        return result;
    }

    /**
     * Checks if a given PEM-encoded X.509 certificate matches a given PEM-encoded private key.
     *
     * @param certificatePem The PEM-encoded X.509 certificate.
     * @param privateKeyPem  The PEM-encoded private key.
     * @return true if the certificate and private key match, false otherwise.
     * @throws Exception if parsing fails or cryptographic operations encounter an issue.
     */
    public static boolean isCertificatePrivateKeyMatch(String certificatePem, String privateKeyPem) throws Exception {
        // 1. Parse the certificate
        X509Certificate certificate = parseCertificatePem(certificatePem);

        // 2. Parse the private key
        PrivateKey privateKey = parsePrivateKeyPem(privateKeyPem);

        // 3. Verify if the public key from the certificate matches the private key
        PublicKey publicKeyFromCert = certificate.getPublicKey();

        // A simple way to check is to sign some data with the private key
        // and verify it with the public key from the certificate.
        try {
            byte[] testData = "test_data_for_key_match_check".getBytes();
            Signature signature = Signature.getInstance(certificate.getSigAlgName(), "BC");
            signature.initSign(privateKey);
            signature.update(testData);
            byte[] signedData = signature.sign();

            signature.initVerify(publicKeyFromCert);
            signature.update(testData);
            return signature.verify(signedData);
        } catch (InvalidKeyException e) {
            // This often means the keys don't match or are of the wrong type for the algorithm
            return false;
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("Signature algorithm not found: " + certificate.getSigAlgName(), e);
        } catch (SignatureException e) {
            throw new Exception("Signature operation failed during key match check.", e);
        }
    }

    /**
     * Extracts common details from a PEM-encoded X.509 certificate.
     *
     * @param certificatePem The PEM-encoded X.509 certificate.
     * @return A JSONObject containing certificate details like common_name, issuer, issued_at_iso, expires_at_iso.
     * @throws Exception if parsing fails.
     */
    public static JSONObject getCertificateDetails(String certificatePem) throws Exception {
        X509Certificate certificate = parseCertificatePem(certificatePem);
        JSONObject details = new JSONObject();

        // Extract Common Name from Subject DN
        String subjectDN = certificate.getSubjectX500Principal().getName();
        String commonName = extractRdnValue(subjectDN, "CN");
        if (commonName == null) {
            // Fallback: try to get from Subject Alternative Names (SANs) if CN is missing
            // This is a more robust approach for modern certificates
            // (Requires more complex BouncyCastle parsing for SANs)
            commonName = subjectDN; // Default to full subject DN if CN not found
        }

        details.put("common_name", commonName);
        details.put("issuer", certificate.getIssuerX500Principal().getName());

        // Format dates to ISO 8601 string
        DateTimeFormatter formatter = DateTimeFormatter.ISO_INSTANT.withZone(ZoneOffset.UTC);
        details.put("issued_at_iso", certificate.getNotBefore().toInstant().atZone(ZoneOffset.UTC).format(formatter));
        details.put("expires_at_iso", certificate.getNotAfter().toInstant().atZone(ZoneOffset.UTC).format(formatter));
        details.put("serial_number", certificate.getSerialNumber().toString());
        details.put("signature_algorithm", certificate.getSigAlgName());

        return details;
    }

    /**
     * Helper method to parse a PEM-encoded X.509 certificate.
     */
    private static X509Certificate parseCertificatePem(String certificatePem) throws Exception {
        try (PEMParser pemParser = new PEMParser(new StringReader(certificatePem))) {
            Object parsedObject = pemParser.readObject();
            if (parsedObject instanceof X509CertificateHolder) {
                return new JcaX509CertificateConverter().setProvider("BC").getCertificate((X509CertificateHolder) parsedObject);
            } else if (parsedObject instanceof java.security.cert.X509Certificate) {
                return (java.security.cert.X509Certificate) parsedObject;
            } else {
                throw new IllegalArgumentException("Provided PEM string is not a valid X.509 certificate.");
            }
        }
    }

    /**
     * Helper method to parse a PEM-encoded Private Key.
     */
    private static PrivateKey parsePrivateKeyPem(String privateKeyPem) throws Exception {
        try (PEMParser pemParser = new PEMParser(new StringReader(privateKeyPem))) {
            Object parsedObject = pemParser.readObject();
            if (parsedObject instanceof PEMKeyPair) {
                return new JcaPEMKeyConverter().setProvider("BC").getPrivateKey(((PEMKeyPair) parsedObject).getPrivateKeyInfo());
            } else if (parsedObject instanceof PrivateKey) {
                return (PrivateKey) parsedObject;
            } else {
                throw new IllegalArgumentException("Provided PEM string is not a valid private key.");
            }
        }
    }

    /**
     * Helper to extract a specific RDN value (e.g., "CN") from an X.500 Distinguished Name string.
     * This is a simplified parser and might not handle all complex DN formats.
     */
    private static String extractRdnValue(String dn, String rdnType) {
        Pattern pattern = Pattern.compile(rdnType + "=(.*?)(?:,|$)", Pattern.CASE_INSENSITIVE);
        java.util.regex.Matcher matcher = pattern.matcher(dn);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return null;
    }

    // --- Main method for testing (can be removed in production) ---
    public static void main(String[] args) {
        try {
            // Test generateCSR
            JSONObject csrResult = generateCSR("testnode.example.com", "TestOrg");
            String csrPem = (String) csrResult.get("csr_pem");
            String privateKeyPem = (String) csrResult.get("private_key_pem");

            System.out.println("Generated CSR:\n" + csrPem);
            System.out.println("\nGenerated Private Key:\n" + privateKeyPem);

            // Simulate a self-signed certificate for testing the match and details extraction
            // In a real scenario, the CSR would be sent to a CA and a signed certificate returned.
            // For simplicity, we'll create a dummy self-signed cert here.
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
            keyPairGenerator.initialize(2048, new SecureRandom());
            KeyPair selfSignedKeyPair = keyPairGenerator.generateKeyPair();

            X500Name issuer = new X500Name("CN=Test CA, O=TestOrg");
            X500Name subject = new X500Name("CN=testnode.example.com, O=TestOrg"); // Matches CSR subject

            //FixedSecureRandom.BigInteger serial = new BigInteger().valueOf(System.currentTimeMillis());
            Date notBefore = Date.from(Instant.now().minusSeconds(3600)); // 1 hour ago
            Date notAfter = Date.from(Instant.now().plusSeconds(365 * 24 * 3600)); // 1 year from now

         /*   X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
                    issuer, serial, notBefore, notAfter, subject,
                    SubjectPublicKeyInfo.getInstance(selfSignedKeyPair.getPublic().getEncoded())
            );

            ContentSigner certSigner = new JcaContentSignerBuilder("SHA256withRSA")
                    .setProvider("BC")
                    .build(selfSignedKeyPair.getPrivate());

            X509CertificateHolder certHolder = certBuilder.build(certSigner);
            X509Certificate selfSignedCert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);

            StringWriter certWriter = new StringWriter();
            PemWriter pemWriter = new PemWriter(certWriter);
            pemWriter.writeObject(new PemObject("CERTIFICATE", selfSignedCert.getEncoded()));
            pemWriter.close();
            String selfSignedCertPem = certWriter.toString();

            System.out.println("\nSimulated Self-Signed Certificate:\n" + selfSignedCertPem);

            // Test isCertificatePrivateKeyMatch with matching keys
            boolean match1 = isCertificatePrivateKeyMatch(selfSignedCertPem, privateKeyPem); // Should be false if privateKeyPem is from different keypair
            System.out.println("\nDoes generated CSR's private key match simulated cert? (Should be false): " + match1);

            // Test isCertificatePrivateKeyMatch with the actual matching keypair
            StringWriter actualPrivateKeyWriter = new StringWriter();
            pemWriter = new PemWriter(actualPrivateKeyWriter);
            pemWriter.writeObject(new PemObject("PRIVATE KEY", selfSignedKeyPair.getPrivate().getEncoded()));
            pemWriter.close();
            String actualPrivateKeyPem = actualPrivateKeyWriter.toString();

            boolean match2 = isCertificatePrivateKeyMatch(selfSignedCertPem, actualPrivateKeyPem);
            System.out.println("Does simulated cert match its own private key? (Should be true): " + match2);


            // Test getCertificateDetails
            JSONObject certDetails = getCertificateDetails(selfSignedCertPem);
            System.out.println("\nCertificate Details: " + certDetails.toJSONString());*/

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}