package org.tsicoop.dxnode.framework;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
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
import org.json.simple.JSONObject;

import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
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
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGenerator.initialize(2048, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        X500Name subject = new X500Name("CN=" + commonName + ", O=" + organization);

        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC")
                .build(keyPair.getPrivate());

        PKCS10CertificationRequestBuilder csrBuilder = new PKCS10CertificationRequestBuilder(
                subject,
                SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded())
        );
        PKCS10CertificationRequest csr = csrBuilder.build(contentSigner);

        StringWriter csrWriter = new StringWriter();
        PemWriter pemWriter = new PemWriter(csrWriter);
        pemWriter.writeObject(new PemObject("CERTIFICATE REQUEST", csr.getEncoded()));
        pemWriter.close();
        String csrPem = csrWriter.toString();

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
     * @param privateKeyPem  The PEM-encoded private key (PKCS#1 or PKCS#8).
     * @return true if the certificate and private key match, false otherwise.
     * @throws Exception if parsing fails or cryptographic operations encounter an issue.
     */
    public static boolean isCertificatePrivateKeyMatch(String certificatePem, String privateKeyPem) throws Exception {
        X509Certificate certificate = parseCertificatePem(certificatePem);
        PrivateKey privateKey = parsePrivateKeyPem(privateKeyPem);
        PublicKey publicKeyFromCert = certificate.getPublicKey();

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
     * @return A JSONObject containing certificate details.
     * @throws Exception if parsing fails.
     */
    public static JSONObject getCertificateDetails(String certificatePem) throws Exception {
        X509Certificate certificate = parseCertificatePem(certificatePem);
        JSONObject details = new JSONObject();

        String subjectDN = certificate.getSubjectX500Principal().getName();
        String commonName = extractRdnValue(subjectDN, "CN");
        if (commonName == null) {
            commonName = subjectDN;
        }

        details.put("common_name", commonName);
        details.put("issuer", certificate.getIssuerX500Principal().getName());

        DateTimeFormatter formatter = DateTimeFormatter.ISO_INSTANT.withZone(ZoneOffset.UTC);
        details.put("issued_at_iso", certificate.getNotBefore().toInstant().atZone(ZoneOffset.UTC).format(formatter));
        details.put("expires_at_iso", certificate.getNotAfter().toInstant().atZone(ZoneOffset.UTC).format(formatter));
        details.put("serial_number", certificate.getSerialNumber().toString());
        details.put("signature_algorithm", certificate.getSigAlgName());

        return details;
    }

    /**
     * Parses a PEM-encoded X.509 certificate.
     */
    private static X509Certificate parseCertificatePem(String certificatePem) throws Exception {
        try (PEMParser pemParser = new PEMParser(new StringReader(certificatePem))) {
            Object parsedObject = pemParser.readObject();
            if (parsedObject instanceof X509CertificateHolder) {
                return new JcaX509CertificateConverter().setProvider("BC")
                        .getCertificate((X509CertificateHolder) parsedObject);
            } else if (parsedObject instanceof X509Certificate) {
                return (X509Certificate) parsedObject;
            } else {
                throw new IllegalArgumentException("Provided PEM string is not a valid X.509 certificate. "
                        + "PEMParser returned: " + (parsedObject == null ? "null" : parsedObject.getClass().getName()));
            }
        }
    }

    /**
     * Parses a PEM-encoded private key — handles all three cases that BouncyCastle's
     * PEMParser can return for a private key PEM:
     *
     *   1. PrivateKeyInfo      — PKCS#8 unencrypted (-----BEGIN PRIVATE KEY-----)
     *      This is what PEMParser actually returns for PKCS#8. The original code only
     *      checked for PEMKeyPair and raw PrivateKey, so this case fell through to the
     *      else-branch and threw "not a valid private key" — which was the root bug.
     *
     *   2. PEMKeyPair          — PKCS#1 (-----BEGIN RSA PRIVATE KEY-----)
     *      PEMParser returns a PEMKeyPair containing both public and private key info.
     *
     *   3. PrivateKey          — rare; only if something already handed us a Java object.
     */
    private static PrivateKey parsePrivateKeyPem(String privateKeyPem) throws Exception {
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");

        try (PEMParser pemParser = new PEMParser(new StringReader(privateKeyPem))) {
            Object parsedObject = pemParser.readObject();

            if (parsedObject == null) {
                throw new IllegalArgumentException(
                        "Provided PEM string is not a valid private key: PEMParser returned null. "
                        + "Check that the PEM headers and Base64 body are well-formed.");
            }

            // ---------------------------------------------------------------
            // FIX: Handle PrivateKeyInfo — this is what PEMParser returns for
            // a PKCS#8 "-----BEGIN PRIVATE KEY-----" PEM. The original code
            // was missing this branch entirely, causing the validation failure.
            // ---------------------------------------------------------------
            if (parsedObject instanceof PrivateKeyInfo) {
                return converter.getPrivateKey((PrivateKeyInfo) parsedObject);
            }

            // PKCS#1 — "-----BEGIN RSA PRIVATE KEY-----"
            // PEMParser returns a PEMKeyPair for this format.
            if (parsedObject instanceof PEMKeyPair) {
                return converter.getPrivateKey(((PEMKeyPair) parsedObject).getPrivateKeyInfo());
            }

            // Fallback: already a Java PrivateKey object (uncommon but safe to handle)
            if (parsedObject instanceof PrivateKey) {
                return (PrivateKey) parsedObject;
            }

            throw new IllegalArgumentException(
                    "Provided PEM string is not a valid private key. "
                    + "PEMParser returned unexpected type: " + parsedObject.getClass().getName());
        }
    }

    /**
     * Extracts a specific RDN value (e.g., "CN") from an X.500 Distinguished Name string.
     */
    private static String extractRdnValue(String dn, String rdnType) {
        Pattern pattern = Pattern.compile(rdnType + "=(.*?)(?:,|$)", Pattern.CASE_INSENSITIVE);
        java.util.regex.Matcher matcher = pattern.matcher(dn);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return null;
    }

    // --- Main method for testing ---
    public static void main(String[] args) {
        try {
            JSONObject csrResult = generateCSR("testnode.example.com", "TestOrg");
            String csrPem = (String) csrResult.get("csr_pem");
            String privateKeyPem = (String) csrResult.get("private_key_pem");

            System.out.println("Generated CSR:\n" + csrPem);
            System.out.println("\nGenerated Private Key:\n" + privateKeyPem);

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
            keyPairGenerator.initialize(2048, new SecureRandom());
            KeyPair selfSignedKeyPair = keyPairGenerator.generateKeyPair();

            X500Name issuer  = new X500Name("CN=Test CA, O=TestOrg");
            X500Name subject = new X500Name("CN=testnode.example.com, O=TestOrg");

            BigInteger serial    = BigInteger.valueOf(System.currentTimeMillis());
            Date       notBefore = Date.from(Instant.now().minusSeconds(3600));
            Date       notAfter  = Date.from(Instant.now().plusSeconds(365L * 24 * 3600));

            SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(selfSignedKeyPair.getPublic().getEncoded());
            X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
                    issuer, serial, notBefore, notAfter, subject, publicKeyInfo);

            ContentSigner certSigner = new JcaContentSignerBuilder("SHA256withRSA")
                    .setProvider("BC")
                    .build(selfSignedKeyPair.getPrivate());

            X509CertificateHolder certHolder  = certBuilder.build(certSigner);
            X509Certificate selfSignedCert    = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);

            StringWriter certWriter = new StringWriter();
            PemWriter pemWriter = new PemWriter(certWriter);
            pemWriter.writeObject(new PemObject("CERTIFICATE", selfSignedCert.getEncoded()));
            pemWriter.close();
            String selfSignedCertPem = certWriter.toString();

            System.out.println("\nSimulated Self-Signed Certificate:\n" + selfSignedCertPem);

            boolean match1 = isCertificatePrivateKeyMatch(selfSignedCertPem, privateKeyPem);
            System.out.println("\nCSR private key vs simulated cert (expect false): " + match1);

            StringWriter actualPrivateKeyWriter = new StringWriter();
            pemWriter = new PemWriter(actualPrivateKeyWriter);
            pemWriter.writeObject(new PemObject("PRIVATE KEY", selfSignedKeyPair.getPrivate().getEncoded()));
            pemWriter.close();
            String actualPrivateKeyPem = actualPrivateKeyWriter.toString();

            boolean match2 = isCertificatePrivateKeyMatch(selfSignedCertPem, actualPrivateKeyPem);
            System.out.println("Cert's own private key vs cert (expect true): " + match2);

            JSONObject certDetails = getCertificateDetails(selfSignedCertPem);
            System.out.println("\nCertificate Details: " + certDetails.toJSONString());

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}