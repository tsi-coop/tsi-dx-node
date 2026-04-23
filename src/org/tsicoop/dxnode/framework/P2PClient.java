package org.tsicoop.dxnode.framework;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.net.http.HttpClient;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.time.Duration;

/**
 * Factory for outbound P2P HttpClients.
 *
 * Builds a client whose TrustStore includes the Jetty transport cert baked into
 * the Docker image (loaded from $JETTY_BASE/etc/keystore.p12). This allows TLS
 * connections to peer nodes whose Jetty presents that dev transport cert.
 *
 * Falls back to trust-all when the keystore file is absent (non-Docker
 * environments, production behind a TLS-terminating proxy, etc.).
 */
public class P2PClient {

    public static HttpClient build(Duration timeout) {
        return build(timeout, HttpClient.Redirect.NEVER);
    }

    public static HttpClient build(Duration timeout, HttpClient.Redirect redirect) {
        try {
            String jettyBase = System.getenv().getOrDefault("JETTY_BASE", "/var/lib/jetty");
            String ksPass    = System.getenv().getOrDefault("P2P_KEYSTORE_PASS", "dev-p2p-tsi");
            java.io.File ksFile = new java.io.File(jettyBase + "/etc/keystore.p12");

            KeyStore trustStore = KeyStore.getInstance("PKCS12");
            trustStore.load(null, null);

            if (ksFile.exists()) {
                KeyStore transportKs = KeyStore.getInstance("PKCS12");
                try (FileInputStream fis = new FileInputStream(ksFile)) {
                    transportKs.load(fis, ksPass.toCharArray());
                }
                java.util.Enumeration<String> aliases = transportKs.aliases();
                while (aliases.hasMoreElements()) {
                    String a = aliases.nextElement();
                    java.security.cert.Certificate c = transportKs.getCertificate(a);
                    if (c != null) trustStore.setCertificateEntry("transport-" + a, c);
                }
            }

            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, tmf.getTrustManagers(), new java.security.SecureRandom());

            return HttpClient.newBuilder()
                    .sslContext(sslContext)
                    .connectTimeout(timeout)
                    .followRedirects(redirect)
                    .build();

        } catch (Exception e) {
            System.err.println("[P2PClient] SSL setup failed, falling back to trust-all: " + e.getMessage());
            return buildTrustAll(timeout, redirect);
        }
    }

    private static HttpClient buildTrustAll(Duration timeout, HttpClient.Redirect redirect) {
        try {
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, new TrustManager[]{new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                public void checkClientTrusted(X509Certificate[] c, String a) {}
                public void checkServerTrusted(X509Certificate[] c, String a) {}
            }}, new java.security.SecureRandom());
            return HttpClient.newBuilder()
                    .sslContext(sc)
                    .connectTimeout(timeout)
                    .followRedirects(redirect)
                    .build();
        } catch (Exception e) {
            return HttpClient.newBuilder().connectTimeout(timeout).followRedirects(redirect).build();
        }
    }
}
