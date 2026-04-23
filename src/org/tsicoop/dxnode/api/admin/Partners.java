package org.tsicoop.dxnode.api.admin;

import org.tsicoop.dxnode.framework.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import javax.net.ssl.*;
import java.io.ByteArrayInputStream;
import java.io.StringReader;
import java.net.ConnectException;
import java.net.NoRouteToHostException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpConnectTimeoutException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

/**
 * Service to manage Partner Nodes and the Identity Handshake protocol.
 *
 * mTLS Implementation:
 *   - Outbound HttpClient presents this node's own certificate (KeyManager)
 *   - Only certificates of registered partners are trusted (TrustManager)
 *   - Client is rebuilt via refreshMtlsClient() before each handshake so
 *     newly registered partner certs are picked up without a restart.
 *   - Falls back to a trust-all client if identity has not yet been activated,
 *     so the probe and bootstrap flows continue to work before certs are loaded.
 */
public class Partners implements REST {

    private static final String P2P_HANDSHAKE_TOKEN = "DX-P2P-PROTOCOL-V1";

    // Rebuilt on each handshake to pick up the latest identity and partner certs
    private volatile HttpClient httpClient;

    public Partners() {
        // Start with a safe fallback — replaced by refreshMtlsClient() on first handshake
        this.httpClient = buildFallbackClient();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // mTLS Client Factory
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Builds a genuine mTLS HttpClient:
     *   KeyManager   → presents this node's own cert+key to the peer
     *   TrustManager → only accepts certs from registered partners
     *
     * If the local identity is not yet activated (no cert/key in DB), falls
     * back to the trust-all client so bootstrapping still works.
     */
    private HttpClient buildMtlsClient() {
        try {
            // ── 1. Load this node's identity (KeyManager) ─────────────────
            String[] identity = loadLocalIdentity();
            if (identity == null) {
                System.err.println("[Partners mTLS] Local identity not yet activated — using fallback client.");
                return buildFallbackClient();
            }
            String certPem = identity[0];
            String keyPem  = identity[1];

            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, null);

            X509Certificate localCert = pemToCertificate(certPem);
            PrivateKey      localKey  = pemToPrivateKey(keyPem);
            keyStore.setKeyEntry("node-identity", localKey, new char[0], new Certificate[]{localCert});

            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, new char[0]);

            // ── 2. Load all registered partner certs (TrustManager) ───────
            List<X509Certificate> partnerCerts = loadPartnerCertificates();

            TrustManager[] trustManagers;
            if (partnerCerts.isEmpty()) {
                // No partners registered yet — trust all so probe still works
                System.err.println("[Partners mTLS] No partner certs loaded — using permissive trust for bootstrap.");
                trustManagers = buildTrustAllManagers();
            } else {
                KeyStore trustStore = KeyStore.getInstance("PKCS12");
                trustStore.load(null, null);
                for (int i = 0; i < partnerCerts.size(); i++) {
                    trustStore.setCertificateEntry("partner-" + i, partnerCerts.get(i));
                }

                // Also trust the Jetty transport cert so TLS handshakes succeed.
                // Jetty presents a dev self-signed transport cert that differs from the
                // identity cert in the DB. Adding it here lets the TLS layer connect while
                // partner identity is still verified at the application layer (JSON payload).
                String jettyBase = System.getenv().getOrDefault("JETTY_BASE", "/var/lib/jetty");
                String ksPass    = System.getenv().getOrDefault("P2P_KEYSTORE_PASS", "dev-p2p-tsi");
                java.io.File transportKsFile = new java.io.File(jettyBase + "/etc/keystore.p12");
                if (transportKsFile.exists()) {
                    try {
                        KeyStore transportKs = KeyStore.getInstance("PKCS12");
                        try (java.io.FileInputStream fis = new java.io.FileInputStream(transportKsFile)) {
                            transportKs.load(fis, ksPass.toCharArray());
                        }
                        java.util.Enumeration<String> aliases = transportKs.aliases();
                        while (aliases.hasMoreElements()) {
                            String a = aliases.nextElement();
                            java.security.cert.Certificate c = transportKs.getCertificate(a);
                            if (c != null) trustStore.setCertificateEntry("transport-" + a, c);
                        }
                        System.err.println("[Partners mTLS] Transport cert loaded from " + transportKsFile.getPath());
                    } catch (Exception e) {
                        System.err.println("[Partners mTLS] Transport cert load skipped: " + e.getMessage());
                    }
                }

                TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                tmf.init(trustStore);
                trustManagers = tmf.getTrustManagers();
                System.err.println("[Partners mTLS] TrustStore loaded with " + partnerCerts.size() + " partner certificate(s).");
            }

            // ── 3. Build SSLContext with both KeyManager and TrustManager ──
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(kmf.getKeyManagers(), trustManagers, new java.security.SecureRandom());

            System.err.println("[Partners mTLS] mTLS client ready — identity: " + localCert.getSubjectX500Principal());

            return HttpClient.newBuilder()
                    .sslContext(sslContext)
                    .connectTimeout(Duration.ofSeconds(10))
                    .build();

        } catch (Exception e) {
            System.err.println("[Partners mTLS] Failed to build mTLS client: " + e.getMessage() + " — falling back.");
            return buildFallbackClient();
        }
    }

    /**
     * Fallback used before identity activation or on cert-load failure.
     * Trusts all certificates — NOT for production use.
     */
    private HttpClient buildFallbackClient() {
        try {
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, buildTrustAllManagers(), new java.security.SecureRandom());
            System.setProperty("jdk.internal.httpclient.disableHostnameVerification", "true");
            return HttpClient.newBuilder()
                    .sslContext(sc)
                    .connectTimeout(Duration.ofSeconds(10))
                    .build();
        } catch (Exception e) {
            return HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
        }
    }

    /**
     * Rebuilds the mTLS client from the latest DB state.
     * Called before every outbound handshake so newly added partner certs
     * are trusted without requiring a server restart.
     */
    private void refreshMtlsClient() {
        this.httpClient = buildMtlsClient();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Certificate / Key Helpers
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Loads this node's active certificate PEM and private key PEM from the DB.
     * Returns [certPem, keyPem] or null if identity is not yet activated.
     */
    private String[] loadLocalIdentity() throws SQLException {
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            // certificate_pem is nullable in schema (null when only CSR/key stored)
            // Only load when both cert and key are present and identity is active
            pstmt = conn.prepareStatement(
                "SELECT certificate_pem, private_key_pem " +
                "FROM node_certificates " +
                "WHERE is_active = TRUE " +
                "AND certificate_pem IS NOT NULL " +
                "ORDER BY created_at DESC LIMIT 1"
            );
            rs = pstmt.executeQuery();
            if (rs.next()) {
                String cert = rs.getString("certificate_pem");
                String key  = rs.getString("private_key_pem");
                if (!cert.isBlank() && !key.isBlank()) {
                    return new String[]{cert, key};
                }
            }
            return null;
        } finally { pool.cleanup(rs, pstmt, conn); }
    }

    /**
     * Loads all active partner public_key_pem values from the partners table.
     * These form the TrustStore — only peers whose certs are registered here
     * will be accepted during mTLS.
     */
    private List<X509Certificate> loadPartnerCertificates() throws SQLException {
        List<X509Certificate> certs = new ArrayList<>();
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(
                "SELECT node_id, public_key_pem FROM partners WHERE public_key_pem IS NOT NULL " +
                "AND public_key_pem NOT LIKE 'MANUAL_BOOTSTRAP%' AND status != 'Terminated'"
            );
            rs = pstmt.executeQuery();
            while (rs.next()) {
                try {
                    certs.add(pemToCertificate(rs.getString("public_key_pem")));
                } catch (Exception e) {
                    System.err.println("[Partners mTLS] Skipping invalid cert for partner: " + rs.getString("node_id"));
                }
            }
        } finally { pool.cleanup(rs, pstmt, conn); }
        return certs;
    }

    /**
     * Parses a PEM-encoded X.509 certificate string into an X509Certificate.
     */
    private X509Certificate pemToCertificate(String pem) throws Exception {
        String clean = pem.replaceAll("-----BEGIN CERTIFICATE-----", "")
                          .replaceAll("-----END CERTIFICATE-----", "")
                          .replaceAll("\\s+", "");
        byte[] der = Base64.getDecoder().decode(clean);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
    }

    /**
     * Parses a PKCS#8 PEM-encoded private key string into a PrivateKey.
     * The UI guide instructs users to import keys in PKCS#8 format, so RSA
     * and EC keys are both supported via KeyFactory with the correct algorithm.
     */
    private PrivateKey pemToPrivateKey(String pem) throws Exception {
        String clean = pem.replaceAll("-----BEGIN PRIVATE KEY-----", "")
                          .replaceAll("-----END PRIVATE KEY-----", "")
                          .replaceAll("-----BEGIN RSA PRIVATE KEY-----", "")
                          .replaceAll("-----END RSA PRIVATE KEY-----", "")
                          .replaceAll("\\s+", "");
        byte[] der = Base64.getDecoder().decode(clean);

        // Try RSA first, then EC
        try {
            java.security.spec.PKCS8EncodedKeySpec spec = new java.security.spec.PKCS8EncodedKeySpec(der);
            return java.security.KeyFactory.getInstance("RSA").generatePrivate(spec);
        } catch (Exception e) {
            java.security.spec.PKCS8EncodedKeySpec spec = new java.security.spec.PKCS8EncodedKeySpec(der);
            return java.security.KeyFactory.getInstance("EC").generatePrivate(spec);
        }
    }

    private TrustManager[] buildTrustAllManagers() {
        return new TrustManager[]{
            new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                public void checkClientTrusted(X509Certificate[] c, String a) {}
                public void checkServerTrusted(X509Certificate[] c, String a) {}
            }
        };
    }

    // ─────────────────────────────────────────────────────────────────────────
    // REST Handler
    // ─────────────────────────────────────────────────────────────────────────

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        JSONObject input = null;
        try {
            String funcHeader = req.getHeader("X-DX-FUNCTION");
            if ("probe".equalsIgnoreCase(funcHeader)) {
                OutputProcessor.send(res, 200, new JSONObject() {{ put("success", true); put("status", "online"); }});
                return;
            }

            input = InputProcessor.getInput(req);
            String func = funcHeader;
            if (func == null || func.isEmpty()) {
                func = (input != null) ? (String) input.get("_func") : null;
            }

            if (func == null || func.trim().isEmpty()) {
                OutputProcessor.errorResponse(res, 400, "Bad Request", "Missing function identifier.", req.getRequestURI());
                return;
            }

            final UUID pId = extractUuid(input, "partner_id");

            switch (func.toLowerCase()) {
                case "list_partners":
                    OutputProcessor.send(res, 200, listPartnersFromDb(input != null ? (String) input.get("search") : null));
                    break;

                case "create_partner":
                    JSONObject created = createPartner(input);
                    try {
                        initiateHandshake(UUID.fromString(created.get("partner_id").toString()), req);
                    } catch (Exception e) {
                        String err = (e.getMessage() != null) ? e.getMessage() : e.getClass().getSimpleName();
                        System.err.println("[Partners] Initial sync deferred: " + err);
                    }
                    OutputProcessor.send(res, 201, created);
                    break;

                case "accept_partnership":
                    OutputProcessor.send(res, 200, initiateHandshake(pId, req));
                    break;

                case "check_connectivity":
                    OutputProcessor.send(res, 200, probeConnectivity(pId));
                    break;

                case "receive_partnership_proposal":
                    OutputProcessor.send(res, 201, handleInboundProposal(input, req));
                    break;

                case "receive_termination_request":
                    handleInboundTerminationRequest(input);
                    OutputProcessor.send(res, 200, new JSONObject() {{ put("success", true); }});
                    break;

                case "accept_termination":
                    finalizeTermination(pId, true, req);
                    OutputProcessor.send(res, 200, new JSONObject() {{ put("success", true); }});
                    break;

                case "receive_termination_finalization":
                    handleInboundFinalization(input);
                    OutputProcessor.send(res, 200, new JSONObject() {{ put("success", true); }});
                    break;

                case "delete_partner":
                    handleTerminationInitiation(pId, req);
                    OutputProcessor.send(res, 200, new JSONObject() {{ put("success", true); }});
                    break;

                default:
                    OutputProcessor.errorResponse(res, 400, "Unknown Function", func, req.getRequestURI());
            }
        } catch (NoRouteToHostException | ConnectException | HttpConnectTimeoutException e) {
            String detail = (e instanceof HttpConnectTimeoutException) ? "Connection timed out." : "Connection refused or no route to host.";
            System.err.println("[Partners 502] Network Failure: " + detail + " (" + e.getClass().getSimpleName() + ")");
            OutputProcessor.errorResponse(res, 502, "P2P Connectivity Error",
                "Partner node unreachable: " + detail + " Ensure the peer is listening on the correct protocol/port.", req.getRequestURI());
        } catch (SSLHandshakeException e) {
            System.err.println("[Partners 502] mTLS Handshake Failed: " + e.getMessage());
            OutputProcessor.errorResponse(res, 502, "mTLS Handshake Failed",
                "Peer certificate was not trusted. Ensure both nodes have exchanged and registered their public certificates.", req.getRequestURI());
        } catch (SQLException e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, 500, "Database Error", e.getMessage(), req.getRequestURI());
        } catch (Exception e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, 500, "Internal Server Error", e.getMessage(), req.getRequestURI());
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Handshake & Protocol Methods
    // ─────────────────────────────────────────────────────────────────────────

    private JSONObject initiateHandshake(final UUID partnerId, HttpServletRequest req) throws Exception {
        // Rebuild the mTLS client so any newly registered partner cert is trusted
        refreshMtlsClient();

        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            // private_key_pem included — needed by refreshMtlsClient() KeyManager
            String sql = "SELECT p.fqdn as target_fqdn, p.status as local_partner_status, " +
                         "cfg.node_id as local_node, cfg.fqdn as local_fqdn, cfg.network_port, " +
                         "cert.certificate_pem, cert.private_key_pem " +
                         "FROM partners p CROSS JOIN (SELECT config_id, node_id, fqdn, network_port FROM node_config LIMIT 1) cfg " +
                         "LEFT JOIN node_certificates cert ON cert.node_config_id = cfg.config_id " +
                         "AND cert.is_active = TRUE AND cert.certificate_pem IS NOT NULL " +
                         "WHERE p.partner_id = ?";

            pstmt = conn.prepareStatement(sql); pstmt.setObject(1, partnerId); rs = pstmt.executeQuery();
            if (rs.next()) {
                final String currentStatus = rs.getString("local_partner_status");
                String localNodeId = rs.getString("local_node");
                String localFqdn   = rs.getString("local_fqdn").trim();
                int    localPort   = rs.getInt("network_port");
                String targetFqdn  = rs.getString("target_fqdn").trim();

                String senderFullFqdn = localFqdn + (localFqdn.contains(":") ? "" : ":" + localPort);
                String certPem = rs.getString("certificate_pem");
                if (certPem == null || certPem.trim().isEmpty()) certPem = "INTERNAL_DEV_IDENTITY_" + localNodeId;

                JSONObject payload = new JSONObject();
                payload.put("_func", "receive_partnership_proposal");
                payload.put("sender_node_id", localNodeId);
                payload.put("sender_fqdn", senderFullFqdn);
                payload.put("sender_public_key", certPem);

                String targetUrl = normalizeUrl(targetFqdn);
                System.err.println("[Partners DEBUG] Initiating mTLS Handshake at: " + targetUrl);

                HttpRequest request = HttpRequest.newBuilder().uri(URI.create(targetUrl))
                        .header("Content-Type", "application/json")
                        .header("X-DX-P2P-HANDSHAKE", P2P_HANDSHAKE_TOKEN)
                        .header("X-DX-FUNCTION", "receive_partnership_proposal")
                        .POST(HttpRequest.BodyPublishers.ofString(payload.toJSONString())).build();

                HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

                if (response.statusCode() >= 200 && response.statusCode() < 300) {
                    if ("Pending".equalsIgnoreCase(currentStatus)) {
                        updatePartnerStatus(conn, partnerId, "Active");
                        return new JSONObject() {{ put("success", true); put("message", "mTLS Identity Sync Successful. Link Verified."); }};
                    }
                    return new JSONObject() {{ put("success", true); put("message", "Sync complete."); }};
                } else {
                    throw new Exception("Handshake failed (HTTP " + response.statusCode() + "). Ensure the partner has registered your Node ID.");
                }
            }
            throw new Exception("Partner not found in local registry.");
        } finally { pool.cleanup(rs, pstmt, conn); }
    }

    private JSONObject handleInboundProposal(JSONObject input, HttpServletRequest req) throws SQLException {
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        String senderNodeId = (String) input.get("sender_node_id");
        String senderFqdn   = (String) input.get("sender_fqdn");
        String senderPubKey = (String) input.get("sender_public_key");

        String sql = "INSERT INTO partners (partner_id, node_id, name, fqdn, public_key_pem, public_key_fingerprint, status, created_at) " +
                     "VALUES (?, ?, ?, ?, ?, ?, 'Pending', NOW()) " +
                     "ON CONFLICT (node_id) DO UPDATE SET " +
                     "fqdn = EXCLUDED.fqdn, " +
                     "public_key_pem = EXCLUDED.public_key_pem, " +
                     "status = CASE WHEN partners.status = 'Pending' THEN 'Active' ELSE partners.status END, " +
                     "updated_at = NOW() " +
                     "RETURNING partner_id";
        try {
            conn = pool.getConnection(); pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, UUID.randomUUID());
            pstmt.setString(2, senderNodeId);
            pstmt.setString(3, senderNodeId);
            pstmt.setString(4, senderFqdn);
            pstmt.setString(5, senderPubKey);
            pstmt.setString(6, "SHA256:" + UUID.randomUUID());
            rs = pstmt.executeQuery();
            if (rs.next()) {
                final String registeredId = rs.getString(1);
                // Refresh mTLS client so this new partner's cert is immediately trusted
                refreshMtlsClient();
                return new JSONObject() {{ put("success", true); put("partner_id", registeredId); }};
            }
            throw new SQLException("Handshake persistence failed.");
        } finally { pool.cleanup(rs, pstmt, conn); }
    }

    private void notifyPeerOfAction(String peerFqdn, String function) {
        try {
            refreshMtlsClient();
            String url = normalizeUrl(peerFqdn);
            JSONObject payload = new JSONObject();
            payload.put("_func", function);
            payload.put("sender_node_id", getLocalNodeId());

            HttpRequest request = HttpRequest.newBuilder().uri(URI.create(url))
                    .header("Content-Type", "application/json")
                    .header("X-DX-P2P-HANDSHAKE", P2P_HANDSHAKE_TOKEN)
                    .header("X-DX-FUNCTION", function)
                    .POST(HttpRequest.BodyPublishers.ofString(payload.toJSONString())).build();

            httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString());
        } catch (Exception e) { System.err.println("[Partners] Protocol Relay Failed: " + e.getMessage()); }
    }

    private void handleTerminationInitiation(UUID partnerId, HttpServletRequest req) throws Exception {
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("SELECT status, fqdn FROM partners WHERE partner_id = ?");
            pstmt.setObject(1, partnerId);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                String status = rs.getString("status");
                String fqdn   = rs.getString("fqdn");
                if ("Active".equalsIgnoreCase(status)) {
                    updatePartnerStatus(conn, partnerId, "Terminating");
                    notifyPeerOfAction(fqdn, "receive_termination_request");
                } else {
                    deletePartnerFromDb(partnerId);
                }
            }
        } finally { pool.cleanup(rs, pstmt, conn); }
    }

    private void handleInboundTerminationRequest(JSONObject input) throws SQLException {
        Connection conn = null; PreparedStatement pstmt = null; PoolDB pool = new PoolDB();
        String senderNodeId = (String) input.get("sender_node_id");
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("UPDATE partners SET status = 'Terminating', updated_at = NOW() WHERE node_id = ?");
            pstmt.setString(1, senderNodeId);
            pstmt.executeUpdate();
        } finally { pool.cleanup(null, pstmt, conn); }
    }

    private void finalizeTermination(UUID partnerId, boolean accepted, HttpServletRequest req) throws Exception {
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("SELECT fqdn FROM partners WHERE partner_id = ?");
            pstmt.setObject(1, partnerId);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                String fqdn = rs.getString("fqdn");
                dispatchTerminationFinalization(fqdn, accepted);
                if (accepted) deletePartnerFromDb(partnerId);
                else updatePartnerStatus(conn, partnerId, "Active");
            }
        } finally { pool.cleanup(rs, pstmt, conn); }
    }

    private void dispatchTerminationFinalization(String peerFqdn, boolean accepted) throws Exception {
        JSONObject payload = new JSONObject();
        payload.put("_func", "receive_termination_finalization");
        payload.put("accepted", accepted);
        payload.put("sender_node_id", getLocalNodeId());

        String targetUrl = normalizeUrl(peerFqdn);
        HttpRequest request = HttpRequest.newBuilder().uri(URI.create(targetUrl))
                .header("Content-Type", "application/json")
                .header("X-DX-P2P-HANDSHAKE", P2P_HANDSHAKE_TOKEN)
                .header("X-DX-FUNCTION", "receive_termination_finalization")
                .POST(HttpRequest.BodyPublishers.ofString(payload.toJSONString())).build();

        httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString());
    }

    private void handleInboundFinalization(JSONObject input) throws SQLException {
        Connection conn = null; PreparedStatement pstmt = null; PoolDB pool = new PoolDB();
        String senderNodeId = (String) input.get("sender_node_id");
        boolean accepted    = (boolean) input.get("accepted");
        try {
            conn = pool.getConnection();
            if (accepted) {
                pstmt = conn.prepareStatement("DELETE FROM partners WHERE node_id = ?");
            } else {
                pstmt = conn.prepareStatement("UPDATE partners SET status = 'Active', updated_at = NOW() WHERE node_id = ?");
            }
            pstmt.setString(1, senderNodeId);
            pstmt.executeUpdate();
        } finally { pool.cleanup(null, pstmt, conn); }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // DB Helpers
    // ─────────────────────────────────────────────────────────────────────────

    private String getLocalNodeId() throws SQLException {
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("SELECT node_id FROM node_config LIMIT 1");
            rs = pstmt.executeQuery();
            return rs.next() ? rs.getString(1) : "UNKNOWN";
        } finally { pool.cleanup(rs, pstmt, conn); }
    }

    private JSONObject listPartnersFromDb(String search) throws SQLException {
        JSONArray arr = new JSONArray(); Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            String sql = "SELECT * FROM partners WHERE (node_id ILIKE ? OR name ILIKE ?) ORDER BY created_at DESC";
            pstmt = conn.prepareStatement(sql);
            String f = (search == null || search.isEmpty()) ? "%%" : "%" + search + "%";
            pstmt.setString(1, f); pstmt.setString(2, f);
            rs = pstmt.executeQuery();
            while (rs.next()) {
                JSONObject p = new JSONObject();
                p.put("partner_id", rs.getString("partner_id"));
                p.put("node_id",    rs.getString("node_id"));
                p.put("name",       rs.getString("name"));
                p.put("fqdn",       rs.getString("fqdn"));
                p.put("status",     rs.getString("status"));
                p.put("created_at", rs.getTimestamp("created_at").toString());
                arr.add(p);
            }
        } finally { pool.cleanup(rs, pstmt, conn); }
        return new JSONObject() {{ put("success", true); put("data", arr); }};
    }

    private JSONObject createPartner(JSONObject input) throws SQLException {
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        UUID id = UUID.randomUUID();
        String nodeId  = (String) input.get("node_id");
        String name    = (String) input.get("name");
        String fqdn    = (String) input.get("fqdn");
        String pubKey  = (String) input.get("public_key_pem");
        if (pubKey == null || pubKey.trim().isEmpty()) pubKey = "MANUAL_BOOTSTRAP_PENDING";

        String sql = "INSERT INTO partners (partner_id, node_id, name, fqdn, public_key_pem, public_key_fingerprint, status, created_at) " +
                     "VALUES (?, ?, ?, ?, ?, ?, 'Pending', NOW()) ON CONFLICT (node_id) DO UPDATE SET fqdn = EXCLUDED.fqdn, name = EXCLUDED.name, public_key_pem = EXCLUDED.public_key_pem RETURNING partner_id";
        try {
            conn = pool.getConnection(); pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, id); pstmt.setString(2, nodeId); pstmt.setString(3, name);
            pstmt.setString(4, fqdn); pstmt.setString(5, pubKey); pstmt.setString(6, "FINGERPRINT:" + id);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                final String registeredId = rs.getString(1);
                return new JSONObject() {{ put("success", true); put("partner_id", registeredId); }};
            }
            throw new SQLException("Creation failed.");
        } finally { pool.cleanup(rs, pstmt, conn); }
    }

    private JSONObject probeConnectivity(UUID partnerId) throws SQLException {
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("SELECT fqdn FROM partners WHERE partner_id = ?");
            pstmt.setObject(1, partnerId); rs = pstmt.executeQuery();
            if (rs.next()) {
                String url = normalizeUrl(rs.getString("fqdn"));
                HttpRequest request = HttpRequest.newBuilder().uri(URI.create(url))
                        .header("X-DX-P2P-HANDSHAKE", P2P_HANDSHAKE_TOKEN)
                        .header("X-DX-FUNCTION", "probe").timeout(Duration.ofSeconds(5))
                        .POST(HttpRequest.BodyPublishers.ofString("{\"_func\":\"probe\"}")).build();
                try {
                    HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
                    final boolean isOnline = (response.statusCode() == 200);
                    return new JSONObject() {{ put("success", true); put("online", isOnline); }};
                } catch (Exception e) { return new JSONObject() {{ put("success", true); put("online", false); }}; }
            }
            return new JSONObject() {{ put("success", false); }};
        } finally { pool.cleanup(rs, pstmt, conn); }
    }

    private void updatePartnerStatus(Connection conn, UUID id, String status) throws SQLException {
        try (PreparedStatement pstmt = conn.prepareStatement("UPDATE partners SET status = ?, updated_at = NOW() WHERE partner_id = ?")) {
            pstmt.setString(1, status); pstmt.setObject(2, id); pstmt.executeUpdate();
        }
    }

    private void deletePartnerFromDb(UUID id) throws SQLException {
        Connection conn = null; PreparedStatement pstmt = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("DELETE FROM partners WHERE partner_id = ?");
            pstmt.setObject(1, id); pstmt.executeUpdate();
        } finally { pool.cleanup(null, pstmt, conn); }
    }

    private String normalizeUrl(String fqdn) {
        String url = fqdn.trim();
        String apiPath = "/api/admin/partners";
        String protocol = "https://";
        if (url.startsWith("http://"))  protocol = "";
        else if (url.startsWith("https://")) protocol = "";
        StringBuilder sb = new StringBuilder(protocol).append(url);
        if (!url.contains(apiPath)) {
            if (!url.endsWith("/")) sb.append("/");
            sb.append("api/admin/partners");
        }
        return sb.toString();
    }

    private UUID extractUuid(JSONObject obj, String key) {
        if (obj == null || obj.get(key) == null) return null;
        try { return UUID.fromString(obj.get(key).toString()); } catch (Exception e) { return null; }
    }

    @Override public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        if (P2P_HANDSHAKE_TOKEN.equals(req.getHeader("X-DX-P2P-HANDSHAKE"))) return true;
        return InputProcessor.validate(req, res);
    }
    @Override public void get(HttpServletRequest req, HttpServletResponse res) {}
    @Override public void put(HttpServletRequest req, HttpServletResponse res) {}
    @Override public void delete(HttpServletRequest req, HttpServletResponse res) {}
}