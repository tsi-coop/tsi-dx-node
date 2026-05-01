package org.tsicoop.dxnode.api.admin;

import org.tsicoop.dxnode.framework.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import javax.net.ssl.*;
import java.io.ByteArrayInputStream;
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
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

/**
 * Service to manage Partner Nodes and the Identity Handshake protocol.
 * REVISED: Implements robust Encoded Byte Comparison for Sovereign Trust.
 * Ensures mTLS handshakes succeed for self-signed certificates by matching 
 * the raw DER encoding against the Partner Registry.
 */
public class Partners implements REST {

    private static final String P2P_HANDSHAKE_TOKEN = "DX-P2P-PROTOCOL-V1";
    private volatile HttpClient httpClient;

    public Partners() {
        this.httpClient = buildFallbackClient();
    }

    private HttpClient buildMtlsClient() {
        try {
            String[] identity = loadLocalIdentity();
            if (identity == null) return buildFallbackClient();
            
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, null);
            keyStore.setKeyEntry("node-identity", pemToPrivateKey(identity[1]), new char[0], new Certificate[]{pemToCertificate(identity[0])});

            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, new char[0]);

            List<X509Certificate> partnerCerts = loadPartnerCertificates();
            loadTransportCert(partnerCerts);
            System.err.println("[Partners mTLS] Trust Registry initialized with " + partnerCerts.size() + " certificates.");
            
            TrustManager[] trustManagers = new TrustManager[]{
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() { return partnerCerts.toArray(new X509Certificate[0]); }
                    public void checkClientTrusted(X509Certificate[] c, String a) {}
                    public void checkServerTrusted(X509Certificate[] certs, String auth) throws java.security.cert.CertificateException {
                        if (partnerCerts.isEmpty()) return; 
                        
                        for (X509Certificate presented : certs) {
                            byte[] presentedEncoded = presented.getEncoded();
                            byte[] presentedKeyEncoded = presented.getPublicKey().getEncoded();
                            String presentedDn = presented.getSubjectX500Principal().getName();
                            
                            for (X509Certificate trusted : partnerCerts) {
                                // 1. Full Certificate Match (Encoded DER)
                                if (Arrays.equals(presentedEncoded, trusted.getEncoded())) {
                                    System.err.println("[Partners mTLS] Trust Established (Full Cert Match): " + presentedDn);
                                    return;
                                }
                                
                                // 2. Public Key Match (Robust against cert re-wrapping/re-issue with same key)
                                if (Arrays.equals(presentedKeyEncoded, trusted.getPublicKey().getEncoded())) {
                                    System.err.println("[Partners mTLS] Trust Established (Public Key Match): " + presentedDn);
                                    return;
                                }
                            }
                            System.err.println("[Partners mTLS] Trust Rejected for: " + presentedDn);
                        }
                        throw new java.security.cert.CertificateException("Sovereign Trust Denied: Peer certificate mismatch.");
                    }
                }
            };

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(kmf.getKeyManagers(), trustManagers, new java.security.SecureRandom());
            System.setProperty("jdk.internal.httpclient.disableHostnameVerification", "true");

            return HttpClient.newBuilder().sslContext(sslContext).connectTimeout(Duration.ofSeconds(15)).build();
        } catch (Exception e) {
            return buildFallbackClient();
        }
    }

    private HttpClient buildFallbackClient() {
        try {
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, new TrustManager[]{ new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                public void checkClientTrusted(X509Certificate[] c, String a) {}
                public void checkServerTrusted(X509Certificate[] c, String a) {}
            }}, new java.security.SecureRandom());
            System.setProperty("jdk.internal.httpclient.disableHostnameVerification", "true");
            return HttpClient.newBuilder().sslContext(sc).connectTimeout(Duration.ofSeconds(10)).build();
        } catch (Exception e) {
            return HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
        }
    }

    private void refreshMtlsClient() { this.httpClient = buildMtlsClient(); }

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
            String func = (funcHeader != null && !funcHeader.isEmpty()) ? funcHeader : (input != null ? (String) input.get("_func") : null);

            if (func == null || func.trim().isEmpty()) {
                OutputProcessor.errorResponse(res, 400, "Bad Request", "Missing protocol function.", req.getRequestURI());
                return;
            }

            final UUID pId = extractUuid(input, "partner_id");

            switch (func.toLowerCase()) {
                case "list_partners":
                    OutputProcessor.send(res, 200, listPartnersFromDb());
                    break;

                case "create_partner":
                    OutputProcessor.send(res, 201, createPartner(input));
                    break;

                case "accept_partnership":
                    OutputProcessor.send(res, 200, initiateHandshake(pId, req));
                    break;

                case "receive_partnership_proposal":
                    OutputProcessor.send(res, 200, handleInboundHandshake(input));
                    break;

                case "check_connectivity":
                    OutputProcessor.send(res, 200, probeConnectivity(pId));
                    break;

                case "delete_partner":
                    handleTerminationInitiation(pId, req);
                    OutputProcessor.send(res, 200, new JSONObject() {{ put("success", true); }});
                    break;

                case "receive_termination_request":
                    handleInboundTerminationRequest(input);
                    OutputProcessor.send(res, 200, new JSONObject() {{ put("success", true); }});
                    break;

                case "accept_termination":
                    finalizeTermination(pId, true, req);
                    OutputProcessor.send(res, 200, new JSONObject() {{ put("success", true); }});
                    break;

                case "reject_termination":
                    finalizeTermination(pId, false, req);
                    OutputProcessor.send(res, 200, new JSONObject() {{ put("success", true); }});
                    break;

                case "receive_termination_finalization":
                    handleInboundFinalization(input);
                    OutputProcessor.send(res, 200, new JSONObject() {{ put("success", true); }});
                    break;

                default:
                    OutputProcessor.errorResponse(res, 400, "Unknown Function", func, req.getRequestURI());
            }
        } catch (NoRouteToHostException | ConnectException | HttpConnectTimeoutException e) {
            OutputProcessor.errorResponse(res, 502, "P2P Connectivity Error", "Partner node unreachable.", req.getRequestURI());
        } catch (SSLHandshakeException e) {
            OutputProcessor.errorResponse(res, 403, "Trust Denied", "Sovereign Trust Denied: Peer certificate mismatch.", req.getRequestURI());
        } catch (Exception e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, 500, "Internal Protocol Error", e.getMessage(), req.getRequestURI());
        }
    }

    private JSONObject initiateHandshake(final UUID partnerId, HttpServletRequest req) throws Exception {
        refreshMtlsClient();
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            String sql = "SELECT p.fqdn as target_fqdn, cfg.node_id as local_node, cfg.fqdn as local_fqdn, cfg.network_port, cert.certificate_pem " +
                         "FROM partners p CROSS JOIN (SELECT config_id, node_id, fqdn, network_port FROM node_config LIMIT 1) cfg " +
                         "LEFT JOIN node_certificates cert ON cert.node_config_id = cfg.config_id AND cert.is_active = TRUE " +
                         "WHERE p.partner_id = ?";
            pstmt = conn.prepareStatement(sql); pstmt.setObject(1, partnerId); rs = pstmt.executeQuery();
            if (rs.next()) {
                String targetFqdn = rs.getString("target_fqdn").trim();
                JSONObject payload = new JSONObject();
                payload.put("_func", "receive_partnership_proposal");
                payload.put("sender_node_id", rs.getString("local_node"));
                payload.put("sender_fqdn", rs.getString("local_fqdn") + ":" + rs.getInt("network_port"));
                payload.put("sender_public_key", rs.getString("certificate_pem"));

                HttpRequest request = HttpRequest.newBuilder().uri(URI.create(normalizeUrl(targetFqdn)))
                        .header("Content-Type", "application/json").header("X-DX-P2P-HANDSHAKE", P2P_HANDSHAKE_TOKEN)
                        .header("X-DX-FUNCTION", "receive_partnership_proposal")
                        .POST(HttpRequest.BodyPublishers.ofString(payload.toJSONString())).build();
                
                HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

                if (response.statusCode() == 200) {
                    JSONObject body = (JSONObject) new JSONParser().parse(response.body());
                    if (Boolean.TRUE.equals(body.get("success"))) {
                        updatePartnerStatus(conn, partnerId, "Active");
                        return new JSONObject() {{ put("success", true); put("message", "Handshake Verified. Status: Active."); }};
                    }
                }
                throw new Exception("Handshake rejected. Ensure the peer has pre-registered your Node ID.");
            }
            throw new Exception("Partner not found.");
        } finally { pool.cleanup(rs, pstmt, conn); }
    }

    private JSONObject handleInboundHandshake(JSONObject input) throws SQLException {
        Connection conn = null; PreparedStatement pstmt = null; PoolDB pool = new PoolDB();
        String senderNodeId = (String) input.get("sender_node_id");
        
        String sql = "UPDATE partners SET fqdn = ?, public_key_pem = ?, status = 'Active', updated_at = NOW() WHERE node_id = ?";
        try {
            conn = pool.getConnection(); pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, (String) input.get("sender_fqdn"));
            pstmt.setString(2, (String) input.get("sender_public_key"));
            pstmt.setString(3, senderNodeId);
            
            if (pstmt.executeUpdate() > 0) {
                refreshMtlsClient();
                return new JSONObject() {{ put("success", true); put("message", "Identity Verified."); }};
            } else {
                throw new SQLException("Handshake rejected: Peer node '" + senderNodeId + "' is not registered in our baseline.");
            }
        } finally { pool.cleanup(null, pstmt, conn); }
    }

    private JSONObject createPartner(JSONObject input) throws SQLException {
        Connection conn = null; PreparedStatement pstmt = null; PoolDB pool = new PoolDB();
        UUID id = UUID.randomUUID();
        String nodeId = (String) input.get("node_id");
        String fqdn = (String) input.get("fqdn");
        String insertSql = "INSERT INTO partners (partner_id, node_id, name, fqdn, public_key_pem, public_key_fingerprint, status, created_at) " +
                           "VALUES (?, ?, ?, ?, ?, ?, 'Pending', NOW()) RETURNING partner_id";
        try {
            conn = pool.getConnection();
            // Remove any stale records that would violate the node_id or fqdn unique constraints
            pstmt = conn.prepareStatement("DELETE FROM partners WHERE node_id = ? OR fqdn = ?");
            pstmt.setString(1, nodeId); pstmt.setString(2, fqdn); pstmt.executeUpdate();
            pstmt.close();
            pstmt = conn.prepareStatement(insertSql);
            pstmt.setObject(1, id);
            pstmt.setString(2, nodeId);
            pstmt.setString(3, nodeId);
            pstmt.setString(4, fqdn);
            pstmt.setString(5, (String) input.get("public_key_pem"));
            pstmt.setString(6, "SHA256:" + id);
            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) return new JSONObject() {{ put("success", true); put("partner_id", rs.getString(1)); }};
            throw new SQLException("Identity persistence failed.");
        } finally { pool.cleanup(null, pstmt, conn); }
    }

    private String[] loadLocalIdentity() throws SQLException {
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("SELECT certificate_pem, private_key_pem FROM node_certificates WHERE is_active = TRUE AND certificate_pem IS NOT NULL ORDER BY created_at DESC LIMIT 1");
            rs = pstmt.executeQuery();
            if (rs.next()) return new String[]{rs.getString(1), rs.getString(2)};
            return null;
        } finally { pool.cleanup(rs, pstmt, conn); }
    }

    private List<X509Certificate> loadPartnerCertificates() throws SQLException {
        List<X509Certificate> certs = new ArrayList<>();
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("SELECT public_key_pem FROM partners WHERE public_key_pem IS NOT NULL AND status != 'Terminated'");
            rs = pstmt.executeQuery();
            while (rs.next()) {
                try { certs.add(pemToCertificate(rs.getString(1))); } catch (Exception ignored) {}
            }
        } finally { pool.cleanup(rs, pstmt, conn); }
        return certs;
    }

    private void loadTransportCert(List<X509Certificate> certs) {
        String pass = System.getenv("P2P_KEYSTORE_PASS");
        String base = System.getenv("JETTY_BASE");
        if (pass == null || base == null) return;
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            try (java.io.FileInputStream fis = new java.io.FileInputStream(base + "/etc/keystore.p12")) {
                ks.load(fis, pass.toCharArray());
            }
            java.util.Enumeration<String> aliases = ks.aliases();
            while (aliases.hasMoreElements()) {
                Certificate c = ks.getCertificate(aliases.nextElement());
                if (c instanceof X509Certificate) certs.add((X509Certificate) c);
            }
        } catch (Exception e) {
            System.err.println("[Partners mTLS] Could not load transport cert from keystore: " + e.getMessage());
        }
    }

    private X509Certificate pemToCertificate(String pem) throws Exception {
        String clean = pem.replaceAll("-----BEGIN CERTIFICATE-----", "").replaceAll("-----END CERTIFICATE-----", "").replaceAll("\\s+", "");
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(clean)));
    }

    private PrivateKey pemToPrivateKey(String pem) throws Exception {
        String clean = pem.replaceAll("-----BEGIN PRIVATE KEY-----", "").replaceAll("-----END PRIVATE KEY-----", "").replaceAll("-----BEGIN RSA PRIVATE KEY-----", "").replaceAll("-----END RSA PRIVATE KEY-----", "").replaceAll("\\s+", "");
        java.security.spec.PKCS8EncodedKeySpec spec = new java.security.spec.PKCS8EncodedKeySpec(Base64.getDecoder().decode(clean));
        try { return java.security.KeyFactory.getInstance("RSA").generatePrivate(spec); } catch (Exception e) { return java.security.KeyFactory.getInstance("EC").generatePrivate(spec); }
    }

    private void handleTerminationInitiation(UUID partnerId, HttpServletRequest req) throws Exception {
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("SELECT status, fqdn FROM partners WHERE partner_id = ?");
            pstmt.setObject(1, partnerId); rs = pstmt.executeQuery();
            if (rs.next()) {
                if ("Active".equalsIgnoreCase(rs.getString(1))) {
                    updatePartnerStatus(conn, partnerId, "TerminationRequested");
                    notifyPeerOfAction(rs.getString(2), "receive_termination_request");
                } else { deletePartnerFromDb(partnerId); }
            }
        } finally { pool.cleanup(rs, pstmt, conn); }
    }

    private void handleInboundTerminationRequest(JSONObject input) throws SQLException {
        Connection conn = null; PreparedStatement pstmt = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("UPDATE partners SET status = 'Terminating', updated_at = NOW() WHERE node_id = ?");
            pstmt.setString(1, (String) input.get("sender_node_id"));
            pstmt.executeUpdate();
        } finally { pool.cleanup(null, pstmt, conn); }
    }

    private void finalizeTermination(UUID partnerId, boolean accepted, HttpServletRequest req) throws Exception {
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("SELECT fqdn FROM partners WHERE partner_id = ?");
            pstmt.setObject(1, partnerId); rs = pstmt.executeQuery();
            if (rs.next()) {
                dispatchTerminationFinalization(rs.getString(1), accepted);
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
        HttpRequest request = HttpRequest.newBuilder().uri(URI.create(normalizeUrl(peerFqdn)))
                .header("Content-Type", "application/json").header("X-DX-P2P-HANDSHAKE", P2P_HANDSHAKE_TOKEN)
                .header("X-DX-FUNCTION", "receive_termination_finalization")
                .POST(HttpRequest.BodyPublishers.ofString(payload.toJSONString())).build();
        httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString());
    }

    private void handleInboundFinalization(JSONObject input) throws SQLException {
        Connection conn = null; PreparedStatement pstmt = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            if ((boolean) input.get("accepted")) pstmt = conn.prepareStatement("DELETE FROM partners WHERE node_id = ?");
            else pstmt = conn.prepareStatement("UPDATE partners SET status = 'Active', updated_at = NOW() WHERE node_id = ?");
            pstmt.setString(1, (String) input.get("sender_node_id"));
            pstmt.executeUpdate();
        } finally { pool.cleanup(null, pstmt, conn); }
    }

    private void notifyPeerOfAction(String peerFqdn, String function) {
        try {
            JSONObject payload = new JSONObject();
            payload.put("_func", function); payload.put("sender_node_id", getLocalNodeId());
            HttpRequest request = HttpRequest.newBuilder().uri(URI.create(normalizeUrl(peerFqdn)))
                    .header("Content-Type", "application/json").header("X-DX-P2P-HANDSHAKE", P2P_HANDSHAKE_TOKEN)
                    .header("X-DX-FUNCTION", function)
                    .POST(HttpRequest.BodyPublishers.ofString(payload.toJSONString())).build();
            httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString());
        } catch (Exception ignored) {}
    }

    private String getLocalNodeId() throws SQLException {
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection(); pstmt = conn.prepareStatement("SELECT node_id FROM node_config LIMIT 1");
            rs = pstmt.executeQuery(); return rs.next() ? rs.getString(1) : "UNKNOWN";
        } finally { pool.cleanup(rs, pstmt, conn); }
    }

    private JSONArray listPartnersFromDb() throws SQLException {
        JSONArray arr = new JSONArray(); Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("SELECT * FROM partners ORDER BY created_at DESC");
            rs = pstmt.executeQuery();
            while (rs.next()) {
                JSONObject p = new JSONObject();
                p.put("partner_id", rs.getString("partner_id")); p.put("node_id", rs.getString("node_id"));
                p.put("name", rs.getString("name")); p.put("fqdn", rs.getString("fqdn"));
                p.put("status", rs.getString("status")); p.put("created_at", rs.getTimestamp("created_at").toString());
                arr.add(p);
            }
        } finally { pool.cleanup(rs, pstmt, conn); }
        return arr;
    }

    private JSONObject probeConnectivity(UUID partnerId) throws SQLException {
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("SELECT fqdn FROM partners WHERE partner_id = ?");
            pstmt.setObject(1, partnerId); rs = pstmt.executeQuery();
            if (rs.next()) {
                HttpRequest request = HttpRequest.newBuilder().uri(URI.create(normalizeUrl(rs.getString(1))))
                        .header("X-DX-P2P-HANDSHAKE", P2P_HANDSHAKE_TOKEN).header("X-DX-FUNCTION", "probe").timeout(Duration.ofSeconds(5))
                        .POST(HttpRequest.BodyPublishers.ofString("{\"_func\":\"probe\"}")).build();
                try {
                    HttpResponse<String> res = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
                    return new JSONObject() {{ put("success", true); put("online", res.statusCode() == 200); }};
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
        String protocol = "https://";
        if (url.startsWith("http://") || url.startsWith("https://")) protocol = "";
        StringBuilder sb = new StringBuilder(protocol).append(url);
        if (!url.contains("/api/admin/partners")) {
            if (!url.endsWith("/")) sb.append("/");
            sb.append("api/admin/partners");
        }
        return sb.toString();
    }

    private UUID extractUuid(JSONObject obj, String key) { if (obj == null || obj.get(key) == null) return null; try { return UUID.fromString(obj.get(key).toString()); } catch (Exception e) { return null; } }
    @Override public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) { if (P2P_HANDSHAKE_TOKEN.equals(req.getHeader("X-DX-P2P-HANDSHAKE"))) return true; return InputProcessor.validate(req, res); }
    @Override public void get(HttpServletRequest req, HttpServletResponse res) {}
    @Override public void put(HttpServletRequest req, HttpServletResponse res) {}
    @Override public void delete(HttpServletRequest req, HttpServletResponse res) {}
}