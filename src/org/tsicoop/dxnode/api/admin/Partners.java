package org.tsicoop.dxnode.api.admin;

import org.tsicoop.dxnode.framework.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import java.net.ConnectException;
import java.net.NoRouteToHostException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.time.Duration;
import java.util.UUID;

/**
 * Service to manage Partner Nodes and the Identity Handshake protocol.
 * Implements a mutual-consent governance model: Invited -> Pending -> Active -> Terminating -> [Purged].
 * REVISED: Captures Public Key PEM on creation, auto-detects HTTPS for secure ports, and enforces mutual deletion.
 */
public class Partners implements REST {

    private static final String P2P_HANDSHAKE_TOKEN = "DX-P2P-PROTOCOL-V1";
    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        JSONObject input = null;
        try {
            // 1. Header-First Protocol Routing
            String funcHeader = req.getHeader("X-DX-FUNCTION");
            if ("probe".equalsIgnoreCase(funcHeader)) {
                OutputProcessor.send(res, 200, new JSONObject() {{ put("success", true); put("status", "online"); }});
                return;
            }

            // 2. Body Parsing
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
                    // ADMIN ACTION: Register peer and auto-dispatch invitation
                    JSONObject created = createPartner(input);
                    final String newIdStr = created.get("partner_id").toString();
                    try {
                        initiateHandshake(UUID.fromString(newIdStr), req);
                    } catch (Exception e) {
                        System.err.println("[Partners] Auto-invite failed, status remains Invited: " + e.getMessage());
                    }
                    logAudit("PARTNER_INVITED", "INFO", InputProcessor.getEmail(req), UUID.fromString(newIdStr), new JSONObject(), req);
                    OutputProcessor.send(res, 201, created);
                    break;
                    
                case "accept_partnership":
                    // ADMIN ACTION: Recipient node B accepts node A
                    OutputProcessor.send(res, 200, initiateHandshake(pId, req));
                    break;
                    
                case "check_connectivity":
                    OutputProcessor.send(res, 200, probeConnectivity(pId));
                    break;
                    
                case "receive_partnership_proposal":
                    // P2P PROTOCOL: Receive handshake from peer
                    JSONObject proposalRes = handleInboundProposal(input, req);
                    logAudit("HANDSHAKE_RECEIVED", "INFO", "P2P_PROTOCOL", UUID.fromString(proposalRes.get("partner_id").toString()), new JSONObject(), req);
                    OutputProcessor.send(res, 201, proposalRes);
                    break;

                case "receive_termination_request":
                    // P2P: Remote peer requested to delete. Change status locally to Terminating.
                    handleInboundTerminationRequest(input);
                    OutputProcessor.send(res, 200, new JSONObject() {{ put("success", true); }});
                    break;

                case "accept_termination":
                    // ADMIN: Local node accepts the peer's delete request.
                    finalizeTermination(pId, true, req);
                    OutputProcessor.send(res, 200, new JSONObject() {{ put("success", true); }});
                    break;

                case "reject_termination":
                    // ADMIN: Local node declines the peer's delete request.
                    finalizeTermination(pId, false, req);
                    OutputProcessor.send(res, 200, new JSONObject() {{ put("success", true); }});
                    break;

                case "receive_termination_finalization":
                    // P2P: Final confirmation from peer after accept/reject decision.
                    handleInboundFinalization(input);
                    OutputProcessor.send(res, 200, new JSONObject() {{ put("success", true); }});
                    break;
                    
                case "delete_partner":
                    // ADMIN: Initiator triggers delete. Active nodes move to Terminating first.
                    handleTerminationInitiation(pId, req);
                    OutputProcessor.send(res, 200, new JSONObject() {{ put("success", true); }});
                    break;
                    
                default:
                    OutputProcessor.errorResponse(res, 400, "Unknown Function", func, req.getRequestURI());
            }
        } catch (NoRouteToHostException | ConnectException e) {
            OutputProcessor.errorResponse(res, 502, "P2P Connectivity Error", "Partner node unreachable.", req.getRequestURI());
        } catch (SQLException e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, 500, "Database Error", e.getMessage(), req.getRequestURI());
        } catch (Exception e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, 500, "Internal Server Error", e.getMessage(), req.getRequestURI());
        }
    }

    private JSONObject initiateHandshake(final UUID partnerId, HttpServletRequest req) throws Exception {
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            String sql = "SELECT p.fqdn as target_fqdn, p.status as local_partner_status, cfg.node_id as local_node, cfg.fqdn as local_fqdn, cfg.network_port, cert.certificate_pem " +
                         "FROM partners p CROSS JOIN (SELECT config_id, node_id, fqdn, network_port FROM node_config LIMIT 1) cfg " +
                         "LEFT JOIN node_certificates cert ON cert.node_config_id = cfg.config_id AND cert.is_active = TRUE " +
                         "WHERE p.partner_id = ?";
            
            pstmt = conn.prepareStatement(sql); pstmt.setObject(1, partnerId); rs = pstmt.executeQuery();
            if (rs.next()) {
                final String currentStatus = rs.getString("local_partner_status");
                String localNodeId = rs.getString("local_node");
                String localFqdn = rs.getString("local_fqdn").trim();
                int localPort = rs.getInt("network_port");
                String targetFqdn = rs.getString("target_fqdn").trim();

                String senderFullFqdn = localFqdn + (localFqdn.contains(":") ? "" : ":" + localPort);
                String certPem = rs.getString("certificate_pem");
                if (certPem == null || certPem.trim().isEmpty()) certPem = "INTERNAL_DEV_IDENTITY_" + localNodeId;

                JSONObject payload = new JSONObject();
                payload.put("_func", "receive_partnership_proposal");
                payload.put("sender_node_id", localNodeId);
                payload.put("sender_fqdn", senderFullFqdn);
                payload.put("sender_public_key", certPem);

                String targetUrl = normalizeUrl(targetFqdn);
                HttpRequest request = HttpRequest.newBuilder().uri(URI.create(targetUrl))
                        .header("Content-Type", "application/json")
                        .header("X-DX-P2P-HANDSHAKE", P2P_HANDSHAKE_TOKEN)
                        .header("X-DX-FUNCTION", "receive_partnership_proposal")
                        .POST(HttpRequest.BodyPublishers.ofString(payload.toJSONString())).build();
                
                HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

                if (response.statusCode() >= 200 && response.statusCode() < 300) {
                    if ("Pending".equalsIgnoreCase(currentStatus)) {
                        updatePartnerStatus(conn, partnerId, "Active");
                        return new JSONObject() {{ put("success", true); put("message", "Partnership activated."); }};
                    }
                    return new JSONObject() {{ put("success", true); put("message", "Invitation dispatched."); }};
                } else {
                    throw new Exception("Handshake rejected by peer: " + response.body());
                }
            }
            throw new Exception("Partner not found.");
        } finally { pool.cleanup(rs, pstmt, conn); }
    }

    private JSONObject handleInboundProposal(JSONObject input, HttpServletRequest req) throws SQLException {
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        String senderNodeId = (String) input.get("sender_node_id");
        String senderFqdn = (String) input.get("sender_fqdn");
        String senderPubKey = (String) input.get("sender_public_key");

        String sql = "INSERT INTO partners (partner_id, node_id, name, fqdn, public_key_pem, public_key_fingerprint, status, created_at) " +
                     "VALUES (?, ?, ?, ?, ?, ?, 'Pending', NOW()) " +
                     "ON CONFLICT (node_id) DO UPDATE SET " +
                     "fqdn = EXCLUDED.fqdn, " +
                     "public_key_pem = EXCLUDED.public_key_pem, " +
                     "status = CASE WHEN partners.status = 'Invited' THEN 'Active' ELSE partners.status END, " +
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
                return new JSONObject() {{ put("success", true); put("partner_id", registeredId); }};
            }
            throw new SQLException("Handshake persistence failed.");
        } finally { pool.cleanup(rs, pstmt, conn); }
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
                String fqdn = rs.getString("fqdn");
                
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
                JSONObject payload = new JSONObject();
                payload.put("_func", "receive_termination_finalization");
                payload.put("accepted", accepted);
                payload.put("sender_node_id", getLocalNodeId());

                String targetUrl = normalizeUrl(fqdn);
                HttpRequest request = HttpRequest.newBuilder().uri(URI.create(targetUrl))
                        .header("Content-Type", "application/json")
                        .header("X-DX-P2P-HANDSHAKE", P2P_HANDSHAKE_TOKEN)
                        .header("X-DX-FUNCTION", "receive_termination_finalization")
                        .POST(HttpRequest.BodyPublishers.ofString(payload.toJSONString())).build();

                httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString());

                if (accepted) {
                    deletePartnerFromDb(partnerId);
                    logAudit("PARTNER_REMOVED", "WARNING", InputProcessor.getEmail(req), partnerId, new JSONObject(), req);
                } else {
                    updatePartnerStatus(conn, partnerId, "Active");
                }
            }
        } finally { pool.cleanup(rs, pstmt, conn); }
    }

    private void handleInboundFinalization(JSONObject input) throws SQLException {
        Connection conn = null; PreparedStatement pstmt = null; PoolDB pool = new PoolDB();
        String senderNodeId = (String) input.get("sender_node_id");
        boolean accepted = (boolean) input.get("accepted");
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

    private void notifyPeerOfAction(String peerFqdn, String function) {
        try {
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

    private String getLocalNodeId() throws SQLException {
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("SELECT node_id FROM node_config LIMIT 1");
            rs = pstmt.executeQuery();
            return rs.next() ? rs.getString(1) : "UNKNOWN";
        } finally { pool.cleanup(rs, pstmt, conn); }
    }

    private String normalizeUrl(String fqdn) {
        String url = fqdn.trim();
        // REVISED: HTTPS auto-detection for secure ports 443 and 8443
        String protocol = (url.contains(":443") || url.contains(":8443")) ? "https" : "http";
        if (!url.startsWith("http")) url = protocol + "://" + url;
        if (!url.endsWith("/api/admin/partners")) url = url.endsWith("/") ? url + "api/admin/partners" : url + "/api/admin/partners";
        return url;
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
                p.put("node_id", rs.getString("node_id"));
                p.put("name", rs.getString("name"));
                p.put("fqdn", rs.getString("fqdn"));
                p.put("status", rs.getString("status"));
                p.put("created_at", rs.getTimestamp("created_at").toString());
                arr.add(p);
            }
        } finally { pool.cleanup(rs, pstmt, conn); }
        return new JSONObject() {{ put("success", true); put("data", arr); }};
    }

    private JSONObject createPartner(JSONObject input) throws SQLException {
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        UUID id = UUID.randomUUID();
        String nodeId = (String) input.get("node_id");
        String name = (String) input.get("name");
        String fqdn = (String) input.get("fqdn");
        String pubKey = (String) input.get("public_key_pem");
        
        if (pubKey == null || pubKey.trim().isEmpty()) pubKey = "MANUAL_BOOTSTRAP_PENDING";

        String sql = "INSERT INTO partners (partner_id, node_id, name, fqdn, public_key_pem, public_key_fingerprint, status, created_at) " +
                     "VALUES (?, ?, ?, ?, ?, ?, 'Invited', NOW()) ON CONFLICT (node_id) DO UPDATE SET fqdn = EXCLUDED.fqdn, name = EXCLUDED.name RETURNING partner_id";
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
            pstmt = conn.prepareStatement("SELECT fqdn, status FROM partners WHERE partner_id = ?");
            pstmt.setObject(1, partnerId); rs = pstmt.executeQuery();
            if (rs.next() && "Active".equalsIgnoreCase(rs.getString("status"))) {
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

    private void logAudit(String type, String severity, String actor, UUID entityId, JSONObject details, HttpServletRequest req) {
        Connection conn = null; PreparedStatement pstmt = null; PoolDB pool = null;
        try {
            pool = new PoolDB();
            conn = pool.getConnection();
            String sql = "INSERT INTO audit_logs (log_id, timestamp, event_type, severity, actor_type, actor_id, entity_type, entity_id, details, origin_ip) " +
                         "VALUES (?, NOW(), ?, ?, 'USER', ?, 'PARTNER', ?, ?::jsonb, ?::inet)";
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, UUID.randomUUID()); pstmt.setString(2, type); pstmt.setString(3, severity);
            pstmt.setString(4, (actor == null) ? "SYSTEM" : actor);
            if (entityId != null) pstmt.setObject(5, entityId); else pstmt.setNull(5, Types.OTHER);
            pstmt.setString(6, details != null ? details.toJSONString() : "{}");
            pstmt.setString(7, req.getRemoteAddr());
            pstmt.executeUpdate();
        } catch (Exception e) { /* Silent */ }
        finally { try { if (pool != null) pool.cleanup(null, pstmt, conn); } catch (Exception e) {} }
    }

    private UUID extractUuid(JSONObject obj, String key) { if (obj == null || obj.get(key) == null) return null; try { return UUID.fromString(obj.get(key).toString()); } catch (Exception e) { return null; } }
    @Override public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) { if (P2P_HANDSHAKE_TOKEN.equals(req.getHeader("X-DX-P2P-HANDSHAKE"))) return true; return InputProcessor.validate(req, res); }
    @Override public void get(HttpServletRequest req, HttpServletResponse res) {}
    @Override public void put(HttpServletRequest req, HttpServletResponse res) {}
    @Override public void delete(HttpServletRequest req, HttpServletResponse res) {}
}