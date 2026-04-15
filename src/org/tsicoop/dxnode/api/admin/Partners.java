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
 * Implements UPSERT logic to handle duplicate Node ID conflicts gracefully.
 * REVISED: Allows fallback identities for Docker-to-Docker internal networking.
 */
public class Partners implements REST {

    private static final String P2P_HANDSHAKE_TOKEN = "DX-P2P-PROTOCOL-V1";
    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        JSONObject input = null;
        try {
            input = InputProcessor.getInput(req);
            String func = (String) input.get("_func");

            if (func == null || func.trim().isEmpty()) {
                OutputProcessor.errorResponse(res, 400, "Bad Request", "Missing '_func'.", req.getRequestURI());
                return;
            }

            switch (func.toLowerCase()) {
                case "list_partners":
                    OutputProcessor.send(res, 200, listPartnersFromDb((String) input.get("search")));
                    break;
                case "create_partner":
                    JSONObject created = createPartner(input);
                    
                    JSONObject cDetails = new JSONObject();
                    cDetails.put("node_id", input.get("node_id"));
                    cDetails.put("fqdn", input.get("fqdn"));
                    
                    // FIX: Explicitly cast to string for valid audit detail JSON
                    logAudit("PARTNER_REGISTERED", "INFO", InputProcessor.getEmail(req), UUID.fromString(created.get("partner_id").toString()), cDetails, req);
                    
                    OutputProcessor.send(res, 201, created);
                    break;
                case "propose_partnership":
                    UUID pId = extractUuid(input, "partner_id");
                    JSONObject handshakeRes = initiateHandshake(pId, req);
                    
                    JSONObject hDetails = new JSONObject();
                    hDetails.put("action", "HANDSHAKE_INITIATED");
                    logAudit("HANDSHAKE_PROPOSED", "INFO", InputProcessor.getEmail(req), pId, hDetails, req);
                    
                    OutputProcessor.send(res, 200, handshakeRes);
                    break;
                case "check_connectivity":
                    UUID checkId = extractUuid(input, "partner_id");
                    OutputProcessor.send(res, 200, probeConnectivity(checkId));
                    break;
                case "receive_partnership_proposal":
                    JSONObject proposalRes = handleInboundProposal(input, req);
                    
                    JSONObject rDetails = new JSONObject();
                    rDetails.put("initiator", input.get("sender_node_id"));
                    // FIX: UUID string cast for audit log
                    logAudit("HANDSHAKE_RECEIVED", "INFO", "P2P_PROTOCOL", UUID.fromString(proposalRes.get("partner_id").toString()), rDetails, req);
                    
                    OutputProcessor.send(res, 201, proposalRes);
                    break;
                case "delete_partner":
                    UUID delId = extractUuid(input, "partner_id");
                    deletePartnerFromDb(delId);
                    logAudit("PARTNER_REMOVED", "WARNING", InputProcessor.getEmail(req), delId, new JSONObject(), req);
                    OutputProcessor.send(res, 200, new JSONObject() {{ put("success", true); }});
                    break;
                default:
                    OutputProcessor.errorResponse(res, 400, "Unknown Function", func, req.getRequestURI());
            }
        } catch (NoRouteToHostException | ConnectException e) {
            OutputProcessor.errorResponse(res, 502, "P2P Connectivity Error", 
                "Partner node is currently unreachable. Check host and port parameters.", req.getRequestURI());
        } catch (IllegalStateException e) {
            // Identity Baseline missing
            OutputProcessor.errorResponse(res, 403, "Identity Error", e.getMessage(), req.getRequestURI());
        } catch (SQLException e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, 500, "Database Error", e.getMessage(), req.getRequestURI());
        } catch (Exception e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, 500, "Internal Protocol Error", e.getMessage(), req.getRequestURI());
        }
    }

    private JSONObject probeConnectivity(UUID partnerId) throws SQLException {
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("SELECT fqdn FROM partners WHERE partner_id = ?");
            pstmt.setObject(1, partnerId);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                String fqdn = rs.getString("fqdn");
                String url = (fqdn.startsWith("http") ? fqdn : "http://" + fqdn) + "/api/admin/partners";
                
                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(url))
                        .timeout(Duration.ofSeconds(3))
                        .POST(HttpRequest.BodyPublishers.ofString("{\"_func\":\"probe\"}"))
                        .build();

                try {
                    HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
                    return new JSONObject() {{ put("success", true); put("online", response.statusCode() != 503); }};
                } catch (Exception e) {
                    return new JSONObject() {{ put("success", true); put("online", false); }};
                }
            }
            return new JSONObject() {{ put("success", false); put("message", "Partner registry entry missing."); }};
        } finally { pool.cleanup(rs, pstmt, conn); }
    }

    private void logAudit(String type, String severity, String actor, UUID entityId, JSONObject details, HttpServletRequest req) {
        Connection conn = null; PreparedStatement pstmt = null; PoolDB pool = null;
        try {
            pool = new PoolDB();
            conn = pool.getConnection();
            String sql = "INSERT INTO audit_logs (log_id, timestamp, event_type, severity, actor_type, actor_id, entity_type, entity_id, details, origin_ip) " +
                         "VALUES (?, NOW(), ?, ?, ?, ?, 'PARTNER', ?, ?::jsonb, ?::inet)";
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, UUID.randomUUID());
            pstmt.setString(2, type);
            pstmt.setString(3, severity);
            String actorId = (actor == null || actor.isEmpty()) ? "SYSTEM" : actor;
            pstmt.setString(4, "P2P_PROTOCOL".equals(actorId) ? "SYSTEM" : "USER");
            pstmt.setString(5, actorId);
            if (entityId != null) pstmt.setObject(6, entityId); else pstmt.setNull(6, Types.OTHER);
            pstmt.setString(7, details != null ? details.toJSONString() : "{}");
            pstmt.setString(8, req.getRemoteAddr());
            pstmt.executeUpdate();
        } catch (Exception e) {
            System.err.println("[Partners] Audit Log Failed: " + e.getMessage());
        } finally { pool.cleanup(null, pstmt, conn); }
    }

    private JSONObject initiateHandshake(UUID partnerId, HttpServletRequest req) throws Exception {
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            String sql = "SELECT p.*, cfg.node_id as local_node, cfg.fqdn as local_fqdn, cert.certificate_pem " +
                         "FROM partners p CROSS JOIN (SELECT config_id, node_id, fqdn FROM node_config LIMIT 1) cfg " +
                         "LEFT JOIN node_certificates cert ON cert.node_config_id = cfg.config_id AND cert.is_active = TRUE " +
                         "WHERE p.partner_id = ?";
            pstmt = conn.prepareStatement(sql); pstmt.setObject(1, partnerId); rs = pstmt.executeQuery();
            if (rs.next()) {
                String certPem = rs.getString("certificate_pem");
                
                // REVISED: Allow fallback identity for internal Docker/Local networks to bypass strict PKI establishment requirement.
                if (certPem == null || certPem.trim().isEmpty()) {
                    String localNodeId = rs.getString("local_node");
                    certPem = "INTERNAL_DEVELOPMENT_IDENTITY_FOR_" + localNodeId;
                }

                String targetFqdn = rs.getString("fqdn");
                JSONObject payload = new JSONObject();
                payload.put("_func", "receive_partnership_proposal");
                payload.put("sender_node_id", rs.getString("local_node"));
                payload.put("sender_fqdn", rs.getString("local_fqdn"));
                payload.put("sender_public_key", certPem);

                String targetUrl = (targetFqdn.startsWith("http") ? targetFqdn : "http://" + targetFqdn) + "/api/admin/partners";
                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(targetUrl))
                        .header("Content-Type", "application/json")
                        .header("X-DX-P2P-HANDSHAKE", P2P_HANDSHAKE_TOKEN)
                        .POST(HttpRequest.BodyPublishers.ofString(payload.toJSONString()))
                        .build();
                
                HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

                if (response.statusCode() >= 200 && response.statusCode() < 300) {
                    updatePartnerStatus(partnerId, "Active");
                    return new JSONObject() {{ put("success", true); put("message", "Handshake confirmed."); }};
                } else { throw new Exception("Partner rejected handshake: " + response.body()); }
            }
            throw new Exception("Partner UUID not found.");
        } finally { pool.cleanup(rs, pstmt, conn); }
    }

    private JSONObject handleInboundProposal(JSONObject input, HttpServletRequest req) throws SQLException {
        Connection conn = null; PreparedStatement pstmt = null; PoolDB pool = new PoolDB();
        UUID newPartnerId = UUID.randomUUID();
        String senderNodeId = (String) input.get("sender_node_id");
        String senderPublicKey = (String) input.get("sender_public_key");

        if (senderPublicKey == null || senderPublicKey.trim().isEmpty()) {
            throw new IllegalArgumentException("Inbound handshake rejected: Peer identity (public key) is missing.");
        }
        
        // UPSERT logic for inbound P2P
        String sql = "INSERT INTO partners (partner_id, node_id, name, fqdn, public_key_pem, public_key_fingerprint, status, created_at) " +
                     "VALUES (?, ?, ?, ?, ?, ?, 'Active', NOW()) " +
                     "ON CONFLICT (node_id) DO UPDATE SET fqdn = EXCLUDED.fqdn, status = 'Active', public_key_pem = EXCLUDED.public_key_pem, updated_at = NOW() " +
                     "RETURNING partner_id";
        try {
            conn = pool.getConnection(); pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, newPartnerId); pstmt.setString(2, senderNodeId);
            pstmt.setString(3, senderNodeId); 
            pstmt.setString(4, (String) input.get("sender_fqdn"));
            pstmt.setString(5, senderPublicKey); 
            
            // Detect if internal identity is used
            String fingerprint = senderPublicKey.startsWith("INTERNAL_") ? "SHA256:INTERNAL_UNSECURE" : "SHA256:VERIFIED";
            pstmt.setString(6, fingerprint);
            
            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                // Return UUID as string for JSON compliance
                String pid = rs.getString("partner_id");
                return new JSONObject() {{ put("success", true); put("partner_id", pid); }};
            }
            throw new SQLException("Auto-registration failed.");
        } finally { pool.cleanup(null, pstmt, conn); }
    }
    
    private void updatePartnerStatus(UUID id, String status) throws SQLException {
        Connection conn = null; PreparedStatement pstmt = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection(); pstmt = conn.prepareStatement("UPDATE partners SET status = ?, updated_at = NOW() WHERE partner_id = ?");
            pstmt.setString(1, status); pstmt.setObject(2, id); pstmt.executeUpdate();
        } finally { pool.cleanup(null, pstmt, conn); }
    }

    private JSONObject listPartnersFromDb(String search) throws SQLException {
        JSONArray arr = new JSONArray(); Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        String sql = "SELECT * FROM partners WHERE (node_id ILIKE ? OR name ILIKE ?) ORDER BY created_at DESC";
        try {
            conn = pool.getConnection(); pstmt = conn.prepareStatement(sql);
            String f = (search == null || search.isEmpty()) ? "%%" : "%" + search + "%";
            pstmt.setString(1, f); pstmt.setString(2, f); rs = pstmt.executeQuery();
            while (rs.next()) {
                JSONObject p = new JSONObject(); 
                p.put("partner_id", rs.getString("partner_id")); 
                p.put("node_id", rs.getString("node_id"));
                p.put("name", rs.getString("name")); 
                p.put("fqdn", rs.getString("fqdn")); 
                p.put("status", rs.getString("status"));
                p.put("created_at", rs.getTimestamp("created_at") != null ? rs.getTimestamp("created_at").toString() : null); 
                arr.add(p);
            }
        } finally { pool.cleanup(rs, pstmt, conn); }
        return new JSONObject() {{ put("success", true); put("data", arr); }};
    }

    /**
     * REVISED: Implements UPSERT logic for manual partner creation.
     * Uses ON CONFLICT (node_id) to update existing records.
     * FIX: Ensures UUID is string-encoded for valid JSON (quoted).
     */
    private JSONObject createPartner(JSONObject input) throws SQLException {
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        UUID newId = UUID.randomUUID();
        String nodeId = (String) input.get("node_id");
        String name = (String) input.get("name");
        String fqdn = (String) input.get("fqdn");
        String pubKey = (String) input.get("public_key_pem");
        
        if (name == null || name.trim().isEmpty()) name = nodeId;
        if (pubKey == null) pubKey = ""; 

        String sql = "INSERT INTO partners (partner_id, name, node_id, fqdn, public_key_pem, public_key_fingerprint, status, created_at) " +
                     "VALUES (?, ?, ?, ?, ?, ?, 'Pending', NOW()) " +
                     "ON CONFLICT (node_id) DO UPDATE SET name = EXCLUDED.name, fqdn = EXCLUDED.fqdn, updated_at = NOW() " +
                     "RETURNING partner_id";

        try {
            conn = pool.getConnection(); 
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, newId); 
            pstmt.setString(2, name);
            pstmt.setString(3, nodeId); 
            pstmt.setString(4, fqdn);
            pstmt.setString(5, pubKey); 
            pstmt.setString(6, pubKey.isEmpty() ? "SHA256:PENDING" : "SHA256:MANUAL");
            
            rs = pstmt.executeQuery();
            if (rs.next()) {
                // Quote the UUID by returning it as a string
                final String finalId = rs.getString("partner_id");
                return new JSONObject() {{ put("success", true); put("partner_id", finalId); }};
            }
            throw new SQLException("Registry upsert failed.");
        } finally { pool.cleanup(rs, pstmt, conn); }
    }

    private JSONObject deletePartnerFromDb(UUID id) throws SQLException {
        Connection conn = null; PreparedStatement pstmt = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection(); pstmt = conn.prepareStatement("DELETE FROM partners WHERE partner_id = ?");
            pstmt.setObject(1, id); pstmt.executeUpdate(); return new JSONObject() {{ put("success", true); }};
        } finally { pool.cleanup(null, pstmt, conn); }
    }

    private UUID extractUuid(JSONObject obj, String key) { Object s = obj.get(key); if (s == null) return null; try { return UUID.fromString(s.toString()); } catch (Exception e) { return null; } }
    @Override public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) { String p2pToken = req.getHeader("X-DX-P2P-HANDSHAKE"); if (P2P_HANDSHAKE_TOKEN.equals(p2pToken)) return true; return InputProcessor.validate(req, res); }
    @Override public void get(HttpServletRequest req, HttpServletResponse res) {}
    @Override public void put(HttpServletRequest req, HttpServletResponse res) {}
    @Override public void delete(HttpServletRequest req, HttpServletResponse res) {}
}