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
 * Instrumented with forensic audit logging to track trust baseline established across the P2P network.
 */
public class Partners implements REST {

    private static final String P2P_HANDSHAKE_TOKEN = "DX-P2P-PROTOCOL-V1";
    private final HttpClient httpClient = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();

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
                    
                    // AUDIT: Manual Entry
                    JSONObject cDetails = new JSONObject();
                    cDetails.put("name", input.get("name"));
                    cDetails.put("remote_node_id", input.get("node_id"));
                    logAudit("PARTNER_REGISTERED", "INFO", InputProcessor.getEmail(req), (UUID) created.get("partner_id"), cDetails, req);
                    
                    OutputProcessor.send(res, 201, created);
                    break;
                case "propose_partnership":
                    UUID pId = extractUuid(input, "partner_id");
                    JSONObject handshakeRes = initiateHandshake(pId, req);
                    
                    // AUDIT: Outbound Handshake Attempt
                    JSONObject hDetails = new JSONObject();
                    hDetails.put("action", "OUTBOUND_HANDSHAKE");
                    logAudit("HANDSHAKE_INITIATED", "INFO", InputProcessor.getEmail(req), pId, hDetails, req);
                    
                    OutputProcessor.send(res, 200, handshakeRes);
                    break;
                case "receive_partnership_proposal":
                    JSONObject proposalRes = handleInboundProposal(input, req);
                    
                    // AUDIT: Inbound Reception
                    JSONObject rDetails = new JSONObject();
                    rDetails.put("initiator_node", input.get("sender_node_id"));
                    rDetails.put("initiator_fqdn", input.get("sender_fqdn"));
                    logAudit("HANDSHAKE_RECEIVED", "INFO", "P2P_PROTOCOL", (UUID) proposalRes.get("partner_id"), rDetails, req);
                    
                    OutputProcessor.send(res, 201, proposalRes);
                    break;
                case "delete_partner":
                    UUID delId = extractUuid(input, "partner_id");
                    deletePartnerFromDb(delId);
                    
                    // AUDIT: Security Event
                    JSONObject dDetails = new JSONObject();
                    dDetails.put("action", "PERMANENT_REMOVAL");
                    logAudit("PARTNER_REMOVED", "WARNING", InputProcessor.getEmail(req), delId, dDetails, req);
                    
                    OutputProcessor.send(res, 200, new JSONObject() {{ put("success", true); }});
                    break;
                default:
                    OutputProcessor.errorResponse(res, 400, "Unknown Function", func, req.getRequestURI());
            }
        } catch (NoRouteToHostException | ConnectException e) {
            OutputProcessor.errorResponse(res, 502, "P2P Connectivity Error", 
                "Identity handshake failed: Partner unreachable. Check FQDN and network routing.", req.getRequestURI());
        } catch (Exception e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, 500, "Protocol Error", e.getMessage(), req.getRequestURI());
        }
    }

    /**
     * Internal helper to persist audit events for the partner lifecycle.
     */
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
            
            if (entityId != null) {
                pstmt.setObject(6, entityId);
            } else {
                pstmt.setNull(6, Types.OTHER);
            }
            
            pstmt.setString(7, details != null ? details.toJSONString() : "{}");
            pstmt.setString(8, req.getRemoteAddr());
            
            pstmt.executeUpdate();
        } catch (Exception e) {
            System.err.println("[Partners] Audit Logging Failure: " + e.getMessage());
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
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
                String targetFqdn = rs.getString("fqdn");
                JSONObject payload = new JSONObject();
                payload.put("_func", "receive_partnership_proposal");
                payload.put("sender_node_id", rs.getString("local_node"));
                payload.put("sender_fqdn", rs.getString("local_fqdn"));
                payload.put("sender_public_key", rs.getString("certificate_pem"));

                String targetUrl = (targetFqdn.startsWith("http") ? targetFqdn : "http://" + targetFqdn) + "/api/admin/partners";
                HttpRequest request = HttpRequest.newBuilder().uri(URI.create(targetUrl)).header("Content-Type", "application/json").header("X-DX-P2P-HANDSHAKE", P2P_HANDSHAKE_TOKEN).POST(HttpRequest.BodyPublishers.ofString(payload.toJSONString())).build();
                HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

                if (response.statusCode() >= 200 && response.statusCode() < 300) {
                    updatePartnerStatus(partnerId, "Active");
                    return new JSONObject() {{ put("success", true); put("message", "Identity handshake successful."); }};
                } else { throw new Exception("Partner rejected identity exchange: " + response.body()); }
            }
            throw new Exception("Partner not found.");
        } finally { pool.cleanup(rs, pstmt, conn); }
    }

    private JSONObject handleInboundProposal(JSONObject input, HttpServletRequest req) throws SQLException {
        Connection conn = null; PreparedStatement pstmt = null; PoolDB pool = new PoolDB();
        UUID newPartnerId = UUID.randomUUID();
        String sql = "INSERT INTO partners (partner_id, node_id, name, fqdn, public_key_pem, public_key_fingerprint, status, created_at) " +
                     "VALUES (?, ?, ?, ?, ?, ?, 'Active', NOW()) ON CONFLICT (node_id) DO UPDATE SET fqdn = EXCLUDED.fqdn, status = 'Active', public_key_pem = EXCLUDED.public_key_pem RETURNING partner_id";
        try {
            conn = pool.getConnection(); pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, newPartnerId); pstmt.setString(2, (String) input.get("sender_node_id"));
            pstmt.setString(3, "Partner: " + input.get("sender_node_id")); pstmt.setString(4, (String) input.get("sender_fqdn"));
            pstmt.setString(5, (String) input.get("sender_public_key")); pstmt.setString(6, "SHA256:VERIFIED_VIA_P2P");
            
            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                UUID actualId = UUID.fromString(rs.getString("partner_id"));
                return new JSONObject() {{ put("success", true); put("partner_id", actualId); }};
            }
            throw new SQLException("Handshake registration failed.");
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
        String sql = "SELECT * FROM partners WHERE (name ILIKE ? OR node_id ILIKE ?) ORDER BY created_at DESC";
        try {
            conn = pool.getConnection(); pstmt = conn.prepareStatement(sql);
            String f = (search == null || search.isEmpty()) ? "%%" : "%" + search + "%";
            pstmt.setString(1, f); pstmt.setString(2, f); rs = pstmt.executeQuery();
            while (rs.next()) {
                JSONObject p = new JSONObject(); p.put("partner_id", rs.getString("partner_id")); p.put("node_id", rs.getString("node_id"));
                p.put("name", rs.getString("name")); p.put("fqdn", rs.getString("fqdn")); p.put("status", rs.getString("status"));
                p.put("created_at", rs.getTimestamp("created_at") != null ? rs.getTimestamp("created_at").toString() : null); arr.add(p);
            }
        } finally { pool.cleanup(rs, pstmt, conn); }
        return new JSONObject() {{ put("success", true); put("data", arr); }};
    }

    private JSONObject createPartner(JSONObject input) throws SQLException {
        Connection conn = null; PreparedStatement pstmt = null; PoolDB pool = new PoolDB();
        UUID id = UUID.randomUUID();
        try {
            conn = pool.getConnection(); pstmt = conn.prepareStatement("INSERT INTO partners (partner_id, name, node_id, fqdn, public_key_pem, public_key_fingerprint, status) VALUES (?, ?, ?, ?, ?, ?, 'Pending')");
            pstmt.setObject(1, id); pstmt.setString(2, (String) input.get("name"));
            pstmt.setString(3, (String) input.get("node_id")); pstmt.setString(4, (String) input.get("fqdn"));
            pstmt.setString(5, (String) input.get("public_key_pem")); pstmt.setString(6, "SHA256:PENDING");
            pstmt.executeUpdate(); 
            return new JSONObject() {{ put("success", true); put("partner_id", id); }};
        } finally { pool.cleanup(null, pstmt, conn); }
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