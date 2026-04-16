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
 * REVISED: Implements manual 'Accept/Reject' flow by defaulting inbound proposals to Pending.
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
            String funcHeader = req.getHeader("X-DX-FUNCTION");
            String p2pHeader = req.getHeader("X-DX-P2P-HANDSHAKE");
            
            String func = funcHeader;
            
            if ("probe".equalsIgnoreCase(func)) {
                System.out.println("[Partners] [DEBUG] Inbound Probe detected via Header. Responding 200 OK.");
                OutputProcessor.send(res, 200, new JSONObject() {{ put("success", true); put("status", "online"); }});
                return;
            }

            input = InputProcessor.getInput(req); 
            if (func == null || func.isEmpty()) {
                func = (input != null) ? (String) input.get("_func") : null;
            }

            System.out.println("[Partners] [DEBUG] Executing Function: " + func + " (P2P Token Present: " + (p2pHeader != null) + ")");

            if (func == null || func.trim().isEmpty()) {
                OutputProcessor.errorResponse(res, 400, "Bad Request", "Missing function identifier.", req.getRequestURI());
                return;
            }

            switch (func.toLowerCase()) {
                case "list_partners":
                    OutputProcessor.send(res, 200, listPartnersFromDb(input != null ? (String) input.get("search") : null));
                    break;
                    
                case "create_partner":
                    JSONObject created = createPartner(input);
                    JSONObject cDetails = new JSONObject();
                    cDetails.put("node_id", input.get("node_id"));
                    cDetails.put("fqdn", input.get("fqdn"));
                    logAudit("PARTNER_REGISTERED", "INFO", InputProcessor.getEmail(req), UUID.fromString(created.get("partner_id").toString()), cDetails, req);
                    OutputProcessor.send(res, 201, created);
                    break;
                    
                case "propose_partnership":
                    UUID pId = extractUuid(input, "partner_id");
                    System.out.println("[Partners] [DEBUG] Admin triggered Handshake (Accept) for partner: " + pId);
                    JSONObject handshakeRes = initiateHandshake(pId, req);
                    
                    JSONObject hDetails = new JSONObject();
                    hDetails.put("action", "HANDSHAKE_INITIATED");
                    logAudit("HANDSHAKE_PROPOSED", "INFO", InputProcessor.getEmail(req), pId, hDetails, req);
                    OutputProcessor.send(res, 200, handshakeRes);
                    break;
                    
                case "check_connectivity":
                    UUID checkId = extractUuid(input, "partner_id");
                    System.out.println("[Partners] [DEBUG] Admin triggered Connectivity Check for partner: " + checkId);
                    OutputProcessor.send(res, 200, probeConnectivity(checkId));
                    break;
                    
                case "receive_partnership_proposal":
                    System.out.println("[Partners] [DEBUG] Receiving Inbound Partnership Proposal from: " + input.get("sender_node_id"));
                    JSONObject proposalRes = handleInboundProposal(input, req);
                    JSONObject rDetails = new JSONObject();
                    rDetails.put("initiator", input.get("sender_node_id"));
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
                    System.out.println("[Partners] [WARN] Unknown function call: " + func);
                    OutputProcessor.errorResponse(res, 400, "Unknown Function", func, req.getRequestURI());
            }
        } catch (NoRouteToHostException | ConnectException e) {
            System.err.println("[Partners] [ERROR] Connectivity failure: " + e.toString());
            OutputProcessor.errorResponse(res, 502, "P2P Connectivity Error", 
                "Partner node unreachable. Verify that the Host and Port are correct in the Partner Registry.", req.getRequestURI());
        } catch (IllegalStateException e) {
            System.err.println("[Partners] [ERROR] Identity Error: " + e.getMessage());
            OutputProcessor.errorResponse(res, 403, "Identity Error", e.getMessage(), req.getRequestURI());
        } catch (SQLException e) {
            System.err.println("[Partners] [ERROR] Database Persistence Error: " + e.getMessage());
            e.printStackTrace();
            OutputProcessor.errorResponse(res, 500, "Database Error", e.getMessage(), req.getRequestURI());
        } catch (Exception e) {
            System.err.println("[Partners] [ERROR] Generic Protocol Exception: " + e.toString());
            e.printStackTrace();
            OutputProcessor.errorResponse(res, 500, "Internal Protocol Error", e.getMessage(), req.getRequestURI());
        }
    }

    private JSONObject probeConnectivity(UUID partnerId) throws SQLException {
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("SELECT fqdn, name FROM partners WHERE partner_id = ?");
            pstmt.setObject(1, partnerId);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                String fqdn = rs.getString("fqdn").trim();
                String name = rs.getString("name");
                
                String url = normalizeUrl(fqdn);
                System.out.println("[Partners] [DEBUG] Probing peer '" + name + "' at " + url);

                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(url))
                        .header("Content-Type", "application/json")
                        .header("X-DX-P2P-HANDSHAKE", P2P_HANDSHAKE_TOKEN)
                        .header("X-DX-FUNCTION", "probe")
                        .timeout(Duration.ofSeconds(4))
                        .POST(HttpRequest.BodyPublishers.ofString("{\"_func\":\"probe\"}"))
                        .build();

                try {
                    HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
                    System.out.println("[Partners] [DEBUG] Peer response code: " + response.statusCode());
                    boolean isOnline = (response.statusCode() == 200);
                    return new JSONObject() {{ put("success", true); put("online", isOnline); }};
                } catch (Exception e) {
                    System.err.println("[Partners] [DEBUG] Peer unreachable at " + url + ". Error: " + e.toString());
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
            System.err.println("[Partners] Audit Log Persistence Failed: " + e.getMessage());
        } finally { pool.cleanup(null, pstmt, conn); }
    }

    private JSONObject initiateHandshake(UUID partnerId, HttpServletRequest req) throws Exception {
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            
            // Aliased p.fqdn to target_fqdn to resolve ambiguity with cfg.fqdn
            String sql = "SELECT p.fqdn as target_fqdn, p.node_id as target_node_id, cfg.node_id as local_node, cfg.fqdn as local_fqdn, cfg.network_port, cert.certificate_pem " +
                         "FROM partners p CROSS JOIN (SELECT config_id, node_id, fqdn, network_port FROM node_config LIMIT 1) cfg " +
                         "LEFT JOIN node_certificates cert ON cert.node_config_id = cfg.config_id AND cert.is_active = TRUE " +
                         "WHERE p.partner_id = ?";
            
            pstmt = conn.prepareStatement(sql); 
            pstmt.setObject(1, partnerId); 
            rs = pstmt.executeQuery();
            
            if (rs.next()) {
                String certPem = rs.getString("certificate_pem");
                String localNodeId = rs.getString("local_node");
                String localFqdn = rs.getString("local_fqdn").trim();
                int localPort = rs.getInt("network_port");
                
                String targetFqdn = rs.getString("target_fqdn").trim();

                String senderFullFqdn = localFqdn;
                if (!senderFullFqdn.contains(":")) {
                    senderFullFqdn = senderFullFqdn + ":" + localPort;
                }

                if (certPem == null || certPem.trim().isEmpty()) {
                    System.out.println("[Partners] [INFO] No local certificate found. Using internal fallback identity.");
                    certPem = "INTERNAL_DEVELOPMENT_IDENTITY_FOR_" + localNodeId;
                }

                String targetUrl = normalizeUrl(targetFqdn);

                JSONObject payload = new JSONObject();
                payload.put("_func", "receive_partnership_proposal");
                payload.put("sender_node_id", localNodeId);
                payload.put("sender_fqdn", senderFullFqdn); 
                payload.put("sender_public_key", certPem);

                System.out.println("[Partners] [DEBUG] Sending Partnership Proposal to: " + targetUrl);

                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(targetUrl))
                        .header("Content-Type", "application/json")
                        .header("X-DX-P2P-HANDSHAKE", P2P_HANDSHAKE_TOKEN)
                        .header("X-DX-FUNCTION", "receive_partnership_proposal")
                        .POST(HttpRequest.BodyPublishers.ofString(payload.toJSONString()))
                        .build();
                
                HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
                System.out.println("[Partners] [DEBUG] Proposal response from " + targetFqdn + ": " + response.statusCode());

                if (response.statusCode() >= 200 && response.statusCode() < 300) {
                    // Update locally to Active since we initiated and peer confirmed
                    updatePartnerStatus(partnerId, "Active");
                    return new JSONObject() {{ put("success", true); put("message", "Handshake confirmed."); }};
                } else { 
                    System.err.println("[Partners] [ERROR] Handshake rejected by peer: " + response.body());
                    throw new Exception("Partner rejected handshake: " + response.body()); 
                }
            }
            throw new Exception("Partner UUID not found in local registry.");
        } finally { pool.cleanup(rs, pstmt, conn); }
    }

    private JSONObject handleInboundProposal(JSONObject input, HttpServletRequest req) throws SQLException {
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        UUID newPartnerId = UUID.randomUUID();
        String senderNodeId = (String) input.get("sender_node_id");
        String senderPublicKey = (String) input.get("sender_public_key");

        if (senderPublicKey == null || senderPublicKey.trim().isEmpty()) {
            throw new IllegalArgumentException("Inbound handshake rejected: Peer identity (public key) is missing.");
        }
        
        // REVISED SQL: Inbound proposals are registered as 'Pending'. 
        // We do NOT update the status to Active if it was already Active.
        String sql = "INSERT INTO partners (partner_id, node_id, name, fqdn, public_key_pem, public_key_fingerprint, status, created_at) " +
                     "VALUES (?, ?, ?, ?, ?, ?, 'Pending', NOW()) " +
                     "ON CONFLICT (node_id) DO UPDATE SET " +
                     "fqdn = EXCLUDED.fqdn, " +
                     "public_key_pem = EXCLUDED.public_key_pem, " +
                     "updated_at = NOW() " +
                     "RETURNING partner_id, status";
        try {
            conn = pool.getConnection(); pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, newPartnerId); pstmt.setString(2, senderNodeId);
            pstmt.setString(3, senderNodeId); 
            pstmt.setString(4, (String) input.get("sender_fqdn"));
            pstmt.setString(5, senderPublicKey); 
            
            String fingerprint = senderPublicKey.startsWith("INTERNAL_") ? "SHA256:INTERNAL_UNSECURE" : "SHA256:VERIFIED";
            pstmt.setString(6, fingerprint);
            
            rs = pstmt.executeQuery();
            if (rs.next()) {
                String pid = rs.getString("partner_id");
                String currentStatus = rs.getString("status");
                System.out.println("[Partners] [DEBUG] Proposal received from '" + senderNodeId + "'. Registry status: " + currentStatus);
                return new JSONObject() {{ put("success", true); put("partner_id", pid); }};
            }
            throw new SQLException("Inbound registration failed.");
        } finally { pool.cleanup(rs, pstmt, conn); }
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

    private String normalizeUrl(String fqdn) {
        String url = fqdn.trim();
        if (!url.startsWith("http")) url = "http://" + url;
        if (!url.endsWith("/api/admin/partners")) {
            url = url.endsWith("/") ? url + "api/admin/partners" : url + "/api/admin/partners";
        }
        return url;
    }

    private UUID extractUuid(JSONObject obj, String key) { 
        if (obj == null) return null;
        Object s = obj.get(key); 
        if (s == null) return null; 
        try { return UUID.fromString(s.toString()); } catch (Exception e) { return null; } 
    }
    
    @Override public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) { 
        String p2pToken = req.getHeader("X-DX-P2P-HANDSHAKE"); 
        if (P2P_HANDSHAKE_TOKEN.equals(p2pToken)) return true; 
        return InputProcessor.validate(req, res); 
    }
    @Override public void get(HttpServletRequest req, HttpServletResponse res) {}
    @Override public void put(HttpServletRequest req, HttpServletResponse res) {}
    @Override public void delete(HttpServletRequest req, HttpServletResponse res) {}
}