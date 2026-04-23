package org.tsicoop.dxnode.api.admin;

import org.tsicoop.dxnode.framework.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

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
 * Service to manage Data Contracts for simplified JSON and CSV exchanges.
 * Implements full P2P lifecycle synchronization and robust status relay logic.
 * Instrumented with forensic audit logging for compliance and governance monitoring.
 */
public class DataContract implements REST {

    private static final String P2P_HANDSHAKE_TOKEN = "DX-P2P-PROTOCOL-V1";
    private final HttpClient httpClient = P2PClient.build(Duration.ofSeconds(10));

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        try {
            JSONObject input = InputProcessor.getInput(req);
            String func = getString(input, "_func");
            UUID contractId = extractUuid(input, "contract_id");

            switch (func.toLowerCase()) {
                case "list_contracts":
                    OutputProcessor.send(res, 200, listContractsFromDb());
                    break;

                case "get_contract":
                    if (contractId == null) throw new IllegalArgumentException("contract_id required.");
                    JSONObject details = getContractByIdFromDb(contractId);
                    if (details != null) OutputProcessor.send(res, 200, details);
                    else OutputProcessor.errorResponse(res, 404, "Not Found", "Contract entry missing.", req.getRequestURI());
                    break;

                case "create_contract":
                    JSONObject created = createContract(input);
                    // AUDIT: Record local draft creation
                    JSONObject cDetails = new JSONObject();
                    cDetails.put("name", getString(input, "name"));
                    cDetails.put("format", ((JSONObject) input.get("metadata")).get("format"));
                    logAudit("CONTRACT_CREATED", "INFO", InputProcessor.getEmail(req), (String) created.get("contract_id"), cDetails, req);
                    OutputProcessor.send(res, 201, created);
                    break;

                case "propose_contract":
                    if (contractId == null) throw new IllegalArgumentException("contract_id required.");
                    validatePartnerTrust(contractId);
                    syncContractWithPartner(contractId);
                    updateStatusInDb(contractId, "Proposed");
                    
                    // AUDIT: Record outbound proposal
                    JSONObject pDetails = new JSONObject();
                    pDetails.put("action", "PROPOSED_TO_PARTNER");
                    logAudit("CONTRACT_PROPOSAL", "INFO", InputProcessor.getEmail(req), contractId.toString(), pDetails, req);
                    
                    OutputProcessor.send(res, 200, new JSONObject() {{ put("success", true); }});
                    break;

                case "accept_contract":
                    if (contractId == null) throw new IllegalArgumentException("contract_id required.");
                    updateStatusInDb(contractId, "Active");
                    pushStatusUpdateToPartner(contractId, "Active");
                    
                    // AUDIT: Record acceptance
                    JSONObject aDetails = new JSONObject();
                    aDetails.put("status", "Active");
                    logAudit("CONTRACT_ACCEPTED", "INFO", InputProcessor.getEmail(req), contractId.toString(), aDetails, req);
                    
                    OutputProcessor.send(res, 200, new JSONObject() {{ put("success", true); }});
                    break;

                case "reject_contract":
                    if (contractId == null) throw new IllegalArgumentException("contract_id required.");
                    updateStatusInDb(contractId, "Rejected");
                    pushStatusUpdateToPartner(contractId, "Rejected");
                    
                    // AUDIT: Record rejection
                    JSONObject rDetails = new JSONObject();
                    rDetails.put("status", "Rejected");
                    logAudit("CONTRACT_REJECTED", "WARNING", InputProcessor.getEmail(req), contractId.toString(), rDetails, req);
                    
                    OutputProcessor.send(res, 200, new JSONObject() {{ put("success", true); }});
                    break;

                case "force_sync_status":
                    if (contractId == null) throw new IllegalArgumentException("contract_id required.");
                    pullStatusFromPartner(contractId);
                    OutputProcessor.send(res, 200, new JSONObject() {{ put("success", true); }});
                    break;

                case "receive_proposed_contract":
                    // Inbound P2P: Triggered by a remote node's proposal
                    handleInboundProposal(input);
                    
                    // AUDIT: Record incoming proposal from peer
                    JSONObject iDetails = new JSONObject();
                    iDetails.put("initiator", getString(input, "sender_partner_id"));
                    logAudit("CONTRACT_INBOUND_PROPOSAL", "INFO", "P2P_PROTOCOL", contractId.toString(), iDetails, req);
                    
                    OutputProcessor.send(res, 201, new JSONObject() {{ put("success", true); }});
                    break;

                case "receive_status_update":
                    // Inbound P2P: Receive status change from partner
                    if (contractId == null) throw new IllegalArgumentException("contract_id required.");
                    String newStatus = getString(input, "status");
                    updateStatusInDb(contractId, newStatus);
                    
                    // AUDIT: Record status sync event
                    JSONObject sDetails = new JSONObject();
                    sDetails.put("remote_status", newStatus);
                    logAudit("CONTRACT_STATUS_SYNC", "INFO", "P2P_PROTOCOL", contractId.toString(), sDetails, req);
                    
                    OutputProcessor.send(res, 200, new JSONObject() {{ put("success", true); }});
                    break;

                case "query_contract_status":
                    if (contractId == null) throw new IllegalArgumentException("contract_id required.");
                    JSONObject statusResp = new JSONObject();
                    statusResp.put("status", getStatusFromDb(contractId));
                    OutputProcessor.send(res, 200, statusResp);
                    break;

                default:
                    OutputProcessor.errorResponse(res, 400, "Bad Request", "Unknown protocol function.", req.getRequestURI());
            }
        } catch (NoRouteToHostException | ConnectException e) {
            OutputProcessor.errorResponse(res, 502, "P2P Connectivity Error", 
                "The target partner node is unreachable. Protocol synchronization aborted.", req.getRequestURI());
        } catch (IllegalStateException e) {
            OutputProcessor.errorResponse(res, 403, "Trust Baseline Missing", e.getMessage(), req.getRequestURI());
        } catch (Exception e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, 500, "Internal Protocol Error", e.getMessage(), req.getRequestURI());
        }
    }

    /**
     * Internal helper to persist audit events for the contract lifecycle.
     */
    private void logAudit(String type, String severity, String actor, String entityId, JSONObject details, HttpServletRequest req) {
        Connection conn = null; PreparedStatement pstmt = null; PoolDB pool = null;
        try {
            pool = new PoolDB();
            conn = pool.getConnection();
            String sql = "INSERT INTO audit_logs (log_id, timestamp, event_type, severity, actor_type, actor_id, entity_type, entity_id, details, origin_ip) " +
                         "VALUES (?, NOW(), ?, ?, ?, ?, 'CONTRACT', ?, ?::jsonb, ?::inet)";
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, UUID.randomUUID());
            pstmt.setString(2, type);
            pstmt.setString(3, severity);
            
            String actorId = (actor == null || actor.isEmpty()) ? "SYSTEM" : actor;
            pstmt.setString(4, "P2P_PROTOCOL".equals(actorId) ? "SYSTEM" : "USER");
            pstmt.setString(5, actorId);
            
            if (entityId != null && !entityId.trim().isEmpty()) {
                pstmt.setObject(6, UUID.fromString(entityId.trim()));
            } else {
                pstmt.setNull(6, Types.OTHER);
            }
            
            pstmt.setString(7, details != null ? details.toJSONString() : "{}");
            pstmt.setString(8, req.getRemoteAddr());
            
            pstmt.executeUpdate();
        } catch (Exception e) {
            System.err.println("[DataContract] Audit Logging Failure: " + e.getMessage());
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
    }

    private void pullStatusFromPartner(UUID contractId) throws Exception {
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            String sql = "SELECT p.fqdn FROM data_contracts c JOIN partners p ON (p.node_id = c.sender_partner_id OR p.node_id = c.receiver_partner_id) " +
                         "WHERE c.contract_id = ? AND p.node_id != (SELECT node_id FROM node_config LIMIT 1)";
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, contractId);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                String fqdn = rs.getString("fqdn");
                JSONObject payload = new JSONObject();
                payload.put("_func", "query_contract_status");
                payload.put("contract_id", contractId.toString());

                // REVISED: Automatic protocol detection based on port
                String protocol = (fqdn.contains(":443") || fqdn.contains(":8443")) ? "https://" : "http://";
                String targetUrl = (fqdn.startsWith("http") ? fqdn : protocol + fqdn) + "/api/admin/contracts";

                HttpRequest request = HttpRequest.newBuilder().uri(URI.create(targetUrl))
                        .header("Content-Type", "application/json").header("X-DX-P2P-HANDSHAKE", P2P_HANDSHAKE_TOKEN)
                        .POST(HttpRequest.BodyPublishers.ofString(payload.toJSONString())).build();

                HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
                if (response.statusCode() == 200) {
                    JSONObject body = (JSONObject) new JSONParser().parse(response.body());
                    String remoteStatus = (String) body.get("status");
                    if (remoteStatus != null) updateStatusInDb(contractId, remoteStatus);
                } else {
                    throw new Exception("Partner node rejected status query: " + response.body());
                }
            }
        } finally { pool.cleanup(rs, pstmt, conn); }
    }

    private void pushStatusUpdateToPartner(UUID contractId, String status) throws Exception {
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            String sql = "SELECT p.fqdn FROM data_contracts c JOIN partners p ON (p.node_id = c.sender_partner_id OR p.node_id = c.receiver_partner_id) " +
                         "WHERE c.contract_id = ? AND p.node_id != (SELECT node_id FROM node_config LIMIT 1)";
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, contractId);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                String fqdn = rs.getString("fqdn");
                JSONObject payload = new JSONObject();
                payload.put("_func", "receive_status_update");
                payload.put("contract_id", contractId.toString());
                payload.put("status", status);
                
                // REVISED: Automatic protocol detection based on port
                String protocol = (fqdn.contains(":443") || fqdn.contains(":8443")) ? "https://" : "http://";
                String targetUrl = (fqdn.startsWith("http") ? fqdn : protocol + fqdn) + "/api/admin/contracts";

                HttpRequest request = HttpRequest.newBuilder().uri(URI.create(targetUrl))
                        .header("Content-Type", "application/json")
                        .header("X-DX-P2P-HANDSHAKE", P2P_HANDSHAKE_TOKEN)
                        .POST(HttpRequest.BodyPublishers.ofString(payload.toJSONString())).build();

                HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
                if (response.statusCode() >= 400) throw new Exception("Partner rejected status relay: " + response.body());
            }
        } finally { pool.cleanup(rs, pstmt, conn); }
    }

    private JSONObject createContract(JSONObject input) throws SQLException {
        Connection conn = null; PreparedStatement pstmt = null; PoolDB pool = new PoolDB();
        UUID id = UUID.randomUUID();
        String sql = "INSERT INTO data_contracts (contract_id, name, direction, sender_partner_id, receiver_partner_id, " +
                     "schema_definition, metadata, pii_fields, status, updated_at) " +
                     "VALUES (?, ?, ?, ?, ?, ?::jsonb, ?::jsonb, ?, 'Draft', NOW())";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, id);
            pstmt.setString(2, getString(input, "name"));
            pstmt.setString(3, getString(input, "direction"));
            pstmt.setString(4, getString(input, "sender_partner_id"));
            pstmt.setString(5, getString(input, "receiver_partner_id"));
            pstmt.setString(6, ((JSONObject) input.get("schema_definition")).toJSONString());
            pstmt.setString(7, ((JSONObject) input.get("metadata")).toJSONString());
            
            JSONArray piiArr = (JSONArray) input.get("pii_fields");
            String[] piiStrings = piiArr != null ? (String[]) piiArr.toArray(new String[0]) : new String[0];
            pstmt.setArray(8, conn.createArrayOf("text", piiStrings));
            pstmt.executeUpdate();
            
            JSONObject out = new JSONObject(); out.put("success", true); out.put("contract_id", id.toString());
            return out;
        } finally { pool.cleanup(null, pstmt, conn); }
    }

    private JSONArray listContractsFromDb() throws SQLException {
        JSONArray arr = new JSONArray(); Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("SELECT * FROM data_contracts ORDER BY updated_at DESC");
            rs = pstmt.executeQuery();
            while (rs.next()) {
                JSONObject c = new JSONObject();
                c.put("contract_id", rs.getString("contract_id"));
                c.put("name", rs.getString("name"));
                c.put("status", rs.getString("status"));
                c.put("sender_partner_id", rs.getString("sender_partner_id"));
                c.put("receiver_partner_id", rs.getString("receiver_partner_id"));
                try { c.put("metadata", new JSONParser().parse(rs.getString("metadata"))); } catch (Exception e) {}
                arr.add(c);
            }
        } finally { pool.cleanup(rs, pstmt, conn); }
        return arr;
    }

    private JSONObject getContractByIdFromDb(UUID id) throws SQLException {
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("SELECT * FROM data_contracts WHERE contract_id = ?");
            pstmt.setObject(1, id);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                JSONObject c = new JSONObject();
                c.put("contract_id", rs.getString("contract_id"));
                c.put("name", rs.getString("name"));
                c.put("sender_partner_id", rs.getString("sender_partner_id"));
                c.put("receiver_partner_id", rs.getString("receiver_partner_id"));
                c.put("status", rs.getString("status"));
                c.put("created_at", rs.getTimestamp("created_at").toString());
                JSONParser parser = new JSONParser();
                try { c.put("schema_definition", parser.parse(rs.getString("schema_definition"))); } catch (Exception e) {}
                try { c.put("metadata", parser.parse(rs.getString("metadata"))); } catch (Exception e) {}
                java.sql.Array pii = rs.getArray("pii_fields");
                if (pii != null) {
                    JSONArray piiJson = new JSONArray();
                    for (Object o : (String[]) pii.getArray()) piiJson.add(o);
                    c.put("pii_fields", piiJson);
                }
                return c;
            }
        } finally { pool.cleanup(rs, pstmt, conn); }
        return null;
    }

    private void validatePartnerTrust(UUID contractId) throws SQLException {
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            String sql = "SELECT p.status, p.name FROM partners p " +
                         "JOIN data_contracts c ON (p.node_id = c.sender_partner_id OR p.node_id = c.receiver_partner_id) " +
                         "CROSS JOIN (SELECT node_id FROM node_config LIMIT 1) cfg " +
                         "WHERE c.contract_id = ? AND p.node_id != cfg.node_id";
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, contractId);
            rs = pstmt.executeQuery();
            if (rs.next() && !"Active".equalsIgnoreCase(rs.getString("status"))) {
                throw new IllegalStateException("Identity Handshake required for partner '" + rs.getString("name") + "'.");
            }
        } finally { pool.cleanup(rs, pstmt, conn); }
    }

    private void syncContractWithPartner(UUID contractId) throws Exception {
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            String sql = "SELECT c.*, p.fqdn FROM data_contracts c JOIN partners p ON (p.node_id = c.sender_partner_id OR p.node_id = c.receiver_partner_id) " +
                         "WHERE c.contract_id = ? AND p.node_id != (SELECT node_id FROM node_config LIMIT 1)";
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, contractId);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                String fqdn = rs.getString("fqdn");
                JSONObject payload = new JSONObject();
                payload.put("_func", "receive_proposed_contract");
                payload.put("contract_id", rs.getString("contract_id"));
                payload.put("name", rs.getString("name"));
                payload.put("direction", rs.getString("direction"));
                payload.put("sender_partner_id", rs.getString("sender_partner_id"));
                payload.put("receiver_partner_id", rs.getString("receiver_partner_id"));
                payload.put("schema_definition", new JSONParser().parse(rs.getString("schema_definition")));
                payload.put("metadata", new JSONParser().parse(rs.getString("metadata")));
                java.sql.Array pii = rs.getArray("pii_fields");
                if (pii != null) {
                    JSONArray piiArr = new JSONArray();
                    for (String s : (String[]) pii.getArray()) piiArr.add(s);
                    payload.put("pii_fields", piiArr);
                }

                // REVISED: Automatic protocol detection based on port
                String protocol = (fqdn.contains(":443") || fqdn.contains(":8443")) ? "https://" : "http://";
                String targetUrl = (fqdn.startsWith("http") ? fqdn : protocol + fqdn) + "/api/admin/contracts";

                HttpRequest request = HttpRequest.newBuilder().uri(URI.create(targetUrl))
                        .header("Content-Type", "application/json").header("X-DX-P2P-HANDSHAKE", P2P_HANDSHAKE_TOKEN)
                        .POST(HttpRequest.BodyPublishers.ofString(payload.toJSONString())).build();

                HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
                if (response.statusCode() >= 400) throw new Exception("Partner rejected proposal: " + response.body());
            }
        } finally { pool.cleanup(rs, pstmt, conn); }
    }

    private JSONObject handleInboundProposal(JSONObject input) throws SQLException {
        Connection conn = null; PreparedStatement pstmt = null; PoolDB pool = new PoolDB();
        String sql = "INSERT INTO data_contracts (contract_id, name, direction, sender_partner_id, receiver_partner_id, " +
                     "schema_definition, metadata, pii_fields, status, updated_at) " +
                     "VALUES (?, ?, ?, ?, ?, ?::jsonb, ?::jsonb, ?, 'Proposed', NOW()) " +
                     "ON CONFLICT (contract_id) DO UPDATE SET status = 'Proposed', updated_at = NOW()";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, extractUuid(input, "contract_id"));
            pstmt.setString(2, getString(input, "name"));
            pstmt.setString(3, getString(input, "direction"));
            pstmt.setString(4, getString(input, "sender_partner_id"));
            pstmt.setString(5, getString(input, "receiver_partner_id"));
            pstmt.setString(6, ((JSONObject) input.get("schema_definition")).toJSONString());
            pstmt.setString(7, ((JSONObject) input.get("metadata")).toJSONString());
            
            JSONArray piiArr = (JSONArray) input.get("pii_fields");
            String[] piiStrings = piiArr != null ? (String[]) piiArr.toArray(new String[0]) : new String[0];
            pstmt.setArray(8, conn.createArrayOf("text", piiStrings));

            pstmt.executeUpdate();
            return new JSONObject() {{ put("success", true); }};
        } finally { pool.cleanup(null, pstmt, conn); }
    }

    private String getStatusFromDb(UUID id) throws SQLException {
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("SELECT status FROM data_contracts WHERE contract_id = ?");
            pstmt.setObject(1, id);
            rs = pstmt.executeQuery();
            return rs.next() ? rs.getString("status") : "Draft";
        } finally { pool.cleanup(rs, pstmt, conn); }
    }

    private void updateStatusInDb(UUID id, String status) throws SQLException {
        Connection conn = null; PreparedStatement pstmt = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("UPDATE data_contracts SET status = ?, updated_at = NOW() WHERE contract_id = ?");
            pstmt.setString(1, status);
            pstmt.setObject(2, id);
            pstmt.executeUpdate();
        } finally { pool.cleanup(null, pstmt, conn); }
    }

    private String getString(JSONObject obj, String key) { Object v = obj.get(key); return v == null ? "" : v.toString(); }
    private UUID extractUuid(JSONObject obj, String key) { Object v = obj.get(key); return v == null || v.toString().isEmpty() ? null : UUID.fromString(v.toString()); }
    
    @Override public boolean validate(String m, HttpServletRequest req, HttpServletResponse res) { 
        if (P2P_HANDSHAKE_TOKEN.equals(req.getHeader("X-DX-P2P-HANDSHAKE"))) return true;
        return InputProcessor.validate(req, res); 
    }
    @Override public void get(HttpServletRequest req, HttpServletResponse res) {}
    @Override public void put(HttpServletRequest req, HttpServletResponse res) {}
    @Override public void delete(HttpServletRequest req, HttpServletResponse res) {}
}