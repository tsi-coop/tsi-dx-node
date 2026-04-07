package org.tsicoop.dxnode.api.admin;

import org.tsicoop.dxnode.framework.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import java.net.ConnectException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.util.UUID;

/**
 * Service to manage Data Contracts within the TSI DX Node.
 * Updated to support Auto-Partner Discovery during the proposal handshake.
 */
public class DataContract implements REST {

    private static final String P2P_HANDSHAKE_TOKEN = "DX-P2P-PROTOCOL-V1";

    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        JSONObject input = null;
        try {
            input = InputProcessor.getInput(req);
            String func = getString(input, "_func");
            UUID contractId = extractUuid(input, "contract_id");

            switch (func.toLowerCase()) {
                case "list_contracts":
                    JSONArray list = listContractsFromDb(getString(input, "status"), getString(input, "search"), getInt(input, "page", 1), getInt(input, "limit", 50));
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, list);
                    break;

                case "create_contract":
                    JSONObject created = createContract(input);
                    OutputProcessor.send(res, HttpServletResponse.SC_CREATED, created);
                    break;

                case "propose_contract":
                    if (contractId == null) throw new IllegalArgumentException("contract_id required.");
                    JSONObject syncResult = syncContractWithPartner(contractId);
                    updateStatusInDb(contractId, "Proposed");
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, syncResult);
                    break;

                case "receive_proposed_contract":
                    // Receiving end: Handles contract AND auto-registers the sender as a partner
                    JSONObject received = handleInboundProposal(input);
                    OutputProcessor.send(res, HttpServletResponse.SC_CREATED, received);
                    break;

                case "accept_contract":
                case "reject_contract":
                case "terminate_contract":
                    if (contractId == null) throw new IllegalArgumentException("contract_id required.");
                    String targetStatus = mapFuncToStatus(func);
                    updateStatusInDb(contractId, targetStatus);
                    pushStatusUpdateToPartner(contractId, targetStatus);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, new JSONObject() {{ put("success", true); }});
                    break;

                case "receive_status_update":
                    if (contractId == null) throw new IllegalArgumentException("contract_id required.");
                    updateStatusInDb(contractId, getString(input, "status"));
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, new JSONObject() {{ put("success", true); }});
                    break;

                default:
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Unknown function.", req.getRequestURI());
                    break;
            }
        } catch (ConnectException | HttpTimeoutException e) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_GATEWAY_TIMEOUT, "P2P Connectivity Error", 
                "Partner node unreachable. Synchronization interrupted.", req.getRequestURI());
        } catch (Exception e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Protocol Error", e.getMessage(), req.getRequestURI());
        }
    }

    /**
     * Node 1 pushes a contract and its own FQDN so Node 2 can discover it.
     */
    private JSONObject syncContractWithPartner(UUID contractId) throws Exception {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        try {
            conn = pool.getConnection();
            // Get contract details AND local node's FQDN/NodeID for the sender context
            String sql = "SELECT c.*, p.fqdn as partner_fqdn, cfg.fqdn as local_fqdn, cfg.node_id as local_node " +
                         "FROM data_contracts c " +
                         "JOIN partners p ON (p.node_id = c.sender_partner_id OR p.node_id = c.receiver_partner_id) " +
                         "CROSS JOIN (SELECT node_id, fqdn FROM node_config LIMIT 1) cfg " +
                         "WHERE c.contract_id = ? AND p.node_id != cfg.node_id";
            
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, contractId);
            rs = pstmt.executeQuery();

            if (rs.next()) {
                String targetFqdn = rs.getString("partner_fqdn");
                
                JSONObject payload = new JSONObject();
                payload.put("_func", "receive_proposed_contract");
                payload.put("contract_id", rs.getString("contract_id"));
                payload.put("name", rs.getString("name"));
                payload.put("version", rs.getString("version") != null ? rs.getString("version") : "1.0.0");
                payload.put("direction", rs.getString("direction"));
                payload.put("sender_partner_id", rs.getString("sender_partner_id"));
                payload.put("receiver_partner_id", rs.getString("receiver_partner_id"));
                payload.put("schema_definition", new JSONParser().parse(rs.getString("schema_definition")));
                
                // Send local metadata so the receiver can auto-register us
                payload.put("sender_fqdn", rs.getString("local_fqdn"));
                payload.put("sender_node_id", rs.getString("local_node"));

                String targetUrl = (targetFqdn.startsWith("http") ? targetFqdn : "http://" + targetFqdn) + "/api/admin/contracts";
                
                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(targetUrl))
                        .header("Content-Type", "application/json")
                        .header("X-DX-P2P-HANDSHAKE", P2P_HANDSHAKE_TOKEN)
                        .POST(HttpRequest.BodyPublishers.ofString(payload.toJSONString()))
                        .build();

                HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

                if (response.statusCode() >= 200 && response.statusCode() < 300) {
                    return new JSONObject() {{ put("success", true); put("message", "Proposal sent to " + targetFqdn); }};
                } else {
                    throw new Exception("Partner rejected proposal: " + response.body());
                }
            }
            throw new Exception("Target partner not configured.");
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }

    /**
     * Logic for Node 2 to save the contract AND auto-register Node 1 as a partner.
     */
    private JSONObject handleInboundProposal(JSONObject input) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmtContract = null;
        PreparedStatement pstmtPartner = null;
        PoolDB pool = new PoolDB();
        
        try {
            conn = pool.getConnection();
            conn.setAutoCommit(false);

            // 1. AUTO-PARTNER DISCOVERY
            String senderNodeId = (String) input.get("sender_node_id");
            String senderFqdn = (String) input.get("sender_fqdn");
            
            if (senderNodeId != null && senderFqdn != null) {
                // Upsert partner: If the Node ID exists, update FQDN. If not, insert as 'Discovery'
                String partnerSql = "INSERT INTO partners (partner_id, node_id, name, fqdn, status, created_at) " +
                                   "VALUES (?, ?, ?, ?, 'Discovery', NOW()) " +
                                   "ON CONFLICT (node_id) DO UPDATE SET fqdn = EXCLUDED.fqdn";
                pstmtPartner = conn.prepareStatement(partnerSql);
                pstmtPartner.setObject(1, UUID.randomUUID());
                pstmtPartner.setString(2, senderNodeId);
                pstmtPartner.setString(3, "Auto-Discovered: " + senderNodeId);
                pstmtPartner.setString(4, senderFqdn);
                pstmtPartner.executeUpdate();
            }

            // 2. REGISTER CONTRACT
            String contractSql = "INSERT INTO data_contracts (contract_id, name, version, status, direction, sender_partner_id, receiver_partner_id, schema_definition, updated_at) " +
                                "VALUES (?, ?, ?, 'Proposed', ?, ?, ?, ?::jsonb, NOW()) " +
                                "ON CONFLICT (contract_id) DO UPDATE SET status = 'Proposed', updated_at = NOW(), name = EXCLUDED.name";

            pstmtContract = conn.prepareStatement(contractSql);
            pstmtContract.setObject(1, UUID.fromString((String) input.get("contract_id")));
            pstmtContract.setString(2, (String) input.get("name"));
            pstmtContract.setString(3, (String) input.get("version"));
            pstmtContract.setString(4, (String) input.get("direction"));
            pstmtContract.setString(5, (String) input.get("sender_partner_id"));
            pstmtContract.setString(6, (String) input.get("receiver_partner_id"));
            pstmtContract.setString(7, ((JSONObject) input.get("schema_definition")).toJSONString());
            pstmtContract.executeUpdate();
            
            conn.commit();
            return new JSONObject() {{ put("success", true); put("message", "Contract and Partner synchronized."); }};
        } catch (SQLException e) {
            if (conn != null) conn.rollback();
            throw e;
        } finally {
            if (pstmtPartner != null) pstmtPartner.close();
            pool.cleanup(null, pstmtContract, conn);
        }
    }

    private void pushStatusUpdateToPartner(UUID contractId, String status) throws Exception {
        String fqdn = getPartnerFqdn(contractId);
        if (fqdn == null) return;
        JSONObject payload = new JSONObject();
        payload.put("_func", "receive_status_update");
        payload.put("contract_id", contractId.toString());
        payload.put("status", status);
        String targetUrl = (fqdn.startsWith("http") ? fqdn : "http://" + fqdn) + "/api/admin/contracts";
        HttpRequest request = HttpRequest.newBuilder().uri(URI.create(targetUrl)).header("Content-Type", "application/json").header("X-DX-P2P-HANDSHAKE", P2P_HANDSHAKE_TOKEN).POST(HttpRequest.BodyPublishers.ofString(payload.toJSONString())).build();
        httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private String getPartnerFqdn(UUID contractId) throws SQLException {
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            String sql = "SELECT p.fqdn FROM data_contracts c JOIN partners p ON (p.node_id = c.sender_partner_id OR p.node_id = c.receiver_partner_id) " +
                         "WHERE c.contract_id = ? AND p.node_id != (SELECT node_id FROM node_config LIMIT 1)";
            pstmt = conn.prepareStatement(sql); pstmt.setObject(1, contractId); rs = pstmt.executeQuery();
            return rs.next() ? rs.getString("fqdn") : null;
        } finally { pool.cleanup(rs, pstmt, conn); }
    }

    private String getString(JSONObject obj, String key) { Object v = obj.get(key); return v == null ? "" : v.toString(); }
    private int getInt(JSONObject obj, String key, int def) { Object v = obj.get(key); if (v instanceof Number) return ((Number) v).intValue(); return def; }
    private UUID extractUuid(JSONObject obj, String key) { String s = getString(obj, key); try { return s.isEmpty() ? null : UUID.fromString(s); } catch (Exception e) { return null; } }
    private String mapFuncToStatus(String func) { if (func.contains("propose")) return "Proposed"; if (func.contains("accept")) return "Active"; if (func.contains("reject")) return "Rejected"; return "Terminated"; }
    
    @Override public void get(HttpServletRequest req, HttpServletResponse res) {}
    @Override public void put(HttpServletRequest req, HttpServletResponse res) {}
    @Override public void delete(HttpServletRequest req, HttpServletResponse res) {}

    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        // If the request is a P2P protocol handshake, authorization is handled by the InterceptingFilter's token check.
        // Otherwise, perform standard input validation for administrative actions.
        String p2pHeader = req.getHeader("X-DX-P2P-HANDSHAKE");
        if (P2P_HANDSHAKE_TOKEN.equals(p2pHeader)) {
            return true;
        }
        return InputProcessor.validate(req, res);
    }

    private JSONObject createContract(JSONObject input) throws SQLException {
        Connection conn = null; PreparedStatement pstmt = null; PoolDB pool = new PoolDB(); UUID id = UUID.randomUUID();
        String sql = "INSERT INTO data_contracts (contract_id, name, direction, sender_partner_id, receiver_partner_id, schema_definition, status, updated_at) VALUES (?, ?, ?, ?, ?, ?::jsonb, 'Draft', NOW())";
        try {
            conn = pool.getConnection(); pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, id); pstmt.setString(2, getString(input, "name")); pstmt.setString(3, getString(input, "direction"));
            pstmt.setString(4, getString(input, "sender_partner_id")); pstmt.setString(5, getString(input, "receiver_partner_id"));
            JSONObject schema = (JSONObject) input.get("schema_definition"); pstmt.setString(6, schema != null ? schema.toJSONString() : "{}");
            pstmt.executeUpdate(); return new JSONObject() {{ put("success", true); put("contract_id", id.toString()); }};
        } finally { pool.cleanup(null, pstmt, conn); }
    }

    private JSONArray listContractsFromDb(String status, String search, int page, int limit) throws SQLException {
        JSONArray arr = new JSONArray(); Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        String sql = "SELECT * FROM data_contracts WHERE 1=1" + (!status.isEmpty() ? " AND status = ?" : "") + " ORDER BY updated_at DESC LIMIT ? OFFSET ?";
        try {
            conn = pool.getConnection(); pstmt = conn.prepareStatement(sql); int idx = 1;
            if (!status.isEmpty()) pstmt.setString(idx++, status); pstmt.setInt(idx++, limit); pstmt.setInt(idx++, (page - 1) * limit);
            rs = pstmt.executeQuery();
            while (rs.next()) {
                JSONObject c = new JSONObject(); c.put("contract_id", rs.getString("contract_id")); c.put("name", rs.getString("name"));
                c.put("status", rs.getString("status")); c.put("direction", rs.getString("direction"));
                c.put("sender_partner_id", rs.getString("sender_partner_id")); c.put("receiver_partner_id", rs.getString("receiver_partner_id"));
                c.put("updated_at", rs.getTimestamp("updated_at").toString()); arr.add(c);
            }
        } finally { pool.cleanup(rs, pstmt, conn); }
        return arr;
    }

    private void updateStatusInDb(UUID id, String status) throws SQLException {
        Connection conn = null; PreparedStatement pstmt = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection(); pstmt = conn.prepareStatement("UPDATE data_contracts SET status = ?, updated_at = NOW() WHERE contract_id = ?");
            pstmt.setString(1, status); pstmt.setObject(2, id); pstmt.executeUpdate();
        } finally { pool.cleanup(null, pstmt, conn); }
    }
}