package org.tsicoop.dxnode.api.admin;

import org.tsicoop.dxnode.framework.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.util.UUID;

/**
 * Service to manage Data Contracts.
 * Optimized for JSON/CSV formats only.
 * Implements Partner-First listing and bidirectional P2P handshakes for governance sync.
 */
public class DataContract implements REST {

    private static final String P2P_HANDSHAKE_TOKEN = "DX-P2P-PROTOCOL-V1";
    private final HttpClient httpClient = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(15)).build();

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
                    OutputProcessor.send(res, 200, getContractByIdFromDb(contractId));
                    break;
                case "create_contract":
                    OutputProcessor.send(res, 201, createContract(input));
                    break;
                case "propose_contract":
                    // 1. Verify partner is 'Active'
                    validatePartnerTrust(contractId);
                    // 2. Transmit definition to peer
                    syncContractWithPartner(contractId);
                    // 3. Update local state
                    updateStatusInDb(contractId, "Proposed");
                    OutputProcessor.send(res, 200, new JSONObject() {{ put("success", true); }});
                    break;
                case "receive_proposed_contract":
                    // P2P Receptor: Triggered by a remote node
                    OutputProcessor.send(res, 201, handleInboundProposal(input));
                    break;
                default:
                    OutputProcessor.errorResponse(res, 400, "Bad Request", "Unknown function: " + func, req.getRequestURI());
            }
        } catch (IllegalStateException e) {
            OutputProcessor.errorResponse(res, 403, "Trust Baseline Missing", e.getMessage(), req.getRequestURI());
        } catch (Exception e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, 500, "Protocol Error", e.getMessage(), req.getRequestURI());
        }
    }

    /**
     * Ensures the counterparty is 'Active' before initiating the contract handshake.
     */
    private void validatePartnerTrust(UUID contractId) throws Exception {
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
            if (rs.next()) {
                if (!"Active".equalsIgnoreCase(rs.getString("status"))) {
                    throw new IllegalStateException("Identity Handshake required for partner '" + rs.getString("name") + "'.");
                }
            } else { throw new Exception("Contract counterparty mapping failed."); }
        } finally { pool.cleanup(rs, pstmt, conn); }
    }

    /**
     * Pushes the contract metadata and schema to the partner node.
     */
    private void syncContractWithPartner(UUID contractId) throws Exception {
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            String sql = "SELECT c.*, p.fqdn FROM data_contracts c " +
                         "JOIN partners p ON (p.node_id = c.sender_partner_id OR p.node_id = c.receiver_partner_id) " +
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

                String targetUrl = (fqdn.startsWith("http") ? fqdn : "http://" + fqdn) + "/api/admin/contracts";
                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(targetUrl))
                        .header("Content-Type", "application/json")
                        .header("X-DX-P2P-HANDSHAKE", P2P_HANDSHAKE_TOKEN)
                        .POST(HttpRequest.BodyPublishers.ofString(payload.toJSONString()))
                        .build();

                HttpResponse<String> res = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
                if (res.statusCode() >= 400) throw new Exception("Peer rejected handshake: " + res.body());
            }
        } finally { pool.cleanup(rs, pstmt, conn); }
    }

    private JSONObject handleInboundProposal(JSONObject input) throws SQLException {
        Connection conn = null; PreparedStatement pstmt = null; PoolDB pool = new PoolDB();
        String sql = "INSERT INTO data_contracts (contract_id, name, direction, sender_partner_id, receiver_partner_id, schema_definition, metadata, pii_fields, status, updated_at) " +
                     "VALUES (?, ?, ?, ?, ?, ?::jsonb, ?::jsonb, ?, 'Proposed', NOW()) " +
                     "ON CONFLICT (contract_id) DO UPDATE SET status = 'Proposed', updated_at = NOW()";
        try {
            conn = pool.getConnection(); pstmt = conn.prepareStatement(sql);
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

    private JSONObject createContract(JSONObject input) throws SQLException {
        Connection conn = null; PreparedStatement pstmt = null; PoolDB pool = new PoolDB(); 
        UUID id = UUID.randomUUID();
        String sql = "INSERT INTO data_contracts (contract_id, name, direction, sender_partner_id, receiver_partner_id, schema_definition, metadata, pii_fields, status, updated_at) " +
                     "VALUES (?, ?, ?, ?, ?, ?::jsonb, ?::jsonb, ?, 'Draft', NOW())";
        try {
            conn = pool.getConnection(); pstmt = conn.prepareStatement(sql);
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
            conn = pool.getConnection(); pstmt = conn.prepareStatement("SELECT * FROM data_contracts ORDER BY updated_at DESC");
            rs = pstmt.executeQuery();
            while (rs.next()) {
                JSONObject c = new JSONObject();
                c.put("contract_id", rs.getString("contract_id"));
                c.put("name", rs.getString("name"));
                c.put("status", rs.getString("status"));
                c.put("sender_partner_id", rs.getString("sender_partner_id"));
                c.put("receiver_partner_id", rs.getString("receiver_partner_id"));
                try { c.put("metadata", new JSONParser().parse(rs.getString("metadata"))); } catch(Exception e) {}
                arr.add(c);
            }
        } finally { pool.cleanup(rs, pstmt, conn); }
        return arr;
    }

    private JSONObject getContractByIdFromDb(UUID id) throws SQLException {
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection(); pstmt = conn.prepareStatement("SELECT * FROM data_contracts WHERE contract_id = ?");
            pstmt.setObject(1, id); rs = pstmt.executeQuery();
            if (rs.next()) {
                JSONObject c = new JSONObject();
                c.put("contract_id", rs.getString("contract_id"));
                c.put("name", rs.getString("name"));
                c.put("sender_partner_id", rs.getString("sender_partner_id"));
                c.put("receiver_partner_id", rs.getString("receiver_partner_id"));
                c.put("status", rs.getString("status"));
                c.put("created_at", rs.getTimestamp("created_at").toString());
                JSONParser p = new JSONParser();
                try { c.put("schema_definition", p.parse(rs.getString("schema_definition"))); } catch(Exception e) {}
                try { c.put("metadata", p.parse(rs.getString("metadata"))); } catch(Exception e) {}
                java.sql.Array piiArray = rs.getArray("pii_fields");
                if (piiArray != null) {
                    JSONArray piiJson = new JSONArray();
                    for (Object o : (String[]) piiArray.getArray()) piiJson.add(o);
                    c.put("pii_fields", piiJson);
                }
                return c;
            }
        } finally { pool.cleanup(rs, pstmt, conn); }
        return null;
    }

    private void updateStatusInDb(UUID id, String status) throws SQLException {
        Connection conn = null; PreparedStatement pstmt = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection(); pstmt = conn.prepareStatement("UPDATE data_contracts SET status = ?, updated_at = NOW() WHERE contract_id = ?");
            pstmt.setString(1, status); pstmt.setObject(2, id); pstmt.executeUpdate();
        } finally { pool.cleanup(null, pstmt, conn); }
    }

    private String getString(JSONObject obj, String key) { Object v = obj.get(key); return v == null ? "" : v.toString(); }
    private UUID extractUuid(JSONObject obj, String key) { Object v = obj.get(key); return v == null ? null : UUID.fromString(v.toString()); }
    @Override public boolean validate(String m, HttpServletRequest req, HttpServletResponse res) { 
        if (P2P_HANDSHAKE_TOKEN.equals(req.getHeader("X-DX-P2P-HANDSHAKE"))) return true;
        return InputProcessor.validate(req, res); 
    }
    @Override public void get(HttpServletRequest req, HttpServletResponse res) {}
    @Override public void put(HttpServletRequest req, HttpServletResponse res) {}
    @Override public void delete(HttpServletRequest req, HttpServletResponse res) {}
}