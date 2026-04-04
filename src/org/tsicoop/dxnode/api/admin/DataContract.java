package org.tsicoop.dxnode.api.admin;

import org.tsicoop.dxnode.framework.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.UUID;
import java.util.Optional;

/**
 * Service to manage Data Contracts between TSI DX Nodes.
 * Synchronized with the schema.sql: partner IDs are VARCHAR (Node IDs).
 */
public class DataContract implements REST {

    @Override
    public void get(HttpServletRequest req, HttpServletResponse res) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "Use POST with '_func' attribute.", req.getRequestURI());
    }

    @Override
    public void put(HttpServletRequest req, HttpServletResponse res) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "Use POST with '_func' attribute.", req.getRequestURI());
    }

    @Override
    public void delete(HttpServletRequest req, HttpServletResponse res) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "Use POST with '_func' attribute.", req.getRequestURI());
    }

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        JSONObject input = null;
        JSONObject output = null;
        JSONArray outputArray = null;

        try {
            input = InputProcessor.getInput(req);
            String func = (String) input.get("_func");

            if (func == null || func.trim().isEmpty()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required '_func' attribute.", req.getRequestURI());
                return;
            }

            // --- SAFE ID EXTRACTION ---
            UUID contractId = extractUuid(input, "contract_id");

            switch (func.toLowerCase()) {
                case "list_contracts":
                    outputArray = listContractsFromDb(getString(input, "status"), getString(input, "search"), getInt(input, "page", 1), getInt(input, "limit", 10));
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, outputArray);
                    break;

                case "get_contract":
                    if (contractId == null) throw new IllegalArgumentException("'contract_id' required.");
                    Optional<JSONObject> contract = getContractByIdFromDb(contractId);
                    if (contract.isPresent()) OutputProcessor.send(res, HttpServletResponse.SC_OK, contract.get());
                    else OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Contract not found.", req.getRequestURI());
                    break;

                case "create_contract":
                    output = createContract(input);
                    OutputProcessor.send(res, HttpServletResponse.SC_CREATED, output);
                    break;

                case "propose_contract":
                case "accept_contract":
                case "reject_contract":
                case "terminate_contract":
                    if (contractId == null) throw new IllegalArgumentException("'contract_id' required.");
                    String targetStatus = mapFuncToStatus(func);
                    output = updateContractStatusInDb(contractId, targetStatus);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
                    break;

                default:
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Unknown _func: " + func, req.getRequestURI());
                    break;
            }

        } catch (IllegalArgumentException e) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Invalid Input", e.getMessage(), req.getRequestURI());
        } catch (Exception e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Error", e.getMessage(), req.getRequestURI());
        }
    }

    /**
     * Creates a new data contract based on the 'data_contracts' table in the Canvas.
     */
    private JSONObject createContract(JSONObject input) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = new PoolDB();
        UUID newId = UUID.randomUUID();

        // 1. Core Meta
        String name = getString(input, "name");
        String version = getString(input, "version");
        if (version.isEmpty()) version = "1.0.0";
        String direction = getString(input, "direction");
        
        // 2. Node Identities (VARCHAR as per Canvas schema)
        String senderId = getString(input, "sender_partner_id");
        String receiverId = getString(input, "receiver_partner_id");

        if (senderId.isEmpty() || receiverId.isEmpty()) {
            throw new IllegalArgumentException("Both sender_partner_id and receiver_partner_id (Node IDs) are mandatory.");
        }

        // 3. Data Schema & Governance
        JSONObject schemaDef = (JSONObject) input.get("schema_definition");
        JSONObject governance = new JSONObject();
        governance.put("retention_days", getInt(input, "retention_policy_days", 30));
        governance.put("pii_fields", input.get("pii_fields"));

        // Aligned with Canvas SQL column order
        String sql = "INSERT INTO data_contracts (contract_id, name, version, status, direction, sender_partner_id, receiver_partner_id, schema_definition, schema_json, governance_json, updated_at) " +
                     "VALUES (?, ?, ?, 'Draft', ?, ?, ?, ?::jsonb, ?::jsonb, ?::jsonb, NOW())";

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, newId);
            pstmt.setString(2, name);
            pstmt.setString(3, version);
            pstmt.setString(4, direction);
            pstmt.setString(5, senderId);
            pstmt.setString(6, receiverId);
            pstmt.setString(7, schemaDef != null ? schemaDef.toJSONString() : "{}");
            pstmt.setString(8, schemaDef != null ? schemaDef.toJSONString() : "{}");
            pstmt.setString(9, governance.toJSONString());
            
            pstmt.executeUpdate();
            
            return new JSONObject() {{ 
                put("success", true); 
                put("contract_id", newId.toString()); 
                put("message", "Contract established in Draft mode.");
            }};
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
    }

    private JSONArray listContractsFromDb(String status, String search, int page, int limit) throws SQLException {
        JSONArray contractsArray = new JSONArray();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        StringBuilder sql = new StringBuilder("SELECT * FROM data_contracts WHERE 1=1");
        if (!status.isEmpty()) sql.append(" AND status = ?");
        if (!search.isEmpty()) sql.append(" AND name ILIKE ?");
        sql.append(" ORDER BY created_at DESC LIMIT ? OFFSET ?");

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql.toString());
            int idx = 1;
            if (!status.isEmpty()) pstmt.setString(idx++, status);
            if (!search.isEmpty()) pstmt.setString(idx++, "%" + search + "%");
            pstmt.setInt(idx++, limit);
            pstmt.setInt(idx++, (page - 1) * limit);
            
            rs = pstmt.executeQuery();
            while (rs.next()) {
                JSONObject c = new JSONObject();
                c.put("contract_id", rs.getString("contract_id"));
                c.put("name", rs.getString("name"));
                c.put("version", rs.getString("version"));
                c.put("status", rs.getString("status"));
                c.put("direction", rs.getString("direction"));
                c.put("sender_partner_id", rs.getString("sender_partner_id"));
                c.put("receiver_partner_id", rs.getString("receiver_partner_id"));
                java.sql.Timestamp updatedAt = rs.getTimestamp("updated_at");
                c.put("updated_at", updatedAt != null ? updatedAt.toString() : "");
                contractsArray.add(c);
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return contractsArray;
    }

    private Optional<JSONObject> getContractByIdFromDb(UUID id) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("SELECT * FROM data_contracts WHERE contract_id = ?");
            pstmt.setObject(1, id);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                JSONObject c = new JSONObject();
                c.put("contract_id", rs.getString("contract_id"));
                c.put("name", rs.getString("name"));
                c.put("version", rs.getString("version"));
                c.put("status", rs.getString("status"));
                c.put("direction", rs.getString("direction"));
                c.put("sender_partner_id", rs.getString("sender_partner_id"));
                c.put("receiver_partner_id", rs.getString("receiver_partner_id"));
                return Optional.of(c);
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return Optional.empty();
    }

    private JSONObject updateContractStatusInDb(UUID id, String status) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("UPDATE data_contracts SET status = ?, updated_at = NOW() WHERE contract_id = ?");
            pstmt.setString(1, status);
            pstmt.setObject(2, id);
            int affected = pstmt.executeUpdate();
            if (affected == 0) throw new SQLException("Contract not found.");
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
        return new JSONObject() {{ put("success", true); put("message", "Contract status transitioned to " + status); }};
    }

    // --- Helpers for Safe Extraction ---

    private String getString(JSONObject obj, String key) {
        Object val = obj.get(key);
        return (val == null) ? "" : val.toString();
    }

    private int getInt(JSONObject obj, String key, int defaultVal) {
        Object val = obj.get(key);
        if (val == null) return defaultVal;
        if (val instanceof Number) return ((Number) val).intValue();
        try { return Integer.parseInt(val.toString()); } catch(Exception e) { return defaultVal; }
    }

    private UUID extractUuid(JSONObject obj, String key) {
        Object val = obj.get(key);
        if (val == null || val.toString().trim().isEmpty()) return null;
        try { return UUID.fromString(val.toString()); } catch(Exception e) { return null; }
    }

    private String mapFuncToStatus(String func) {
        if (func.contains("propose")) return "Proposed";
        if (func.contains("accept")) return "Active";
        if (func.contains("reject")) return "Rejected";
        if (func.contains("terminate")) return "Terminated";
        return "Unknown";
    }

    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        return "POST".equalsIgnoreCase(method) && InputProcessor.validate(req, res);
    }
}