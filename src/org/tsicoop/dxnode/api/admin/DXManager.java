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
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Service to manage and monitor data transfers.
 * Updated to fix the 'Internal Protocol Error' caused by missing mandatory 'message_timestamp'.
 */
public class DXManager implements REST {

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
        try {
            input = InputProcessor.getInput(req);
            String func = (String) input.get("_func");

            if (func == null || func.trim().isEmpty()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required '_func' attribute.", req.getRequestURI());
                return;
            }

            switch (func.toLowerCase()) {
                case "list_transfers":
                    // Aligned with list_transfers_schema.json
                    String statusFilter = (String) input.get("status");
                    String search = (String) input.get("search");
                    int page = getInt(input, "page", 1);
                    int limit = getInt(input, "limit", 50);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, listTransfersFromDb(statusFilter, search, page, limit));
                    break;

                case "initiate_transfer":
                    // FIX: Implemented to handle single transfer initiation and satisfy DB constraints
                    OutputProcessor.send(res, HttpServletResponse.SC_CREATED, initiateTransfer(input));
                    break;

                case "get_transfer":
                    UUID tid = extractUuid(input, "transfer_id");
                    if (tid == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'transfer_id' required.", req.getRequestURI());
                        return;
                    }
                    JSONObject transfer = getTransferByIdFromDb(tid);
                    if (transfer != null && !transfer.isEmpty()) {
                        OutputProcessor.send(res, HttpServletResponse.SC_OK, transfer);
                    } else {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Transfer not found.", req.getRequestURI());
                    }
                    break;

                default:
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Unknown function: " + func, req.getRequestURI());
                    break;
            }
        } catch (SQLException e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Database Error", e.getMessage(), req.getRequestURI());
        } catch (Exception e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Protocol Error", e.getMessage(), req.getRequestURI());
        }
    }

    /**
     * Resolves the 'Database Error' by ensuring all mandatory columns including 'file_checksum', 
     * 'sequence_number', and 'message_timestamp' are populated during the initial insertion.
     */
    private JSONObject initiateTransfer(JSONObject input) throws Exception {
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        
        try {
            conn = pool.getConnection();
            
            // 1. Resolve local Node ID to satisfy 'sender_node_id'
            String localNodeId = null;
            pstmt = conn.prepareStatement("SELECT node_id FROM node_config LIMIT 1");
            rs = pstmt.executeQuery();
            if (rs.next()) localNodeId = rs.getString("node_id");
            if (localNodeId == null) throw new IllegalStateException("Node identity not configured. Set Identity first.");
            pstmt.close();

            // 2. Insert with placeholders for mandatory engine fields
            UUID tid = UUID.randomUUID();
            // FIX: Added 'message_timestamp' to the column list to resolve Not-Null constraint violation
            String sql = "INSERT INTO data_transfers (transfer_id, contract_id, sender_node_id, receiver_node_id, file_name, file_size_bytes, file_checksum, sequence_number, message_timestamp, status, start_time) " +
                         "VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW(), 'Pending', NOW())";
            
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, tid);
            pstmt.setObject(2, UUID.fromString((String) input.get("contract_id")));
            pstmt.setString(3, localNodeId);
            pstmt.setString(4, (String) input.get("receiver_node_id"));
            pstmt.setString(5, (String) input.get("file_name"));
            
            Object fs = input.get("file_size");
            long size = (fs instanceof Number) ? ((Number) fs).longValue() : 0L;
            pstmt.setLong(6, size);
            
            // Satisfy 'file_checksum' NOT NULL constraint
            pstmt.setString(7, "PENDING_SHA256"); 

            // Satisfy 'sequence_number' NOT NULL constraint
            pstmt.setLong(8, 0L);

            pstmt.executeUpdate();
            
            JSONObject response = new JSONObject();
            response.put("success", true);
            response.put("transfer_id", tid.toString());
            return response;
            
        } finally { pool.cleanup(rs, pstmt, conn); }
    }

    private JSONObject listTransfersFromDb(String statusFilter, String search, int page, int limit) throws SQLException {
        JSONObject response = new JSONObject();
        JSONArray arr = new JSONArray();
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();

        try {
            conn = pool.getConnection();
            
            // Resolve local node for direction calculation
            String localNodeId = "";
            PreparedStatement idStmt = conn.prepareStatement("SELECT node_id FROM node_config LIMIT 1");
            ResultSet idRs = idStmt.executeQuery();
            if (idRs.next()) localNodeId = idRs.getString("node_id");
            idRs.close(); idStmt.close();

            StringBuilder sql = new StringBuilder(
                "SELECT t.*, c.name as contract_name FROM data_transfers t " +
                "LEFT JOIN data_contracts c ON t.contract_id = c.contract_id " +
                "WHERE 1=1"
            );
            List<Object> params = new ArrayList<>();

            if (statusFilter != null && !statusFilter.isEmpty()) {
                sql.append(" AND t.status = ?");
                params.add(statusFilter);
            }
            if (search != null && !search.isEmpty()) {
                sql.append(" AND (t.file_name ILIKE ? OR t.transfer_id::text ILIKE ?)");
                String wrap = "%" + search + "%";
                params.add(wrap); params.add(wrap);
            }

            sql.append(" ORDER BY t.start_time DESC LIMIT ? OFFSET ?");
            params.add(limit);
            params.add((page - 1) * limit);

            pstmt = conn.prepareStatement(sql.toString());
            for (int i = 0; i < params.size(); i++) pstmt.setObject(i + 1, params.get(i));
            
            rs = pstmt.executeQuery();
            while (rs.next()) {
                JSONObject t = new JSONObject();
                String sender = rs.getString("sender_node_id");
                String receiver = rs.getString("receiver_node_id");
                boolean isOutgoing = sender != null && sender.equals(localNodeId);

                t.put("transfer_id", rs.getString("transfer_id"));
                t.put("file_name", rs.getString("file_name"));
                t.put("status", rs.getString("status"));
                t.put("contract_name", rs.getString("contract_name"));
                t.put("direction", isOutgoing ? "Outgoing" : "Incoming");
                t.put("peer_node_id", isOutgoing ? receiver : sender);
                t.put("start_time", rs.getTimestamp("start_time").toString());
                arr.add(t);
            }
            response.put("success", true);
            response.put("data", arr);
        } finally { pool.cleanup(rs, pstmt, conn); }
        return response;
    }

    private JSONObject getTransferByIdFromDb(UUID id) throws SQLException {
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        JSONObject t = new JSONObject();
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("SELECT * FROM data_transfers WHERE transfer_id = ?");
            pstmt.setObject(1, id);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                t.put("transfer_id", rs.getString("transfer_id"));
                t.put("status", rs.getString("status"));
                t.put("file_name", rs.getString("file_name"));
                t.put("file_size_bytes", rs.getLong("file_size_bytes"));
                t.put("file_checksum", rs.getString("file_checksum"));
                t.put("sequence_number", rs.getLong("sequence_number"));
                t.put("message_timestamp", rs.getTimestamp("message_timestamp").toString());
                t.put("start_time", rs.getTimestamp("start_time").toString());
            }
        } finally { pool.cleanup(rs, pstmt, conn); }
        return t;
    }

    private int getInt(JSONObject obj, String key, int def) {
        Object val = obj.get(key);
        if (val instanceof Number) return ((Number) val).intValue();
        return def;
    }

    private UUID extractUuid(JSONObject obj, String key) {
        Object val = obj.get(key);
        if (val == null || val.toString().trim().isEmpty()) return null;
        try { return UUID.fromString(val.toString()); } catch (Exception e) { return null; }
    }

    @Override public boolean validate(String m, HttpServletRequest req, HttpServletResponse res) { return "POST".equalsIgnoreCase(m) && InputProcessor.validate(req, res); }
}