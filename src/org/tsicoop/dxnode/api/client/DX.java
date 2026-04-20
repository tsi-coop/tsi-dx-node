package org.tsicoop.dxnode.api.client;

import org.tsicoop.dxnode.framework.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.*;
import java.util.Base64;
import java.util.UUID;

/**
 * Sovereign API Gateway for Client Applications.
 * Implements RBAC-restricted access to Data Contracts and Transfers.
 * Uses X-API-Key and X-API-Secret for authenticated orchestration.
 */
public class DX implements REST {

    private final PasswordHasher passwordHasher = new PasswordHasher();
    private static final String ATTR_APP_ID = "dx_authenticated_app_id";

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        try {
            JSONObject input = InputProcessor.getInput(req);
            String func = (input != null) ? (String) input.get("_func") : null;
            UUID appId = (UUID) req.getAttribute(ATTR_APP_ID);

            if (func == null) {
                OutputProcessor.errorResponse(res, 400, "Bad Request", "Missing '_func' identifier.", req.getRequestURI());
                return;
            }

            switch (func.toLowerCase()) {
                case "list_contracts":
                    OutputProcessor.send(res, 200, listAuthorizedContracts(appId));
                    break;

                case "get_contract_inspector":
                    OutputProcessor.send(res, 200, getContractDetail(appId, extractUuid(input, "contract_id")));
                    break;

                case "initiate_transfer":
                    OutputProcessor.send(res, 201, initiateTransfer(appId, input, req));
                    break;

                case "get_transfer_status":
                    OutputProcessor.send(res, 200, getTransferStatus(appId, extractUuid(input, "transfer_id")));
                    break;

                case "view_forensic_payload":
                    OutputProcessor.send(res, 200, getForensicPayload(appId, extractUuid(input, "transfer_id"), req));
                    break;

                default:
                    OutputProcessor.errorResponse(res, 400, "Bad Request", "Unknown client function: " + func, req.getRequestURI());
            }
        } catch (SecurityException se) {
            OutputProcessor.errorResponse(res, 403, "Access Denied", se.getMessage(), req.getRequestURI());
        } catch (Exception e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, 500, "Internal API Error", e.getMessage(), req.getRequestURI());
        }
    }

    /**
     * Lists only the Data Contracts this specific App is authorized to use.
     */
    private JSONArray listAuthorizedContracts(UUID appId) throws SQLException {
        JSONArray arr = new JSONArray();
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            String sql = "SELECT c.contract_id, c.name, c.status, c.direction, c.metadata " +
                         "FROM data_contracts c " +
                         "JOIN app_contracts ac ON c.contract_id = ac.contract_id " +
                         "WHERE ac.app_id = ? ORDER BY c.name ASC";
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, appId);
            rs = pstmt.executeQuery();
            while (rs.next()) {
                JSONObject c = new JSONObject();
                c.put("contract_id", rs.getString("contract_id"));
                c.put("name", rs.getString("name"));
                c.put("status", rs.getString("status"));
                c.put("direction", rs.getString("direction"));
                try { c.put("metadata", new JSONParser().parse(rs.getString("metadata"))); } catch (Exception e) {}
                arr.add(c);
            }
        } finally { pool.cleanup(rs, pstmt, conn); }
        return arr;
    }

    /**
     * Client-side Contract Inspector. Validates RBAC before showing schema details.
     */
    private JSONObject getContractDetail(UUID appId, UUID contractId) throws SQLException {
        if (contractId == null) throw new IllegalArgumentException("contract_id is required.");
        
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            String sql = "SELECT c.* FROM data_contracts c " +
                         "JOIN app_contracts ac ON c.contract_id = ac.contract_id " +
                         "WHERE ac.app_id = ? AND c.contract_id = ?";
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, appId);
            pstmt.setObject(2, contractId);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                JSONObject c = new JSONObject();
                c.put("contract_id", rs.getString("contract_id"));
                c.put("name", rs.getString("name"));
                JSONParser parser = new JSONParser();
                try { c.put("schema_definition", parser.parse(rs.getString("schema_definition"))); } catch (Exception e) {}
                try { c.put("metadata", parser.parse(rs.getString("metadata"))); } catch (Exception e) {}
                return c;
            }
            throw new SecurityException("Application not authorized for this contract.");
        } finally { pool.cleanup(rs, pstmt, conn); }
    }

    /**
     * Initiates an outbound P2P transfer sequence via API.
     */
    private JSONObject initiateTransfer(UUID appId, JSONObject input, HttpServletRequest req) throws Exception {
        UUID contractId = extractUuid(input, "contract_id");
        String fileName = (String) input.get("file_name");
        String fileDataBase64 = (String) input.get("file_data");

        if (contractId == null || fileName == null || fileDataBase64 == null) {
            throw new IllegalArgumentException("contract_id, file_name, and file_data (Base64) are required.");
        }

        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            
            // 1. RBAC & Routing Check
            String sql = "SELECT c.receiver_partner_id, cfg.node_id, cfg.storage_active_path " +
                         "FROM data_contracts c " +
                         "JOIN app_contracts ac ON c.contract_id = ac.contract_id " +
                         "CROSS JOIN (SELECT node_id, storage_active_path FROM node_config LIMIT 1) cfg " +
                         "WHERE ac.app_id = ? AND c.contract_id = ? AND c.status = 'Active'";
            
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, appId);
            pstmt.setObject(2, contractId);
            rs = pstmt.executeQuery();

            if (!rs.next()) throw new SecurityException("Unauthorized or inactive data contract.");

            String receiverId = rs.getString("receiver_partner_id");
            String senderId = rs.getString("node_id");
            String activePath = rs.getString("storage_active_path");
            pstmt.close();

            // 2. Stage File
            byte[] fileBytes = Base64.getDecoder().decode(fileDataBase64);
            File targetFile = new File(activePath, fileName);
            try (FileOutputStream fos = new FileOutputStream(targetFile)) { fos.write(fileBytes); }

            // 3. Register Transfer
            UUID tid = UUID.randomUUID();
            String insertSql = "INSERT INTO data_transfers (transfer_id, contract_id, sender_node_id, receiver_node_id, " +
                               "file_name, file_size_bytes, file_checksum, sequence_number, message_timestamp, status, start_time) " +
                               "VALUES (?, ?, ?, ?, ?, ?, 'API_UPLOAD', 0, NOW(), 'Pending', NOW())";
            
            pstmt = conn.prepareStatement(insertSql);
            pstmt.setObject(1, tid);
            pstmt.setObject(2, contractId);
            pstmt.setString(3, senderId);
            pstmt.setString(4, receiverId);
            pstmt.setString(5, fileName);
            pstmt.setLong(6, (long) fileBytes.length);
            pstmt.executeUpdate();

            // 4. Orchestrate
            TransferEngine.getInstance().startTransfer(tid);

            return new JSONObject() {{ put("success", true); put("transfer_id", tid.toString()); }};
        } finally { pool.cleanup(rs, pstmt, conn); }
    }

    private JSONObject getTransferStatus(UUID appId, UUID tid) throws SQLException {
        if (tid == null) throw new IllegalArgumentException("transfer_id required.");
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            String sql = "SELECT t.status, t.error_message, t.start_time, t.end_time " +
                         "FROM data_transfers t " +
                         "JOIN app_contracts ac ON t.contract_id = ac.contract_id " +
                         "WHERE ac.app_id = ? AND t.transfer_id = ?";
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, appId);
            pstmt.setObject(2, tid);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                JSONObject out = new JSONObject();
                out.put("status", rs.getString("status"));
                out.put("error", rs.getString("error_message"));
                out.put("started_at", rs.getTimestamp("start_time").toString());
                Timestamp end = rs.getTimestamp("end_time");
                if (end != null) out.put("completed_at", end.toString());
                return out;
            }
            throw new SecurityException("Transfer record not found or access denied.");
        } finally { pool.cleanup(rs, pstmt, conn); }
    }

    /**
     * Returns the "Forensic Mirror" (the anonymized version) of the file.
     */
    private JSONObject getForensicPayload(UUID appId, UUID tid, HttpServletRequest req) throws Exception {
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            String sql = "SELECT t.file_name, cfg.storage_active_path " +
                         "FROM data_transfers t " +
                         "JOIN app_contracts ac ON t.contract_id = ac.contract_id " +
                         "CROSS JOIN (SELECT storage_active_path FROM node_config LIMIT 1) cfg " +
                         "WHERE ac.app_id = ? AND t.transfer_id = ?";
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, appId);
            pstmt.setObject(2, tid);
            rs = pstmt.executeQuery();
            
            if (rs.next()) {
                String fileName = rs.getString("file_name");
                Path filePath = Path.of(rs.getString("storage_active_path"), fileName);
                if (Files.exists(filePath)) {
                    JSONObject out = new JSONObject();
                    out.put("success", true);
                    out.put("payload", Files.readString(filePath, StandardCharsets.UTF_8));
                    return out;
                }
            }
            throw new SecurityException("Forensic record unavailable.");
        } finally { pool.cleanup(rs, pstmt, conn); }
    }

    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        String key = req.getHeader("X-API-Key");
        String secret = req.getHeader("X-API-Secret");

        if (key == null || secret == null) {
            OutputProcessor.errorResponse(res, 401, "Unauthorized", "X-API-Key and X-API-Secret headers required.", req.getRequestURI());
            return false;
        }

        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = null;
        try {
            pool = new PoolDB();
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("SELECT app_id, api_secret_hash FROM api_keys WHERE api_key = ? AND status = 'Active'");
            pstmt.setString(1, key);
            rs = pstmt.executeQuery();

            if (rs.next()) {
                String hash = rs.getString("api_secret_hash");
                if (passwordHasher.checkPassword(secret, hash)) {
                    req.setAttribute(ATTR_APP_ID, UUID.fromString(rs.getString("app_id")));
                    return true;
                }
            }
        } catch (Exception e) { e.printStackTrace(); } 
        finally { pool.cleanup(rs, pstmt, conn); }

        OutputProcessor.errorResponse(res, 401, "Unauthorized", "Invalid Client API credentials.", req.getRequestURI());
        return false;
    }

    private UUID extractUuid(JSONObject obj, String key) {
        Object v = obj.get(key);
        if (v == null || v.toString().trim().isEmpty()) return null;
        try { return UUID.fromString(v.toString()); } catch (Exception e) { return null; }
    }

    @Override public void get(HttpServletRequest req, HttpServletResponse res) {}
    @Override public void put(HttpServletRequest req, HttpServletResponse res) {}
    @Override public void delete(HttpServletRequest req, HttpServletResponse res) {}
}