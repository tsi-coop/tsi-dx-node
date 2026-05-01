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
 * Implements "Single Package Routing" using JSON-embedded Base64 payloads.
 * This allows external systems to push data directly without folder-based uploads.
 * FIX: Resolved unclosed string literals and illegal characters in the validate method.
 */
public class DX implements Action {

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
                    // PRIMARY ACTION: Accepts Base64 string directly in the JSON body
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
        } catch (IllegalArgumentException iae) {
            OutputProcessor.errorResponse(res, 400, "Bad Request", iae.getMessage(), req.getRequestURI());
        } catch (Exception e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, 500, "Internal API Error", e.getMessage(), req.getRequestURI());
        }
    }

    /**
     * Initiates a transfer using a Base64 string provided in the 'file_data' attribute.
     */
    private JSONObject initiateTransfer(UUID appId, JSONObject input, HttpServletRequest req) throws Exception {
        UUID contractId = extractUuid(input, "contract_id");
        String fileName = (String) input.get("file_name");
        String fileDataBase64 = (String) input.get("file_data");

        if (contractId == null || fileName == null || fileDataBase64 == null) {
            throw new IllegalArgumentException("contract_id, file_name, and file_data (Base64 string) are required.");
        }

        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            
            // 1. Resolve Contract Metadata and Active Storage Path
            String sql = "SELECT c.receiver_partner_id, c.metadata, cfg.node_id, cfg.storage_active_path " +
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
            String contractMetadataRaw = rs.getString("metadata");
            pstmt.close();

            // 2. Base64 Sanitization & Validation
            if (fileDataBase64.contains(",")) {
                fileDataBase64 = fileDataBase64.split(",")[1];
            }

            byte[] fileBytes;
            try {
                fileBytes = Base64.getDecoder().decode(fileDataBase64.trim());
            } catch (Exception e) {
                throw new IllegalArgumentException("Invalid Base64 encoding in 'file_data'.");
            }
            
            // Fail-Fast Check for JSON Contracts
            if (contractMetadataRaw != null && contractMetadataRaw.contains("\"format\":\"json\"")) {
                try {
                    new JSONParser().parse(new String(fileBytes, StandardCharsets.UTF_8));
                } catch (Exception pe) {
                    throw new IllegalArgumentException("Structural Error: Provided data is not valid JSON.");
                }
            }

            // 3. Sovereign Staging
            File storageDir = new File(activePath);
            if (!storageDir.exists()) storageDir.mkdirs();
            
            File targetFile = new File(storageDir, fileName);
            try (FileOutputStream fos = new FileOutputStream(targetFile)) { 
                fos.write(fileBytes); 
            }

            // 4. Register the Transfer Lifecycle
            UUID tid = UUID.randomUUID();
            String insertSql = "INSERT INTO data_transfers (transfer_id, contract_id, sender_node_id, receiver_node_id, " +
                               "file_name, file_size_bytes, file_checksum, sequence_number, message_timestamp, status, start_time) " +
                               "VALUES (?, ?, ?, ?, ?, ?, 'API_BASE64_INGEST', 0, NOW(), 'Pending', NOW())";
            
            pstmt = conn.prepareStatement(insertSql);
            pstmt.setObject(1, tid);
            pstmt.setObject(2, contractId);
            pstmt.setString(3, senderId);
            pstmt.setString(4, receiverId);
            pstmt.setString(5, fileName);
            pstmt.setLong(6, (long) fileBytes.length);
            pstmt.executeUpdate();

            // 5. Orchestrate
            TransferEngine.getInstance().startTransfer(tid);

            return new JSONObject() {{ 
                put("success", true); 
                put("transfer_id", tid.toString()); 
                put("message", "Single-package payload accepted for processing.");
            }};
        } finally { pool.cleanup(rs, pstmt, conn); }
    }

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

    private JSONObject getContractDetail(UUID appId, UUID contractId) throws SQLException {
        if (contractId == null) throw new IllegalArgumentException("contract_id required.");
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            String sql = "SELECT c.* FROM data_contracts c JOIN app_contracts ac ON c.contract_id = ac.contract_id " +
                         "WHERE ac.app_id = ? AND c.contract_id = ?";
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, appId);
            pstmt.setObject(2, contractId);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                JSONObject c = new JSONObject();
                c.put("contract_id", rs.getString("contract_id"));
                c.put("name", rs.getString("name"));
                JSONParser p = new JSONParser();
                try { c.put("schema_definition", p.parse(rs.getString("schema_definition"))); } catch (Exception e) {}
                try { c.put("metadata", p.parse(rs.getString("metadata"))); } catch (Exception e) {}
                return c;
            }
            throw new SecurityException("Unauthorized access to contract details.");
        } finally { pool.cleanup(rs, pstmt, conn); }
    }

    private JSONObject getTransferStatus(UUID appId, UUID tid) throws SQLException {
        if (tid == null) throw new IllegalArgumentException("transfer_id required.");
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            String sql = "SELECT t.status, t.error_message, t.start_time, t.end_time FROM data_transfers t " +
                         "JOIN app_contracts ac ON t.contract_id = ac.contract_id WHERE ac.app_id = ? AND t.transfer_id = ?";
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, appId);
            pstmt.setObject(2, tid);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                JSONObject o = new JSONObject();
                o.put("status", rs.getString("status"));
                o.put("error", rs.getString("error_message"));
                o.put("started_at", rs.getTimestamp("start_time").toString());
                Timestamp end = rs.getTimestamp("end_time");
                if (end != null) o.put("completed_at", end.toString());
                return o;
            }
            throw new SecurityException("Transfer not found.");
        } finally { pool.cleanup(rs, pstmt, conn); }
    }

    private JSONObject getForensicPayload(UUID appId, UUID tid, HttpServletRequest req) throws Exception {
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            String sql = "SELECT t.file_name, cfg.storage_active_path FROM data_transfers t " +
                         "JOIN app_contracts ac ON t.contract_id = ac.contract_id " +
                         "CROSS JOIN (SELECT storage_active_path FROM node_config LIMIT 1) cfg " +
                         "WHERE ac.app_id = ? AND t.transfer_id = ?";
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, appId);
            pstmt.setObject(2, tid);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                Path p = Path.of(rs.getString("storage_active_path"), rs.getString("file_name"));
                if (Files.exists(p)) {
                    JSONObject out = new JSONObject();
                    out.put("success", true);
                    out.put("payload", Files.readString(p, StandardCharsets.UTF_8));
                    return out;
                }
            }
            throw new SecurityException("Forensic data unavailable.");
        } finally { pool.cleanup(rs, pstmt, conn); }
    }

    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        String key = req.getHeader("X-API-Key");
        String secret = req.getHeader("X-API-Secret");
        if (key == null || secret == null) {
            OutputProcessor.errorResponse(res, 401, "Unauthorized", "Authentication headers missing.", req.getRequestURI());
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
                if (passwordHasher.checkPassword(secret, rs.getString("api_secret_hash"))) {
                    req.setAttribute(ATTR_APP_ID, UUID.fromString(rs.getString("app_id")));
                    return true;
                }
            }
        } catch (Exception e) { e.printStackTrace(); } 
        finally { pool.cleanup(rs, pstmt, conn); }
        OutputProcessor.errorResponse(res, 401, "Unauthorized", "Invalid API Credentials.", req.getRequestURI());
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