package org.tsicoop.dxnode.api.admin;

import org.tsicoop.dxnode.framework.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.*;
import java.util.Base64;
import java.util.UUID;

/**
 * Service to manage and monitor data transfers.
 * Standardized on JSON-based exchanges (Base64 encoded payloads).
 * Instrumented with forensic audit logging.
 */
public class DXManager implements REST {

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        try {
            // FIX: Changed getRawInput to getInput to match the InputProcessor framework utility
            JSONObject input = InputProcessor.getInput(req); 
            
            String func = req.getHeader("X-DX-FUNCTION");
            if (func == null || func.isEmpty()) {
                func = (input != null) ? (String) input.get("_func") : null;
            }

            if (func == null) {
                OutputProcessor.errorResponse(res, 400, "Bad Request", "Function identifier missing.", req.getRequestURI());
                return;
            }

            switch (func.toLowerCase()) {
                case "list_transfers":
                    OutputProcessor.send(res, 200, listTransfersFromDb(input));
                    break;

                case "initiate_transfer":
                    JSONObject initResult = handleOutboundInitiation(input, req);
                    TransferEngine.getInstance().startTransfer(UUID.fromString((String) initResult.get("transfer_id")));
                    OutputProcessor.send(res, 201, initResult);
                    break;

                case "receive_transfer_stream":
                    handleIncomingJsonTransfer(input, res, req);
                    break;

                case "get_transfer_payload":
                    OutputProcessor.send(res, 200, getTransferPayload(input, req));
                    break;

                default:
                    OutputProcessor.errorResponse(res, 400, "Bad Request", "Unknown Function: " + func, req.getRequestURI());
            }
        } catch (IllegalArgumentException e) {
            OutputProcessor.errorResponse(res, 400, "Validation Error", e.getMessage(), req.getRequestURI());
        } catch (Exception e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, 500, "Internal Protocol Error", e.getMessage(), req.getRequestURI());
        }
    }

    private JSONObject getTransferPayload(JSONObject input, HttpServletRequest req) throws Exception {
        String tid = (String) input.get("transfer_id");
        if (tid == null) throw new IllegalArgumentException("transfer_id required.");

        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            String activePath = "";
            pstmt = conn.prepareStatement("SELECT storage_active_path FROM node_config LIMIT 1");
            rs = pstmt.executeQuery();
            if (rs.next()) activePath = rs.getString(1);
            rs.close(); pstmt.close();

            pstmt = conn.prepareStatement("SELECT file_name FROM data_transfers WHERE transfer_id = ?");
            pstmt.setObject(1, UUID.fromString(tid));
            rs = pstmt.executeQuery();
            
            if (rs.next()) {
                String fileName = rs.getString("file_name");
                Path filePath = Path.of(activePath, fileName);
                
                if (Files.exists(filePath)) {
                    String content = Files.readString(filePath, StandardCharsets.UTF_8);
                    
                    JSONObject details = new JSONObject();
                    details.put("file_name", fileName);
                    details.put("action", "UI_INSPECTION");
                    // AUDIT: Record admin access
                    logAudit("SECURITY", "WARNING", InputProcessor.getEmail(req), tid, details, req);

                    JSONObject out = new JSONObject();
                    out.put("success", true);
                    out.put("payload", content);
                    return out;
                }
            }
            return new JSONObject() {{ put("success", false); put("message", "File content purged."); }};
        } finally { pool.cleanup(rs, pstmt, conn); }
    }

    private JSONObject handleOutboundInitiation(JSONObject input, HttpServletRequest req) throws Exception {
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            String localNodeId = ""; String activePath = "";
            pstmt = conn.prepareStatement("SELECT node_id, storage_active_path FROM node_config LIMIT 1");
            rs = pstmt.executeQuery();
            if (rs.next()) {
                localNodeId = rs.getString("node_id");
                activePath = rs.getString("storage_active_path");
            }
            pstmt.close();

            String contractId = (String) input.get("contract_id");
            String receiverNodeId = (String) input.get("receiver_node_id");
            String fileName = (String) input.get("file_name");
            String fileDataBase64 = (String) input.get("file_data");

            byte[] fileBytes = Base64.getDecoder().decode(fileDataBase64);
            File storageDir = new File(activePath);
            if (!storageDir.exists()) storageDir.mkdirs();
            
            File targetFile = new File(storageDir, fileName);
            try (FileOutputStream fos = new FileOutputStream(targetFile)) { fos.write(fileBytes); }

            UUID tid = UUID.randomUUID();
            String sql = "INSERT INTO data_transfers (transfer_id, contract_id, sender_node_id, receiver_node_id, " +
                         "file_name, file_size_bytes, file_checksum, sequence_number, message_timestamp, status, start_time) " +
                         "VALUES (?, ?, ?, ?, ?, ?, 'UPLOAD_STAGED', 0, NOW(), 'Pending', NOW())";
            
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, tid);
            pstmt.setObject(2, UUID.fromString(contractId));
            pstmt.setString(3, localNodeId);
            pstmt.setString(4, receiverNodeId);
            pstmt.setString(5, fileName);
            pstmt.setLong(6, (long) fileBytes.length);
            pstmt.executeUpdate();

            // AUDIT: Successful Staging
            JSONObject details = new JSONObject();
            details.put("receiver", receiverNodeId);
            details.put("file", fileName);
            logAudit("TRANSFER", "INFO", InputProcessor.getEmail(req), tid.toString(), details, req);

            return new JSONObject() {{ put("success", true); put("transfer_id", tid.toString()); }};
        } finally { pool.cleanup(rs, pstmt, conn); }
    }

    private void handleIncomingJsonTransfer(JSONObject input, HttpServletResponse res, HttpServletRequest req) throws Exception {
        String transferId = (String) input.get("transfer_id");
        String contractId = (String) input.get("contract_id");
        String senderNodeId = (String) input.get("sender_node_id");
        String fileName = (String) input.get("file_name");
        String fileDataBase64 = (String) input.get("file_data");
        String messageTimestamp = (String) input.get("message_timestamp");

        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            String activePath = ""; String localNodeId = "";
            pstmt = conn.prepareStatement("SELECT node_id, storage_active_path FROM node_config LIMIT 1");
            rs = pstmt.executeQuery();
            if (rs.next()) {
                localNodeId = rs.getString("node_id");
                activePath = rs.getString("storage_active_path");
            }
            pstmt.close();

            byte[] data = Base64.getDecoder().decode(fileDataBase64);
            Path targetFile = Path.of(activePath, fileName);
            Files.createDirectories(targetFile.getParent());
            Files.write(targetFile, data);

            String sql = "INSERT INTO data_transfers (transfer_id, contract_id, sender_node_id, receiver_node_id, " +
                         "file_name, file_size_bytes, file_checksum, sequence_number, message_timestamp, status, start_time, end_time) " +
                         "VALUES (?, ?, ?, ?, ?, ?, 'RECEPTION_VERIFIED', 0, ?, 'Received', NOW(), NOW()) " +
                         "ON CONFLICT (transfer_id) DO UPDATE SET status = 'Received', end_time = NOW()";
            
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, UUID.fromString(transferId));
            pstmt.setObject(2, UUID.fromString(contractId));
            pstmt.setString(3, senderNodeId);
            pstmt.setString(4, localNodeId);
            pstmt.setString(5, fileName);
            pstmt.setLong(6, (long) data.length);
            pstmt.setTimestamp(7, messageTimestamp != null ? Timestamp.valueOf(messageTimestamp) : new Timestamp(System.currentTimeMillis()));
            pstmt.executeUpdate();

            // AUDIT: Successful P2P Reception
            JSONObject details = new JSONObject();
            details.put("sender", senderNodeId);
            details.put("file", fileName);
            logAudit("TRANSFER", "INFO", "P2P_PROTOCOL", transferId, details, req);

            OutputProcessor.send(res, 200, new JSONObject() {{ put("success", true); }});
        } finally { pool.cleanup(rs, pstmt, conn); }
    }

    private JSONObject listTransfersFromDb(JSONObject input) throws SQLException {
        JSONObject response = new JSONObject(); JSONArray arr = new JSONArray();
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            String localId = "";
            ResultSet idRs = conn.prepareStatement("SELECT node_id FROM node_config LIMIT 1").executeQuery();
            if (idRs.next()) localId = idRs.getString(1);
            idRs.close();

            String status = (input != null) ? (String) input.get("status") : "";
            StringBuilder sql = new StringBuilder("SELECT t.*, c.name as contract_name FROM data_transfers t LEFT JOIN data_contracts c ON t.contract_id = c.contract_id WHERE 1=1");
            if (status != null && !status.isEmpty()) sql.append(" AND t.status = ?");
            sql.append(" ORDER BY t.start_time DESC LIMIT 50");

            pstmt = conn.prepareStatement(sql.toString());
            if (status != null && !status.isEmpty()) pstmt.setString(1, status);
            rs = pstmt.executeQuery();
            while (rs.next()) {
                JSONObject t = new JSONObject();
                String sender = rs.getString("sender_node_id");
                boolean isOutgoing = sender != null && sender.equals(localId);
                t.put("transfer_id", rs.getString("transfer_id"));
                t.put("file_name", rs.getString("file_name"));
                t.put("status", rs.getString("status"));
                t.put("direction", isOutgoing ? "Outgoing" : "Incoming");
                t.put("peer_node_id", isOutgoing ? rs.getString("receiver_node_id") : sender);
                t.put("start_time", rs.getTimestamp("start_time").toString());
                arr.add(t);
            }
            response.put("success", true); response.put("data", arr);
        } finally { pool.cleanup(rs, pstmt, conn); }
        return response;
    }

    /**
     * Internal helper to persist audit events.
     * FIX: Corrects the type mismatch for 'origin_ip' by using an explicit ::inet cast in SQL.
     */
    private void logAudit(String type, String severity, String actor, String entityId, JSONObject details, HttpServletRequest req) {
        Connection conn = null; PreparedStatement pstmt = null; PoolDB pool = null;
        try {
            pool = new PoolDB();
            conn = pool.getConnection();
            // FIX: Added ?::inet cast to satisfy PostgreSQL strict type requirement for network addresses.
            String sql = "INSERT INTO audit_logs (log_id, timestamp, event_type, severity, actor_type, actor_id, entity_type, entity_id, details, origin_ip) " +
                         "VALUES (?, NOW(), ?, ?, ?, ?, 'TRANSFER', ?, ?::jsonb, ?::inet)";
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
            System.err.println("[DXManager] CRITICAL: Audit persistence failed for " + type + ". Error: " + e.getMessage());
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
    }

    @Override public boolean validate(String m, HttpServletRequest req, HttpServletResponse res) { return true; }
    @Override public void get(HttpServletRequest req, HttpServletResponse res) {}
    @Override public void put(HttpServletRequest req, HttpServletResponse res) {}
    @Override public void delete(HttpServletRequest req, HttpServletResponse res) {}
}