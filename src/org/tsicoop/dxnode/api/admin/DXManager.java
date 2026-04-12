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
 * Fixed: Explicitly handles 'message_timestamp' to satisfy DB constraints.
 */
public class DXManager implements REST {

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        try {
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
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, listTransfersFromDb(input));
                    break;

                case "initiate_transfer":
                    JSONObject initResult = handleOutboundInitiation(input);
                    TransferEngine.getInstance().startTransfer(UUID.fromString((String) initResult.get("transfer_id")));
                    OutputProcessor.send(res, HttpServletResponse.SC_CREATED, initResult);
                    break;

                case "receive_transfer_stream":
                    handleIncomingJsonTransfer(input, res, req);
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

    /**
     * Staging logic for UI-initiated transfers.
     * FIX: Added message_timestamp to satisfy the NOT NULL constraint.
     */
    private JSONObject handleOutboundInitiation(JSONObject input) throws Exception {
        if (input == null) throw new IllegalArgumentException("Request body is empty.");

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
            // FIX: Columns list now includes message_timestamp
            String sql = "INSERT INTO data_transfers (transfer_id, contract_id, sender_node_id, receiver_node_id, " +
                         "file_name, file_size_bytes, file_checksum, sequence_number, message_timestamp, status, start_time) " +
                         "VALUES (?, ?, ?, ?, ?, ?, ?, 0, NOW(), 'Pending', NOW())";
            
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, tid);
            pstmt.setObject(2, UUID.fromString(contractId));
            pstmt.setString(3, localNodeId);
            pstmt.setString(4, receiverNodeId);
            pstmt.setString(5, fileName);
            pstmt.setLong(6, (long) fileBytes.length);
            pstmt.setString(7, "UPLOAD_STAGED");
            
            pstmt.executeUpdate();

            JSONObject response = new JSONObject();
            response.put("success", true);
            response.put("transfer_id", tid.toString());
            return response;
        } finally { pool.cleanup(rs, pstmt, conn); }
    }

    /**
     * Logic to process inbound P2P JSON transfers.
     * FIX: Added message_timestamp support to ensure registry sync.
     */
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

            // FIX: UPSERT logic now includes message_timestamp to satisfy constraint
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
            // Use sender's timestamp if provided, otherwise fallback to local NOW()
            pstmt.setTimestamp(7, messageTimestamp != null ? Timestamp.valueOf(messageTimestamp) : new Timestamp(System.currentTimeMillis()));
            
            pstmt.executeUpdate();
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

    @Override public boolean validate(String m, HttpServletRequest req, HttpServletResponse res) { return true; }
    @Override public void get(HttpServletRequest req, HttpServletResponse res) {}
    @Override public void put(HttpServletRequest req, HttpServletResponse res) {}
    @Override public void delete(HttpServletRequest req, HttpServletResponse res) {}
}