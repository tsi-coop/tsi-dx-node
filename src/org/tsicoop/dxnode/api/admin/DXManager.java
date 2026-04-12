package org.tsicoop.dxnode.api.admin;

import org.tsicoop.dxnode.framework.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.sql.*;
import java.util.Base64;
import java.util.UUID;

/**
 * Service to manage and monitor data transfers.
 * Updated to support JSON-based Base64 uploads for the Administrative UI,
 * bypassing multipart stream conflicts.
 */
public class DXManager implements REST {

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        try {
            // 1. Identification: Check for P2P protocol headers
            String func = req.getHeader("X-DX-FUNCTION");
            JSONObject input = null;

            // 2. Resolve Input: Administrative actions now use standard JSON (Base64 approach)
            if (func == null || func.isEmpty()) {
                input = InputProcessor.getInput(req);
                if (input != null) {
                    func = (String) input.get("_func");
                }
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
                    // Administrative UI Trigger: Base64 data inside standard JSON body
                    JSONObject initResult = handleOutboundInitiation(input);
                    // Engage the background engine for P2P delivery
                    TransferEngine.getInstance().startTransfer(UUID.fromString((String) initResult.get("transfer_id")));
                    OutputProcessor.send(res, HttpServletResponse.SC_CREATED, initResult);
                    break;

                case "receive_transfer_stream":
                    // P2P Protocol Endpoint: Receives binary stream from remote TransferEngine
                    handleIncomingStream(req, res);
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
     * Logic for Node Administrator to upload a file via JSON Base64.
     * Decodes the string and stages it on disk for the TransferEngine.
     */
    private JSONObject handleOutboundInitiation(JSONObject input) throws Exception {
        if (input == null) throw new IllegalArgumentException("Request body is empty.");

        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        
        try {
            conn = pool.getConnection();
            
            // 1. Resolve Local Configuration
            String localNodeId = "";
            String activePath = "";
            pstmt = conn.prepareStatement("SELECT node_id, storage_active_path FROM node_config LIMIT 1");
            rs = pstmt.executeQuery();
            if (rs.next()) {
                localNodeId = rs.getString("node_id");
                activePath = rs.getString("storage_active_path");
            }
            pstmt.close();

            if (localNodeId.isEmpty()) throw new IllegalStateException("Node identity not configured.");

            // 2. Extract Data from JSON Payload
            String contractId = (String) input.get("contract_id");
            String receiverNodeId = (String) input.get("receiver_node_id");
            String fileName = (String) input.get("file_name");
            String fileDataBase64 = (String) input.get("file_data");

            if (fileDataBase64 == null || fileDataBase64.isEmpty()) {
                throw new IllegalArgumentException("Physical data (Base64) is missing from the payload.");
            }

            // 3. Decode and Persist to Staging Path
            byte[] fileBytes = Base64.getDecoder().decode(fileDataBase64);
            
            // FIX: Ensure parent directories exist before writing
            File storageDir = new File(activePath);
            if (!storageDir.exists()) {
                storageDir.mkdirs();
            }
            
            File targetFile = new File(storageDir, fileName);
            try (FileOutputStream fos = new FileOutputStream(targetFile)) {
                fos.write(fileBytes);
            }

            // 4. Create Audit/Metadata Registry Entry
            UUID tid = UUID.randomUUID();
            
            // FIX: Explicitly listed all mandatory protocol columns including 'file_checksum', 
            // 'sequence_number', and 'message_timestamp' to satisfy database constraints.
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
            pstmt.setString(7, "UPLOAD_STAGED"); // Checksum placeholder for UI-initiated uploads
            
            pstmt.executeUpdate();

            JSONObject response = new JSONObject();
            response.put("success", true);
            response.put("transfer_id", tid.toString());
            return response;

        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }

    /**
     * P2P Reception Logic: Receives raw binary stream from partner node.
     */
    private void handleIncomingStream(HttpServletRequest req, HttpServletResponse res) throws Exception {
        String transferId = req.getHeader("X-DX-TRANSFER-ID");
        String fileName = req.getHeader("X-DX-FILE-NAME");

        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("SELECT storage_active_path FROM node_config LIMIT 1");
            rs = pstmt.executeQuery();
            String path = rs.next() ? rs.getString(1) : "/tmp";
            pstmt.close();

            // Direct Pipe: Network Stream -> Disk
            Path targetFile = Path.of(path, fileName);
            
            // FIX: Ensure parent directories exist for the inbound stream
            Files.createDirectories(targetFile.getParent());
            
            try (InputStream is = req.getInputStream()) {
                Files.copy(is, targetFile, StandardCopyOption.REPLACE_EXISTING);
            }

            // Update status to mark receipt
            String sql = "UPDATE data_transfers SET status = 'Received', end_time = NOW() WHERE transfer_id = ?";
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, UUID.fromString(transferId));
            pstmt.executeUpdate();

            OutputProcessor.send(res, 200, new JSONObject() {{ put("success", true); }});
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }

    private JSONObject listTransfersFromDb(JSONObject input) throws SQLException {
        JSONObject response = new JSONObject();
        JSONArray arr = new JSONArray();
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();

        try {
            conn = pool.getConnection();
            String localNodeId = "";
            ResultSet idRs = conn.prepareStatement("SELECT node_id FROM node_config LIMIT 1").executeQuery();
            if (idRs.next()) localNodeId = idRs.getString(1);
            idRs.close();

            String status = input != null ? (String) input.get("status") : "";
            
            StringBuilder sql = new StringBuilder(
                "SELECT t.*, c.name as contract_name FROM data_transfers t " +
                "LEFT JOIN data_contracts c ON t.contract_id = c.contract_id WHERE 1=1"
            );
            
            if (status != null && !status.isEmpty()) sql.append(" AND t.status = ?");
            sql.append(" ORDER BY t.start_time DESC LIMIT 50");

            pstmt = conn.prepareStatement(sql.toString());
            if (status != null && !status.isEmpty()) pstmt.setString(1, status);
            
            rs = pstmt.executeQuery();
            while (rs.next()) {
                JSONObject t = new JSONObject();
                String sender = rs.getString("sender_node_id");
                boolean isOutgoing = sender != null && sender.equals(localNodeId);

                t.put("transfer_id", rs.getString("transfer_id"));
                t.put("file_name", rs.getString("file_name"));
                t.put("status", rs.getString("status"));
                t.put("direction", isOutgoing ? "Outgoing" : "Incoming");
                t.put("peer_node_id", isOutgoing ? rs.getString("receiver_node_id") : sender);
                t.put("start_time", rs.getTimestamp("start_time").toString());
                arr.add(t);
            }
            response.put("success", true);
            response.put("data", arr);
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return response;
    }

    @Override public boolean validate(String m, HttpServletRequest req, HttpServletResponse res) { return true; }
    @Override public void get(HttpServletRequest req, HttpServletResponse res) {}
    @Override public void put(HttpServletRequest req, HttpServletResponse res) {}
    @Override public void delete(HttpServletRequest req, HttpServletResponse res) {}
}