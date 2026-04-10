package org.tsicoop.dxnode.api.admin;

import org.tsicoop.dxnode.framework.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.Part;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Service to manage and monitor data transfers.
 * Implements administrative initiation (JSON/CSV upload) and P2P protocol reception.
 */
public class DXManager implements REST {

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        try {
            // 1. Identification: Check for P2P Headers or UI/Admin Body
            String func = req.getHeader("X-DX-FUNCTION");
            JSONObject input = null;

            // Handle Multipart (Administrative Upload) vs JSON (Standard Listing)
            boolean isMultipart = req.getContentType() != null && req.getContentType().toLowerCase().contains("multipart/form-data");
            
            if (func == null || func.isEmpty()) {
                if (isMultipart) {
                    func = req.getParameter("_func");
                } else {
                    input = InputProcessor.getInput(req);
                    func = (String) input.get("_func");
                }
            }

            if (func == null) {
                OutputProcessor.errorResponse(res, 400, "Bad Request", "Transfer function identifier missing.", req.getRequestURI());
                return;
            }

            switch (func.toLowerCase()) {
                case "list_transfers":
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, listTransfersFromDb(input));
                    break;

                case "initiate_transfer":
                    // Administrative UI Trigger: Upload file and stage for P2P engine
                    JSONObject initResult = handleOutboundInitiation(req);
                    // Trigger the background TransferEngine for network delivery
                    TransferEngine.getInstance().startTransfer(UUID.fromString((String) initResult.get("transfer_id")));
                    OutputProcessor.send(res, HttpServletResponse.SC_CREATED, initResult);
                    break;

                case "receive_transfer_stream":
                    // P2P Protocol Endpoint: Receive binary stream from a remote TransferEngine
                    handleIncomingStream(req, res);
                    break;

                default:
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Unknown Function", func, req.getRequestURI());
            }
        } catch (IllegalArgumentException e) {
            OutputProcessor.errorResponse(res, 400, "Validation Error", e.getMessage(), req.getRequestURI());
        } catch (Exception e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, 500, "Internal Protocol Error", e.getMessage(), req.getRequestURI());
        }
    }

    /**
     * Logic for Node Administrator to upload a file (JSON/CSV) and start the exchange.
     */
    private JSONObject handleOutboundInitiation(HttpServletRequest req) throws Exception {
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        
        try {
            conn = pool.getConnection();
            
            // 1. Resolve Configuration (Path and Identity)
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

            // 2. Extract Multipart Parameters
            String contractId = req.getParameter("contract_id");
            String receiverNodeId = req.getParameter("receiver_node_id");
            Part filePart = req.getPart("payload_file");
            
            if (filePart == null) throw new IllegalArgumentException("Physical data file missing from request.");
            
            String fileName = filePart.getSubmittedFileName();
            String extension = fileName.substring(fileName.lastIndexOf(".") + 1).toLowerCase();

            // 3. Simple Format Restriction
            if (!"json".equals(extension) && !"csv".equals(extension)) {
                throw new IllegalArgumentException("Restricted format: Only JSON and CSV files are permitted.");
            }

            // 4. Persist to Staging Path (Disk only, no DB storage for file content)
            Path targetPath = Path.of(activePath, fileName);
            try (InputStream is = filePart.getInputStream()) {
                Files.copy(is, targetPath, StandardCopyOption.REPLACE_EXISTING);
            }

            // 5. Create Metadata Registry Entry
            UUID tid = UUID.randomUUID();
            String sql = "INSERT INTO data_transfers (transfer_id, contract_id, sender_node_id, receiver_node_id, file_name, file_size_bytes, file_checksum, sequence_number, message_timestamp, status, start_time) " +
                         "VALUES (?, ?, ?, ?, ?, ?, ?, 0, NOW(), 'Pending', NOW())";
            
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, tid);
            pstmt.setObject(2, UUID.fromString(contractId));
            pstmt.setString(3, localNodeId);
            pstmt.setString(4, receiverNodeId);
            pstmt.setString(5, fileName);
            pstmt.setLong(6, filePart.getSize());
            pstmt.setString(7, "UPLOAD_STAGED"); // Checksum calculated by engine during stream
            
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
     * Protocol Logic for acting as a receiver in the P2P chain.
     */
    private void handleIncomingStream(HttpServletRequest req, HttpServletResponse res) throws Exception {
        String transferId = req.getHeader("X-DX-TRANSFER-ID");
        String contractId = req.getHeader("X-DX-CONTRACT-ID");
        String senderId = req.getHeader("X-DX-SENDER-ID");
        String fileName = req.getHeader("X-DX-FILE-NAME");
        String sequence = req.getHeader("X-DX-SEQUENCE");

        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            String activePath = "";
            String localNodeId = "";
            pstmt = conn.prepareStatement("SELECT node_id, storage_active_path FROM node_config LIMIT 1");
            rs = pstmt.executeQuery();
            if (rs.next()) {
                localNodeId = rs.getString("node_id");
                activePath = rs.getString("storage_active_path");
            }
            pstmt.close();

            // Direct Pipe: Network Stream -> Disk Path
            Path targetFile = Path.of(activePath, fileName);
            try (InputStream is = req.getInputStream()) {
                Files.copy(is, targetFile, StandardCopyOption.REPLACE_EXISTING);
            }

            // Sync Transfer Registry (Upsert for correlation)
            String sql = "INSERT INTO data_transfers (transfer_id, contract_id, sender_node_id, receiver_node_id, file_name, file_size_bytes, file_checksum, sequence_number, message_timestamp, status, start_time, end_time) " +
                         "VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW(), 'Received', NOW(), NOW()) " +
                         "ON CONFLICT (transfer_id) DO UPDATE SET status = 'Received', end_time = NOW()";
            
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, UUID.fromString(transferId));
            pstmt.setObject(2, UUID.fromString(contractId));
            pstmt.setString(3, senderId);
            pstmt.setString(4, localNodeId);
            pstmt.setString(5, fileName);
            pstmt.setLong(6, Files.size(targetFile));
            pstmt.setString(7, "RECEPTION_VERIFIED"); 
            pstmt.setLong(8, Long.parseLong(sequence));
            
            pstmt.executeUpdate();

            JSONObject success = new JSONObject();
            success.put("success", true);
            OutputProcessor.send(res, 200, success);
        } finally { pool.cleanup(rs, pstmt, conn); }
    }

    private JSONObject listTransfersFromDb(JSONObject input) throws SQLException {
        JSONObject response = new JSONObject();
        JSONArray arr = new JSONArray();
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();

        try {
            conn = pool.getConnection();
            String localNodeId = "";
            PreparedStatement idStmt = conn.prepareStatement("SELECT node_id FROM node_config LIMIT 1");
            ResultSet idRs = idStmt.executeQuery();
            if (idRs.next()) localNodeId = idRs.getString("node_id");
            idRs.close(); idStmt.close();

            String status = input != null ? (String) input.get("status") : "";
            String search = input != null ? (String) input.get("search") : "";
            
            StringBuilder sql = new StringBuilder(
                "SELECT t.*, c.name as contract_name FROM data_transfers t " +
                "LEFT JOIN data_contracts c ON t.contract_id = c.contract_id WHERE 1=1"
            );
            
            if (status != null && !status.isEmpty()) sql.append(" AND t.status = ?");
            if (search != null && !search.isEmpty()) sql.append(" AND (t.file_name ILIKE ? OR t.transfer_id::text ILIKE ?)");
            sql.append(" ORDER BY t.start_time DESC LIMIT 50");

            pstmt = conn.prepareStatement(sql.toString());
            int idx = 1;
            if (status != null && !status.isEmpty()) pstmt.setString(idx++, status);
            if (search != null && !search.isEmpty()) {
                String f = "%" + search + "%";
                pstmt.setString(idx++, f);
                pstmt.setString(idx++, f);
            }
            
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

    @Override public boolean validate(String m, HttpServletRequest req, HttpServletResponse res) { return true; }
    @Override public void get(HttpServletRequest req, HttpServletResponse res) {}
    @Override public void put(HttpServletRequest req, HttpServletResponse res) {}
    @Override public void delete(HttpServletRequest req, HttpServletResponse res) {}
}