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
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.Optional;

// Assuming these utility classes are provided as per the user's style
// import org.tsicoop.aadhaarvault.framework.REST;
// import org.tsicoop.aadhaarvault.framework.InputProcessor;
// import org.tsicoop.aadhaarvault.framework.OutputProcessor;
// import org.tsicoop.aadhaarvault.framework.PoolDB;
// import org.tsicoop.aadhaarvault.framework.JWTUtil; // For JWT validation and claims extraction
// import org.tsicoop.aadhaarvault.framework.FileUtil; // For file operations (checksum, storage)
// import org.tsicoop.aadhaarvault.framework.TransferEngine; // Placeholder for actual P2P transfer logic

public class DXMgmt implements REST {

    // All HTTP methods will now defer to the POST method
    @Override
    public void get(HttpServletRequest req, HttpServletResponse res) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "GET method is not used directly. Use POST with '_func' attribute.", req.getRequestURI());
    }

    @Override
    public void put(HttpServletRequest req, HttpServletResponse res) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "PUT method is not used directly. Use POST with '_func' attribute.", req.getRequestURI());
    }

    @Override
    public void delete(HttpServletRequest req, HttpServletResponse res) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "DELETE method is not used directly. Use POST with '_func' attribute.", req.getRequestURI());
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
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required '_func' attribute in input JSON.", req.getRequestURI());
                return;
            }

            // Extract IDs if present in input for specific operations
            UUID transferId = null;
            String transferIdStr = (String) input.get("transfer_id");
            if (!transferIdStr.isEmpty()) {
                try {
                    transferId = UUID.fromString(transferIdStr);
                } catch (IllegalArgumentException e) {
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid 'transfer_id' format.", req.getRequestURI());
                    return;
                }
            }

            UUID bulkUploadId = null;
            String bulkUploadIdStr = (String) input.get("bulk_upload_id");
            if (!bulkUploadIdStr.isEmpty()) {
                try {
                    bulkUploadId = UUID.fromString(bulkUploadIdStr);
                } catch (IllegalArgumentException e) {
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid 'bulk_upload_id' format.", req.getRequestURI());
                    return;
                }
            }

            switch (func.toLowerCase()) {
                // --- Transfer Monitoring & Management ---
                case "list_transfers":
                    String statusFilter = (String) input.get("status");
                    String directionFilter = (String) input.get("direction"); // "incoming", "outgoing"
                    String partnerIdFilter = (String) input.get("partner_id");
                    String contractIdFilter = (String) input.get("contract_id");
                    String startDateStr = (String) input.get("start_date");
                    String endDateStr = (String) input.get("end_date");
                    String search = (String) input.get("search");
                    int page = (int)(long)input.get("page");
                    int limit = (int) input.get("limit");

                    outputArray = listTransfersFromDb(statusFilter, directionFilter, partnerIdFilter, contractIdFilter, startDateStr, endDateStr, search, page, limit);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, outputArray);
                    break;

                case "get_transfer":
                    if (transferId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'transfer_id' is required for 'get_transfer' function.", req.getRequestURI());
                        return;
                    }
                    JSONObject transferOptional = getTransferByIdFromDb(transferId);
                    if (!transferOptional.isEmpty()) {
                        OutputProcessor.send(res, HttpServletResponse.SC_OK, transferOptional);
                    } else {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Transfer with ID '" + transferId + "' not found.", req.getRequestURI());
                    }
                    break;

                case "resend_transfer":
                    if (transferId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'transfer_id' is required for 'resend_transfer' function.", req.getRequestURI());
                        return;
                    }
                    JSONObject originalTransfer = getTransferByIdFromDb(transferId);
                    if (originalTransfer.isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Original transfer with ID '" + transferId + "' not found.", req.getRequestURI());
                        return;
                    }

                    // Extract necessary details from original transfer for re-send
                    String originalFileName = (String) originalTransfer.get("file_name");
                    String originalLocalFilePath = (String) originalTransfer.get("local_file_path"); // Path to the data on local disk
                    String originalSenderNodeId = (String) originalTransfer.get("sender_node_id"); // This node's ID
                    String originalReceiverNodeId = (String) originalTransfer.get("receiver_node_id");
                    String originalContractId = (String) originalTransfer.get("contract_id");

                    // Validate that the original transfer was outgoing from this node
                    // (A re-send implies re-sending something *we* sent before)
                    // This would require getting the local node's ID. For now, assuming it's an outgoing transfer.
                    // if (!originalSenderNodeId.equals(getLocalNodeId())) {
                    //     OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "Cannot re-send an incoming transfer.", req.getRequestURI());
                    //     return;
                    // }

                    // Trigger the re-send logic (this would typically be asynchronous)
                    // The TransferEngine would handle creating a new data_transfer record
                    // with a new sequence number, and re-initiating the P2P transfer.
                    /*JSONObject resendOutput = TransferEngine.resendTransfer(
                            originalFileName,
                            originalLocalFilePath, // Path to the data content
                            originalSenderNodeId,
                            originalReceiverNodeId,
                            UUID.fromString(originalContractId)
                    );*/
                    OutputProcessor.send(res, HttpServletResponse.SC_ACCEPTED, ""); // 202 Accepted
                    break;

                // --- Bulk Upload Management ---
                case "list_bulk_uploads":
                    String bulkStatusFilter = (String) input.get("status");
                    String bulkSearch = (String) input.get("search");
                    int bulkPage = (int)(long)input.get("page");
                    int bulkLimit = (int)(long) input.get("limit");

                    outputArray = listBulkUploadsFromDb(bulkStatusFilter, bulkSearch, bulkPage, bulkLimit);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, outputArray);
                    break;

                case "get_bulk_upload":
                    if (bulkUploadId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'bulk_upload_id' is required for 'get_bulk_upload' function.", req.getRequestURI());
                        return;
                    }
                    Optional<JSONObject> bulkUploadOptional = getBulkUploadByIdFromDb(bulkUploadId);
                    if (bulkUploadOptional.isPresent()) {
                        output = bulkUploadOptional.get();
                        OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
                    } else {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Bulk upload with ID '" + bulkUploadId + "' not found.", req.getRequestURI());
                    }
                    break;

                case "initiate_bulk_upload":
                    // This endpoint would typically handle multipart/form-data for file uploads
                    // or accept a list of file paths if files are pre-staged.
                    // For this RPC-style POST, we'll assume file paths are provided.
                    JSONArray targetPartnerIdsJson = (JSONArray) input.get("target_partner_ids");
                    String contractIdStr = (String) input.get("contract_id");
                    JSONArray filesJson = (JSONArray) input.get("files"); // Array of {"name": "...", "path": "..."}

                    if (targetPartnerIdsJson == null || targetPartnerIdsJson.isEmpty() || contractIdStr.isEmpty() || filesJson == null || filesJson.isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required fields (target_partner_ids, contract_id, files) for 'initiate_bulk_upload'.", req.getRequestURI());
                        return;
                    }

                    List<UUID> targetPartnerIds = new ArrayList<>();
                    for (Object id : targetPartnerIdsJson) {
                        try {
                            targetPartnerIds.add(UUID.fromString((String) id));
                        } catch (IllegalArgumentException e) {
                            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid partner ID format in target_partner_ids.", req.getRequestURI());
                            return;
                        }
                    }
                    UUID contractId = UUID.fromString(contractIdStr);

                    List<JSONObject> filesToTransfer = new ArrayList<>();
                    for (Object fileObj : filesJson) {
                        if (fileObj instanceof JSONObject) {
                            JSONObject file = (JSONObject) fileObj;
                            String fileName = (String) file.get("name");
                            String filePath = (String) file.get("path");
                            if (fileName.isEmpty() || filePath.isEmpty()) {
                                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Each file in 'files' array must have 'name' and 'path'.", req.getRequestURI());
                                return;
                            }
                            filesToTransfer.add(file);
                        }
                    }

                    // Get user ID from JWT claims for initiated_by_user_id
/*                    JSONObject claims = JWTUtil.getClaims(req.getHeader("Authorization").substring(7));
                    String initiatedByUserId = (String) claims.get("user_id");

                    output = initiateBulkUpload(targetPartnerIds, contractId, filesToTransfer, UUID.fromString(initiatedByUserId));
                    OutputProcessor.send(res, HttpServletResponse.SC_ACCEPTED, output); // 202 Accepted*/
                    break;

                default:
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Unknown or unsupported '_func' value: " + func, req.getRequestURI());
                    break;
            }

        } catch (SQLException e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Database Error", "A database error occurred: " + e.getMessage(), req.getRequestURI());
        } catch (DateTimeParseException e) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid date format. Use ISO 8601 (e.g., YYYY-MM-DDTHH:MM:SSZ).", req.getRequestURI());
        } catch (Exception e) { // Catch all other exceptions, including from JWTUtil.getClaims
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error", "An unexpected error occurred: " + e.getMessage(), req.getRequestURI());
        }
    }

    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        if (!"POST".equalsIgnoreCase(method)) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "Only POST method is supported for Data Transfer Management operations.", req.getRequestURI());
            return false;
        }

        String authHeader = req.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized", "Missing or invalid Authorization header.", req.getRequestURI());
            return false;
        }

        /*String token = authHeader.substring(7);

        try {
            if (!JWTUtil.validateToken(token)) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized", "Invalid or expired token.", req.getRequestURI());
                return false;
            }

            JSONObject claims = JWTUtil.getClaims(token);
            JSONArray rolesJson = (JSONArray) claims.get("roles");
            if (rolesJson == null || rolesJson.isEmpty()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "User has no assigned roles.", req.getRequestURI());
                return false;
            }

            boolean isAdmin = false;
            boolean canInitiateTransfer = false;
            boolean canViewTransfer = false;
            for (Object role : rolesJson) {
                String roleName = (String) role;
                if ("Administrator".equalsIgnoreCase(roleName)) {
                    isAdmin = true;
                    canInitiateTransfer = true;
                    canViewTransfer = true;
                    break;
                }
                // Example: Specific roles for data transfer operations
                // if ("DataUploader".equalsIgnoreCase(roleName)) {
                //     canInitiateTransfer = true;
                // }
                // if ("DataDownloader".equalsIgnoreCase(roleName) || "Auditor".equalsIgnoreCase(roleName)) {
                //     canViewTransfer = true;
                // }
            }

            JSONObject input = InputProcessor.getInput(req); // Parse input for func
            String func = input.optString("_func", "").trim();

            if (func.isEmpty()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing '_func' attribute for authorization check.", req.getRequestURI());
                return false;
            }

            switch (func.toLowerCase()) {
                case "list_transfers":
                case "get_transfer":
                case "list_bulk_uploads":
                case "get_bulk_upload":
                    if (!canViewTransfer) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "Access denied. Insufficient privileges to view transfer data.", req.getRequestURI());
                        return false;
                    }
                    break;
                case "resend_transfer":
                case "initiate_bulk_upload":
                    if (!canInitiateTransfer) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "Access denied. Insufficient privileges to initiate or re-send transfers.", req.getRequestURI());
                        return false;
                    }
                    break;
                default:
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Unknown or unsupported '_func' value for authorization: " + func, req.getRequestURI());
                    return false;
            }

            return InputProcessor.validate(req, res); // This validates content-type and basic body parsing

        } catch (Exception e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error", "Authorization or token validation failed: " + e.getMessage(), req.getRequestURI());
            return false;
        }*/
        return InputProcessor.validate(req, res); // This validates content-type and basic body parsing
    }

    // --- Helper Methods for Data Transfer Monitoring & Management ---

    /**
     * Retrieves a list of data transfers from the database with optional filtering and pagination.
     * @return JSONArray of data transfer JSONObjects.
     * @throws SQLException if a database access error occurs.
     */
    private JSONArray listTransfersFromDb(String statusFilter, String directionFilter, String partnerIdFilter, String contractIdFilter, String startDateStr, String endDateStr, String search, int page, int limit) throws SQLException {
        JSONArray transfersArray = new JSONArray();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        StringBuilder sqlBuilder = new StringBuilder("SELECT transfer_id, bulk_upload_id, contract_id, sender_node_id, receiver_node_id, file_name, file_size_bytes, status, start_time, end_time FROM data_transfers WHERE 1=1");
        List<Object> params = new ArrayList<>();

        if (statusFilter != null && !statusFilter.isEmpty()) {
            sqlBuilder.append(" AND status = ?");
            params.add(statusFilter);
        }
        // Direction filter would require knowing the local node ID
        // For now, assuming sender_node_id and receiver_node_id are sufficient for UI to determine direction
        if (partnerIdFilter != null && !partnerIdFilter.isEmpty()) {
            // This needs to check against both sender and receiver node IDs, potentially joining with partners table
            sqlBuilder.append(" AND (sender_node_id = (SELECT node_id FROM partners WHERE partner_id = ?) OR receiver_node_id = (SELECT node_id FROM partners WHERE partner_id = ?))");
            params.add(UUID.fromString(partnerIdFilter));
            params.add(UUID.fromString(partnerIdFilter));
        }
        if (contractIdFilter != null && !contractIdFilter.isEmpty()) {
            sqlBuilder.append(" AND contract_id = ?");
            params.add(UUID.fromString(contractIdFilter));
        }
        if (startDateStr != null && !startDateStr.isEmpty()) {
            sqlBuilder.append(" AND start_time >= ?");
            params.add(Timestamp.valueOf(LocalDateTime.parse(startDateStr)));
        }
        if (endDateStr != null && !endDateStr.isEmpty()) {
            sqlBuilder.append(" AND start_time <= ?");
            params.add(Timestamp.valueOf(LocalDateTime.parse(endDateStr)));
        }
        if (search != null && !search.isEmpty()) {
            sqlBuilder.append(" AND file_name ILIKE ?");
            params.add("%" + search + "%");
        }

        sqlBuilder.append(" ORDER BY start_time DESC LIMIT ? OFFSET ?");
        params.add(limit);
        params.add((page - 1) * limit);

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sqlBuilder.toString());
            for (int i = 0; i < params.size(); i++) {
                pstmt.setObject(i + 1, params.get(i));
            }
            rs = pstmt.executeQuery();

            while (rs.next()) {
                JSONObject transfer = new JSONObject();
                transfer.put("transfer_id", rs.getString("transfer_id"));
                transfer.put("bulk_upload_id", rs.getString("bulk_upload_id"));
                transfer.put("contract_id", rs.getString("contract_id"));
                transfer.put("sender_node_id", rs.getString("sender_node_id"));
                transfer.put("receiver_node_id", rs.getString("receiver_node_id"));
                transfer.put("file_name", rs.getString("file_name"));
                transfer.put("file_size_bytes", rs.getLong("file_size_bytes"));
                transfer.put("status", rs.getString("status"));
                transfer.put("start_time", rs.getTimestamp("start_time").toInstant().toString());
                transfer.put("end_time", rs.getTimestamp("end_time") != null ? rs.getTimestamp("end_time").toInstant().toString() : null);
                transfersArray.add(transfer);
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return transfersArray;
    }

    /**
     * Retrieves details of a single data transfer by its ID.
     * @param transferId The UUID of the transfer.
     * @return An Optional containing the transfer JSONObject if found, otherwise empty.
     * @throws SQLException if a database access error occurs.
     */
    private JSONObject getTransferByIdFromDb(UUID transferId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        JSONObject transfer = new JSONObject();
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "SELECT transfer_id, bulk_upload_id, contract_id, sender_node_id, receiver_node_id, file_name, file_size_bytes, file_checksum, sequence_number, message_timestamp, status, error_message, local_file_path, initiated_by_user_id, start_time, end_time FROM data_transfers WHERE transfer_id = ?";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, transferId);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                transfer.put("transfer_id", rs.getString("transfer_id"));
                transfer.put("bulk_upload_id", rs.getString("bulk_upload_id"));
                transfer.put("contract_id", rs.getString("contract_id"));
                transfer.put("sender_node_id", rs.getString("sender_node_id"));
                transfer.put("receiver_node_id", rs.getString("receiver_node_id"));
                transfer.put("file_name", rs.getString("file_name"));
                transfer.put("file_size_bytes", rs.getLong("file_size_bytes"));
                transfer.put("file_checksum", rs.getString("file_checksum"));
                transfer.put("sequence_number", rs.getLong("sequence_number"));
                transfer.put("message_timestamp", rs.getTimestamp("message_timestamp").toInstant().toString());
                transfer.put("status", rs.getString("status"));
                transfer.put("error_message", rs.getString("error_message"));
                transfer.put("local_file_path", rs.getString("local_file_path"));
                transfer.put("initiated_by_user_id", rs.getString("initiated_by_user_id"));
                transfer.put("start_time", rs.getTimestamp("start_time").toInstant().toString());
                transfer.put("end_time", rs.getTimestamp("end_time") != null ? rs.getTimestamp("end_time").toInstant().toString() : null);
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return transfer;
    }

    // --- Helper Methods for Bulk Upload Management ---

    /**
     * Initiates a bulk upload operation, creating a record in the database.
     * This method would then trigger asynchronous processing of individual files.
     * @param targetPartnerIds List of UUIDs for target partners.
     * @param contractId The UUID of the data contract.
     * @param filesToTransfer List of JSONObjects, each with 'name' and 'path' of the file.
     * @param initiatedByUserId The UUID of the user initiating the bulk upload.
     * @return JSONObject containing the bulk upload ID and status.
     * @throws SQLException if a database access error occurs.
     */
    private JSONObject initiateBulkUpload(List<UUID> targetPartnerIds, UUID contractId, List<JSONObject> filesToTransfer, UUID initiatedByUserId) throws SQLException {
        JSONObject output = new JSONObject();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        String sql = "INSERT INTO bulk_uploads (initiated_by_user_id, target_partner_ids, contract_id, total_files, status) VALUES (?, ?, ?, ?, ?) RETURNING bulk_upload_id";

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, initiatedByUserId);
            // Convert List<UUID> to UUID[] for PostgreSQL array type
            pstmt.setArray(2, conn.createArrayOf("uuid", targetPartnerIds.toArray(new UUID[0])));
            pstmt.setObject(3, contractId);
            pstmt.setInt(4, filesToTransfer.size());
            pstmt.setString(5, "Initiated"); // Initial status

            int affectedRows = pstmt.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Initiating bulk upload failed, no rows affected.");
            }

            rs = pstmt.getGeneratedKeys();
            if (rs.next()) {
                String bulkUploadId = rs.getString("bulk_upload_id");
                output.put("bulk_upload_id", bulkUploadId);
                output.put("status", "Initiated");
                output.put("total_files", filesToTransfer.size());
                output.put("message", "Bulk upload initiated successfully. Files will be processed asynchronously.");

                // TODO: Trigger asynchronous processing for each file in filesToTransfer
                // This would involve sending messages to an internal queue for the TransferEngine to pick up.
                // Each message would contain details for a single transfer (file path, target partners, contract, bulk_upload_id).
                // Example: TransferEngine.enqueueSingleTransfer(bulkUploadId, file, targetPartnerIds, contractId, initiatedByUserId);

            } else {
                throw new SQLException("Initiating bulk upload failed, no ID obtained.");
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return new JSONObject() {{ put("success", true); put("data", output); }};
    }

    /**
     * Retrieves a list of bulk uploads from the database with optional filtering and pagination.
     * @return JSONArray of bulk upload JSONObjects.
     * @throws SQLException if a database access error occurs.
     */
    private JSONArray listBulkUploadsFromDb(String statusFilter, String search, int page, int limit) throws SQLException {
        JSONArray bulkUploadsArray = new JSONArray();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        StringBuilder sqlBuilder = new StringBuilder("SELECT bulk_upload_id, initiated_by_user_id, contract_id, total_files, successful_files, failed_files, status, start_time, end_time, error_summary FROM bulk_uploads WHERE 1=1");
        List<Object> params = new ArrayList<>();

        if (statusFilter != null && !statusFilter.isEmpty()) {
            sqlBuilder.append(" AND status = ?");
            params.add(statusFilter);
        }
        if (search != null && !search.isEmpty()) {
            // Assuming search could be on contract name or user name (requires joins)
            // For simplicity, no specific search on text fields for now.
        }

        sqlBuilder.append(" ORDER BY start_time DESC LIMIT ? OFFSET ?");
        params.add(limit);
        params.add((page - 1) * limit);

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sqlBuilder.toString());
            for (int i = 0; i < params.size(); i++) {
                pstmt.setObject(i + 1, params.get(i));
            }
            rs = pstmt.executeQuery();

            while (rs.next()) {
                JSONObject bulkUpload = new JSONObject();
                bulkUpload.put("bulk_upload_id", rs.getString("bulk_upload_id"));
                bulkUpload.put("initiated_by_user_id", rs.getString("initiated_by_user_id"));
                bulkUpload.put("contract_id", rs.getString("contract_id"));
                bulkUpload.put("total_files", rs.getInt("total_files"));
                bulkUpload.put("successful_files", rs.getInt("successful_files"));
                bulkUpload.put("failed_files", rs.getInt("failed_files"));
                bulkUpload.put("status", rs.getString("status"));
                bulkUpload.put("start_time", rs.getTimestamp("start_time").toInstant().toString());
                bulkUpload.put("end_time", rs.getTimestamp("end_time") != null ? rs.getTimestamp("end_time").toInstant().toString() : null);
                bulkUpload.put("error_summary", rs.getString("error_summary"));
                bulkUploadsArray.add(bulkUpload);
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return bulkUploadsArray;
    }

    /**
     * Retrieves details of a single bulk upload by its ID, including associated individual transfers.
     * @param bulkUploadId The UUID of the bulk upload.
     * @return An Optional containing the bulk upload JSONObject if found, otherwise empty.
     * @throws SQLException if a database access error occurs.
     */
    private Optional<JSONObject> getBulkUploadByIdFromDb(UUID bulkUploadId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmtBulk = null;
        PreparedStatement pstmtTransfers = null;
        ResultSet rsBulk = null;
        ResultSet rsTransfers = null;
        PoolDB pool = new PoolDB();

        String sqlBulk = "SELECT bulk_upload_id, initiated_by_user_id, contract_id, total_files, successful_files, failed_files, status, start_time, end_time, error_summary FROM bulk_uploads WHERE bulk_upload_id = ?";
        String sqlTransfers = "SELECT transfer_id, file_name, status, error_message FROM data_transfers WHERE bulk_upload_id = ? ORDER BY start_time ASC";

        try {
            conn = pool.getConnection();
            pstmtBulk = conn.prepareStatement(sqlBulk);
            pstmtBulk.setObject(1, bulkUploadId);
            rsBulk = pstmtBulk.executeQuery();

            if (rsBulk.next()) {
                JSONObject bulkUpload = new JSONObject();
                bulkUpload.put("bulk_upload_id", rsBulk.getString("bulk_upload_id"));
                bulkUpload.put("initiated_by_user_id", rsBulk.getString("initiated_by_user_id"));
                bulkUpload.put("contract_id", rsBulk.getString("contract_id"));
                bulkUpload.put("total_files", rsBulk.getInt("total_files"));
                bulkUpload.put("successful_files", rsBulk.getInt("successful_files"));
                bulkUpload.put("failed_files", rsBulk.getInt("failed_files"));
                bulkUpload.put("status", rsBulk.getString("status"));
                bulkUpload.put("start_time", rsBulk.getTimestamp("start_time").toInstant().toString());
                bulkUpload.put("end_time", rsBulk.getTimestamp("end_time") != null ? rsBulk.getTimestamp("end_time").toInstant().toString() : null);
                bulkUpload.put("error_summary", rsBulk.getString("error_summary"));

                // Get individual transfers associated with this bulk upload
                JSONArray individualTransfers = new JSONArray();
                pstmtTransfers = conn.prepareStatement(sqlTransfers);
                pstmtTransfers.setObject(1, bulkUploadId);
                rsTransfers = pstmtTransfers.executeQuery();
                while (rsTransfers.next()) {
                    JSONObject transfer = new JSONObject();
                    transfer.put("transfer_id", rsTransfers.getString("transfer_id"));
                    transfer.put("file_name", rsTransfers.getString("file_name"));
                    transfer.put("status", rsTransfers.getString("status"));
                    transfer.put("error_message", rsTransfers.getString("error_message"));
                    individualTransfers.add(transfer);
                }
                bulkUpload.put("individual_transfers", individualTransfers);

                return Optional.of(bulkUpload);
            }
        } finally {
            pool.cleanup(rsBulk, pstmtBulk, null);
            pool.cleanup(rsTransfers, pstmtTransfers, conn);
        }
        return Optional.empty();
    }
}
