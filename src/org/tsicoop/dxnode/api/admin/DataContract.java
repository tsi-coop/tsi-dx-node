package org.tsicoop.dxnode.api.admin;

import org.tsicoop.dxnode.framework.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
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

public class DataContract implements REST {

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

            UUID contractId = null;
            String contractIdStr = (String) input.get("contract_id");
            if (!contractIdStr.isEmpty()) {
                try {
                    contractId = UUID.fromString(contractIdStr);
                } catch (IllegalArgumentException e) {
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid 'contract_id' format.", req.getRequestURI());
                    return;
                }
            }

            switch (func.toLowerCase()) {
                case "list_contracts":
                    String statusFilter = (String) input.get("status");
                    String directionFilter = (String) input.get("direction");
                    String partnerIdFilter = (String) input.get("partner_id");
                    String search = (String) input.get("search");
                    int page = (int)(long)input.get("page");
                    int limit = (int)(long)input.get("limit");

                    outputArray = listContractsFromDb(statusFilter, directionFilter, partnerIdFilter, search, page, limit);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, outputArray);
                    break;

                case "get_contract":
                    if (contractId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'contract_id' is required for 'get_contract' function.", req.getRequestURI());
                        return;
                    }
                    Optional<JSONObject> contractOptional = getContractByIdFromDb(contractId);
                    if (contractOptional.isPresent()) {
                        output = contractOptional.get();
                        OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
                    } else {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Contract with ID '" + contractId + "' not found.", req.getRequestURI());
                    }
                    break;

                case "create_contract":
                    String name = (String) input.get("name");
                    int version = (int)(long)input.get("version");
                    String description = (String) input.get("description");
                    String senderPartnerIdStr = (String) input.get("sender_partner_id");
                    String receiverPartnerIdStr = (String) input.get("receiver_partner_id");
                    JSONObject schemaDefinition = (JSONObject) input.get("schema_definition"); // Required
                    JSONObject metadata = (JSONObject) input.get("metadata"); // Optional
                    String validationScriptIdStr = (String) input.get("validation_script_id");
                    int retentionPolicyDays = (int)(long)input.get("retention_policy_days");
                    JSONArray piiFieldsJson = (JSONArray) input.get("pii_fields"); // Optional array of strings

                    if (name.isEmpty() || senderPartnerIdStr.isEmpty() || receiverPartnerIdStr.isEmpty() || schemaDefinition == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required fields (name, sender_partner_id, receiver_partner_id, schema_definition) for 'create_contract'.", req.getRequestURI());
                        return;
                    }

                    UUID senderPartnerId = UUID.fromString(senderPartnerIdStr);
                    UUID receiverPartnerId = UUID.fromString(receiverPartnerIdStr);
                    UUID validationScriptId = validationScriptIdStr.isEmpty() ? null : UUID.fromString(validationScriptIdStr);
                    String[] piiFields = piiFieldsJson != null ? (String[]) piiFieldsJson.toArray(new String[0]) : null;


                    // Validate existence of partners and script
                    if (!partnerExists(senderPartnerId) || !partnerExists(receiverPartnerId)) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Sender or Receiver Partner ID does not exist.", req.getRequestURI());
                        return;
                    }
                    if (validationScriptId != null && !validationScriptExists(validationScriptId)) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Validation Script ID does not exist.", req.getRequestURI());
                        return;
                    }

                    output = saveContractToDb(name, version, description, senderPartnerId, receiverPartnerId, schemaDefinition, metadata, validationScriptId, retentionPolicyDays, piiFields);
                    OutputProcessor.send(res, HttpServletResponse.SC_CREATED, output);
                    break;

                case "update_contract":
                    if (contractId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'contract_id' is required for 'update_contract' function.", req.getRequestURI());
                        return;
                    }
                    if (getContractByIdFromDb(contractId).isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Contract with ID '" + contractId + "' not found.", req.getRequestURI());
                        return;
                    }

                    name = (String) input.get("name");
                    version = (int)(long)input.get("version");
                    description = (String) input.get("description");
                    senderPartnerIdStr = (String) input.get("sender_partner_id");
                    receiverPartnerIdStr = (String) input.get("receiver_partner_id");
                    schemaDefinition = (JSONObject) input.get("schema_definition");
                    metadata = (JSONObject) input.get("metadata");
                    validationScriptIdStr = (String) input.get("validation_script_id");
                    retentionPolicyDays = (int)(long)input.get("retention_policy_days");
                    piiFieldsJson = (JSONArray) input.get("pii_fields");

                    senderPartnerId = senderPartnerIdStr.isEmpty() ? null : UUID.fromString(senderPartnerIdStr);
                    receiverPartnerId = receiverPartnerIdStr.isEmpty() ? null : UUID.fromString(receiverPartnerIdStr);
                    validationScriptId = validationScriptIdStr.isEmpty() ? null : UUID.fromString(validationScriptIdStr);
                    piiFields = piiFieldsJson != null ? (String[]) piiFieldsJson.toArray(new String[0]) : null;

                    // Validate existence of partners and script if provided for update
                    if (senderPartnerId != null && !partnerExists(senderPartnerId)) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Sender Partner ID for update does not exist.", req.getRequestURI());
                        return;
                    }
                    if (receiverPartnerId != null && !partnerExists(receiverPartnerId)) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Receiver Partner ID for update does not exist.", req.getRequestURI());
                        return;
                    }
                    if (validationScriptId != null && !validationScriptExists(validationScriptId)) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Validation Script ID for update does not exist.", req.getRequestURI());
                        return;
                    }

                    output = updateContractInDb(contractId, name, version, description, senderPartnerId, receiverPartnerId, schemaDefinition, metadata, validationScriptId, retentionPolicyDays, piiFields);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
                    break;

                case "propose_contract":
                case "accept_contract":
                case "reject_contract":
                case "terminate_contract":
                    if (contractId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'contract_id' is required for status update functions.", req.getRequestURI());
                        return;
                    }
                    if (getContractByIdFromDb(contractId).isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Contract with ID '" + contractId + "' not found.", req.getRequestURI());
                        return;
                    }
                    String newStatus = func.replace("_contract", ""); // "propose", "accept", "reject", "terminate"
                    output = updateContractStatusInDb(contractId, newStatus);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
                    break;

                default:
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Unknown or unsupported '_func' value: " + func, req.getRequestURI());
                    break;
            }

        } catch (SQLException e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Database Error", "A database error occurred: " + e.getMessage(), req.getRequestURI());
        } catch (ParseException e) { // From InputProcessor.getInput
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid JSON input: " + e.getMessage(), req.getRequestURI());
        } catch (IllegalArgumentException e) { // From UUID.fromString
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid UUID format in input: " + e.getMessage(), req.getRequestURI());
        } catch (Exception e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error", "An unexpected error occurred: " + e.getMessage(), req.getRequestURI());
        }
    }

    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        if (!"POST".equalsIgnoreCase(method)) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "Only POST method is supported for Data Contract Management operations.", req.getRequestURI());
            return false;
        }

      /*  String authHeader = req.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized", "Missing or invalid Authorization header.", req.getRequestURI());
            return false;
        }

        String token = authHeader.substring(7);

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
            boolean canViewContracts = false;
            for (Object role : rolesJson) {
                String roleName = (String) role;
                if ("Administrator".equalsIgnoreCase(roleName)) {
                    isAdmin = true;
                    canViewContracts = true;
                    break;
                }
                // Example: If you have a specific role for viewing contracts
                // if (!canViewContracts && "ContractViewer".equalsIgnoreCase(roleName)) {
                //     canViewContracts = true;
                // }
            }

            JSONObject input = InputProcessor.getInput(req); // Parse input for func
            String func = input.optString("_func", "").trim();

            if (func.isEmpty()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing '_func' attribute for authorization check.", req.getRequestURI());
                return false;
            }

            switch (func.toLowerCase()) {
                case "list_contracts":
                case "get_contract":
                    if (!canViewContracts) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "Access denied. Insufficient privileges to view contracts.", req.getRequestURI());
                        return false;
                    }
                    break;
                case "create_contract":
                case "update_contract":
                case "propose_contract":
                case "accept_contract":
                case "reject_contract":
                case "terminate_contract":
                    if (!isAdmin) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "Access denied. Administrator privileges required for this action.", req.getRequestURI());
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
        return InputProcessor.validate(req, res);
    }

    /**
     * Retrieves a list of data contracts from the database with optional filtering and pagination.
     * @param statusFilter Optional status to filter by.
     * @param directionFilter Optional direction to filter by.
     * @param partnerIdFilter Optional partner ID to filter by.
     * @param search Optional search term for name or description.
     * @param page Page number (1-based).
     * @param limit Number of records per page.
     * @return JSONArray of contract JSONObjects.
     * @throws SQLException if a database access error occurs.
     */
    private JSONArray listContractsFromDb(String statusFilter, String directionFilter, String partnerIdFilter, String search, int page, int limit) throws SQLException {
        JSONArray contractsArray = new JSONArray();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        StringBuilder sqlBuilder = new StringBuilder("SELECT contract_id, name, version, description, sender_partner_id, receiver_partner_id, status, created_at, updated_at FROM data_contracts WHERE 1=1");
        List<Object> params = new ArrayList<>();

        if (statusFilter != null && !statusFilter.isEmpty()) {
            sqlBuilder.append(" AND status = ?");
            params.add(statusFilter);
        }
        if (directionFilter != null && !directionFilter.isEmpty()) {
            // Assuming 'direction' is not directly stored, but derived from sender/receiver IDs relative to local node_id
            // This would require knowing the local node_id, or adding a 'direction' column to the contract
            // For now, let's assume 'direction' is handled client-side or we'd need to join with node_config
        }
        if (partnerIdFilter != null && !partnerIdFilter.isEmpty()) {
            sqlBuilder.append(" AND (sender_partner_id = ? OR receiver_partner_id = ?)");
            params.add(UUID.fromString(partnerIdFilter));
            params.add(UUID.fromString(partnerIdFilter));
        }
        if (search != null && !search.isEmpty()) {
            sqlBuilder.append(" AND (name ILIKE ? OR description ILIKE ?)");
            params.add("%" + search + "%");
            params.add("%" + search + "%");
        }

        sqlBuilder.append(" ORDER BY created_at DESC LIMIT ? OFFSET ?");
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
                JSONObject contract = new JSONObject();
                contract.put("contract_id", rs.getString("contract_id"));
                contract.put("name", rs.getString("name"));
                contract.put("version", rs.getInt("version"));
                contract.put("description", rs.getString("description"));
                contract.put("sender_partner_id", rs.getString("sender_partner_id"));
                contract.put("receiver_partner_id", rs.getString("receiver_partner_id"));
                contract.put("status", rs.getString("status"));
                contract.put("created_at", rs.getTimestamp("created_at").toInstant().toString());
                contract.put("updated_at", rs.getTimestamp("updated_at").toInstant().toString());
                contractsArray.add(contract);
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return contractsArray;
    }

    /**
     * Retrieves a single data contract by its ID from the database.
     * @param contractId The UUID of the contract.
     * @return An Optional containing the contract JSONObject if found, otherwise empty.
     * @throws SQLException if a database access error occurs.
     */
    private Optional<JSONObject> getContractByIdFromDb(UUID contractId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "SELECT contract_id, name, version, description, sender_partner_id, receiver_partner_id, schema_definition, metadata, validation_script_id, retention_policy_days, pii_fields, status, created_at, updated_at FROM data_contracts WHERE contract_id = ?";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, contractId);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                JSONObject contract = new JSONObject();
                contract.put("contract_id", rs.getString("contract_id"));
                contract.put("name", rs.getString("name"));
                contract.put("version", rs.getInt("version"));
                contract.put("description", rs.getString("description"));
                contract.put("sender_partner_id", rs.getString("sender_partner_id"));
                contract.put("receiver_partner_id", rs.getString("receiver_partner_id"));

                // Handle JSONB fields
                String schemaDefJson = rs.getString("schema_definition");
                if (schemaDefJson != null) {
                    try {
                        contract.put("schema_definition", (JSONObject) new JSONParser().parse(schemaDefJson));
                    } catch (ParseException e) { /* Log error, but continue */ }
                }
                String metadataJson = rs.getString("metadata");
                if (metadataJson != null) {
                    try {
                        contract.put("metadata", (JSONObject) new JSONParser().parse(metadataJson));
                    } catch (ParseException e) { /* Log error, but continue */ }
                }

                contract.put("validation_script_id", rs.getString("validation_script_id"));
                contract.put("retention_policy_days", rs.getInt("retention_policy_days"));

                // Handle TEXT[] (PostgreSQL array)
                java.sql.Array piiArray = rs.getArray("pii_fields");
                if (piiArray != null) {
                    String[] piiFields = (String[]) piiArray.getArray();
                    JSONArray piiJsonArray = new JSONArray();
                    for (String field : piiFields) {
                        piiJsonArray.add(field);
                    }
                    contract.put("pii_fields", piiJsonArray);
                } else {
                    contract.put("pii_fields", new JSONArray());
                }

                contract.put("status", rs.getString("status"));
                contract.put("created_at", rs.getTimestamp("created_at").toInstant().toString());
                contract.put("updated_at", rs.getTimestamp("updated_at").toInstant().toString());
                return Optional.of(contract);
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return Optional.empty();
    }

    /**
     * Saves a new data contract to the database.
     * @return JSONObject containing the new contract's details.
     * @throws SQLException if a database access error occurs.
     */
    private JSONObject saveContractToDb(String name, int version, String description, UUID senderPartnerId, UUID receiverPartnerId, JSONObject schemaDefinition, JSONObject metadata, UUID validationScriptId, int retentionPolicyDays, String[] piiFields) throws SQLException {
        JSONObject output = new JSONObject();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "INSERT INTO data_contracts (name, version, description, sender_partner_id, receiver_partner_id, schema_definition, metadata, validation_script_id, retention_policy_days, pii_fields, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING contract_id";

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, name);
            pstmt.setInt(2, version);
            pstmt.setString(3, description);
            pstmt.setObject(4, senderPartnerId);
            pstmt.setObject(5, receiverPartnerId);
            pstmt.setString(6, schemaDefinition.toJSONString()); // Store JSONB as string
            pstmt.setString(7, metadata != null ? metadata.toJSONString() : null); // Store JSONB as string
            pstmt.setObject(8, validationScriptId);
            if (retentionPolicyDays != -1) {
                pstmt.setInt(9, retentionPolicyDays);
            } else {
                pstmt.setNull(9, java.sql.Types.INTEGER);
            }
            pstmt.setArray(10, conn.createArrayOf("text", piiFields)); // Store String array as TEXT[]
            pstmt.setString(11, "Draft"); // Default status

            int affectedRows = pstmt.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Creating contract failed, no rows affected.");
            }

            rs = pstmt.getGeneratedKeys();
            if (rs.next()) {
                String contractId = rs.getString("contract_id");
                output.put("contract_id", contractId);
                output.put("name", name);
                output.put("status", "Draft");
                output.put("message", "Contract created successfully. Status is Draft.");
            } else {
                throw new SQLException("Creating contract failed, no ID obtained.");
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return new JSONObject() {{ put("success", true); put("data", output); }};
    }

    /**
     * Updates an existing data contract in the database.
     * @return JSONObject indicating success.
     * @throws SQLException if a database access error occurs.
     */
    private JSONObject updateContractInDb(UUID contractId, String name, int version, String description, UUID senderPartnerId, UUID receiverPartnerId, JSONObject schemaDefinition, JSONObject metadata, UUID validationScriptId, int retentionPolicyDays, String[] piiFields) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = new PoolDB();

        StringBuilder sqlBuilder = new StringBuilder("UPDATE data_contracts SET updated_at = NOW()");
        List<Object> params = new ArrayList<>();

        if (name != null && !name.isEmpty()) { sqlBuilder.append(", name = ?"); params.add(name); }
        if (version != -1) { sqlBuilder.append(", version = ?"); params.add(version); }
        if (description != null && !description.isEmpty()) { sqlBuilder.append(", description = ?"); params.add(description); }
        if (senderPartnerId != null) { sqlBuilder.append(", sender_partner_id = ?"); params.add(senderPartnerId); }
        if (receiverPartnerId != null) { sqlBuilder.append(", receiver_partner_id = ?"); params.add(receiverPartnerId); }
        if (schemaDefinition != null) { sqlBuilder.append(", schema_definition = ?::jsonb"); params.add(schemaDefinition.toJSONString()); }
        if (metadata != null) { sqlBuilder.append(", metadata = ?::jsonb"); params.add(metadata.toJSONString()); } else if (schemaDefinition == null && metadata == null) { /* no change */ } // If both are null, don't update
        else if (metadata == null) { sqlBuilder.append(", metadata = NULL"); } // Explicitly set to null if provided as null

        if (validationScriptId != null) { sqlBuilder.append(", validation_script_id = ?"); params.add(validationScriptId); }
        else if (validationScriptId == null && !inputHasField("validation_script_id", null)) { /* no change */ } // Check if field was explicitly sent as null
        else if (validationScriptId == null) { sqlBuilder.append(", validation_script_id = NULL"); } // Explicitly set to null

        if (retentionPolicyDays != -1) { sqlBuilder.append(", retention_policy_days = ?"); params.add(retentionPolicyDays); }
        else if (retentionPolicyDays == -1 && !inputHasField("retention_policy_days", null)) { /* no change */ }
        else if (retentionPolicyDays == -1) { sqlBuilder.append(", retention_policy_days = NULL"); }

        if (piiFields != null) { sqlBuilder.append(", pii_fields = ?"); params.add(piiFields); }
        else if (piiFields == null && !inputHasField("pii_fields", null)) { /* no change */ }
        else if (piiFields == null) { sqlBuilder.append(", pii_fields = NULL"); }


        sqlBuilder.append(" WHERE contract_id = ?");
        params.add(contractId);

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sqlBuilder.toString());
            for (int i = 0; i < params.size(); i++) {
                // Handle JSONB and TEXT[] types specifically
                if (params.get(i) instanceof JSONObject) {
                    pstmt.setString(i + 1, ((JSONObject) params.get(i)).toJSONString());
                } else if (params.get(i) instanceof String[]) {
                    pstmt.setArray(i + 1, conn.createArrayOf("text", (String[]) params.get(i)));
                } else if (params.get(i) instanceof UUID) {
                    pstmt.setObject(i + 1, params.get(i));
                }
                else {
                    pstmt.setObject(i + 1, params.get(i));
                }
            }

            int affectedRows = pstmt.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Updating contract failed, contract not found or no changes made.");
            }
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
        return new JSONObject() {{ put("success", true); put("message", "Contract updated successfully."); }};
    }

    /**
     * Updates the status of a data contract.
     * @param contractId The UUID of the contract.
     * @param newStatus The new status ('propose', 'accept', 'reject', 'terminate').
     * @return JSONObject indicating success.
     * @throws SQLException if a database access error occurs.
     */
    private JSONObject updateContractStatusInDb(UUID contractId, String newStatus) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = new PoolDB();
        String sql = "UPDATE data_contracts SET status = ?, updated_at = NOW() WHERE contract_id = ?";

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, newStatus);
            pstmt.setObject(2, contractId);
            int affectedRows = pstmt.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Updating contract status failed, contract not found or no changes made.");
            }
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
        return new JSONObject() {{ put("success", true); put("message", "Contract status updated to '" + newStatus + "' successfully."); }};
    }

    /**
     * Helper to check if a partner exists by ID.
     */
    private boolean partnerExists(UUID partnerId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "SELECT COUNT(*) FROM partners WHERE partner_id = ?";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, partnerId);
            rs = pstmt.executeQuery();
            return rs.next() && rs.getInt(1) > 0;
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }

    /**
     * Helper to check if a validation script exists by ID.
     */
    private boolean validationScriptExists(UUID scriptId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "SELECT COUNT(*) FROM validation_scripts WHERE script_id = ?";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, scriptId);
            rs = pstmt.executeQuery();
            return rs.next() && rs.getInt(1) > 0;
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }

    /**
     * Helper to check if a field was explicitly included in the input JSON, even if its value is null/empty.
     * This is useful for differentiating between "field not provided" and "field provided as null".
     * Note: This is a simplified check. A more robust solution might involve iterating through the JSONObject keys.
     */
    private boolean inputHasField(String fieldName, JSONObject input) {
        // This method needs the actual input JSON to work correctly.
        // For simplicity in this template, it's a placeholder.
        // In a real implementation, you'd pass the 'input' JSONObject here.
        return input != null && input.containsKey(fieldName);
    }
}