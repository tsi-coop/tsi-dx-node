package org.tsicoop.dxnode.api.admin;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.Optional;
import org.tsicoop.dxnode.framework.*;


public class Partners implements REST {

    // All HTTP methods will now defer to the POST method
    @Override
    public void get(HttpServletRequest req, HttpServletResponse res) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "GET method is not used directly. Use POST with _func attribute.", req.getRequestURI());
    }

    @Override
    public void put(HttpServletRequest req, HttpServletResponse res) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "PUT method is not used directly. Use POST with _func attribute.", req.getRequestURI());
    }

    @Override
    public void delete(HttpServletRequest req, HttpServletResponse res) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "DELETE method is not used directly. Use POST with _func attribute.", req.getRequestURI());
    }

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        JSONObject input = null;
        JSONObject output = null;
        JSONArray outputArray = null; // Can be used for list responses

        try {
            input = InputProcessor.getInput(req);
            String func = (String) input.get("_func"); // Get the function identifier

            if (func == null || func.trim().isEmpty()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required '_func' attribute in input JSON.", req.getRequestURI());
                return;
            }

            // Extract partner_id if present in input for specific operations
            UUID partnerId = null;
            String partnerIdStr = (String) input.get("partner_id");
            if (!partnerIdStr.isEmpty()) {
                try {
                    partnerId = UUID.fromString(partnerIdStr);
                } catch (IllegalArgumentException e) {
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid 'partner_id' format.", req.getRequestURI());
                    return;
                }
            }

            switch (func.toLowerCase()) { // Case-insensitive comparison for _func
                case "list_partners":
                    String statusFilter = (String) input.get("status");
                    String search = (String) input.get("search");
                    int page = (int)(long) input.get("page");
                    int limit = (int)(long) input.get("limit");
                    outputArray = listPartnersFromDb(statusFilter, search, page, limit);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, outputArray);
                    break;

                case "get_partner":
                    if (partnerId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'partner_id' is required for 'get_partner' function.", req.getRequestURI());
                        return;
                    }
                    Optional<JSONObject> partnerOptional = getPartnerByIdFromDb(partnerId);
                    if (partnerOptional.isPresent()) {
                        output = partnerOptional.get();
                        OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
                    } else {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Partner with ID '" + partnerId + "' not found.", req.getRequestURI());
                    }
                    break;

                case "create_partner":
                    String name = (String)input.get("name");
                    String nodeId = (String)input.get("node_id");
                    String fqdn = (String)input.get("fqdn");
                    String publicKeyPem = (String)input.get("public_key_pem");

                    if (name.isEmpty() || nodeId.isEmpty() || fqdn.isEmpty() || publicKeyPem.isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required fields (name, node_id, fqdn, public_key_pem) for 'create_partner'.", req.getRequestURI());
                        return;
                    }

                    String publicKeyFingerprint = null; //PKIUtil.calculatePublicKeyFingerprint(publicKeyPem);
                    if (publicKeyFingerprint == null || publicKeyFingerprint.isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid public key PEM format.", req.getRequestURI());
                        return;
                    }

                    if (isNodeIdOrFqdnOrFingerprintPresent(nodeId, fqdn, publicKeyFingerprint, null)) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_CONFLICT, "Conflict", "Partner with same Node ID, FQDN, or Public Key Fingerprint already exists.", req.getRequestURI());
                        return;
                    }

                    output = savePartnerToDb(name, nodeId, fqdn, publicKeyPem, publicKeyFingerprint);
                    OutputProcessor.send(res, HttpServletResponse.SC_CREATED, output);
                    break;

                case "update_partner":
                    if (partnerId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'partner_id' is required for 'update_partner' function.", req.getRequestURI());
                        return;
                    }

                    name = (String) input.get("name");
                    nodeId = (String) input.get("node_id");
                    fqdn = (String) input.get("fqdn");
                    publicKeyPem = (String) input.get("public_key_pem");
                    String status = (String) input.get("status");

                    if (name.isEmpty() && nodeId.isEmpty() && fqdn.isEmpty() && publicKeyPem.isEmpty() && status.isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "No fields provided for update for 'update_partner'.", req.getRequestURI());
                        return;
                    }

                    publicKeyFingerprint = null; // Recalculate only if PEM is provided
                    if (!publicKeyPem.isEmpty()) {
                        publicKeyFingerprint = null; //PKIUtil.calculatePublicKeyFingerprint(publicKeyPem);
                        if (publicKeyFingerprint == null || publicKeyFingerprint.isEmpty()) {
                            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid public key PEM format for update.", req.getRequestURI());
                            return;
                        }
                    }

                    if ((!nodeId.isEmpty() || !fqdn.isEmpty() || !publicKeyPem.isEmpty()) && isNodeIdOrFqdnOrFingerprintPresent(nodeId, fqdn, publicKeyFingerprint, partnerId)) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_CONFLICT, "Conflict", "Updated Node ID, FQDN, or Public Key Fingerprint conflicts with an existing partner.", req.getRequestURI());
                        return;
                    }

                    if (getPartnerByIdFromDb(partnerId).isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Partner with ID '" + partnerId + "' not found.", req.getRequestURI());
                        return;
                    }

                    output = updatePartnerInDb(partnerId, name, nodeId, fqdn, publicKeyPem, publicKeyFingerprint, status);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
                    break;

                case "delete_partner":
                    if (partnerId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'partner_id' is required for 'delete_partner' function.", req.getRequestURI());
                        return;
                    }

                    if (getPartnerByIdFromDb(partnerId).isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Partner with ID '" + partnerId + "' not found.", req.getRequestURI());
                        return;
                    }

                    deletePartnerFromDb(partnerId);
                    OutputProcessor.send(res, HttpServletResponse.SC_NO_CONTENT, null); // 204 No Content
                    break;

                default:
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Unknown or unsupported '_func' value: " + func, req.getRequestURI());
                    break;
            }

        } catch (SQLException e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Database Error", "A database error occurred: " + e.getMessage(), req.getRequestURI());
        } catch (Exception e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error", "An unexpected error occurred: " + e.getMessage(), req.getRequestURI());
        }
    }

    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        // Only POST method is allowed for this consolidated API
        if (!"POST".equalsIgnoreCase(method)) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "Only POST method is supported for Partner Management operations.", req.getRequestURI());
            return false;
        }

        // All Admin API endpoints require JWT authentication and Administrator role
        String authHeader = req.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized", "Missing or invalid Authorization header.", req.getRequestURI());
            return false;
        }

        String token = authHeader.substring(7); // Extract JWT token

        try {
            // Validate JWT token
            if (!JWTUtil.isTokenValid(token)) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized", "Invalid or expired token.", req.getRequestURI());
                return false;
            }

            // Get claims from token to check roles
           /* JSONObject claims = JWTUtil.getClaims(token);
            JSONArray rolesJson = (JSONArray) claims.get("roles");
            if (rolesJson == null || rolesJson.isEmpty()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "User has no assigned roles.", req.getRequestURI());
                return false;
            }

            // Check if user has 'Administrator' role for full management, or specific roles for read-only
            boolean isAdmin = false;
            boolean canViewPartners = false;
            for (Object role : rolesJson) {
                String roleName = (String) role;
                if ("Administrator".equalsIgnoreCase(roleName)) {
                    isAdmin = true;
                    canViewPartners = true;
                    break;
                }
                // Example: If you have a specific role for viewing partners
                // if (!canViewPartners && "PartnerViewer".equalsIgnoreCase(roleName)) {
                //     canViewPartners = true;
                // }
            }*/

            // Now, validate authorization based on the _func attribute from the input JSON.
            // This requires parsing the input *before* the main post method logic,
            // which means InputProcessor.getInput(req) must be called here.
            JSONObject input = InputProcessor.getInput(req); // Parse input here
            String func = (String) input.get("_func");

            if (func.isEmpty()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing '_func' attribute for authorization check.", req.getRequestURI());
                return false;
            }

            switch (func.toLowerCase()) {
                case "list_partners":
                case "get_partner":
                    /*if (!canViewPartners) { // Assuming 'canViewPartners' is derived from Administrator or a specific viewer role
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "Access denied. Insufficient privileges to view partners.", req.getRequestURI());
                        return false;
                    }*/
                    break;
                case "create_partner":
                case "update_partner":
                case "delete_partner":
                   /* if (!isAdmin) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "Access denied. Administrator privileges required for this action.", req.getRequestURI());
                        return false;
                    }*/
                    break;
                default:
                    // For unknown functions, deny access or let the main POST method handle it as an invalid func
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Unknown or unsupported '_func' value for authorization: " + func, req.getRequestURI());
                    return false;
            }

            return InputProcessor.validate(req, res); // This validates content-type and basic body parsing

        } catch (Exception e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error", "Authorization or token validation failed: " + e.getMessage(), req.getRequestURI());
            return false;
        }
    }

    /**
     * Retrieves a list of partners from the database with optional filtering and pagination.
     * @param statusFilter Optional status to filter by ('Pending', 'Active', 'Inactive').
     * @param search Optional search term for name, node_id, or fqdn.
     * @param page Page number (1-based).
     * @param limit Number of records per page.
     * @return JSONArray of partner JSONObjects.
     * @throws SQLException if a database access error occurs.
     */
    private JSONArray listPartnersFromDb(String statusFilter, String search, int page, int limit) throws SQLException {
        JSONArray partnersArray = new JSONArray();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        StringBuilder sqlBuilder = new StringBuilder("SELECT partner_id, node_id, name, fqdn, public_key_pem, public_key_fingerprint, status, created_at, updated_at FROM partners WHERE 1=1");
        List<Object> params = new ArrayList<>();

        if (statusFilter != null && !statusFilter.isEmpty()) {
            sqlBuilder.append(" AND status = ?");
            params.add(statusFilter);
        }
        if (search != null && !search.isEmpty()) {
            sqlBuilder.append(" AND (name ILIKE ? OR node_id ILIKE ? OR fqdn ILIKE ?)");
            params.add("%" + search + "%");
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
                JSONObject partner = new JSONObject();
                partner.put("partner_id", rs.getString("partner_id"));
                partner.put("node_id", rs.getString("node_id"));
                partner.put("name", rs.getString("name"));
                partner.put("fqdn", rs.getString("fqdn"));
                // Do NOT return public_key_pem in list view for security/brevity
                partner.put("public_key_fingerprint", rs.getString("public_key_fingerprint"));
                partner.put("status", rs.getString("status"));
                partner.put("created_at", rs.getTimestamp("created_at").toInstant().toString());
                partner.put("updated_at", rs.getTimestamp("updated_at").toInstant().toString());
                partnersArray.add(partner);
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return partnersArray;
    }

    /**
     * Retrieves a single partner by its ID from the database.
     * @param partnerId The UUID of the partner.
     * @return An Optional containing the partner JSONObject if found, otherwise empty.
     * @throws SQLException if a database access error occurs.
     */
    private Optional<JSONObject> getPartnerByIdFromDb(UUID partnerId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "SELECT partner_id, node_id, name, fqdn, public_key_pem, public_key_fingerprint, status, created_at, updated_at FROM partners WHERE partner_id = ?";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, partnerId);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                JSONObject partner = new JSONObject();
                partner.put("partner_id", rs.getString("partner_id"));
                partner.put("node_id", rs.getString("node_id"));
                partner.put("name", rs.getString("name"));
                partner.put("fqdn", rs.getString("fqdn"));
                partner.put("public_key_pem", rs.getString("public_key_pem")); // Include PEM for single view
                partner.put("public_key_fingerprint", rs.getString("public_key_fingerprint"));
                partner.put("status", rs.getString("status"));
                partner.put("created_at", rs.getTimestamp("created_at").toInstant().toString());
                partner.put("updated_at", rs.getTimestamp("updated_at").toInstant().toString());
                return Optional.of(partner);
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return Optional.empty();
    }

    /**
     * Saves a new partner to the database.
     * @return JSONObject containing the new partner's details.
     * @throws SQLException if a database access error occurs.
     */
    private JSONObject savePartnerToDb(String name, String nodeId, String fqdn, String publicKeyPem, String publicKeyFingerprint) throws SQLException {
        JSONObject output = new JSONObject();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "INSERT INTO partners (name, node_id, fqdn, public_key_pem, public_key_fingerprint, status) VALUES (?, ?, ?, ?, ?, ?) RETURNING partner_id";

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, name);
            pstmt.setString(2, nodeId);
            pstmt.setString(3, fqdn);
            pstmt.setString(4, publicKeyPem);
            pstmt.setString(5, publicKeyFingerprint);
            pstmt.setString(6, "Pending"); // Default status for new partners

            int affectedRows = pstmt.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Creating partner failed, no rows affected.");
            }

            rs = pstmt.getGeneratedKeys();
            if (rs.next()) {
                String partnerId = rs.getString("partner_id");
                output.put("partner_id", partnerId);
                output.put("name", name);
                output.put("node_id", nodeId);
                output.put("fqdn", fqdn);
                output.put("public_key_fingerprint", publicKeyFingerprint);
                output.put("status", "Pending");
                output.put("message", "Partner created successfully. Status is Pending.");
            } else {
                throw new SQLException("Creating partner failed, no ID obtained.");
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return new JSONObject() {{ put("success", true); put("data", output); }};
    }

    /**
     * Updates an existing partner in the database.
     * @return JSONObject indicating success.
     * @throws SQLException if a database access error occurs.
     */
    private JSONObject updatePartnerInDb(UUID partnerId, String name, String nodeId, String fqdn, String publicKeyPem, String publicKeyFingerprint, String status) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = new PoolDB();

        StringBuilder sqlBuilder = new StringBuilder("UPDATE partners SET updated_at = NOW()");
        List<Object> params = new ArrayList<>();

        if (name != null && !name.isEmpty()) { sqlBuilder.append(", name = ?"); params.add(name); }
        if (nodeId != null && !nodeId.isEmpty()) { sqlBuilder.append(", node_id = ?"); params.add(nodeId); }
        if (fqdn != null && !fqdn.isEmpty()) { sqlBuilder.append(", fqdn = ?"); params.add(fqdn); }
        if (publicKeyPem != null && !publicKeyPem.isEmpty()) {
            sqlBuilder.append(", public_key_pem = ?"); params.add(publicKeyPem);
            sqlBuilder.append(", public_key_fingerprint = ?"); params.add(publicKeyFingerprint);
        }
        if (status != null && !status.isEmpty()) { sqlBuilder.append(", status = ?"); params.add(status); }

        sqlBuilder.append(" WHERE partner_id = ?");
        params.add(partnerId);

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sqlBuilder.toString());
            for (int i = 0; i < params.size(); i++) {
                pstmt.setObject(i + 1, params.get(i));
            }

            int affectedRows = pstmt.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Updating partner failed, partner not found or no changes made.");
            }
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
        return new JSONObject() {{ put("success", true); put("message", "Partner updated successfully."); }};
    }

    /**
     * Deletes a partner from the database.
     * @param partnerId The UUID of the partner to delete.
     * @throws SQLException if a database access error occurs.
     */
    private void deletePartnerFromDb(UUID partnerId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = new PoolDB();
        String sql = "DELETE FROM partners WHERE partner_id = ?";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, partnerId);
            int affectedRows = pstmt.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Deleting partner failed, partner not found.");
            }
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
    }

    /**
     * Checks if a node_id, fqdn, or public_key_fingerprint already exists in the database.
     * Used for uniqueness checks during create and update operations.
     * @param nodeId The node ID to check.
     * @param fqdn The FQDN to check.
     * @param publicKeyFingerprint The public key fingerprint to check.
     * @param excludePartnerId Optional UUID to exclude from the check (for update operations).
     * @return true if a conflict is found, false otherwise.
     * @throws SQLException if a database access error occurs.
     */
    private boolean isNodeIdOrFqdnOrFingerprintPresent(String nodeId, String fqdn, String publicKeyFingerprint, UUID excludePartnerId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        StringBuilder sqlBuilder = new StringBuilder("SELECT COUNT(*) FROM partners WHERE (node_id = ? OR fqdn = ? OR public_key_fingerprint = ?)");
        List<Object> params = new ArrayList<>();
        params.add(nodeId);
        params.add(fqdn);
        params.add(publicKeyFingerprint);

        if (excludePartnerId != null) {
            sqlBuilder.append(" AND partner_id != ?");
            params.add(excludePartnerId);
        }

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sqlBuilder.toString());
            for (int i = 0; i < params.size(); i++) {
                pstmt.setObject(i + 1, params.get(i));
            }
            rs = pstmt.executeQuery();
            if (rs.next() && rs.getInt(1) > 0) {
                return true; // Conflict found
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return false;
    }
}
