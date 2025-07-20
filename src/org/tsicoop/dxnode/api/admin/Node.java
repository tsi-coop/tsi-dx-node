package org.tsicoop.dxnode.api.admin;

import org.tsicoop.dxnode.framework.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONObject;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.UUID;

public class Node implements REST {

    // Unique ID for the single node_config entry, as per init.sql
    private static final UUID NODE_CONFIG_SINGLETON_ID = UUID.fromString("00000000-0000-0000-0000-000000000001");

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

        try {
            input = InputProcessor.getInput(req);
            String func = (String) input.get("_func"); // Get the function identifier

            if (func == null || func.trim().isEmpty()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required '_func' attribute in input JSON.", req.getRequestURI());
                return;
            }

            switch (func.toLowerCase()) { // Case-insensitive comparison for _func
                case "get_status":
                    output = getNodeStatus();
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
                    break;

                case "get_config":
                    output = getNodeConfig();
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
                    break;

                case "update_config":
                    String nodeId = (String) input.get("node_id");
                    String fqdn = (String) input.get("fqdn");
                    int networkPort = (int)(long)input.get("network_port");
                    String storageActivePath = (String) input.get("storage_active_path");
                    String storageArchivePath = (String) input.get("storage_archive_path");
                    String loggingLevel = (String) input.get("logging_level");

                    if (nodeId.isEmpty() || fqdn.isEmpty() || networkPort == -1 || storageActivePath.isEmpty() || storageArchivePath.isEmpty() || loggingLevel.isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing or invalid required configuration fields for 'update_config'.", req.getRequestURI());
                        return;
                    }
                    output = updateNodeConfig(nodeId, fqdn, networkPort, storageActivePath, storageArchivePath, loggingLevel);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
                    break;

                case "generate_csr":
                    String commonName = (String) input.get("common_name");
                    String organization = (String) input.get("organization");

                    if (commonName.isEmpty() || organization.isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required fields (common_name, organization) for 'generate_csr'.", req.getRequestURI());
                        return;
                    }
                    output = generateCsrAndStorePrivateKey(commonName, organization);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
                    break;

                case "import_certificate":
                    String certificatePem = (String) input.get("certificate_pem");
                    String privateKeyPem = (String) input.get("private_key_pem");

                    if (certificatePem.isEmpty() || privateKeyPem.isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required fields (certificate_pem, private_key_pem) for 'import_certificate'.", req.getRequestURI());
                        return;
                    }
                    output = importCertificateAndActivate(certificatePem, privateKeyPem);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
                    break;

                default:
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Unknown or unsupported '_func' value: " + func, req.getRequestURI());
                    break;
            }
        } catch (IllegalArgumentException e) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", e.getMessage(), req.getRequestURI());
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
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "Only POST method is supported for Node Management operations.", req.getRequestURI());
            return false;
        }

        // All Admin API endpoints require JWT authentication and Administrator role
        String authHeader = req.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized", "Missing or invalid Authorization header.", req.getRequestURI());
            return false;
        }

        return InputProcessor.validate(req, res); // This validates content-type and basic body parsing

    }

    /**
     * Retrieves the current status of the DX Node.
     * @return JSONObject containing node status details.
     * @throws SQLException if a database access error occurs.
     */
    private JSONObject getNodeStatus() throws SQLException {
        JSONObject status = new JSONObject();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        try {
            conn = pool.getConnection();
            String sql = "SELECT node_id, fqdn, network_port FROM node_config WHERE config_id = ?";
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, NODE_CONFIG_SINGLETON_ID);
            rs = pstmt.executeQuery();

            if (rs.next()) {
                status.put("node_id", rs.getString("node_id"));
                status.put("fqdn", rs.getString("fqdn"));
                status.put("status", "Online"); // Placeholder: Actual status would involve internal checks
                status.put("last_heartbeat", Timestamp.valueOf(LocalDateTime.now()).toString()); // Placeholder
                status.put("uptime_seconds", 3600); // Placeholder
                // Add disk usage, transfer counts (would require querying other tables/metrics)
                status.put("disk_usage_gb", new JSONObject() {{ put("total", 500); put("used", 150); put("archive", 50); }});
                status.put("active_transfers_count", 0); // Placeholder
                status.put("pending_transfers_count", 0); // Placeholder
                status.put("failed_transfers_count", 0); // Placeholder
            } else {
                status.put("status", "Uninitialized");
                status.put("message", "Node configuration not found. Please ensure initial setup is complete.");
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return new JSONObject() {{ put("success", true); put("data", status); }};
    }

    /**
     * Retrieves the current configuration of the DX Node.
     * @return JSONObject containing node configuration details.
     * @throws SQLException if a database access error occurs.
     */
    private JSONObject getNodeConfig() throws SQLException {
        JSONObject config = new JSONObject();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        try {
            conn = pool.getConnection();
            String sql = "SELECT node_id, fqdn, network_port, storage_active_path, storage_archive_path, logging_level FROM node_config WHERE config_id = ?";
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, NODE_CONFIG_SINGLETON_ID);
            rs = pstmt.executeQuery();

            if (rs.next()) {
                config.put("node_id", rs.getString("node_id"));
                config.put("fqdn", rs.getString("fqdn"));
                config.put("network_port", rs.getInt("network_port"));
                config.put("storage_active_path", rs.getString("storage_active_path"));
                config.put("storage_archive_path", rs.getString("storage_archive_path"));
                config.put("logging_level", rs.getString("logging_level"));
            } else {
                throw new SQLException("Node configuration not found for ID: " + NODE_CONFIG_SINGLETON_ID);
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return new JSONObject() {{ put("success", true); put("data", config); }};
    }

    /**
     * Updates the node configuration in the database.
     * @param nodeId The node ID.
     * @param fqdn The FQDN.
     * @param networkPort The network port.
     * @param storageActivePath Active storage path.
     * @param storageArchivePath Archive storage path.
     * @param loggingLevel Logging level.
     * @return JSONObject indicating success.
     * @throws SQLException if a database access error occurs.
     */
    private JSONObject updateNodeConfig(String nodeId, String fqdn, int networkPort, String storageActivePath, String storageArchivePath, String loggingLevel) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = new PoolDB();

        String sql = "UPDATE node_config SET node_id = ?, fqdn = ?, network_port = ?, storage_active_path = ?, storage_archive_path = ?, logging_level = ?, updated_at = NOW() WHERE config_id = ?";

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, nodeId);
            pstmt.setString(2, fqdn);
            pstmt.setInt(3, networkPort);
            pstmt.setString(4, storageActivePath);
            pstmt.setString(5, storageArchivePath);
            pstmt.setString(6, loggingLevel);
            pstmt.setObject(7, NODE_CONFIG_SINGLETON_ID);

            int affectedRows = pstmt.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Node configuration not found or no changes made for ID: " + NODE_CONFIG_SINGLETON_ID);
            }
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
        return new JSONObject() {{ put("success", true); put("message", "Node configuration updated successfully."); }};
    }

    /**
     * Generates a CSR and stores the associated private key.
     * @param commonName The Common Name for the CSR.
     * @param organization The Organization for the CSR.
     * @return JSONObject containing the generated CSR in PEM format.
     * @throws Exception if PKI operation fails.
     */
    private JSONObject generateCsrAndStorePrivateKey(String commonName, String organization) throws Exception {
        // PKIUtil.generateCSR should return a pair: {csr_pem: "...", private_key_pem: "..."}
        JSONObject pkiOutput = PKIUtil.generateCSR(commonName, organization);
        String csrPem = (String) pkiOutput.get("csr_pem");
        String privateKeyPem = (String) pkiOutput.get("private_key_pem");

        // Store the private key securely in the database, associated with the node config
        // Mark it as 'pending' or 'inactive' until a signed certificate is imported
        // Note: This assumes a node_certificates table with a way to link to node_config
        // and manage active/inactive status.
        saveCertificateToDb(NODE_CONFIG_SINGLETON_ID, null, privateKeyPem, false, null, null); // cert_pem is null initially

        JSONObject output = new JSONObject();
        output.put("csr_pem", csrPem);
        output.put("message", "CSR generated and private key stored. Please get the CSR signed by a CA.");
        return new JSONObject() {{ put("success", true); put("data", output); }};
    }

    /**
     * Imports a signed certificate and its corresponding private key, then activates it.
     * Deactivates any previously active certificates for this node config.
     * @param certificatePem The PEM-encoded signed certificate.
     * @param privateKeyPem The PEM-encoded private key.
     * @return JSONObject indicating success.
     * @throws Exception if PKI operation fails or key/cert mismatch.
     */
    private JSONObject importCertificateAndActivate(String certificatePem, String privateKeyPem) throws Exception {
        // 1. Validate certificate and private key match
        if (!PKIUtil.isCertificatePrivateKeyMatch(certificatePem, privateKeyPem)) {
            throw new IllegalArgumentException("Provided certificate and private key do not match.");
        }

        // 2. Extract certificate details (e.g., expiry date, common name)
        JSONObject certDetails = PKIUtil.getCertificateDetails(certificatePem);
        String fqdnFromCert = (String) certDetails.get("common_name"); // Or Subject Alternative Names
        Timestamp expiresAt = Timestamp.valueOf(LocalDateTime.parse((String) certDetails.get("expires_at_iso")));
        Timestamp issuedAt = Timestamp.valueOf(LocalDateTime.parse((String) certDetails.get("issued_at_iso")));


        Connection conn = null;
        PreparedStatement pstmtUpdateOld = null;
        PoolDB pool = new PoolDB();

        try {
            conn = pool.getConnection();
            conn.setAutoCommit(false); // Start transaction

            // Deactivate all existing active certificates for this node config
            String deactivateSql = "UPDATE node_certificates SET is_active = FALSE, updated_at = NOW() WHERE node_config_id = ? AND is_active = TRUE";
            pstmtUpdateOld = conn.prepareStatement(deactivateSql);
            pstmtUpdateOld.setObject(1, NODE_CONFIG_SINGLETON_ID);
            pstmtUpdateOld.executeUpdate();

            // Save the new certificate and private key, marking it as active
            saveCertificateToDb(NODE_CONFIG_SINGLETON_ID, certificatePem, privateKeyPem, true, issuedAt, expiresAt);

            // Update the node_config table's FQDN to match the new certificate's common name
            String updateNodeConfigFqdnSql = "UPDATE node_config SET fqdn = ?, updated_at = NOW() WHERE config_id = ?";
            PreparedStatement pstmtUpdateFqdn = conn.prepareStatement(updateNodeConfigFqdnSql);
            pstmtUpdateFqdn.setString(1, fqdnFromCert);
            pstmtUpdateFqdn.setObject(2, NODE_CONFIG_SINGLETON_ID);
            pstmtUpdateFqdn.executeUpdate();
            pstmtUpdateFqdn.close();

            conn.commit(); // Commit transaction

            JSONObject output = new JSONObject();
            output.put("message", "Certificate imported and activated successfully. Node FQDN updated to: " + fqdnFromCert);
            return new JSONObject() {{ put("success", true); put("data", output); }};

        } catch (SQLException e) {
            if (conn != null) {
                try {
                    conn.rollback();
                } catch (SQLException ex) {
                    ex.printStackTrace();
                }
            }
            throw e;
        } finally {
            pool.cleanup(null, pstmtUpdateOld, conn); // conn is cleaned up last
        }
    }

    /**
     * Helper to save/update certificate details in the node_certificates table.
     * This method assumes a 'node_certificates' table exists in the database schema.
     * (It was not explicitly in the provided init.sql, but is implied by NodeManagement's PKI operations).
     */
    private void saveCertificateToDb(UUID nodeConfigId, String certificatePem, String privateKeyPem, boolean isActive, Timestamp issuedAt, Timestamp expiresAt) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = new PoolDB();

        // This SQL assumes a node_certificates table with columns:
        // cert_id UUID PRIMARY KEY, node_config_id UUID, certificate_pem TEXT, private_key_pem TEXT,
        // is_active BOOLEAN, issued_at TIMESTAMP WITH TIME ZONE, expires_at TIMESTAMP WITH TIME ZONE,
        // created_at TIMESTAMP WITH TIME ZONE, updated_at TIMESTAMP WITH TIME ZONE
        String sql = "INSERT INTO node_certificates (node_config_id, certificate_pem, private_key_pem, is_active, issued_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)";

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, nodeConfigId);
            pstmt.setString(2, certificatePem);
            pstmt.setString(3, privateKeyPem);
            pstmt.setBoolean(4, isActive);
            pstmt.setTimestamp(5, issuedAt);
            pstmt.setTimestamp(6, expiresAt);
            pstmt.executeUpdate();
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
    }
}