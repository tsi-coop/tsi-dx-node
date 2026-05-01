package org.tsicoop.dxnode.api.admin;

import org.tsicoop.dxnode.framework.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.json.simple.JSONObject;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Service to handle the initial bootstrapping of the DX Node.
 * Sets the immutable Node Identity (including port) and creates the Master Administrator.
 * Aligned with the latest init.html and init.sql requirements.
 */
public class RegisterAdmin implements Action {

    private final PasswordHasher passwordHasher = new PasswordHasher();
    private static final UUID NODE_CONFIG_SINGLETON_ID = UUID.fromString("00000000-0000-0000-0000-000000000001");

    private static final Pattern PASSWORD_PATTERN =
            Pattern.compile("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[!@#$%^&*()_+])[A-Za-z\\d!@#$%^&*()_+]{8,}$");
    private static final Pattern EMAIL_PATTERN =
            Pattern.compile("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,6}$");

    @Override
    public void get(HttpServletRequest req, HttpServletResponse res) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "GET method not supported for admin registration.", req.getRequestURI());
    }

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        JSONObject input = null;
        JSONObject output = null;

        try {
            // 1. Check if the node has already been initialized
            if (isNodeInitialized()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_CONFLICT, "Conflict", "The TSI DX Node has already been initialized. Please use the login gateway.", req.getRequestURI());
                return;
            }

            input = InputProcessor.getInput(req);

            // Extract Node Identity parameters
            String nodeId = (String) input.get("node_id");
            String fqdn = (String) input.get("fqdn");
            
            // Extract Network Port from payload (matching init.html script)
            int networkPort = 8443;
            if (input.get("network_port") != null) {
                networkPort = (int)(long) input.get("network_port");
            }

            // Extract Admin Details
            String username = (String) input.get("username"); // Labeled "Admin User Name" in UI
            String email = (String) input.get("email");
            String password = (String) input.get("password");
            String confirmPassword = (String) input.get("confirm");
          
            // 2. Input Validation
            String validationError = validateRegistrationInput(nodeId, fqdn, networkPort, username, email, password, confirmPassword);
            if (validationError != null) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", validationError, req.getRequestURI());
                return;
            }

            // 3. Hash the password
            String hashedPassword = passwordHasher.hashPassword(password);

            // 4. Get the 'Administrator' role ID
            UUID adminRoleId = getRoleId("Administrator");
            if (adminRoleId == null) {
                OutputProcessor.errorResponse(res, 500, "Internal Error", "Administrator role missing from registry.", req.getRequestURI());
                return;
            }

            // 5. Initialize Node Config and Save Admin User (Transaction)
            output = bootstrapNode(nodeId, fqdn, networkPort, username, email, hashedPassword, adminRoleId);

            // 6. Return success response
            OutputProcessor.send(res, HttpServletResponse.SC_CREATED, output);

        } catch (SQLException e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, 500, "Database Error", e.getMessage(), req.getRequestURI());
        } catch (Exception e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, 500, "Internal Server Error", e.getMessage(), req.getRequestURI());
        }
    }

    @Override
    public void delete(HttpServletRequest req, HttpServletResponse res) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "DELETE not supported.", req.getRequestURI());
    }

    @Override
    public void put(HttpServletRequest req, HttpServletResponse res) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "PUT not supported.", req.getRequestURI());
    }

    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        return true;
    }

    private String validateRegistrationInput(String nodeId, String fqdn, int port, String username, String email, String password, String confirmPassword) {
        if (nodeId == null || nodeId.trim().isEmpty()) return "Node ID is required.";
        if (fqdn == null || fqdn.trim().isEmpty()) return "Public FQDN is required.";
        if (port < 1 || port > 65535) return "Invalid network port (1-65535).";
        if (username == null || username.trim().isEmpty()) return "Admin user name is required.";
        if (email == null || !EMAIL_PATTERN.matcher(email).matches()) return "Valid email is required.";
        if (!password.equals(confirmPassword)) return "Passwords do not match.";
        if (!PASSWORD_PATTERN.matcher(password).matches()) {
            return "Password must be at least 8 characters with uppercase, lowercase, digit, and special char.";
        }
        return null;
    }

    private boolean isNodeInitialized() throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("SELECT COUNT(*) FROM users");
            rs = pstmt.executeQuery();
            if (rs.next() && rs.getInt(1) > 0) return true;
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return false;
    }

    private UUID getRoleId(String roleName) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("SELECT role_id FROM roles WHERE name = ?");
            pstmt.setString(1, roleName);
            rs = pstmt.executeQuery();
            if (rs.next()) return UUID.fromString(rs.getString("role_id"));
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return null;
    }

    /**
     * Executes the bootstrap transaction: Configures the node and creates the first user.
     * REVISED: Removed 'name' column from node_config SQL to resolve DB error.
     * The Admin User Name is correctly persisted in the 'users' table.
     */
    private JSONObject bootstrapNode(String nodeId, String fqdn, int networkPort, String username, String email, String hashedPassword, UUID adminRoleId) throws SQLException {
        JSONObject output = new JSONObject();
        Connection conn = null;
        PreparedStatement pstmtConfig = null;
        PreparedStatement pstmtUser = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        // Derive storage paths from TSI_EXPORT_PATH so files land inside the Docker volume
        // and survive container restarts. Falls back to /var/lib/tsi/exports/ (the compose default).
        String exportBase = System.getenv().getOrDefault("TSI_EXPORT_PATH", "/var/lib/tsi/exports/");
        if (!exportBase.endsWith("/")) exportBase = exportBase + "/";
        String activeStoragePath  = exportBase + "active/";
        String archiveStoragePath = exportBase + "archive/";

        String configSql = "INSERT INTO node_config (config_id, node_id, fqdn, network_port, storage_active_path, storage_archive_path, logging_level) " +
                          "VALUES (?, ?, ?, ?, ?, ?, 'INFO')";

        String userSql = "INSERT INTO users (username, email, password_hash, role_id, status) VALUES (?, ?, ?, ?, 'Active') RETURNING user_id";

        try {
            conn = pool.getConnection();
            conn.setAutoCommit(false);

            // 1. Initialize Node Configuration
            pstmtConfig = conn.prepareStatement(configSql);
            pstmtConfig.setObject(1, NODE_CONFIG_SINGLETON_ID);
            pstmtConfig.setString(2, nodeId);
            pstmtConfig.setString(3, fqdn);
            pstmtConfig.setInt(4, networkPort);
            pstmtConfig.setString(5, activeStoragePath);
            pstmtConfig.setString(6, archiveStoragePath);
            pstmtConfig.executeUpdate();

            // 2. Create Master Administrator (Sets the name/username in User table)
            pstmtUser = conn.prepareStatement(userSql);
            pstmtUser.setString(1, username);
            pstmtUser.setString(2, email);
            pstmtUser.setString(3, hashedPassword);
            pstmtUser.setObject(4, adminRoleId);

            boolean hasResultSet = pstmtUser.execute();
            if (hasResultSet) {
                rs = pstmtUser.getResultSet();
                if (rs.next()) {
                    output.put("user_id", rs.getString("user_id"));
                    output.put("node_id", nodeId);
                    output.put("username", username);
                    output.put("fqdn", fqdn);
                    output.put("network_port", networkPort);
                } else {
                    throw new SQLException("Critical: User ID generation failed.");
                }
            }

            conn.commit();
            output.put("success", true);
            output.put("message", "Node identity and administrator registered successfully.");

        } catch (SQLException e) {
            if (conn != null) conn.rollback();
            throw e;
        } finally {
            if (pstmtConfig != null) pstmtConfig.close();
            pool.cleanup(rs, pstmtUser, conn);
        }
        return output;
    }
}