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
import java.sql.Types;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

/**
 * Service to manage administrative authentication.
 * Instrumented with forensic audit logging to track access attempts and security events.
 */
public class Login implements REST {

    private final PasswordHasher passwordHasher = new PasswordHasher();

    @Override
    public void get(HttpServletRequest req, HttpServletResponse res) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "GET method is not used directly. Use POST for login.", req.getRequestURI());
    }

    @Override
    public void put(HttpServletRequest req, HttpServletResponse res) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "PUT method is not used directly. Use POST for login.", req.getRequestURI());
    }

    @Override
    public void delete(HttpServletRequest req, HttpServletResponse res) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "DELETE method is not used directly. Use POST for login.", req.getRequestURI());
    }

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        try {
            JSONObject input = InputProcessor.getInput(req);
            String email = (String) input.get("email");
            String password = (String) input.get("password");

            if (email == null || email.trim().isEmpty() ||
                    password == null || password.trim().isEmpty()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required fields.", req.getRequestURI());
                return;
            }

            // 1. Get user details from DB
            Optional<JSONObject> userDetailsOptional = getUserDetails(email);

            if (userDetailsOptional.isEmpty()) {
                // AUDIT: Failed attempt (User not found)
                JSONObject details = new JSONObject();
                details.put("reason", "USER_NOT_FOUND");
                logAudit("SECURITY_AUTH_FAILURE", "WARNING", email, null, details, req);

                OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized", "Invalid username or password.", req.getRequestURI());
                return;
            }

            JSONObject userDetails = userDetailsOptional.get();
            String storedPasswordHash = (String) userDetails.get("passwordHash");
            String userId = (String) userDetails.get("userId"); 
            String userEmail = (String) userDetails.get("email");
            String userStatus = (String) userDetails.get("status");
            String username = (String) userDetails.get("username");
            String nodeId = (String) userDetails.get("nodeId");
            String roleName = (String) userDetails.get("roleName");

            // Check user status
            if (!"Active".equalsIgnoreCase(userStatus)) {
                // AUDIT: Blocked attempt (Inactive account)
                JSONObject details = new JSONObject();
                details.put("reason", "ACCOUNT_NOT_ACTIVE");
                details.put("current_status", userStatus);
                logAudit("SECURITY_AUTH_BLOCKED", "WARNING", userEmail, UUID.fromString(userId), details, req);

                OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized", "User account is " + userStatus.toLowerCase() + ".", req.getRequestURI());
                return;
            }

            // Validate password
            if (!passwordHasher.checkPassword(password, storedPasswordHash)) {
                // AUDIT: Failed attempt (Bad credentials)
                JSONObject details = new JSONObject();
                details.put("reason", "INVALID_PASSWORD");
                logAudit("SECURITY_AUTH_FAILURE", "WARNING", userEmail, UUID.fromString(userId), details, req);

                OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized", "Invalid username or password.", req.getRequestURI());
                return;
            }

            // 2. Success logic
            updateLastLogin(userId);
            String generatedToken = JWTUtil.generateToken(userId, username, roleName);

            // AUDIT: Successful Login
            JSONObject successDetails = new JSONObject();
            successDetails.put("role", roleName);
            successDetails.put("node_id", nodeId);
            logAudit("SECURITY_AUTH_SUCCESS", "INFO", userEmail, UUID.fromString(userId), successDetails, req);

            // 3. Response
            JSONObject output = new JSONObject();
            output.put("success", true);
            output.put("message", "Login successful");
            output.put("token", generatedToken);
            output.put("username", username); 
            output.put("role", roleName);
            output.put("email", userEmail);
            output.put("nodeId", nodeId);
            output.put("user_id", userId);

            OutputProcessor.send(res, HttpServletResponse.SC_OK, output);

        } catch (SQLException e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, 500, "Database Error", e.getMessage(), req.getRequestURI());
        } catch (Exception e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, 500, "Internal Server Error", e.getMessage(), req.getRequestURI());
        }
    }

    /**
     * Internal helper to persist security audit events.
     */
    private void logAudit(String type, String severity, String actor, UUID entityId, JSONObject details, HttpServletRequest req) {
        Connection conn = null; PreparedStatement pstmt = null; PoolDB pool = null;
        try {
            pool = new PoolDB();
            conn = pool.getConnection();
            // Use jsonb and inet casts for Postgres compatibility
            String sql = "INSERT INTO audit_logs (log_id, timestamp, event_type, severity, actor_type, actor_id, entity_type, entity_id, details, origin_ip) " +
                         "VALUES (?, NOW(), ?, ?, 'USER', ?, 'USER', ?, ?::jsonb, ?::inet)";
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, UUID.randomUUID());
            pstmt.setString(2, type);
            pstmt.setString(3, severity);
            
            // actor_id represents the email used for login
            pstmt.setString(4, (actor == null || actor.isEmpty()) ? "UNKNOWN" : actor);
            
            // entity_id refers to the User UUID if resolved
            if (entityId != null) {
                pstmt.setObject(5, entityId);
            } else {
                pstmt.setNull(5, Types.OTHER);
            }
            
            pstmt.setString(6, details != null ? details.toJSONString() : "{}");
            pstmt.setString(7, req.getRemoteAddr());
            
            pstmt.executeUpdate();
        } catch (Exception e) {
            System.err.println("[Login] Audit Logging Failure: " + e.getMessage());
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
    }

    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        if (!"POST".equalsIgnoreCase(method)) {
            OutputProcessor.errorResponse(res, 405, "Method Not Allowed", "Only POST supported.", req.getRequestURI());
            return false;
        }
        return InputProcessor.validate(req, res);
    }

    private Optional<JSONObject> getUserDetails(String email) throws SQLException {
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        String sql = "SELECT u.user_id, u.username, u.password_hash, u.email, u.status, r.name AS role_name, " +
                "(SELECT node_id FROM node_config WHERE config_id = '00000000-0000-0000-0000-000000000001') AS local_node_id " +
                "FROM users u JOIN roles r ON u.role_id = r.role_id WHERE u.email = ?";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, email);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                JSONObject user = new JSONObject();
                user.put("userId", rs.getString("user_id"));
                user.put("username", rs.getString("username"));
                user.put("passwordHash", rs.getString("password_hash"));
                user.put("email", rs.getString("email"));
                user.put("status", rs.getString("status"));
                user.put("roleName", rs.getString("role_name"));
                user.put("nodeId", rs.getString("local_node_id")); 
                return Optional.of(user);
            }
        } finally { pool.cleanup(rs, pstmt, conn); }
        return Optional.empty();
    }

    private void updateLastLogin(String userId) throws SQLException {
        Connection conn = null; PreparedStatement pstmt = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("UPDATE users SET last_login_at = ? WHERE user_id = ?");
            pstmt.setTimestamp(1, Timestamp.valueOf(LocalDateTime.now()));
            pstmt.setObject(2, UUID.fromString(userId));
            pstmt.executeUpdate();
        } finally { pool.cleanup(null, pstmt, conn); }
    }
}