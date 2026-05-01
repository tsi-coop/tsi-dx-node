package org.tsicoop.dxnode.api.admin;

import org.tsicoop.dxnode.framework.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.util.Base64;
import java.util.UUID;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Service to manage system users and access control roles.
 * Instrumented with forensic audit logging to track identity and permission changes.
 * REVISED: Implements 'Break Glass' protocol using a dedicated master_key_hash column.
 * This ensures original passwords remain valid while a recovery key is active.
 */
public class User implements Action {

    private final PasswordHasher passwordHasher = new PasswordHasher();

    private static final Pattern PASSWORD_PATTERN =
            Pattern.compile("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[!@#$%^&*()_+])[A-Za-z\\d!@#$%^&*()_+]{8,}$");
    private static final Pattern EMAIL_PATTERN =
            Pattern.compile("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,6}$");

    @Override
    public void get(HttpServletRequest req, HttpServletResponse res) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "Use POST with '_func' attribute.", req.getRequestURI());
    }

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        JSONObject input = null;
        try {
            input = InputProcessor.getInput(req);
            
            String func = (input != null) ? (String) input.get("_func") : null;

            if (func == null || func.trim().isEmpty()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing '_func' identifier.", req.getRequestURI());
                return;
            }

            UUID userId = extractUuid(input, "user_id");
            UUID roleId = extractUuid(input, "role_id");

            switch (func.toLowerCase()) {
                case "list_users":
                    OutputProcessor.send(res, 200, listUsersFromDb(getString(input, "status"), getString(input, "search"), getInt(input, "page", 1), getInt(input, "limit", 10)));
                    break;

                case "create_user":
                    JSONObject createdUser = createUser(input, req);
                    OutputProcessor.send(res, 201, createdUser);
                    break;

                case "update_user":
                    if (userId == null) throw new IllegalArgumentException("'user_id' required.");
                    JSONObject updatedUser = updateUserInDb(userId, getString(input, "username"), roleId, getString(input, "status"), req);
                    OutputProcessor.send(res, 200, updatedUser);
                    break;

                case "delete_user":
                    if (userId == null) throw new IllegalArgumentException("'user_id' required.");
                    deleteUserFromDb(userId, req);
                    OutputProcessor.send(res, 204, null);
                    break;

                case "generate_master_key":
                    // BREAK GLASS: Issue emergency recovery key for target user
                    if (userId == null) throw new IllegalArgumentException("'user_id' required for break-glass.");
                    OutputProcessor.send(res, 200, generateMasterKey(userId, req));
                    break;

                case "reset_password_with_key":
                    // RECOVERY: Finalize password change using the one-time key
                    OutputProcessor.send(res, 200, resetPasswordWithMasterKey(input, req));
                    break;

                case "list_roles":
                    OutputProcessor.send(res, 200, listRolesFromDb(getString(input, "search"), getInt(input, "page", 1), getInt(input, "limit", 10)));
                    break;

                default:
                    OutputProcessor.errorResponse(res, 400, "Bad Request", "Unknown _func: " + func, req.getRequestURI());
                    break;
            }

        } catch (IllegalArgumentException e) {
            OutputProcessor.errorResponse(res, 400, "Validation Error", e.getMessage(), req.getRequestURI());
        } catch (Exception e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, 500, "Internal Server Error", e.getMessage(), req.getRequestURI());
        }
    }

    /**
     * Recovery Protocol: Verifies the Master Key from the dedicated column.
     * On success, updates the main password_hash and clears the master_key_hash.
     */
    private JSONObject resetPasswordWithMasterKey(JSONObject input, HttpServletRequest req) throws SQLException {
        String email = getString(input, "email");
        String masterKey = getString(input, "master_key");
        String newPassword = getString(input, "new_password");

        if (email.isEmpty() || masterKey.isEmpty() || newPassword.isEmpty()) 
            throw new IllegalArgumentException("Email, Master Key, and New Password are all required.");

        if (!PASSWORD_PATTERN.matcher(newPassword).matches())
            throw new IllegalArgumentException("New password does not meet complexity requirements.");

        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            conn.setAutoCommit(false); 
            
            // 1. Resolve User and their active Master Key hash
            pstmt = conn.prepareStatement("SELECT user_id, master_key_hash FROM users WHERE email = ?");
            pstmt.setString(1, email);
            rs = pstmt.executeQuery();

            if (rs.next()) {
                UUID userIdFromDb = UUID.fromString(rs.getString("user_id"));
                String storedMkHash = rs.getString("master_key_hash");

                if (storedMkHash == null) {
                    throw new IllegalArgumentException("No active master key found for this account.");
                }

                // 2. Cryptographic verification of the master key
                if (passwordHasher.checkPassword(masterKey, storedMkHash)) {
                    
                    // 3. Update main password, ensure account is Active, and CLEAR the MK hash (one-time use)
                    String newHash = passwordHasher.hashPassword(newPassword);
                    try (PreparedStatement upd = conn.prepareStatement(
                            "UPDATE users SET password_hash = ?, master_key_hash = NULL, status = 'Active', updated_at = NOW() WHERE user_id = ?")) {
                        upd.setString(1, newHash);
                        upd.setObject(2, userIdFromDb);
                        upd.executeUpdate();
                    }

                    // 4. Forensic Audit
                    JSONObject details = new JSONObject();
                    details.put("recovery_method", "MASTER_KEY_RECOVERY");
                    logAudit("SECURITY_RECOVERY_COMPLETE", "INFO", email, "USER", userIdFromDb, details, req);

                    conn.commit(); 
                    return new JSONObject() {{ put("success", true); put("message", "Account recovered. Primary credentials updated."); }};
                }
            }
            
            if (conn != null) conn.rollback();
            throw new IllegalArgumentException("Identity verification failed. Invalid key or email.");
            
        } catch (SQLException e) {
            if (conn != null) conn.rollback();
            throw e;
        } finally { pool.cleanup(rs, pstmt, conn); }
    }

    /**
     * Break Glass Protocol: Generates a key and stores it in master_key_hash.
     * Primary password_hash is left UNTOUCHED, allowing normal login to continue.
     */
    private JSONObject generateMasterKey(UUID targetUserId, HttpServletRequest req) throws SQLException {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[12];
        random.nextBytes(bytes);
        String rawKey = "MK-" + Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        
        String hashedKey = passwordHasher.hashPassword(rawKey);

        Connection conn = null; PreparedStatement pstmt = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            conn.setAutoCommit(false);

            // UPDATED: Store hash in master_key_hash instead of overwriting password_hash
            pstmt = conn.prepareStatement("UPDATE users SET master_key_hash = ?, updated_at = NOW() WHERE user_id = ?");
            pstmt.setString(1, hashedKey);
            pstmt.setObject(2, targetUserId);
            pstmt.executeUpdate();

            JSONObject details = new JSONObject();
            details.put("action", "EMERGENCY_KEY_ISSUED");
            details.put("status", "ORIGINAL_PASSWORD_RETAINED");
            logAudit("SECURITY_BREAK_GLASS", "CRITICAL", InputProcessor.getEmail(req), "USER", targetUserId, details, req);

            conn.commit();

            JSONObject out = new JSONObject();
            out.put("success", true);
            out.put("master_key", rawKey); 
            return out;
        } catch (SQLException e) {
            if (conn != null) conn.rollback();
            throw e;
        } finally { pool.cleanup(null, pstmt, conn); }
    }

    private JSONObject updateUserInDb(UUID id, String username, UUID roleId, String status, HttpServletRequest req) throws SQLException {
        Connection conn = null; PreparedStatement pstmt = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            String sql = "UPDATE users SET " +
                         "username = COALESCE(NULLIF(?, ''), username), " +
                         "role_id = COALESCE(?, role_id), " +
                         "status = COALESCE(NULLIF(?, ''), status), " +
                         "updated_at = NOW() WHERE user_id = ?";
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, username);
            if (roleId != null) pstmt.setObject(2, roleId); else pstmt.setNull(2, Types.OTHER);
            pstmt.setString(3, status);
            pstmt.setObject(4, id);
            pstmt.executeUpdate();

            logAudit("USER_UPDATED", "INFO", InputProcessor.getEmail(req), "USER", id, new JSONObject(), req);

            return new JSONObject() {{ put("success", true); }};
        } finally { pool.cleanup(null, pstmt, conn); }
    }

    private JSONObject createUser(JSONObject input, HttpServletRequest req) throws SQLException {
        String username = getString(input, "username");
        String email = getString(input, "email");
        String password = getString(input, "password");
        String roleIdStr = getString(input, "role_id");

        if (username.isEmpty() || email.isEmpty() || password.isEmpty() || roleIdStr.isEmpty()) 
            throw new IllegalArgumentException("Missing required identity fields.");
        
        if (!EMAIL_PATTERN.matcher(email).matches()) throw new IllegalArgumentException("Invalid email format.");
        if (!PASSWORD_PATTERN.matcher(password).matches()) throw new IllegalArgumentException("Password complexity violation.");

        String hashedPassword = passwordHasher.hashPassword(password);
        UUID roleId = UUID.fromString(roleIdStr);
        JSONObject result = saveUserToDb(username, email, hashedPassword, roleId, "Active");

        logAudit("USER_CREATED", "INFO", InputProcessor.getEmail(req), "USER", UUID.fromString((String)result.get("user_id")), new JSONObject(), req);

        return result;
    }

    private void deleteUserFromDb(UUID userId, HttpServletRequest req) throws SQLException {
        Connection conn = null; PreparedStatement pstmt = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("DELETE FROM users WHERE user_id = ?");
            pstmt.setObject(1, userId);
            pstmt.executeUpdate();
            logAudit("USER_DELETED", "WARNING", InputProcessor.getEmail(req), "USER", userId, new JSONObject(), req);
        } finally { pool.cleanup(null, pstmt, conn); }
    }

    private JSONArray listUsersFromDb(String statusFilter, String search, int page, int limit) throws SQLException {
        JSONArray usersArray = new JSONArray();
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        StringBuilder sql = new StringBuilder("SELECT u.*, r.name as role_name FROM users u JOIN roles r ON u.role_id = r.role_id WHERE 1=1");
        if (!statusFilter.isEmpty()) sql.append(" AND u.status = ?");
        if (!search.isEmpty()) sql.append(" AND (u.username ILIKE ? OR u.email ILIKE ?)");
        sql.append(" ORDER BY u.created_at DESC LIMIT ? OFFSET ?");
        try {
            conn = pool.getConnection(); pstmt = conn.prepareStatement(sql.toString());
            int idx = 1;
            if (!statusFilter.isEmpty()) pstmt.setString(idx++, statusFilter);
            if (!search.isEmpty()) { pstmt.setString(idx++, "%" + search + "%"); pstmt.setString(idx++, "%" + search + "%"); }
            pstmt.setInt(idx++, limit); pstmt.setInt(idx++, (page - 1) * limit);
            rs = pstmt.executeQuery();
            while (rs.next()) {
                JSONObject u = new JSONObject(); u.put("user_id", rs.getString("user_id")); u.put("username", rs.getString("username")); u.put("email", rs.getString("email")); u.put("status", rs.getString("status")); u.put("role", rs.getString("role_name")); u.put("last_login_at", rs.getTimestamp("last_login_at") != null ? rs.getTimestamp("last_login_at").toString() : null); usersArray.add(u);
            }
        } finally { pool.cleanup(rs, pstmt, conn); }
        return usersArray;
    }

    private JSONObject saveUserToDb(String username, String email, String password, UUID roleId, String status) throws SQLException {
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        String sql = "INSERT INTO users (username, email, password_hash, role_id, status) VALUES (?, ?, ?, ?, ?) RETURNING user_id";
        try {
            conn = pool.getConnection(); pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, username); pstmt.setString(2, email); pstmt.setString(3, password); pstmt.setObject(4, roleId); pstmt.setString(5, status);
            boolean hasResult = pstmt.execute();
            if (hasResult) { 
                rs = pstmt.getResultSet(); 
                if (rs.next()) { 
                    String id = rs.getString("user_id"); 
                    return new JSONObject() {{ put("success", true); put("user_id", id); }}; 
                } 
            }
            throw new SQLException("Identity persistence failed.");
        } finally { pool.cleanup(rs, pstmt, conn); }
    }

    private JSONArray listRolesFromDb(String search, int page, int limit) throws SQLException {
        JSONArray rolesArray = new JSONArray(); Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        String sql = "SELECT * FROM roles WHERE (name ILIKE ? OR description ILIKE ?) ORDER BY created_at DESC LIMIT ? OFFSET ?";
        try {
            conn = pool.getConnection(); pstmt = conn.prepareStatement(sql);
            String f = search.isEmpty() ? "%%" : "%" + search + "%";
            pstmt.setString(1, f); pstmt.setString(2, f); pstmt.setInt(3, limit); pstmt.setInt(4, (page - 1) * limit);
            rs = pstmt.executeQuery();
            while (rs.next()) {
                JSONObject r = new JSONObject(); r.put("role_id", rs.getString("role_id")); r.put("name", rs.getString("name")); r.put("description", rs.getString("description")); r.put("is_system_role", rs.getBoolean("is_system_role")); rolesArray.add(r);
            }
        } finally { pool.cleanup(rs, pstmt, conn); }
        return rolesArray;
    }

    private boolean isUsernameOrEmailPresent(String user, String email, UUID exclude) throws SQLException {
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            String sql = "SELECT COUNT(*) FROM users WHERE (username = ? OR email = ?)";
            if (exclude != null) sql += " AND user_id != ?";
            pstmt = conn.prepareStatement(sql); pstmt.setString(1, user); pstmt.setString(2, email);
            if (exclude != null) pstmt.setObject(3, exclude);
            rs = pstmt.executeQuery(); return rs.next() && rs.getInt(1) > 0;
        } finally { pool.cleanup(rs, pstmt, conn); }
    }

    private void logAudit(String type, String severity, String actor, String entityType, UUID entityId, JSONObject details, HttpServletRequest req) {
        Connection conn = null; PreparedStatement pstmt = null; PoolDB pool = null;
        try {
            pool = new PoolDB();
            conn = pool.getConnection();
            String sql = "INSERT INTO audit_logs (log_id, timestamp, event_type, severity, actor_type, actor_id, entity_type, entity_id, details, origin_ip) " +
                         "VALUES (?, NOW(), ?, ?, ?, ?, ?, ?, ?::jsonb, ?::inet)";
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, UUID.randomUUID());
            pstmt.setString(2, type);
            pstmt.setString(3, severity);
            String actorId = (actor == null || actor.isEmpty()) ? "SYSTEM" : actor;
            pstmt.setString(4, actorId.contains("@") ? "USER" : "SYSTEM");
            pstmt.setString(5, actorId);
            pstmt.setString(6, entityType);
            if (entityId != null) pstmt.setObject(7, entityId); else pstmt.setNull(7, Types.OTHER);
            pstmt.setString(8, details != null ? details.toJSONString() : "{}");
            pstmt.setString(9, req.getRemoteAddr());
            pstmt.executeUpdate();
        } catch (Exception e) { System.err.println("[User] Audit Failure: " + e.getMessage()); }
        finally { pool.cleanup(null, pstmt, conn); }
    }

    private String getString(JSONObject obj, String key) { Object v = obj.get(key); return (v == null) ? "" : v.toString(); }
    private int getInt(JSONObject obj, String key, int def) { Object v = obj.get(key); if (v == null) return def; try { return Integer.parseInt(v.toString()); } catch (Exception e) { return def; } }
    private UUID extractUuid(JSONObject obj, String key) { Object v = obj.get(key); if (v == null || v.toString().trim().isEmpty()) return null; try { return UUID.fromString(v.toString()); } catch(Exception e) { return null; } }
    @Override public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) { return "POST".equalsIgnoreCase(method) && InputProcessor.validate(req, res); }
    @Override public void put(HttpServletRequest req, HttpServletResponse res) {}
    @Override public void delete(HttpServletRequest req, HttpServletResponse res) {}
}