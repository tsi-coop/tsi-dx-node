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
 * REVISED: Added 'Break Glass' Master Key generation functionality.
 */
public class User implements REST {

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
            String func = (String) input.get("_func");

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
                    // BREAK GLASS PROTOCOL: Generate a one-time secure recovery key
                    if (userId == null) throw new IllegalArgumentException("'user_id' target required.");
                    OutputProcessor.send(res, 200, generateMasterKey(userId, req));
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
     * Break Glass Protocol: Generates a high-entropy temporary key.
     * Updates the user's password hash and returns the raw key to the UI once.
     */
    private JSONObject generateMasterKey(UUID targetUserId, HttpServletRequest req) throws SQLException {
        // 1. Generate secure random key (16 bytes -> Base64)
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[12];
        random.nextBytes(bytes);
        String rawKey = "MK-" + Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        
        // 2. Hash it
        String hashedKey = passwordHasher.hashPassword(rawKey);

        Connection conn = null; PreparedStatement pstmt = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            conn.setAutoCommit(false);

            // 3. Update target user record
            pstmt = conn.prepareStatement("UPDATE users SET password_hash = ?, updated_at = NOW() WHERE user_id = ?");
            pstmt.setString(1, hashedKey);
            pstmt.setObject(2, targetUserId);
            pstmt.executeUpdate();

            // 4. Critical Forensic Audit
            JSONObject details = new JSONObject();
            details.put("action", "BREAK_GLASS_MASTER_KEY_GENERATED");
            details.put("target_user_id", targetUserId.toString());
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

            JSONObject details = new JSONObject();
            details.put("action", "ADMIN_UPDATE");
            logAudit("USER_UPDATED", "INFO", InputProcessor.getEmail(req), "USER", id, details, req);

            return new JSONObject() {{ put("success", true); }};
        } finally { pool.cleanup(null, pstmt, conn); }
    }

    private JSONObject createUser(JSONObject input, HttpServletRequest req) throws SQLException {
        String username = getString(input, "username");
        String email = getString(input, "email");
        String password = getString(input, "password");
        String roleIdStr = getString(input, "role_id");

        if (username.isEmpty() || email.isEmpty() || password.isEmpty() || roleIdStr.isEmpty()) throw new IllegalArgumentException("Missing required fields.");
        if (isUsernameOrEmailPresent(username, email, null)) throw new IllegalArgumentException("Identity conflict.");

        String hashedPassword = passwordHasher.hashPassword(password);
        UUID roleId = UUID.fromString(roleIdStr);
        JSONObject result = saveUserToDb(username, email, hashedPassword, roleId, "Active");

        JSONObject details = new JSONObject();
        details.put("username", username);
        details.put("email", email);
        logAudit("USER_CREATED", "INFO", InputProcessor.getEmail(req), "USER", UUID.fromString((String)result.get("user_id")), details, req);

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
            if (hasResult) { rs = pstmt.getResultSet(); if (rs.next()) { String id = rs.getString("user_id"); return new JSONObject() {{ put("success", true); put("user_id", id); }}; } }
            throw new SQLException("ID generation failed.");
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
                         "VALUES (?, NOW(), ?, ?, 'USER', ?, ?, ?, ?::jsonb, ?::inet)";
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, UUID.randomUUID());
            pstmt.setString(2, type);
            pstmt.setString(3, severity);
            pstmt.setString(4, (actor == null || actor.isEmpty()) ? "SYSTEM" : actor);
            pstmt.setString(5, entityType);
            if (entityId != null) pstmt.setObject(6, entityId); else pstmt.setNull(6, Types.OTHER);
            pstmt.setString(7, details != null ? details.toJSONString() : "{}");
            pstmt.setString(8, req.getRemoteAddr());
            pstmt.executeUpdate();
        } catch (Exception e) { System.err.println("[User] Audit Failure: " + e.getMessage()); }
        finally { pool.cleanup(null, pstmt, conn); }
    }

    private String getString(JSONObject obj, String key) { Object v = obj.get(key); return (v == null) ? "" : v.toString(); }
    private int getInt(JSONObject obj, String key, int def) { Object v = obj.get(key); if (v == null) return def; try { return Integer.parseInt(v.toString()); } catch (Exception e) { return def; } }
    private UUID extractUuid(JSONObject obj, String key) { Object v = obj.get(key); if (v == null || v.toString().trim().isEmpty()) return null; return UUID.fromString(v.toString()); }
    @Override public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) { return "POST".equalsIgnoreCase(method) && InputProcessor.validate(req, res); }
    @Override public void put(HttpServletRequest req, HttpServletResponse res) {}
    @Override public void delete(HttpServletRequest req, HttpServletResponse res) {}
}