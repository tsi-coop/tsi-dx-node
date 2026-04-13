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
import java.sql.Types;
import java.util.UUID;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Service to manage system users and access control roles.
 * Instrumented with forensic audit logging to track identity and permission changes.
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
    public void put(HttpServletRequest req, HttpServletResponse res) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "Use POST with '_func' attribute.", req.getRequestURI());
    }

    @Override
    public void delete(HttpServletRequest req, HttpServletResponse res) {
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

                case "get_user":
                    if (userId == null) throw new IllegalArgumentException("'user_id' required.");
                    Optional<JSONObject> user = getUserByIdFromDb(userId);
                    if (user.isPresent()) OutputProcessor.send(res, 200, user.get());
                    else OutputProcessor.errorResponse(res, 404, "Not Found", "User not found.", req.getRequestURI());
                    break;

                case "create_user":
                    JSONObject createdUser = createUser(input, req);
                    OutputProcessor.send(res, 201, createdUser);
                    break;

                case "update_user":
                    if (userId == null) throw new IllegalArgumentException("'user_id' required.");
                    JSONObject updatedUser = updateUserInDb(userId, getString(input, "username"), getString(input, "email"), getString(input, "password"), getString(input, "role_id"), getString(input, "status"), req);
                    OutputProcessor.send(res, 200, updatedUser);
                    break;

                case "delete_user":
                    if (userId == null) throw new IllegalArgumentException("'user_id' required.");
                    deleteUserFromDb(userId, req);
                    OutputProcessor.send(res, 204, null);
                    break;

                case "list_roles":
                    OutputProcessor.send(res, 200, listRolesFromDb(getString(input, "search"), getInt(input, "page", 1), getInt(input, "limit", 10)));
                    break;

                case "get_role":
                    if (roleId == null) throw new IllegalArgumentException("'role_id' required.");
                    Optional<JSONObject> role = getRoleByIdFromDb(roleId);
                    if (role.isPresent()) OutputProcessor.send(res, 200, role.get());
                    else OutputProcessor.errorResponse(res, 404, "Not Found", "Role not found.", req.getRequestURI());
                    break;

                case "create_role":
                    JSONObject createdRole = createRole(input, req);
                    OutputProcessor.send(res, 201, createdRole);
                    break;

                case "update_role":
                    if (roleId == null) throw new IllegalArgumentException("'role_id' required.");
                    JSONObject updatedRole = updateRole(input, roleId, req);
                    OutputProcessor.send(res, 200, updatedRole);
                    break;

                case "delete_role":
                    if (roleId == null) throw new IllegalArgumentException("'role_id' required.");
                    deleteRoleFromDb(roleId, req);
                    OutputProcessor.send(res, 204, null);
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
     * Internal helper to persist audit events.
     */
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
            
            String actorId = (actor == null || actor.isEmpty()) ? "SYSTEM" : actor;
            pstmt.setString(4, actorId);
            pstmt.setString(5, entityType);
            
            if (entityId != null) {
                pstmt.setObject(6, entityId);
            } else {
                pstmt.setNull(6, Types.OTHER);
            }
            
            pstmt.setString(7, details != null ? details.toJSONString() : "{}");
            pstmt.setString(8, req.getRemoteAddr());
            
            pstmt.executeUpdate();
        } catch (Exception e) {
            System.err.println("[User] Audit Logging Failure: " + e.getMessage());
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
    }

    private JSONObject updateRole(JSONObject input, UUID roleId, HttpServletRequest req) throws SQLException {
        String name = getString(input, "name");
        String description = getString(input, "description");
        JSONArray permissions = (JSONArray) input.get("permissions");

        if (name.isEmpty() || permissions == null || permissions.isEmpty()) {
            throw new IllegalArgumentException("Role name and permissions required.");
        }

        Connection conn = null; PreparedStatement pstmt = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            conn.setAutoCommit(false);

            pstmt = conn.prepareStatement("SELECT is_system_role FROM roles WHERE role_id = ?");
            pstmt.setObject(1, roleId);
            ResultSet rs = pstmt.executeQuery();
            if (rs.next() && rs.getBoolean("is_system_role")) throw new IllegalArgumentException("System roles are immutable.");
            rs.close(); pstmt.close();

            pstmt = conn.prepareStatement("UPDATE roles SET name = ?, description = ?, updated_at = NOW() WHERE role_id = ?");
            pstmt.setString(1, name); pstmt.setString(2, description); pstmt.setObject(3, roleId);
            pstmt.executeUpdate(); pstmt.close();

            pstmt = conn.prepareStatement("DELETE FROM role_permissions WHERE role_id = ?");
            pstmt.setObject(1, roleId); pstmt.executeUpdate(); pstmt.close();

            pstmt = conn.prepareStatement("INSERT INTO role_permissions (role_id, resource, action) VALUES (?, ?, ?)");
            for (Object pObj : permissions) {
                JSONObject p = (JSONObject) pObj;
                pstmt.setObject(1, roleId);
                pstmt.setString(2, (String) p.get("resource"));
                pstmt.setString(3, (String) p.get("action"));
                pstmt.addBatch();
            }
            pstmt.executeBatch();
            conn.commit();

            // AUDIT
            JSONObject details = new JSONObject();
            details.put("role_name", name);
            details.put("permission_count", permissions.size());
            logAudit("ROLE_UPDATED", "INFO", InputProcessor.getEmail(req), "ROLE", roleId, details, req);

            return new JSONObject() {{ put("success", true); }};
        } catch (SQLException e) { if (conn != null) conn.rollback(); throw e; }
        finally { pool.cleanup(null, pstmt, conn); }
    }

    private JSONObject createRole(JSONObject input, HttpServletRequest req) throws SQLException {
        String name = getString(input, "name");
        String description = getString(input, "description");
        JSONArray permissions = (JSONArray) input.get("permissions");

        if (name.isEmpty() || permissions == null || permissions.isEmpty()) throw new IllegalArgumentException("Metadata and permissions required.");

        Connection conn = null; PreparedStatement pstmt = null; PoolDB pool = new PoolDB();
        UUID newRoleId = UUID.randomUUID();

        try {
            conn = pool.getConnection();
            conn.setAutoCommit(false);

            pstmt = conn.prepareStatement("INSERT INTO roles (role_id, name, description, is_system_role) VALUES (?, ?, ?, FALSE)");
            pstmt.setObject(1, newRoleId); pstmt.setString(2, name); pstmt.setString(3, description);
            pstmt.executeUpdate(); pstmt.close();

            pstmt = conn.prepareStatement("INSERT INTO role_permissions (role_id, resource, action) VALUES (?, ?, ?)");
            for (Object pObj : permissions) {
                JSONObject p = (JSONObject) pObj;
                pstmt.setObject(1, newRoleId);
                pstmt.setString(2, (String) p.get("resource"));
                pstmt.setString(3, (String) p.get("action"));
                pstmt.addBatch();
            }
            pstmt.executeBatch();
            conn.commit();

            // AUDIT
            JSONObject details = new JSONObject();
            details.put("name", name);
            logAudit("ROLE_CREATED", "INFO", InputProcessor.getEmail(req), "ROLE", newRoleId, details, req);

            return new JSONObject() {{ put("success", true); put("role_id", newRoleId.toString()); }};
        } catch (SQLException e) { if (conn != null) conn.rollback(); throw e; }
        finally { pool.cleanup(null, pstmt, conn); }
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

        // AUDIT
        JSONObject details = new JSONObject();
        details.put("username", username);
        details.put("email", email);
        details.put("role_id", roleIdStr);
        logAudit("USER_CREATED", "INFO", InputProcessor.getEmail(req), "USER", UUID.fromString((String)result.get("user_id")), details, req);

        return result;
    }

    private JSONObject updateUserInDb(UUID id, String user, String email, String pass, String role, String status, HttpServletRequest req) throws SQLException {
        Connection conn = null; PreparedStatement pstmt = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            String sql = "UPDATE users SET username = COALESCE(NULLIF(?, ''), username), email = COALESCE(NULLIF(?, ''), email), status = COALESCE(NULLIF(?, ''), status), updated_at = NOW() WHERE user_id = ?";
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, user); pstmt.setString(2, email); pstmt.setString(3, status); pstmt.setObject(4, id);
            pstmt.executeUpdate();

            // AUDIT
            JSONObject details = new JSONObject();
            details.put("updated_fields", "username/email/status");
            logAudit("USER_UPDATED", "INFO", InputProcessor.getEmail(req), "USER", id, details, req);

            return new JSONObject() {{ put("success", true); }};
        } finally { pool.cleanup(null, pstmt, conn); }
    }

    private void deleteUserFromDb(UUID userId, HttpServletRequest req) throws SQLException {
        Connection conn = null; PreparedStatement pstmt = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("DELETE FROM users WHERE user_id = ?");
            pstmt.setObject(1, userId);
            pstmt.executeUpdate();

            // AUDIT
            logAudit("USER_DELETED", "WARNING", InputProcessor.getEmail(req), "USER", userId, new JSONObject(), req);
        } finally { pool.cleanup(null, pstmt, conn); }
    }

    private void deleteRoleFromDb(UUID roleId, HttpServletRequest req) throws SQLException {
        Connection conn = null; PreparedStatement pstmt = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            conn.setAutoCommit(false);

            pstmt = conn.prepareStatement("SELECT is_system_role FROM roles WHERE role_id = ?");
            pstmt.setObject(1, roleId);
            ResultSet rs = pstmt.executeQuery();
            if (rs.next() && rs.getBoolean("is_system_role")) throw new IllegalArgumentException("System roles immutable.");
            rs.close(); pstmt.close();

            pstmt = conn.prepareStatement("DELETE FROM role_permissions WHERE role_id = ?");
            pstmt.setObject(1, roleId); pstmt.executeUpdate(); pstmt.close();

            pstmt = conn.prepareStatement("DELETE FROM roles WHERE role_id = ?");
            pstmt.setObject(1, roleId); pstmt.executeUpdate();
            
            conn.commit();

            // AUDIT
            logAudit("ROLE_DELETED", "WARNING", InputProcessor.getEmail(req), "ROLE", roleId, new JSONObject(), req);
        } catch (SQLException e) { if (conn != null) conn.rollback(); throw e; }
        finally { pool.cleanup(null, pstmt, conn); }
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

    private Optional<JSONObject> getUserByIdFromDb(UUID userId) throws SQLException {
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        String sql = "SELECT u.*, r.name as role_name FROM users u JOIN roles r ON u.role_id = r.role_id WHERE u.user_id = ?";
        try {
            conn = pool.getConnection(); pstmt = conn.prepareStatement(sql); pstmt.setObject(1, userId);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                JSONObject u = new JSONObject(); u.put("user_id", rs.getString("user_id")); u.put("username", rs.getString("username")); u.put("email", rs.getString("email")); u.put("status", rs.getString("status")); u.put("role_id", rs.getString("role_id")); u.put("role_name", rs.getString("role_name")); return Optional.of(u);
            }
        } finally { pool.cleanup(rs, pstmt, conn); }
        return Optional.empty();
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

    private Optional<JSONObject> getRoleByIdFromDb(UUID roleId) throws SQLException {
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection(); pstmt = conn.prepareStatement("SELECT * FROM roles WHERE role_id = ?"); pstmt.setObject(1, roleId);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                JSONObject r = new JSONObject(); r.put("role_id", rs.getString("role_id")); r.put("name", rs.getString("name")); r.put("description", rs.getString("description"));
                rs.close(); pstmt.close();
                JSONArray perms = new JSONArray();
                pstmt = conn.prepareStatement("SELECT resource, action FROM role_permissions WHERE role_id = ?"); pstmt.setObject(1, roleId);
                rs = pstmt.executeQuery();
                while (rs.next()) { JSONObject p = new JSONObject(); p.put("resource", rs.getString("resource")); p.put("action", rs.getString("action")); perms.add(p); }
                r.put("permissions", perms); return Optional.of(r);
            }
        } finally { pool.cleanup(rs, pstmt, conn); }
        return Optional.empty();
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

    private String getString(JSONObject obj, String key) { Object v = obj.get(key); return (v == null) ? "" : v.toString(); }
    private int getInt(JSONObject obj, String key, int def) { Object v = obj.get(key); if (v == null) return def; try { return Integer.parseInt(v.toString()); } catch (Exception e) { return def; } }
    private UUID extractUuid(JSONObject obj, String key) { Object v = obj.get(key); if (v == null || v.toString().trim().isEmpty()) return null; return UUID.fromString(v.toString()); }
    @Override public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) { return "POST".equalsIgnoreCase(method) && InputProcessor.validate(req, res); }
}