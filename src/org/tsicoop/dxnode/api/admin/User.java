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
import java.util.UUID;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Service to manage system users and access control roles.
 * Updated to support get_role (with permissions) and delete_role functionality.
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
        JSONObject output = null;
        JSONArray outputArray = null;

        try {
            input = InputProcessor.getInput(req);
            String func = (String) input.get("_func");

            if (func == null || func.trim().isEmpty()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required '_func' attribute.", req.getRequestURI());
                return;
            }

            // --- SAFE ID EXTRACTION ---
            UUID userId = null;
            Object userIdRaw = input.get("user_id");
            if (userIdRaw != null && !userIdRaw.toString().trim().isEmpty()) {
                try {
                    userId = UUID.fromString(userIdRaw.toString());
                } catch (IllegalArgumentException e) {
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid 'user_id' format.", req.getRequestURI());
                    return;
                }
            }

            UUID roleId = null;
            Object roleIdRaw = input.get("role_id");
            if (roleIdRaw != null && !roleIdRaw.toString().trim().isEmpty()) {
                try {
                    roleId = UUID.fromString(roleIdRaw.toString());
                } catch (IllegalArgumentException e) {
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid 'role_id' format.", req.getRequestURI());
                    return;
                }
            }

            switch (func.toLowerCase()) {
                case "list_users":
                    String userStatusFilter = getString(input, "status");
                    String userSearch = getString(input, "search");
                    int userPage = getInt(input, "page", 1);
                    int userLimit = getInt(input, "limit", 10);
                    outputArray = listUsersFromDb(userStatusFilter, userSearch, userPage, userLimit);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, outputArray);
                    break;

                case "get_user":
                    if (userId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'user_id' is required.", req.getRequestURI());
                        return;
                    }
                    Optional<JSONObject> userOptional = getUserByIdFromDb(userId);
                    if (userOptional.isPresent()) {
                        OutputProcessor.send(res, HttpServletResponse.SC_OK, userOptional.get());
                    } else {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "User not found.", req.getRequestURI());
                    }
                    break;

                case "create_user":
                    output = createUser(input);
                    OutputProcessor.send(res, HttpServletResponse.SC_CREATED, output);
                    break;

                case "update_user":
                    if (userId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'user_id' is required.", req.getRequestURI());
                        return;
                    }
                    output = updateUserInDb(userId, getString(input, "username"), getString(input, "email"), getString(input, "password"), getString(input, "role_id"), getString(input, "status"));
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
                    break;

                case "delete_user":
                    if (userId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'user_id' is required.", req.getRequestURI());
                        return;
                    }
                    deleteUserFromDb(userId);
                    OutputProcessor.send(res, HttpServletResponse.SC_NO_CONTENT, null);
                    break;

                case "list_roles":
                    String roleSearch = getString(input, "search");
                    int rolePage = getInt(input, "page", 1);
                    int roleLimit = getInt(input, "limit", 10);
                    outputArray = listRolesFromDb(roleSearch, rolePage, roleLimit);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, outputArray);
                    break;

                case "get_role":
                    if (roleId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'role_id' is required.", req.getRequestURI());
                        return;
                    }
                    Optional<JSONObject> roleOptional = getRoleByIdFromDb(roleId);
                    if (roleOptional.isPresent()) {
                        OutputProcessor.send(res, HttpServletResponse.SC_OK, roleOptional.get());
                    } else {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Role not found.", req.getRequestURI());
                    }
                    break;

                case "create_role":
                    output = createRole(input);
                    OutputProcessor.send(res, HttpServletResponse.SC_CREATED, output);
                    break;

                case "delete_role":
                    if (roleId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'role_id' is required.", req.getRequestURI());
                        return;
                    }
                    deleteRoleFromDb(roleId);
                    OutputProcessor.send(res, HttpServletResponse.SC_NO_CONTENT, null);
                    break;

                default:
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Unknown _func: " + func, req.getRequestURI());
                    break;
            }

        } catch (Exception e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Error", e.getMessage(), req.getRequestURI());
        }
    }

    // --- Helper Utilities for Safe Extraction ---
    private String getString(JSONObject obj, String key) {
        Object val = obj.get(key);
        return (val == null) ? "" : val.toString();
    }

    private int getInt(JSONObject obj, String key, int defaultVal) {
        Object val = obj.get(key);
        if (val == null) return defaultVal;
        if (val instanceof Number) return ((Number) val).intValue();
        try { return Integer.parseInt(val.toString()); } catch (Exception e) { return defaultVal; }
    }

    // --- Implementation Methods ---

    private JSONObject createRole(JSONObject input) throws SQLException {
        String name = getString(input, "name");
        String description = getString(input, "description");
        JSONArray permissions = (JSONArray) input.get("permissions");

        if (name.isEmpty() || permissions == null || permissions.isEmpty()) {
            throw new IllegalArgumentException("Role name and at least one permission are required.");
        }

        Connection conn = null;
        PreparedStatement pstmtRole = null;
        PreparedStatement pstmtPerm = null;
        PoolDB pool = new PoolDB();
        UUID newRoleId = UUID.randomUUID();

        try {
            conn = pool.getConnection();
            conn.setAutoCommit(false);

            String insertRoleSql = "INSERT INTO roles (role_id, name, description, is_system_role) VALUES (?, ?, ?, FALSE)";
            pstmtRole = conn.prepareStatement(insertRoleSql);
            pstmtRole.setObject(1, newRoleId);
            pstmtRole.setString(2, name);
            pstmtRole.setString(3, description);
            pstmtRole.executeUpdate();

            String insertPermSql = "INSERT INTO role_permissions (role_id, resource, action) VALUES (?, ?, ?)";
            pstmtPerm = conn.prepareStatement(insertPermSql);
            for (Object pObj : permissions) {
                JSONObject p = (JSONObject) pObj;
                pstmtPerm.setObject(1, newRoleId);
                pstmtPerm.setString(2, (String) p.get("resource"));
                pstmtPerm.setString(3, (String) p.get("action"));
                pstmtPerm.addBatch();
            }
            pstmtPerm.executeBatch();

            conn.commit();
            return new JSONObject() {{ put("success", true); put("role_id", newRoleId.toString()); }};

        } catch (SQLException e) {
            if (conn != null) conn.rollback();
            throw e;
        } finally {
            if (pstmtRole != null) pstmtRole.close();
            if (pstmtPerm != null) pstmtPerm.close();
            pool.cleanup(null, null, conn);
        }
    }

    private JSONObject createUser(JSONObject input) throws SQLException {
        String username = getString(input, "username");
        String email = getString(input, "email");
        String password = getString(input, "password");
        String roleIdStr = getString(input, "role_id");

        if (username.isEmpty() || email.isEmpty() || password.isEmpty() || roleIdStr.isEmpty()) {
            throw new IllegalArgumentException("Missing required fields for user creation.");
        }

        if (isUsernameOrEmailPresent(username, email, null)) {
            throw new IllegalArgumentException("Username or Email already exists.");
        }

        String hashedPassword = passwordHasher.hashPassword(password);
        return saveUserToDb(username, email, hashedPassword, UUID.fromString(roleIdStr), "Active");
    }

    private JSONArray listUsersFromDb(String statusFilter, String search, int page, int limit) throws SQLException {
        JSONArray usersArray = new JSONArray();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        StringBuilder sql = new StringBuilder("SELECT u.*, r.name as role_name FROM users u JOIN roles r ON u.role_id = r.role_id WHERE 1=1");
        if (statusFilter != null && !statusFilter.isEmpty()) sql.append(" AND u.status = ?");
        if (search != null && !search.isEmpty()) sql.append(" AND (u.username ILIKE ? OR u.email ILIKE ?)");
        sql.append(" ORDER BY u.created_at DESC LIMIT ? OFFSET ?");

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql.toString());
            int idx = 1;
            if (statusFilter != null && !statusFilter.isEmpty()) pstmt.setString(idx++, statusFilter);
            if (search != null && !search.isEmpty()) {
                pstmt.setString(idx++, "%" + search + "%");
                pstmt.setString(idx++, "%" + search + "%");
            }
            pstmt.setInt(idx++, limit);
            pstmt.setInt(idx++, (page - 1) * limit);
            rs = pstmt.executeQuery();

            while (rs.next()) {
                JSONObject u = new JSONObject();
                u.put("user_id", rs.getString("user_id"));
                u.put("username", rs.getString("username"));
                u.put("email", rs.getString("email"));
                u.put("status", rs.getString("status"));
                u.put("role", rs.getString("role_name"));
                u.put("last_login_at", rs.getTimestamp("last_login_at") != null ? rs.getTimestamp("last_login_at").toString() : null);
                usersArray.add(u);
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return usersArray;
    }

    private Optional<JSONObject> getUserByIdFromDb(UUID userId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "SELECT u.*, r.name as role_name FROM users u JOIN roles r ON u.role_id = r.role_id WHERE u.user_id = ?";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, userId);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                JSONObject u = new JSONObject();
                u.put("user_id", rs.getString("user_id"));
                u.put("username", rs.getString("username"));
                u.put("email", rs.getString("email"));
                u.put("status", rs.getString("status"));
                u.put("role_id", rs.getString("role_id"));
                u.put("role_name", rs.getString("role_name"));
                return Optional.of(u);
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return Optional.empty();
    }

    private JSONObject saveUserToDb(String username, String email, String password, UUID roleId, String status) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "INSERT INTO users (username, email, password_hash, role_id, status) VALUES (?, ?, ?, ?, ?) RETURNING user_id";

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, username);
            pstmt.setString(2, email);
            pstmt.setString(3, password);
            pstmt.setObject(4, roleId);
            pstmt.setString(5, status);

            boolean hasResult = pstmt.execute();
            if (hasResult) {
                rs = pstmt.getResultSet();
                if (rs.next()) {
                    String newId = rs.getString("user_id");
                    return new JSONObject() {{ put("success", true); put("user_id", newId); }};
                }
            }
            throw new SQLException("Failed to retrieve generated user ID.");
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }

    private JSONObject updateUserInDb(UUID id, String user, String email, String pass, String role, String status) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            String sql = "UPDATE users SET username = COALESCE(NULLIF(?, ''), username), email = COALESCE(NULLIF(?, ''), email), status = COALESCE(NULLIF(?, ''), status), updated_at = NOW() WHERE user_id = ?";
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, user);
            pstmt.setString(2, email);
            pstmt.setString(3, status);
            pstmt.setObject(4, id);
            pstmt.executeUpdate();
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
        return new JSONObject() {{ put("success", true); put("message", "User updated."); }};
    }

    private void deleteUserFromDb(UUID userId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("DELETE FROM users WHERE user_id = ?");
            pstmt.setObject(1, userId);
            pstmt.executeUpdate();
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
    }

    private JSONArray listRolesFromDb(String search, int page, int limit) throws SQLException {
        JSONArray rolesArray = new JSONArray();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        String sql = "SELECT * FROM roles WHERE (name ILIKE ? OR description ILIKE ?) ORDER BY created_at DESC LIMIT ? OFFSET ?";

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            String filter = (search == null || search.isEmpty()) ? "%%" : "%" + search + "%";
            pstmt.setString(1, filter);
            pstmt.setString(2, filter);
            pstmt.setInt(3, limit);
            pstmt.setInt(4, (page - 1) * limit);
            rs = pstmt.executeQuery();

            while (rs.next()) {
                JSONObject r = new JSONObject();
                r.put("role_id", rs.getString("role_id"));
                r.put("name", rs.getString("name"));
                r.put("description", rs.getString("description"));
                r.put("is_system_role", rs.getBoolean("is_system_role"));
                rolesArray.add(r);
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return rolesArray;
    }

    private Optional<JSONObject> getRoleByIdFromDb(UUID roleId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            
            // 1. Get Role Details
            pstmt = conn.prepareStatement("SELECT * FROM roles WHERE role_id = ?");
            pstmt.setObject(1, roleId);
            rs = pstmt.executeQuery();
            
            if (rs.next()) {
                JSONObject r = new JSONObject();
                r.put("role_id", rs.getString("role_id"));
                r.put("name", rs.getString("name"));
                r.put("description", rs.getString("description"));
                
                // 2. Get Permissions
                rs.close();
                pstmt.close();
                JSONArray perms = new JSONArray();
                pstmt = conn.prepareStatement("SELECT resource, action FROM role_permissions WHERE role_id = ?");
                pstmt.setObject(1, roleId);
                rs = pstmt.executeQuery();
                while (rs.next()) {
                    JSONObject p = new JSONObject();
                    p.put("resource", rs.getString("resource"));
                    p.put("action", rs.getString("action"));
                    perms.add(p);
                }
                r.put("permissions", perms);
                return Optional.of(r);
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return Optional.empty();
    }

    private void deleteRoleFromDb(UUID roleId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            conn.setAutoCommit(false);

            // 1. Verify it's not a system role
            pstmt = conn.prepareStatement("SELECT is_system_role FROM roles WHERE role_id = ?");
            pstmt.setObject(1, roleId);
            ResultSet rs = pstmt.executeQuery();
            if (rs.next() && rs.getBoolean("is_system_role")) {
                throw new IllegalArgumentException("System roles cannot be deleted.");
            }
            rs.close();
            pstmt.close();

            // 2. Delete Permissions
            pstmt = conn.prepareStatement("DELETE FROM role_permissions WHERE role_id = ?");
            pstmt.setObject(1, roleId);
            pstmt.executeUpdate();
            pstmt.close();

            // 3. Delete Role
            pstmt = conn.prepareStatement("DELETE FROM roles WHERE role_id = ?");
            pstmt.setObject(1, roleId);
            int affected = pstmt.executeUpdate();
            if (affected == 0) throw new SQLException("Role not found.");

            conn.commit();
        } catch (SQLException e) {
            if (conn != null) conn.rollback();
            throw e;
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
    }

    private boolean isUsernameOrEmailPresent(String user, String email, UUID exclude) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            String sql = "SELECT COUNT(*) FROM users WHERE (username = ? OR email = ?)";
            if (exclude != null) sql += " AND user_id != ?";
            
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, user);
            pstmt.setString(2, email);
            if (exclude != null) pstmt.setObject(3, exclude);
            
            rs = pstmt.executeQuery();
            return rs.next() && rs.getInt(1) > 0;
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }

    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        return "POST".equalsIgnoreCase(method) && InputProcessor.validate(req, res);
    }
}