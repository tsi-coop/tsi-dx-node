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
import java.util.regex.Pattern;


public class User implements REST {

    private final PasswordHasher passwordHasher = new PasswordHasher();

    // Regex for password complexity (same as in Register class)
    private static final Pattern PASSWORD_PATTERN =
            Pattern.compile("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[!@#$%^&*()_+])[A-Za-z\\d!@#$%^&*()_+]{8,}$");
    private static final Pattern EMAIL_PATTERN =
            Pattern.compile("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,6}$");

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
            UUID userId = null;
            String userIdStr = (String) input.get("user_id");
            if (!userIdStr.isEmpty()) {
                try {
                    userId = UUID.fromString(userIdStr);
                } catch (IllegalArgumentException e) {
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid 'user_id' format.", req.getRequestURI());
                    return;
                }
            }

            UUID roleId = null;
            String roleIdStr = (String) input.get("role_id");
            if (!roleIdStr.isEmpty()) {
                try {
                    roleId = UUID.fromString(roleIdStr);
                } catch (IllegalArgumentException e) {
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid 'role_id' format.", req.getRequestURI());
                    return;
                }
            }

            switch (func.toLowerCase()) {
                // --- User Management ---
                case "list_users":
                    String userStatusFilter = (String) input.get("status");
                    String userSearch = (String) input.get("search");
                    int userPage = (int)(long)input.get("page");
                    int userLimit = (int)(long)input.get("limit");
                    outputArray = listUsersFromDb(userStatusFilter, userSearch, userPage, userLimit);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, outputArray);
                    break;

                case "get_user":
                    if (userId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'user_id' is required for 'get_user' function.", req.getRequestURI());
                        return;
                    }
                    Optional<JSONObject> userOptional = getUserByIdFromDb(userId);
                    if (userOptional.isPresent()) {
                        output = userOptional.get();
                        OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
                    } else {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "User with ID '" + userId + "' not found.", req.getRequestURI());
                    }
                    break;

                case "create_user":
                    String username = (String) input.get("username");
                    String email = (String) input.get("email");
                    String password = (String) input.get("password");
                    String userRoleIdStr = (String) input.get("role_id"); // Required for new user

                    if (username.isEmpty() || email.isEmpty() || password.isEmpty() || userRoleIdStr.isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required fields (username, email, password, role_id) for 'create_user'.", req.getRequestURI());
                        return;
                    }
                    UUID userRoleId = UUID.fromString(userRoleIdStr);

                    String validationError = validateUserInput(username, email, password, password); // Confirm password not needed for create_user here, but validate format
                    if (validationError != null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", validationError, req.getRequestURI());
                        return;
                    }

                    if (isUsernameOrEmailPresent(username, email, null)) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_CONFLICT, "Conflict", "Username or Email already exists.", req.getRequestURI());
                        return;
                    }
                    if (!roleExists(userRoleId)) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Provided role_id does not exist.", req.getRequestURI());
                        return;
                    }

                    String hashedPassword = passwordHasher.hashPassword(password);
                    output = saveUserToDb(username, email, hashedPassword, userRoleId, "Active");
                    OutputProcessor.send(res, HttpServletResponse.SC_CREATED, output);
                    break;

                case "update_user":
                    if (userId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'user_id' is required for 'update_user' function.", req.getRequestURI());
                        return;
                    }
                    if (getUserByIdFromDb(userId).isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "User with ID '" + userId + "' not found.", req.getRequestURI());
                        return;
                    }

                    username = (String) input.get("username");
                    email = (String) input.get("email");
                    password = (String) input.get("password");
                    userRoleIdStr = (String) input.get("role_id");
                    userStatusFilter = (String) input.get("status");

                    if (username.isEmpty() && email.isEmpty() && password.isEmpty() && userRoleIdStr.isEmpty() && userStatusFilter.isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "No fields provided for update for 'update_user'.", req.getRequestURI());
                        return;
                    }

                    if (!password.isEmpty() && !PASSWORD_PATTERN.matcher(password).matches()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "New password does not meet complexity requirements.", req.getRequestURI());
                        return;
                    }
                    if (!email.isEmpty() && !EMAIL_PATTERN.matcher(email).matches()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid email format for update.", req.getRequestURI());
                        return;
                    }

                    if (isUsernameOrEmailPresent(username, email, userId)) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_CONFLICT, "Conflict", "Updated Username or Email conflicts with an existing user.", req.getRequestURI());
                        return;
                    }

                    userRoleId = userRoleIdStr.isEmpty() ? null : UUID.fromString(userRoleIdStr);
                    if (userRoleId != null && !roleExists(userRoleId)) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Provided role_id for update does not exist.", req.getRequestURI());
                        return;
                    }

                    output = updateUserInDb(userId, username, email, password.isEmpty() ? null : passwordHasher.hashPassword(password), userRoleId, userStatusFilter);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
                    break;

                case "delete_user":
                    if (userId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'user_id' is required for 'delete_user' function.", req.getRequestURI());
                        return;
                    }
                    if (getUserByIdFromDb(userId).isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "User with ID '" + userId + "' not found.", req.getRequestURI());
                        return;
                    }
                    deleteUserFromDb(userId);
                    OutputProcessor.send(res, HttpServletResponse.SC_NO_CONTENT, null);
                    break;

                // --- Role Management ---
                case "list_roles":
                    String roleSearch = (String) input.get("search");
                    int rolePage = (int)(long) input.get("page");
                    int roleLimit = (int)(long)input.get("limit");
                    outputArray = listRolesFromDb(roleSearch, rolePage, roleLimit);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, outputArray);
                    break;

                case "get_role":
                    if (roleId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'role_id' is required for 'get_role' function.", req.getRequestURI());
                        return;
                    }
                    Optional<JSONObject> roleOptional = getRoleByIdFromDb(roleId);
                    if (roleOptional.isPresent()) {
                        output = roleOptional.get();
                        OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
                    } else {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Role with ID '" + roleId + "' not found.", req.getRequestURI());
                    }
                    break;

                case "create_role":
                    String roleName = (String)input.get("name");
                    String roleDescription = (String) input.get("description");
                    JSONArray permissionsJson = (JSONArray) input.get("permissions"); // Array of {"resource": "...", "action": "..."}

                    if (roleName.isEmpty() || permissionsJson == null || permissionsJson.isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required fields (name, permissions) for 'create_role'.", req.getRequestURI());
                        return;
                    }
                    if (isRoleNamePresent(roleName, null)) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_CONFLICT, "Conflict", "Role name '" + roleName + "' already exists.", req.getRequestURI());
                        return;
                    }

                    List<JSONObject> permissions = new ArrayList<>();
                    for (Object obj : permissionsJson) {
                        if (obj instanceof JSONObject) {
                            permissions.add((JSONObject) obj);
                        }
                    }

                    output = saveRoleToDb(roleName, roleDescription, permissions);
                    OutputProcessor.send(res, HttpServletResponse.SC_CREATED, output);
                    break;

                case "update_role":
                    if (roleId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'role_id' is required for 'update_role' function.", req.getRequestURI());
                        return;
                    }
                    Optional<JSONObject> existingRole = getRoleByIdFromDb(roleId);
                    if (existingRole.isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Role with ID '" + roleId + "' not found.", req.getRequestURI());
                        return;
                    }
                    /*if ((Boolean) existingRole.get("isSystemRole")) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "System roles cannot be updated.", req.getRequestURI());
                        return;
                    }*/

                    roleName = (String) input.get("name");
                    roleDescription = (String) input.get("description");
                    permissionsJson = (JSONArray) input.get("permissions"); // Optional for update

                    if (roleName.isEmpty() && roleDescription.isEmpty() && permissionsJson == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "No fields provided for update for 'update_role'.", req.getRequestURI());
                        return;
                    }

                    if (!roleName.isEmpty() && isRoleNamePresent(roleName, roleId)) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_CONFLICT, "Conflict", "Role name '" + roleName + "' conflicts with an existing role.", req.getRequestURI());
                        return;
                    }

                    permissions = null;
                    if (permissionsJson != null) {
                        permissions = new ArrayList<>();
                        for (Object obj : permissionsJson) {
                            if (obj instanceof JSONObject) {
                                permissions.add((JSONObject) obj);
                            }
                        }
                    }

                    output = updateRoleInDb(roleId, roleName, roleDescription, permissions);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
                    break;

                case "delete_role":
                    if (roleId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'role_id' is required for 'delete_role' function.", req.getRequestURI());
                        return;
                    }
                    existingRole = getRoleByIdFromDb(roleId);
                    if (existingRole.isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Role with ID '" + roleId + "' not found.", req.getRequestURI());
                        return;
                    }
                    /*if ((Boolean) existingRole.get("isSystemRole")) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "System roles cannot be deleted.", req.getRequestURI());
                        return;
                    }*/
                    if (isRoleAssignedToUsers(roleId)) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_CONFLICT, "Conflict", "Role is currently assigned to one or more users and cannot be deleted.", req.getRequestURI());
                        return;
                    }

                    deleteRoleFromDb(roleId);
                    OutputProcessor.send(res, HttpServletResponse.SC_NO_CONTENT, null);
                    break;

                default:
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Unknown or unsupported '_func' value: " + func, req.getRequestURI());
                    break;
            }

        } catch (SQLException e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Database Error", "A database error occurred: " + e.getMessage(), req.getRequestURI());
        } catch (ParseException e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid JSON input: " + e.getMessage(), req.getRequestURI());
        } catch (IllegalArgumentException e) {
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
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "Only POST method is supported for User & Role Management operations.", req.getRequestURI());
            return false;
        }
        return InputProcessor.validate(req, res); // This validates content-type and basic body parsing
    }

    // --- Helper Methods for User Management ---

    /**
     * Validates the input for user creation/update.
     * @return null if valid, otherwise an error message.
     */
    private String validateUserInput(String username, String email, String password, String confirmPassword) {
        if (username.length() < 3 || username.length() > 50) {
            return "Username must be between 3 and 50 characters.";
        }
        if (!EMAIL_PATTERN.matcher(email).matches()) {
            return "Invalid email format.";
        }
        if (!password.equals(confirmPassword)) { // For create, confirmPassword would be same as password
            return "Passwords do not match.";
        }
        if (!PASSWORD_PATTERN.matcher(password).matches()) {
            return "Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one digit, and one special character.";
        }
        return null; // Input is valid
    }

    /**
     * Checks if a username or email already exists (for uniqueness).
     * @param username The username to check.
     * @param email The email to check.
     * @param excludeUserId Optional UUID to exclude from the check (for update operations).
     * @return true if a conflict is found, false otherwise.
     * @throws SQLException if a database access error occurs.
     */
    private boolean isUsernameOrEmailPresent(String username, String email, UUID excludeUserId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        StringBuilder sqlBuilder = new StringBuilder("SELECT COUNT(*) FROM users WHERE (username = ? OR email = ?)");
        List<Object> params = new ArrayList<>();
        params.add(username);
        params.add(email);

        if (excludeUserId != null) {
            sqlBuilder.append(" AND user_id != ?");
            params.add(excludeUserId);
        }

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sqlBuilder.toString());
            for (int i = 0; i < params.size(); i++) {
                pstmt.setObject(i + 1, params.get(i));
            }
            rs = pstmt.executeQuery();
            return rs.next() && rs.getInt(1) > 0;
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }

    /**
     * Helper to check if a role exists by ID.
     */
    private boolean roleExists(UUID roleId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "SELECT COUNT(*) FROM roles WHERE role_id = ?";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, roleId);
            rs = pstmt.executeQuery();
            return rs.next() && rs.getInt(1) > 0;
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }

    /**
     * Retrieves a list of users from the database with optional filtering and pagination.
     * @return JSONArray of user JSONObjects.
     * @throws SQLException if a database access error occurs.
     */
    private JSONArray listUsersFromDb(String statusFilter, String search, int page, int limit) throws SQLException {
        JSONArray usersArray = new JSONArray();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        StringBuilder sqlBuilder = new StringBuilder("SELECT u.user_id, u.username, u.email, u.status, u.last_login_at, u.created_at, u.updated_at, r.name AS role_name FROM users u JOIN roles r ON u.role_id = r.role_id WHERE 1=1");
        List<Object> params = new ArrayList<>();

        if (statusFilter != null && !statusFilter.isEmpty()) {
            sqlBuilder.append(" AND u.status = ?");
            params.add(statusFilter);
        }
        if (search != null && !search.isEmpty()) {
            sqlBuilder.append(" AND (u.username ILIKE ? OR u.email ILIKE ?)");
            params.add("%" + search + "%");
            params.add("%" + search + "%");
        }

        sqlBuilder.append(" ORDER BY u.created_at DESC LIMIT ? OFFSET ?");
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
                JSONObject user = new JSONObject();
                user.put("user_id", rs.getString("user_id"));
                user.put("username", rs.getString("username"));
                user.put("email", rs.getString("email"));
                user.put("status", rs.getString("status"));
                user.put("role", rs.getString("role_name")); // Single role name
                user.put("last_login_at", rs.getTimestamp("last_login_at") != null ? rs.getTimestamp("last_login_at").toInstant().toString() : null);
                user.put("created_at", rs.getTimestamp("created_at").toInstant().toString());
                user.put("updated_at", rs.getTimestamp("updated_at").toInstant().toString());
                usersArray.add(user);
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return usersArray;
    }

    /**
     * Retrieves a single user by ID from the database.
     * @param userId The UUID of the user.
     * @return An Optional containing the user JSONObject if found, otherwise empty.
     * @throws SQLException if a database access error occurs.
     */
    private Optional<JSONObject> getUserByIdFromDb(UUID userId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "SELECT u.user_id, u.username, u.email, u.password_hash, u.status, u.last_login_at, u.created_at, u.updated_at, r.role_id, r.name AS role_name FROM users u JOIN roles r ON u.role_id = r.role_id WHERE u.user_id = ?";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, userId);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                JSONObject user = new JSONObject();
                user.put("user_id", rs.getString("user_id"));
                user.put("username", rs.getString("username"));
                user.put("email", rs.getString("email"));
                user.put("password_hash", rs.getString("password_hash")); // Include for internal use, but be careful with API exposure
                user.put("status", rs.getString("status"));
                user.put("role_id", rs.getString("role_id"));
                user.put("role_name", rs.getString("role_name"));
                user.put("last_login_at", rs.getTimestamp("last_login_at") != null ? rs.getTimestamp("last_login_at").toInstant().toString() : null);
                user.put("created_at", rs.getTimestamp("created_at").toInstant().toString());
                user.put("updated_at", rs.getTimestamp("updated_at").toInstant().toString());
                return Optional.of(user);
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return Optional.empty();
    }

    /**
     * Saves a new user to the database.
     * @return JSONObject containing the new user's details.
     * @throws SQLException if a database access error occurs.
     */
    private JSONObject saveUserToDb(String username, String email, String hashedPassword, UUID roleId, String status) throws SQLException {
        JSONObject output = new JSONObject();
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
            pstmt.setString(3, hashedPassword);
            pstmt.setObject(4, roleId);
            pstmt.setString(5, status);

            int affectedRows = pstmt.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Creating user failed, no rows affected.");
            }

            rs = pstmt.getGeneratedKeys();
            if (rs.next()) {
                String userId = rs.getString("user_id");
                output.put("user_id", userId);
                output.put("username", username);
                output.put("email", email);
                output.put("status", status);
                output.put("role_id", roleId.toString());
                output.put("message", "User created successfully.");
            } else {
                throw new SQLException("Creating user failed, no ID obtained.");
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return new JSONObject() {{ put("success", true); put("data", output); }};
    }

    /**
     * Updates an existing user in the database.
     * @return JSONObject indicating success.
     * @throws SQLException if a database access error occurs.
     */
    private JSONObject updateUserInDb(UUID userId, String username, String email, String hashedPassword, UUID roleId, String status) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = new PoolDB();

        StringBuilder sqlBuilder = new StringBuilder("UPDATE users SET updated_at = NOW()");
        List<Object> params = new ArrayList<>();

        if (username != null && !username.isEmpty()) { sqlBuilder.append(", username = ?"); params.add(username); }
        if (email != null && !email.isEmpty()) { sqlBuilder.append(", email = ?"); params.add(email); }
        if (hashedPassword != null && !hashedPassword.isEmpty()) { sqlBuilder.append(", password_hash = ?"); params.add(hashedPassword); }
        if (roleId != null) { sqlBuilder.append(", role_id = ?"); params.add(roleId); }
        if (status != null && !status.isEmpty()) { sqlBuilder.append(", status = ?"); params.add(status); }

        sqlBuilder.append(" WHERE user_id = ?");
        params.add(userId);

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sqlBuilder.toString());
            for (int i = 0; i < params.size(); i++) {
                pstmt.setObject(i + 1, params.get(i));
            }

            int affectedRows = pstmt.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Updating user failed, user not found or no changes made.");
            }
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
        return new JSONObject() {{ put("success", true); put("message", "User updated successfully."); }};
    }

    /**
     * Deletes a user from the database.
     * @param userId The UUID of the user to delete.
     * @throws SQLException if a database access error occurs.
     */
    private void deleteUserFromDb(UUID userId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = new PoolDB();
        String sql = "DELETE FROM users WHERE user_id = ?";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, userId);
            int affectedRows = pstmt.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Deleting user failed, user not found.");
            }
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
    }

    // --- Helper Methods for Role Management ---

    /**
     * Checks if a role name already exists (for uniqueness).
     * @param roleName The role name to check.
     * @param excludeRoleId Optional UUID to exclude from the check (for update operations).
     * @return true if a conflict is found, false otherwise.
     * @throws SQLException if a database access error occurs.
     */
    private boolean isRoleNamePresent(String roleName, UUID excludeRoleId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        StringBuilder sqlBuilder = new StringBuilder("SELECT COUNT(*) FROM roles WHERE name = ?");
        List<Object> params = new ArrayList<>();
        params.add(roleName);

        if (excludeRoleId != null) {
            sqlBuilder.append(" AND role_id != ?");
            params.add(excludeRoleId);
        }

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sqlBuilder.toString());
            for (int i = 0; i < params.size(); i++) {
                pstmt.setObject(i + 1, params.get(i));
            }
            rs = pstmt.executeQuery();
            return rs.next() && rs.getInt(1) > 0;
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }

    /**
     * Checks if a role is currently assigned to any users.
     * @param roleId The UUID of the role to check.
     * @return true if the role is assigned to users, false otherwise.
     * @throws SQLException if a database access error occurs.
     */
    private boolean isRoleAssignedToUsers(UUID roleId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "SELECT COUNT(*) FROM users WHERE role_id = ?";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, roleId);
            rs = pstmt.executeQuery();
            return rs.next() && rs.getInt(1) > 0;
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }

    /**
     * Retrieves a list of roles from the database with optional filtering and pagination.
     * @return JSONArray of role JSONObjects.
     * @throws SQLException if a database access error occurs.
     */
    private JSONArray listRolesFromDb(String search, int page, int limit) throws SQLException {
        JSONArray rolesArray = new JSONArray();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        StringBuilder sqlBuilder = new StringBuilder("SELECT role_id, name, description, is_system_role, created_at, updated_at FROM roles WHERE 1=1");
        List<Object> params = new ArrayList<>();

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
                JSONObject role = new JSONObject();
                role.put("role_id", rs.getString("role_id"));
                role.put("name", rs.getString("name"));
                role.put("description", rs.getString("description"));
                role.put("is_system_role", rs.getBoolean("is_system_role"));
                role.put("created_at", rs.getTimestamp("created_at").toInstant().toString());
                role.put("updated_at", rs.getTimestamp("updated_at").toInstant().toString());
                rolesArray.add(role);
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return rolesArray;
    }

    /**
     * Retrieves a single role by ID from the database, including its permissions.
     * @param roleId The UUID of the role.
     * @return An Optional containing the role JSONObject if found, otherwise empty.
     * @throws SQLException if a database access error occurs.
     */
    private Optional<JSONObject> getRoleByIdFromDb(UUID roleId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmtRole = null;
        PreparedStatement pstmtPermissions = null;
        ResultSet rsRole = null;
        ResultSet rsPermissions = null;
        PoolDB pool = new PoolDB();

        String sqlRole = "SELECT role_id, name, description, is_system_role, created_at, updated_at FROM roles WHERE role_id = ?";
        String sqlPermissions = "SELECT resource, action FROM role_permissions WHERE role_id = ?";

        try {
            conn = pool.getConnection();
            pstmtRole = conn.prepareStatement(sqlRole);
            pstmtRole.setObject(1, roleId);
            rsRole = pstmtRole.executeQuery();

            if (rsRole.next()) {
                JSONObject role = new JSONObject();
                role.put("role_id", rsRole.getString("role_id"));
                role.put("name", rsRole.getString("name"));
                role.put("description", rsRole.getString("description"));
                role.put("is_system_role", rsRole.getBoolean("is_system_role"));
                role.put("created_at", rsRole.getTimestamp("created_at").toInstant().toString());
                role.put("updated_at", rsRole.getTimestamp("updated_at").toInstant().toString());

                // Get permissions for this role
                JSONArray permissionsArray = new JSONArray();
                pstmtPermissions = conn.prepareStatement(sqlPermissions);
                pstmtPermissions.setObject(1, roleId);
                rsPermissions = pstmtPermissions.executeQuery();
                while (rsPermissions.next()) {
                    JSONObject permission = new JSONObject();
                    permission.put("resource", rsPermissions.getString("resource"));
                    permission.put("action", rsPermissions.getString("action"));
                    permissionsArray.add(permission);
                }
                role.put("permissions", permissionsArray);
                return Optional.of(role);
            }
        } finally {
            pool.cleanup(rsRole, pstmtRole, null);
            pool.cleanup(rsPermissions, pstmtPermissions, conn);
        }
        return Optional.empty();
    }

    /**
     * Saves a new role and its permissions to the database in a transaction.
     * @param name The name of the role.
     * @param description The description of the role.
     * @param permissions List of permission JSONObjects (resource, action).
     * @return JSONObject containing the new role's details.
     * @throws SQLException if a database access error occurs.
     */
    private JSONObject saveRoleToDb(String name, String description, List<JSONObject> permissions) throws SQLException {
        JSONObject output = new JSONObject();
        Connection conn = null;
        PreparedStatement pstmtRole = null;
        PreparedStatement pstmtPermission = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        String insertRoleSql = "INSERT INTO roles (name, description, is_system_role) VALUES (?, ?, ?) RETURNING role_id";
        String insertPermissionSql = "INSERT INTO role_permissions (role_id, resource, action) VALUES (?, ?, ?)";

        try {
            conn = pool.getConnection();
            conn.setAutoCommit(false); // Start transaction

            // Insert into roles table
            pstmtRole = conn.prepareStatement(insertRoleSql);
            pstmtRole.setString(1, name);
            pstmtRole.setString(2, description);
            pstmtRole.setBoolean(3, false); // Custom roles are not system roles

            int affectedRows = pstmtRole.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Creating role failed, no rows affected.");
            }

            rs = pstmtRole.getGeneratedKeys();
            UUID newRoleId;
            if (rs.next()) {
                newRoleId = UUID.fromString(rs.getString(1));
                output.put("role_id", newRoleId.toString());
                output.put("name", name);
                output.put("message", "Role created successfully.");
            } else {
                throw new SQLException("Creating role failed, no ID obtained.");
            }

            // Assign permissions
            for (JSONObject perm : permissions) {
                pstmtPermission = conn.prepareStatement(insertPermissionSql);
                pstmtPermission.setObject(1, newRoleId);
                pstmtPermission.setString(2, (String) perm.get("resource"));
                pstmtPermission.setString(3, (String) perm.get("action"));
                pstmtPermission.executeUpdate();
            }

            conn.commit(); // Commit transaction

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
            pool.cleanup(rs, pstmtRole, null);
            pool.cleanup(null, pstmtPermission, conn);
        }
        return new JSONObject() {{ put("success", true); put("data", output); }};
    }

    /**
     * Updates an existing role and its permissions in the database in a transaction.
     * @return JSONObject indicating success.
     * @throws SQLException if a database access error occurs.
     */
    private JSONObject updateRoleInDb(UUID roleId, String name, String description, List<JSONObject> permissions) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmtRole = null;
        PreparedStatement pstmtDeletePermissions = null;
        PreparedStatement pstmtInsertPermission = null;
        PoolDB pool = new PoolDB();

        StringBuilder sqlBuilder = new StringBuilder("UPDATE roles SET updated_at = NOW()");
        List<Object> params = new ArrayList<>();

        if (name != null && !name.isEmpty()) { sqlBuilder.append(", name = ?"); params.add(name); }
        if (description != null && !description.isEmpty()) { sqlBuilder.append(", description = ?"); params.add(description); }

        sqlBuilder.append(" WHERE role_id = ?");
        params.add(roleId);

        try {
            conn = pool.getConnection();
            conn.setAutoCommit(false); // Start transaction

            // Update role details
            pstmtRole = conn.prepareStatement(sqlBuilder.toString());
            for (int i = 0; i < params.size(); i++) {
                pstmtRole.setObject(i + 1, params.get(i));
            }
            int affectedRows = pstmtRole.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Updating role failed, role not found or no changes made to role details.");
            }

            // Update permissions if provided
            if (permissions != null) {
                // Delete existing permissions for the role
                String deletePermissionsSql = "DELETE FROM role_permissions WHERE role_id = ?";
                pstmtDeletePermissions = conn.prepareStatement(deletePermissionsSql);
                pstmtDeletePermissions.setObject(1, roleId);
                pstmtDeletePermissions.executeUpdate();

                // Insert new permissions
                String insertPermissionSql = "INSERT INTO role_permissions (role_id, resource, action) VALUES (?, ?, ?)";
                pstmtInsertPermission = conn.prepareStatement(insertPermissionSql);
                for (JSONObject perm : permissions) {
                    pstmtInsertPermission.setObject(1, roleId);
                    pstmtInsertPermission.setString(2, (String) perm.get("resource"));
                    pstmtInsertPermission.setString(3, (String) perm.get("action"));
                    pstmtInsertPermission.addBatch(); // Add to batch for efficiency
                }
                pstmtInsertPermission.executeBatch(); // Execute all batched inserts
            }

            conn.commit(); // Commit transaction

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
            pool.cleanup(null, pstmtRole, null);
            pool.cleanup(null, pstmtDeletePermissions, null);
            pool.cleanup(null, pstmtInsertPermission, conn);
        }
        return new JSONObject() {{ put("success", true); put("message", "Role updated successfully."); }};
    }

    /**
     * Deletes a role from the database, including its permissions, in a transaction.
     * @param roleId The UUID of the role to delete.
     * @throws SQLException if a database access error occurs.
     */
    private void deleteRoleFromDb(UUID roleId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmtDeletePermissions = null;
        PreparedStatement pstmtDeleteRole = null;
        PoolDB pool = new PoolDB();

        String deletePermissionsSql = "DELETE FROM role_permissions WHERE role_id = ?";
        String deleteRoleSql = "DELETE FROM roles WHERE role_id = ?";

        try {
            conn = pool.getConnection();
            conn.setAutoCommit(false); // Start transaction

            // Delete associated permissions first
            pstmtDeletePermissions = conn.prepareStatement(deletePermissionsSql);
            pstmtDeletePermissions.setObject(1, roleId);
            pstmtDeletePermissions.executeUpdate();

            // Then delete the role itself
            pstmtDeleteRole = conn.prepareStatement(deleteRoleSql);
            pstmtDeleteRole.setObject(1, roleId);
            int affectedRows = pstmtDeleteRole.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Deleting role failed, role not found.");
            }

            conn.commit(); // Commit transaction

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
            pool.cleanup(null, pstmtDeletePermissions, null);
            pool.cleanup(null, pstmtDeleteRole, conn);
        }
    }
}