package org.tsicoop.dxnode.api.admin;

import org.tsicoop.dxnode.framework.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
// import org.json.simple.JSONArray; // No longer needed as roles are single
import org.json.simple.JSONObject;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.ArrayList; // Still needed if JWTUtil expects List<String> for roles
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public class Login implements REST {

    private final PasswordHasher passwordHasher = new PasswordHasher();

    // All HTTP methods will now defer to the POST method
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
        JSONObject output = null;
        try {
            JSONObject input = InputProcessor.getInput(req);
            String username = (String) input.get("username");
            String password = (String) input.get("password");

            // Basic input validation
            if (username == null || username.trim().isEmpty() ||
                    password == null || password.trim().isEmpty()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required fields (username, password).", req.getRequestURI());
                return;
            }

            // 1. Get user details from DB and validate password
            Optional<JSONObject> userDetailsOptional = getUserDetails(username);

            if (userDetailsOptional.isEmpty()) {
                // User not found. Use a generic message for security (avoid username enumeration).
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized", "Invalid username or password.", req.getRequestURI());
                return;
            }

            JSONObject userDetails = userDetailsOptional.get();
            String storedPasswordHash = (String) userDetails.get("passwordHash");
            String userId = (String) userDetails.get("userId"); // UUID as String
            String userEmail = (String) userDetails.get("email");
            String userStatus = (String) userDetails.get("status");
            String roleName = (String) userDetails.get("roleName"); // Get the single role name

            // Check user status
            if (!"Active".equalsIgnoreCase(userStatus)) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized", "User account is " + userStatus.toLowerCase() + ".", req.getRequestURI());
                return;
            }

            // Validate password
            if (!passwordHasher.checkPassword(password, storedPasswordHash)) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized", "Invalid username or password.", req.getRequestURI());
                return;
            }

            // 2. If valid, update last login time and generate a token
            updateLastLogin(userId); // Update using user_id (UUID)

            // Generate JWT token with user details and the single role
            String generatedToken = JWTUtil.generateToken(userId, username, roleName);

            // 3. Prepare success response
            output = new JSONObject();
            output.put("success", true); // Consistent with API design
            output.put("message", "Login successful");
            output.put("username", username);
            output.put("token", generatedToken);
            output.put("role", roleName); // Return the single role name
            output.put("email", userEmail);
            output.put("user_id", userId);

            OutputProcessor.send(res, HttpServletResponse.SC_OK, output);

        } catch (SQLException e) {
            e.printStackTrace(); // Log the stack trace
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Database Error", "A database error occurred during login: " + e.getMessage(), req.getRequestURI());
        } catch (Exception e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error", "An unexpected error occurred: " + e.getMessage(), req.getRequestURI());
        }
    }

    /**
     * Validates that the request method is POST and performs basic input validation.
     * For login, no JWT validation is performed here as it's the authentication endpoint.
     * @param method The HTTP method of the request.
     * @param req The HttpServletRequest.
     * @param res The HttpServletResponse.
     * @return true if validation passes, false otherwise.
     */
    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        if (!"POST".equalsIgnoreCase(method)) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "Only POST method is supported for admin login.", req.getRequestURI());
            return false;
        }
        // InputProcessor.validate should handle basic request body parsing and content-type checks
        return InputProcessor.validate(req, res);
    }

    /**
     * Retrieves user details including password hash, email, and their single role name.
     * @param username The username to look up.
     * @return An Optional containing a JSONObject with user details if found, otherwise empty.
     * @throws SQLException if a database access error occurs.
     */
    private Optional<JSONObject> getUserDetails(String username) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        // SQL to join users and roles to get the single role name
        String sql = "SELECT u.user_id, u.username, u.password_hash, u.email, u.status, r.name AS role_name " +
                "FROM users u " +
                "JOIN roles r ON u.role_id = r.role_id " +
                "WHERE u.username = ?";

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, username);
            rs = pstmt.executeQuery();

            if (rs.next()) {
                JSONObject user = new JSONObject();
                user.put("userId", rs.getString("user_id")); // Store UUID as String
                user.put("username", rs.getString("username"));
                user.put("passwordHash", rs.getString("password_hash"));
                user.put("email", rs.getString("email"));
                user.put("status", rs.getString("status"));
                user.put("roleName", rs.getString("role_name")); // Get the single role name
                return Optional.of(user);
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return Optional.empty();
    }

    /**
     * Updates the last login timestamp for a user.
     * @param userId The UUID of the user.
     * @throws SQLException if a database access error occurs.
     */
    private void updateLastLogin(String userId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = new PoolDB();
        String sql = "UPDATE users SET last_login_at = ? WHERE user_id = ?";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setTimestamp(1, Timestamp.valueOf(LocalDateTime.now()));
            pstmt.setObject(2, UUID.fromString(userId)); // Set UUID object
            pstmt.executeUpdate();
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
    }
}