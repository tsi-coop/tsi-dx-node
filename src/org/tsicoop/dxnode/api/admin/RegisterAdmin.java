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


public class RegisterAdmin implements REST {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final PasswordHasher passwordHasher = new PasswordHasher(); // Assuming this handles secure hashing (e.g., bcrypt)

    // Regex for password complexity: At least 8 chars, 1 uppercase, 1 lowercase, 1 digit, 1 special char
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
            // 1. Check if the node has already been initialized with an administrator
            if (isNodeInitialized()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_CONFLICT, "Conflict", "The TSI DX Node has already been initialized with an administrator. Please use the login endpoint or contact an existing administrator for user management.", req.getRequestURI());
                return;
            }

            input = InputProcessor.getInput(req);

            String username = (String) input.get("username");
            String email = (String) input.get("email");
            String password = (String) input.get("password");
            String confirmPassword = (String) input.get("confirm_password");
            // The 'role' attribute from input in the original template is not strictly needed here
            // as this endpoint *always* registers an 'Administrator'.

            // 2. Input Validation
            String validationError = validateRegistrationInput(username, email, password, confirmPassword);
            if (validationError != null) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", validationError, req.getRequestURI());
                return;
            }

            // 3. Hash the password
            String hashedPassword = passwordHasher.hashPassword(password);

            // 4. Get the 'Administrator' role ID
            UUID adminRoleId = getRoleId("Administrator");
            if (adminRoleId == null) {
                // This indicates a critical setup error (e.g., init.sql didn't create the role)
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error", "Administrator role not found. Node setup is incomplete.", req.getRequestURI());
                return;
            }

            // 5. Save the new admin user with the Administrator role
            output = saveAdminUser(username, email, hashedPassword, adminRoleId);

            // 6. Return success response
            OutputProcessor.send(res, HttpServletResponse.SC_CREATED, output); // Use SC_CREATED for successful resource creation

        } catch (SQLException e) {
            e.printStackTrace(); // Log the stack trace
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Database Error", "A database error occurred during login: " + e.getMessage(), req.getRequestURI());
        } catch (Exception e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error", "An unexpected error occurred: " + e.getMessage(), req.getRequestURI());
        }
    }

    @Override
    public void delete(HttpServletRequest req, HttpServletResponse res) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "DELETE method not supported for this resource.", req.getRequestURI());
    }

    @Override
    public void put(HttpServletRequest req, HttpServletResponse res) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "PUT method not supported for this resource.", req.getRequestURI());
    }

    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        // For the Register endpoint, validation typically happens within the post method
        // as authentication is not required for the first call.
        // If there were other validation concerns (e.g., IP whitelisting), it could go here.
        return true; // Allow processing by the post method
    }

    /**
     * Validates the input for administrator registration.
     * @return null if valid, otherwise an error message.
     */
    private String validateRegistrationInput(String username, String email, String password, String confirmPassword) {
        if (username.isEmpty() || email.isEmpty() || password.isEmpty() || confirmPassword.isEmpty()) {
            return "Missing required fields (username, email, password, confirm_password).";
        }
        if (username.length() < 3 || username.length() > 50) {
            return "Username must be between 3 and 50 characters.";
        }
        if (!EMAIL_PATTERN.matcher(email).matches()) {
            return "Invalid email format.";
        }
        if (!password.equals(confirmPassword)) {
            return "Passwords do not match.";
        }
        if (!PASSWORD_PATTERN.matcher(password).matches()) {
            return "Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one digit, and one special character.";
        }
        return null; // Input is valid
    }

    /**
     * Checks if any user (indicating node initialization) is present in the database.
     * This is crucial for the single-use nature of the /admin/register endpoint.
     * @return true if at least one user exists, false otherwise.
     * @throws SQLException if a database access error occurs.
     */
    private boolean isNodeInitialized() throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "SELECT COUNT(*) FROM users"; // Check for any user
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            rs = pstmt.executeQuery();
            if (rs.next() && rs.getInt(1) > 0) {
                return true; // At least one user exists
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return false;
    }

    /**
     * Retrieves the UUID of a role by its name.
     * @param roleName The name of the role (e.g., "Administrator").
     * @return The UUID of the role, or null if not found.
     * @throws SQLException if a database access error occurs.
     */
    private UUID getRoleId(String roleName) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "SELECT role_id FROM roles WHERE name = ?";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, roleName);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                return UUID.fromString(rs.getString("role_id"));
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return null;
    }

    /**
     * Saves the new administrator user and assigns the Administrator role.
     * This method is now simplified as 'role_id' is directly in the 'users' table.
     * @param username The username for the new admin.
     * @param email The email for the new admin.
     * @param hashedPassword The securely hashed password.
     * @param adminRoleId The UUID of the Administrator role to assign.
     * @return A JSONObject containing the new user's ID.
     * @throws SQLException if a database access error occurs.
     */
    private JSONObject saveAdminUser(String username, String email, String hashedPassword, UUID adminRoleId) throws SQLException {
        JSONObject output = new JSONObject();
        Connection conn = null;
        PreparedStatement pstmtUser = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        // Modified SQL: Include role_id directly in the users table insert
        String insertUserSql = "INSERT INTO users (username, email, password_hash, role_id, status) VALUES (?, ?, ?, ?, ?) RETURNING user_id";

        try {
            conn = pool.getConnection();
            conn.setAutoCommit(false); // Start transaction

            // Insert into users table
            pstmtUser = conn.prepareStatement(insertUserSql);
            pstmtUser.setString(1, username);
            pstmtUser.setString(2, email);
            pstmtUser.setString(3, hashedPassword);
            pstmtUser.setObject(4, adminRoleId); // Set the UUID for role_id
            pstmtUser.setString(5, "Active"); // Default status for new admin user

            int affectedRows = pstmtUser.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Creating user failed, no rows affected.");
            }

            // Get the generated user_id
            rs = pstmtUser.getGeneratedKeys();
            UUID newUserId;
            if (rs.next()) {
                newUserId = UUID.fromString(rs.getString(1));
                output.put("user_id", newUserId.toString());
                output.put("username", username);
                output.put("email", email);
            } else {
                throw new SQLException("Creating user failed, no ID obtained.");
            }

            conn.commit(); // Commit transaction

            output.put("success", true); // Consistent with API design
            output.put("message", "Initial administrator registered successfully.");

        } catch (SQLException e) {
            if (conn != null) {
                try {
                    conn.rollback(); // Rollback transaction on error
                } catch (SQLException ex) {
                    ex.printStackTrace();
                }
            }
            throw e; // Re-throw the exception
        } finally {
            pool.cleanup(rs, pstmtUser, conn); // conn is cleaned up last
        }
        return output;
    }
}