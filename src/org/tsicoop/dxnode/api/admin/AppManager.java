package org.tsicoop.dxnode.api.admin;

import org.tsicoop.dxnode.framework.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import java.security.SecureRandom;
import java.sql.*;
import java.util.Base64;
import java.util.UUID;

/**
 * Service to manage Application Registration and API Keys.
 * REVISED: Standardized on 200 OK for deletions to prevent protocol-level hangs.
 * Enforces one-time visibility for API Secrets with secure SHA-256 hashing.
 */
public class AppManager implements REST {

    private final PasswordHasher passwordHasher = new PasswordHasher();
    private static final String KEY_PREFIX = "dx_";
    private static final int KEY_LENGTH = 24;
    private static final int SECRET_LENGTH = 32;

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        try {
            JSONObject input = InputProcessor.getInput(req);
            String func = (input != null) ? (String) input.get("_func") : null;

            System.out.println("[AppManager DEBUG] Received POST request. Func: " + func);

            if (func == null || func.trim().isEmpty()) {
                OutputProcessor.errorResponse(res, 400, "Bad Request", "Missing '_func' identifier.", req.getRequestURI());
                return;
            }

            switch (func.toLowerCase()) {
                case "list_apps":
                    OutputProcessor.send(res, 200, listAppsFromDb());
                    break;
                    
                case "create_app":
                    OutputProcessor.send(res, 201, createApp(input, req));
                    break;
                    
                case "delete_app":
                    System.out.println("[AppManager DEBUG] Invoking delete_app sequence...");
                    deleteApp(extractUuid(input, "id"), req);
                    System.out.println("[AppManager DEBUG] delete_app sequence completed. Dispatching 200 OK response...");
                    
                    // REVISED: Using 200 OK instead of 204 to ensure the connection is closed with a valid body
                    JSONObject deleteSuccess = new JSONObject();
                    deleteSuccess.put("success", true);
                    deleteSuccess.put("message", "Application and keys successfully purged.");
                    
                    OutputProcessor.send(res, 200, deleteSuccess);
                    System.out.println("[AppManager DEBUG] Response dispatched to OutputProcessor.");
                    break;
                    
                case "generate_api_key":
                    OutputProcessor.send(res, 201, generateApiKey(extractUuid(input, "app_id"), req));
                    break;
                    
                default:
                    OutputProcessor.errorResponse(res, 400, "Bad Request", "Unknown function: " + func, req.getRequestURI());
            }
        } catch (SQLException sqle) {
            System.err.println("[AppManager ERROR] Database Protocol Violation!");
            System.err.println("SQL State: " + sqle.getSQLState());
            System.err.println("Error Code: " + sqle.getErrorCode());
            System.err.println("Message: " + sqle.getMessage());
            
            OutputProcessor.errorResponse(res, 500, "Database Sync Failure", 
                "DB Error [" + sqle.getSQLState() + "]: " + sqle.getMessage(), req.getRequestURI());
        } catch (Exception e) {
            System.err.println("[AppManager ERROR] Generic Exception: " + e.getMessage());
            e.printStackTrace();
            OutputProcessor.errorResponse(res, 500, "Internal Service Error", e.getMessage(), req.getRequestURI());
        }
        
        System.out.println("[AppManager DEBUG] Post-processing request lifecycle ended.");
    }

    private JSONArray listAppsFromDb() throws SQLException {
        JSONArray arr = new JSONArray();
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("SELECT id, name, description, status, created_at FROM apps ORDER BY created_at DESC");
            rs = pstmt.executeQuery();
            while (rs.next()) {
                JSONObject app = new JSONObject();
                app.put("id", rs.getString("id"));
                app.put("name", rs.getString("name"));
                app.put("description", rs.getString("description"));
                app.put("status", rs.getString("status"));
                app.put("created_at", rs.getTimestamp("created_at").toString());
                arr.add(app);
            }
        } finally { pool.cleanup(rs, pstmt, conn); }
        return arr;
    }

    private JSONObject createApp(JSONObject input, HttpServletRequest req) throws SQLException {
        Connection conn = null; PreparedStatement pstmt = null; PoolDB pool = new PoolDB();
        UUID id = UUID.randomUUID();
        String name = (String) input.get("name");
        try {
            conn = pool.getConnection();
            conn.setAutoCommit(false);
            
            pstmt = conn.prepareStatement("INSERT INTO apps (id, name, description, status) VALUES (?, ?, ?, 'ACTIVE')");
            pstmt.setObject(1, id);
            pstmt.setString(2, name);
            pstmt.setString(3, (String) input.get("description"));
            pstmt.executeUpdate();

            logAudit(conn, "APP_CREATED", id, InputProcessor.getEmail(req), "Application '" + name + "' registered.", req);
            
            conn.commit();
            return new JSONObject() {{ put("success", true); put("id", id.toString()); }};
        } catch (SQLException e) {
            if (conn != null) conn.rollback();
            throw e;
        } finally { pool.cleanup(null, pstmt, conn); }
    }

    private JSONObject generateApiKey(UUID appId, HttpServletRequest req) throws Exception {
        if (appId == null) throw new IllegalArgumentException("Target app_id is required.");
        
        String rawKey = KEY_PREFIX + generateSecureString(KEY_LENGTH);
        String rawSecret = generateSecureString(SECRET_LENGTH);
        String hashedSecret = passwordHasher.hashPassword(rawSecret);

        Connection conn = null; PreparedStatement pstmt = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            conn.setAutoCommit(false);

            pstmt = conn.prepareStatement("INSERT INTO api_keys (key_id, api_key, api_secret_hash, app_id, status) VALUES (?, ?, ?, ?, 'Active')");
            pstmt.setObject(1, UUID.randomUUID());
            pstmt.setString(2, rawKey);
            pstmt.setString(3, hashedSecret);
            pstmt.setObject(4, appId);
            pstmt.executeUpdate();

            logAudit(conn, "API_KEY_GENERATED", appId, InputProcessor.getEmail(req), "New Client API access key issued.", req);

            conn.commit();

            JSONObject out = new JSONObject();
            out.put("success", true);
            out.put("api_key", rawKey);
            out.put("api_secret", rawSecret);
            return out;
        } catch (SQLException e) {
            if (conn != null) conn.rollback();
            throw e;
        } finally { pool.cleanup(null, pstmt, conn); }
    }

    private void deleteApp(UUID appId, HttpServletRequest req) throws SQLException {
        System.out.println("[AppManager DEBUG] deleteApp started for UUID: " + appId);
        Connection conn = null; 
        PreparedStatement pstmt = null; 
        PoolDB pool = new PoolDB();
        
        try {
            conn = pool.getConnection();
            conn.setAutoCommit(false);

            System.out.println("[AppManager DEBUG] Executing DELETE statement on 'apps' table...");
            pstmt = conn.prepareStatement("DELETE FROM apps WHERE id = ?");
            pstmt.setObject(1, appId);
            int rows = pstmt.executeUpdate();
            System.out.println("[AppManager DEBUG] DELETE executed. Rows affected: " + rows);

            logAudit(conn, "APP_DELETED", appId, InputProcessor.getEmail(req), "Application purged from node registry.", req);
            
            System.out.println("[AppManager DEBUG] Attempting final COMMIT...");
            conn.commit();
            System.out.println("[AppManager DEBUG] COMMIT successful.");
            
        } catch (SQLException e) {
            System.err.println("[AppManager DEBUG] deleteApp encountered SQLException: " + e.getMessage());
            if (conn != null) {
                try { conn.rollback(); } catch (SQLException ex) { /* Silent */ }
            }
            throw e; 
        } finally { 
            pool.cleanup(null, pstmt, conn); 
        }
    }

    private String generateSecureString(int length) {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes).substring(0, length);
    }

    private void logAudit(Connection conn, String type, UUID entityId, String actor, String note, HttpServletRequest req) throws SQLException {
        String sql = "INSERT INTO audit_logs (log_id, timestamp, event_type, severity, actor_type, actor_id, entity_type, entity_id, details, origin_ip) " +
                     "VALUES (?, NOW(), ?, 'INFO', 'USER', ?, 'APP', ?, ?::jsonb, ?::inet)";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setObject(1, UUID.randomUUID());
            ps.setString(2, type);
            ps.setString(3, (actor == null || actor.isEmpty()) ? "SYSTEM" : actor);
            ps.setObject(4, entityId);
            JSONObject d = new JSONObject(); d.put("note", note);
            ps.setString(5, d.toJSONString());
            ps.setString(6, req.getRemoteAddr());
            ps.executeUpdate();
        }
    }

    private UUID extractUuid(JSONObject obj, String key) { 
        Object v = obj.get(key); 
        if (v == null || v.toString().trim().isEmpty()) return null; 
        try { return UUID.fromString(v.toString().trim()); } catch (Exception e) { return null; }
    }

    @Override public boolean validate(String m, HttpServletRequest req, HttpServletResponse res) { return InputProcessor.validate(req, res); }
    @Override public void get(HttpServletRequest req, HttpServletResponse res) {}
    @Override public void put(HttpServletRequest req, HttpServletResponse res) {}
    @Override public void delete(HttpServletRequest req, HttpServletResponse res) {}
}