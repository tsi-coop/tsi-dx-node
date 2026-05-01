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
 * Service to manage Application Registration, API Keys, and Contract-level RBAC.
 * REVISED: Implements App-to-Contract authorization mapping.
 * Enforces one-time visibility for API Secrets with secure SHA-256 hashing.
 * Standardized on 200 OK responses with JSON bodies to ensure frontend stability.
 */
public class AppManager implements Action {

    private final PasswordHasher passwordHasher = new PasswordHasher();
    private static final String KEY_PREFIX = "dx_";
    private static final int KEY_LENGTH = 24;
    private static final int SECRET_LENGTH = 32;

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        try {
            JSONObject input = InputProcessor.getInput(req);
            String func = (input != null) ? (String) input.get("_func") : null;

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
                    deleteApp(extractUuid(input, "id"), req);
                    // Return 200 with JSON to avoid frontend parse errors on empty 204 bodies
                    JSONObject deleteSuccess = new JSONObject();
                    deleteSuccess.put("success", true);
                    deleteSuccess.put("message", "Application and associated authorizations purged.");
                    OutputProcessor.send(res, 200, deleteSuccess);
                    break;
                    
                case "generate_api_key":
                    OutputProcessor.send(res, 201, generateApiKey(extractUuid(input, "app_id"), req));
                    break;
                    
                default:
                    OutputProcessor.errorResponse(res, 400, "Bad Request", "Unknown function: " + func, req.getRequestURI());
            }
        } catch (SQLException sqle) {
            System.err.println("[AppManager ERROR] Database Protocol Violation: " + sqle.getMessage());
            OutputProcessor.errorResponse(res, 500, "Database Sync Failure", 
                "DB Error [" + sqle.getSQLState() + "]: " + sqle.getMessage(), req.getRequestURI());
        } catch (Exception e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, 500, "Internal Service Error", e.getMessage(), req.getRequestURI());
        }
    }

    /**
     * Retrieves the application registry.
     * Uses a JSON aggregation subquery to fetch names of authorized contracts.
     */
    private JSONArray listAppsFromDb() throws SQLException {
        JSONArray arr = new JSONArray();
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            String sql = "SELECT a.id, a.name, a.description, a.status, a.created_at, " +
                         "(SELECT json_agg(c.name) FROM app_contracts ac " +
                         " JOIN data_contracts c ON ac.contract_id = c.contract_id " +
                         " WHERE ac.app_id = a.id) as authorized_contracts " +
                         "FROM apps a ORDER BY a.created_at DESC";
            
            pstmt = conn.prepareStatement(sql);
            rs = pstmt.executeQuery();
            while (rs.next()) {
                JSONObject app = new JSONObject();
                app.put("id", rs.getString("id"));
                app.put("name", rs.getString("name"));
                app.put("description", rs.getString("description"));
                app.put("status", rs.getString("status"));
                app.put("created_at", rs.getTimestamp("created_at").toString());
                
                String contractsJson = rs.getString("authorized_contracts");
                app.put("authorized_contracts", contractsJson != null ? contractsJson : "[]");
                arr.add(app);
            }
        } finally { pool.cleanup(rs, pstmt, conn); }
        return arr;
    }

    /**
     * Registers a new application and its contract-level RBAC mappings.
     */
    private JSONObject createApp(JSONObject input, HttpServletRequest req) throws SQLException {
        Connection conn = null; PreparedStatement pstmt = null; PoolDB pool = new PoolDB();
        UUID appId = UUID.randomUUID();
        String name = (String) input.get("name");
        JSONArray contractIds = (JSONArray) input.get("authorized_contract_ids");

        try {
            conn = pool.getConnection();
            conn.setAutoCommit(false);
            
            // 1. Create the base Application record
            pstmt = conn.prepareStatement("INSERT INTO apps (id, name, description, status) VALUES (?, ?, ?, 'ACTIVE')");
            pstmt.setObject(1, appId);
            pstmt.setString(2, name);
            pstmt.setString(3, (String) input.get("description"));
            pstmt.executeUpdate();
            pstmt.close();

            // 2. Map authorized Data Contracts (RBAC)
            if (contractIds != null && !contractIds.isEmpty()) {
                pstmt = conn.prepareStatement("INSERT INTO app_contracts (app_id, contract_id) VALUES (?, ?)");
                for (Object cid : contractIds) {
                    pstmt.setObject(1, appId);
                    pstmt.setObject(2, UUID.fromString(cid.toString()));
                    pstmt.addBatch();
                }
                pstmt.executeBatch();
            }

            logAudit(conn, "APP_CREATED", appId, InputProcessor.getEmail(req), 
                "App '" + name + "' registered with " + (contractIds != null ? contractIds.size() : 0) + " authorized contracts.", req);
            
            conn.commit();
            return new JSONObject() {{ put("success", true); put("id", appId.toString()); }};
        } catch (SQLException e) {
            if (conn != null) conn.rollback();
            throw e;
        } finally { pool.cleanup(null, pstmt, conn); }
    }

    /**
     * Generates sovereign Client API credentials.
     * Stores only the hash of the secret to ensure identity sovereignty.
     */
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

            // Return the raw secret only once
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

    /**
     * Purges an application and its associated security metadata.
     */
    private void deleteApp(UUID appId, HttpServletRequest req) throws SQLException {
        Connection conn = null; PreparedStatement pstmt = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            conn.setAutoCommit(false);

            // DELETE cascades to app_contracts mapping via schema definition
            pstmt = conn.prepareStatement("DELETE FROM apps WHERE id = ?");
            pstmt.setObject(1, appId);
            pstmt.executeUpdate();

            logAudit(conn, "APP_DELETED", appId, InputProcessor.getEmail(req), "Application purged from node registry.", req);
            
            conn.commit();
        } catch (SQLException e) {
            if (conn != null) conn.rollback();
            throw e;
        } finally { pool.cleanup(null, pstmt, conn); }
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