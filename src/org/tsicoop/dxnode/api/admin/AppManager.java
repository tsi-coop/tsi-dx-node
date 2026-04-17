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
 * Enforces one-time visibility for API Secrets.
 */
public class AppManager implements REST {

    private final PasswordHasher passwordHasher = new PasswordHasher();
    private static final String KEY_PREFIX = "dx_";

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
                    OutputProcessor.send(res, 204, null);
                    break;
                case "generate_api_key":
                    OutputProcessor.send(res, 201, generateApiKey(extractUuid(input, "app_id"), req));
                    break;
                default:
                    OutputProcessor.errorResponse(res, 400, "Bad Request", "Unknown function.", req.getRequestURI());
            }
        } catch (Exception e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, 500, "Internal Error", e.getMessage(), req.getRequestURI());
        }
    }

    private JSONArray listAppsFromDb() throws SQLException {
        JSONArray arr = new JSONArray();
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("SELECT * FROM apps ORDER BY created_at DESC");
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
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("INSERT INTO apps (id, name, description, status) VALUES (?, ?, ?, 'ACTIVE')");
            pstmt.setObject(1, id);
            pstmt.setString(2, (String) input.get("name"));
            pstmt.setString(3, (String) input.get("description"));
            pstmt.executeUpdate();

            logAudit(conn, "APP_CREATED", id, InputProcessor.getEmail(req), (String) input.get("name"), req);
            return new JSONObject() {{ put("success", true); put("id", id.toString()); }};
        } finally { pool.cleanup(null, pstmt, conn); }
    }

    private JSONObject generateApiKey(UUID appId, HttpServletRequest req) throws Exception {
        if (appId == null) throw new IllegalArgumentException("app_id required.");
        
        // 1. Generate Key and Secret
        String rawKey = KEY_PREFIX + generateRandomString(24);
        String rawSecret = generateRandomString(32);
        String hashedSecret = passwordHasher.hashPassword(rawSecret);

        Connection conn = null; PreparedStatement pstmt = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("INSERT INTO api_keys (api_key, api_secret_hash, app_id, status) VALUES (?, ?, ?, 'Active')");
            pstmt.setString(1, rawKey);
            pstmt.setString(2, hashedSecret);
            pstmt.setObject(3, appId);
            pstmt.executeUpdate();

            logAudit(conn, "API_KEY_GENERATED", appId, InputProcessor.getEmail(req), "New Key Created", req);

            // 2. Return raw secret ONLY ONCE
            JSONObject out = new JSONObject();
            out.put("success", true);
            out.put("api_key", rawKey);
            out.put("api_secret", rawSecret);
            return out;
        } finally { pool.cleanup(null, pstmt, conn); }
    }

    private void deleteApp(UUID appId, HttpServletRequest req) throws SQLException {
        Connection conn = null; PreparedStatement pstmt = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("DELETE FROM apps WHERE id = ?");
            pstmt.setObject(1, appId);
            pstmt.executeUpdate();
            logAudit(conn, "APP_DELETED", appId, InputProcessor.getEmail(req), "App Purged", req);
        } finally { pool.cleanup(null, pstmt, conn); }
    }

    private String generateRandomString(int length) {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes).substring(0, length);
    }

    private void logAudit(Connection conn, String type, UUID entityId, String actor, String note, HttpServletRequest req) {
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO audit_logs (log_id, timestamp, event_type, severity, actor_type, actor_id, entity_type, entity_id, details, origin_ip) " +
                "VALUES (?, NOW(), ?, 'INFO', 'USER', ?, 'APP', ?, ?::jsonb, ?::inet)")) {
            ps.setObject(1, UUID.randomUUID());
            ps.setString(2, type);
            ps.setString(3, actor);
            ps.setObject(4, entityId);
            JSONObject d = new JSONObject(); d.put("note", note);
            ps.setString(5, d.toJSONString());
            ps.setString(6, req.getRemoteAddr());
            ps.executeUpdate();
        } catch (Exception ignored) {}
    }

    private UUID extractUuid(JSONObject obj, String key) { Object v = obj.get(key); return (v == null || v.toString().isEmpty()) ? null : UUID.fromString(v.toString()); }
    @Override public boolean validate(String m, HttpServletRequest req, HttpServletResponse res) { return InputProcessor.validate(req, res); }
    @Override public void get(HttpServletRequest req, HttpServletResponse res) {}
    @Override public void put(HttpServletRequest req, HttpServletResponse res) {}
    @Override public void delete(HttpServletRequest req, HttpServletResponse res) {}
}