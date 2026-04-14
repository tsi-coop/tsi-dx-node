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

/**
 * Settings service for the TSI DX Node Admin App.
 * Manages Node Config, PII Rules, and Retention Policies.
 * Updated to include 'About' metadata and remove script dependencies.
 */
public class Settings implements REST {

    private static final UUID NODE_CONFIG_SINGLETON_ID = UUID.fromString("00000000-0000-0000-0000-000000000001");

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

        try {
            input = InputProcessor.getInput(req);
            String func = (String) input.get("_func");

            if (func == null || func.trim().isEmpty()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required '_func' attribute.", req.getRequestURI());
                return;
            }

            switch (func.toLowerCase()) {
                case "get_all_settings":
                    output = getAllSettings();
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
                    break;

                case "update_node_config":
                    output = updateNodeConfig(
                        (String) input.get("fqdn"),
                        (int)(long)input.get("network_port"),
                        (String) input.get("about") // Added About field
                    );
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
                    break;

                case "save_pii_rule":
                    output = savePiiRule(
                        (String) input.get("rule_id"),
                        (String) input.get("field_name"),
                        (String) input.get("method"),
                        (JSONObject) input.get("config")
                    );
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
                    break;

                case "update_retention_policy":
                    output = new JSONObject() {{ put("success", true); put("message", "Retention policy updated."); }};
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
                    break;

                default:
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Unknown '_func': " + func, req.getRequestURI());
                    break;
            }
        } catch (Exception e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Error", e.getMessage(), req.getRequestURI());
        }
    }

    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        if (!"POST".equalsIgnoreCase(method)) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "Only POST is supported.", req.getRequestURI());
            return false;
        }

        String authHeader = req.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized", "Missing or invalid Authorization header.", req.getRequestURI());
            return false;
        }

        return InputProcessor.validate(req, res);
    }

    /**
     * Fetches combined settings. Removed validation_scripts dependency.
     */
    private JSONObject getAllSettings() throws SQLException {
        JSONObject data = new JSONObject();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        try {
            conn = pool.getConnection();

            // 1. Node Config - Added 'about' column
            pstmt = conn.prepareStatement("SELECT node_id, fqdn, network_port, about FROM node_config WHERE config_id = ?");
            pstmt.setObject(1, NODE_CONFIG_SINGLETON_ID);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                JSONObject node = new JSONObject();
                node.put("node_id", rs.getString("node_id"));
                node.put("fqdn", rs.getString("fqdn"));
                node.put("network_port", rs.getInt("network_port"));
                node.put("about", rs.getString("about"));
                data.put("node", node);
            }
            rs.close();
            pstmt.close();

            // 2. PII Rules
            JSONArray piiRules = new JSONArray();
            pstmt = conn.prepareStatement("SELECT rule_id, field_name, anonymization_method, config FROM pii_rules ORDER BY field_name ASC");
            rs = pstmt.executeQuery();
            while (rs.next()) {
                JSONObject rule = new JSONObject();
                rule.put("id", rs.getString("rule_id"));
                rule.put("name", rs.getString("field_name"));
                rule.put("method", rs.getString("anonymization_method"));
                rule.put("params", rs.getString("config"));
                piiRules.add(rule);
            }
            data.put("pii_rules", piiRules);
            rs.close();
            pstmt.close();

            // 3. Retention (Defaults)
            JSONObject retention = new JSONObject();
            retention.put("active_days", 30);
            retention.put("archive_years", 7);
            data.put("retention", retention);

        } finally {
            pool.cleanup(rs, pstmt, conn);
        }

        return new JSONObject() {{ put("success", true); put("data", data); }};
    }

    private JSONObject updateNodeConfig(String fqdn, int port, String about) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("UPDATE node_config SET fqdn = ?, network_port = ?, about = ?, updated_at = NOW() WHERE config_id = ?");
            pstmt.setString(1, fqdn);
            pstmt.setInt(2, port);
            pstmt.setString(3, about);
            pstmt.setObject(4, NODE_CONFIG_SINGLETON_ID);
            pstmt.executeUpdate();
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
        return new JSONObject() {{ put("success", true); put("message", "Node parameters updated."); }};
    }

    private JSONObject savePiiRule(String id, String fieldName, String method, JSONObject config) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            String sql = (id == null) 
                ? "INSERT INTO pii_rules (field_name, anonymization_method, config, rule_id) VALUES (?, ?, ?::jsonb, ?)"
                : "UPDATE pii_rules SET field_name = ?, anonymization_method = ?, config = ?::jsonb WHERE rule_id = ?";
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, fieldName);
            pstmt.setString(2, method);
            pstmt.setString(3, config != null ? config.toJSONString() : "{}");
            pstmt.setObject(4, id == null ? UUID.randomUUID() : UUID.fromString(id));
            pstmt.executeUpdate();
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
        return new JSONObject() {{ put("success", true); put("message", "PII Rule template saved."); }};
    }
}