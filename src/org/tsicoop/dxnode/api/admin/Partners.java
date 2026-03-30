package org.tsicoop.dxnode.api.admin;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.tsicoop.dxnode.framework.*;

public class Partners implements REST {

    @Override
    public void get(HttpServletRequest req, HttpServletResponse res) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "Use POST with _func attribute.", req.getRequestURI());
    }

    @Override
    public void put(HttpServletRequest req, HttpServletResponse res) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "Use POST with _func attribute.", req.getRequestURI());
    }

    @Override
    public void delete(HttpServletRequest req, HttpServletResponse res) {
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "Use POST with _func attribute.", req.getRequestURI());
    }

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        JSONObject input = null;
        JSONObject output = null;

        try {
            input = InputProcessor.getInput(req);
            String func = (String) input.get("_func");

            if (func == null || func.trim().isEmpty()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing '_func' attribute.", req.getRequestURI());
                return;
            }

            switch (func.toLowerCase()) {
                case "list_partners":
                    String search = (String) input.get("search");
                    int page = input.get("page") != null ? (int)(long) input.get("page") : 1;
                    int limit = input.get("limit") != null ? (int)(long) input.get("limit") : 10;
                    output = listPartnersFromDb(search, page, limit);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
                    break;

                case "create_partner":
                    output = createPartner(input);
                    OutputProcessor.send(res, HttpServletResponse.SC_CREATED, output);
                    break;

                case "delete_partner":
                    String partnerIdStr = (String) input.get("partner_id");
                    if (partnerIdStr == null) throw new IllegalArgumentException("partner_id required");
                    output = deletePartnerFromDb(UUID.fromString(partnerIdStr));
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
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

    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        if (!"POST".equalsIgnoreCase(method)) return false;
        String authHeader = req.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized", "JWT Required", req.getRequestURI());
            return false;
        }
        return InputProcessor.validate(req, res);
    }

    private JSONObject listPartnersFromDb(String search, int page, int limit) throws SQLException {
        JSONArray partnersArray = new JSONArray();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        String sql = "SELECT * FROM partners WHERE (name ILIKE ? OR node_id ILIKE ? OR fqdn ILIKE ?) ORDER BY created_at DESC LIMIT ? OFFSET ?";
        String filter = (search == null) ? "%%" : "%" + search + "%";

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, filter);
            pstmt.setString(2, filter);
            pstmt.setString(3, filter);
            pstmt.setInt(4, limit);
            pstmt.setInt(5, (page - 1) * limit);
            rs = pstmt.executeQuery();

            while (rs.next()) {
                JSONObject p = new JSONObject();
                p.put("partner_id", rs.getString("partner_id"));
                p.put("node_id", rs.getString("node_id"));
                p.put("name", rs.getString("name"));
                p.put("fqdn", rs.getString("fqdn"));
                p.put("status", rs.getString("status"));
                p.put("created_at", rs.getTimestamp("created_at").toString());
                partnersArray.add(p);
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return new JSONObject() {{ put("success", true); put("data", partnersArray); }};
    }

    private JSONObject createPartner(JSONObject input) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = new PoolDB();
        
        String name = (String) input.get("name");
        String nodeId = (String) input.get("node_id");
        String fqdn = (String) input.get("fqdn");
        String pem = (String) input.get("public_key_pem");
        
        // Simulating fingerprint calculation for schema compliance
        String fingerprint = "SHA256:" + UUID.randomUUID().toString().substring(0, 8).toUpperCase();

        String sql = "INSERT INTO partners (name, node_id, fqdn, public_key_pem, public_key_fingerprint, status) VALUES (?, ?, ?, ?, ?, 'Pending')";

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, name);
            pstmt.setString(2, nodeId);
            pstmt.setString(3, fqdn);
            pstmt.setString(4, pem);
            pstmt.setString(5, fingerprint);
            pstmt.executeUpdate();
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
        return new JSONObject() {{ put("success", true); put("message", "Partner registered."); }};
    }

    private JSONObject deletePartnerFromDb(UUID id) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("DELETE FROM partners WHERE partner_id = ?");
            pstmt.setObject(1, id);
            pstmt.executeUpdate();
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
        return new JSONObject() {{ put("success", true); put("message", "Partner deleted."); }};
    }
}