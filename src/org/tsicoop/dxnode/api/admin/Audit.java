package org.tsicoop.dxnode.api.admin;

import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.tsicoop.dxnode.framework.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.Optional;

/**
 * Service to manage system audit trails.
 * Provides immutable read-access to node operations, protocol events, and security logs.
 * Supports granular filtering and JSONB detail inspection.
 */
public class Audit implements Action {

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
                case "list_audit_logs":
                    OutputProcessor.send(res, 200, listAuditLogs(input));
                    break;

                case "get_audit_log":
                    String logId = (String) input.get("log_id");
                    if (logId == null) throw new IllegalArgumentException("log_id is required.");
                    Optional<JSONObject> log = getAuditLogById(UUID.fromString(logId));
                    if (log.isPresent()) {
                        OutputProcessor.send(res, 200, log.get());
                    } else {
                        OutputProcessor.errorResponse(res, 404, "Not Found", "Log entry missing.", req.getRequestURI());
                    }
                    break;

                default:
                    OutputProcessor.errorResponse(res, 400, "Bad Request", "Unknown Function: " + func, req.getRequestURI());
            }
        } catch (IllegalArgumentException e) {
            OutputProcessor.errorResponse(res, 400, "Validation Error", e.getMessage(), req.getRequestURI());
        } catch (Exception e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, 500, "Internal Protocol Error", e.getMessage(), req.getRequestURI());
        }
    }

    private JSONObject listAuditLogs(JSONObject input) throws SQLException {
        JSONArray logs = new JSONArray();
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        
        // Extraction with safe defaults
        String severity = (String) input.get("severity");
        String eventType = (String) input.get("event_type");
        String actorId = (String) input.get("actor_id");
        String search = (String) input.get("search");
        int limit = (input.get("limit") != null) ? (int)(long)input.get("limit") : 50;
        int offset = (input.get("page") != null) ? ((int)(long)input.get("page") - 1) * limit : 0;

        StringBuilder sql = new StringBuilder("SELECT * FROM audit_logs WHERE 1=1");
        List<Object> params = new ArrayList<>();

        if (severity != null && !severity.isEmpty()) { sql.append(" AND severity = ?"); params.add(severity); }
        if (eventType != null && !eventType.isEmpty()) { sql.append(" AND event_type = ?"); params.add(eventType); }
        if (actorId != null && !actorId.isEmpty()) { sql.append(" AND actor_id = ?"); params.add(actorId); }
        if (search != null && !search.isEmpty()) { 
            sql.append(" AND (event_type ILIKE ? OR details::text ILIKE ? OR actor_id ILIKE ?)"); 
            String f = "%" + search + "%";
            params.add(f); params.add(f); params.add(f);
        }

        sql.append(" ORDER BY timestamp DESC LIMIT ? OFFSET ?");
        params.add(limit);
        params.add(offset);

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql.toString());
            for (int i = 0; i < params.size(); i++) pstmt.setObject(i + 1, params.get(i));
            
            rs = pstmt.executeQuery();
            while (rs.next()) {
                logs.add(mapRowToLog(rs));
            }
            
            JSONObject response = new JSONObject();
            response.put("success", true);
            response.put("data", logs);
            return response;
        } finally { pool.cleanup(rs, pstmt, conn); }
    }

    private Optional<JSONObject> getAuditLogById(UUID logId) throws SQLException {
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("SELECT * FROM audit_logs WHERE log_id = ?");
            pstmt.setObject(1, logId);
            rs = pstmt.executeQuery();
            if (rs.next()) return Optional.of(mapRowToLog(rs));
        } finally { pool.cleanup(rs, pstmt, conn); }
        return Optional.empty();
    }

    private JSONObject mapRowToLog(ResultSet rs) throws SQLException {
        JSONObject log = new JSONObject();
        log.put("log_id", rs.getString("log_id"));
        log.put("timestamp", rs.getTimestamp("timestamp").toString());
        log.put("event_type", rs.getString("event_type"));
        log.put("severity", rs.getString("severity"));
        log.put("actor_type", rs.getString("actor_type"));
        log.put("actor_id", rs.getString("actor_id"));
        log.put("entity_id", rs.getString("entity_id"));
        log.put("origin_ip", rs.getString("origin_ip"));
        
        try {
            String details = rs.getString("details");
            log.put("details", (details != null) ? new JSONParser().parse(details) : new JSONObject());
        } catch (ParseException e) {
            log.put("details", new JSONObject());
        }
        return log;
    }

    @Override public boolean validate(String m, HttpServletRequest req, HttpServletResponse res) { return InputProcessor.validate(req, res); }
    @Override public void get(HttpServletRequest req, HttpServletResponse res) {}
    @Override public void put(HttpServletRequest req, HttpServletResponse res) {}
    @Override public void delete(HttpServletRequest req, HttpServletResponse res) {}
}