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
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.Optional;

// Assuming these utility classes are provided as per the user's style
// import org.tsicoop.aadhaarvault.framework.REST;
// import org.tsicoop.aadhaarvault.framework.InputProcessor;
// import org.tsicoop.aadhaarvault.framework.OutputProcessor;
// import org.tsicoop.aadhaarvault.framework.PoolDB;
// import org.tsicoop.aadhaarvault.framework.JWTUtil; // For JWT validation and claims extraction

public class Audit implements REST {

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

            // Extract log_id if present in input for specific operations
            UUID logId = null;
            String logIdStr = (String) input.get("log_id");
            if (!logIdStr.isEmpty()) {
                try {
                    logId = UUID.fromString(logIdStr);
                } catch (IllegalArgumentException e) {
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid 'log_id' format.", req.getRequestURI());
                    return;
                }
            }

            switch (func.toLowerCase()) {
                case "list_audit_logs":
                    String eventTypeFilter = (String) input.get("event_type");
                    String actorIdFilter = (String) input.get("actor_id");
                    String entityTypeFilter = (String) input.get("entity_type");
                    String entityIdFilter = (String) input.get("entity_id");
                    String severityFilter = (String) input.get("severity");
                    String startDateStr = (String) input.get("start_date");
                    String endDateStr = (String) input.get("end_date");
                    String search = (String) input.get("search"); // For general text search in details
                    int page = (int)(long)input.get("page");
                    int limit = (int)(long)input.get("limit");

                    outputArray = listAuditLogsFromDb(eventTypeFilter, actorIdFilter, entityTypeFilter, entityIdFilter, severityFilter, startDateStr, endDateStr, search, page, limit);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, outputArray);
                    break;

                case "get_audit_log":
                    if (logId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'log_id' is required for 'get_audit_log' function.", req.getRequestURI());
                        return;
                    }
                    Optional<JSONObject> logOptional = getAuditLogByIdFromDb(logId);
                    if (logOptional.isPresent()) {
                        output = logOptional.get();
                        OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
                    } else {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Audit log with ID '" + logId + "' not found.", req.getRequestURI());
                    }
                    break;

                // No 'create_audit_log' endpoint as logs are generated internally by other services.
                // No 'update_audit_log' or 'delete_audit_log' as audit logs should be immutable.

                default:
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Unknown or unsupported '_func' value: " + func, req.getRequestURI());
                    break;
            }

        } catch (SQLException e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Database Error", "A database error occurred: " + e.getMessage(), req.getRequestURI());
        } catch (DateTimeParseException e) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid date format. Use ISO 8601 (e.g., YYYY-MM-DDTHH:MM:SSZ).", req.getRequestURI());
        } catch (Exception e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error", "An unexpected error occurred: " + e.getMessage(), req.getRequestURI());
        }
    }

    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        if (!"POST".equalsIgnoreCase(method)) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "Only POST method is supported for Audit Management operations.", req.getRequestURI());
            return false;
        }

        String authHeader = req.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized", "Missing or invalid Authorization header.", req.getRequestURI());
            return false;
        }

       /* String token = authHeader.substring(7);

        try {
            if (!JWTUtil.validateToken(token)) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized", "Invalid or expired token.", req.getRequestURI());
                return false;
            }

            JSONObject claims = JWTUtil.getClaims(token);
            JSONArray rolesJson = (JSONArray) claims.get("roles");
            if (rolesJson == null || rolesJson.isEmpty()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "User has no assigned roles.", req.getRequestURI());
                return false;
            }

            // Check if user has 'Administrator' or 'Auditor' role
            boolean isAdmin = false;
            boolean isAuditor = false;
            for (Object role : rolesJson) {
                String roleName = (String) role;
                if ("Administrator".equalsIgnoreCase(roleName)) {
                    isAdmin = true;
                    isAuditor = true; // Admins can audit
                    break;
                }
                if ("Auditor".equalsIgnoreCase(roleName)) {
                    isAuditor = true;
                }
            }

            JSONObject input = InputProcessor.getInput(req); // Parse input for func
            String func = (String) input.get("_func");

            if (func.isEmpty()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing '_func' attribute for authorization check.", req.getRequestURI());
                return false;
            }

            switch (func.toLowerCase()) {
                case "list_audit_logs":
                case "get_audit_log":
                    if (!isAuditor) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "Access denied. Auditor or Administrator privileges required to view audit logs.", req.getRequestURI());
                        return false;
                    }
                    break;
                default:
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Unknown or unsupported '_func' value for authorization: " + func, req.getRequestURI());
                    return false;
            }

            return InputProcessor.validate(req, res); // This validates content-type and basic body parsing

        } catch (Exception e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error", "Authorization or token validation failed: " + e.getRequestURI() + ": " + e.getMessage(), req.getRequestURI());
            return false;
        }*/
        return InputProcessor.validate(req, res);
    }

    // --- Helper Methods for Audit Management ---

    /**
     * Retrieves a list of audit logs from the database with optional filtering and pagination.
     * @return JSONArray of audit log JSONObjects.
     * @throws SQLException if a database access error occurs.
     */
    private JSONArray listAuditLogsFromDb(String eventTypeFilter, String actorIdFilter, String entityTypeFilter, String entityIdFilter, String severityFilter, String startDateStr, String endDateStr, String search, int page, int limit) throws SQLException {
        JSONArray logsArray = new JSONArray();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        StringBuilder sqlBuilder = new StringBuilder("SELECT log_id, timestamp, event_type, severity, actor_type, actor_id, entity_type, entity_id, details, origin_ip FROM audit_logs WHERE 1=1");
        List<Object> params = new ArrayList<>();

        if (eventTypeFilter != null && !eventTypeFilter.isEmpty()) {
            sqlBuilder.append(" AND event_type = ?");
            params.add(eventTypeFilter);
        }
        if (actorIdFilter != null && !actorIdFilter.isEmpty()) {
            sqlBuilder.append(" AND actor_id = ?");
            params.add(actorIdFilter);
        }
        if (entityTypeFilter != null && !entityTypeFilter.isEmpty()) {
            sqlBuilder.append(" AND entity_type = ?");
            params.add(entityTypeFilter);
        }
        if (entityIdFilter != null && !entityIdFilter.isEmpty()) {
            sqlBuilder.append(" AND entity_id = ?");
            params.add(UUID.fromString(entityIdFilter));
        }
        if (severityFilter != null && !severityFilter.isEmpty()) {
            sqlBuilder.append(" AND severity = ?");
            params.add(severityFilter);
        }
        if (startDateStr != null && !startDateStr.isEmpty()) {
            sqlBuilder.append(" AND timestamp >= ?");
            params.add(Timestamp.valueOf(LocalDateTime.parse(startDateStr)));
        }
        if (endDateStr != null && !endDateStr.isEmpty()) {
            sqlBuilder.append(" AND timestamp <= ?");
            params.add(Timestamp.valueOf(LocalDateTime.parse(endDateStr)));
        }
        if (search != null && !search.isEmpty()) {
            sqlBuilder.append(" AND details::text ILIKE ?"); // Search in JSONB details as text
            params.add("%" + search + "%");
        }

        sqlBuilder.append(" ORDER BY timestamp DESC LIMIT ? OFFSET ?");
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
                JSONObject log = new JSONObject();
                log.put("log_id", rs.getString("log_id"));
                log.put("timestamp", rs.getTimestamp("timestamp").toInstant().toString());
                log.put("event_type", rs.getString("event_type"));
                log.put("severity", rs.getString("severity"));
                log.put("actor_type", rs.getString("actor_type"));
                log.put("actor_id", rs.getString("actor_id"));
                log.put("entity_type", rs.getString("entity_type"));
                log.put("entity_id", rs.getString("entity_id"));

                String detailsJson = rs.getString("details");
                if (detailsJson != null) {
                    try {
                        log.put("details", (JSONObject) new JSONParser().parse(detailsJson));
                    } catch (ParseException e) { /* Log parse error, but continue */ }
                } else {
                    log.put("details", new JSONObject());
                }

                log.put("origin_ip", rs.getString("origin_ip"));
                logsArray.add(log);
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return logsArray;
    }

    /**
     * Retrieves details of a single audit log by its ID.
     * @param logId The UUID of the log entry.
     * @return An Optional containing the audit log JSONObject if found, otherwise empty.
     * @throws SQLException if a database access error occurs.
     */
    private Optional<JSONObject> getAuditLogByIdFromDb(UUID logId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "SELECT log_id, timestamp, event_type, severity, actor_type, actor_id, entity_type, entity_id, details, origin_ip FROM audit_logs WHERE log_id = ?";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, logId);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                JSONObject log = new JSONObject();
                log.put("log_id", rs.getString("log_id"));
                log.put("timestamp", rs.getTimestamp("timestamp").toInstant().toString());
                log.put("event_type", rs.getString("event_type"));
                log.put("severity", rs.getString("severity"));
                log.put("actor_type", rs.getString("actor_type"));
                log.put("actor_id", rs.getString("actor_id"));
                log.put("entity_type", rs.getString("entity_type"));
                log.put("entity_id", rs.getString("entity_id"));

                String detailsJson = rs.getString("details");
                if (detailsJson != null) {
                    try {
                        log.put("details", (JSONObject) new JSONParser().parse(detailsJson));
                    } catch (ParseException e) { /* Log parse error, but continue */ }
                } else {
                    log.put("details", new JSONObject());
                }

                log.put("origin_ip", rs.getString("origin_ip"));
                return Optional.of(log);
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return Optional.empty();
    }
}