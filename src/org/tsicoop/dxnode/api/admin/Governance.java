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

public class Governance implements REST {

    // Unique ID for the single archiving_purging_config entry
    private static final UUID ARCHIVING_PURGING_CONFIG_SINGLETON_ID = UUID.fromString("00000000-0000-0000-0000-000000000002");


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
            UUID ruleId = null;
            String ruleIdStr = (String) input.get("rule_id");
            if (!ruleIdStr.isEmpty()) {
                try {
                    ruleId = UUID.fromString(ruleIdStr);
                } catch (IllegalArgumentException e) {
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid 'rule_id' format.", req.getRequestURI());
                    return;
                }
            }

            UUID scriptId = null;
            String scriptIdStr = (String) input.get("script_id");
            if (!scriptIdStr.isEmpty()) {
                try {
                    scriptId = UUID.fromString(scriptIdStr);
                } catch (IllegalArgumentException e) {
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid 'script_id' format.", req.getRequestURI());
                    return;
                }
            }

            switch (func.toLowerCase()) {
                // --- PII Rules Management ---
                case "list_pii_rules":
                    outputArray = listPiiRulesFromDb();
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, outputArray);
                    break;

                case "create_pii_rule":
                    String fieldName = (String) input.get("field_name");
                    String anonymizationMethod = (String) input.get("anonymization_method");
                    JSONObject config = (JSONObject) input.get("config"); // Optional JSONB
                    String description = (String) input.get("description");

                    if (fieldName.isEmpty() || anonymizationMethod.isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required fields (field_name, anonymization_method) for 'create_pii_rule'.", req.getRequestURI());
                        return;
                    }
                    if (isPiiRulePresent(fieldName, null)) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_CONFLICT, "Conflict", "PII rule for field '" + fieldName + "' already exists.", req.getRequestURI());
                        return;
                    }

                    output = savePiiRuleToDb(fieldName, anonymizationMethod, config, description);
                    OutputProcessor.send(res, HttpServletResponse.SC_CREATED, output);
                    break;

                case "update_pii_rule":
                    if (ruleId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'rule_id' is required for 'update_pii_rule' function.", req.getRequestURI());
                        return;
                    }
                    if (getPiiRuleByIdFromDb(ruleId).isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "PII rule with ID '" + ruleId + "' not found.", req.getRequestURI());
                        return;
                    }

                    fieldName = (String) input.get("field_name");
                    anonymizationMethod = (String) input.get("anonymization_method");
                    config = (JSONObject) input.get("config");
                    description = (String) input.get("description");

                    if (fieldName.isEmpty() && anonymizationMethod.isEmpty() && config == null && description.isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "No fields provided for update for 'update_pii_rule'.", req.getRequestURI());
                        return;
                    }
                    if (!fieldName.isEmpty() && isPiiRulePresent(fieldName, ruleId)) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_CONFLICT, "Conflict", "Updated field_name conflicts with an existing PII rule.", req.getRequestURI());
                        return;
                    }

                    output = updatePiiRuleInDb(ruleId, fieldName, anonymizationMethod, config, description);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
                    break;

                case "delete_pii_rule":
                    if (ruleId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'rule_id' is required for 'delete_pii_rule' function.", req.getRequestURI());
                        return;
                    }
                    if (getPiiRuleByIdFromDb(ruleId).isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "PII rule with ID '" + ruleId + "' not found.", req.getRequestURI());
                        return;
                    }
                    deletePiiRuleFromDb(ruleId);
                    OutputProcessor.send(res, HttpServletResponse.SC_NO_CONTENT, null);
                    break;

                // --- Validation Scripts Management ---
                case "list_validation_scripts":
                    outputArray = listValidationScriptsFromDb();
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, outputArray);
                    break;

                case "create_validation_script":
                    String name = (String) input.get("name");
                    String language = (String) input.get("language");
                    String content = (String) input.get("content");

                    if (name.isEmpty() || language.isEmpty() || content.isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required fields (name, language, content) for 'create_validation_script'.", req.getRequestURI());
                        return;
                    }
                    if (isValidationScriptPresent(name, null)) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_CONFLICT, "Conflict", "Validation script with name '" + name + "' already exists.", req.getRequestURI());
                        return;
                    }

                    output = saveValidationScriptToDb(name, language, content);
                    OutputProcessor.send(res, HttpServletResponse.SC_CREATED, output);
                    break;

                case "update_validation_script":
                    if (scriptId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'script_id' is required for 'update_validation_script' function.", req.getRequestURI());
                        return;
                    }
                    if (getValidationScriptByIdFromDb(scriptId).isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Validation script with ID '" + scriptId + "' not found.", req.getRequestURI());
                        return;
                    }

                    name = (String) input.get("name");
                    language = (String) input.get("language");
                    content = (String) input.get("content");

                    if (name.isEmpty() && language.isEmpty() && content.isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "No fields provided for update for 'update_validation_script'.", req.getRequestURI());
                        return;
                    }
                    if (!name.isEmpty() && isValidationScriptPresent(name, scriptId)) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_CONFLICT, "Conflict", "Updated script name conflicts with an existing validation script.", req.getRequestURI());
                        return;
                    }

                    output = updateValidationScriptInDb(scriptId, name, language, content);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
                    break;

                case "delete_validation_script":
                    if (scriptId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'script_id' is required for 'delete_validation_script' function.", req.getRequestURI());
                        return;
                    }
                    if (getValidationScriptByIdFromDb(scriptId).isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Validation script with ID '" + scriptId + "' not found.", req.getRequestURI());
                        return;
                    }
                    if (isValidationScriptUsedInContracts(scriptId)) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_CONFLICT, "Conflict", "Validation script is currently associated with one or more data contracts and cannot be deleted.", req.getRequestURI());
                        return;
                    }
                    deleteValidationScriptFromDb(scriptId);
                    OutputProcessor.send(res, HttpServletResponse.SC_NO_CONTENT, null);
                    break;

                // --- Archiving & Purging Configuration ---
                case "get_archiving_purging_config":
                    output = getArchivingPurgingConfigFromDb();
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
                    break;

                case "update_archiving_purging_config":
                    int activeRetentionDays = (int)(long)input.get("active_retention_days");
                    int archiveRetentionDays = (int)(long)input.get("archive_retention_days");
                    String archiveLocation = (String) input.get("archive_location");

                    if (activeRetentionDays == -1 && archiveRetentionDays == -1 && archiveLocation.isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "No fields provided for update for 'update_archiving_purging_config'.", req.getRequestURI());
                        return;
                    }
                    if (activeRetentionDays != -1 && activeRetentionDays < 0) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Active retention days cannot be negative.", req.getRequestURI());
                        return;
                    }
                    if (archiveRetentionDays != -1 && archiveRetentionDays < 0) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Archive retention days cannot be negative.", req.getRequestURI());
                        return;
                    }

                    output = updateArchivingPurgingConfigInDb(activeRetentionDays, archiveRetentionDays, archiveLocation);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
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

    /**
     * Retrieves a single validation script by its ID from the database.
     * @param scriptId The UUID of the script.
     * @return An Optional containing the script JSONObject if found, otherwise empty.
     * @throws SQLException if a database access error occurs.
     */
    private Optional<JSONObject> getValidationScriptByIdFromDb(UUID scriptId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "SELECT script_id, name, language, content, created_at, updated_at FROM validation_scripts WHERE script_id = ?";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, scriptId);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                JSONObject script = new JSONObject();
                script.put("script_id", rs.getString("script_id"));
                script.put("name", rs.getString("name"));
                script.put("language", rs.getString("language"));
                script.put("content", rs.getString("content")); // Full content for single view
                script.put("created_at", rs.getTimestamp("created_at").toInstant().toString());
                script.put("updated_at", rs.getTimestamp("updated_at").toInstant().toString());
                return Optional.of(script);
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return Optional.empty();
    }

    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        if (!"POST".equalsIgnoreCase(method)) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "Only POST method is supported for Data Governance Management operations.", req.getRequestURI());
            return false;
        }

        String authHeader = req.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized", "Missing or invalid Authorization header.", req.getRequestURI());
            return false;
        }

        /*String token = authHeader.substring(7);

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

            boolean isAdmin = false;
            boolean canViewGovernance = false; // For roles like 'Auditor' or 'GovernanceViewer'
            for (Object role : rolesJson) {
                String roleName = (String) role;
                if ("Administrator".equalsIgnoreCase(roleName)) {
                    isAdmin = true;
                    canViewGovernance = true;
                    break;
                }
                // if ("GovernanceViewer".equalsIgnoreCase(roleName)) {
                //     canViewGovernance = true;
                // }
            }

            JSONObject input = InputProcessor.getInput(req); // Parse input for func
            String func = input.optString("_func", "").trim();

            if (func.isEmpty()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing '_func' attribute for authorization check.", req.getRequestURI());
                return false;
            }

            switch (func.toLowerCase()) {
                case "list_pii_rules":
                case "list_validation_scripts":
                case "get_archiving_purging_config":
                    if (!canViewGovernance) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "Access denied. Insufficient privileges to view governance configurations.", req.getRequestURI());
                        return false;
                    }
                    break;
                case "create_pii_rule":
                case "update_pii_rule":
                case "delete_pii_rule":
                case "create_validation_script":
                case "update_validation_script":
                case "delete_validation_script":
                case "update_archiving_purging_config":
                    if (!isAdmin) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "Access denied. Administrator privileges required for this action.", req.getRequestURI());
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
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error", "Authorization or token validation failed: " + e.getMessage(), req.getRequestURI());
            return false;
        }*/
        return InputProcessor.validate(req, res);
    }

    // --- Helper Methods for PII Rules Management ---

    /**
     * Retrieves a list of PII rules from the database.
     * @return JSONArray of PII rule JSONObjects.
     * @throws SQLException if a database access error occurs.
     */
    private JSONArray listPiiRulesFromDb() throws SQLException {
        JSONArray rulesArray = new JSONArray();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "SELECT rule_id, field_name, anonymization_method, config, description, created_at, updated_at FROM pii_rules ORDER BY created_at DESC";

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            rs = pstmt.executeQuery();

            while (rs.next()) {
                JSONObject rule = new JSONObject();
                rule.put("rule_id", rs.getString("rule_id"));
                rule.put("field_name", rs.getString("field_name"));
                rule.put("anonymization_method", rs.getString("anonymization_method"));
                String configJson = rs.getString("config");
                if (configJson != null) {
                    try {
                        rule.put("config", (JSONObject) new JSONParser().parse(configJson));
                    } catch (ParseException e) { /* Log parse error, but continue */ }
                } else {
                    rule.put("config", new JSONObject());
                }
                rule.put("description", rs.getString("description"));
                rule.put("created_at", rs.getTimestamp("created_at").toInstant().toString());
                rule.put("updated_at", rs.getTimestamp("updated_at").toInstant().toString());
                rulesArray.add(rule);
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return rulesArray;
    }

    /**
     * Checks if a PII rule for a given field name already exists.
     * @param fieldName The field name to check.
     * @param excludeRuleId Optional UUID to exclude from the check (for update operations).
     * @return true if a conflict is found, false otherwise.
     * @throws SQLException if a database access error occurs.
     */
    private boolean isPiiRulePresent(String fieldName, UUID excludeRuleId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        StringBuilder sqlBuilder = new StringBuilder("SELECT COUNT(*) FROM pii_rules WHERE field_name = ?");
        List<Object> params = new ArrayList<>();
        params.add(fieldName);

        if (excludeRuleId != null) {
            sqlBuilder.append(" AND rule_id != ?");
            params.add(excludeRuleId);
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
     * Saves a new PII rule to the database.
     * @return JSONObject containing the new rule's details.
     * @throws SQLException if a database access error occurs.
     */
    private JSONObject savePiiRuleToDb(String fieldName, String anonymizationMethod, JSONObject config, String description) throws SQLException {
        JSONObject output = new JSONObject();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "INSERT INTO pii_rules (field_name, anonymization_method, config, description) VALUES (?, ?, ?::jsonb, ?) RETURNING rule_id";

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, fieldName);
            pstmt.setString(2, anonymizationMethod);
            pstmt.setString(3, config != null ? config.toJSONString() : null);
            pstmt.setString(4, description);

            int affectedRows = pstmt.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Creating PII rule failed, no rows affected.");
            }

            rs = pstmt.getGeneratedKeys();
            if (rs.next()) {
                String ruleId = rs.getString("rule_id");
                output.put("rule_id", ruleId);
                output.put("field_name", fieldName);
                output.put("message", "PII rule created successfully.");
            } else {
                throw new SQLException("Creating PII rule failed, no ID obtained.");
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return new JSONObject() {{ put("success", true); put("data", output); }};
    }

    /**
     * Retrieves a single PII rule by ID from the database.
     * @param ruleId The UUID of the rule.
     * @return An Optional containing the rule JSONObject if found, otherwise empty.
     * @throws SQLException if a database access error occurs.
     */
    private Optional<JSONObject> getPiiRuleByIdFromDb(UUID ruleId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "SELECT rule_id, field_name, anonymization_method, config, description, created_at, updated_at FROM pii_rules WHERE rule_id = ?";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, ruleId);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                JSONObject rule = new JSONObject();
                rule.put("rule_id", rs.getString("rule_id"));
                rule.put("field_name", rs.getString("field_name"));
                rule.put("anonymization_method", rs.getString("anonymization_method"));
                String configJson = rs.getString("config");
                if (configJson != null) {
                    try {
                        rule.put("config", (JSONObject) new JSONParser().parse(configJson));
                    } catch (ParseException e) { /* Log parse error, but continue */ }
                } else {
                    rule.put("config", new JSONObject());
                }
                rule.put("description", rs.getString("description"));
                rule.put("created_at", rs.getTimestamp("created_at").toInstant().toString());
                rule.put("updated_at", rs.getTimestamp("updated_at").toInstant().toString());
                return Optional.of(rule);
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return Optional.empty();
    }

    /**
     * Updates an existing PII rule in the database.
     * @return JSONObject indicating success.
     * @throws SQLException if a database access error occurs.
     */
    private JSONObject updatePiiRuleInDb(UUID ruleId, String fieldName, String anonymizationMethod, JSONObject config, String description) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = new PoolDB();

        StringBuilder sqlBuilder = new StringBuilder("UPDATE pii_rules SET updated_at = NOW()");
        List<Object> params = new ArrayList<>();

        if (fieldName != null && !fieldName.isEmpty()) { sqlBuilder.append(", field_name = ?"); params.add(fieldName); }
        if (anonymizationMethod != null && !anonymizationMethod.isEmpty()) { sqlBuilder.append(", anonymization_method = ?"); params.add(anonymizationMethod); }
        if (config != null) { sqlBuilder.append(", config = ?::jsonb"); params.add(config.toJSONString()); }
        if (description != null && !description.isEmpty()) { sqlBuilder.append(", description = ?"); params.add(description); }

        sqlBuilder.append(" WHERE rule_id = ?");
        params.add(ruleId);

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sqlBuilder.toString());
            for (int i = 0; i < params.size(); i++) {
                pstmt.setObject(i + 1, params.get(i));
            }

            int affectedRows = pstmt.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Updating PII rule failed, rule not found or no changes made.");
            }
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
        return new JSONObject() {{ put("success", true); put("message", "PII rule updated successfully."); }};
    }

    /**
     * Deletes a PII rule from the database.
     * @param ruleId The UUID of the rule to delete.
     * @throws SQLException if a database access error occurs.
     */
    private void deletePiiRuleFromDb(UUID ruleId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = new PoolDB();
        String sql = "DELETE FROM pii_rules WHERE rule_id = ?";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, ruleId);
            int affectedRows = pstmt.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Deleting PII rule failed, rule not found.");
            }
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
    }

    // --- Helper Methods for Validation Scripts Management ---

    /**
     * Retrieves a list of validation scripts from the database.
     * @return JSONArray of validation script JSONObjects.
     * @throws SQLException if a database access error occurs.
     */
    private JSONArray listValidationScriptsFromDb() throws SQLException {
        JSONArray scriptsArray = new JSONArray();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "SELECT script_id, name, language, content, created_at, updated_at FROM validation_scripts ORDER BY created_at DESC";

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            rs = pstmt.executeQuery();

            while (rs.next()) {
                JSONObject script = new JSONObject();
                script.put("script_id", rs.getString("script_id"));
                script.put("name", rs.getString("name"));
                script.put("language", rs.getString("language"));
                // Do NOT return full content in list view for brevity/security
                script.put("created_at", rs.getTimestamp("created_at").toInstant().toString());
                script.put("updated_at", rs.getTimestamp("updated_at").toInstant().toString());
                scriptsArray.add(script);
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return scriptsArray;
    }

    /**
     * Checks if a validation script with the given name already exists.
     * @param name The name of the script to check.
     * @param excludeScriptId Optional UUID to exclude from the check (for update operations).
     * @return true if a conflict is found, false otherwise.
     * @throws SQLException if a database access error occurs.
     */
    private boolean isValidationScriptPresent(String name, UUID excludeScriptId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        StringBuilder sqlBuilder = new StringBuilder("SELECT COUNT(*) FROM validation_scripts WHERE name = ?");
        List<Object> params = new ArrayList<>();
        params.add(name);

        if (excludeScriptId != null) {
            sqlBuilder.append(" AND script_id != ?");
            params.add(excludeScriptId);
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
     * Saves a new validation script to the database.
     * @return JSONObject containing the new script's details.
     * @throws SQLException if a database access error occurs.
     */
    private JSONObject saveValidationScriptToDb(String name, String language, String content) throws SQLException {
        JSONObject output = new JSONObject();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "INSERT INTO validation_scripts (name, language, content) VALUES (?, ?, ?) RETURNING script_id";

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, name);
            pstmt.setString(2, language);
            pstmt.setString(3, content);

            int affectedRows = pstmt.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Creating validation script failed, no rows affected.");
            }

            rs = pstmt.getGeneratedKeys();
            if (rs.next()) {
                String scriptId = rs.getString("script_id");
                output.put("script_id", scriptId);
                output.put("name", name);
                output.put("message", "Validation script created successfully.");
            } else {
                throw new SQLException("Creating validation script failed, no ID obtained.");
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return new JSONObject() {{ put("success", true); put("data", output); }};
    }

    /**
     * Updates an existing validation script in the database.
     * @return JSONObject indicating success.
     * @throws SQLException if a database access error occurs.
     */
    private JSONObject updateValidationScriptInDb(UUID scriptId, String name, String language, String content) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = new PoolDB();

        StringBuilder sqlBuilder = new StringBuilder("UPDATE validation_scripts SET updated_at = NOW()");
        List<Object> params = new ArrayList<>();

        if (name != null && !name.isEmpty()) { sqlBuilder.append(", name = ?"); params.add(name); }
        if (language != null && !language.isEmpty()) { sqlBuilder.append(", language = ?"); params.add(language); }
        if (content != null && !content.isEmpty()) { sqlBuilder.append(", content = ?"); params.add(content); }

        sqlBuilder.append(" WHERE script_id = ?");
        params.add(scriptId);

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sqlBuilder.toString());
            for (int i = 0; i < params.size(); i++) {
                pstmt.setObject(i + 1, params.get(i));
            }

            int affectedRows = pstmt.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Updating validation script failed, script not found or no changes made.");
            }
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
        return new JSONObject() {{ put("success", true); put("message", "Validation script updated successfully."); }};
    }

    /**
     * Checks if a validation script is currently associated with any data contracts.
     * @param scriptId The UUID of the script to check.
     * @return true if the script is used in contracts, false otherwise.
     * @throws SQLException if a database access error occurs.
     */
    private boolean isValidationScriptUsedInContracts(UUID scriptId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "SELECT COUNT(*) FROM data_contracts WHERE validation_script_id = ?";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, scriptId);
            rs = pstmt.executeQuery();
            return rs.next() && rs.getInt(1) > 0;
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }

    /**
     * Deletes a validation script from the database.
     * @param scriptId The UUID of the script to delete.
     * @throws SQLException if a database access error occurs.
     */
    private void deleteValidationScriptFromDb(UUID scriptId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = new PoolDB();
        String sql = "DELETE FROM validation_scripts WHERE script_id = ?";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, scriptId);
            int affectedRows = pstmt.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Deleting validation script failed, script not found.");
            }
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
    }

    // --- Helper Methods for Archiving & Purging Configuration ---

    /**
     * Retrieves the archiving and purging configuration from the database.
     * @return JSONObject containing the configuration details.
     * @throws SQLException if a database access error occurs.
     */
    private JSONObject getArchivingPurgingConfigFromDb() throws SQLException {
        JSONObject config = new JSONObject();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "SELECT active_retention_days, archive_retention_days, archive_location FROM archiving_purging_config WHERE config_id = ?";

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, ARCHIVING_PURGING_CONFIG_SINGLETON_ID);
            rs = pstmt.executeQuery();

            if (rs.next()) {
                config.put("active_retention_days", rs.getInt("active_retention_days"));
                config.put("archive_retention_days", rs.getInt("archive_retention_days"));
                config.put("archive_location", rs.getString("archive_location"));
            } else {
                // If no config exists, return default/empty or throw an error indicating uninitialized
                config.put("message", "Archiving and purging configuration not found. Node may not be fully initialized.");
                config.put("active_retention_days", -1); // Indicate not set
                config.put("archive_retention_days", -1);
                config.put("archive_location", "");
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return new JSONObject() {{ put("success", true); put("data", config); }};
    }

    /**
     * Updates the archiving and purging configuration in the database.
     * This method will also insert a default record if one doesn't exist (for initial setup).
     * @return JSONObject indicating success.
     * @throws SQLException if a database access error occurs.
     */
    private JSONObject updateArchivingPurgingConfigInDb(int activeRetentionDays, int archiveRetentionDays, String archiveLocation) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = new PoolDB();

        // Use UPSERT (INSERT ON CONFLICT) for PostgreSQL to handle initial creation or update
        String sql = "INSERT INTO archiving_purging_config (config_id, active_retention_days, archive_retention_days, archive_location) VALUES (?, ?, ?, ?) " +
                "ON CONFLICT (config_id) DO UPDATE SET active_retention_days = EXCLUDED.active_retention_days, " +
                "archive_retention_days = EXCLUDED.archive_retention_days, " +
                "archive_location = EXCLUDED.archive_location, " +
                "updated_at = NOW()";

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, ARCHIVING_PURGING_CONFIG_SINGLETON_ID);

            if (activeRetentionDays != -1) {
                pstmt.setInt(2, activeRetentionDays);
            } else {
                pstmt.setNull(2, java.sql.Types.INTEGER);
            }
            if (archiveRetentionDays != -1) {
                pstmt.setInt(3, archiveRetentionDays);
            } else {
                pstmt.setNull(3, java.sql.Types.INTEGER);
            }
            pstmt.setString(4, archiveLocation);

            pstmt.executeUpdate();
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
        return new JSONObject() {{ put("success", true); put("message", "Archiving and purging configuration updated successfully."); }};
    }
}
