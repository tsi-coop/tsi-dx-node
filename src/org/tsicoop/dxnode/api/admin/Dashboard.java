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
 * Dashboard service for the TSI DX Node Admin App.
 * Aggregates system metrics, recent activities, and pending actions.
 * Updated to prioritize Data Contract visibility over storage metrics.
 */
public class Dashboard implements Action {

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
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required '_func' attribute in input JSON.", req.getRequestURI());
                return;
            }

            switch (func.toLowerCase()) {
                case "get_dashboard_summary":
                    output = getDashboardSummary();
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
     * Aggregates all data required for the dashboard landing page.
     * Aligned with 'init.sql' schema.
     */
    private JSONObject getDashboardSummary() throws SQLException {
        JSONObject summary = new JSONObject();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        try {
            conn = pool.getConnection();

            // 1. Node Identity & Status
            JSONObject nodeStatus = new JSONObject();
            pstmt = conn.prepareStatement("SELECT node_id, fqdn FROM node_config WHERE config_id = ?");
            pstmt.setObject(1, NODE_CONFIG_SINGLETON_ID);
            rs = pstmt.executeQuery();
            String localNodeId = "";
            if (rs.next()) {
                localNodeId = rs.getString("node_id");
                nodeStatus.put("node_id", localNodeId);
                nodeStatus.put("fqdn", rs.getString("fqdn"));
                nodeStatus.put("status", "Operational");
            }
            summary.put("node", nodeStatus);
            rs.close();
            pstmt.close();

            // 2. High-level Metrics
            pstmt = conn.prepareStatement("SELECT COUNT(*) FROM partners WHERE status = 'Active'");
            rs = pstmt.executeQuery();
            summary.put("partners_online", rs.next() ? rs.getInt(1) : 0);
            rs.close();
            pstmt.close();

            pstmt = conn.prepareStatement("SELECT COUNT(*) FROM data_transfers WHERE start_time > NOW() - INTERVAL '24 hours'");
            rs = pstmt.executeQuery();
            summary.put("transfers_24h", rs.next() ? rs.getInt(1) : 0);
            rs.close();
            pstmt.close();

            // REVISED: Active Contracts Count
            pstmt = conn.prepareStatement("SELECT COUNT(*) FROM data_contracts WHERE status = 'Active'");
            rs = pstmt.executeQuery();
            summary.put("contracts_active_count", rs.next() ? rs.getInt(1) : 0);
            rs.close();
            pstmt.close();

            // 3. Recent Transfers
            JSONArray recentTransfers = new JSONArray();
            String transferSql = "SELECT t.transfer_id, t.status, t.sender_node_id, t.receiver_node_id, c.name as contract_name " +
                                 "FROM data_transfers t " +
                                 "JOIN data_contracts c ON t.contract_id = c.contract_id " +
                                 "ORDER BY t.start_time DESC LIMIT 5";
            pstmt = conn.prepareStatement(transferSql);
            rs = pstmt.executeQuery();
            while (rs.next()) {
                JSONObject t = new JSONObject();
                String sender = rs.getString("sender_node_id");
                t.put("id", rs.getString("transfer_id"));
                t.put("partner", localNodeId.equals(sender) ? rs.getString("receiver_node_id") : sender);
                t.put("direction", localNodeId.equals(sender) ? "OUTGOING" : "INCOMING");
                t.put("status", rs.getString("status"));
                
                String status = rs.getString("status");
                int progress = 0;
                if ("Delivered".equals(status) || "Sent".equals(status) || "Received".equals(status)) progress = 100;
                else if ("Processing".equals(status)) progress = 50;
                else if ("Pending".equals(status)) progress = 10;
                
                t.put("progress", progress);
                recentTransfers.add(t);
            }
            summary.put("recent_transfers", recentTransfers);
            rs.close();
            pstmt.close();

            // 4. Pending Actions (Proposed contracts)
            JSONArray pendingActions = new JSONArray();
            pstmt = conn.prepareStatement("SELECT contract_id, name FROM data_contracts WHERE status = 'Proposed'");
            rs = pstmt.executeQuery();
            while (rs.next()) {
                JSONObject action = new JSONObject();
                action.put("type", "CONTRACT_APPROVAL");
                action.put("title", "Review: " + rs.getString("name"));
                action.put("entity_id", rs.getString("contract_id"));
                pendingActions.add(action);
            }
            summary.put("pending_actions", pendingActions);
            rs.close();
            pstmt.close();

            // 5. Recent Audit Events
            JSONArray auditLogs = new JSONArray();
            pstmt = conn.prepareStatement("SELECT timestamp, severity, event_type, actor_id FROM audit_logs ORDER BY timestamp DESC LIMIT 5");
            rs = pstmt.executeQuery();
            while (rs.next()) {
                JSONObject log = new JSONObject();
                log.put("timestamp", rs.getTimestamp("timestamp").toString());
                log.put("severity", rs.getString("severity"));
                log.put("event", rs.getString("event_type"));
                log.put("summary", rs.getString("event_type") + " by " + rs.getString("actor_id"));
                auditLogs.add(log);
            }
            summary.put("recent_audit", auditLogs);
            rs.close();
            pstmt.close();

            // NEW: Recent Active Contracts
            JSONArray recentContracts = new JSONArray();
            pstmt = conn.prepareStatement("SELECT name, updated_at FROM data_contracts WHERE status = 'Active' ORDER BY updated_at DESC LIMIT 3");
            rs = pstmt.executeQuery();
            while (rs.next()) {
                JSONObject c = new JSONObject();
                c.put("name", rs.getString("name"));
                c.put("date", rs.getTimestamp("updated_at").toString());
                recentContracts.add(c);
            }
            summary.put("recent_contracts", recentContracts);

        } finally {
            pool.cleanup(rs, pstmt, conn);
        }

        return new JSONObject() {{ put("success", true); put("data", summary); }};
    }
}