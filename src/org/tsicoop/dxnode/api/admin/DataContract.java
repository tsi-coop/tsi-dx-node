package org.tsicoop.dxnode.api.admin;

import org.tsicoop.dxnode.framework.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import java.net.ConnectException;
import java.net.NoRouteToHostException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.sql.*;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Manages Data Contracts under the receiver-authority model.
 *
 * Only the receiving node creates contracts. Senders are invited participants.
 * A single contract may have multiple active participants (Node A, C, D …).
 * sync_responder_url is local-only and is never transmitted to participants.
 */
public class DataContract implements Action {

    private static final String P2P_HANDSHAKE_TOKEN = "DX-P2P-PROTOCOL-V1";
    private final HttpClient httpClient = P2PClient.build(Duration.ofSeconds(10));

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        try {
            JSONObject input = InputProcessor.getInput(req);
            String func = getString(input, "_func");
            UUID contractId = extractUuid(input, "contract_id");

            switch (func.toLowerCase()) {

                case "list_contracts":
                    OutputProcessor.send(res, 200, listContracts());
                    break;

                case "get_contract":
                    if (contractId == null) throw new IllegalArgumentException("contract_id required.");
                    JSONObject detail = getContractById(contractId);
                    if (detail != null) OutputProcessor.send(res, 200, detail);
                    else OutputProcessor.errorResponse(res, 404, "Not Found", "Contract not found.", req.getRequestURI());
                    break;

                case "create_contract":
                    JSONObject created = createContract(input);
                    JSONObject cAudit = new JSONObject();
                    cAudit.put("name", getString(input, "name"));
                    cAudit.put("format", ((JSONObject) input.get("metadata")).get("format"));
                    logAudit("CONTRACT_CREATED", "INFO", resolveActor(req),
                            (String) created.get("contract_id"), cAudit, req);
                    OutputProcessor.send(res, 201, created);
                    break;

                case "invite_node": {
                    if (contractId == null) throw new IllegalArgumentException("contract_id required.");
                    requireNotSystem(contractId);
                    String nodeId = getString(input, "node_id");
                    if (nodeId.isEmpty()) throw new IllegalArgumentException("node_id required.");
                    inviteNode(contractId, nodeId);
                    JSONObject iAudit = new JSONObject();
                    iAudit.put("invited_node", nodeId);
                    logAudit("CONTRACT_INVITATION_SENT", "INFO", resolveActor(req),
                            contractId.toString(), iAudit, req);
                    OutputProcessor.send(res, 200, ok());
                    break;
                }

                case "receive_contract_invitation":
                    // Inbound P2P: store contract and mark local node as Invited
                    receiveContractInvitation(input);
                    JSONObject riAudit = new JSONObject();
                    riAudit.put("sender", getString(input, "sender_node_id"));
                    logAudit("CONTRACT_INVITATION_RECEIVED", "INFO", "P2P_PROTOCOL",
                            contractId != null ? contractId.toString() : null, riAudit, req);
                    OutputProcessor.send(res, 201, ok());
                    break;

                case "accept_contract":
                    if (contractId == null) throw new IllegalArgumentException("contract_id required.");
                    acceptContract(contractId);
                    JSONObject aAudit = new JSONObject();
                    aAudit.put("action", "ACCEPTED");
                    logAudit("CONTRACT_ACCEPTED", "INFO", resolveActor(req),
                            contractId.toString(), aAudit, req);
                    OutputProcessor.send(res, 200, ok());
                    break;

                case "reject_contract":
                    if (contractId == null) throw new IllegalArgumentException("contract_id required.");
                    rejectContract(contractId);
                    JSONObject rjAudit = new JSONObject();
                    rjAudit.put("action", "REJECTED");
                    logAudit("CONTRACT_REJECTED", "INFO", resolveActor(req),
                            contractId.toString(), rjAudit, req);
                    OutputProcessor.send(res, 200, ok());
                    break;

                case "confirm_invitation":
                    // Inbound P2P: invitee has accepted — activate their participant row
                    if (contractId == null) throw new IllegalArgumentException("contract_id required.");
                    requirePeerIs(req, getString(input, "node_id"));
                    confirmInvitation(contractId, getString(input, "node_id"));
                    logAudit("CONTRACT_PARTICIPANT_ACTIVATED", "INFO", "P2P_PROTOCOL",
                            contractId.toString(), new JSONObject(), req);
                    OutputProcessor.send(res, 200, ok());
                    break;

                case "decline_invitation":
                    // Inbound P2P: invitee has rejected
                    if (contractId == null) throw new IllegalArgumentException("contract_id required.");
                    requirePeerIs(req, getString(input, "node_id"));
                    declineInvitation(contractId, getString(input, "node_id"));
                    logAudit("CONTRACT_PARTICIPANT_REJECTED", "INFO", "P2P_PROTOCOL",
                            contractId.toString(), new JSONObject(), req);
                    OutputProcessor.send(res, 200, ok());
                    break;

                case "notify_participant_suspended":
                    // Inbound P2P: receiver has suspended this node on the contract
                    if (contractId == null) throw new IllegalArgumentException("contract_id required.");
                    requirePeerIsReceiver(contractId, req);
                    requireNotSystem(contractId);
                    applyParticipantSuspension(contractId);
                    logAudit("CONTRACT_PARTICIPANT_SUSPENDED", "INFO", "P2P_PROTOCOL",
                            contractId.toString(), new JSONObject(), req);
                    OutputProcessor.send(res, 200, ok());
                    break;

                case "notify_contract_suspended":
                    // Inbound P2P: receiver has suspended the contract
                    if (contractId == null) throw new IllegalArgumentException("contract_id required.");
                    requirePeerIsReceiver(contractId, req);
                    requireNotSystem(contractId);
                    applyContractSuspension(contractId);
                    logAudit("CONTRACT_SUSPENDED", "INFO", "P2P_PROTOCOL",
                            contractId.toString(), new JSONObject(), req);
                    OutputProcessor.send(res, 200, ok());
                    break;

                case "update_contract": {
                    if (contractId == null) throw new IllegalArgumentException("contract_id required.");
                    requireNotSystem(contractId);
                    JSONObject updated = updateContract(contractId, input);
                    JSONObject auditDetails = new JSONObject();
                    auditDetails.put("changed", updated.get("changed"));
                    logAudit("CONTRACT_UPDATED", "INFO", resolveActor(req), contractId.toString(), auditDetails, req);
                    OutputProcessor.send(res, 200, updated);
                    break;
                }

                case "receive_contract_update":
                    // Inbound P2P: the receiver changed operational settings of a contract we participate in
                    if (contractId == null) throw new IllegalArgumentException("contract_id required.");
                    requirePeerIsReceiver(contractId, req);
                    requireNotSystem(contractId);
                    applyContractUpdate(contractId, input);
                    logAudit("CONTRACT_UPDATED", "INFO", "P2P_PROTOCOL", contractId.toString(), new JSONObject(), req);
                    OutputProcessor.send(res, 200, ok());
                    break;

                case "deactivate_participant": {
                    if (contractId == null) throw new IllegalArgumentException("contract_id required.");
                    requireNotSystem(contractId);
                    String nodeId = getString(input, "node_id");
                    if (nodeId.isEmpty()) throw new IllegalArgumentException("node_id required.");
                    deactivateParticipant(contractId, nodeId);
                    JSONObject dpAudit = new JSONObject();
                    dpAudit.put("suspended_node", nodeId);
                    logAudit("CONTRACT_PARTICIPANT_SUSPENDED", "INFO", resolveActor(req),
                            contractId.toString(), dpAudit, req);
                    OutputProcessor.send(res, 200, ok());
                    break;
                }

                case "deactivate_contract":
                    if (contractId == null) throw new IllegalArgumentException("contract_id required.");
                    requireNotSystem(contractId);
                    deactivateContract(contractId);
                    logAudit("CONTRACT_SUSPENDED", "INFO", resolveActor(req),
                            contractId.toString(), new JSONObject(), req);
                    OutputProcessor.send(res, 200, ok());
                    break;

                default:
                    OutputProcessor.errorResponse(res, 400, "Bad Request",
                            "Unknown function: " + func, req.getRequestURI());
            }

        } catch (NoRouteToHostException | ConnectException e) {
            OutputProcessor.errorResponse(res, 502, "P2P Connectivity Error",
                    "Target node unreachable.", req.getRequestURI());
        } catch (IllegalArgumentException e) {
            OutputProcessor.errorResponse(res, 400, "Validation Error", e.getMessage(), req.getRequestURI());
        } catch (IllegalStateException e) {
            OutputProcessor.errorResponse(res, 403, "Forbidden", e.getMessage(), req.getRequestURI());
        } catch (Exception e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, 500, "Internal Error", e.getMessage(), req.getRequestURI());
        }
    }

    // -------------------------------------------------------------------------
    // CONTRACT CRUD
    // -------------------------------------------------------------------------

    private JSONObject createContract(JSONObject input) throws SQLException {
        UUID id = UUID.randomUUID();
        String interactionType = getString(input, "interaction_type");
        if (!interactionType.equals("sync") && !interactionType.equals("async")) interactionType = "async";

        // A sync contract without a responder can never answer a call, so refuse it up front rather than
        // letting it become Active and fail every request with 503.
        if (interactionType.equals("sync")) {
            Object meta = input.get("metadata");
            Object url = meta instanceof JSONObject ? ((JSONObject) meta).get("sync_responder_url") : null;
            String u = url == null ? "" : url.toString().trim();
            if (u.isEmpty()) throw new IllegalArgumentException(
                "A sync contract requires metadata.sync_responder_url: the internal service this node forwards requests to.");
            if (!u.startsWith("http://") && !u.startsWith("https://")) throw new IllegalArgumentException(
                "sync_responder_url must be an http:// or https:// URL.");
        }

        String sql = "INSERT INTO data_contracts " +
                     "(contract_id, name, receiver_node_id, schema_definition, metadata, " +
                     "pii_fields, interaction_type, retention_policy_days, status, updated_at) " +
                     "VALUES (?, ?, (SELECT node_id FROM node_config LIMIT 1), " +
                     "?::jsonb, ?::jsonb, ?, ?, ?, 'Draft', NOW())";

        PoolDB pool = new PoolDB();
        Connection conn = null; PreparedStatement pstmt = null;
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, id);
            pstmt.setString(2, getString(input, "name"));
            pstmt.setString(3, ((JSONObject) input.get("schema_definition")).toJSONString());
            pstmt.setString(4, ((JSONObject) input.get("metadata")).toJSONString());
            JSONArray piiArr = (JSONArray) input.get("pii_fields");
            String[] pii = piiArr != null ? (String[]) piiArr.toArray(new String[0]) : new String[0];
            pstmt.setArray(5, conn.createArrayOf("text", pii));
            pstmt.setString(6, interactionType);
            Object retention = input.get("retention_policy_days");
            pstmt.setObject(7, retention instanceof Number && ((Number) retention).longValue() >= 0
                    ? Integer.valueOf(((Number) retention).intValue()) : null, java.sql.Types.INTEGER);
            pstmt.executeUpdate();
        } finally { pool.cleanup(null, pstmt, conn); }

        JSONObject out = new JSONObject();
        out.put("success", true);
        out.put("contract_id", id.toString());
        return out;
    }

    /** The built-in CEF-EVENTS contract is read-only: it is never edited, suspended or given invitations. */
    private void requireNotSystem(UUID contractId) throws SQLException {
        if (CefEvents.isSystemContract(contractId))
            throw new IllegalStateException("CEF-EVENTS is a built-in system contract and cannot be changed.");
    }

    private JSONArray listContracts() throws SQLException {
        CefEvents.sync();   // the built-in CEF-EVENTS contracts are created on first use
        String sql =
            "SELECT dc.contract_id, dc.name, dc.status, dc.interaction_type, " +
            "       dc.receiver_node_id, dc.updated_at, " +
            "       (dc.receiver_node_id = cfg.node_id) AS is_receiver, " +
            "       cp_local.status AS participant_status, " +
            "       (SELECT COUNT(*) FROM contract_participants cp2 " +
            "        WHERE cp2.contract_id = dc.contract_id AND cp2.status = 'Active') AS active_count, " +
            "       (SELECT COUNT(*) FROM contract_participants cp3 " +
            "        WHERE cp3.contract_id = dc.contract_id) AS total_invited, " +
            "       dc.metadata " +
            "FROM data_contracts dc " +
            "CROSS JOIN (SELECT node_id FROM node_config LIMIT 1) cfg " +
            "LEFT JOIN contract_participants cp_local " +
            "       ON cp_local.contract_id = dc.contract_id AND cp_local.node_id = cfg.node_id " +
            "WHERE dc.receiver_node_id = cfg.node_id OR cp_local.node_id IS NOT NULL " +
            "ORDER BY dc.updated_at DESC";

        JSONArray arr = new JSONArray();
        PoolDB pool = new PoolDB();
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null;
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            rs = pstmt.executeQuery();
            while (rs.next()) {
                JSONObject c = new JSONObject();
                c.put("contract_id", rs.getString("contract_id"));
                c.put("name", rs.getString("name"));
                c.put("status", rs.getString("status"));
                c.put("interaction_type", rs.getString("interaction_type"));
                c.put("receiver_node_id", rs.getString("receiver_node_id"));
                c.put("is_receiver", rs.getBoolean("is_receiver"));
                c.put("participant_status", rs.getString("participant_status"));
                c.put("active_participant_count", rs.getLong("active_count"));
                c.put("total_invited", rs.getLong("total_invited"));
                try { c.put("metadata", new JSONParser().parse(rs.getString("metadata"))); } catch (Exception ignored) {}
                arr.add(c);
            }
        } finally { pool.cleanup(rs, pstmt, conn); }
        return arr;
    }

    private JSONObject getContractById(UUID id) throws SQLException {
        String sql = "SELECT dc.*, cfg.node_id AS local_node_id, " +
                     "(dc.receiver_node_id = cfg.node_id) AS is_receiver " +
                     "FROM data_contracts dc " +
                     "CROSS JOIN (SELECT node_id FROM node_config LIMIT 1) cfg " +
                     "WHERE dc.contract_id = ?";

        PoolDB pool = new PoolDB();
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null;
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, id);
            rs = pstmt.executeQuery();
            if (!rs.next()) return null;

            JSONObject c = new JSONObject();
            c.put("contract_id",      rs.getString("contract_id"));
            c.put("name",             rs.getString("name"));
            c.put("receiver_node_id", rs.getString("receiver_node_id"));
            c.put("status",           rs.getString("status"));
            c.put("interaction_type", rs.getString("interaction_type"));
            c.put("is_receiver",      rs.getBoolean("is_receiver"));
            c.put("created_at",       rs.getTimestamp("created_at").toString());
            int retentionDays = rs.getInt("retention_policy_days");
            if (!rs.wasNull()) c.put("retention_policy_days", retentionDays);
            JSONParser parser = new JSONParser();
            try { c.put("schema_definition", parser.parse(rs.getString("schema_definition"))); } catch (Exception ignored) {}
            try { c.put("metadata",          parser.parse(rs.getString("metadata"))); }          catch (Exception ignored) {}
            java.sql.Array pii = rs.getArray("pii_fields");
            if (pii != null) {
                JSONArray piiJson = new JSONArray();
                for (Object o : (String[]) pii.getArray()) piiJson.add(o);
                c.put("pii_fields", piiJson);
            }

            // Participants
            c.put("participants", getParticipants(conn, id));
            return c;
        } finally { pool.cleanup(rs, pstmt, conn); }
    }

    private JSONArray getParticipants(Connection conn, UUID contractId) throws SQLException {
        JSONArray arr = new JSONArray();
        String sql = "SELECT cp.node_id, cp.status, cp.invited_at, p.name AS partner_name " +
                     "FROM contract_participants cp " +
                     "LEFT JOIN partners p ON p.node_id = cp.node_id " +
                     "WHERE cp.contract_id = ? ORDER BY cp.invited_at";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setObject(1, contractId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    JSONObject p = new JSONObject();
                    p.put("node_id",      rs.getString("node_id"));
                    p.put("status",       rs.getString("status"));
                    p.put("invited_at",   rs.getTimestamp("invited_at").toString());
                    p.put("partner_name", rs.getString("partner_name"));
                    arr.add(p);
                }
            }
        }
        return arr;
    }

    // -------------------------------------------------------------------------
    // INVITE FLOW
    // -------------------------------------------------------------------------

    private void inviteNode(UUID contractId, String nodeId) throws Exception {
        PoolDB pool = new PoolDB();
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null;
        try {
            conn = pool.getConnection();

            // Insert participant row
            try (PreparedStatement ps = conn.prepareStatement(
                    "INSERT INTO contract_participants (contract_id, node_id, status) " +
                    "VALUES (?, ?, 'Invited') ON CONFLICT (contract_id, node_id) DO NOTHING")) {
                ps.setObject(1, contractId);
                ps.setString(2, nodeId);
                ps.executeUpdate();
            }

            // Load contract + partner FQDN
            pstmt = conn.prepareStatement(
                "SELECT dc.*, p.fqdn, cfg.node_id AS local_node_id " +
                "FROM data_contracts dc " +
                "JOIN partners p ON p.node_id = ? " +
                "CROSS JOIN (SELECT node_id FROM node_config LIMIT 1) cfg " +
                "WHERE dc.contract_id = ?");
            pstmt.setString(1, nodeId);
            pstmt.setObject(2, contractId);
            rs = pstmt.executeQuery();
            if (!rs.next()) throw new IllegalArgumentException("Contract or partner not found.");

            String fqdn        = rs.getString("fqdn");
            String localNodeId = rs.getString("local_node_id");

            // Build invitation — strip sync_responder_url before sending
            JSONObject payload = new JSONObject();
            payload.put("_func",            "receive_contract_invitation");
            payload.put("contract_id",      rs.getString("contract_id"));
            payload.put("name",             rs.getString("name"));
            payload.put("interaction_type", rs.getString("interaction_type"));
            int retentionDays = rs.getInt("retention_policy_days");
            if (!rs.wasNull()) payload.put("retention_policy_days", retentionDays);
            payload.put("sender_node_id",   localNodeId);
            payload.put("schema_definition", new JSONParser().parse(rs.getString("schema_definition")));

            JSONObject meta = (JSONObject) new JSONParser().parse(rs.getString("metadata"));
            meta.remove("sync_responder_url"); // never expose internal URL to participants
            payload.put("metadata", meta);

            java.sql.Array pii = rs.getArray("pii_fields");
            if (pii != null) {
                JSONArray piiArr = new JSONArray();
                for (String s : (String[]) pii.getArray()) piiArr.add(s);
                payload.put("pii_fields", piiArr);
            }

            dispatch(fqdn, payload);
        } finally { pool.cleanup(rs, pstmt, conn); }
    }

    private void receiveContractInvitation(JSONObject input) throws SQLException {
        PoolDB pool = new PoolDB();
        Connection conn = null; PreparedStatement pstmt = null;
        try {
            conn = pool.getConnection();

            // Upsert contract
            String sql = "INSERT INTO data_contracts " +
                         "(contract_id, name, receiver_node_id, schema_definition, metadata, " +
                         "pii_fields, interaction_type, retention_policy_days, status, updated_at) " +
                         "VALUES (?, ?, ?, ?::jsonb, ?::jsonb, ?, ?, ?, 'Draft', NOW()) " +
                         "ON CONFLICT (contract_id) DO UPDATE " +
                         "SET name = EXCLUDED.name, updated_at = NOW()";
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, extractUuid(input, "contract_id"));
            pstmt.setString(2, getString(input, "name"));
            pstmt.setString(3, getString(input, "sender_node_id")); // sender is the receiver/owner
            pstmt.setString(4, ((JSONObject) input.get("schema_definition")).toJSONString());
            pstmt.setString(5, ((JSONObject) input.get("metadata")).toJSONString());
            JSONArray piiArr = (JSONArray) input.get("pii_fields");
            String[] pii = piiArr != null ? (String[]) piiArr.toArray(new String[0]) : new String[0];
            pstmt.setArray(6, conn.createArrayOf("text", pii));
            pstmt.setString(7, getString(input, "interaction_type"));
            Object invRetention = input.get("retention_policy_days");
            pstmt.setObject(8, invRetention instanceof Number ? Integer.valueOf(((Number) invRetention).intValue()) : null,
                    java.sql.Types.INTEGER);
            pstmt.executeUpdate();
            pool.cleanup(null, pstmt, null);

            // Mark local node as Invited participant
            pstmt = conn.prepareStatement(
                "INSERT INTO contract_participants (contract_id, node_id, status) " +
                "VALUES (?, (SELECT node_id FROM node_config LIMIT 1), 'Invited') " +
                "ON CONFLICT (contract_id, node_id) DO NOTHING");
            pstmt.setObject(1, extractUuid(input, "contract_id"));
            pstmt.executeUpdate();
        } finally { pool.cleanup(null, pstmt, conn); }
    }

    private void acceptContract(UUID contractId) throws Exception {
        PoolDB pool = new PoolDB();
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null;
        try {
            conn = pool.getConnection();

            // Update local participant row
            try (PreparedStatement ps = conn.prepareStatement(
                    "UPDATE contract_participants SET status = 'Active' " +
                    "WHERE contract_id = ? AND node_id = (SELECT node_id FROM node_config LIMIT 1)")) {
                ps.setObject(1, contractId);
                ps.executeUpdate();
            }

            // Activate the contract locally — it arrived as Draft and is now accepted
            try (PreparedStatement ps = conn.prepareStatement(
                    "UPDATE data_contracts SET status = 'Active', updated_at = NOW() " +
                    "WHERE contract_id = ?")) {
                ps.setObject(1, contractId);
                ps.executeUpdate();
            }

            // Resolve receiver's FQDN and local node_id
            pstmt = conn.prepareStatement(
                "SELECT dc.receiver_node_id, p.fqdn, cfg.node_id AS local_node_id " +
                "FROM data_contracts dc " +
                "JOIN partners p ON p.node_id = dc.receiver_node_id " +
                "CROSS JOIN (SELECT node_id FROM node_config LIMIT 1) cfg " +
                "WHERE dc.contract_id = ?");
            pstmt.setObject(1, contractId);
            rs = pstmt.executeQuery();
            if (!rs.next()) return;

            String fqdn        = rs.getString("fqdn");
            String localNodeId = rs.getString("local_node_id");

            JSONObject payload = new JSONObject();
            payload.put("_func",        "confirm_invitation");
            payload.put("contract_id",  contractId.toString());
            payload.put("node_id",      localNodeId);
            dispatch(fqdn, payload);
        } finally { pool.cleanup(rs, pstmt, conn); }
    }

    private void rejectContract(UUID contractId) throws Exception {
        PoolDB pool = new PoolDB();
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null;
        try {
            conn = pool.getConnection();

            try (PreparedStatement ps = conn.prepareStatement(
                    "UPDATE contract_participants SET status = 'Rejected' " +
                    "WHERE contract_id = ? AND node_id = (SELECT node_id FROM node_config LIMIT 1)")) {
                ps.setObject(1, contractId);
                ps.executeUpdate();
            }

            pstmt = conn.prepareStatement(
                "SELECT dc.receiver_node_id, p.fqdn, cfg.node_id AS local_node_id " +
                "FROM data_contracts dc " +
                "JOIN partners p ON p.node_id = dc.receiver_node_id " +
                "CROSS JOIN (SELECT node_id FROM node_config LIMIT 1) cfg " +
                "WHERE dc.contract_id = ?");
            pstmt.setObject(1, contractId);
            rs = pstmt.executeQuery();
            if (!rs.next()) return;

            JSONObject payload = new JSONObject();
            payload.put("_func",       "decline_invitation");
            payload.put("contract_id", contractId.toString());
            payload.put("node_id",     rs.getString("local_node_id"));
            dispatch(rs.getString("fqdn"), payload);
        } finally { pool.cleanup(rs, pstmt, conn); }
    }

    private void confirmInvitation(UUID contractId, String nodeId) throws SQLException {
        PoolDB pool = new PoolDB();
        Connection conn = null; PreparedStatement pstmt = null;
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(
                "UPDATE contract_participants SET status = 'Active' " +
                "WHERE contract_id = ? AND node_id = ?");
            pstmt.setObject(1, contractId);
            pstmt.setString(2, nodeId);
            pstmt.executeUpdate();
            pool.cleanup(null, pstmt, null);

            // Activate contract if still Draft
            pstmt = conn.prepareStatement(
                "UPDATE data_contracts SET status = 'Active', updated_at = NOW() " +
                "WHERE contract_id = ? AND status = 'Draft'");
            pstmt.setObject(1, contractId);
            pstmt.executeUpdate();
        } finally { pool.cleanup(null, pstmt, conn); }
    }

    private void deactivateParticipant(UUID contractId, String nodeId) throws Exception {
        PoolDB pool = new PoolDB();
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null;
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(
                "UPDATE contract_participants SET status = 'Suspended' " +
                "WHERE contract_id = ? AND node_id = ? " +
                "AND (SELECT receiver_node_id FROM data_contracts WHERE contract_id = ?) = " +
                "(SELECT node_id FROM node_config LIMIT 1)");
            pstmt.setObject(1, contractId);
            pstmt.setString(2, nodeId);
            pstmt.setObject(3, contractId);
            if (pstmt.executeUpdate() == 0)
                throw new IllegalStateException("Not authorised or participant not found.");
            pool.cleanup(null, pstmt, null);

            // Notify the suspended sender so their local participant status updates
            String fqdn = getFqdnForNode(conn, nodeId);
            if (fqdn != null) {
                JSONObject payload = new JSONObject();
                payload.put("_func",       "notify_participant_suspended");
                payload.put("contract_id", contractId.toString());
                try { dispatch(fqdn, payload); }
                catch (Exception e) { System.err.println("[DataContract] notify_participant_suspended failed for " + nodeId + ": " + e.getMessage()); }
            }
        } finally { pool.cleanup(rs, pstmt, conn); }
    }

    private void deactivateContract(UUID contractId) throws Exception {
        PoolDB pool = new PoolDB();
        Connection conn = null; PreparedStatement pstmt = null;
        try {
            conn = pool.getConnection();

            // Collect active participants before suspending (while status is still 'Active')
            List<String[]> participants = getActiveParticipantFqdns(conn, contractId);

            pstmt = conn.prepareStatement(
                "UPDATE data_contracts SET status = 'Suspended', updated_at = NOW() " +
                "WHERE contract_id = ? AND receiver_node_id = (SELECT node_id FROM node_config LIMIT 1)");
            pstmt.setObject(1, contractId);
            if (pstmt.executeUpdate() == 0)
                throw new IllegalStateException("Not authorised or contract not found.");
            pool.cleanup(null, pstmt, null);

            // Notify all active participants so their local contract status updates
            JSONObject payload = new JSONObject();
            payload.put("_func",       "notify_contract_suspended");
            payload.put("contract_id", contractId.toString());
            for (String[] p : participants) {
                try { dispatch(p[1], payload); }
                catch (Exception e) { System.err.println("[DataContract] notify_contract_suspended failed for " + p[0] + ": " + e.getMessage()); }
            }
        } finally { pool.cleanup(null, pstmt, conn); }
    }

    // -------------------------------------------------------------------------
    // EDIT CONTRACT
    // -------------------------------------------------------------------------

    private static final java.util.Set<String> ANON_METHODS =
            new java.util.HashSet<>(java.util.Arrays.asList("MASK", "HASH", "TOKENIZE", "NONE"));

    /**
     * Edits a contract on the receiving node.
     *
     * Operational settings (name, retention_policy_days, and for sync contracts sync_responder_url and
     * sync_timeout_ms) can be changed while the contract is Draft or Active. The contract's terms
     * (schema_definition, governance_rules, pii_fields) are what participants agreed to, so they can only
     * be changed while the contract is still a Draft that nobody has been invited to; afterwards create a
     * new contract instead. interaction_type and format never change.
     */
    private JSONObject updateContract(UUID contractId, JSONObject input) throws Exception {
        PoolDB pool = new PoolDB();
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null;
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(
                "SELECT dc.name, dc.status, dc.interaction_type, dc.metadata, dc.schema_definition, dc.pii_fields, " +
                "dc.retention_policy_days, (dc.receiver_node_id = cfg.node_id) AS is_receiver, " +
                "(SELECT COUNT(*) FROM contract_participants cp WHERE cp.contract_id = dc.contract_id) AS participants " +
                "FROM data_contracts dc CROSS JOIN (SELECT node_id FROM node_config LIMIT 1) cfg " +
                "WHERE dc.contract_id = ?");
            pstmt.setObject(1, contractId);
            rs = pstmt.executeQuery();
            if (!rs.next()) throw new IllegalArgumentException("Contract not found.");
            if (!rs.getBoolean("is_receiver"))
                throw new IllegalStateException("Only the receiving node may edit a contract.");
            String status = rs.getString("status");
            if (!"Draft".equals(status) && !"Active".equals(status))
                throw new IllegalStateException("A " + status + " contract cannot be edited.");

            boolean isSync = "sync".equals(rs.getString("interaction_type"));
            boolean termsLocked = !"Draft".equals(status) || rs.getLong("participants") > 0;
            JSONParser parser = new JSONParser();
            JSONObject metadata = (JSONObject) parser.parse(rs.getString("metadata"));
            String name = rs.getString("name");
            Object schemaDef = null;
            JSONArray changed = new JSONArray();
            boolean shared = false;   // a change participants need to know about

            Object nameIn = input.get("name");
            if (nameIn != null) {
                String n = nameIn.toString().trim();
                if (n.isEmpty()) throw new IllegalArgumentException("name cannot be empty.");
                if (!n.equals(name)) { name = n; changed.add("name"); shared = true; }
            }

            Integer retention = null; boolean retentionSet = false;
            if (input.containsKey("retention_policy_days")) {
                Object r = input.get("retention_policy_days");
                if (r instanceof Number && ((Number) r).longValue() >= 0) {
                    retention = ((Number) r).intValue(); retentionSet = true;
                    changed.add("retention_policy_days"); shared = true;
                } else if (r == null) {
                    retentionSet = true; changed.add("retention_policy_days"); shared = true;   // keep indefinitely
                } else throw new IllegalArgumentException("retention_policy_days must be a number of days (0 or more).");
            }

            boolean wantsResponder = input.containsKey("sync_responder_url"), wantsTimeout = input.containsKey("sync_timeout_ms");
            if ((wantsResponder || wantsTimeout) && !isSync)
                throw new IllegalArgumentException("sync_responder_url and sync_timeout_ms apply to sync contracts only.");
            if (wantsResponder) {
                String u = getString(input, "sync_responder_url").trim();
                if (!u.startsWith("http://") && !u.startsWith("https://"))
                    throw new IllegalArgumentException("sync_responder_url must be an http:// or https:// URL.");
                metadata.put("sync_responder_url", u); changed.add("sync_responder_url");
            }
            if (wantsTimeout) {
                Object t = input.get("sync_timeout_ms");
                if (!(t instanceof Number) || ((Number) t).longValue() < 100 || ((Number) t).longValue() > 600000)
                    throw new IllegalArgumentException("sync_timeout_ms must be between 100 and 600000.");
                metadata.put("sync_timeout_ms", ((Number) t).longValue()); changed.add("sync_timeout_ms"); shared = true;
            }

            boolean wantsSchema = input.containsKey("schema_definition"), wantsRules = input.containsKey("pii_anonymization"),
                    wantsPii = input.containsKey("pii_fields");
            String[] piiFields = null;
            if (wantsSchema || wantsRules || wantsPii) {
                if (termsLocked) throw new IllegalStateException(
                    "The contract's terms (schema, governance rules, PII fields) cannot change once the contract is active or " +
                    "partners have been invited. Create a new contract instead.");
                if (wantsSchema) {
                    if (!(input.get("schema_definition") instanceof JSONObject))
                        throw new IllegalArgumentException("schema_definition must be an object.");
                    schemaDef = input.get("schema_definition"); changed.add("schema_definition");
                }
                if (wantsRules) {
                    if (!(input.get("pii_anonymization") instanceof JSONObject))
                        throw new IllegalArgumentException("pii_anonymization must be an object of field -> MASK|HASH|TOKENIZE|NONE.");
                    JSONObject rules = (JSONObject) input.get("pii_anonymization");
                    for (Object k : rules.keySet()) {
                        if (!ANON_METHODS.contains(String.valueOf(rules.get(k)).toUpperCase()))
                            throw new IllegalArgumentException("Unknown anonymisation method for field '" + k + "'.");
                    }
                    JSONObject gr = metadata.get("governance_rules") instanceof JSONObject
                            ? (JSONObject) metadata.get("governance_rules") : new JSONObject();
                    gr.put("pii_anonymization", rules);
                    metadata.put("governance_rules", gr); changed.add("pii_anonymization");
                }
                if (wantsPii) {
                    if (!(input.get("pii_fields") instanceof JSONArray))
                        throw new IllegalArgumentException("pii_fields must be an array.");
                    piiFields = (String[]) ((JSONArray) input.get("pii_fields")).toArray(new String[0]); changed.add("pii_fields");
                }
            }

            if (changed.isEmpty()) throw new IllegalArgumentException("Nothing to change.");
            if (isSync) {
                Object u = metadata.get("sync_responder_url");
                if (u == null || u.toString().trim().isEmpty())
                    throw new IllegalArgumentException("A sync contract requires sync_responder_url.");
            }

            rs.close(); pstmt.close();
            pstmt = conn.prepareStatement(
                "UPDATE data_contracts SET name = ?, metadata = ?::jsonb, " +
                "schema_definition = COALESCE(?::jsonb, schema_definition), " +
                "pii_fields = COALESCE(?, pii_fields), " +
                "retention_policy_days = CASE WHEN ? THEN ? ELSE retention_policy_days END, updated_at = NOW() " +
                "WHERE contract_id = ? AND receiver_node_id = (SELECT node_id FROM node_config LIMIT 1)");
            pstmt.setString(1, name);
            pstmt.setString(2, metadata.toJSONString());
            pstmt.setString(3, schemaDef == null ? null : ((JSONObject) schemaDef).toJSONString());
            if (piiFields == null) pstmt.setNull(4, java.sql.Types.ARRAY); else pstmt.setArray(4, conn.createArrayOf("text", piiFields));
            pstmt.setBoolean(5, retentionSet);
            pstmt.setObject(6, retention, java.sql.Types.INTEGER);
            pstmt.setObject(7, contractId);
            pstmt.executeUpdate();
            pool.cleanup(null, pstmt, null);

            int notified = 0;
            if (shared) {
                JSONObject payload = new JSONObject();
                payload.put("_func",       "receive_contract_update");
                payload.put("contract_id", contractId.toString());
                payload.put("name",        name);
                if (retentionSet) payload.put("retention_policy_days", retention);
                if (metadata.get("sync_timeout_ms") != null) payload.put("sync_timeout_ms", metadata.get("sync_timeout_ms"));
                try (PreparedStatement ps = conn.prepareStatement(
                        "SELECT p.node_id, p.fqdn FROM contract_participants cp JOIN partners p ON p.node_id = cp.node_id " +
                        "WHERE cp.contract_id = ? AND cp.status IN ('Invited','Active')")) {
                    ps.setObject(1, contractId);
                    try (ResultSet prs = ps.executeQuery()) {
                        while (prs.next()) {
                            try { dispatch(prs.getString(2), payload); notified++; }
                            catch (Exception e) { System.err.println("[DataContract] receive_contract_update failed for "
                                    + prs.getString(1) + ": " + e.getMessage()); }
                        }
                    }
                }
            }
            JSONObject out = ok();
            out.put("contract_id", contractId.toString());
            out.put("changed", changed);
            out.put("participants_notified", notified);
            return out;
        } finally { pool.cleanup(rs, pstmt, conn); }
    }

    /** Participant side: applies the receiver's operational changes (name, retention, sync timeout). */
    private void applyContractUpdate(UUID contractId, JSONObject input) throws Exception {
        PoolDB pool = new PoolDB();
        Connection conn = null; PreparedStatement pstmt = null;
        try {
            conn = pool.getConnection();
            Object retention = input.get("retention_policy_days");
            Object timeout = input.get("sync_timeout_ms");
            String name = getString(input, "name").trim();
            pstmt = conn.prepareStatement(
                "UPDATE data_contracts SET " +
                "name = CASE WHEN ? <> '' THEN ? ELSE name END, " +
                "retention_policy_days = CASE WHEN ? THEN ? ELSE retention_policy_days END, " +
                "metadata = CASE WHEN ? THEN jsonb_set(metadata, '{sync_timeout_ms}', to_jsonb(?::bigint)) ELSE metadata END, " +
                "updated_at = NOW() " +
                "WHERE contract_id = ? AND receiver_node_id <> (SELECT node_id FROM node_config LIMIT 1)");
            pstmt.setString(1, name);
            pstmt.setString(2, name);
            pstmt.setBoolean(3, input.containsKey("retention_policy_days"));
            pstmt.setObject(4, retention instanceof Number ? Integer.valueOf(((Number) retention).intValue()) : null, java.sql.Types.INTEGER);
            pstmt.setBoolean(5, timeout instanceof Number);
            pstmt.setLong(6, timeout instanceof Number ? ((Number) timeout).longValue() : 0L);
            pstmt.setObject(7, contractId);
            pstmt.executeUpdate();
        } finally { pool.cleanup(null, pstmt, conn); }
    }

    /** The signed peer must be the node that owns (receives on) this contract. */
    private void requirePeerIsReceiver(UUID contractId, HttpServletRequest req) throws SQLException {
        Object peer = req.getAttribute(PeerAuth.ATTR_PEER);
        if (peer == null) return;   // unsigned traffic is only reachable in TSI_DX_NODE_P2P_SIGNATURES=optional mode
        PoolDB pool = new PoolDB();
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null;
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("SELECT receiver_node_id FROM data_contracts WHERE contract_id = ?");
            pstmt.setObject(1, contractId);
            rs = pstmt.executeQuery();
            if (!rs.next() || !peer.equals(rs.getString(1)))
                throw new IllegalStateException("Only the contract's receiving node may send this notification.");
        } finally { pool.cleanup(rs, pstmt, conn); }
    }

    /** The signed peer must be the node named in the request body. */
    private void requirePeerIs(HttpServletRequest req, String nodeId) {
        Object peer = req.getAttribute(PeerAuth.ATTR_PEER);
        if (peer != null && !peer.equals(nodeId))
            throw new IllegalStateException("The signing node does not match the node this message speaks for.");
    }

    /** Updates the local participant row to Suspended — called on the sender side via P2P. */
    private void applyParticipantSuspension(UUID contractId) throws SQLException {
        PoolDB pool = new PoolDB();
        Connection conn = null; PreparedStatement pstmt = null;
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(
                "UPDATE contract_participants SET status = 'Suspended' " +
                "WHERE contract_id = ? AND node_id = (SELECT node_id FROM node_config LIMIT 1)");
            pstmt.setObject(1, contractId);
            pstmt.executeUpdate();
        } finally { pool.cleanup(null, pstmt, conn); }
    }

    /** Updates the local contract status to Suspended — called on sender nodes via P2P. */
    private void applyContractSuspension(UUID contractId) throws SQLException {
        PoolDB pool = new PoolDB();
        Connection conn = null; PreparedStatement pstmt = null;
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(
                "UPDATE data_contracts SET status = 'Suspended', updated_at = NOW() WHERE contract_id = ?");
            pstmt.setObject(1, contractId);
            pstmt.executeUpdate();
        } finally { pool.cleanup(null, pstmt, conn); }
    }

    private String getFqdnForNode(Connection conn, String nodeId) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement("SELECT fqdn FROM partners WHERE node_id = ?")) {
            ps.setString(1, nodeId);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getString("fqdn") : null;
            }
        }
    }

    private List<String[]> getActiveParticipantFqdns(Connection conn, UUID contractId) throws SQLException {
        List<String[]> result = new ArrayList<>();
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT cp.node_id, p.fqdn FROM contract_participants cp " +
                "JOIN partners p ON p.node_id = cp.node_id " +
                "WHERE cp.contract_id = ? AND cp.status = 'Active'")) {
            ps.setObject(1, contractId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) result.add(new String[]{rs.getString("node_id"), rs.getString("fqdn")});
            }
        }
        return result;
    }

    private void declineInvitation(UUID contractId, String nodeId) throws SQLException {
        PoolDB pool = new PoolDB();
        Connection conn = null; PreparedStatement pstmt = null;
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(
                "UPDATE contract_participants SET status = 'Rejected' " +
                "WHERE contract_id = ? AND node_id = ?");
            pstmt.setObject(1, contractId);
            pstmt.setString(2, nodeId);
            pstmt.executeUpdate();
        } finally { pool.cleanup(null, pstmt, conn); }
    }

    // -------------------------------------------------------------------------
    // HELPERS
    // -------------------------------------------------------------------------

    private void dispatch(String fqdn, JSONObject payload) throws Exception {
        String protocol  = (fqdn.contains(":443") || fqdn.contains(":8443")) ? "https://" : "http://";
        String targetUrl = (fqdn.startsWith("http") ? fqdn : protocol + fqdn) + "/api/admin/contracts";
        HttpRequest request = PeerAuth.sign(HttpRequest.newBuilder()
                .uri(URI.create(targetUrl))
                .header("Content-Type", "application/json")
                .header("X-DX-P2P-HANDSHAKE", P2P_HANDSHAKE_TOKEN)
                .POST(HttpRequest.BodyPublishers.ofString(payload.toJSONString())), payload.toJSONString(), null)
                .build();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() >= 400)
            throw new Exception("Partner rejected P2P call [" + payload.get("_func") + "]: " + response.body());
    }

    private void logAudit(String type, String severity, String actor, String entityId,
                          JSONObject details, HttpServletRequest req) {
        Connection conn = null; PreparedStatement pstmt = null; PoolDB pool = null;
        try {
            pool = new PoolDB();
            conn = pool.getConnection();
            String sql = "INSERT INTO audit_logs " +
                         "(log_id, timestamp, event_type, severity, actor_type, actor_id, " +
                         "entity_type, entity_id, details, origin_ip) " +
                         "VALUES (?, NOW(), ?, ?, ?, ?, 'CONTRACT', ?, ?::jsonb, ?::inet)";
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, UUID.randomUUID());
            pstmt.setString(2, type);
            pstmt.setString(3, severity);
            String actorId = (actor == null || actor.isEmpty()) ? "SYSTEM" : actor;
            pstmt.setString(4, "P2P_PROTOCOL".equals(actorId) ? "SYSTEM" : "USER");
            pstmt.setString(5, actorId);
            if (entityId != null && !entityId.trim().isEmpty()) {
                pstmt.setObject(6, UUID.fromString(entityId.trim()));
            } else {
                pstmt.setNull(6, Types.OTHER);
            }
            pstmt.setString(7, details != null ? details.toJSONString() : "{}");
            pstmt.setString(8, req.getRemoteAddr());
            pstmt.executeUpdate();
        } catch (Exception e) {
            System.err.println("[DataContract] Audit failure: " + e.getMessage());
        } finally {
            if (pool != null) pool.cleanup(null, pstmt, conn);
        }
    }

    private String resolveActor(HttpServletRequest req) {
        String email = InputProcessor.getEmail(req);
        String name  = InputProcessor.getName(req);
        if (email == null || email.isEmpty()) return "SYSTEM";
        if (name != null && !name.isEmpty() && !name.equals(email)) return name + " (" + email + ")";
        return email;
    }

    @SuppressWarnings("unchecked")
    private JSONObject ok() { JSONObject o = new JSONObject(); o.put("success", true); return o; }
    private String getString(JSONObject obj, String key) { Object v = obj.get(key); return v == null ? "" : v.toString(); }
    private UUID extractUuid(JSONObject obj, String key) {
        Object v = obj.get(key);
        return (v == null || v.toString().isEmpty()) ? null : UUID.fromString(v.toString());
    }

    @Override
    public boolean validate(String m, HttpServletRequest req, HttpServletResponse res) {
        if (P2P_HANDSHAKE_TOKEN.equals(req.getHeader("X-DX-P2P-HANDSHAKE"))) return true;
        return InputProcessor.validate(req, res);
    }
    @Override public void get(HttpServletRequest req, HttpServletResponse res) {}
    @Override public void put(HttpServletRequest req, HttpServletResponse res) {}
    @Override public void delete(HttpServletRequest req, HttpServletResponse res) {}
}
