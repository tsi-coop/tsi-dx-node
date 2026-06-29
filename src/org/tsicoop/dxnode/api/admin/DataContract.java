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
                    confirmInvitation(contractId, getString(input, "node_id"));
                    logAudit("CONTRACT_PARTICIPANT_ACTIVATED", "INFO", "P2P_PROTOCOL",
                            contractId.toString(), new JSONObject(), req);
                    OutputProcessor.send(res, 200, ok());
                    break;

                case "decline_invitation":
                    // Inbound P2P: invitee has rejected
                    if (contractId == null) throw new IllegalArgumentException("contract_id required.");
                    declineInvitation(contractId, getString(input, "node_id"));
                    logAudit("CONTRACT_PARTICIPANT_REJECTED", "INFO", "P2P_PROTOCOL",
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

        String sql = "INSERT INTO data_contracts " +
                     "(contract_id, name, receiver_node_id, schema_definition, metadata, " +
                     "pii_fields, interaction_type, status, updated_at) " +
                     "VALUES (?, ?, (SELECT node_id FROM node_config LIMIT 1), " +
                     "?::jsonb, ?::jsonb, ?, ?, 'Draft', NOW())";

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
            pstmt.executeUpdate();
        } finally { pool.cleanup(null, pstmt, conn); }

        JSONObject out = new JSONObject();
        out.put("success", true);
        out.put("contract_id", id.toString());
        return out;
    }

    private JSONArray listContracts() throws SQLException {
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
                         "pii_fields, interaction_type, status, updated_at) " +
                         "VALUES (?, ?, ?, ?::jsonb, ?::jsonb, ?, ?, 'Draft', NOW()) " +
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
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(targetUrl))
                .header("Content-Type", "application/json")
                .header("X-DX-P2P-HANDSHAKE", P2P_HANDSHAKE_TOKEN)
                .POST(HttpRequest.BodyPublishers.ofString(payload.toJSONString()))
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
