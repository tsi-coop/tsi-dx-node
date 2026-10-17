package org.tsicoop.dxnode.framework;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * The built-in CEF-EVENTS system contract: the consent channel (docs/plan/consent-and-erasure-roadmap.md).
 *
 * Every node owns one CEF-EVENTS contract that carries Consent Exchange Format (CEF) JSON. Its id is derived
 * from the owning node's id, so a sender can address a partner's contract without any invitation. Every Active
 * partner is a participant, so no invite/accept handshake is needed. Each node also keeps a local copy of each
 * Active partner's CEF-EVENTS, because a sender governs and records a transfer against its own copy of the
 * contract, exactly as it does for an invited contract.
 *
 * The node checks only the shape of a CEF file (the schema below). It never judges consent.
 */
public final class CefEvents {

    public static final String NAME = "CEF-EVENTS";

    private CefEvents() {}

    /** The id of the CEF-EVENTS contract owned by the given node. */
    public static UUID contractIdFor(String nodeId) {
        return UUID.nameUUIDFromBytes(("tsi-dx-cef-events:" + nodeId).getBytes(StandardCharsets.UTF_8));
    }

    /** True when the contract metadata marks a built-in system contract. */
    public static boolean isSystem(JSONObject metadata) {
        return metadata != null && Boolean.TRUE.equals(metadata.get("system"));
    }

    /** True when the contract is a built-in system contract (read-only, never edited or suspended). */
    public static boolean isSystemContract(UUID contractId) throws SQLException {
        PoolDB pool = new PoolDB();
        Connection conn = null; PreparedStatement ps = null; ResultSet rs = null;
        try {
            conn = pool.getConnection();
            ps = conn.prepareStatement("SELECT metadata FROM data_contracts WHERE contract_id = ?");
            ps.setObject(1, contractId);
            rs = ps.executeQuery();
            if (!rs.next() || rs.getString(1) == null) return false;
            return isSystem((JSONObject) new JSONParser().parse(rs.getString(1)));
        } catch (SQLException e) {
            throw e;
        } catch (Exception e) {
            return false;
        } finally { pool.cleanup(rs, ps, conn); }
    }

    /** CEF v1 envelope and the five fields every event must carry. Unknown fields are allowed (1.x rule). */
    public static JSONObject schema() {
        try {
            return (JSONObject) new JSONParser().parse(
                "{\"$schema\":\"http://json-schema.org/draft-07/schema#\",\"type\":\"object\"," +
                "\"required\":[\"cef_version\",\"events\"]," +
                "\"properties\":{" +
                  "\"cef_version\":{\"type\":\"string\",\"pattern\":\"^1\\\\.[0-9]+$\"}," +
                  "\"events\":{\"type\":\"array\",\"minItems\":1,\"items\":{\"type\":\"object\"," +
                    "\"required\":[\"event_id\",\"event_type\",\"event_time\",\"fiduciary_id\",\"principal_id\"]," +
                    "\"properties\":{" +
                      "\"event_id\":{\"type\":\"string\",\"minLength\":1}," +
                      "\"event_type\":{\"type\":\"string\",\"enum\":[\"CONSENT_GRANTED\",\"CONSENT_MODIFIED\"," +
                        "\"CONSENT_WITHDRAWN\",\"ERASURE_REQUESTED\",\"ERASURE_CONFIRMED\"]}," +
                      "\"event_time\":{\"type\":\"string\",\"minLength\":1}," +
                      "\"fiduciary_id\":{\"type\":\"string\",\"minLength\":1}," +
                      "\"principal_id\":{\"type\":\"string\",\"minLength\":1}" +
                    "}}}}}");
        } catch (Exception e) { throw new IllegalStateException(e); }
    }

    private static JSONObject metadata() {
        JSONObject m = new JSONObject();
        m.put("format", "json");
        m.put("system", Boolean.TRUE);
        m.put("cef_version", "1.0");
        return m;
    }

    /**
     * Makes this node's CEF-EVENTS and its copies of every Active partner's CEF-EVENTS exist and be current.
     * Idempotent and cheap, so it is safe to call before listing contracts or moving a transfer. Does nothing
     * until the node is initialised.
     */
    public static void sync() throws SQLException {
        PoolDB pool = new PoolDB();
        Connection conn = null; PreparedStatement ps = null; ResultSet rs = null;
        try {
            conn = pool.getConnection();
            ps = conn.prepareStatement("SELECT node_id FROM node_config LIMIT 1");
            rs = ps.executeQuery();
            if (!rs.next()) return;
            String localNodeId = rs.getString(1);
            rs.close(); ps.close();
            if (localNodeId == null || localNodeId.isEmpty()) return;

            List<String> active = new ArrayList<>();
            List<String> inactive = new ArrayList<>();
            ps = conn.prepareStatement("SELECT node_id, status FROM partners");
            rs = ps.executeQuery();
            while (rs.next()) {
                if ("Active".equalsIgnoreCase(rs.getString("status"))) active.add(rs.getString("node_id"));
                else inactive.add(rs.getString("node_id"));
            }
            rs.close(); ps.close();

            // This node's own contract, with every Active partner as a participant.
            UUID own = contractIdFor(localNodeId);
            upsertContract(conn, own, localNodeId);
            for (String p : active) upsertParticipant(conn, own, p, "Active");
            for (String p : inactive) suspendParticipant(conn, own, p);

            // Local copies of each Active partner's contract, with this node as the sender.
            for (String p : active) {
                UUID theirs = contractIdFor(p);
                upsertContract(conn, theirs, p);
                upsertParticipant(conn, theirs, localNodeId, "Active");
            }
        } finally { pool.cleanup(rs, ps, conn); }
    }

    /** Runs {@link #sync()} when the contract id is a CEF-EVENTS id for this node or one of its Active partners. */
    public static void syncIfCef(UUID contractId) throws SQLException {
        if (contractId == null) return;
        PoolDB pool = new PoolDB();
        Connection conn = null; PreparedStatement ps = null; ResultSet rs = null;
        boolean cef = false;
        try {
            conn = pool.getConnection();
            ps = conn.prepareStatement(
                "SELECT node_id FROM partners WHERE status = 'Active' UNION SELECT node_id FROM node_config");
            rs = ps.executeQuery();
            while (rs.next()) {
                if (contractIdFor(rs.getString(1)).equals(contractId)) { cef = true; break; }
            }
        } finally { pool.cleanup(rs, ps, conn); }
        if (cef) sync();
    }

    private static void upsertContract(Connection conn, UUID id, String ownerNodeId) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO data_contracts (contract_id, name, receiver_node_id, schema_definition, metadata, " +
                "pii_fields, interaction_type, retention_policy_days, status, updated_at) " +
                "VALUES (?, ?, ?, ?::jsonb, ?::jsonb, ?, 'async', NULL, 'Active', NOW()) " +
                "ON CONFLICT (contract_id) DO UPDATE SET schema_definition = EXCLUDED.schema_definition, " +
                "metadata = EXCLUDED.metadata, status = 'Active', retention_policy_days = NULL")) {
            ps.setObject(1, id);
            ps.setString(2, NAME);
            ps.setString(3, ownerNodeId);
            ps.setString(4, schema().toJSONString());
            ps.setString(5, metadata().toJSONString());
            ps.setArray(6, conn.createArrayOf("text", new String[0]));
            ps.executeUpdate();
        }
    }

    private static void upsertParticipant(Connection conn, UUID contractId, String nodeId, String status) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO contract_participants (contract_id, node_id, status) VALUES (?, ?, ?) " +
                "ON CONFLICT (contract_id, node_id) DO UPDATE SET status = EXCLUDED.status")) {
            ps.setObject(1, contractId);
            ps.setString(2, nodeId);
            ps.setString(3, status);
            ps.executeUpdate();
        }
    }

    private static void suspendParticipant(Connection conn, UUID contractId, String nodeId) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "UPDATE contract_participants SET status = 'Suspended' " +
                "WHERE contract_id = ? AND node_id = ? AND status = 'Active'")) {
            ps.setObject(1, contractId);
            ps.setString(2, nodeId);
            ps.executeUpdate();
        }
    }
}
