package org.tsicoop.dxnode.framework;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.sql.*;
import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Synchronous data-contract delivery engine.
 *
 * Reuses the existing mTLS/PKI layer (P2PClient), node registry (partners table),
 * and L1/L2 governance pipeline (TransferEngine.applyGovernance) - adding only
 * the mechanics specific to request/response: connection pooling, TTL-based
 * nonce replay protection, live responder invocation, and a per-call audit log.
 *
 * The asynchronous pipeline in TransferEngine is untouched.
 */
public class SyncEngine {

    private static SyncEngine instance;

    private static final String P2P_HANDSHAKE_TOKEN = "DX-P2P-PROTOCOL-V1";
    private static final long   DEFAULT_TIMEOUT_MS  = 10_000;
    private static final int    CIRCUIT_OPEN_THRESHOLD = 5;
    private static final long   CIRCUIT_RESET_MS    = 60_000;

    // Circuit breaker state per partner FQDN
    private final ConcurrentHashMap<String, AtomicInteger> failureCount   = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Long>          lastFailureTime = new ConcurrentHashMap<>();

    public static synchronized SyncEngine getInstance() {
        if (instance == null) instance = new SyncEngine();
        return instance;
    }

    // -------------------------------------------------------------------------
    // CALLER SIDE
    // -------------------------------------------------------------------------

    /**
     * Executes a governed synchronous request to a partner node.
     * Called by the client API (DX.java) on behalf of an authorised application.
     *
     * @param contractId      Active sync contract governing this exchange
     * @param requestPayload  Raw request object from the calling application
     * @param idempotencyKey  Optional caller-supplied idempotency key
     * @return JSONObject with success, response_payload, duration_ms
     */
    public JSONObject executeSyncRequest(UUID contractId, JSONObject requestPayload, String idempotencyKey) throws Exception {
        long startTime = System.currentTimeMillis();

        // 1. Load contract - validates interaction_type = 'sync' and status = 'Active'
        JSONObject contract   = loadSyncContract(contractId);
        String partnerFqdn    = (String) contract.get("fqdn");
        String senderNodeId   = (String) contract.get("local_node_id");
        String receiverNodeId = (String) contract.get("receiver_node_id");
        JSONObject schema     = (JSONObject) contract.get("schema_definition");
        JSONObject metadata   = (JSONObject) contract.get("metadata");
        String format         = metadata.get("format") != null ? metadata.get("format").toString().toLowerCase() : "json";
        long timeoutMs        = metadata.get("sync_timeout_ms") != null
                                ? Long.parseLong(metadata.get("sync_timeout_ms").toString())
                                : DEFAULT_TIMEOUT_MS;

        // 2. Apply L1/L2 governance to the outbound request payload
        byte[] reqBytes         = requestPayload.toJSONString().getBytes(StandardCharsets.UTF_8);
        byte[] governedReqBytes = TransferEngine.getInstance().applyGovernance(reqBytes, format, schema, metadata);
        JSONObject governedRequest = (JSONObject) new JSONParser().parse(new String(governedReqBytes, StandardCharsets.UTF_8));

        // 3. Idempotency: a key that already completed successfully returns the recorded answer
        //    instead of calling the partner again. The same key with a different request is an error.
        if (idempotencyKey != null && !idempotencyKey.isEmpty()) {
            JSONObject earlier = findCompletedCall(contractId, senderNodeId, idempotencyKey);
            if (earlier != null) {
                JSONObject storedReq = (JSONObject) earlier.get("request");
                if (storedReq != null && !storedReq.equals(governedRequest)) {   // map equality: jsonb reorders keys
                    throw new IllegalArgumentException(
                        "idempotency_key '" + idempotencyKey + "' was already used with a different request.");
                }
                JSONObject replay = new JSONObject();
                replay.put("success",           true);
                replay.put("response_payload",  earlier.get("response"));
                replay.put("duration_ms",       0L);
                replay.put("idempotent_replay", true);
                return replay;
            }
        }

        // 3b. Circuit breaker check - fail fast if partner has been unreachable
        checkCircuitBreaker(partnerFqdn);

        // 4. Generate nonce; persist to sync_nonces for tracking and idempotency
        String nonce = UUID.randomUUID().toString();
        persistCallerNonce(nonce, contractId, idempotencyKey, timeoutMs);

        // 5. Build and dispatch P2P request over pooled mTLS connection
        JSONObject p2pPayload = new JSONObject();
        p2pPayload.put("_func",            "receive_sync_request");
        p2pPayload.put("contract_id",      contractId.toString());
        p2pPayload.put("nonce",            nonce);
        p2pPayload.put("idempotency_key",  idempotencyKey);
        p2pPayload.put("sender_node_id",   senderNodeId);
        p2pPayload.put("request_payload",  governedRequest);

        String protocol  = (partnerFqdn.contains(":443") || partnerFqdn.contains(":8443")) ? "https://" : "http://";
        String targetUrl = (partnerFqdn.startsWith("http") ? partnerFqdn : protocol + partnerFqdn) + "/api/admin/transfers";

        HttpClient client = P2PClient.buildPooled(partnerFqdn, Duration.ofMillis(timeoutMs));

        JSONObject governedResponse = null;
        String logStatus  = "ERROR";
        String errorDetail = null;

        try {
            HttpRequest request = PeerAuth.sign(HttpRequest.newBuilder()
                    .uri(URI.create(targetUrl))
                    .header("Content-Type", "application/json")
                    .header("X-DX-P2P-HANDSHAKE", P2P_HANDSHAKE_TOKEN)
                    .header("X-DX-FUNCTION", "receive_sync_request")
                    .timeout(Duration.ofMillis(timeoutMs))
                    .POST(HttpRequest.BodyPublishers.ofString(p2pPayload.toJSONString())),
                    p2pPayload.toJSONString(), receiverNodeId)
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() >= 200 && response.statusCode() < 300) {
                JSONObject responseBody = (JSONObject) new JSONParser().parse(response.body());
                JSONObject rawResponse  = (JSONObject) responseBody.get("response_payload");
                if (rawResponse == null) rawResponse = new JSONObject();

                // 6. The receiver already applied L2 to its response. Verify it did (no schema validation -
                //    the response structure differs from the request) rather than transforming it a second time.
                try {
                    TransferEngine.getInstance().requireAnonymisedFields(rawResponse, metadata);
                } catch (IllegalArgumentException v) {
                    errorDetail = "Partner response violates the contract: " + v.getMessage();
                    logStatus   = "ERROR";
                    throw new Exception(errorDetail);
                }
                governedResponse = rawResponse;

                resetCircuitBreaker(partnerFqdn);
                logStatus = "SUCCESS";
            } else {
                errorDetail = "Partner responded HTTP " + response.statusCode() + ": " + response.body();
                logStatus   = "ERROR";
                recordFailure(partnerFqdn);
                throw new Exception(errorDetail);
            }

        } catch (HttpTimeoutException e) {
            logStatus   = "TIMEOUT";
            errorDetail = "Request timed out after " + timeoutMs + "ms";
            recordFailure(partnerFqdn);
            throw e;
        } finally {
            // 7. Write sync_audit_log entry regardless of outcome
            long duration = System.currentTimeMillis() - startTime;
            persistSyncAuditLog(contractId, idempotencyKey, governedRequest, governedResponse,
                    senderNodeId, receiverNodeId, duration, logStatus, errorDetail);
        }

        // 8. Return governed response to caller
        JSONObject result = new JSONObject();
        result.put("success",          true);
        result.put("response_payload", governedResponse);
        result.put("duration_ms",      System.currentTimeMillis() - startTime);
        return result;
    }

    // -------------------------------------------------------------------------
    // RECEIVER SIDE
    // -------------------------------------------------------------------------

    /**
     * Handles an inbound synchronous request from a peer node.
     * Invoked by DXManager when _func = "receive_sync_request".
     *
     * Validates the nonce (anti-replay), applies governance to the inbound payload,
     * forwards to the configured responder service, governs the response, and
     * returns the result to the caller synchronously.
     */
    public void receiveSyncRequest(JSONObject input, HttpServletResponse res, HttpServletRequest req) throws Exception {
        String contractIdStr  = (String) input.get("contract_id");
        String nonce          = (String) input.get("nonce");
        String idempotencyKey = (String) input.get("idempotency_key");
        String senderNodeId   = (String) input.get("sender_node_id");
        JSONObject rawRequest = (JSONObject) input.get("request_payload");
        if (rawRequest == null) rawRequest = new JSONObject();

        if (contractIdStr == null || nonce == null) {
            OutputProcessor.errorResponse(res, 400, "Bad Request", "contract_id and nonce are required.", req.getRequestURI());
            return;
        }

        UUID contractId = UUID.fromString(contractIdStr);
        long startTime  = System.currentTimeMillis();

        // 1. Load contract - validates interaction_type = 'sync' and status = 'Active'
        JSONObject contract    = loadSyncContractReceiver(contractId, senderNodeId);
        String receiverNodeId  = (String) contract.get("local_node_id");
        JSONObject schema      = (JSONObject) contract.get("schema_definition");
        JSONObject metadata    = (JSONObject) contract.get("metadata");
        String format          = metadata.get("format") != null ? metadata.get("format").toString().toLowerCase() : "json";
        long timeoutMs         = metadata.get("sync_timeout_ms") != null
                                 ? Long.parseLong(metadata.get("sync_timeout_ms").toString())
                                 : DEFAULT_TIMEOUT_MS;
        String responderUrl    = metadata.get("sync_responder_url") != null
                                 ? metadata.get("sync_responder_url").toString() : null;

        if (responderUrl == null || responderUrl.isEmpty()) {
            OutputProcessor.errorResponse(res, 503, "Misconfigured Contract",
                    "sync_responder_url is not configured for this contract.", req.getRequestURI());
            return;
        }

        // 2. Nonce anti-replay check - insert or reject
        if (!claimNonce(nonce, contractId, idempotencyKey, timeoutMs)) {
            persistSyncAuditLog(contractId, idempotencyKey, null, null,
                    senderNodeId, receiverNodeId, 0L, "ERROR", "Replay: nonce already consumed");
            OutputProcessor.errorResponse(res, 403, "Forbidden",
                    "Replay Protection: nonce already consumed.", req.getRequestURI());
            return;
        }

        JSONObject governedRequest  = null;
        JSONObject governedResponse = null;
        String logStatus  = "ERROR";
        String errorDetail = null;

        try {
            // 3. The receiver is the authority on its contract: validate the request as received (L1) and
            //    check the sender anonymised what the contract says (L2). It is not transformed again.
            byte[] reqBytes = rawRequest.toJSONString().getBytes(StandardCharsets.UTF_8);
            try {
                TransferEngine.getInstance().validateInbound(reqBytes, format, schema, metadata);
            } catch (IllegalArgumentException violation) {
                errorDetail = violation.getMessage();
                logStatus   = "ERROR";
                OutputProcessor.errorResponse(res, 400, "Contract Violation", errorDetail, req.getRequestURI());
                return;
            }
            governedRequest = rawRequest;

            // 4. Forward governed payload to the partner's internal responder service
            HttpClient internalClient = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofMillis(timeoutMs))
                    .build();

            HttpRequest forwardRequest = HttpRequest.newBuilder()
                    .uri(URI.create(responderUrl))
                    .header("Content-Type", "application/json")
                    .timeout(Duration.ofMillis(timeoutMs))
                    .POST(HttpRequest.BodyPublishers.ofString(governedRequest.toJSONString()))
                    .build();

            HttpResponse<String> responderResp = internalClient.send(forwardRequest, HttpResponse.BodyHandlers.ofString());

            if (responderResp.statusCode() < 200 || responderResp.statusCode() >= 300) {
                errorDetail = "Responder returned HTTP " + responderResp.statusCode();
                logStatus   = "ERROR";
                OutputProcessor.errorResponse(res, 502, "Responder Error", errorDetail, req.getRequestURI());
                return;
            }

            JSONObject rawResponse = (JSONObject) new JSONParser().parse(responderResp.body());

            // 5. Apply L2 PII governance to the responder's output (no schema validation — response structure differs from request)
            byte[] respBytes         = rawResponse.toJSONString().getBytes(StandardCharsets.UTF_8);
            byte[] governedRespBytes = TransferEngine.getInstance().applyPiiOnly(respBytes, metadata);
            governedResponse = (JSONObject) new JSONParser().parse(new String(governedRespBytes, StandardCharsets.UTF_8));

            logStatus = "SUCCESS";

            // 6. Return governed response to the calling peer node
            JSONObject result = new JSONObject();
            result.put("success",          true);
            result.put("response_payload", governedResponse);
            OutputProcessor.send(res, 200, result);

        } catch (HttpTimeoutException e) {
            logStatus   = "TIMEOUT";
            errorDetail = "Responder timed out after " + timeoutMs + "ms";
            OutputProcessor.errorResponse(res, 504, "Gateway Timeout", errorDetail, req.getRequestURI());
        } finally {
            // 7. Write sync_audit_log on receiver side
            long duration = System.currentTimeMillis() - startTime;
            persistSyncAuditLog(contractId, idempotencyKey, governedRequest, governedResponse,
                    senderNodeId, receiverNodeId, duration, logStatus, errorDetail);
        }
    }

    // -------------------------------------------------------------------------
    // DB HELPERS
    // -------------------------------------------------------------------------

    private JSONObject loadSyncContract(UUID contractId) throws Exception {
        PoolDB pool = new PoolDB();
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null;
        try {
            conn = pool.getConnection();
            // Joins contract_participants to confirm local node is an active participant
            String sql =
                "SELECT c.receiver_node_id, c.schema_definition, c.metadata, " +
                "c.interaction_type, c.status, p.fqdn, cfg.node_id AS local_node_id " +
                "FROM data_contracts c " +
                "JOIN partners p ON p.node_id = c.receiver_node_id " +
                "JOIN contract_participants cp " +
                "  ON cp.contract_id = c.contract_id " +
                " AND cp.node_id = (SELECT node_id FROM node_config LIMIT 1) " +
                " AND cp.status = 'Active' " +
                "CROSS JOIN (SELECT node_id FROM node_config LIMIT 1) cfg " +
                "WHERE c.contract_id = ?";
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, contractId);
            rs = pstmt.executeQuery();
            if (!rs.next()) throw new IllegalArgumentException(
                "Contract not found, or local node is not an active participant: " + contractId);

            String interactionType = rs.getString("interaction_type");
            String status          = rs.getString("status");
            if (!"sync".equalsIgnoreCase(interactionType))
                throw new IllegalArgumentException("Contract " + contractId + " is not a sync contract.");
            if (!"Active".equalsIgnoreCase(status))
                throw new IllegalStateException("Contract " + contractId + " is not Active (status: " + status + ").");

            JSONParser parser = new JSONParser();
            JSONObject result = new JSONObject();
            result.put("receiver_node_id",  rs.getString("receiver_node_id"));
            result.put("fqdn",              rs.getString("fqdn"));
            result.put("local_node_id",     rs.getString("local_node_id"));
            result.put("schema_definition", parser.parse(rs.getString("schema_definition")));
            result.put("metadata",          parser.parse(rs.getString("metadata")));
            return result;
        } finally { pool.cleanup(rs, pstmt, conn); }
    }

    private JSONObject loadSyncContractReceiver(UUID contractId, String senderNodeId) throws Exception {
        PoolDB pool = new PoolDB();
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null;
        try {
            conn = pool.getConnection();
            // Validates sender is an active participant; contract must be owned by local node
            String sql =
                "SELECT c.schema_definition, c.metadata, c.interaction_type, c.status, " +
                "cfg.node_id AS local_node_id " +
                "FROM data_contracts c " +
                "CROSS JOIN (SELECT node_id FROM node_config LIMIT 1) cfg " +
                "WHERE c.contract_id = ? " +
                "  AND c.receiver_node_id = cfg.node_id " +
                "  AND EXISTS ( " +
                "    SELECT 1 FROM contract_participants cp " +
                "    WHERE cp.contract_id = c.contract_id " +
                "      AND cp.node_id = ? " +
                "      AND cp.status = 'Active' " +
                "  )";
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, contractId);
            pstmt.setString(2, senderNodeId);
            rs = pstmt.executeQuery();
            if (!rs.next()) throw new IllegalStateException(
                "Contract not found, sender is not an active participant, or this node is not the receiver: " + contractId);

            String interactionType = rs.getString("interaction_type");
            String status          = rs.getString("status");
            if (!"sync".equalsIgnoreCase(interactionType))
                throw new IllegalArgumentException("Contract " + contractId + " is not a sync contract.");
            if (!"Active".equalsIgnoreCase(status))
                throw new IllegalStateException("Contract " + contractId + " is not Active.");

            JSONParser parser = new JSONParser();
            JSONObject result = new JSONObject();
            result.put("local_node_id",     rs.getString("local_node_id"));
            result.put("schema_definition", parser.parse(rs.getString("schema_definition")));
            result.put("metadata",          parser.parse(rs.getString("metadata")));
            return result;
        } finally { pool.cleanup(rs, pstmt, conn); }
    }

    /** Caller side: save nonce to track in-flight request. */
    private void persistCallerNonce(String nonce, UUID contractId, String idempotencyKey, long timeoutMs) throws SQLException {
        PoolDB pool = new PoolDB();
        Connection conn = null; PreparedStatement pstmt = null;
        try {
            conn = pool.getConnection();
            String sql = "INSERT INTO sync_nonces (contract_id, nonce, idempotency_key, expires_at) " +
                         "VALUES (?, ?, ?, NOW() + INTERVAL '1 millisecond' * ?)";
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, contractId);
            pstmt.setString(2, nonce);
            pstmt.setString(3, idempotencyKey);
            pstmt.setLong(4, timeoutMs);
            pstmt.executeUpdate();
        } finally { pool.cleanup(null, pstmt, conn); }
    }

    /**
     * Receiver side: atomically claim the nonce.
     * Returns true if the nonce is new (proceed); false if already seen (replay).
     */
    private boolean claimNonce(String nonce, UUID contractId, String idempotencyKey, long timeoutMs) {
        Connection conn = null; PreparedStatement pstmt = null; PoolDB pool = null;
        try {
            pool = new PoolDB();
            conn = pool.getConnection();
            String sql = "INSERT INTO sync_nonces (contract_id, nonce, idempotency_key, expires_at) " +
                         "VALUES (?, ?, ?, NOW() + INTERVAL '1 millisecond' * ?) " +
                         "ON CONFLICT (nonce) DO NOTHING";
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, contractId);
            pstmt.setString(2, nonce);
            pstmt.setString(3, idempotencyKey);
            pstmt.setLong(4, timeoutMs);
            int rows = pstmt.executeUpdate();
            return rows > 0; // 0 means nonce already existed - replay
        } catch (Exception e) {
            System.err.println("[SyncEngine] Nonce claim error: " + e.getMessage());
            return false;
        } finally {
            if (pool != null) try { pool.cleanup(null, pstmt, conn); } catch (Exception ignored) {}
        }
    }

    /** Most recent successful call from this node with the given idempotency key, within 24 hours. */
    private JSONObject findCompletedCall(UUID contractId, String localNodeId, String idempotencyKey) {
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = null;
        try {
            pool = new PoolDB();
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(
                "SELECT request_payload::text, response_payload::text FROM sync_audit_log " +
                "WHERE contract_id = ? AND idempotency_key = ? AND sender_node_id = ? AND status = 'SUCCESS' " +
                "AND timestamp > NOW() - INTERVAL '24 hours' ORDER BY timestamp DESC LIMIT 1");
            pstmt.setObject(1, contractId);
            pstmt.setString(2, idempotencyKey);
            pstmt.setString(3, localNodeId);
            rs = pstmt.executeQuery();
            if (!rs.next()) return null;
            JSONParser p = new JSONParser();
            JSONObject out = new JSONObject();
            if (rs.getString(1) != null) out.put("request", p.parse(rs.getString(1)));
            if (rs.getString(2) != null) out.put("response", p.parse(rs.getString(2)));
            return out;
        } catch (Exception e) {
            System.err.println("[SyncEngine] Idempotency lookup failed: " + e.getMessage());
            return null;
        } finally {
            if (pool != null) try { pool.cleanup(rs, pstmt, conn); } catch (Exception ignored) {}
        }
    }

    private void persistSyncAuditLog(UUID contractId, String idempotencyKey,
                                     JSONObject request, JSONObject response,
                                     String senderNodeId, String receiverNodeId,
                                     long durationMs, String status, String errorDetail) {
        Connection conn = null; PreparedStatement pstmt = null; PoolDB pool = null;
        try {
            pool = new PoolDB();
            conn = pool.getConnection();
            String sql = "INSERT INTO sync_audit_log " +
                         "(contract_id, idempotency_key, request_payload, response_payload, " +
                         "sender_node_id, receiver_node_id, duration_ms, status, error_detail) " +
                         "VALUES (?, ?, ?::jsonb, ?::jsonb, ?, ?, ?, ?, ?)";
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, contractId);
            pstmt.setString(2, idempotencyKey);
            pstmt.setString(3, request  != null ? request.toJSONString()  : null);
            pstmt.setString(4, response != null ? response.toJSONString() : null);
            pstmt.setString(5, senderNodeId);
            pstmt.setString(6, receiverNodeId);
            pstmt.setLong(7, durationMs);
            pstmt.setString(8, status);
            pstmt.setString(9, errorDetail);
            pstmt.executeUpdate();
        } catch (Exception e) {
            System.err.println("[SyncEngine] Audit log write failed: " + e.getMessage());
        } finally {
            if (pool != null) try { pool.cleanup(null, pstmt, conn); } catch (Exception ignored) {}
        }
    }

    // -------------------------------------------------------------------------
    // CIRCUIT BREAKER
    // -------------------------------------------------------------------------

    private void checkCircuitBreaker(String fqdn) throws Exception {
        AtomicInteger count = failureCount.get(fqdn);
        if (count != null && count.get() >= CIRCUIT_OPEN_THRESHOLD) {
            long last = lastFailureTime.getOrDefault(fqdn, 0L);
            if (System.currentTimeMillis() - last < CIRCUIT_RESET_MS) {
                throw new Exception("Circuit open for partner: " + fqdn +
                        ". Too many consecutive failures. Retrying after cooldown.");
            }
            // Cooldown elapsed - half-open: reset and allow one attempt
            count.set(0);
        }
    }

    private void recordFailure(String fqdn) {
        failureCount.computeIfAbsent(fqdn, k -> new AtomicInteger(0)).incrementAndGet();
        lastFailureTime.put(fqdn, System.currentTimeMillis());
    }

    private void resetCircuitBreaker(String fqdn) {
        failureCount.remove(fqdn);
        lastFailureTime.remove(fqdn);
    }
}
