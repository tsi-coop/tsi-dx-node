package org.tsicoop.dxnode.framework;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.networknt.schema.JsonSchema;
import com.networknt.schema.JsonSchemaFactory;
import com.networknt.schema.SpecVersion;
import com.networknt.schema.ValidationMessage;
import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.sql.*;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;

/**
 * Orchestration engine for P2P Data Transfers.
 * REVISED: Implements P2P Replay Protection via cryptographic sequence numbers and timestamps.
 * Enforces L1 (Structural) and L2 (PII) Governance for JSON and CSV.
 */
public class TransferEngine implements ServletContextListener {

    private static TransferEngine instance;
    private ScheduledExecutorService scheduler;
    private ExecutorService transferPool;
    private final HttpClient httpClient;
    private final ObjectMapper mapper = new ObjectMapper();
    
    private static final String P2P_HEADER = "X-DX-P2P-HANDSHAKE";
    private static final String P2P_TOKEN = "DX-P2P-PROTOCOL-V1";
    private static final int MAX_CONCURRENT_TRANSFERS = 10;
    
    // Freshness window for replay protection (e.g., 5 minutes)
    private static final long FRESHNESS_THRESHOLD_MS = 300000; 

    public TransferEngine() {
        this.httpClient = P2PClient.build(Duration.ofSeconds(60), HttpClient.Redirect.NORMAL);
    }

    public static synchronized TransferEngine getInstance() {
        if (instance == null) instance = new TransferEngine();
        return instance;
    }

    @Override
    public void contextInitialized(ServletContextEvent sce) {
        System.out.println("[TransferEngine] Initializing Governed JSON/CSV Orchestration with Replay Protection...");
        instance = this;
        transferPool = Executors.newFixedThreadPool(MAX_CONCURRENT_TRANSFERS);
        scheduler = Executors.newSingleThreadScheduledExecutor();
        JWTUtil.assertConfigured();
        scheduler.scheduleAtFixedRate(this::pollAndProcessPending, 15, 30, TimeUnit.SECONDS);
        long maintenanceSeconds = 3600;
        try { maintenanceSeconds = Long.parseLong(System.getenv().getOrDefault("TSI_DX_NODE_MAINTENANCE_SECONDS", "3600")); } catch (NumberFormatException ignored) {}
        scheduler.scheduleAtFixedRate(() -> {
            try { runMaintenance(); } catch (Exception e) { System.err.println("[TransferEngine] Maintenance failed: " + e.getMessage()); }
        }, 120, Math.max(60, maintenanceSeconds), TimeUnit.SECONDS);
    }

    public void startTransfer(UUID transferId) {
        if (transferPool != null && !transferPool.isShutdown()) {
            transferPool.submit(() -> executeTransferSequence(transferId));
        }
    }

    private void pollAndProcessPending() {
        ensureSchema();
        if (!schemaReady) return;
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = null;
        try {
            pool = new PoolDB();
            conn = pool.getConnection();
            String sql = "SELECT transfer_id FROM data_transfers WHERE status = 'Pending' " +
                         "AND (next_retry_at IS NULL OR next_retry_at <= NOW()) " +
                         "ORDER BY start_time ASC LIMIT 20";
            pstmt = conn.prepareStatement(sql);
            rs = pstmt.executeQuery();
            while (rs.next()) {
                startTransfer(UUID.fromString(rs.getString("transfer_id")));
            }
        } catch (Exception e) {
            System.err.println("[TransferEngine] Polling failed: " + e.getMessage());
        } finally {
            try { if (pool != null) pool.cleanup(rs, pstmt, conn); } catch (Exception ignored) {}
        }
    }

    /** Transport failures are retried with this many attempts in total (30 s, 2 min, 8 min, 32 min apart). */
    private static final int MAX_ATTEMPTS = 5;
    private static final long BASE_RETRY_SECONDS = 30;

    /** One lock per (contract, receiver): sequence numbers are allocated and consumed in send order. */
    private final ConcurrentHashMap<String, java.util.concurrent.locks.ReentrantLock> laneLocks = new ConcurrentHashMap<>();

    private void executeTransferSequence(UUID tid) {
        ensureSchema();
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = null;
        java.util.concurrent.locks.ReentrantLock lane = null;
        try {
            pool = new PoolDB();
            conn = pool.getConnection();

            // Claim the transfer atomically so the poller and the initiating request never both run it.
            pstmt = conn.prepareStatement(
                "UPDATE data_transfers SET status = 'Processing' WHERE transfer_id = ? AND status = 'Pending'");
            pstmt.setObject(1, tid);
            int claimed = pstmt.executeUpdate();
            pstmt.close();
            if (claimed == 0) return;

            String sql = "SELECT t.*, p.fqdn, cfg.storage_active_path, " +
                         "c.schema_definition, c.pii_fields, c.metadata as contract_metadata " +
                         "FROM data_transfers t " +
                         "JOIN partners p ON t.receiver_node_id = p.node_id " +
                         "JOIN data_contracts c ON t.contract_id = c.contract_id " +
                         "CROSS JOIN (SELECT storage_active_path FROM node_config LIMIT 1) cfg " +
                         "WHERE t.transfer_id = ?";
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, tid);
            rs = pstmt.executeQuery();

            if (!rs.next()) {
                updateStatus(tid, "Failed", "Receiver is not a registered partner or the contract no longer exists.");
                return;
            }

            final String targetFqdn = rs.getString("fqdn");
            final String fileName = rs.getString("file_name");
            final String contractId = rs.getString("contract_id");
            final String receiverNodeId = rs.getString("receiver_node_id");
            final String activePath = rs.getString("storage_active_path");
            final String checksum = rs.getString("file_checksum");
            final int attempt = rs.getInt("retry_count");

            final String senderNodeId = rs.getString("sender_node_id");
            JSONParser parser = new JSONParser();
            final JSONObject schemaDef = (JSONObject) parser.parse(rs.getString("schema_definition"));
            final JSONObject metadata = (JSONObject) parser.parse(rs.getString("contract_metadata"));
            final String format = metadata.get("format") != null ? metadata.get("format").toString().toLowerCase() : "json";

            // 1. Read the staged file
            Path filePath = SafeFilePath.resolve(activePath, fileName);
            if (!Files.exists(filePath)) { updateStatus(tid, "Failed", "Staged payload missing."); return; }
            byte[] fileBytes = Files.readAllBytes(filePath);

            // 2. Apply governance once. A retry finds the file already governed and must not transform it again.
            if (checksum == null || !checksum.startsWith("GOVERNED:")) {
                try {
                    fileBytes = applyGovernance(fileBytes, format, schemaDef, metadata);
                    Files.write(filePath, fileBytes);
                    markGoverned(conn, tid, fileBytes);
                } catch (Exception ge) {
                    updateStatus(tid, "Failed", "Governance Error: " + ge.getMessage());
                    return;
                }
            }

            // 3. Sequence, send and record under the lane lock so numbers go out in order and never collide.
            lane = laneLocks.computeIfAbsent(contractId + "|" + receiverNodeId, k -> new java.util.concurrent.locks.ReentrantLock());
            lane.lock();

            long nextSequence = getNextOutboundSequence(conn, UUID.fromString(contractId), receiverNodeId);
            Timestamp messageTimestamp = new Timestamp(System.currentTimeMillis());

            JSONObject payload = new JSONObject();
            payload.put("_func", "receive_transfer_stream");
            payload.put("transfer_id", tid.toString());
            payload.put("contract_id", contractId);
            payload.put("sender_node_id", senderNodeId);
            payload.put("file_name", fileName);
            payload.put("file_data", Base64.encodeToString(fileBytes));
            payload.put("sequence_number", nextSequence);
            payload.put("message_timestamp", messageTimestamp.toString());

            String protocol = (targetFqdn.contains(":443") || targetFqdn.contains(":8443")) ? "https://" : "http://";
            String targetUrl = (targetFqdn.startsWith("http") ? targetFqdn : protocol + targetFqdn) + "/api/admin/transfers";
            String body = payload.toJSONString();

            HttpRequest request = PeerAuth.sign(HttpRequest.newBuilder().uri(URI.create(targetUrl))
                    .header(P2P_HEADER, P2P_TOKEN)
                    .header("Content-Type", "application/json")
                    .header("X-DX-FUNCTION", "receive_transfer_stream")
                    .POST(HttpRequest.BodyPublishers.ofString(body)), body, receiverNodeId)
                    .build();

            HttpResponse<String> response;
            try {
                response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            } catch (IOException | InterruptedException io) {
                if (io instanceof InterruptedException) Thread.currentThread().interrupt();
                retryOrFail(tid, attempt, "Peer unreachable: " + io.getClass().getSimpleName() + ": " + io.getMessage());
                return;
            }

            int code = response.statusCode();
            if (code >= 200 && code < 300) {
                saveSequenceMetadata(conn, tid, nextSequence, messageTimestamp);
                updateStatus(tid, "Delivered", null);
            } else if (code >= 500 || code == 429 || code == 408) {
                retryOrFail(tid, attempt, "Peer returned HTTP " + code);
            } else {
                updateStatus(tid, "Failed", "Peer Rejected Protocol: HTTP " + code + " " + abbreviate(response.body()));
            }

        } catch (Exception e) {
            updateStatus(tid, "Failed", "System Error: " + e.getMessage());
            e.printStackTrace();
        } finally {
            if (lane != null && lane.isHeldByCurrentThread()) lane.unlock();
            try { if (pool != null) pool.cleanup(rs, pstmt, conn); } catch (Exception ignored) {}
        }
    }

    private static String abbreviate(String s) {
        if (s == null) return "";
        s = s.replaceAll("\\s+", " ").trim();
        return s.length() > 300 ? s.substring(0, 300) + "..." : s;
    }

    /** Records the checksum of the governed bytes so a retry knows the file is already governed. */
    private void markGoverned(Connection conn, UUID tid, byte[] governed) throws Exception {
        try (PreparedStatement ps = conn.prepareStatement("UPDATE data_transfers SET file_checksum = ?, file_size_bytes = ? WHERE transfer_id = ?")) {
            ps.setString(1, "GOVERNED:" + hashSha256(new String(governed, StandardCharsets.UTF_8)));
            ps.setLong(2, governed.length);
            ps.setObject(3, tid);
            ps.executeUpdate();
        }
    }

    /** Transport-level failure: put the transfer back to Pending with a backoff, or fail it for good. */
    private void retryOrFail(UUID tid, int previousAttempts, String reason) {
        int attempt = previousAttempts + 1;
        if (attempt >= MAX_ATTEMPTS) {
            updateStatus(tid, "Failed", reason + " (gave up after " + attempt + " attempts)");
            return;
        }
        long delay = BASE_RETRY_SECONDS * (long) Math.pow(4, previousAttempts);
        Connection conn = null; PreparedStatement pstmt = null; PoolDB pool = null;
        try {
            pool = new PoolDB();
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("UPDATE data_transfers SET status = 'Pending', retry_count = ?, " +
                    "next_retry_at = NOW() + (? * INTERVAL '1 second'), error_message = ? WHERE transfer_id = ?");
            pstmt.setInt(1, attempt);
            pstmt.setLong(2, delay);
            pstmt.setString(3, reason + " - attempt " + attempt + " of " + MAX_ATTEMPTS + ", retrying in " + delay + "s");
            pstmt.setObject(4, tid);
            pstmt.executeUpdate();
        } catch (Exception e) {
            updateStatus(tid, "Failed", reason);
        } finally {
            try { if (pool != null) pool.cleanup(null, pstmt, conn); } catch (Exception ignored) {}
        }
    }

    /**
     * REPLAY PROTECTION: RECEIVER PHASE
     * Validates an incoming P2P transfer against freshness and sequence monotonicity.
     * Called by DXManager or InterceptingFilter during reception.
     */
    public void verifyIncomingTransfer(String senderNodeId, UUID contractId, long incomingSeq, String timestampStr) throws SecurityException, SQLException {
        // 1. Freshness Check
        Timestamp incomingTs = Timestamp.valueOf(timestampStr);
        long drift = Math.abs(System.currentTimeMillis() - incomingTs.getTime());
        if (drift > FRESHNESS_THRESHOLD_MS) {
            throw new SecurityException("Replay Protection: Timestamp drift exceeds 5-minute window. Potential stale replay attack.");
        }

        // 2. Monotonicity Check
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            String sql = "SELECT MAX(sequence_number) FROM data_transfers WHERE sender_node_id = ? AND contract_id = ?";
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, senderNodeId);
            pstmt.setObject(2, contractId);
            rs = pstmt.executeQuery();
            
            long lastSeq = 0;
            if (rs.next()) lastSeq = rs.getLong(1);
            
            if (incomingSeq <= lastSeq) {
                throw new SecurityException("Replay Protection: Incoming sequence (" + incomingSeq + ") is not greater than last received (" + lastSeq + "). Transaction rejected.");
            }
        } finally { pool.cleanup(rs, pstmt, conn); }
    }

    private long getNextOutboundSequence(Connection conn, UUID contractId, String receiverNodeId) throws SQLException {
        String sql = "SELECT COALESCE(MAX(sequence_number), 0) + 1 FROM data_transfers " +
                     "WHERE contract_id = ? AND receiver_node_id = ?";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setObject(1, contractId);
            ps.setString(2, receiverNodeId);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getLong(1) : 1;
            }
        }
    }

    private void saveSequenceMetadata(Connection conn, UUID tid, long seq, Timestamp ts) throws SQLException {
        String sql = "UPDATE data_transfers SET sequence_number = ?, message_timestamp = ? WHERE transfer_id = ?";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setLong(1, seq);
            ps.setTimestamp(2, ts);
            ps.setObject(3, tid);
            ps.executeUpdate();
        }
    }

    // -------------------------------------------------------------------------
    // SCHEMA ADDITIONS (idempotent; db/05_transfer_retry.sql does the same for fresh installs)
    // -------------------------------------------------------------------------

    private volatile boolean schemaReady = false;

    /** Runs once the database pool is usable (the listener starts before the application config is loaded). */
    private synchronized void ensureSchema() {
        if (schemaReady) return;
        Connection conn = null; Statement st = null; PoolDB pool = null;
        try {
            pool = new PoolDB();
            conn = pool.getConnection();
            st = conn.createStatement();
            st.execute("ALTER TABLE data_transfers ADD COLUMN IF NOT EXISTS retry_count INT NOT NULL DEFAULT 0");
            st.execute("ALTER TABLE data_transfers ADD COLUMN IF NOT EXISTS next_retry_at TIMESTAMP WITH TIME ZONE NULL");
            schemaReady = true;
        } catch (Exception e) {
            System.err.println("[TransferEngine] Schema check failed: " + e.getMessage());
        } finally {
            try { if (st != null) st.close(); } catch (Exception ignored) {}
            try { if (pool != null) pool.cleanup(null, null, conn); } catch (Exception ignored) {}
        }
    }

    // -------------------------------------------------------------------------
    // MAINTENANCE: retention purge and nonce clean-up
    // -------------------------------------------------------------------------

    /**
     * Deletes payload files of finished transfers whose contract retention period has elapsed and marks
     * the transfer row Purged (the metadata row is kept). Contracts without a retention period are kept.
     * Also removes sync nonces that expired more than 24 hours ago.
     * Safe to run repeatedly; also exposed to administrators as transfers/run_maintenance.
     */
    public synchronized JSONObject runMaintenance() throws Exception {
        ensureSchema();
        int purged = 0, missing = 0, nonces = 0;
        Connection conn = null; PreparedStatement ps = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        try {
            conn = pool.getConnection();
            String activePath = null;
            ps = conn.prepareStatement("SELECT storage_active_path FROM node_config LIMIT 1");
            rs = ps.executeQuery();
            if (rs.next()) activePath = rs.getString(1);
            rs.close(); ps.close();

            if (activePath != null) {
                ps = conn.prepareStatement(
                    "SELECT t.transfer_id, t.file_name FROM data_transfers t " +
                    "JOIN data_contracts c ON c.contract_id = t.contract_id " +
                    "WHERE t.retention_status = 'Active' AND t.status IN ('Delivered','Received','Failed') " +
                    "AND t.end_time IS NOT NULL AND c.retention_policy_days IS NOT NULL " +
                    "AND t.end_time < NOW() - (c.retention_policy_days * INTERVAL '1 day') LIMIT 500");
                rs = ps.executeQuery();
                List<Object[]> due = new ArrayList<>();
                while (rs.next()) due.add(new Object[]{rs.getObject(1), rs.getString(2)});
                rs.close(); ps.close();

                for (Object[] d : due) {
                    try {
                        Path f = SafeFilePath.resolve(activePath, (String) d[1]);
                        if (Files.deleteIfExists(f)) purged++; else missing++;
                    } catch (Exception e) {
                        System.err.println("[TransferEngine] Could not purge " + d[1] + ": " + e.getMessage());
                        continue;
                    }
                    try (PreparedStatement up = conn.prepareStatement(
                            "UPDATE data_transfers SET retention_status = 'Purged', purged_at = NOW() WHERE transfer_id = ?")) {
                        up.setObject(1, d[0]);
                        up.executeUpdate();
                    }
                }
            }

            ps = conn.prepareStatement("DELETE FROM sync_nonces WHERE expires_at < NOW() - INTERVAL '24 hours'");
            nonces = ps.executeUpdate();
        } finally { pool.cleanup(rs, ps, conn); }

        JSONObject out = new JSONObject();
        out.put("success", true);
        out.put("payloads_purged", purged);
        out.put("payloads_already_missing", missing);
        out.put("nonces_removed", nonces);
        return out;
    }

    // -------------------------------------------------------------------------
    // RECEIVER-SIDE CONTRACT ENFORCEMENT
    // -------------------------------------------------------------------------

    /**
     * The receiver is the authority on its own contract, so it does not trust that a sender governed
     * the data. Checks an inbound payload against the receiver's copy of the contract:
     *   L1  structure against the schema (anonymised fields are exempt from value rules, because the
     *       sender has already replaced them with a mask, hash or token), and
     *   L2  every field the contract says must be anonymised actually is, in the declared form.
     * The payload is NOT transformed again, so hashing is never applied twice.
     *
     * @throws IllegalArgumentException with a "Contract Violation" message when the payload fails.
     */
    public void validateInbound(byte[] data, String format, JSONObject schema, JSONObject metadata) throws Exception {
        JSONObject anonRules = anonymisationRules(metadata);
        if ("csv".equals(format)) {
            validateInboundCsv(data, schema, anonRules);
            return;
        }
        String jsonStr = new String(data, StandardCharsets.UTF_8);
        JsonNode payloadNode = mapper.readTree(jsonStr);

        JSONObject relaxed = (JSONObject) new JSONParser().parse(schema.toJSONString());
        Object props = relaxed.get("properties");
        if (props instanceof JSONObject && anonRules != null) {
            for (Object field : anonRules.keySet()) {
                if (((JSONObject) props).containsKey(field)) ((JSONObject) props).put(field, new JSONObject());
            }
        }
        JsonSchema jsonSchema = JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V7).getSchema(relaxed.toJSONString());
        Set<ValidationMessage> assertions = jsonSchema.validate(payloadNode);
        if (!assertions.isEmpty()) {
            StringBuilder log = new StringBuilder("Contract Violation: ");
            for (ValidationMessage m : assertions) log.append("[").append(m.getMessage()).append("] ");
            throw new IllegalArgumentException(log.toString());
        }

        JSONObject payload = (JSONObject) new JSONParser().parse(jsonStr);
        if (anonRules != null) {
            for (Object key : anonRules.keySet()) {
                String field = (String) key;
                if (payload.containsKey(field)) requireAnonymised(field, payload.get(field), anonRules.get(field));
            }
        }
    }

    private void validateInboundCsv(byte[] data, JSONObject schema, JSONObject anonRules) {
        List<String> lines = Arrays.asList(new String(data, StandardCharsets.UTF_8).split("\\r?\\n"));
        if (lines.isEmpty() || lines.get(0).isBlank()) throw new IllegalArgumentException("Contract Violation: empty CSV payload.");
        String[] headers = lines.get(0).split(",");
        JSONArray fields = (JSONArray) schema.get("fields");
        List<String> expected = new ArrayList<>();
        if (fields != null) for (Object f : fields) expected.add(((JSONObject) f).get("name").toString());
        if (!Arrays.asList(headers).equals(expected)) {
            throw new IllegalArgumentException("Contract Violation: CSV header does not match the contract fields.");
        }
        if (anonRules == null) return;
        for (int i = 1; i < lines.size(); i++) {
            if (lines.get(i).isBlank()) continue;
            String[] values = lines.get(i).split(",");
            for (int j = 0; j < headers.length && j < values.length; j++) {
                Object rule = anonRules.get(headers[j]);
                if (rule != null) requireAnonymised(headers[j], values[j], rule);
            }
        }
    }

    private static JSONObject anonymisationRules(JSONObject metadata) {
        Object gr = metadata.get("governance_rules");
        if (!(gr instanceof JSONObject)) return null;
        Object ar = ((JSONObject) gr).get("pii_anonymization");
        return ar instanceof JSONObject ? (JSONObject) ar : null;
    }

    private static void requireAnonymised(String field, Object value, Object rule) {
        if (value == null) return;
        String v = value.toString();
        if (v.isEmpty()) return;
        String r = String.valueOf(rule).toUpperCase();
        boolean ok;
        switch (r) {
            case "MASK":     ok = v.matches("^\\*{4}.{0,4}$"); break;
            case "HASH":     ok = v.matches("^[0-9a-f]{64}$"); break;
            case "TOKENIZE": ok = v.matches("^\\[TOKEN:[0-9a-fA-F-]{36}\\]$"); break;
            default:         return;   // NONE or unknown: nothing to enforce
        }
        if (!ok) throw new IllegalArgumentException(
            "Contract Violation: field '" + field + "' must be anonymised (" + r + ") before it is sent.");
    }

    /** Same L2 conformance check for a response coming back from a partner (never re-applies the transform). */
    public void requireAnonymisedFields(JSONObject payload, JSONObject metadata) {
        JSONObject anonRules = anonymisationRules(metadata);
        if (anonRules == null) return;
        for (Object key : anonRules.keySet()) {
            String field = (String) key;
            if (payload.containsKey(field)) requireAnonymised(field, payload.get(field), anonRules.get(field));
        }
    }

    public byte[] applyGovernance(byte[] data, String format, JSONObject schema, JSONObject metadata) throws Exception {
        if ("csv".equals(format)) return processCsvGovernance(data, schema, metadata);
        return processJsonGovernance(data, schema, metadata);
    }

    /**
     * Applies only L2 PII anonymization to a JSON payload, skipping L1 schema validation.
     * Used for sync response payloads, which have a different structure than the request schema.
     */
    public byte[] applyPiiOnly(byte[] data, JSONObject metadata) throws Exception {
        String jsonStr = new String(data, StandardCharsets.UTF_8);
        JSONObject payload = (JSONObject) new JSONParser().parse(jsonStr);
        JSONObject governanceRules = (JSONObject) metadata.get("governance_rules");
        JSONObject anonRules = governanceRules != null ? (JSONObject) governanceRules.get("pii_anonymization") : null;
        if (anonRules != null) {
            for (Object key : anonRules.keySet()) {
                String fieldName = (String) key;
                if (payload.containsKey(fieldName)) payload.put(fieldName, transformValue(payload.get(fieldName), anonRules.get(fieldName).toString()));
            }
        }
        return payload.toJSONString().getBytes(StandardCharsets.UTF_8);
    }

    private byte[] processJsonGovernance(byte[] data, JSONObject schema, JSONObject metadata) throws Exception {
        String jsonStr = new String(data, StandardCharsets.UTF_8);
        JsonNode payloadNode = mapper.readTree(jsonStr);
        JsonSchemaFactory factory = JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V7);
        JsonSchema jsonSchema = factory.getSchema(schema.toJSONString());
        
        Set<ValidationMessage> assertions = jsonSchema.validate(payloadNode);
        if (!assertions.isEmpty()) {
            StringBuilder errorLog = new StringBuilder("Contract Violation: ");
            for (ValidationMessage msg : assertions) errorLog.append("[").append(msg.getMessage()).append("] ");
            throw new IllegalArgumentException(errorLog.toString());
        }

        JSONObject payload = (JSONObject) new JSONParser().parse(jsonStr);
        JSONObject governanceRules = (JSONObject) metadata.get("governance_rules");
        JSONObject anonRules = governanceRules != null ? (JSONObject) governanceRules.get("pii_anonymization") : null;
        
        if (anonRules != null) {
            for (Object key : anonRules.keySet()) {
                String fieldName = (String) key;
                if (payload.containsKey(fieldName)) payload.put(fieldName, transformValue(payload.get(fieldName), anonRules.get(fieldName).toString()));
            }
        }
        return payload.toJSONString().getBytes(StandardCharsets.UTF_8);
    }

    private byte[] processCsvGovernance(byte[] data, JSONObject schema, JSONObject metadata) throws Exception {
        String csvStr = new String(data, StandardCharsets.UTF_8);
        List<String> lines = Arrays.asList(csvStr.split("\\r?\\n"));
        if (lines.isEmpty()) throw new IllegalArgumentException("Empty CSV payload.");

        String[] headers = lines.get(0).split(",");
        JSONArray fields = (JSONArray) schema.get("fields");
        List<String> expectedHeaders = (List<String>) fields.stream().map(f -> ((JSONObject)f).get("name").toString()).collect(Collectors.toList());

        if (headers.length != expectedHeaders.size()) throw new IllegalArgumentException("CSV Header mismatch.");

        JSONObject governanceRules = (JSONObject) metadata.get("governance_rules");
        JSONObject anonRules = governanceRules != null ? (JSONObject) governanceRules.get("pii_anonymization") : null;
        StringBuilder processedCsv = new StringBuilder(lines.get(0)).append("\n");

        for (int i = 1; i < lines.size(); i++) {
            String[] values = lines.get(i).split(",");
            String[] processedValues = new String[headers.length];
            for (int j = 0; j < headers.length; j++) {
                String val = (j < values.length) ? values[j] : "";
                String rule = anonRules != null ? (String) anonRules.get(headers[j]) : "NONE";
                processedValues[j] = (rule != null && !"NONE".equals(rule)) ? transformValue(val, rule) : val;
            }
            processedCsv.append(String.join(",", processedValues)).append("\n");
        }
        return processedCsv.toString().getBytes(StandardCharsets.UTF_8);
    }

    private String transformValue(Object value, String method) {
        if (value == null) return "";
        String valStr = value.toString();
        switch (method.toUpperCase()) {
            case "MASK": return valStr.length() > 4 ? "****" + valStr.substring(valStr.length() - 4) : "****";
            case "HASH": return hashSha256(valStr);
            case "TOKENIZE": return "[TOKEN:" + UUID.nameUUIDFromBytes(valStr.getBytes(StandardCharsets.UTF_8)) + "]";
            default: return valStr;
        }
    }

    private String hashSha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) { return "HASH_ERROR"; }
    }

    private void updateStatus(UUID tid, String status, String error) {
        Connection conn = null; PreparedStatement pstmt = null; PoolDB pool = null;
        try {
            pool = new PoolDB();
            conn = pool.getConnection();
            String sql = "UPDATE data_transfers SET status = ?, error_message = ?, " +
                         "end_time = CASE WHEN ? IN ('Delivered', 'Failed') THEN NOW() ELSE end_time END " +
                         "WHERE transfer_id = ?";
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, status);
            pstmt.setString(2, error);
            pstmt.setString(3, status);
            pstmt.setObject(4, tid);
            pstmt.executeUpdate();
        } catch (Exception e) {
            System.err.println("[TransferEngine] Status Update Error: " + e.getMessage());
        } finally {
            try { if (pool != null) pool.cleanup(null, pstmt, conn); } catch (Exception ignored) {}
        }
    }

    @Override public void contextDestroyed(ServletContextEvent sce) {
        if (scheduler != null) scheduler.shutdownNow();
        if (transferPool != null) transferPool.shutdownNow();
    }
}