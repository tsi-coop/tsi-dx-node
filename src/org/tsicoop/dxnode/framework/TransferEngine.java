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
        scheduler.scheduleAtFixedRate(this::pollAndProcessPending, 1, 2, TimeUnit.MINUTES);
    }

    public void startTransfer(UUID transferId) {
        if (transferPool != null && !transferPool.isShutdown()) {
            transferPool.submit(() -> executeTransferSequence(transferId));
        }
    }

    private void pollAndProcessPending() {
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = null;
        try {
            pool = new PoolDB();
            conn = pool.getConnection();
            String sql = "SELECT transfer_id FROM data_transfers WHERE status = 'Pending' " +
                         "ORDER BY start_time ASC LIMIT 5 FOR UPDATE SKIP LOCKED";
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

    private void executeTransferSequence(UUID tid) {
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = null;
        try {
            pool = new PoolDB();
            conn = pool.getConnection();
            
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

            if (!rs.next()) return;

            final String targetFqdn = rs.getString("fqdn");
            final String fileName = rs.getString("file_name");
            final String contractId = rs.getString("contract_id");
            final String senderNodeId = rs.getString("sender_node_id");
            final String receiverNodeId = rs.getString("receiver_node_id");
            final String activePath = rs.getString("storage_active_path");
            
            JSONParser parser = new JSONParser();
            final JSONObject schemaDef = (JSONObject) parser.parse(rs.getString("schema_definition"));
            final JSONObject metadata = (JSONObject) parser.parse(rs.getString("contract_metadata"));
            final String format = metadata.get("format") != null ? metadata.get("format").toString().toLowerCase() : "json";
            
            updateStatus(tid, "Processing", null);

            // --- REPLAY PROTECTION: SENDER PHASE ---
            // 1. Generate unique Monotonic Sequence and Timestamp
            long nextSequence = getNextOutboundSequence(conn, UUID.fromString(contractId), receiverNodeId);
            Timestamp messageTimestamp = new Timestamp(System.currentTimeMillis());

            // 2. Read staged file
            Path filePath = Path.of(activePath, fileName);
            if (!Files.exists(filePath)) throw new IOException("Staged payload missing at: " + filePath);
            byte[] fileBytes = Files.readAllBytes(filePath);

            // 3. Apply Governance (Anonymization mirrored locally)
            try {
                fileBytes = applyGovernance(fileBytes, format, schemaDef, metadata);
                Files.write(filePath, fileBytes);
            } catch (Exception ge) {
                updateStatus(tid, "Failed", "Governance Error: " + ge.getMessage());
                return;
            }

            // 4. Construct Governed P2P Payload
            String base64Payload = Base64.encodeToString(fileBytes);
            JSONObject payload = new JSONObject();
            payload.put("_func", "receive_transfer_stream");
            payload.put("transfer_id", tid.toString());
            payload.put("contract_id", contractId);
            payload.put("sender_node_id", senderNodeId);
            payload.put("file_name", fileName);
            payload.put("file_data", base64Payload);
            
            // SECURITY ATTACHMENTS
            payload.put("sequence_number", nextSequence);
            payload.put("message_timestamp", messageTimestamp.toString());

            // 5. Dispatch
            String protocol = (targetFqdn.contains(":443") || targetFqdn.contains(":8443")) ? "https://" : "http://";
            String targetUrl = (targetFqdn.startsWith("http") ? targetFqdn : protocol + targetFqdn) + "/api/admin/transfers";
            
            HttpRequest request = HttpRequest.newBuilder().uri(URI.create(targetUrl))
                    .header(P2P_HEADER, P2P_TOKEN)
                    .header("Content-Type", "application/json")
                    .header("X-DX-FUNCTION", "receive_transfer_stream")
                    .POST(HttpRequest.BodyPublishers.ofString(payload.toJSONString()))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() >= 200 && response.statusCode() < 300) {
                // Persist successful sequence in DB
                saveSequenceMetadata(conn, tid, nextSequence, messageTimestamp);
                updateStatus(tid, "Delivered", null);
            } else {
                updateStatus(tid, "Failed", "Peer Rejected Protocol: HTTP " + response.statusCode());
            }

        } catch (Exception e) {
            updateStatus(tid, "Failed", "System Error: " + e.getMessage());
            e.printStackTrace();
        } finally {
            try { if (pool != null) pool.cleanup(rs, pstmt, conn); } catch (Exception ignored) {}
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

    private byte[] applyGovernance(byte[] data, String format, JSONObject schema, JSONObject metadata) throws Exception {
        if ("csv".equals(format)) return processCsvGovernance(data, schema, metadata);
        return processJsonGovernance(data, schema, metadata);
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