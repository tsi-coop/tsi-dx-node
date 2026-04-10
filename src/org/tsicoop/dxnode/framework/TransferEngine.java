package org.tsicoop.dxnode.framework;

import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.sql.*;
import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.*;

/**
 * Orchestration engine for P2P Data Transfers.
 * Implements ServletContextListener for lifecycle management and background polling.
 * Enhanced to handle large file streaming directly from disk to the network socket.
 */
public class TransferEngine implements ServletContextListener {

    private static TransferEngine instance;
    private ScheduledExecutorService scheduler;
    private ExecutorService transferPool;
    private final HttpClient httpClient;
    
    private static final String P2P_HEADER = "X-DX-P2P-HANDSHAKE";
    private static final String P2P_TOKEN = "DX-P2P-PROTOCOL-V1";
    private static final int MAX_CONCURRENT_TRANSFERS = 10;

    public TransferEngine() {
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(60)) // Increased timeout for heavy P2P streams
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
    }

    /**
     * Singleton accessor for immediate transfer triggering from API handlers.
     */
    public static synchronized TransferEngine getInstance() {
        if (instance == null) instance = new TransferEngine();
        return instance;
    }

    @Override
    public void contextInitialized(ServletContextEvent sce) {
        System.out.println("[TransferEngine] Initializing P2P Orchestration Layer...");
        instance = this;

        // Pool for executing the actual P2P network calls
        transferPool = Executors.newFixedThreadPool(MAX_CONCURRENT_TRANSFERS);

        // Scheduler for picking up stuck or missed transfers every 2 minutes
        scheduler = Executors.newSingleThreadScheduledExecutor();
        scheduler.scheduleAtFixedRate(this::pollAndProcessPending, 1, 2, TimeUnit.MINUTES);
    }

    /**
     * Triggers a specific transfer immediately (e.g., called by DXManager after registration).
     */
    public void startTransfer(UUID transferId) {
        if (transferPool != null && !transferPool.isShutdown()) {
            transferPool.submit(() -> executeTransferSequence(transferId));
        }
    }

    /**
     * Polls the database for transfers that are stuck in 'Pending' or 'Processing', ensuring recovery after node restarts.
     */
    private void pollAndProcessPending() {
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = null;
        try {
            pool = new PoolDB();
            conn = pool.getConnection();
            String sql = "SELECT transfer_id FROM data_transfers " +
                         "WHERE status = 'Pending' " +
                         "ORDER BY start_time ASC LIMIT 5 FOR UPDATE SKIP LOCKED";
            
            pstmt = conn.prepareStatement(sql);
            rs = pstmt.executeQuery();
            while (rs.next()) {
                startTransfer(UUID.fromString(rs.getString("transfer_id")));
            }
        } catch (Exception e) {
            System.err.println("[TransferEngine] Polling failed: " + e.getMessage());
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }

    private void executeTransferSequence(UUID tid) {
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = null;
        try {
            pool = new PoolDB();
            conn = pool.getConnection();
            
            // 1. Fetch Context: Identity, Peer, and Storage Configuration
            String sql = "SELECT t.*, p.fqdn, c.metadata as contract_meta, cfg.storage_active_path " +
                         "FROM data_transfers t " +
                         "JOIN partners p ON t.receiver_node_id = p.node_id " +
                         "JOIN data_contracts c ON t.contract_id = c.contract_id " +
                         "CROSS JOIN (SELECT storage_active_path FROM node_config LIMIT 1) cfg " +
                         "WHERE t.transfer_id = ?";
            
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, tid);
            rs = pstmt.executeQuery();

            if (!rs.next()) return;

            String targetFqdn = rs.getString("fqdn");
            String fileName = rs.getString("file_name");
            String contractId = rs.getString("contract_id");
            String senderNodeId = rs.getString("sender_node_id");
            String activePath = rs.getString("storage_active_path");
            
            // Extract transfer architecture (Structured vs Stream) from contract metadata
            String category = "structured";
            try {
                JSONObject meta = (JSONObject) new JSONParser().parse(rs.getString("contract_meta"));
                category = (String) meta.getOrDefault("transfer_category", "structured");
            } catch (Exception e) { /* Fallback to structured */ }

            updateStatus(tid, "Processing", null);

            // 2. Build Protocol Header with Metadata
            String targetUrl = (targetFqdn.startsWith("http") ? targetFqdn : "http://" + targetFqdn) + "/api/admin/transfers";
            
            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                    .uri(URI.create(targetUrl))
                    .header(P2P_HEADER, P2P_TOKEN)
                    .header("X-DX-FUNCTION", "receive_transfer_stream")
                    .header("X-DX-TRANSFER-ID", tid.toString())
                    .header("X-DX-CONTRACT-ID", contractId)
                    .header("X-DX-SENDER-ID", senderNodeId)
                    .header("X-DX-FILE-NAME", fileName)
                    .header("X-DX-SEQUENCE", String.valueOf(System.currentTimeMillis()));

            // 3. mTLS P2P Transmission: Conditional Streaming
            if ("stream".equalsIgnoreCase(category)) {
                // BINARY STREAMING: Direct Disk-to-Socket piping using BodyPublishers.ofFile
                Path filePath = Path.of(activePath, fileName);
                System.out.println("[TransferEngine] Initiating Outbound Stream: " + filePath);
                requestBuilder.POST(HttpRequest.BodyPublishers.ofFile(filePath));
            } else {
                // STRUCTURED DATA: Sending JSON payload in body
                JSONObject payload = new JSONObject();
                payload.put("_func", "receive_transfer_stream");
                payload.put("transfer_id", tid.toString());
                payload.put("contract_id", contractId);
                payload.put("sender_node_id", senderNodeId);
                payload.put("file_name", fileName);
                
                requestBuilder.header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(payload.toJSONString()));
            }

            System.out.println("[TransferEngine] Dispatching Sequence -> " + targetUrl + " (Mode: " + category + ")");
            HttpResponse<String> response = httpClient.send(requestBuilder.build(), HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() >= 200 && response.statusCode() < 300) {
                updateStatus(tid, "Delivered", null);
                System.out.println("[TransferEngine] Sequence SUCCESS: " + tid);
            } else {
                updateStatus(tid, "Failed", "Peer rejection: HTTP " + response.statusCode() + " - " + response.body());
            }

        } catch (Exception e) {
            updateStatus(tid, "Failed", "Network/Protocol Error: " + e.getMessage());
            e.printStackTrace();
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
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
            pool.cleanup(null, pstmt, conn);
        }
    }

    @Override
    public void contextDestroyed(ServletContextEvent sce) {
        System.out.println("[TransferEngine] Shutting down P2P Orchestration...");
        if (scheduler != null) scheduler.shutdownNow();
        if (transferPool != null) {
            try {
                transferPool.shutdown();
                if (!transferPool.awaitTermination(30, TimeUnit.SECONDS)) {
                    transferPool.shutdownNow();
                }
            } catch (InterruptedException e) {
                transferPool.shutdownNow();
            }
        }
    }
}