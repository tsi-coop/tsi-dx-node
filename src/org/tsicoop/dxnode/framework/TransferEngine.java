package org.tsicoop.dxnode.framework;

import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import org.json.simple.JSONObject;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.*;
import java.time.Duration;
import java.util.Base64;
import java.util.UUID;
import java.util.concurrent.*;

/**
 * Orchestration engine for P2P Data Transfers.
 * Standardized on JSON-based exchanges using Base64 encoded payloads.
 * This engine reads staged files from disk and pipes them to partner nodes 
 * as structured JSON, bypassing the complexities of binary streaming.
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
                .connectTimeout(Duration.ofSeconds(60))
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
        System.out.println("[TransferEngine] Initializing JSON-based P2P Orchestration...");
        instance = this;

        // Pool for executing outbound JSON P2P calls
        transferPool = Executors.newFixedThreadPool(MAX_CONCURRENT_TRANSFERS);

        // Scheduler for picking up stuck transfers (recovery logic)
        scheduler = Executors.newSingleThreadScheduledExecutor();
        scheduler.scheduleAtFixedRate(this::pollAndProcessPending, 1, 2, TimeUnit.MINUTES);
    }

    /**
     * Triggers a specific transfer immediately.
     */
    public void startTransfer(UUID transferId) {
        if (transferPool != null && !transferPool.isShutdown()) {
            transferPool.submit(() -> executeTransferSequence(transferId));
        }
    }

    /**
     * Periodically recovers pending transfers from the database.
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
            // COMPILATION FIX: Catch potential SQLException in cleanup
            try { pool.cleanup(rs, pstmt, conn); } catch (Exception ignored) {}
        }
    }

    /**
     * The core P2P protocol sequence: Metadata Retrieval -> File Reading -> Base64 Encoding -> JSON POST.
     */
    private void executeTransferSequence(UUID tid) {
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = null;
        try {
            pool = new PoolDB();
            conn = pool.getConnection();
            
            // 1. Fetch Metadata and Local Storage Config
            String sql = "SELECT t.*, p.fqdn, cfg.storage_active_path " +
                         "FROM data_transfers t " +
                         "JOIN partners p ON t.receiver_node_id = p.node_id " +
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
            
            updateStatus(tid, "Processing", null);

            // 2. Read the file from the staging area and encode to Base64
            // This ensures compatibility with the receiver's JSON input processing.
            Path filePath = Path.of(activePath, fileName);
            if (!Files.exists(filePath)) {
                throw new IOException("Staged payload not found at: " + filePath);
            }
            
            byte[] fileBytes = Files.readAllBytes(filePath);
            String base64Payload = Base64.getEncoder().encodeToString(fileBytes);

            // 3. Construct Unified JSON Protocol Message
            JSONObject payload = new JSONObject();
            payload.put("_func", "receive_transfer_stream");
            payload.put("transfer_id", tid.toString());
            payload.put("contract_id", contractId);
            payload.put("sender_node_id", senderNodeId);
            payload.put("file_name", fileName);
            payload.put("file_data", base64Payload);

            // 4. Execute standard JSON API call to the partner node
            String targetUrl = (targetFqdn.startsWith("http") ? targetFqdn : "http://" + targetFqdn) + "/api/admin/transfers";
            
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(targetUrl))
                    .header(P2P_HEADER, P2P_TOKEN)
                    .header("Content-Type", "application/json")
                    .header("X-DX-FUNCTION", "receive_transfer_stream")
                    .header("X-DX-TRANSFER-ID", tid.toString())
                    .POST(HttpRequest.BodyPublishers.ofString(payload.toJSONString()))
                    .build();

            System.out.println("[TransferEngine] Dispatching JSON P2P Transfer (" + fileBytes.length + " bytes) -> " + targetUrl);
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() >= 200 && response.statusCode() < 300) {
                updateStatus(tid, "Delivered", null);
                System.out.println("[TransferEngine] Transfer Sequence SUCCESS: " + tid);
            } else {
                updateStatus(tid, "Failed", "Peer rejected transfer: HTTP " + response.statusCode() + " - " + response.body());
            }

        } catch (Exception e) {
            updateStatus(tid, "Failed", "P2P Protocol Failure: " + e.getMessage());
            e.printStackTrace();
        } finally {
            // COMPILATION FIX: Catch potential SQLException in cleanup
            try { pool.cleanup(rs, pstmt, conn); } catch (Exception ignored) {}
        }
    }

    /**
     * Updates the transfer registry with the latest lifecycle status.
     */
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
            // COMPILATION FIX: Catch potential SQLException in cleanup
            try { pool.cleanup(null, pstmt, conn); } catch (Exception ignored) {}
        }
    }

    @Override
    public void contextDestroyed(ServletContextEvent sce) {
        System.out.println("[TransferEngine] Shutting down JSON P2P Orchestration...");
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