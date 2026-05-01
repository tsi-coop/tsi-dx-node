package org.tsicoop.dxnode.api.admin;

import org.tsicoop.dxnode.framework.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONObject;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Service to manage Node Configuration and Protocol Identity.
 * REVISED: Completely removed 'name' column to align with existing DB schema.
 * Implements adaptive PEM normalization that detects and preserves specific
 * PKCS labels (e.g., RSA PRIVATE KEY) to ensure cryptographic validity.
 *
 * FIX: normalizePemString now normalizes line endings BEFORE label detection.
 * importCertificateAndActivate now uses java.time.Instant for parsing ISO 
 * timestamps with 'Z' suffixes to prevent DateTimeParseException.
 */
public class Node implements Action {

    private static final UUID NODE_CONFIG_SINGLETON_ID = UUID.fromString("00000000-0000-0000-0000-000000000001");

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        System.err.println("[Node TRACE] Processing POST request: " + req.getRequestURI());
        JSONObject input = null;
        JSONObject output = null;

        try {
            input = InputProcessor.getInput(req);
            String func = (String) input.get("_func");

            if (func == null || func.trim().isEmpty()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required '_func' attribute.", req.getRequestURI());
                return;
            }

            switch (func.toLowerCase()) {
                case "import_node_certificate":
                    System.err.println("[Node DEBUG] Attempting Identity Activation via File Ingest...");
                    String certRaw = (String) input.get("certificate_pem");
                    String keyRaw  = (String) input.get("private_key_pem");

                    if (certRaw == null || certRaw.isEmpty() || keyRaw == null || keyRaw.isEmpty()) {
                        OutputProcessor.errorResponse(res, 400, "Bad Request", "Missing PEM strings.", req.getRequestURI());
                        return;
                    }

                    // --- ADAPTIVE PEM NORMALIZATION ---
                    String cleanCert = normalizePemString(certRaw, "CERTIFICATE");
                    String cleanKey  = normalizePemString(keyRaw, null);

                    output = importCertificateAndActivate(cleanCert, cleanKey);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
                    break;

                case "get_node_status":
                    output = getNodeStatus();
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
                    break;

                case "get_node_config":
                    output = getNodeConfig();
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
                    break;

                case "upsert_node_config":
                    output = upsertNodeConfig(
                        (String) input.get("node_id"),
                        (String) input.get("fqdn"),
                        (int)(long) input.get("network_port"),
                        (String) input.get("storage_active_path"),
                        (String) input.get("storage_archive_path"),
                        (String) input.get("logging_level")
                    );
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
                    break;

                default:
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Unknown '_func': " + func, req.getRequestURI());
                    break;
            }
        } catch (IllegalArgumentException e) {
            System.err.println("[Node ERROR] Validation Failure: " + e.getMessage());
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", e.getMessage(), req.getRequestURI());
        } catch (Exception e) {
            System.err.println("[Node ERROR] System Exception: " + e.getMessage());
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Error", e.getMessage(), req.getRequestURI());
        }
    }

    /**
     * Normalizes a PEM string with strict line wrapping and auto-detection of headers.
     */
    private String normalizePemString(String input, String defaultType) {
        if (input == null) return null;

        String s = input.trim()
                        .replaceAll("\r\n", "\n")
                        .replaceAll("\r", "\n");

        String label = null;

        if (s.contains("BEGIN RSA PRIVATE KEY")) {
            label = "RSA PRIVATE KEY";
        } else if (s.contains("BEGIN EC PRIVATE KEY")) {
            label = "EC PRIVATE KEY";
        } else if (s.contains("BEGIN PRIVATE KEY")) {
            label = "PRIVATE KEY";
        } else if (s.contains("BEGIN CERTIFICATE")) {
            label = "CERTIFICATE";
        }

        if (label == null) {
            if (defaultType == null) {
                throw new IllegalArgumentException("PEM input has no recognizable header.");
            }
            label = defaultType;
        }

        String beginMarker = "-----BEGIN " + label + "-----";
        String endMarker   = "-----END "   + label + "-----";

        String base64 = s.replaceAll("-----BEGIN [^-]+-----", "")
                         .replaceAll("-----END [^-]+-----", "")
                         .replaceAll("\\s+", "");

        StringBuilder sb = new StringBuilder(beginMarker).append("\n");
        for (int i = 0; i < base64.length(); i++) {
            sb.append(base64.charAt(i));
            if ((i + 1) % 64 == 0) sb.append("\n");
        }
        if (base64.length() % 64 != 0) sb.append("\n");
        sb.append(endMarker);

        return sb.toString();
    }

    private JSONObject importCertificateAndActivate(String certificatePem, String privateKeyPem) throws Exception {
        System.err.println("[Node DEBUG] Calling PKIUtil validation...");

        String effectiveKey = privateKeyPem;
        if (!PKIUtil.isCertificatePrivateKeyMatch(certificatePem, effectiveKey)) {
            System.err.println("[Node DEBUG] Initial key validation failed. Attempting PKCS#1 re-wrap...");
            effectiveKey = normalizePemString(privateKeyPem, "RSA PRIVATE KEY");
            if (!PKIUtil.isCertificatePrivateKeyMatch(certificatePem, effectiveKey)) {
                throw new IllegalArgumentException("Certificate and private key do not match.");
            }
        }

        JSONObject certDetails  = PKIUtil.getCertificateDetails(certificatePem);
        String    fqdnFromCert  = (String) certDetails.get("common_name");
        
        // FIX: Use Instant.parse to handle 'Z' suffix in timestamps like '2027-04-22T11:49:03Z'
        Timestamp expiresAt     = Timestamp.from(Instant.parse((String) certDetails.get("expires_at_iso")));
        Timestamp issuedAt      = Timestamp.from(Instant.parse((String) certDetails.get("issued_at_iso")));

        Connection        conn            = null;
        PreparedStatement pstmtUpdateOld  = null;
        PreparedStatement pstmtUpdateFqdn = null;
        PoolDB            pool            = new PoolDB();

        try {
            conn = pool.getConnection();
            conn.setAutoCommit(false);

            pstmtUpdateOld = conn.prepareStatement(
                "UPDATE node_certificates SET is_active = FALSE, updated_at = NOW() WHERE node_config_id = ? AND is_active = TRUE");
            pstmtUpdateOld.setObject(1, NODE_CONFIG_SINGLETON_ID);
            pstmtUpdateOld.executeUpdate();

            saveCertificateToDb(NODE_CONFIG_SINGLETON_ID, certificatePem, effectiveKey, true, issuedAt, expiresAt);

            pstmtUpdateFqdn = conn.prepareStatement(
                "UPDATE node_config SET fqdn = ?, updated_at = NOW() WHERE config_id = ?");
            pstmtUpdateFqdn.setString(1, fqdnFromCert);
            pstmtUpdateFqdn.setObject(2, NODE_CONFIG_SINGLETON_ID);
            pstmtUpdateFqdn.executeUpdate();

            conn.commit();
            System.err.println("[Node DEBUG] Identity activation successful for " + fqdnFromCert);
            return new JSONObject() {{ put("success", true); put("message", "Identity activated for: " + fqdnFromCert); }};
        } catch (SQLException e) {
            if (conn != null) conn.rollback();
            throw e;
        } finally {
            if (pstmtUpdateFqdn != null) pstmtUpdateFqdn.close();
            pool.cleanup(null, pstmtUpdateOld, conn);
        }
    }

    private void saveCertificateToDb(UUID nodeConfigId, String certificatePem, String privateKeyPem,
                                     boolean isActive, Timestamp issuedAt, Timestamp expiresAt) throws SQLException {
        Connection conn = null; PreparedStatement pstmt = null; PoolDB pool = new PoolDB();
        String sql = "INSERT INTO node_certificates (node_config_id, certificate_pem, private_key_pem, is_active, issued_at, expires_at) "
                   + "VALUES (?, ?, ?, ?, ?, ?)";
        try {
            conn  = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, nodeConfigId);
            pstmt.setString(2, certificatePem);
            pstmt.setString(3, privateKeyPem);
            pstmt.setBoolean(4, isActive);
            pstmt.setTimestamp(5, issuedAt);
            pstmt.setTimestamp(6, expiresAt);
            pstmt.executeUpdate();
        } finally { pool.cleanup(null, pstmt, conn); }
    }

    private JSONObject getNodeStatus() throws SQLException {
        JSONObject status = new JSONObject();
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        try {
            conn  = pool.getConnection();
            pstmt = conn.prepareStatement("SELECT node_id, fqdn FROM node_config WHERE config_id = ?");
            pstmt.setObject(1, NODE_CONFIG_SINGLETON_ID);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                status.put("node_id", rs.getString("node_id"));
                status.put("fqdn",    rs.getString("fqdn"));
                status.put("status",  "Online");
            }
        } finally { pool.cleanup(rs, pstmt, conn); }
        return new JSONObject() {{ put("success", true); put("data", status); }};
    }

    private JSONObject getNodeConfig() throws SQLException {
        JSONObject config = new JSONObject();
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null; PoolDB pool = new PoolDB();
        try {
            conn  = pool.getConnection();
            pstmt = conn.prepareStatement(
                "SELECT node_id, fqdn, network_port, storage_active_path, storage_archive_path, logging_level "
                + "FROM node_config WHERE config_id = ?");
            pstmt.setObject(1, NODE_CONFIG_SINGLETON_ID);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                config.put("node_id",               rs.getString("node_id"));
                config.put("fqdn",                  rs.getString("fqdn"));
                config.put("network_port",           rs.getInt("network_port"));
                config.put("storage_active_path",    rs.getString("storage_active_path"));
                config.put("storage_archive_path",   rs.getString("storage_archive_path"));
                config.put("logging_level",          rs.getString("logging_level"));
            }
        } finally { pool.cleanup(rs, pstmt, conn); }
        return new JSONObject() {{ put("success", true); put("data", config); }};
    }

    private JSONObject upsertNodeConfig(String nodeId, String fqdn, int networkPort,
                                        String activePath, String archivePath, String logLevel) throws SQLException {
        Connection conn = null; PreparedStatement pstmt = null; PoolDB pool = new PoolDB();
        String sql = "INSERT INTO node_config (config_id, node_id, fqdn, network_port, storage_active_path, storage_archive_path, logging_level) "
                   + "VALUES (?, ?, ?, ?, ?, ?, ?) "
                   + "ON CONFLICT (config_id) DO UPDATE SET "
                   + "node_id = EXCLUDED.node_id, fqdn = EXCLUDED.fqdn, network_port = EXCLUDED.network_port, "
                   + "storage_active_path = EXCLUDED.storage_active_path, storage_archive_path = EXCLUDED.storage_archive_path, "
                   + "logging_level = EXCLUDED.logging_level, updated_at = NOW()";
        try {
            conn  = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, NODE_CONFIG_SINGLETON_ID);
            pstmt.setString(2, nodeId);   pstmt.setString(3, fqdn);        pstmt.setInt(4, networkPort);
            pstmt.setString(5, activePath); pstmt.setString(6, archivePath); pstmt.setString(7, logLevel);
            pstmt.executeUpdate();
        } finally { pool.cleanup(null, pstmt, conn); }
        return new JSONObject() {{ put("success", true); put("message", "Node configuration synchronized."); }};
    }

    @Override public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) { return true; }
    @Override public void get(HttpServletRequest req, HttpServletResponse res) {}
    @Override public void put(HttpServletRequest req, HttpServletResponse res) {}
    @Override public void delete(HttpServletRequest req, HttpServletResponse res) {}
}