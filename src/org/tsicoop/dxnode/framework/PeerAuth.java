package org.tsicoop.dxnode.framework;

import jakarta.servlet.http.HttpServletRequest;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.json.simple.JSONObject;

import java.io.StringReader;
import java.net.http.HttpRequest;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.Base64;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Message-level authentication between nodes.
 *
 * Every peer-to-peer request is signed with the sending node's identity key and verified by the
 * receiver against the public key registered for that partner. This is what authenticates a peer:
 * the {@code X-DX-P2P-HANDSHAKE} header only routes a request to the peer-function allow-list, it is
 * a fixed public value and proves nothing by itself.
 *
 * Canonical string signed (SHA256withRSA, or SHA256withECDSA for EC keys), lines joined with \n:
 * <pre>
 *   DX-P2P-SIG-V1
 *   &lt;sender node id&gt;          X-DX-NODE-ID
 *   &lt;target node id or empty&gt; X-DX-TARGET-NODE-ID
 *   &lt;function&gt;                _func of the body
 *   &lt;timestamp ms&gt;            X-DX-TIMESTAMP
 *   &lt;request id&gt;              X-DX-REQUEST-ID
 *   &lt;hex SHA-256 of the body, whitespace-trimmed&gt;
 * </pre>
 *
 * Receivers also enforce a +/-5 minute clock window, single use of the request id, that the target
 * (when present) is this node, and that any {@code sender_node_id} in the body equals the signer.
 *
 * Only the two bootstrap functions ({@link #BOOTSTRAP_FUNCS}) may arrive unsigned, because the
 * sender is not yet a known partner when they are sent; they only create Pending records that an
 * administrator has to accept.
 */
public final class PeerAuth {

    public static final String H_NODE   = "X-DX-NODE-ID";
    public static final String H_TARGET = "X-DX-TARGET-NODE-ID";
    public static final String H_TS     = "X-DX-TIMESTAMP";
    public static final String H_REQID  = "X-DX-REQUEST-ID";
    public static final String H_SIG    = "X-DX-SIGNATURE";
    public static final String ATTR_PEER = "dx.peer.node_id";

    public static final Set<String> BOOTSTRAP_FUNCS = Set.of("probe", "receive_partnership_proposal");

    private static final long MAX_SKEW_MS = 5 * 60 * 1000L;
    private static final int  MAX_SEEN    = 100_000;
    private static final ConcurrentHashMap<String, Long> SEEN = new ConcurrentHashMap<>();

    private PeerAuth() {}

    /** TSI_DX_NODE_P2P_SIGNATURES=optional accepts unsigned peer calls (rolling upgrades only). */
    private static boolean enforced() {
        return !"optional".equalsIgnoreCase(System.getenv("TSI_DX_NODE_P2P_SIGNATURES"));
    }

    // ------------------------------------------------------------------ signing

    /**
     * Adds the identity headers and signature to an outbound peer request.
     *
     * @param body         exact JSON text that will be sent
     * @param targetNodeId node id of the receiver, or null when not known
     */
    public static HttpRequest.Builder sign(HttpRequest.Builder builder, String body, String targetNodeId) {
        try {
            String[] id = loadLocalIdentity();   // {node_id, private_key_pem}
            if (id == null) return builder;       // node not initialised: send unsigned, receiver decides
            String func = functionOf(body);
            String ts = Long.toString(System.currentTimeMillis());
            String reqId = UUID.randomUUID().toString();
            String canonical = canonical(id[0], targetNodeId, func, ts, reqId, body);

            PrivateKey key = PKIUtil.parsePrivateKeyPem(id[1]);
            Signature sig = Signature.getInstance(algorithmFor(key.getAlgorithm()));
            sig.initSign(key);
            sig.update(canonical.getBytes(StandardCharsets.UTF_8));

            builder.header(H_NODE, id[0]).header(H_TS, ts).header(H_REQID, reqId)
                   .header(H_SIG, Base64.getEncoder().encodeToString(sig.sign()));
            if (targetNodeId != null && !targetNodeId.isEmpty()) builder.header(H_TARGET, targetNodeId);
        } catch (Exception e) {
            System.err.println("[PeerAuth] Could not sign peer request: " + e.getMessage());
        }
        return builder;
    }

    // ---------------------------------------------------------------- verifying

    /**
     * Verifies an inbound peer request. Returns null when it is acceptable, or a short reason when it
     * must be rejected with 401. On success the signer's node id is exposed as request attribute
     * {@link #ATTR_PEER}.
     */
    public static String verify(HttpServletRequest req, String func, String body) {
        String node = req.getHeader(H_NODE), ts = req.getHeader(H_TS), reqId = req.getHeader(H_REQID),
               sigB64 = req.getHeader(H_SIG), target = req.getHeader(H_TARGET);
        boolean bootstrap = func != null && BOOTSTRAP_FUNCS.contains(func.toLowerCase());
        boolean unsigned = node == null || ts == null || reqId == null || sigB64 == null;

        if (unsigned) {
            if (bootstrap || !enforced()) return null;
            return "Peer request is not signed.";
        }
        try {
            long t = Long.parseLong(ts.trim());
            if (Math.abs(System.currentTimeMillis() - t) > MAX_SKEW_MS) return "Peer request timestamp outside the allowed window.";

            String[] partner = loadPartnerKey(node);   // {public_key_pem, status}
            if (partner == null) {
                // Unknown signer. Only the bootstrap functions are allowed from a node we have not registered.
                return bootstrap ? null : "Signer is not a registered partner.";
            }
            if ("Terminated".equalsIgnoreCase(partner[1]) || "Inactive".equalsIgnoreCase(partner[1])) {
                return "Partner relationship is not active.";
            }
            if (target != null && !target.isEmpty()) {
                String local = loadLocalNodeId();
                if (local != null && !local.equals(target)) return "Request is addressed to a different node.";
            }

            PublicKey pub = parsePublicKey(partner[0]);
            Signature sig = Signature.getInstance(algorithmFor(pub.getAlgorithm()));
            sig.initVerify(pub);
            sig.update(canonical(node, target, func, ts.trim(), reqId, body).getBytes(StandardCharsets.UTF_8));
            if (!sig.verify(Base64.getDecoder().decode(sigB64.trim()))) return "Peer signature does not verify.";

            if (!claimRequestId(node + ":" + reqId, t)) return "Peer request id already used (replay).";

            // The body must not name a different sender than the one that signed it.
            Object bodySender = bodyField(body, "sender_node_id");
            if (bodySender instanceof String && !node.equals(bodySender)) return "sender_node_id does not match the signer.";

            req.setAttribute(ATTR_PEER, node);
            return null;
        } catch (Exception e) {
            return "Peer signature could not be verified.";
        }
    }

    // ------------------------------------------------------------------ helpers

    private static String canonical(String node, String target, String func, String ts, String reqId, String body) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] h = md.digest(body.strip().getBytes(StandardCharsets.UTF_8));
        StringBuilder hex = new StringBuilder();
        for (byte b : h) hex.append(String.format("%02x", b));
        return "DX-P2P-SIG-V1\n" + node + "\n" + (target == null ? "" : target) + "\n"
                + (func == null ? "" : func) + "\n" + ts + "\n" + reqId + "\n" + hex;
    }

    private static String algorithmFor(String keyAlg) {
        return "EC".equalsIgnoreCase(keyAlg) || "ECDSA".equalsIgnoreCase(keyAlg) ? "SHA256withECDSA" : "SHA256withRSA";
    }

    private static boolean claimRequestId(String id, long requestTs) {
        long now = System.currentTimeMillis();
        if (SEEN.size() > MAX_SEEN) SEEN.entrySet().removeIf(e -> now - e.getValue() > 2 * MAX_SKEW_MS);
        return SEEN.putIfAbsent(id, now) == null;
    }

    private static String functionOf(String body) {
        Object f = bodyField(body, "_func");
        return f instanceof String ? (String) f : "";
    }

    private static Object bodyField(String body, String name) {
        try {
            Object o = new org.json.simple.parser.JSONParser().parse(body);
            return o instanceof JSONObject ? ((JSONObject) o).get(name) : null;
        } catch (Exception e) {
            return null;
        }
    }

    private static PublicKey parsePublicKey(String pem) throws Exception {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) Security.addProvider(new BouncyCastleProvider());
        JcaPEMKeyConverter conv = new JcaPEMKeyConverter().setProvider("BC");
        try (PEMParser p = new PEMParser(new StringReader(pem))) {
            Object o = p.readObject();
            if (o instanceof X509CertificateHolder) return conv.getPublicKey(((X509CertificateHolder) o).getSubjectPublicKeyInfo());
            if (o instanceof SubjectPublicKeyInfo) return conv.getPublicKey((SubjectPublicKeyInfo) o);
        }
        throw new IllegalArgumentException("Unsupported partner key format.");
    }

    private static String[] loadLocalIdentity() throws Exception {
        PoolDB pool = new PoolDB(); Connection c = null; PreparedStatement ps = null; ResultSet rs = null;
        try {
            c = pool.getConnection();
            ps = c.prepareStatement("SELECT cfg.node_id, cert.private_key_pem FROM node_config cfg " +
                    "JOIN node_certificates cert ON cert.node_config_id = cfg.config_id AND cert.is_active = TRUE " +
                    "ORDER BY cert.created_at DESC LIMIT 1");
            rs = ps.executeQuery();
            return rs.next() ? new String[]{rs.getString(1), rs.getString(2)} : null;
        } finally { pool.cleanup(rs, ps, c); }
    }

    private static String loadLocalNodeId() throws Exception {
        PoolDB pool = new PoolDB(); Connection c = null; PreparedStatement ps = null; ResultSet rs = null;
        try {
            c = pool.getConnection();
            ps = c.prepareStatement("SELECT node_id FROM node_config LIMIT 1");
            rs = ps.executeQuery();
            return rs.next() ? rs.getString(1) : null;
        } finally { pool.cleanup(rs, ps, c); }
    }

    private static String[] loadPartnerKey(String nodeId) throws Exception {
        PoolDB pool = new PoolDB(); Connection c = null; PreparedStatement ps = null; ResultSet rs = null;
        try {
            c = pool.getConnection();
            ps = c.prepareStatement("SELECT public_key_pem, status FROM partners WHERE node_id = ?");
            ps.setString(1, nodeId);
            rs = ps.executeQuery();
            return rs.next() ? new String[]{rs.getString(1), rs.getString(2)} : null;
        } finally { pool.cleanup(rs, ps, c); }
    }
}
