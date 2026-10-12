package org.tsicoop.dxnode.framework;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * Utility for managing JSON Web Tokens (JWT) for administrative and client sessions.
 * REVISED: Implements persistent signing keys to ensure session continuity across server restarts.
 * This version replaces the transient secret key with one derived from a stable configuration source.
 */
public class JWTUtil {

    private static final long EXPIRATION_TIME = 864000000; // 10 days
    
    private static final int MIN_SECRET_BYTES = 32;

    /** Values shipped in sample configuration; never acceptable as a real secret. */
    private static boolean isPlaceholder(String secret) {
        String s = secret.toLowerCase();
        return s.startsWith("your_32_character") || s.contains("change_me") || s.contains("changeme");
    }

    private static boolean isDevelopment() {
        String env = System.getenv("TSI_DX_NODE_ENV");
        return "local".equalsIgnoreCase(env) || "development".equalsIgnoreCase(env) || "dev".equalsIgnoreCase(env);
    }

    /**
     * SIGNING KEY:
     * Read from TSI_DX_NODE_JWT_SECRET (at least 32 bytes). There is no built-in default: outside a
     * local/development environment the node refuses to start without a proper secret. In local or
     * development mode a random per-process key is generated and sessions end when the node restarts.
     */
    private static Key getSigningKey() {
        String secret = System.getenv("TSI_DX_NODE_JWT_SECRET");
        boolean usable = secret != null && !secret.trim().isEmpty() && !isPlaceholder(secret)
                && secret.getBytes(StandardCharsets.UTF_8).length >= MIN_SECRET_BYTES;

        if (!usable) {
            if (!isDevelopment()) {
                throw new IllegalStateException("TSI_DX_NODE_JWT_SECRET must be set to a unique value of at least "
                        + MIN_SECRET_BYTES + " characters (set TSI_DX_NODE_ENV=development only for local testing).");
            }
            System.err.println("[JWTUtil] WARNING: TSI_DX_NODE_JWT_SECRET is not set to a usable value; using a random "
                    + "per-process key. Admin sessions will not survive a restart.");
            byte[] random = new byte[48];
            new java.security.SecureRandom().nextBytes(random);
            return Keys.hmacShaKeyFor(random);
        }
        return Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    private static final Key SECRET_KEY = getSigningKey();

    /** Forces the signing key to be resolved now, so a misconfigured node fails at start-up. */
    public static void assertConfigured() {
        if (SECRET_KEY == null) throw new IllegalStateException("JWT signing key unavailable.");
    }

    public static String generateAppLoginToken(String email, String type, String username, String role, String state, String city) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("name", username);
        claims.put("role", role);
        claims.put("type", type);
        claims.put("state", state);
        claims.put("city", city);
        return createToken(claims, email);
    }

    public static String generateToken(String email, String username, String role) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("name", username);
        claims.put("role", role);
        return createToken(claims, email);
    }

    private static String createToken(Map<String, Object> claims, String subject) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(SECRET_KEY, SignatureAlgorithm.HS256)
                .compact();
    }

    public static boolean isTokenValid(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(SECRET_KEY).build().parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public static String getEmailFromToken(String token) {
        return parseClaims(token).getSubject();
    }

    public static String getNameFromToken(String token) {
        return (String) parseClaims(token).get("name");
    }

    public static String getRoleFromToken(String token) {
        return (String) parseClaims(token).get("role");
    }

    public static String getAccountTypeFromToken(String token) {
        return (String) parseClaims(token).get("type");
    }

    private static Claims parseClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(SECRET_KEY)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}