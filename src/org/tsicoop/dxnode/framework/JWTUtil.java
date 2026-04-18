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
    
    /**
     * STABLE SIGNING KEY:
     * To ensure tokens remain valid after a server reboot, the signing key must be deterministic.
     * We look for 'DX_JWT_SECRET' in System Properties or Environment Variables.
     * A fallback is provided, but a unique 32-character string should be used in production.
     */
    private static final String FALLBACK_SECRET = "tsi-dx-node-identity-governance-stable-key-2026";
    
    private static Key getSigningKey() {
        // 1. Look for a configured secret in Environment Variable (DX_JWT_SECRET)
        String secret = System.getenv("TSI_DX_NODE_JWT_SECRET");
        
        // 3. Final Fallback to a stable hardcoded string
        if (secret == null || secret.trim().isEmpty()) {
            secret = FALLBACK_SECRET;
        }

        byte[] keyBytes = secret.getBytes(StandardCharsets.UTF_8);
        
        // HMAC-SHA256 requires a key of at least 256 bits (32 bytes)
        if (keyBytes.length < 32) {
            byte[] padded = new byte[32];
            System.arraycopy(keyBytes, 0, padded, 0, Math.min(keyBytes.length, 32));
            return Keys.hmacShaKeyFor(padded);
        }
        
        return Keys.hmacShaKeyFor(keyBytes);
    }

    private static final Key SECRET_KEY = getSigningKey();

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