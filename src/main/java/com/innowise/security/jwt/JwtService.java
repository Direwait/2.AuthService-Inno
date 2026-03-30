package com.innowise.security.jwt;

import com.innowise.security.jwt.dto.JwtResponse;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;

@Slf4j
@Component
public class JwtService {

    public static final String TOKEN_TYPE_ACCESS = "access";
    public static final String TOKEN_TYPE_REFRESH = "refresh";
    public static final String CLAIM_USER_ID = "userId";
    public static final String CLAIM_ROLE = "role";
    public static final String CLAIM_TYPE = "type";

    @Value("${jwt.secret}")
    private String JWT_SECRET;

    @Value("${jwt.expiration}")
    private long JWT_EXPIRATION;

    @Value("${jwt.refresh-expiration}")
    private long REFRESH_EXPIRATION;

    public String generateAccessToken(UserDetails userDetails, UUID userId, String role) {
        Map<String, Object> claims = new HashMap<>();
        claims.put(CLAIM_USER_ID, userId.toString());
        claims.put(CLAIM_ROLE, role);
        claims.put(CLAIM_TYPE, TOKEN_TYPE_ACCESS);

        return Jwts.builder()
                .id(UUID.randomUUID().toString())
                .claims(claims)
                .subject(userDetails.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + JWT_EXPIRATION))
                .signWith(getSignInKey())
                .compact();
    }

    public String generateRefreshToken(String username) {
        Map<String, Object> claims = new HashMap<>();
        claims.put(CLAIM_TYPE, TOKEN_TYPE_REFRESH);

        return Jwts.builder()
                .id(UUID.randomUUID().toString())
                .claims(claims)
                .subject(username)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + REFRESH_EXPIRATION))
                .signWith(getSignInKey())
                .compact();
    }

    public JwtResponse generateAuthToken(UserDetails userDetails, UUID userId, String role) {
        return new JwtResponse(
                generateAccessToken(userDetails, userId, role),
                generateRefreshToken(userDetails.getUsername())
        );
    }

    private SecretKey getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(JWT_SECRET);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        if (token == null || userDetails == null) {
            log.warn("Token or userDetails is null");
            return false;
        }
        try {
            String username = extractUsername(token);
            boolean isValid = username.equals(userDetails.getUsername()) && isTokenNotExpired(token);
            if (!isValid) {
                log.debug("Token invalid for user: {}", username);
            }
            return isValid;
        } catch (Exception e) {
            log.error("Error validating token: {}", e.getMessage());
            return false;
        }
    }

    public boolean isTokenValid(String token) {
        if (token == null) {
            log.warn("Token is null");
            return false;
        }
        try {
            return isTokenNotExpired(token);
        } catch (Exception e) {
            log.error("Error validating token: {}", e.getMessage());
            return false;
        }
    }

    private boolean isTokenNotExpired(String token) {
        return extractExpiration(token).after(new Date());
    }

    public boolean isRefreshToken(String token) {
        try {
            return TOKEN_TYPE_REFRESH.equals(extractTokenType(token));
        } catch (Exception e) {
            return false;
        }
    }

    public String extractTokenType(String token) {
        return extractClaim(token, claims -> claims.get(CLAIM_TYPE, String.class));
    }

    private Claims extractAllClaims(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(getSignInKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (Exception e) {
            log.error("Failed to parse JWT token: {}", e.getMessage());
            throw new JwtException("Invalid JWT token");
        }
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public UUID extractUserId(String token) {
        String userIdStr = extractClaim(token, claims -> claims.get(CLAIM_USER_ID, String.class));
        return userIdStr != null ? UUID.fromString(userIdStr) : null;
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public String extractRole(String token) {
        return extractClaim(token, claims -> claims.get(CLAIM_ROLE, String.class));
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public boolean isAccessToken(String token) {
        try {
            String type = extractTokenType(token);
            return TOKEN_TYPE_ACCESS.equals(type);
        } catch (Exception e) {
            log.debug("Failed to check if token is access token: {}", e.getMessage());
            return false;
        }
    }
}