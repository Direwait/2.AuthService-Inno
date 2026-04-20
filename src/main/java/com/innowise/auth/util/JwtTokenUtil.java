package com.innowise.auth.util;

import org.springframework.stereotype.Component;

@Component
public class JwtTokenUtil {
    public static final String BEARER = "Bearer ";

    public String extractBearerToken(String authHeader) {
        if (authHeader == null || !authHeader.startsWith(BEARER) || authHeader.length() < 8) {
            throw new IllegalArgumentException("Invalid Authorization header format");
        }
        return authHeader.substring(7);
    }
}