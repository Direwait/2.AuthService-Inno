package com.innowise.security.jwt.dto;

public record JwtResponse(
        String accessToken,
    String refreshToken) {
}
