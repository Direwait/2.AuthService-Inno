package com.innowise.auth.service;

import com.innowise.security.jwt.dto.JwtResponse;
import com.innowise.security.jwt.dto.AuthRequest;

public interface AuthService {

    JwtResponse createToken(AuthRequest authRequest);

    JwtResponse saveUserCredentials(AuthRequest authRequest);

    void validateToken(String token);

    JwtResponse refreshToken(String token);
}
