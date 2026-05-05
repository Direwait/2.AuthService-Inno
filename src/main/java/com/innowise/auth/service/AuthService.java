package com.innowise.auth.service;

import com.innowise.auth.database.enums.Role;
import com.innowise.security.jwt.dto.AuthRequest;
import com.innowise.security.jwt.dto.JwtResponse;
import com.innowise.security.jwt.dto.RegisterRequest;

import java.util.UUID;

public interface AuthService {

    JwtResponse createToken(AuthRequest authRequest);

    JwtResponse saveUserCredentials(RegisterRequest authRequest, Role role);

    void validateToken(String token);

    JwtResponse refreshToken(String token);

    void deleteById(UUID userId);
}
