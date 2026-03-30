package com.innowise.auth.service;

import com.innowise.auth.database.enums.Role;
import com.innowise.security.jwt.dto.JwtResponse;
import com.innowise.security.jwt.dto.AuthRequest;

public interface AuthService {

    JwtResponse createToken(AuthRequest authRequest);

    JwtResponse saveUserCredentials(AuthRequest authRequest, Role role);

    void validateToken(String token);

    JwtResponse refreshToken(String token);
}
