package com.innowise.auth.controller;

import com.innowise.security.jwt.dto.AuthRequest;
import com.innowise.security.jwt.dto.JwtResponse;
import org.springframework.http.ResponseEntity;


public interface AuthController {

    ResponseEntity<JwtResponse> createToken(AuthRequest loginRequest);

    ResponseEntity<JwtResponse> saveUserCredentials(AuthRequest authRequest);

    ResponseEntity<String> validate(String authHeader);

    ResponseEntity<JwtResponse> refreshToken(String token);
}
