package com.innowise.auth.controller;

import com.innowise.security.jwt.dto.AuthRequest;
import com.innowise.security.jwt.dto.JwtResponse;
import org.springframework.http.ResponseEntity;

public interface AuthController {

    /**
     * Authenticates a user and generates access and refresh tokens
     *
     * @param loginRequest the authentication request containing username and password
     * @return ResponseEntity containing JWT access and refresh tokens
     * @throws org.springframework.security.core.AuthenticationException if authentication fails
     */
    ResponseEntity<JwtResponse> createToken(AuthRequest loginRequest);

    /**
     * Registers a new user and returns authentication tokens
     *
     * @param authRequest the registration request containing username and password
     * @return ResponseEntity containing JWT access and refresh tokens for the new user
     * @throws RuntimeException if user with given username already exists
     */
    ResponseEntity<JwtResponse> saveUserCredentials(AuthRequest authRequest);

    /**
     * Registers a new admin user (requires admin privileges)
     *
     * @param authRequest the registration request containing username and password
     * @return ResponseEntity containing JWT access and refresh tokens for the new admin user
     * @throws com.innowise.exception.UserAlreadyExistsException if user with given username already exists
     * @throws org.springframework.security.access.AccessDeniedException if the current user does not have ADMIN role
     */
    ResponseEntity<JwtResponse> registerAdmin(AuthRequest authRequest);

    /**
     * Validates the provided authentication token
     *
     * @param authHeader the Authorization header containing Bearer token
     * @return ResponseEntity with validation result message
     * @throws com.innowise.exception.TokenValidationException if token is invalid, expired, or wrong type
     */
    ResponseEntity<String> validate(String authHeader);

    /**
     * Refreshes access token using a valid refresh token
     *
     * @param authHeader the Authorization header containing the refresh token (format: "Bearer {refreshToken}")
     * @return ResponseEntity containing new access and refresh tokens
     * @throws com.innowise.exception.TokenValidationException if refresh token is invalid
     * @throws com.innowise.exception.TokenExpiredException if refresh token has expired
     * @throws com.innowise.exception.TokenRevokedException if refresh token has been revoked
     */
    ResponseEntity<JwtResponse> refreshToken(String authHeader);
}
