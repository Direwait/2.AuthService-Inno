package com.innowise.auth.controller;

import com.innowise.auth.database.enums.Role;
import com.innowise.auth.service.AuthService;
import com.innowise.security.jwt.dto.JwtResponse;
import com.innowise.security.jwt.dto.AuthRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthControllerImpl implements AuthController {
    private final AuthService authService;

    @DeleteMapping("/rollback/{userId}")
    @Override
    public ResponseEntity<Void> deleteUser(@PathVariable UUID userId) {
        authService.deleteById(userId);
        return null;
    }

    @PostMapping("/login")
    @Override
    public ResponseEntity<JwtResponse> createToken(@Valid @RequestBody AuthRequest loginRequest){
        JwtResponse jwtResponseDto = authService.createToken(loginRequest);
        return ResponseEntity.ok(jwtResponseDto);
    }

    @PostMapping("/register")
    @Override
    public ResponseEntity<JwtResponse> saveUserCredentials(@Valid @RequestBody AuthRequest authRequest) {
        JwtResponse jwtResponseDto = authService.saveUserCredentials(authRequest, Role.USER);
        return ResponseEntity.ok(jwtResponseDto);
    }

    @PostMapping("/register/admin")
    @PreAuthorize("hasRole('ADMIN')")
    @Override
    public ResponseEntity<JwtResponse> registerAdmin(@Valid @RequestBody AuthRequest authRequest) {
        JwtResponse jwtResponseDto = authService.saveUserCredentials(authRequest, Role.ADMIN);
        return ResponseEntity.ok(jwtResponseDto);
    }

    @PostMapping("/validate")
    @Override
    public ResponseEntity<String> validate(@RequestHeader("Authorization") String authHeader) {
        authService.validateToken(authHeader);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/refresh")
    public ResponseEntity<JwtResponse> refreshToken(@RequestHeader("Authorization") String authHeader) {
        JwtResponse result = authService.refreshToken(authHeader);
        return ResponseEntity.ok(result);
    }
}
