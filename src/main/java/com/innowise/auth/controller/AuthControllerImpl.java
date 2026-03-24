package com.innowise.auth.controller;

import com.innowise.auth.service.AuthService;
import com.innowise.security.jwt.dto.JwtResponse;
import com.innowise.security.jwt.dto.AuthRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthControllerImpl implements AuthController {
    private final AuthService authService;

    @PostMapping("/login")
    @Override
    public ResponseEntity<JwtResponse> createToken(@Valid @RequestBody AuthRequest loginRequest){
        JwtResponse jwtResponseDto = authService.createToken(loginRequest);
        return ResponseEntity.ok(jwtResponseDto);
    }

    @PostMapping("/register")
    @Override
    public ResponseEntity<JwtResponse> saveUserCredentials(@Valid @RequestBody AuthRequest authRequest) {
        JwtResponse jwtResponseDto = authService.saveUserCredentials(authRequest);
        return ResponseEntity.ok(jwtResponseDto);
    }

    @PostMapping("/validate")
    @Override
    public ResponseEntity<String> validate(@RequestHeader("Authorization") String authHeader) {
        String token = authHeader.substring(7);
        authService.validateToken(token);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/refresh")
    public ResponseEntity<JwtResponse> refreshToken(@RequestHeader("Authorization") String authHeader) {
        String token = authHeader.substring(7);
        JwtResponse result = authService.refreshToken(token);
        return ResponseEntity.ok(result);
    }
}
