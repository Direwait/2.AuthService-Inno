package com.innowise.auth.service.impl;

import com.innowise.auth.database.RefreshTokenRepository;
import com.innowise.auth.database.UserCredentialRepository;
import com.innowise.auth.database.enums.Role;
import com.innowise.auth.database.model.RefreshTokenModel;
import com.innowise.auth.database.model.UserCredential;
import com.innowise.auth.service.AuthService;
import com.innowise.auth.service.UserCredentialService;
import com.innowise.exception.TokenExpiredException;
import com.innowise.exception.TokenRevokedException;
import com.innowise.exception.TokenValidationException;
import com.innowise.security.jwt.CustomUserDetails;
import com.innowise.security.jwt.JwtService;
import com.innowise.security.jwt.dto.JwtResponse;
import com.innowise.security.jwt.dto.AuthRequest;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserCredentialRepository userCredentialRepository;
    private final UserCredentialService userCredentialService;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenRepository refreshTokenRepository;

    @Transactional
    @Override
    public JwtResponse saveUserCredentials(AuthRequest request) {
        if (userCredentialRepository.existsByUsername(request.getUsername())) {
            throw new RuntimeException("User with username '" + request.getUsername() + "' already exists");
        }
        UserCredential user = UserCredential.builder()
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();

        UserCredential savedUser = userCredentialRepository.save(user);
        UserDetails userDetails = new CustomUserDetails(savedUser);

        var jwtResponseDto = jwtService.generateAuthToken(
                userDetails,
                savedUser.getId(),
                savedUser.getRole().name()
        );
        RefreshTokenModel refreshTokenEntity = RefreshTokenModel.builder()
                .token(jwtResponseDto.refreshToken())
                .user(savedUser)
                .expiryDate(Instant.now().plus(30, ChronoUnit.DAYS))
                .revoked(false)
                .build();

        refreshTokenRepository.save(refreshTokenEntity);
        return jwtResponseDto;
    }

    @Transactional
    @Override
    public JwtResponse createToken(AuthRequest request) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );

        UserCredential user = userCredentialRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new EntityNotFoundException("User " + request.getUsername() + " not found"));

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        JwtResponse tokens = jwtService.generateAuthToken(
                userDetails,
                user.getId(),
                user.getRole().name()
        );

        RefreshTokenModel refreshTokenEntity = RefreshTokenModel.builder()
                .token(tokens.refreshToken())
                .user(user)
                .expiryDate(Instant.now().plus(30, ChronoUnit.DAYS))
                .revoked(false)
                .build();

        refreshTokenRepository.save(refreshTokenEntity);

        return tokens;
    }

    @Override
    public void validateToken(String token) {
        if (!jwtService.isAccessToken(token)) {
            throw new TokenValidationException("Invalid token type. Expected access token");
        }
        if (!jwtService.isTokenValid(token)) {
            throw new TokenValidationException("Token is invalid or expired");
        }
    }

    @Override
    public JwtResponse refreshToken(String token) {
        if (!jwtService.isRefreshToken(token)) {
            throw new RuntimeException("Invalid token type. Expected refresh token");
        }
        RefreshTokenModel refreshTokenEntity = refreshTokenRepository
                .findByToken(token)
                .orElseThrow(() -> new TokenValidationException("Refresh token not found"));

        if (refreshTokenEntity.isRevoked()) {
            throw new TokenRevokedException("Refresh token has been revoked");
        }

        if (refreshTokenEntity.getExpiryDate().isBefore(Instant.now())) {
            throw new TokenExpiredException("Refresh token has expired");
        }

        String username = jwtService.extractUsername(token);
        UserDetails userDetails = userCredentialService.loadUserByUsername(username);

        if (!jwtService.isTokenValid(token, userDetails)) {
            throw new TokenValidationException("Refresh token is invalid");
        }

        UserCredential user = refreshTokenEntity.getUser();
        refreshTokenEntity.setRevoked(true);
        refreshTokenRepository.save(refreshTokenEntity);
        String newAccessToken = jwtService.generateAccessToken(
                userDetails,
                user.getId(),
                user.getRole().name()
        );
        String newRefreshToken = jwtService.generateRefreshToken(username);

        RefreshTokenModel newRefreshTokenEntity = RefreshTokenModel.builder()
                .token(newRefreshToken)
                .user(user)
                .expiryDate(Instant.now().plus(30, ChronoUnit.DAYS))
                .revoked(false)
                .build();

        refreshTokenRepository.save(newRefreshTokenEntity);

        return new JwtResponse(newAccessToken, newRefreshToken);

    }
}
