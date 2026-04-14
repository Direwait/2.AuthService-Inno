package com.innowise.auth.service.impl;

import com.innowise.auth.database.RefreshTokenRepository;
import com.innowise.auth.database.UserCredentialRepository;
import com.innowise.auth.database.enums.Role;
import com.innowise.auth.database.model.RefreshTokenModel;
import com.innowise.auth.database.model.UserCredential;
import com.innowise.auth.service.AuthService;
import com.innowise.auth.service.UserCredentialService;
import com.innowise.auth.util.JwtTokenUtil;
import com.innowise.exception.TokenExpiredException;
import com.innowise.exception.TokenRevokedException;
import com.innowise.exception.TokenValidationException;
import com.innowise.exception.UserAlreadyExistsException;
import com.innowise.security.jwt.CustomUserDetails;
import com.innowise.security.jwt.JwtService;
import com.innowise.security.jwt.dto.JwtResponse;
import com.innowise.security.jwt.dto.AuthRequest;
import com.innowise.factory.RefreshTokenFactory;
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
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final JwtTokenUtil jwtTokenUtil;
    private final RefreshTokenFactory refreshTokenFactory;
    private final UserCredentialRepository userCredentialRepository;
    private final UserCredentialService userCredentialService;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenRepository refreshTokenRepository;

    @Transactional
    @Override
    public JwtResponse saveUserCredentials(AuthRequest request, Role role) {
        if (userCredentialRepository.existsByUsername(request.getUsername())) {
            throw new UserAlreadyExistsException("User with username '" + request.getUsername() + "' already exists");
        }
        UserCredential user = UserCredential.builder()
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(role)
                .build();

        UserCredential savedUser = userCredentialRepository.save(user);
        UserDetails userDetails = new CustomUserDetails(savedUser);

        var jwtResponseDto = jwtService.generateAuthToken(
                userDetails,
                savedUser.getId(),
                savedUser.getRole().name()
        );
        RefreshTokenModel refreshTokenEntity = refreshTokenFactory.create(savedUser, jwtResponseDto.refreshToken());
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

        RefreshTokenModel refreshTokenEntity = refreshTokenFactory.create(user, tokens.refreshToken());
        refreshTokenRepository.save(refreshTokenEntity);

        return tokens;
    }

    @Override
    public void validateToken(String authHeader) {
        String token = jwtTokenUtil.extractBearerToken(authHeader);
        if (!jwtService.isAccessToken(token)) {
            throw new TokenValidationException("Invalid token type. Expected access token");
        }
        if (!jwtService.isTokenValid(token)) {
            throw new TokenValidationException("Token is invalid or expired");
        }
    }

    @Override
    public JwtResponse refreshToken(String authHeader) {
        String token = jwtTokenUtil.extractBearerToken(authHeader);
        if (!jwtService.isRefreshToken(token)) {
            throw new TokenValidationException("Invalid token type. Expected refresh token");
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
        RefreshTokenModel newRefreshTokenEntity = refreshTokenFactory.create(user, newRefreshToken);
        refreshTokenRepository.save(newRefreshTokenEntity);

        return new JwtResponse(newAccessToken, newRefreshToken);
    }

    @Override
    @Transactional
    public void deleteById(UUID userId) {
        if (!userCredentialRepository.existsById(userId)) {
            throw new EntityNotFoundException("User not found with id: " + userId);
        }
        userCredentialRepository.deleteById(userId);
    }
}
