package com.innowise.auth.service.impl;

import com.innowise.auth.database.RefreshTokenRepository;
import com.innowise.auth.database.UserCredentialRepository;
import com.innowise.auth.database.enums.Role;
import com.innowise.auth.database.model.RefreshTokenModel;
import com.innowise.auth.database.model.UserCredential;
import com.innowise.auth.service.UserCredentialService;
import com.innowise.auth.util.JwtTokenUtil;
import com.innowise.exception.TokenExpiredException;
import com.innowise.exception.TokenRevokedException;
import com.innowise.exception.TokenValidationException;
import com.innowise.factory.RefreshTokenFactory;
import com.innowise.security.jwt.CustomUserDetails;
import com.innowise.security.jwt.JwtService;
import com.innowise.security.jwt.dto.JwtResponse;
import com.innowise.security.jwt.dto.AuthRequest;
import jakarta.persistence.EntityNotFoundException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceImplTest {

    @Mock
    private UserCredentialRepository userCredentialRepository;
    @Mock
    private UserCredentialService userCredentialService;
    @Mock
    private JwtService jwtService;
    @Mock
    private AuthenticationManager authenticationManager;
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private RefreshTokenRepository refreshTokenRepository;
    @Mock
    private RefreshTokenFactory refreshTokenFactory;
    @Mock
    private JwtTokenUtil jwtTokenUtil;

    @InjectMocks
    private AuthServiceImpl authService;

    private UserCredential testUser;
    private AuthRequest authRequest;
    private JwtResponse jwtResponse;
    private RefreshTokenModel refreshTokenModel;
    private UserDetails userDetails;
    private UUID userId;

    @BeforeEach
    void setUp() {
        userId = UUID.randomUUID();
        testUser = UserCredential.builder()
                .id(userId)
                .username("testuser")
                .password("encodedPassword")
                .role(Role.USER)
                .build();
        authRequest = AuthRequest.builder()
                .username("testuser")
                .password("password123")
                .build();
        jwtResponse = new JwtResponse("access.token", "refresh.token");
        refreshTokenModel = RefreshTokenModel.builder()
                .token("refresh.token")
                .user(testUser)
                .expiryDate(Instant.now().plus(30, ChronoUnit.DAYS))
                .revoked(false)
                .build();
        userDetails = new CustomUserDetails(testUser);
    }

    @Test
    void saveUserCredentials_ShouldSaveUserAndReturnTokens_WhenUserDoesNotExist() {
        when(userCredentialRepository.existsByUsername("testuser")).thenReturn(false);
        when(passwordEncoder.encode("password123")).thenReturn("encodedPassword");
        when(userCredentialRepository.save(any(UserCredential.class))).thenReturn(testUser);
        when(jwtService.generateAuthToken(any(), any(UUID.class), anyString()))
                .thenReturn(jwtResponse);
        when(refreshTokenFactory.create(any(UserCredential.class), anyString()))
                .thenReturn(refreshTokenModel);
        when(refreshTokenRepository.save(any(RefreshTokenModel.class))).thenReturn(refreshTokenModel);

        JwtResponse result = authService.saveUserCredentials(authRequest, Role.USER);

        assertThat(result).isEqualTo(jwtResponse);
        verify(userCredentialRepository).existsByUsername("testuser");
        verify(userCredentialRepository).save(any(UserCredential.class));
        verify(jwtService).generateAuthToken(any(), eq(userId), eq("USER"));
        verify(refreshTokenFactory).create(eq(testUser), anyString());
        verify(refreshTokenRepository).save(any(RefreshTokenModel.class));
    }

    @Test
    void saveUserCredentials_ShouldThrowException_WhenUserAlreadyExists() {
        when(userCredentialRepository.existsByUsername("testuser")).thenReturn(true);

        assertThatThrownBy(() -> authService.saveUserCredentials(authRequest, Role.USER))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("already exists");

        verify(userCredentialRepository, never()).save(any(UserCredential.class));
        verify(jwtService, never()).generateAuthToken(any(), any(), anyString());
        verify(refreshTokenFactory, never()).create(any(), anyString());
    }

    @Test
    void createToken_ShouldAuthenticateAndReturnTokens_WhenCredentialsAreValid() {
        Authentication authentication = mock(Authentication.class);
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(authentication);
        when(authentication.getPrincipal()).thenReturn(userDetails);

        when(userCredentialRepository.findByUsername("testuser"))
                .thenReturn(Optional.of(testUser));
        when(jwtService.generateAuthToken(any(), any(UUID.class), anyString()))
                .thenReturn(jwtResponse);
        when(refreshTokenFactory.create(any(UserCredential.class), anyString()))
                .thenReturn(refreshTokenModel);
        when(refreshTokenRepository.save(any(RefreshTokenModel.class))).thenReturn(refreshTokenModel);

        JwtResponse result = authService.createToken(authRequest);

        assertThat(result).isEqualTo(jwtResponse);
        verify(authenticationManager).authenticate(any(UsernamePasswordAuthenticationToken.class));
        verify(userCredentialRepository).findByUsername("testuser");
        verify(jwtService).generateAuthToken(any(), eq(userId), eq("USER"));
        verify(refreshTokenFactory).create(eq(testUser), anyString());
        verify(refreshTokenRepository).save(any(RefreshTokenModel.class));
    }

    @Test
    void createToken_ShouldThrowException_WhenUserNotFound() {
        Authentication authentication = mock(Authentication.class);
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(authentication);
        when(userCredentialRepository.findByUsername("testuser"))
                .thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.createToken(authRequest))
                .isInstanceOf(EntityNotFoundException.class)
                .hasMessageContaining("User testuser not found");

        verify(jwtService, never()).generateAuthToken(any(), any(), anyString());
        verify(refreshTokenFactory, never()).create(any(), anyString());
    }

    @Test
    void validateToken_ShouldDoNothing_WhenTokenIsValid() {
        String authHeader = "Bearer valid.access.token";
        String token = "valid.access.token";
        when(jwtTokenUtil.extractBearerToken(authHeader)).thenReturn(token);
        when(jwtService.isAccessToken(token)).thenReturn(true);
        when(jwtService.isTokenValid(token)).thenReturn(true);

        authService.validateToken(authHeader);

        verify(jwtTokenUtil).extractBearerToken(authHeader);
        verify(jwtService).isAccessToken(token);
        verify(jwtService).isTokenValid(token);
    }

    @Test
    void validateToken_ShouldThrowException_WhenTokenIsNotAccessToken() {
        String authHeader = "Bearer refresh.token";
        String token = "refresh.token";
        when(jwtTokenUtil.extractBearerToken(authHeader)).thenReturn(token);
        when(jwtService.isAccessToken(token)).thenReturn(false);

        assertThatThrownBy(() -> authService.validateToken(authHeader))
                .isInstanceOf(TokenValidationException.class)
                .hasMessageContaining("Invalid token type");

        verify(jwtTokenUtil).extractBearerToken(authHeader);
        verify(jwtService).isAccessToken(token);
        verify(jwtService, never()).isTokenValid(anyString());
    }

    @Test
    void validateToken_ShouldThrowException_WhenTokenIsInvalid() {
        String authHeader = "Bearer invalid.token";
        String token = "invalid.token";
        when(jwtTokenUtil.extractBearerToken(authHeader)).thenReturn(token);
        when(jwtService.isAccessToken(token)).thenReturn(true);
        when(jwtService.isTokenValid(token)).thenReturn(false);

        assertThatThrownBy(() -> authService.validateToken(authHeader))
                .isInstanceOf(TokenValidationException.class)
                .hasMessageContaining("Token is invalid or expired");

        verify(jwtTokenUtil).extractBearerToken(authHeader);
        verify(jwtService).isAccessToken(token);
        verify(jwtService).isTokenValid(token);
    }

    @Test
    void refreshToken_ShouldReturnNewTokens_WhenRefreshTokenIsValid() {
        String authHeader = "Bearer valid.refresh.token";
        String refreshToken = "valid.refresh.token";
        when(jwtTokenUtil.extractBearerToken(authHeader)).thenReturn(refreshToken);
        when(jwtService.isRefreshToken(refreshToken)).thenReturn(true);
        when(refreshTokenRepository.findByToken(refreshToken))
                .thenReturn(Optional.of(refreshTokenModel));
        when(jwtService.extractUsername(refreshToken)).thenReturn("testuser");
        when(userCredentialService.loadUserByUsername("testuser")).thenReturn(userDetails);
        when(jwtService.isTokenValid(refreshToken, userDetails)).thenReturn(true);
        when(jwtService.generateAccessToken(any(), any(UUID.class), anyString()))
                .thenReturn("new.access.token");
        when(jwtService.generateRefreshToken("testuser")).thenReturn("new.refresh.token");
        when(refreshTokenFactory.create(any(UserCredential.class), anyString()))
                .thenReturn(refreshTokenModel);
        when(refreshTokenRepository.save(any(RefreshTokenModel.class))).thenReturn(refreshTokenModel);

        JwtResponse result = authService.refreshToken(authHeader);

        assertThat(result.accessToken()).isEqualTo("new.access.token");
        assertThat(result.refreshToken()).isEqualTo("new.refresh.token");

        verify(jwtTokenUtil).extractBearerToken(authHeader);
        verify(jwtService).isRefreshToken(refreshToken);
        verify(refreshTokenRepository).findByToken(refreshToken);
        verify(refreshTokenFactory).create(eq(testUser), anyString());
        verify(refreshTokenRepository, times(2)).save(any(RefreshTokenModel.class));
        verify(jwtService).generateAccessToken(any(), eq(userId), eq("USER"));
        verify(jwtService).generateRefreshToken("testuser");
    }

    @Test
    void refreshToken_ShouldThrowException_WhenTokenIsNotRefreshToken() {
        String authHeader = "Bearer access.token";
        String token = "access.token";
        when(jwtTokenUtil.extractBearerToken(authHeader)).thenReturn(token);
        when(jwtService.isRefreshToken(token)).thenReturn(false);

        assertThatThrownBy(() -> authService.refreshToken(authHeader))
                .isInstanceOf(TokenValidationException.class)
                .hasMessageContaining("Invalid token type");

        verify(jwtTokenUtil).extractBearerToken(authHeader);
        verify(jwtService).isRefreshToken(token);
        verify(refreshTokenRepository, never()).findByToken(anyString());
        verify(refreshTokenFactory, never()).create(any(), anyString());
    }

    @Test
    void refreshToken_ShouldThrowException_WhenRefreshTokenNotFound() {
        String authHeader = "Bearer unknown.token";
        String refreshToken = "unknown.token";
        when(jwtTokenUtil.extractBearerToken(authHeader)).thenReturn(refreshToken);
        when(jwtService.isRefreshToken(refreshToken)).thenReturn(true);
        when(refreshTokenRepository.findByToken(refreshToken))
                .thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.refreshToken(authHeader))
                .isInstanceOf(TokenValidationException.class)
                .hasMessageContaining("Refresh token not found");

        verify(jwtTokenUtil).extractBearerToken(authHeader);
        verify(jwtService).isRefreshToken(refreshToken);
        verify(refreshTokenRepository).findByToken(refreshToken);
        verify(refreshTokenFactory, never()).create(any(), anyString());
    }

    @Test
    void refreshToken_ShouldThrowException_WhenRefreshTokenIsRevoked() {
        String authHeader = "Bearer revoked.token";
        String refreshToken = "revoked.token";
        refreshTokenModel.setRevoked(true);

        when(jwtTokenUtil.extractBearerToken(authHeader)).thenReturn(refreshToken);
        when(jwtService.isRefreshToken(refreshToken)).thenReturn(true);
        when(refreshTokenRepository.findByToken(refreshToken))
                .thenReturn(Optional.of(refreshTokenModel));

        assertThatThrownBy(() -> authService.refreshToken(authHeader))
                .isInstanceOf(TokenRevokedException.class)
                .hasMessageContaining("Refresh token has been revoked");

        verify(jwtTokenUtil).extractBearerToken(authHeader);
        verify(jwtService).isRefreshToken(refreshToken);
        verify(refreshTokenRepository).findByToken(refreshToken);
        verify(refreshTokenFactory, never()).create(any(), anyString());
    }

    @Test
    void refreshToken_ShouldThrowException_WhenRefreshTokenIsExpired() {
        String authHeader = "Bearer expired.token";
        String refreshToken = "expired.token";
        refreshTokenModel.setExpiryDate(Instant.now().minus(1, ChronoUnit.DAYS));

        when(jwtTokenUtil.extractBearerToken(authHeader)).thenReturn(refreshToken);
        when(jwtService.isRefreshToken(refreshToken)).thenReturn(true);
        when(refreshTokenRepository.findByToken(refreshToken))
                .thenReturn(Optional.of(refreshTokenModel));

        assertThatThrownBy(() -> authService.refreshToken(authHeader))
                .isInstanceOf(TokenExpiredException.class)
                .hasMessageContaining("Refresh token has expired");

        verify(jwtTokenUtil).extractBearerToken(authHeader);
        verify(jwtService).isRefreshToken(refreshToken);
        verify(refreshTokenRepository).findByToken(refreshToken);
        verify(refreshTokenFactory, never()).create(any(), anyString());
    }

    @Test
    void refreshToken_ShouldThrowException_WhenTokenIsInvalid() {
        String authHeader = "Bearer invalid.refresh.token";
        String refreshToken = "invalid.refresh.token";
        when(jwtTokenUtil.extractBearerToken(authHeader)).thenReturn(refreshToken);
        when(jwtService.isRefreshToken(refreshToken)).thenReturn(true);
        when(refreshTokenRepository.findByToken(refreshToken))
                .thenReturn(Optional.of(refreshTokenModel));
        when(jwtService.extractUsername(refreshToken)).thenReturn("testuser");
        when(userCredentialService.loadUserByUsername("testuser")).thenReturn(userDetails);
        when(jwtService.isTokenValid(refreshToken, userDetails)).thenReturn(false);

        assertThatThrownBy(() -> authService.refreshToken(authHeader))
                .isInstanceOf(TokenValidationException.class)
                .hasMessageContaining("Refresh token is invalid");

        verify(jwtTokenUtil).extractBearerToken(authHeader);
        verify(jwtService).isRefreshToken(refreshToken);
        verify(refreshTokenRepository).findByToken(refreshToken);
        verify(jwtService).extractUsername(refreshToken);
        verify(userCredentialService).loadUserByUsername("testuser");
        verify(jwtService).isTokenValid(refreshToken, userDetails);
        verify(refreshTokenFactory, never()).create(any(), anyString());
    }

    @Test
    void refreshToken_ShouldRevokeOldToken_WhenRefreshing() {
        String authHeader = "Bearer valid.refresh.token";
        String refreshToken = "valid.refresh.token";
        when(jwtTokenUtil.extractBearerToken(authHeader)).thenReturn(refreshToken);
        when(jwtService.isRefreshToken(refreshToken)).thenReturn(true);
        when(refreshTokenRepository.findByToken(refreshToken))
                .thenReturn(Optional.of(refreshTokenModel));
        when(jwtService.extractUsername(refreshToken)).thenReturn("testuser");
        when(userCredentialService.loadUserByUsername("testuser")).thenReturn(userDetails);
        when(jwtService.isTokenValid(refreshToken, userDetails)).thenReturn(true);
        when(jwtService.generateAccessToken(any(), any(UUID.class), anyString()))
                .thenReturn("new.access.token");
        when(jwtService.generateRefreshToken("testuser")).thenReturn("new.refresh.token");

        RefreshTokenModel newRefreshTokenModel = RefreshTokenModel.builder()
                .token("new.refresh.token")
                .user(testUser)
                .expiryDate(Instant.now().plus(30, ChronoUnit.DAYS))
                .revoked(false)
                .build();

        when(refreshTokenFactory.create(any(UserCredential.class), anyString()))
                .thenReturn(newRefreshTokenModel);
        when(refreshTokenRepository.save(any(RefreshTokenModel.class)))
                .thenReturn(refreshTokenModel)
                .thenReturn(newRefreshTokenModel);

        authService.refreshToken(authHeader);

        assertThat(refreshTokenModel.isRevoked()).isTrue();

        verify(jwtTokenUtil).extractBearerToken(authHeader);
        verify(jwtService).isRefreshToken(refreshToken);
        verify(refreshTokenRepository).findByToken(refreshToken);
        verify(refreshTokenRepository).save(refreshTokenModel);
        verify(refreshTokenFactory).create(eq(testUser), anyString());
        verify(refreshTokenRepository, times(2)).save(any(RefreshTokenModel.class));
    }

    @Test
    void deleteById_ShouldDeleteUser_WhenUserExists() {
        when(userCredentialRepository.existsById(userId)).thenReturn(true);
        doNothing().when(userCredentialRepository).deleteById(userId);

        authService.deleteById(userId);

        verify(userCredentialRepository).existsById(userId);
        verify(userCredentialRepository).deleteById(userId);
    }

    @Test
    void deleteById_ShouldThrowEntityNotFoundException_WhenUserDoesNotExist() {
        when(userCredentialRepository.existsById(userId)).thenReturn(false);

        assertThatThrownBy(() -> authService.deleteById(userId))
                .isInstanceOf(EntityNotFoundException.class)
                .hasMessageContaining("User not found with id: " + userId);

        verify(userCredentialRepository).existsById(userId);
        verify(userCredentialRepository, never()).deleteById(any());
    }
}