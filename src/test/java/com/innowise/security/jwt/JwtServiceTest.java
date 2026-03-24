package com.innowise.security.jwt;

import com.innowise.security.jwt.dto.JwtResponse;
import io.jsonwebtoken.JwtException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@ExtendWith(MockitoExtension.class)
class JwtServiceTest {

    private JwtService jwtService;

    private UserDetails userDetails;
    private UUID userId;
    private String role;

    @BeforeEach
    void setUp() {
        jwtService = new JwtService();

        ReflectionTestUtils.setField(jwtService, "JWT_SECRET",
                "932a9ed0a578a7883486e5605c40012cd949b1dba8e435c1119f369365442c3e");
        ReflectionTestUtils.setField(jwtService, "JWT_EXPIRATION", 900000); // 15 минут
        ReflectionTestUtils.setField(jwtService, "REFRESH_EXPIRATION", 2592000000L); // 30 дней

        userDetails = User.withUsername("testuser")
                .password("password")
                .authorities("USER")
                .build();
        userId = UUID.randomUUID();
        role = "USER";
    }

    @Test
    void generateAccessToken_ShouldReturnValidToken() {
        String token = jwtService.generateAccessToken(userDetails, userId, role);

        assertThat(token).isNotBlank();
        assertThat(jwtService.isAccessToken(token)).isTrue();
        assertThat(jwtService.isRefreshToken(token)).isFalse();
        assertThat(jwtService.extractUsername(token)).isEqualTo("testuser");
        assertThat(jwtService.extractUserId(token)).isEqualTo(userId);
        assertThat(jwtService.extractRole(token)).isEqualTo(role);
    }

    @Test
    void generateRefreshToken_ShouldReturnValidToken() {
        String token = jwtService.generateRefreshToken("testuser");

        assertThat(token).isNotBlank();
        assertThat(jwtService.isRefreshToken(token)).isTrue();
        assertThat(jwtService.isAccessToken(token)).isFalse();
        assertThat(jwtService.extractUsername(token)).isEqualTo("testuser");
        assertThat(jwtService.extractUserId(token)).isNull();
        assertThat(jwtService.extractRole(token)).isNull();
    }

    @Test
    void generateAuthToken_ShouldReturnBothTokens() {
        JwtResponse response = jwtService.generateAuthToken(userDetails, userId, role);

        assertThat(response.accessToken()).isNotBlank();
        assertThat(response.refreshToken()).isNotBlank();
        assertThat(jwtService.isAccessToken(response.accessToken())).isTrue();
        assertThat(jwtService.isRefreshToken(response.refreshToken())).isTrue();
        assertThat(jwtService.extractUsername(response.accessToken())).isEqualTo("testuser");
        assertThat(jwtService.extractUsername(response.refreshToken())).isEqualTo("testuser");
    }

    @Test
    void isTokenValid_WithValidAccessToken_ShouldReturnTrue() {
        String token = jwtService.generateAccessToken(userDetails, userId, role);

        boolean isValid = jwtService.isTokenValid(token, userDetails);

        assertThat(isValid).isTrue();
    }

    @Test
    void isTokenValid_WithValidRefreshToken_ShouldReturnTrue() {
        String token = jwtService.generateRefreshToken("testuser");

        boolean isValid = jwtService.isTokenValid(token);

        assertThat(isValid).isTrue();
    }

    @Test
    void isTokenValid_WithWrongUser_ShouldReturnFalse() {
        String token = jwtService.generateAccessToken(userDetails, userId, role);
        UserDetails wrongUser = User.withUsername("wronguser")
                .password("password")
                .authorities("USER")
                .build();

        boolean isValid = jwtService.isTokenValid(token, wrongUser);

        assertThat(isValid).isFalse();
    }

    @Test
    void isTokenValid_WithNullToken_ShouldReturnFalse() {
        boolean isValid = jwtService.isTokenValid(null, userDetails);

        assertThat(isValid).isFalse();
    }

    @Test
    void isTokenValid_WithNullUserDetails_ShouldReturnFalse() {
        String token = jwtService.generateAccessToken(userDetails, userId, role);

        boolean isValid = jwtService.isTokenValid(token, null);

        assertThat(isValid).isFalse();
    }

    @Test
    void isTokenValid_WithInvalidToken_ShouldReturnFalse() {
        String invalidToken = "invalid.token.here";

        boolean isValid = jwtService.isTokenValid(invalidToken);

        assertThat(isValid).isFalse();
    }

    @Test
    void isAccessToken_WithAccessToken_ShouldReturnTrue() {
        String token = jwtService.generateAccessToken(userDetails, userId, role);

        boolean isAccess = jwtService.isAccessToken(token);

        assertThat(isAccess).isTrue();
    }

    @Test
    void isAccessToken_WithRefreshToken_ShouldReturnFalse() {
        String token = jwtService.generateRefreshToken("testuser");

        boolean isAccess = jwtService.isAccessToken(token);

        assertThat(isAccess).isFalse();
    }

    @Test
    void isAccessToken_WithInvalidToken_ShouldReturnFalse() {
        boolean isAccess = jwtService.isAccessToken("invalid.token");

        assertThat(isAccess).isFalse();
    }

    @Test
    void isRefreshToken_WithRefreshToken_ShouldReturnTrue() {
        String token = jwtService.generateRefreshToken("testuser");

        boolean isRefresh = jwtService.isRefreshToken(token);

        assertThat(isRefresh).isTrue();
    }

    @Test
    void isRefreshToken_WithAccessToken_ShouldReturnFalse() {
        String token = jwtService.generateAccessToken(userDetails, userId, role);

        boolean isRefresh = jwtService.isRefreshToken(token);

        assertThat(isRefresh).isFalse();
    }

    @Test
    void isRefreshToken_WithInvalidToken_ShouldReturnFalse() {
        boolean isRefresh = jwtService.isRefreshToken("invalid.token");

        assertThat(isRefresh).isFalse();
    }

    @Test
    void extractUsername_ShouldReturnCorrectUsername() {
        String token = jwtService.generateAccessToken(userDetails, userId, role);

        String username = jwtService.extractUsername(token);

        assertThat(username).isEqualTo("testuser");
    }

    @Test
    void extractUserId_ShouldReturnCorrectUserId() {
        String token = jwtService.generateAccessToken(userDetails, userId, role);

        UUID extractedUserId = jwtService.extractUserId(token);

        assertThat(extractedUserId).isEqualTo(userId);
    }

    @Test
    void extractUserId_FromRefreshToken_ShouldReturnNull() {
        String token = jwtService.generateRefreshToken("testuser");

        UUID extractedUserId = jwtService.extractUserId(token);

        assertThat(extractedUserId).isNull();
    }

    @Test
    void extractRole_ShouldReturnCorrectRole() {
        String token = jwtService.generateAccessToken(userDetails, userId, role);

        String extractedRole = jwtService.extractRole(token);

        assertThat(extractedRole).isEqualTo(role);
    }

    @Test
    void extractRole_FromRefreshToken_ShouldReturnNull() {
        String token = jwtService.generateRefreshToken("testuser");

        String extractedRole = jwtService.extractRole(token);

        assertThat(extractedRole).isNull();
    }

    @Test
    void extractTokenType_ShouldReturnAccessType() {
        String token = jwtService.generateAccessToken(userDetails, userId, role);

        String type = jwtService.extractTokenType(token);

        assertThat(type).isEqualTo(JwtService.TOKEN_TYPE_ACCESS);
    }

    @Test
    void extractTokenType_ShouldReturnRefreshType() {
        String token = jwtService.generateRefreshToken("testuser");

        String type = jwtService.extractTokenType(token);

        assertThat(type).isEqualTo(JwtService.TOKEN_TYPE_REFRESH);
    }

    @Test
    void isTokenValid_ShouldReturnFalse_WhenTokenExpired() throws InterruptedException {
        ReflectionTestUtils.setField(jwtService, "JWT_EXPIRATION", 1);

        String token = jwtService.generateAccessToken(userDetails, userId, role);

        Thread.sleep(10);
        boolean isValid = jwtService.isTokenValid(token, userDetails);

        assertThat(isValid).isFalse();
    }

    @Test
    void extractAllClaims_WithInvalidToken_ShouldThrowJwtException() {
        String invalidToken = "invalid.token.here";

        assertThatThrownBy(() -> jwtService.extractUsername(invalidToken))
                .isInstanceOf(JwtException.class)
                .hasMessageContaining("Invalid JWT token");
    }

    @Test
    void extractUsername_WithNullToken_ShouldThrowException() {
        assertThatThrownBy(() -> jwtService.extractUsername(null))
                .isInstanceOf(Exception.class);
    }
}