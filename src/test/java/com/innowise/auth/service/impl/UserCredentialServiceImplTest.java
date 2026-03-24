package com.innowise.auth.service.impl;

import com.innowise.auth.database.UserCredentialRepository;
import com.innowise.auth.database.model.UserCredential;
import com.innowise.security.jwt.CustomUserDetails;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UserCredentialServiceImplTest {

    @Mock
    private UserCredentialRepository userCredentialRepository;

    @InjectMocks
    private UserCredentialServiceImpl userCredentialService;

    private UserCredential testUser;
    private String username;

    @BeforeEach
    void setUp() {
        username = "testuser";
        testUser = UserCredential.builder()
                .id(UUID.randomUUID())
                .username(username)
                .password("encodedPassword")
                .build();
    }

    @Test
    void loadUserByUsername_ShouldReturnUserDetails_WhenUserExists() {
        when(userCredentialRepository.findByUsername(username))
                .thenReturn(Optional.of(testUser));

        UserDetails result = userCredentialService.loadUserByUsername(username);

        assertThat(result).isNotNull();
        assertThat(result).isInstanceOf(CustomUserDetails.class);
        assertThat(result.getUsername()).isEqualTo(username);
    }

    @Test
    void loadUserByUsername_ShouldThrowUsernameNotFoundException_WhenUserDoesNotExist() {
        String nonExistentUsername = "nonexistent";
        when(userCredentialRepository.findByUsername(nonExistentUsername))
                .thenReturn(Optional.empty());

        assertThatThrownBy(() -> userCredentialService.loadUserByUsername(nonExistentUsername))
                .isInstanceOf(UsernameNotFoundException.class)
                .hasMessageContaining(nonExistentUsername);
    }

    @Test
    void loadUserByUsername_ShouldThrowUsernameNotFoundException_WhenUsernameIsNull() {
        assertThatThrownBy(() -> userCredentialService.loadUserByUsername(null))
                .isInstanceOf(UsernameNotFoundException.class);
    }

    @Test
    void loadUserByUsername_ShouldReturnUserDetails_WithCorrectUsername() {
        when(userCredentialRepository.findByUsername(username))
                .thenReturn(Optional.of(testUser));

        UserDetails result = userCredentialService.loadUserByUsername(username);

        assertThat(result.getUsername()).isEqualTo(username);
    }
}