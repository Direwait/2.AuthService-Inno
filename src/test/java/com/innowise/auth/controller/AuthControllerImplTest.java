package com.innowise.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.innowise.security.jwt.dto.AuthRequest;
import com.innowise.security.jwt.dto.JwtResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class AuthControllerImplTest extends BaseIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    private AuthRequest request;

    @BeforeEach
    void setUp() {
        request = AuthRequest.builder()
                .username("testuser")
                .password("password123")
                .email("template@mail.com")
                .build();
    }

    @Test
    void register_ShouldReturnTokens() throws Exception {
        MvcResult result = mockMvc.perform(post("/tokens/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andReturn();

        JwtResponse response = objectMapper.readValue(
                result.getResponse().getContentAsString(),
                JwtResponse.class);

        assertThat(response.accessToken()).isNotBlank();
        assertThat(response.refreshToken()).isNotBlank();
    }

    @Test
    void login_ShouldReturnTokens() throws Exception {
        mockMvc.perform(post("/tokens/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk());

        MvcResult result = mockMvc.perform(post("/tokens/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andReturn();

        JwtResponse response = objectMapper.readValue(
                result.getResponse().getContentAsString(),
                JwtResponse.class);

        assertThat(response.accessToken()).isNotBlank();
        assertThat(response.refreshToken()).isNotBlank();
    }

    @Test
    void validate_ShouldReturnOk_WhenTokenValid() throws Exception {
        MvcResult registerResult = mockMvc.perform(post("/tokens/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andReturn();

        JwtResponse tokens = objectMapper.readValue(
                registerResult.getResponse().getContentAsString(),
                JwtResponse.class);

        mockMvc.perform(post("/tokens/validate")
                        .header("Authorization", "Bearer " + tokens.accessToken()))
                .andExpect(status().isOk());
    }

    @Test
    void refresh_ShouldReturnNewTokens() throws Exception {
        MvcResult registerResult = mockMvc.perform(post("/tokens/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andReturn();

        JwtResponse tokens = objectMapper.readValue(
                registerResult.getResponse().getContentAsString(),
                JwtResponse.class);

        MvcResult refreshResult = mockMvc.perform(post("/tokens/refresh")
                        .header("Authorization", "Bearer " + tokens.refreshToken()))
                .andExpect(status().isOk())
                .andReturn();

        JwtResponse newTokens = objectMapper.readValue(
                refreshResult.getResponse().getContentAsString(),
                JwtResponse.class);

        assertThat(newTokens.accessToken()).isNotBlank();
        assertThat(newTokens.refreshToken()).isNotBlank();
        assertThat(newTokens.accessToken()).isNotEqualTo(tokens.accessToken());
    }
}