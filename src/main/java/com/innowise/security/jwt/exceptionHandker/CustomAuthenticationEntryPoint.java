package com.innowise.security.jwt.exceptionHandker;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.innowise.auth.controller.advice.ErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.LocalDateTime;

@Component
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException) throws IOException {

        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        ErrorResponse errorResponse = ErrorResponse.builder()
                .timestamp(LocalDateTime.now())
                .status(HttpServletResponse.SC_UNAUTHORIZED)
                .error("Unauthorized")
                .path(request.getRequestURI())
                .build();

        if (authException instanceof InsufficientAuthenticationException) {
            errorResponse.setMessage("Missing or invalid JWT token");
        } else if (authException instanceof BadCredentialsException) {
            errorResponse.setMessage("Invalid credentials");
        } else {
            errorResponse.setMessage("Authentication required: " + authException.getMessage());
        }

        ObjectMapper mapper = new ObjectMapper();
        response.getWriter().write(mapper.writeValueAsString(errorResponse));
    }
}
