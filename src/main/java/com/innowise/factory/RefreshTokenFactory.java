package com.innowise.factory;

import com.innowise.auth.database.model.RefreshTokenModel;
import com.innowise.auth.database.model.UserCredential;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

@Component
@RequiredArgsConstructor
public class RefreshTokenFactory {

    public RefreshTokenModel create(UserCredential userCredential, String token) {
        return RefreshTokenModel.builder()
                .token(token)
                .user(userCredential)
                .expiryDate(Instant.now().plus(30, ChronoUnit.DAYS))
                .revoked(false)
                .build();
    }
}
