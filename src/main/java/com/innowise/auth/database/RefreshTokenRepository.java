package com.innowise.auth.database;

import com.innowise.auth.database.model.RefreshTokenModel;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshTokenModel, UUID> {
   Optional<RefreshTokenModel> findByToken(String token);
}
