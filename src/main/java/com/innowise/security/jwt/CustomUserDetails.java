package com.innowise.security.jwt;

import com.innowise.auth.database.model.UserCredential;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

public record CustomUserDetails(UserCredential userCredential) implements UserDetails {

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(userCredential.getRole().getAuthority()));
    }

    @Override
    public String getPassword() {
        return userCredential.getPassword();
    }

    @Override
    public String getUsername() {
        return userCredential.getUsername();
    }
}
