package com.innowise.auth.service;

import org.springframework.security.core.userdetails.UserDetails;

public interface UserCredentialService {
    UserDetails loadUserByUsername(String username);
}
