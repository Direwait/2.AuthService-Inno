package com.innowise.auth.service.impl;

import com.innowise.auth.database.UserCredentialRepository;
import com.innowise.auth.database.model.UserCredential;
import com.innowise.auth.service.UserCredentialService;
import com.innowise.security.jwt.CustomUserDetails;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserCredentialServiceImpl implements UserDetailsService, UserCredentialService {
    private final UserCredentialRepository userCredentialRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        var byUsername = userCredentialRepository.findByUsername(username);
        if (byUsername.isPresent()) {
            UserCredential userCredential = byUsername.get();
            return new CustomUserDetails(userCredential);
        } else {
            throw new UsernameNotFoundException(username);
        }
    }
}
