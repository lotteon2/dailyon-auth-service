package com.dailyon.authservice.auth.service;

import com.dailyon.authservice.auth.entity.Auth;
import com.dailyon.authservice.auth.repository.AuthRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

@Service
public class CustomUserDetailsService implements UserDetailsService {
    private final AuthRepository authRepository;

    @Autowired
    public CustomUserDetailsService(AuthRepository authRepository) {
        this.authRepository = authRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
         Auth auth = authRepository.findByEmail(username);
        if (auth == null) {
            throw new UsernameNotFoundException("User not found");
        }
        String email = auth.getEmail();
        String password = auth.getPassword();
        if (email == null || email.isEmpty()) {
            throw new IllegalArgumentException("User details must not be null or empty");
        }
        if (password == null || password.isEmpty()) {
            password = "N/A";
        }
        return new User(email, password, new ArrayList<>());
    }


}
