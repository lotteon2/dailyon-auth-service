package com.dailyon.authservice.auth.service;

import com.dailyon.authservice.auth.api.request.AdminLoginRequest;
import com.dailyon.authservice.auth.entity.Auth;
import com.dailyon.authservice.auth.repository.AuthRepository;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@Service
public class AdminService {

    private final AuthRepository authRepository;

    public AdminService(AuthRepository authRepository) {
        this.authRepository = authRepository;
    }

}
