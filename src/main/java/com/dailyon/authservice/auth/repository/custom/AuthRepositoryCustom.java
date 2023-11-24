package com.dailyon.authservice.auth.repository.custom;

import com.dailyon.authservice.auth.entity.Auth;

public interface AuthRepositoryCustom {
    Auth findByEmail(String username);
}
