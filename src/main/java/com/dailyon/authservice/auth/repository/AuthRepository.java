package com.dailyon.authservice.auth.repository;

import com.dailyon.authservice.auth.entity.Auth;
import com.dailyon.authservice.auth.repository.custom.AuthRepositoryCustom;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuthRepository extends JpaRepository<Auth, Long>, AuthRepositoryCustom {
}
