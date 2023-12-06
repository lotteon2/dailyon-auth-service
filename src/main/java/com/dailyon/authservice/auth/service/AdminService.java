package com.dailyon.authservice.auth.service;

import org.springframework.stereotype.Service;

@Service
public class AdminService {

    // 실제로는 데이터베이스에서 관리자 정보를 조회하여 확인해야 함
    public boolean isValidAdmin(String adminId, String adminPassword) {
        return "admin".equals(adminId) && "password".equals(adminPassword);
    }
}
