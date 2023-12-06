package com.dailyon.authservice.auth.api.request;


import lombok.Getter;

@Getter
public class AdminLoginRequest {
    private String id;
    private String pw;
}
