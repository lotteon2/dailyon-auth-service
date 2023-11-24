package com.dailyon.authservice.auth.entity;


import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.*;


@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Entity
public class Auth {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String email;

    private String password;

    @Column(nullable = false)
    private String role;

    @Column(nullable = false)
    private String oauthProvider;

    @Builder
    public Auth(
        Long id,
        String email,
        String password,
        String role,
        String oauthProvider
    ){
        this.id = id;
        this.email = email;
        this.password = password;
        this.role = role;
        this.oauthProvider = oauthProvider;
    }

}
