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
    private Long id;

    @Column(nullable = false, unique=true)
    private String email;

    private String password;

    @Column(nullable = false)
    private String role;


    @Builder
    public Auth(
        Long id,
        String email,
        String password,
        String role
    ){
        this.id = id;
        this.email = email;
        this.password = password;
        this.role = role;
    }

}
