package com.dailyon.authservice.auth.api.request;

import lombok.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor(access = AccessLevel.PROTECTED)

public class PostLoginReq {
    private String user_email;
    private String user_password;
}