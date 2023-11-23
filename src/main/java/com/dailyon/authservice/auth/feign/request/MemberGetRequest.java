package com.dailyon.authservice.auth.feign.request;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class MemberGetRequest {

    private String email;

    private String profileImgUrl;

    private String gender;

    private String birth;

    private Long point;
}
