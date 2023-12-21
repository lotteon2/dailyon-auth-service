package com.dailyon.authservice.auth.feign.request;


import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.validation.constraints.NotNull;

@Getter
@AllArgsConstructor
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class MemberCreateRequest {

    private String email;

    private String profileImgUrl;

    private String nickname;


    private String gender;

    private String birth;

}