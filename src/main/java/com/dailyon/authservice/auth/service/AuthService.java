package com.dailyon.authservice.auth.service;

import com.dailyon.authservice.auth.entity.Auth;
import com.dailyon.authservice.auth.feign.MemberApiClient;
import com.dailyon.authservice.auth.feign.request.MemberCreateRequest;
import com.dailyon.authservice.auth.feign.request.MemberGetRequest;
import com.dailyon.authservice.auth.repository.AuthRepository;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.hibernate.annotations.common.reflection.XMember;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestBody;

import javax.transaction.Transactional;
import java.util.List;
import java.util.Map;

@Slf4j
@Service
public class AuthService extends DefaultOAuth2UserService {

    private final MemberApiClient memberApiClient;
    private final AuthRepository authRepository;

    @Autowired
    public AuthService(MemberApiClient memberApiClient, AuthRepository authRepository) {
        this.memberApiClient = memberApiClient;
        this.authRepository = authRepository;
    }

    public MemberGetRequest getMember(Long id) {
        return memberApiClient.getMember(id);
    }

    public String registerMember(@RequestBody MemberCreateRequest request){
        return request.getEmail();
    }

    @Transactional
    public void saveAuth(String email, String role, String oauthProvider, @RequestBody MemberCreateRequest request) {
        if (memberApiClient.duplicateCheck(email)) {

        } else {
            memberApiClient.registerMember(request);

            Auth auth = Auth.builder()
                    .email(email)
                    .password(null)
                    .role(role)
                    .oauthProvider(oauthProvider)
                    .build();

            authRepository.save(auth);
        }
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);

        List<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList("ROLE_USER");

        String userNameAttributeName = userRequest.getClientRegistration()
                .getProviderDetails()
                .getUserInfoEndpoint()
                .getUserNameAttributeName();

        Map<String, Object> kakaoAccount = oAuth2User.getAttribute("kakao_account");
        String email = (String) kakaoAccount.get("email");

        Map<String, Object> kakaoInfo = oAuth2User.getAttribute("properties");
        String nickname = (String) kakaoInfo.get("nickname");
        String profileImgUrl = (String) kakaoInfo.get("profile_image");

        MemberCreateRequest memberCreateRequest = new MemberCreateRequest(email, profileImgUrl, nickname);


        saveAuth(email, "ROLE_USER", "KAKAO",memberCreateRequest);



        return new DefaultOAuth2User(authorities, oAuth2User.getAttributes(), userNameAttributeName);
    }
}
