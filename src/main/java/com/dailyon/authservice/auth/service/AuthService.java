package com.dailyon.authservice.auth.service;

import com.dailyon.authservice.auth.entity.Auth;
import com.dailyon.authservice.auth.feign.MemberApiClient;
import com.dailyon.authservice.auth.feign.request.MemberGetRequest;
import com.dailyon.authservice.auth.repository.AuthRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
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

    public void saveAuth(String email, String role, String oauthProvider) {
        Auth auth = Auth.builder()
                .email(email)
                .password(null)
                .role(role)
                .oauthProvider(oauthProvider)
                .build();

        authRepository.save(auth);
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);

        // Role generate
        List<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList("ROLE_USER");

        // nameAttributeKey
        String userNameAttributeName = userRequest.getClientRegistration()
                .getProviderDetails()
                .getUserInfoEndpoint()
                .getUserNameAttributeName();

        // 추출한 정보를 이용하여 saveAuth 호출
        System.out.println(oAuth2User);
        Map<String, Object> kakaoAccount = (Map<String, Object>) oAuth2User.getAttribute("kakao_account");
        String email = (String) kakaoAccount.get("email");
        System.out.println(email);
        saveAuth(email, "ROLE_USER", "KAKAO");

        return new DefaultOAuth2User(authorities, oAuth2User.getAttributes(), userNameAttributeName);
    }
}
