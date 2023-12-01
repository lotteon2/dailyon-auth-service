package com.dailyon.authservice.auth.service;

import com.dailyon.authservice.auth.entity.Auth;
import com.dailyon.authservice.auth.feign.MemberApiClient;
import com.dailyon.authservice.auth.feign.request.MemberCreateRequest;
import com.dailyon.authservice.auth.feign.request.MemberGetRequest;
import com.dailyon.authservice.auth.repository.AuthRepository;
import com.dailyon.authservice.jwt.JwtService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
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
import java.util.UUID;

@Slf4j
@Service
public class AuthService extends DefaultOAuth2UserService {

    private final MemberApiClient memberApiClient;
    private final AuthRepository authRepository;

    private final CustomUserDetailsService userDetailsService;
    private final JwtService jwtService;

    @Autowired
    public AuthService(MemberApiClient memberApiClient, AuthRepository authRepository, CustomUserDetailsService userDetailsService, JwtService jwtService) {
        this.memberApiClient = memberApiClient;
        this.authRepository = authRepository;
        this.userDetailsService = userDetailsService;
        this.jwtService = jwtService;
    }

    public MemberGetRequest getMember(Long id) {
        return memberApiClient.getMember(id);
    }


    @Transactional
    public String authenticateAndGenerateToken(String email) {
        UserDetails userDetails = userDetailsService.loadUserByUsername(email);
        return jwtService.generateToken(userDetails);
    }

    @Transactional
    public String saveAuth(String email, String role, @RequestBody MemberCreateRequest request) {
        String jwtToken = null;
        Auth member = authRepository.findByEmail(email);

        if (member != null) {
            jwtToken = authenticateAndGenerateToken(email);
        } else {
            ResponseEntity<Long> response= memberApiClient.registerMember(request);


            Auth auth = Auth.builder()
                    .id(response.getBody())
                    .email(email)
                    .password(null)
                    .role(role)
                    .build();

            authRepository.save(auth);

            jwtToken = authenticateAndGenerateToken(email);
        }
        //TODO: 테스트 완료후 지울 예정
        log.info("User login successful. JWT Token: " + jwtToken);
        return jwtToken;
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

        //테스트 후 UUID 중복 가능성 있으면 중복체크 로직 작성해야함
        String uuid = UUID.randomUUID().toString();

        MemberCreateRequest memberCreateRequest = new MemberCreateRequest(email, profileImgUrl, nickname);

        saveAuth(email, "ROLE_USER", memberCreateRequest);



        return new DefaultOAuth2User(authorities, oAuth2User.getAttributes(), userNameAttributeName);
    }
}
