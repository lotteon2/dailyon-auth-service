package com.dailyon.authservice.auth.config;

import com.dailyon.authservice.auth.service.AuthService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.util.Map;

@Configuration
@EnableMethodSecurity
public class OAuth2SuccessHandler {
    private final OAuth2UserService oAuth2UserService;
    private final AuthService authService;

    public OAuth2SuccessHandler(OAuth2UserService oAuth2UserService, AuthService authService) {
        this.oAuth2UserService = oAuth2UserService;
        this.authService = authService;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.authorizeHttpRequests(config -> config.anyRequest().permitAll());
        http.oauth2Login(oauth2Configurer -> oauth2Configurer
                .loginPage("/login")
                .successHandler(successHandler())
                .userInfoEndpoint()
                .userService(oAuth2UserService));

        return http.build();
    }

    @Bean
    public AuthenticationSuccessHandler successHandler() {
        return ((request, response, authentication) -> {
            DefaultOAuth2User defaultOAuth2User = (DefaultOAuth2User) authentication.getPrincipal();

            String id = defaultOAuth2User.getAttributes().get("id").toString();

            Map<String, Object> kakaoInfo =  (Map<String, Object>) defaultOAuth2User.getAttribute("properties");

            String nickname = (String) kakaoInfo.get("nickname");
            String profilePicture = (String) kakaoInfo.get("profile_image");

            Map<String, Object> kakaoAccount = (Map<String, Object>) defaultOAuth2User.getAttribute("kakao_account");
            String email = (String) kakaoAccount.get("email");

            //String gender =  Optional.ofNullable(defaultOAuth2User.getAttributes().get("kakao_account.profile_image_url")).orElse("").toString();;

        });
    }
}
