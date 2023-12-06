package com.dailyon.authservice.auth.config;

import com.dailyon.authservice.auth.service.AuthService;
import com.dailyon.authservice.jwt.JwtService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;

import java.util.Map;


@Configuration
@EnableMethodSecurity
public class OAuth2SuccessHandler {
    private final OAuth2UserService oAuth2UserService;
    private final AuthService authService;

    private final JwtService jwtService;

    public OAuth2SuccessHandler(OAuth2UserService oAuth2UserService, AuthService authService, JwtService jwtService) {
        this.oAuth2UserService = oAuth2UserService;
        this.authService = authService;
        this.jwtService = jwtService;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.authorizeHttpRequests(config -> config.anyRequest().permitAll());
        http
                .oauth2Login(oauth2Configurer -> oauth2Configurer
                        .loginPage("/login")
                        .successHandler(successHandler())
                        .userInfoEndpoint()
                        .userService(oAuth2UserService));

        http.formLogin(formLoginConfigurer -> formLoginConfigurer
                .loginPage("/admin/login")
                .loginProcessingUrl("/admin/login")
                .defaultSuccessUrl("/admin/dashboard", true)
                .permitAll());

        return http.build();
    }

    @Bean
    public AuthenticationSuccessHandler successHandler() {
        return (request, response, authentication) -> {
            OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
            Map<String, Object> userAttributes = oAuth2User.getAttributes();
            Map<String, Object> kakaoAccount = (Map<String, Object>) userAttributes.get("kakao_account");
            String email = (String) kakaoAccount.get("email");
            authService.generateToken(email, response);

            response.sendRedirect("http://localhost:5173/logininfo");
        };
    }



}
