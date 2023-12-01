package com.dailyon.authservice.auth.config;

import com.dailyon.authservice.jwt.JwtService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;

import javax.servlet.http.Cookie;


@Configuration
@EnableMethodSecurity
public class OAuth2SuccessHandler {
    private final OAuth2UserService oAuth2UserService;

    private final JwtService jwtService;

    public OAuth2SuccessHandler(OAuth2UserService oAuth2UserService, JwtService jwtService) {
        this.oAuth2UserService = oAuth2UserService;
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
                        .failureHandler(failureHandler())
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
            String token = jwtService.getTokenFromRequest(request);

            Cookie cookie = new Cookie("Authorization", "Bearer " + token);
            cookie.setHttpOnly(true);
            cookie.setMaxAge(7 * 24 * 60 * 60);

            response.addCookie(cookie);

            response.sendRedirect("/login-success");
        };
    }

    @Bean
    public AuthenticationFailureHandler failureHandler() {
        return new SimpleUrlAuthenticationFailureHandler("/login-failure");
    }
}
