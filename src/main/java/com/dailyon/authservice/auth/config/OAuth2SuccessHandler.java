package com.dailyon.authservice.auth.config;

import com.dailyon.authservice.auth.service.AuthService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Map;

import static org.springframework.security.config.Customizer.withDefaults;


@Slf4j
@Configuration
@EnableMethodSecurity

public class OAuth2SuccessHandler {
    private final OAuth2UserService oAuth2UserService;
    private final AuthService authService;

    @Autowired
    private Environment environment;

    public OAuth2SuccessHandler(OAuth2UserService oAuth2UserService, AuthService authService) {
        this.oAuth2UserService = oAuth2UserService;
        this.authService = authService;
    }


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .cors(withDefaults())
                .csrf().disable()
                .authorizeHttpRequests(config -> config
                        .antMatchers("/h2-console/**").permitAll()
                        .anyRequest().permitAll())
                .headers(headers -> headers.frameOptions().disable())
                .oauth2Login(oauth2Configurer -> oauth2Configurer
                        .successHandler(successHandler())
                        .userInfoEndpoint()
                        .userService(oAuth2UserService))

                .formLogin(formLoginConfigurer -> formLoginConfigurer
                        .loginProcessingUrl("/admin/login")
                        .successHandler(adminSuccessHandler()));

        return http.build();
    }



    private AuthenticationSuccessHandler adminSuccessHandler() {
        return (request, response, authentication) -> {
            UserDetails userDetails = (UserDetails) authentication.getPrincipal();

            String email = userDetails.getUsername();
            String token = authService.generateToken(email, response);

            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            response.getWriter().write("{\"token\":\"" + token + "\"}");

        };
    }

    @Bean
    public AuthenticationSuccessHandler successHandler() {
        return (request, response, authentication) -> {
            OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
            Map<String, Object> userAttributes = oAuth2User.getAttributes();
            String provider = ((OAuth2AuthenticationToken) authentication).getAuthorizedClientRegistrationId();

            if (provider.equals("kakao")) {
                Map<String, Object> kakaoAccount = (Map<String, Object>) userAttributes.get("kakao_account");
                String email = (String) kakaoAccount.get("email");
                String token = authService.generateToken(email, response);

                response.sendRedirect(environment.getProperty("redirectUrl") + "?token=" + token);
            } else if(provider.equals("google")) {
                String email = oAuth2User.getAttribute("email");
                String token = authService.generateToken(email, response);

                response.sendRedirect(environment.getProperty("redirectUrl") + "?token=" + token);
            }
        };
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.addAllowedOrigin("*");
        configuration.addAllowedMethod("*");
        configuration.addAllowedHeader("*");
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }



}