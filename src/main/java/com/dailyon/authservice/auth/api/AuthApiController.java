package com.dailyon.authservice.auth.api;

import com.dailyon.authservice.auth.feign.request.MemberGetRequest;
import com.dailyon.authservice.auth.service.AuthService;
import com.dailyon.authservice.jwt.JwtService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import java.util.Collections;
import java.util.Map;


@RestController
@Slf4j
@RequestMapping("/auth")
@CrossOrigin("*")
public class AuthApiController {
    @Autowired
    private JwtService jwtService;

    @PostMapping("/refresh-token")
    public ResponseEntity<Map<String, String>> refreshTokens(@RequestHeader Long memberId,@RequestBody Map<String, String> request, HttpServletResponse response) {
        String accessToken = request.get("accessToken");

        if (accessToken == null) {
            return ResponseEntity.badRequest().body(Collections.singletonMap("error", "Access token is missing."));
        }

        String newAccessToken = jwtService.refreshTokens(memberId,accessToken, response);

        if (newAccessToken != null) {
            Map<String, String> responseMap = Collections.singletonMap("accessToken", newAccessToken);
            return ResponseEntity.ok(responseMap);
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Collections.singletonMap("error", "Failed to refresh tokens. Please log in again."));
        }
    }
}


