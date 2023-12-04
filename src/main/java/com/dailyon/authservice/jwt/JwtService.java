package com.dailyon.authservice.jwt;

import com.dailyon.authservice.auth.entity.Auth;
import com.dailyon.authservice.auth.repository.AuthRepository;
import com.google.common.base.Function;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.crypto.SecretKey;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
public class JwtService {


    @Autowired
    private AuthRepository authRepository;

    //TODO: Secret Key 테스트 완료 후 암호화 예정
    private String SECRET_KEY = "thisIsMySecretKeyWhichIsAtLeast32Characters";

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(token).getBody();
    }

    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public String generateToken(String username, Map<String, Object> claims, HttpServletResponse response) {
        String jwtToken = createToken(claims, username);
        setTokenCookie(jwtToken, response);

        return jwtToken;
    }


    private void setTokenCookie(String token, HttpServletResponse response) {
        if (response == null) {
            System.out.println("Response is null. Cannot set cookie.");
            return;
        }

        Cookie cookie = new Cookie("userInfo", token);
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        cookie.setSecure(false); // 서비스시 true로?
        cookie.setMaxAge(3600); // 1시간 동안 유지
        response.addCookie(cookie);

    }


    //TODO: 토큰 정상 작동 확인 후 Refresh 설정 및 지속 시간 수정
    private String createToken(Map<String, Object> claims, String subject) {
        SecretKey key = Keys.secretKeyFor(SignatureAlgorithm.HS256);
        return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10))
                .signWith(key).compact();
    }


    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    public String getTokenFromRequest(HttpServletRequest request) {
        final String authorizationHeader = request.getHeader("Authorization");

        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            return authorizationHeader.substring(7); //
        }

        return authorizationHeader;
    }




}
