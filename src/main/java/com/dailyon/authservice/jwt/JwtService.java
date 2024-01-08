package com.dailyon.authservice.jwt;

import com.dailyon.authservice.auth.entity.Auth;
import com.dailyon.authservice.auth.repository.AuthRepository;
import com.google.common.base.Function;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import javax.servlet.http.HttpServletResponse;
import java.util.*;

@Service
@Slf4j
public class JwtService {

    @Autowired
    private AuthRepository authRepository;

    @Autowired
    private Environment environment;

    @Autowired
    private RedisTemplate<String, Object> redisTemplate;

    @Value("${secretKey}")
    private String key;

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser().setSigningKey(Keys.hmacShaKeyFor(key.getBytes())).parseClaimsJws(token).getBody();
    }

    public String generateToken(String username, Map<String, Object> claims, HttpServletResponse response) {
        String jwtToken = createToken(claims, username);
        setTokenHeader(jwtToken, response);

        return jwtToken;
    }


    private void setTokenHeader(String token, HttpServletResponse response) {
        if (response == null) {
            return;
        }

        response.addHeader("Authorization", "Bearer " + token);
    }


    //TODO: 토큰 만료시간 설정 및 환경변수화 시켜야함
    private String createToken(Map<String, Object> claims, String subject) {
        String refreshToken = generateRefreshToken(subject, claims);

        long accessExpInMillis = Long.parseLong(Objects.requireNonNull(environment.getProperty("accessExp")));


        String accessToken = Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + accessExpInMillis)) // 10초
                .signWith(Keys.hmacShaKeyFor(environment.getProperty("secretKey").getBytes()))
                .compact();

        storeRefreshToken(subject, refreshToken);

        return accessToken;
    }

    private String generateRefreshToken(String subject, Map<String, Object> claims) {
        long refreshExpInMillis = Long.parseLong(Objects.requireNonNull(environment.getProperty("refreshExp")));
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + refreshExpInMillis))
                .signWith(Keys.hmacShaKeyFor(environment.getProperty("secretKey").getBytes()))
                .compact();
    }

    private void storeRefreshToken(String subject, String refreshToken) {
        String key = "refreshToken:" + subject;
        redisTemplate.opsForValue().set(key, refreshToken);
    }


    public boolean isRefreshTokenExpired(String username) {
        String storedRefreshToken = getStoredRefreshToken(username);

        if (storedRefreshToken == null) {
            return true;
        }

        Date expirationDate = extractExpiration(storedRefreshToken);
        return expirationDate.before(new Date());
    }



    private String getStoredRefreshToken(String username) {
        String key = "refreshToken:" + username;
        return (String) redisTemplate.opsForValue().get(key);
    }


    public String refreshTokens(Long memberId, String accessToken, HttpServletResponse response) {

        Optional<Auth> auth = authRepository.findById(memberId);
        String username = auth.get().getEmail();

        if (isRefreshTokenExpired(username)) {
            return "refreshTokenExpired";
        }

        Claims refreshTokenClaims = extractClaimsFromRefreshToken(username);

        Map<String, Object> accessTokenClaims = new HashMap<>();
        accessTokenClaims.put("role", refreshTokenClaims.get("role"));
        accessTokenClaims.put("memberId", refreshTokenClaims.get("memberId"));


        String newAccessToken = generateToken(username, accessTokenClaims, response);

        String newRefreshToken = refreshTokenClaims.getExpiration().before(new Date())
                ? null
                : generateRefreshToken(username, accessTokenClaims);

        storeRefreshToken(username, newRefreshToken);

        return newAccessToken;
    }

    private Claims extractClaimsFromRefreshToken(String username) {
        String refreshToken = getStoredRefreshToken(username);
        Claims refreshTokenClaims = Jwts.parser().setSigningKey(Keys.hmacShaKeyFor(key.getBytes())).parseClaimsJws(refreshToken).getBody();
        return refreshTokenClaims;
    }



}
