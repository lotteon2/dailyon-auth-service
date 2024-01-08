package com.dailyon.authservice.jwt;

import com.dailyon.authservice.auth.entity.Auth;
import com.dailyon.authservice.auth.repository.AuthRepository;
import com.google.common.base.Function;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.crypto.SecretKey;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

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

        String accessToken = Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                //.setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10))
                .setExpiration(new Date(System.currentTimeMillis() + 10000)) // 10초
                .signWith(Keys.hmacShaKeyFor(environment.getProperty("secretKey").getBytes()))
                .compact();

        storeRefreshToken(subject, refreshToken);

        return accessToken;
    }

    private String generateRefreshToken(String subject, Map<String, Object> claims) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 100000))
                .signWith(Keys.hmacShaKeyFor(environment.getProperty("secretKey").getBytes()))
                .compact();
    }

    private void storeRefreshToken(String subject, String refreshToken) {
        String key = "refreshToken:" + subject;
        redisTemplate.opsForValue().set(key, refreshToken);
    }


/*    public Boolean validateRefreshToken(String username) {
        String storedRefreshToken = getStoredRefreshToken(username);

        if (storedRefreshToken == null) {
            return false;
        }

        Date expirationDate = extractExpiration(storedRefreshToken);
        return !expirationDate.before(new Date());
    }*/

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
        // 1. access 토큰 검증
        Optional<Auth> auth = authRepository.findById(memberId);
        String username = auth.get().getEmail();

        if (isRefreshTokenExpired(username)) {
            return "refreshTokenExpired";
        }

      /*  if (!validateRefreshToken(username)) {
            // refreshToken이 만료되었으면 클라이언트에게 다시 로그인을 요청하도록 처리
            throw new RuntimeException("RefreshToken expired");
        }*/

        // 2. refresh 토큰 claims 추출
        Claims refreshTokenClaims = extractClaimsFromRefreshToken(username);

        // 3. access 토큰 재발급
        Map<String, Object> accessTokenClaims = new HashMap<>();
        accessTokenClaims.put("role", refreshTokenClaims.get("role"));
        accessTokenClaims.put("memberId", refreshTokenClaims.get("memberId"));


        String newAccessToken = generateToken(username, accessTokenClaims, response);

        // 4. refresh 토큰 재발급
        //String newRefreshToken = generateRefreshToken(username, accessTokenClaims);
        String newRefreshToken = refreshTokenClaims.getExpiration().before(new Date())
                ? null
                : generateRefreshToken(username, accessTokenClaims);

        // 5. Redis에 새로운 refresh 토큰 저장
        storeRefreshToken(username, newRefreshToken);

        return newAccessToken;
    }

    // 리프레시 claim 가져오기
    private Claims extractClaimsFromRefreshToken(String username) {
        String refreshToken = getStoredRefreshToken(username);
        Claims refreshTokenClaims = Jwts.parser().setSigningKey(Keys.hmacShaKeyFor(key.getBytes())).parseClaimsJws(refreshToken).getBody();
        return refreshTokenClaims;
    }



}
