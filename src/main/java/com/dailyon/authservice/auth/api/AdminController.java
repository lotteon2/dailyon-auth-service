package com.dailyon.authservice.auth.api;

import com.dailyon.authservice.auth.api.request.AdminLoginRequest;
import com.dailyon.authservice.auth.config.OAuth2SuccessHandler;
import com.dailyon.authservice.auth.service.AdminService;
import com.dailyon.authservice.auth.service.AuthService;
import com.dailyon.authservice.jwt.JwtService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

@RestController
@RequestMapping("/admin")
@Slf4j
@CrossOrigin("*")
public class AdminController {
    @GetMapping("")
    public void test() {
        log.info("admintest : {} => ");
    }

}


