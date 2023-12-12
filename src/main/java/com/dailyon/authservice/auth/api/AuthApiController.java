package com.dailyon.authservice.auth.api;

import com.dailyon.authservice.auth.feign.request.MemberGetRequest;
import com.dailyon.authservice.auth.service.AuthService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;


@RestController
@Slf4j
@RequestMapping("/auth")
@CrossOrigin("*")
public class AuthApiController {

}


