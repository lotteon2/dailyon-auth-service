package com.dailyon.authservice.auth.api;

import com.dailyon.authservice.auth.feign.request.MemberGetRequest;
import com.dailyon.authservice.auth.service.AuthService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;


@Controller
@Slf4j
@RequestMapping("/auth")
@CrossOrigin("*")
public class AuthApiController {

    @Autowired
    private AuthService authService;


    @GetMapping("/index")
    public String index() {
        return "login";
    }


    @GetMapping("/search/{id}")
    public ResponseEntity<MemberGetRequest> getMember(@PathVariable Long id) {
        MemberGetRequest memberData = authService.getMember(id);

        if (memberData == null) {
            return ResponseEntity.notFound().build();
        }

        return ResponseEntity.ok(memberData);
    }


}


