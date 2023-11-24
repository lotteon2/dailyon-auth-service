package com.dailyon.authservice.auth.feign;

import com.dailyon.authservice.auth.config.MemberFeignConfig;
import com.dailyon.authservice.auth.feign.request.MemberCreateRequest;
import com.dailyon.authservice.auth.feign.request.MemberGetRequest;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.*;


@FeignClient(name ="member-service", url ="http://localhost:8081" , configuration = MemberFeignConfig.class)
public interface MemberApiClient {
    @GetMapping("/members/{id}")
    MemberGetRequest getMember(@PathVariable Long id);

    @GetMapping("/members/check/{email}")
    boolean duplicateCheck(@PathVariable String email);

   @PostMapping("/members/register")
    void registerMember(@RequestBody MemberCreateRequest request);

}
