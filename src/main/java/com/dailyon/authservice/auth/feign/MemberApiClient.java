package com.dailyon.authservice.auth.feign;

import com.dailyon.authservice.auth.config.MemberFeignConfig;
import com.dailyon.authservice.auth.feign.request.MemberCreateRequest;
import com.dailyon.authservice.auth.feign.request.MemberGetRequest;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;


@FeignClient(name ="member-service",
        url = "${endpoint.member-service}",
        configuration = MemberFeignConfig.class)
public interface MemberApiClient {
   @PostMapping("/clients/members/register")
   ResponseEntity<Long> registerMember(@RequestBody MemberCreateRequest request);

}
