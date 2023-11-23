package com.dailyon.authservice.auth.feign;

import com.dailyon.authservice.auth.config.MemberFeignConfig;
import com.dailyon.authservice.auth.feign.request.MemberGetRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;


@FeignClient(name ="member-service", url ="http://localhost:8081" , configuration = MemberFeignConfig.class)
public interface MemberApiClient {
    @GetMapping("/members/{id}")
    MemberGetRequest getMember(@PathVariable Long id);

}
