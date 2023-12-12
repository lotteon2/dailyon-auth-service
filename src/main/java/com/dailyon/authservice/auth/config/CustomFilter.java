package com.dailyon.authservice.auth.config;

import lombok.extern.slf4j.Slf4j;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Enumeration;

@Slf4j
public class CustomFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        log.info("$$$$$$$$$$$$$$$$$#ㅕ$&#$#$#");

        HttpServletRequest req = (HttpServletRequest) request;

        log.info(String.valueOf(req));

        if ("/admin/login".equals(req.getServletPath()) && "POST".equals(req.getMethod())) {
            Enumeration<String> params = req.getParameterNames();
            while (params.hasMoreElements()){
                String name = params.nextElement();
                String value = request.getParameter(name);
                System.out.println(name + " : " + value);
            }
        }
        chain.doFilter(request, response);
    }
}
