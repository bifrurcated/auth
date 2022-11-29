package com.bifrurcated.auth.interceptor;

import com.bifrurcated.auth.error.NoBearerTokenError;
import com.bifrurcated.auth.service.AuthService;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Component
public class AuthorizationInterceptor implements HandlerInterceptor {
    private final AuthService authService;

    public AuthorizationInterceptor(AuthService authService) {
        this.authService = authService;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            throw new NoBearerTokenError();
        }

        request.setAttribute("user", authService.getUserFromToken(authorizationHeader.substring(7)));

        return true;
    }
}
