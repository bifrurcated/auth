package com.bifrurcated.auth.service;

import com.bifrurcated.auth.data.Token;
import lombok.Getter;

public class Login {
    @Getter
    private final Jwt accessToken;
    @Getter
    private final Jwt refreshToken;

    private Login(Jwt accessToken, Jwt refreshToken) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
    }

    public static Login of(Long userId, String accessSecret, Long accessTokenValidity, String refreshSecret, Long refreshTokenValidity) {
        return new Login(
                Jwt.of(userId, accessTokenValidity, accessSecret),
                Jwt.of(userId, refreshTokenValidity, refreshSecret)
        );
    }

    public static Login of(Long userId, String accessSecret, Jwt refreshToken, Long refreshTokenValidity) {
        return new Login(
                Jwt.of(userId, 10L, accessSecret),
                refreshToken
        );
    }
}
