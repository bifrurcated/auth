package com.bifrurcated.auth.service;

import dev.samstevens.totp.secret.DefaultSecretGenerator;
import lombok.Getter;

public class Login {
    @Getter
    private final Jwt accessToken;
    @Getter
    private final Jwt refreshToken;
    @Getter
    private final String otpSecret;
    @Getter
    private final String optUrl;

    private Login(Jwt accessToken, Jwt refreshToken, String otpSecret, String optUrl) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.otpSecret = otpSecret;
        this.optUrl = optUrl;
    }

    public static Login of(Long userId, String accessSecret, Long accessTokenValidity, String refreshSecret, Long refreshTokenValidity, Boolean generateOtp) {
        String otpSecret = null;
        String otpUrl = null;

        if (generateOtp) {
            otpSecret = generateOtpSecret();
            otpUrl = getOtpUrl(otpSecret);
        }

        return new Login(
                Jwt.of(userId, accessTokenValidity, accessSecret),
                Jwt.of(userId, refreshTokenValidity, refreshSecret),
                otpSecret,
                otpUrl
        );
    }

    public static Login of(Long userId, String accessSecret, Long accessTokenValidity, Jwt refreshToken, Boolean generateOtp) {
        String otpSecret = null;
        String otpUrl = null;

        if (generateOtp) {
            otpSecret = generateOtpSecret();
            otpUrl = getOtpUrl(otpSecret);
        }
        return new Login(
                Jwt.of(userId, accessTokenValidity, accessSecret),
                refreshToken,
                otpSecret,
                otpUrl
        );
    }

    private static String generateOtpSecret() {
        return new DefaultSecretGenerator().generate();
    }

    private static String getOtpUrl(String otpSecret) {
        var appName = "My%20App";
        return String.format("otpauth://totp/%s:Secret?secret=%s&issuer=%s", appName, otpSecret, appName);
    }
}
