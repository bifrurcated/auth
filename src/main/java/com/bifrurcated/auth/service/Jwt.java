package com.bifrurcated.auth.service;

import com.bifrurcated.auth.data.Token;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.Getter;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.Date;

public class Jwt {
    @Getter
    private final String token;
    @Getter
    private final LocalDateTime issueAt;
    @Getter
    private final LocalDateTime expiration;
    @Getter
    private final Long userId;

    private Jwt(String token, LocalDateTime issueAt, LocalDateTime expiration, Long userId) {
        this.token = token;
        this.issueAt = issueAt;
        this.expiration = expiration;
        this.userId = userId;
    }

    public static Jwt of(Long userId, Long validityInMinutes, String secretKey) {
        var issueDate = Instant.now();
        //SecretKey keys = new SecretKeySpec(secretKey.getBytes(StandardCharsets.UTF_8), SignatureAlgorithm.HS256.getJcaName());
        var expiration = issueDate.plus(validityInMinutes, ChronoUnit.MINUTES);
        final String tokenStr = Jwts.builder()
                .claim("user_id", userId)
                .setIssuedAt(Date.from(issueDate))
                .setExpiration(Date.from(expiration))
                .signWith(Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8)))
                .compact();
        return new Jwt(
                tokenStr,
                LocalDateTime.ofInstant(issueDate, ZoneId.systemDefault()),
                LocalDateTime.ofInstant(expiration, ZoneId.systemDefault()),
                userId
        );
    }

    public static Jwt from(String token, String accessTokenSecret) {
        var claims = Jwts.parserBuilder()
                .setSigningKey(Keys.hmacShaKeyFor(accessTokenSecret.getBytes(StandardCharsets.UTF_8)))
                .build()
                .parseClaimsJws(token)
                .getBody();
        return new Jwt(
                token,
                LocalDateTime.ofInstant(claims.getIssuedAt().toInstant(), ZoneId.systemDefault()),
                LocalDateTime.ofInstant(claims.getExpiration().toInstant(), ZoneId.systemDefault()),
                claims.get("user_id", Long.class)
        );
    }

}
