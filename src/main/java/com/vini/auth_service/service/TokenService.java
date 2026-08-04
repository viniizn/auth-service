package com.vini.auth_service.service;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class TokenService {
    private final StringRedisTemplate redis;

    private static final String REFRESH_PREFIX = "refresh:";
    private static final String BLACKLIST_PREFIX = "blacklist:";

    //Salvar o refresh token no redis vinculado ao email
    public String createRefreshToken(String email, Duration ttl) {
        String token = UUID.randomUUID().toString();
        redis.opsForValue().set(REFRESH_PREFIX + token, email, ttl);
        return token;
    }

    //Valida e retorna o email do refresh Token
    public String rotateRefreshToken(String token) {
        String key = REFRESH_PREFIX + token;
        String email = redis.opsForValue().get(key);

        if (email == null) {
            throw new IllegalArgumentException("Invalid or expired refresh token");
        }

        redis.delete(key);
        return email;
    }

    //Invalida o refresh token no logout
    public void deleteRefreshToken(String token) {
        redis.delete(REFRESH_PREFIX + token);
    }

    //Coloca access token na blacklist
    public void blackListAccessToken(String token, Duration ttl) {
        redis.opsForValue().set(BLACKLIST_PREFIX + token, "true", ttl);
    }

    //Verifica se access tokeen está na blacklist
    public boolean isBlacklisted(String token) {
        return Boolean.TRUE.equals(redis.hasKey(BLACKLIST_PREFIX + token));
    }
}
