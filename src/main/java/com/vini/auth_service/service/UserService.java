package com.vini.auth_service.service;

import com.vini.auth_service.domain.User;
import com.vini.auth_service.dto.AuthResponse;
import com.vini.auth_service.dto.LoginRequest;
import com.vini.auth_service.dto.RegisterRequest;
import com.vini.auth_service.repository.UserRepository;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Arrays;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final TokenService tokenService;

    public User register(RegisterRequest request) {
        if (userRepository.existsByEmail(request.email())) {
            throw new IllegalArgumentException("Email already in use");
        }

        User user = User.builder()
                .email(request.email())
                .password(passwordEncoder.encode(request.password()))
                .build();

        return userRepository.save(user);
    }

    public AuthResponse login(LoginRequest request, HttpServletResponse response) {
        User user = userRepository.findByEmail(request.email())
                .orElseThrow(() -> new IllegalArgumentException("Invalid credentials"));

        if (!passwordEncoder.matches(request.password(), user.getPassword())) {
            throw new IllegalArgumentException("Invalid credentials");
        }

        String accessToken = jwtService.generateAccessToken(user.getEmail());
        String refreshToken = tokenService.createRefreshToken(
                user.getEmail(),
                jwtService.getRefreshTokenTtl()
        );

        setRefreshCookie(response, refreshToken);

        return new AuthResponse(accessToken, null);
    }

    public AuthResponse refresh(HttpServletRequest request, HttpServletResponse response) {
        String refreshToken = extractRefreshCookie(request);

        String email = tokenService.rotateRefreshToken(refreshToken);
        String newAccessToken = jwtService.generateAccessToken(email);
        String newRefreshToken = tokenService.createRefreshToken(
                email,
                jwtService.getRefreshTokenTtl()
        );

        setRefreshCookie(response, newRefreshToken);

        return new AuthResponse(newAccessToken, null);
    }

    public void logout(HttpServletRequest request, HttpServletResponse response) {
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String accessToken = authHeader.substring(7);
            if (jwtService.isTokenValid(accessToken)) {
                tokenService.blackListAccessToken(
                        accessToken,
                        jwtService.getRemainingTtl(accessToken)
                );
            }
        }

        String refreshToken = extractRefreshCookie(request);
        if (refreshToken != null) {
            tokenService.deleteRefreshToken(refreshToken);
        }

        clearRefreshCookie(response);
    }

    private void setRefreshCookie(HttpServletResponse response, String token) {
        Cookie cookie = new Cookie("refresh_token", token);
        cookie.setHttpOnly(true);
        cookie.setSecure(false); //true em produção com HTTPS
        cookie.setPath("/auth/refresh");
        cookie.setMaxAge(7 * 24 * 60 * 60);
        response.addCookie(cookie);
    }

    private void clearRefreshCookie(HttpServletResponse response) {
        Cookie cookie = new Cookie("refresh_token", "");
        cookie.setHttpOnly(true);
        cookie.setPath("/auth/refresh");
        cookie.setMaxAge(0);
        response.addCookie(cookie);
    }

    private String extractRefreshCookie(HttpServletRequest request) {
        if (request.getCookies() == null) return null;
        return Arrays.stream(request.getCookies())
                .filter(c -> "refresh_token".equals(c.getName()))
                .map(Cookie::getValue)
                .findFirst()
                .orElse(null);
    }
}