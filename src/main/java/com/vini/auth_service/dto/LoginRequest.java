package com.vini.auth_service.dto;

import jakarta.validation.constraints.NotBlank;

public record LoginRequest(
        @NotBlank(message = "Email is required")
        @NotBlank(message = "Invalid email format")
        String email,

        @NotBlank(message = "Password is required")
        String password
) {
}
