package com.ridesharing.gateway.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;


@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LoginResponse {
    private String sessionId;
    private Long expiresIn;
    private UserResponse user;

    public static LoginResponse of(String sessionId, Long expiresIn, UserResponse user) {
        return LoginResponse.builder()
                .sessionId(sessionId)
                .expiresIn(expiresIn)
                .user(user)
                .build();
    }
}
