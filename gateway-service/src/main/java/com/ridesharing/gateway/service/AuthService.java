package com.ridesharing.gateway.service;

import com.ridesharing.gateway.dto.*;
import com.ridesharing.gateway.entity.User;
import com.ridesharing.gateway.exception.BadRequestException;
import com.ridesharing.gateway.exception.ConflictException;
import com.ridesharing.gateway.exception.UnauthorizedException;
import com.ridesharing.gateway.repository.UserRepository;
import com.ridesharing.gateway.security.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;


@Service
@RequiredArgsConstructor
@Log4j2
public class AuthService {
    

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    
    @Transactional(readOnly = true)
    public LoginResponse login(LoginRequest request) {
        log.info("Login attempt for user: {}", request.getUsername());
        
        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> {
                    log.warn("Login failed: User not found - {}", request.getUsername());
                    return new UnauthorizedException("Invalid username or password");
                });
        
        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            log.warn("Login failed: Invalid password for user - {}", request.getUsername());
            throw new UnauthorizedException("Invalid username or password");
        }
        
        if (!user.getEnabled()) {
            log.warn("Login failed: User account disabled - {}", request.getUsername());
            throw new UnauthorizedException("User account is disabled");
        }
        
        String token = jwtUtil.generateToken(user.getUsername(), user.getId(), user.getRole());
        UserResponse userResponse = mapToUserResponse(user);
        
        log.info("Login successful for user: {}, role: {}", user.getUsername(), user.getRole());
        return LoginResponse.of(token, jwtUtil.getExpirationTime(), userResponse);
    }
    
    @Transactional
    public UserResponse register(RegisterRequest request) {
        log.info("Registration attempt for user: {}, role: {}", request.getUsername(), request.getRole());
        
        if (userRepository.existsByUsername(request.getUsername())) {
            log.warn("Registration failed: Username already exists - {}", request.getUsername());
            throw new ConflictException("Username already exists");
        }
        
        if (userRepository.existsByEmail(request.getEmail())) {
            log.warn("Registration failed: Email already exists - {}", request.getEmail());
            throw new ConflictException("Email already exists");
        }
        
        User user = User.builder()
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .email(request.getEmail())
                .phone(request.getPhone())
                .role(request.getRole())
                .enabled(true)
                .build();
        
        User savedUser = userRepository.save(user);
        log.info("User registered successfully: {}, id: {}", savedUser.getUsername(), savedUser.getId());
        
        return mapToUserResponse(savedUser);
    }

    
    private UserResponse mapToUserResponse(User user) {
        return UserResponse.builder()
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .phone(user.getPhone())
                .role(user.getRole())
                .createdAt(user.getCreatedAt())
                .build();
    }
}
