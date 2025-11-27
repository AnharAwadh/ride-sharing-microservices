package com.ridesharing.gateway.service;

import com.ridesharing.gateway.dto.*;
import com.ridesharing.gateway.entity.User;
import com.ridesharing.gateway.exception.BadRequestException;
import com.ridesharing.gateway.exception.ConflictException;
import com.ridesharing.gateway.exception.UnauthorizedException;
import com.ridesharing.gateway.repository.UserRepository;
import com.ridesharing.gateway.security.CustomUserDetails;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebSession;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;


@Service
@RequiredArgsConstructor
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final ReactiveAuthenticationManager authenticationManager;

    private static final int SESSION_TIMEOUT = 3600; // 1 hour in seconds
    private static final String SPRING_SECURITY_CONTEXT = "SPRING_SECURITY_CONTEXT";

    public Mono<LoginResponse> login(LoginRequest request, ServerWebExchange exchange) {
        log.info("Login attempt for user: {}", request.getUsername());

        return authenticationManager.authenticate(
                        new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
                )
                .flatMap(authentication -> {
                    SecurityContext securityContext = new SecurityContextImpl(authentication);

                    return exchange.getSession()
                            .flatMap(session -> {
                                session.getAttributes().put(SPRING_SECURITY_CONTEXT, securityContext);
                                session.setMaxIdleTime(java.time.Duration.ofSeconds(SESSION_TIMEOUT));

                                CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
                                UserResponse userResponse = UserResponse.builder()
                                        .id(userDetails.getId())
                                        .username(userDetails.getUsername())
                                        .email(userDetails.getEmail())
                                        .phone(userDetails.getPhone())
                                        .role(Role.valueOf(userDetails.getRole()))
                                        .build();

                                log.info("Login successful for user: {}, session: {}",
                                        request.getUsername(), session.getId());

                                return Mono.just(LoginResponse.of(session.getId(), (long) SESSION_TIMEOUT, userResponse));
                            });
                })
                .onErrorResume(e -> {
                    log.warn("Login failed for user {}: {}", request.getUsername(), e.getMessage());
                    return Mono.error(new UnauthorizedException("Invalid username or password"));
                });
    }

    public UserResponse register(RegisterRequest request) {
        log.info("Registration attempt for user: {}, role: {}", request.getUsername(), request.getRole());

        // 1. Check Username
        if (userRepository.existsByUsername(request.getUsername())) {
            log.warn("Registration failed: Username already exists - {}", request.getUsername());
            throw new ConflictException("Username already exists");
        }

        // 2. Check Email
        if (userRepository.existsByEmail(request.getEmail())) {
            log.warn("Registration failed: Email already exists - {}", request.getEmail());
            throw new ConflictException("Email already exists");
        }

        // 3. Create User
        User user = User.builder()
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .email(request.getEmail())
                .phone(request.getPhone())
                .role(request.getRole())
                .enabled(true)
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .build();

        // 4. Save User
        User savedUser = userRepository.save(user);

        log.info("User registered successfully: {}, id: {}", savedUser.getUsername(), savedUser.getId());

        // 5. Map to Response
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
