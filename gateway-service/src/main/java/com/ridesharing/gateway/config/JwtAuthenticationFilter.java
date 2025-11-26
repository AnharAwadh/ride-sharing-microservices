package com.ridesharing.gateway.config;

import com.ridesharing.gateway.dto.Role;
import com.ridesharing.gateway.security.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;


@Component
@RequiredArgsConstructor
@Log4j2
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {
    

    private final JwtUtil jwtUtil;
    
    private static final List<String> PUBLIC_PATHS = List.of(
            "/auth/login",
            "/auth/register"
    );
    
    private static final List<String> CUSTOMER_PATHS = List.of("/api/customer");
    private static final List<String> DRIVER_PATHS = List.of("/api/driver");
    
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getPath().value();
        log.debug("Processing request for path: {}", path);
        
        if (isPublicPath(path)) {
            log.debug("Public path accessed: {}", path);
            return chain.filter(exchange);
        }
        
        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            log.warn("Missing or invalid Authorization header for path: {}", path);
            return onError(exchange, HttpStatus.UNAUTHORIZED);
        }
        
        String token = authHeader.substring(7);
        
        try {
            if (!jwtUtil.validateToken(token)) {
                log.warn("Invalid or expired JWT token for path: {}", path);
                return onError(exchange, HttpStatus.UNAUTHORIZED);
            }
            
            String username = jwtUtil.extractUsername(token);
            Long userId = jwtUtil.extractUserId(token);
            Role role = jwtUtil.extractRole(token);
            
            log.info("Authenticated user: {}, role: {} accessing path: {}", username, role, path);
            
            if (!isAuthorizedForPath(path, role)) {
                log.warn("User {} with role {} not authorized for path: {}", username, role, path);
                return onError(exchange, HttpStatus.FORBIDDEN);
            }
            
            ServerHttpRequest modifiedRequest = exchange.getRequest().mutate()
                    .header("X-User-Id", String.valueOf(userId))
                    .header("X-User-Name", username)
                    .header("X-User-Role", role.name())
                    .build();
            
            return chain.filter(exchange.mutate().request(modifiedRequest).build());
            
        } catch (Exception e) {
            log.error("Error processing JWT token: {}", e.getMessage());
            return onError(exchange, HttpStatus.UNAUTHORIZED);
        }
    }
    
    private boolean isPublicPath(String path) {
        return PUBLIC_PATHS.stream().anyMatch(path::startsWith);
    }
    
    private boolean isAuthorizedForPath(String path, Role role) {
        if (CUSTOMER_PATHS.stream().anyMatch(path::startsWith)) {
            return role == Role.CUSTOMER;
        }
        if (DRIVER_PATHS.stream().anyMatch(path::startsWith)) {
            return role == Role.DRIVER;
        }
        return true;
    }
    
    private Mono<Void> onError(ServerWebExchange exchange, HttpStatus status) {
        exchange.getResponse().setStatusCode(status);
        return exchange.getResponse().setComplete();
    }
    
    @Override
    public int getOrder() {
        return -100;
    }
}
