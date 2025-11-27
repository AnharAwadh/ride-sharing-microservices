package com.ridesharing.gateway.config;

import com.ridesharing.gateway.security.CustomUserDetails;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;


@Component
public class AuthenticationHeadersFilter implements GlobalFilter, Ordered {
    
    private static final Logger log = LoggerFactory.getLogger(AuthenticationHeadersFilter.class);
    
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return ReactiveSecurityContextHolder.getContext()
                .map(SecurityContext::getAuthentication)
                .filter(Authentication::isAuthenticated)
                .flatMap(authentication -> {
                    if (authentication.getPrincipal() instanceof CustomUserDetails userDetails) {
                        log.debug("Adding user headers for: {}", userDetails.getUsername());
                        
                        ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                                .header("X-User-Id", String.valueOf(userDetails.getId()))
                                .header("X-User-Name", userDetails.getUsername())
                                .header("X-User-Role", userDetails.getRole())
                                .build();
                        
                        ServerWebExchange mutatedExchange = exchange.mutate()
                                .request(mutatedRequest)
                                .build();
                        
                        return chain.filter(mutatedExchange);
                    }
                    return chain.filter(exchange);
                })
                .switchIfEmpty(chain.filter(exchange));
    }
    
    @Override
    public int getOrder() {
        return -100; // Run early in the filter chain
    }
}
