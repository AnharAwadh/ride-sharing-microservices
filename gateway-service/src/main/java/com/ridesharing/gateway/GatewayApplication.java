package com.ridesharing.gateway;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Main entry point for the API Gateway Service.
 * Handles routing, authentication, and authorization.
 */
@SpringBootApplication
public class GatewayApplication {
    
    private static final Logger log = LoggerFactory.getLogger(GatewayApplication.class);
    
    public static void main(String[] args) {
        log.info("Starting Gateway Service...");
        SpringApplication.run(GatewayApplication.class, args);
        log.info("Gateway Service started successfully on port 8080");
    }
}
