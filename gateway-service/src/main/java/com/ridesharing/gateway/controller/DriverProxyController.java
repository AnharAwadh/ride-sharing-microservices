package com.ridesharing.gateway.controller;

import com.ridesharing.gateway.security.CurrentUser;
import com.ridesharing.gateway.security.CustomUserDetails;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

/**
 * Proxy controller to forward driver requests to Driver Service.
 * Adds user information from session to headers.
 */
@RestController
@RequestMapping("/api/driver")
@RequiredArgsConstructor
@Log4j2
public class DriverProxyController {
    

    private final RestTemplate restTemplate;
    
    @Value("${driver-service.url:http://localhost:8082}")
    private String driverServiceUrl;


    @GetMapping("/profile")
    @PreAuthorize("hasRole('DRIVER')")
    public ResponseEntity<String> getProfile(
            @CurrentUser CustomUserDetails currentUser) {

        log.info("Proxying profile for driver: {}", currentUser.getUsername());
        return forwardRequest("/api/driver/profile", HttpMethod.GET,null, currentUser);
    }
    
    @PutMapping("/status")
    @PreAuthorize("hasRole('DRIVER')")
    public ResponseEntity<String> updateStatus(
            @CurrentUser CustomUserDetails currentUser,
            @RequestBody String body) {
        
        log.info("Proxying status update for driver: {}", currentUser.getUsername());
        return forwardRequest("/api/driver/status", HttpMethod.PUT, body, currentUser);
    }

    
    @GetMapping("/rides/available")
    @PreAuthorize("hasRole('DRIVER')")
    public ResponseEntity<String> getAvailableRides(@CurrentUser CustomUserDetails currentUser) {
        log.info("Proxying available rides request for driver: {}", currentUser.getUsername());
        return forwardRequest("/api/driver/rides/available", HttpMethod.GET, null, currentUser);
    }
    
    @PostMapping("/rides/{rideId}/accept")
    @PreAuthorize("hasRole('DRIVER')")
    public ResponseEntity<String> acceptRide(
            @CurrentUser CustomUserDetails currentUser,
            @PathVariable Long rideId) {
        
        log.info("Proxying accept ride request for driver: {}, rideId: {}", currentUser.getUsername(), rideId);
        return forwardRequest("/api/driver/rides/" + rideId + "/accept", HttpMethod.POST, null, currentUser);
    }

    
    @GetMapping("/rides/history")
    @PreAuthorize("hasRole('DRIVER')")
    public ResponseEntity<String> getRideHistory(@CurrentUser CustomUserDetails currentUser) {
        log.info("Proxying ride history request for driver: {}", currentUser.getUsername());
        return forwardRequest("/api/driver/rides/history", HttpMethod.GET, null, currentUser);
    }

    private ResponseEntity<String> forwardRequest(String path, HttpMethod method, String body, CustomUserDetails user) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        
        if (user != null) {
            headers.set("X-User-Id", String.valueOf(user.getId()));
            headers.set("X-User-Name", user.getUsername());
            headers.set("X-User-Role", user.getRole());
        }
        
        HttpEntity<String> entity = new HttpEntity<>(body, headers);
        String url = driverServiceUrl + path;
        
        log.debug("Forwarding {} request to: {}", method, url);
        
        try {
            return restTemplate.exchange(url, method, entity, String.class);
        } catch (Exception e) {
            log.error("Error forwarding request to Driver Service: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                    .body("{\"success\":false,\"message\":\"Driver Service unavailable\"}");
        }
    }
}
