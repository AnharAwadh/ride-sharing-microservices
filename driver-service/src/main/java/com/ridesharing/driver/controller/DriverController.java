package com.ridesharing.driver.controller;

import com.ridesharing.driver.dto.*;
import com.ridesharing.driver.security.CurrentUser;
import com.ridesharing.driver.security.UserPrincipal;
import com.ridesharing.driver.service.DriverService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;


@RestController
@RequestMapping("/api/driver")
@RequiredArgsConstructor
@Log4j2
public class DriverController {


    private final DriverService driverService;


    @GetMapping("/profile")
    @PreAuthorize("hasRole('DRIVER')")
    public ResponseEntity<ApiResponse<DriverProfileResponse>> getProfile(
            @CurrentUser UserPrincipal currentUser) {

        log.info("Fetching profile for authenticated driver: {} (ID: {})",
                currentUser.getUsername(), currentUser.getId());

        DriverProfileResponse profile = driverService.getOrCreateProfile(
                currentUser.getId(),
                currentUser.getUsername(),
                null,
                null
        );
        return ResponseEntity.ok(ApiResponse.success(profile));
    }


    @PutMapping("/status")
    @PreAuthorize("hasRole('DRIVER')")
    public ResponseEntity<ApiResponse<String>> updateStatus(
            @CurrentUser UserPrincipal currentUser,
            @Valid @RequestBody UpdateStatusRequest request) {

        log.info("Updating status for authenticated driver: {} to {}",
                currentUser.getUsername(), request.getStatus());

        driverService.updateStatus(currentUser.getId(), request.getStatus());
        return ResponseEntity.ok(ApiResponse.success("Status updated successfully"));
    }


    @GetMapping("/rides/available")
    @PreAuthorize("hasRole('DRIVER')")
    public ResponseEntity<ApiResponse<List<RideResponse>>> getAvailableRides(
            @CurrentUser UserPrincipal currentUser) {

        log.info("Authenticated driver {} fetching available rides", currentUser.getUsername());

        List<RideResponse> rides = driverService.getPendingRides();
        return ResponseEntity.ok(ApiResponse.success(rides));
    }


    @PostMapping("/rides/{rideId}/accept")
    @PreAuthorize("hasRole('DRIVER')")
    public ResponseEntity<ApiResponse<RideResponse>> acceptRide(
            @CurrentUser UserPrincipal currentUser,
            @PathVariable Long rideId) {

        log.info("Authenticated driver {} accepting ride ID: {}", currentUser.getUsername(), rideId);

        RideResponse ride = driverService.assignRide(currentUser.getId(), currentUser.getUsername(), rideId);
        return ResponseEntity.ok(ApiResponse.success("Ride accepted successfully", ride));
    }


    @GetMapping("/rides/history")
    @PreAuthorize("hasRole('DRIVER')")
    public ResponseEntity<ApiResponse<List<RideResponse>>> getRideHistory(
            @CurrentUser UserPrincipal currentUser) {

        log.info("Fetching ride history for authenticated driver: {}", currentUser.getUsername());

        List<RideResponse> rides = driverService.getRideHistory(currentUser.getId());
        return ResponseEntity.ok(ApiResponse.success(rides));
    }


}
