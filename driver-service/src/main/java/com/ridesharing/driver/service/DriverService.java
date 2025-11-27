package com.ridesharing.driver.service;

import com.ridesharing.driver.client.CustomerServiceClient;
import com.ridesharing.driver.dto.*;
import com.ridesharing.driver.entity.DriverProfile;
import com.ridesharing.driver.exception.BadRequestException;
import com.ridesharing.driver.exception.ResourceNotFoundException;
import com.ridesharing.driver.repository.DriverProfileRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;
import java.util.List;

@Service
@RequiredArgsConstructor
@Log4j2
public class DriverService {
    

    private final DriverProfileRepository driverProfileRepository;
    private final CustomerServiceClient customerServiceClient;  // Feign Client
    

    
    @Transactional
    public void updateStatus(Long userId, DriverStatus status) {
        log.info("Updating status for driver ID: {} to {}", userId, status);
        
        DriverProfile profile = driverProfileRepository.findByUserId(userId)
                .orElseThrow(() -> new ResourceNotFoundException("Driver profile not found"));
        
        profile.setStatus(status);
       driverProfileRepository.save(profile);
    }
    

    
    @Transactional(readOnly = true)
    public List<RideResponse> getPendingRides() {
        log.info("Fetching pending rides via Feign Client");
        
        ApiResponse<List<RideResponse>> response = customerServiceClient.getPendingRides();
        
        if (response != null && response.isSuccess() && response.getData() != null) {
            log.info("Found {} pending rides", response.getData().size());
            return response.getData();
        }
        
        log.warn("No pending rides found or service error");
        return Collections.emptyList();
    }
    @Transactional
    public DriverProfileResponse getOrCreateProfile(Long userId, String username, String email, String phone) {
        log.info("Getting or creating profile for driver: {} (ID: {})", username, userId);

        DriverProfile profile = driverProfileRepository.findByUserId(userId)
                .orElseGet(() -> {
                    log.info("Creating new driver profile for user: {}", username);
                    DriverProfile newProfile = DriverProfile.builder()
                            .userId(userId)
                            .username(username)
                            .email(email != null ? email : "")
                            .phone(phone != null ? phone : "")
                            .status(DriverStatus.OFFLINE)
                            .totalRides(0)
                            .build();
                    return driverProfileRepository.save(newProfile);
                });

        return mapToResponse(profile);
    }


    @Transactional
    public RideResponse assignRide(Long userId, String username, Long rideId) {
        log.info("Driver {} assigning ride ID: {} via Feign Client", username, rideId);
        
        DriverProfile profile = driverProfileRepository.findByUserId(userId)
                .orElseThrow(() -> new ResourceNotFoundException("Driver profile not found"));
        
        if (profile.getStatus() != DriverStatus.ONLINE) {
            throw new BadRequestException("You must be online to accept rides");
        }
        
        ApiResponse<RideResponse> response = customerServiceClient.assignDriver(rideId, userId, username);
        
        if (response != null && response.isSuccess() && response.getData() != null) {
            profile.setTotalRides(profile.getTotalRides() + 1);
            driverProfileRepository.save(profile);
            log.info("Successfully assigned ride {} to driver {}", rideId, username);
            return response.getData();
        }
        
        throw new BadRequestException(response != null ? response.getMessage() : "Failed to assign ride");
    }
    
    @Transactional(readOnly = true)
    public List<RideResponse> getRideHistory(Long userId) {
        log.info("Fetching ride history for driver ID: {} via Feign Client", userId);
        
        ApiResponse<List<RideResponse>> response = customerServiceClient.getDriverRideHistory(userId);
        
        if (response != null && response.isSuccess() && response.getData() != null) {
            return response.getData();
        }
        
        return Collections.emptyList();
    }

    private DriverProfileResponse mapToResponse(DriverProfile profile) {
        return DriverProfileResponse.builder()
                .id(profile.getId())
                .userId(profile.getUserId())
                .username(profile.getUsername())
                .email(profile.getEmail())
                .phone(profile.getPhone())
                .status(profile.getStatus())
                .vehicleModel(profile.getVehicleModel())
                .vehiclePlate(profile.getVehiclePlate())
                .totalRides(profile.getTotalRides())
                .createdAt(profile.getCreatedAt())
                .build();
    }

}
