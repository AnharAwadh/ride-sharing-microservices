package com.ridesharing.driver.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DriverProfileResponse {
    private Long id;
    private Long userId;
    private String username;
    private String email;
    private String phone;
    private DriverStatus status;
    private String vehicleModel;
    private String vehiclePlate;
    private Integer totalRides;
    private LocalDateTime createdAt;
}