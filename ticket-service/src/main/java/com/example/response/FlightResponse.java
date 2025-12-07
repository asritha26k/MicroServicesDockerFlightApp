package com.example.response;

import java.time.LocalDateTime;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class FlightResponse {
	private int flightId;
	private Airline airline;
	private String origin;
	private String destination;
	private double price;
	private LocalDateTime departureTime;
	private LocalDateTime arrivalTime;

}