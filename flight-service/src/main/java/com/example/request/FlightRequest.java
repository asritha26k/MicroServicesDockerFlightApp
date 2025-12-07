package com.example.request;

import java.time.LocalDateTime;

import com.example.model.Airline;

import jakarta.validation.constraints.Future;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class FlightRequest {
	@NotNull
	private Airline airline;
	@NotNull
	private String origin;
	@NotNull
	private String destination;
	@Positive
	private double price;
	@NotNull
	@Future
	private LocalDateTime departureTime;
	@NotNull
	@Future
	private LocalDateTime arrivalTime;

}
