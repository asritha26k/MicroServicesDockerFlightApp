package com.example.feign;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

import com.example.exception.ResourceNotFoundException;
import com.example.response.FlightResponse;

@FeignClient(name = "FLIGHT-SERVICE")

public interface FlightInterface {
	@GetMapping("/flight/getFlightById/{id}")
	public ResponseEntity<FlightResponse> getByID(@PathVariable int id) throws ResourceNotFoundException;
}
