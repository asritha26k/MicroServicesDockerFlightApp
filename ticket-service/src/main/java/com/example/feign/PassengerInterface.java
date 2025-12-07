package com.example.feign;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

import com.example.exception.ResourceNotFoundException;
import com.example.response.PassengerDetailsResponse;

@FeignClient(name = "PASSENGER-SERVICE")
public interface PassengerInterface {
	// get request by id
	@GetMapping("/passenger/getByPassengerId/{id}")
	public ResponseEntity<PassengerDetailsResponse> getPassengerDetails(@PathVariable int id)
			throws ResourceNotFoundException;

	// get id by email
	@GetMapping("/passenger/getPassengerIdByEmail/{email}")
	public ResponseEntity<Integer> getIdByEmail(@PathVariable String email) throws ResourceNotFoundException;
}
