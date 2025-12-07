package com.example.controller;

import java.util.List;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.exception.ResourceNotFoundException;
import com.example.model.Flight;
import com.example.request.FlightRequest;
import com.example.request.SearchRequest;
import com.example.service.FlightService;

import jakarta.validation.Valid;

@RestController
@RequestMapping("flight")
class FlightController {

	private final FlightService flightService;

	public FlightController(FlightService flightService) {
		this.flightService = flightService;
	}

	@PostMapping("register")
	public ResponseEntity<Integer> registerFlightByID(@Valid @RequestBody FlightRequest req) {
		return flightService.registerFlightByIDService(req);

	}

	@GetMapping("getFlightById/{id}")
	public ResponseEntity<Flight> getByID(@PathVariable int id) throws ResourceNotFoundException {
		return flightService.getByIDService(id);
	}

	@GetMapping("getByOriginDestination")
	public ResponseEntity<List<Flight>> getByOriginAndDestination(@Valid @RequestBody SearchRequest req) {
		return flightService.getByOriginAndDestinationService(req);

	}

	@DeleteMapping("delete/{id}")
	public ResponseEntity<String> deleteById(@PathVariable int id) throws ResourceNotFoundException {
		return flightService.deleteByIDService(id);
	}

}
