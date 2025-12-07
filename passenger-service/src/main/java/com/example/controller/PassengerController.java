package com.example.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.exception.ResourceNotFoundException;
import com.example.request.PassengerDetailsRequest;
import com.example.response.PassengerDetailsResponse;
import com.example.service.PassengerService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;

@RequestMapping("passenger")
@RestController
public class PassengerController {

	private final PassengerService passengerService;

	PassengerController(PassengerService passengerService) {
		this.passengerService = passengerService;
	}

	@GetMapping("/debug")
	public String debug(HttpServletRequest request) {
		String auth = request.getHeader("Authorization");
		System.out.println("PASSENGER SERVICE RECEIVED TOKEN = " + auth);
		return auth;
	}

	// get request by id
	@GetMapping("getByPassengerId/{id}")
	public ResponseEntity<PassengerDetailsResponse> getPassengerDetails(@PathVariable int id)
			throws ResourceNotFoundException {
		return passengerService.getPassengerDetailsService(id);
	}

	// get id by email
	@GetMapping("getPassengerIdByEmail/{email}")
	public ResponseEntity<Integer> getIdByEmail(@PathVariable String email) throws ResourceNotFoundException {
		return passengerService.getIdByEmailService(email);
	}

	// post request
	@PostMapping("register")
	public ResponseEntity<Integer> registerPassenger(@Valid @RequestBody PassengerDetailsRequest req) {
		return passengerService.registerPassengerService(req);

	}

	// delete request
	@DeleteMapping("delete/{id}")
	public ResponseEntity<String> deletePassenger(@PathVariable int id) throws ResourceNotFoundException {
		return passengerService.deletePassengerService(id);
	}

}
