package com.example.service;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import com.example.exception.ResourceNotFoundException;
import com.example.model.Address;
import com.example.model.Passenger;
import com.example.repository.PassengerRepository;
import com.example.request.PassengerDetailsRequest;
import com.example.response.PassengerDetailsResponse;

@Service
public class PassengerService {

	private final PassengerRepository passengerRepository;

	PassengerService(PassengerRepository passengerRepository) {
		this.passengerRepository = passengerRepository;
	}

	public ResponseEntity<PassengerDetailsResponse> getPassengerDetailsService(int id)
			throws ResourceNotFoundException {
		Passenger passenger = passengerRepository.findById(id)
				.orElseThrow(() -> new ResourceNotFoundException("Passenger not found"));
		PassengerDetailsResponse passengerDetails = PassengerDetailsResponse.builder().email(passenger.getEmail())
				.phoneNum(passenger.getPhoneNumber()).name(passenger.getName()).city(passenger.getAddress().getCity())
				.state(passenger.getAddress().getState()).build();
		return new ResponseEntity<>(passengerDetails, HttpStatus.OK);

	}

	public ResponseEntity<Integer> registerPassengerService(PassengerDetailsRequest req) {
		Address address = Address.builder().city(req.getCity()).state(req.getState()).houseNo(req.getHouseNo()).build();

		Passenger passenger = Passenger.builder().email(req.getEmail()).name(req.getName())
				.phoneNumber(req.getPhoneNumber()).build();
		passenger.setAddress(address);
		Passenger savedPassenger = passengerRepository.save(passenger);// saving passenger here saves address table also
		return new ResponseEntity<>(savedPassenger.getPassengerId(), HttpStatus.CREATED);

	}

	public ResponseEntity<String> deletePassengerService(int id) throws ResourceNotFoundException {
		passengerRepository.findById(id).orElseThrow(() -> new ResourceNotFoundException("Passenger not found"));

		passengerRepository.deleteById(id);
		return ResponseEntity.ok("deleted");
	}

	public ResponseEntity<Integer> getIdByEmailService(String email) throws ResourceNotFoundException {

		Passenger passenger = passengerRepository.findByEmail(email)
				.orElseThrow(() -> new ResourceNotFoundException("Passenger with this email not found"));
		Integer passengerId = passenger.getPassengerId();
		return new ResponseEntity<>(passengerId, HttpStatus.OK);
	}
}
