package com.example.service;

import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import com.example.exception.ResourceNotFoundException;
import com.example.model.Flight;
import com.example.repository.FlightRepository;
import com.example.request.FlightRequest;
import com.example.request.SearchRequest;

@Service
public class FlightService {

	private final FlightRepository flightRepository;

	public FlightService(FlightRepository flightRepository) {
		this.flightRepository = flightRepository;
	}

	public ResponseEntity<Integer> registerFlightByIDService(FlightRequest req) {
		Flight flight = Flight.builder().airline(req.getAirline()).arrivalTime(req.getArrivalTime())
				.departureTime(req.getDepartureTime()).origin(req.getOrigin()).destination(req.getDestination())
				.price(req.getPrice()).build();
		Flight savedFlight = flightRepository.save(flight);
		return new ResponseEntity<>(savedFlight.getFlightId(), HttpStatus.CREATED);
	}

	public ResponseEntity<Flight> getByIDService(int id) throws ResourceNotFoundException {
		Flight flight = flightRepository.findById(id)
				.orElseThrow(() -> new ResourceNotFoundException("flight by this id not found"));
		return new ResponseEntity<>(flight, HttpStatus.OK);
	}

	public ResponseEntity<List<Flight>> getByOriginAndDestinationService(SearchRequest req) {
		List<Flight> listOfFlights = flightRepository.findByOriginAndDestination(req.getOrigin(), req.getDestination());
		return new ResponseEntity<>(listOfFlights, HttpStatus.OK);
	}

	public ResponseEntity<String> deleteByIDService(int id) throws ResourceNotFoundException {
		flightRepository.findById(id).orElseThrow(() -> new ResourceNotFoundException("flight by this id not found"));

		flightRepository.deleteById(id);
		return new ResponseEntity<>("deleted", HttpStatus.OK);
	}

}
