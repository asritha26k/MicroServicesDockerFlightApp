package com.example.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.when;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.example.exception.ResourceNotFoundException;
import com.example.model.Airline;
import com.example.model.Flight;
import com.example.repository.FlightRepository;
import com.example.request.FlightRequest;
import com.example.request.SearchRequest;

@ExtendWith(MockitoExtension.class)
class FlightServiceTest {

	@Mock
	private FlightRepository flightRepository;

	@InjectMocks
	private FlightService flightService;

	private Flight createFlight() {
		return Flight.builder().flightId(1).airline(Airline.INDIGO).origin("DEL").destination("HYD").price(5000)
				.arrivalTime(LocalDateTime.now().plusDays(2)).departureTime(LocalDateTime.now().plusDays(1)).build();
	}

	private FlightRequest createRequest() {
		return FlightRequest.builder().airline(Airline.INDIGO).origin("DEL").destination("HYD").price(5000)
				.departureTime(LocalDateTime.now().plusDays(1)).arrivalTime(LocalDateTime.now().plusDays(2)).build();
	}

	@Test
	void testRegisterFlight() {
		Flight flight = createFlight();
		FlightRequest req = createRequest();

		when(flightRepository.save(any(Flight.class))).thenReturn(flight);

		var response = flightService.registerFlightByIDService(req);
		assertEquals(201, response.getStatusCode().value());
		assertEquals(1, response.getBody());
	}

	@Test
	void testGetById_Success() throws Exception {
		Flight flight = createFlight();
		when(flightRepository.findById(1)).thenReturn(Optional.of(flight));

		var response = flightService.getByIDService(1);
		assertEquals(200, response.getStatusCode().value());
		assertEquals("DEL", response.getBody().getOrigin());
	}

	@Test
	void testGetById_NotFound() {
		when(flightRepository.findById(1)).thenReturn(Optional.empty());

		assertThrows(ResourceNotFoundException.class, () -> {
			flightService.getByIDService(1);
		});
	}

	@Test
	void testSearchByOriginDestination() {
		Flight flight = createFlight();
		SearchRequest req = new SearchRequest("DEL", "HYD");

		when(flightRepository.findByOriginAndDestination("DEL", "HYD")).thenReturn(Arrays.asList(flight));

		var response = flightService.getByOriginAndDestinationService(req);
		assertEquals(200, response.getStatusCode().value());

		assertEquals(1, response.getBody().size());
	}

	@Test
	void testDelete_Success() throws Exception {
		Flight flight = createFlight();

		when(flightRepository.findById(1)).thenReturn(Optional.of(flight));
		doNothing().when(flightRepository).deleteById(1);

		var response = flightService.deleteByIDService(1);

		assertEquals(200, response.getStatusCode().value());
		assertEquals("deleted", response.getBody());
	}

	@Test
	void testDelete_NotFound() {
		when(flightRepository.findById(1)).thenReturn(Optional.empty());

		assertThrows(ResourceNotFoundException.class, () -> {
			flightService.deleteByIDService(1);
		});
	}
}
