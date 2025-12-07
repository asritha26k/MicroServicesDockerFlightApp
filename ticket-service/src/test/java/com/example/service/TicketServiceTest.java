package com.example.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.kafka.core.KafkaTemplate;

import com.example.feign.FlightInterface;
import com.example.feign.PassengerInterface;
import com.example.model.Ticket;
import com.example.repository.TicketRepository;
import com.example.request.BookTicketRequest;
import com.example.response.FlightResponse;
import com.example.response.PassengerDetailsResponse;
import com.example.response.TicketResponse;

class TicketServiceTest {

	@InjectMocks
	private TicketService ticketService;

	@Mock
	private TicketRepository ticketRepository;

	@Mock
	private PassengerInterface passengerInterface;

	@Mock
	private FlightInterface flightInterface;
	@Mock
	private KafkaTemplate<String, Object> kafkaTemplate;

	@BeforeEach
	void init() {
		MockitoAnnotations.openMocks(this);
	}

	@Test
	void testBookTicketService() {
		BookTicketRequest req = new BookTicketRequest();
		req.setFlightId(1);
		req.setPassengerId(10);
		req.setSeatNo("A1");

		when(ticketRepository.save(any(Ticket.class))).thenAnswer(i -> i.getArguments()[0]);

		ResponseEntity<String> response = ticketService.bookTicketService(req);

		assertEquals(HttpStatus.OK, response.getStatusCode());
		assertNotNull(response.getBody());
		assertEquals(8, response.getBody().length()); // PNR is 8 chars
	}

	@Test
	void testBookTicketServicee() {
		BookTicketRequest req = new BookTicketRequest();
		req.setFlightId(1);
		req.setPassengerId(10);
		req.setSeatNo("A1");

		when(ticketRepository.save(any(Ticket.class))).thenAnswer(i -> i.getArguments()[0]);

		when(kafkaTemplate.send(any(), any())).thenReturn(CompletableFuture.completedFuture(null));

		ResponseEntity<String> response = ticketService.bookTicketService(req);

		assertEquals(HttpStatus.OK, response.getStatusCode());
		assertNotNull(response.getBody());
		assertEquals(8, response.getBody().length()); // PNR is 8 chars
	}

	@Test
	void testGetByPnrServiceSuccess() {

		Ticket ticket = Ticket.builder().pnr("ABC12345").seatNo("A1").flightId(1).passengerId(10).booked(true).build();

		when(ticketRepository.findByPnr("ABC12345")).thenReturn(Optional.of(ticket));

		PassengerDetailsResponse passenger = new PassengerDetailsResponse();
		passenger.setName("John");
		passenger.setEmail("john@gmail.com");

		when(passengerInterface.getPassengerDetails(10)).thenReturn(ResponseEntity.ok(passenger));

		FlightResponse flight = new FlightResponse();
		flight.setOrigin("HYD");
		flight.setDestination("DEL");
		flight.setDepartureTime(LocalDateTime.now());
		flight.setArrivalTime(LocalDateTime.now().plusHours(2));

		when(flightInterface.getByID(1)).thenReturn(ResponseEntity.ok(flight));

		ResponseEntity<TicketResponse> response = ticketService.getByPnrService("ABC12345");

		assertEquals(HttpStatus.OK, response.getStatusCode());
		assertEquals("John", response.getBody().getName());
		assertEquals("HYD", response.getBody().getOrigin());
	}

	@Test
	void testGetTicketsByEmailServiceSuccess() {

		when(passengerInterface.getIdByEmail("abc@gmail.com")).thenReturn(ResponseEntity.ok(10));

		PassengerDetailsResponse passenger = new PassengerDetailsResponse();
		passenger.setName("John");
		passenger.setEmail("abc@gmail.com");
		when(passengerInterface.getPassengerDetails(10)).thenReturn(ResponseEntity.ok(passenger));

		Ticket t1 = Ticket.builder().pnr("PNR1").flightId(1).passengerId(10).build();
		Ticket t2 = Ticket.builder().pnr("PNR2").flightId(2).passengerId(10).build();

		when(ticketRepository.findAllByPassengerId(10)).thenReturn(Arrays.asList(t1, t2));

		FlightResponse fr1 = new FlightResponse();
		fr1.setOrigin("HYD");
		fr1.setDestination("DEL");

		FlightResponse fr2 = new FlightResponse();
		fr2.setOrigin("BLR");
		fr2.setDestination("DEL");

		when(flightInterface.getByID(1)).thenReturn(ResponseEntity.ok(fr1));
		when(flightInterface.getByID(2)).thenReturn(ResponseEntity.ok(fr2));

		ResponseEntity<List<TicketResponse>> response = ticketService.getTicketsByEmailService("abc@gmail.com");

		assertEquals(HttpStatus.OK, response.getStatusCode());
		assertEquals(2, response.getBody().size());
	}

	@Test
	void testGetByPnrServiceFallback() {

		Throwable t = new RuntimeException("DOWN");

		ResponseEntity<TicketResponse> response = ticketService.getByPnrFallback("ABC12345", t);

		assertEquals(503, response.getStatusCode().value());
		assertNull(response.getBody());
	}

	@Test
	void testGetTicketsByEmailFallback() {

		Throwable ex = new RuntimeException("DOWN");

		ResponseEntity<List<TicketResponse>> response = ticketService.getTicketsByEmailFallback("abc@gmail.com", ex);

		assertEquals(HttpStatus.SERVICE_UNAVAILABLE, response.getStatusCode());

		assertNotNull(response.getBody());
		assertTrue(response.getBody().isEmpty());
	}

}
