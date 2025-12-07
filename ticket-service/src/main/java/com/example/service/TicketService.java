package com.example.service;

import java.util.List;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;

import com.example.exception.ResourceNotFoundException;
import com.example.exception.SeatAlreadyBookedException;
import com.example.feign.FlightInterface;
import com.example.feign.PassengerInterface;
import com.example.model.Ticket;
import com.example.repository.TicketRepository;
import com.example.request.BookTicketRequest;
import com.example.response.FlightResponse;
import com.example.response.PassengerDetailsResponse;
import com.example.response.TicketResponse;

import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;

@Service
public class TicketService {

	private TicketRepository ticketRepository;

	private PassengerInterface passengerInterface;
	private FlightInterface flightInterface;
	private KafkaTemplate<String, String> kafkaTemplate;

	public TicketService(@Autowired TicketRepository ticketRepository, @Autowired PassengerInterface passengerInterface,
			@Autowired FlightInterface flightInterface, @Autowired KafkaTemplate<String, String> kafkaTemplate) {
		this.ticketRepository = ticketRepository;
		this.passengerInterface = passengerInterface;
		this.flightInterface = flightInterface;
		this.kafkaTemplate = kafkaTemplate;
	}

	private static final Logger logger = LoggerFactory.getLogger(TicketService.class);

	public ResponseEntity<String> bookTicketService(BookTicketRequest req) {
		boolean exists = ticketRepository.existsByFlightIdAndSeatNo(req.getFlightId(), req.getSeatNo());

		if (exists) {
			throw new SeatAlreadyBookedException("Seat already booked for this flight!");
		}

		String pnr = UUID.randomUUID().toString().substring(0, 8);

		Ticket ticket = Ticket.builder().pnr(pnr).seatNo(req.getSeatNo()).passengerId(req.getPassengerId())
				.flightId(req.getFlightId()).booked(true).build();

		ticketRepository.save(ticket);

		String event = "Ticket booked for passengerId=" + req.getPassengerId() + ", flightId=" + req.getFlightId()
				+ ", pnr=" + pnr;

		// --- HANDLE KAFKA FAILURE
		try {
			kafkaTemplate.send("ticket-confirmation", event).exceptionally(ex -> {
				logger.error("Failed to send Kafka message for PNR {}: {}", pnr, ex.getMessage());
				return null;
			});
		} catch (Exception ex) {
			logger.error("Kafka send crashed for PNR {}: {}", pnr, ex.getMessage());
		}

		return ResponseEntity.ok(pnr);
	}

	@CircuitBreaker(name = "flightService", fallbackMethod = "getByPnrFallback")
	public ResponseEntity<TicketResponse> getByPnrService(String pnr) {

		Ticket ticket = ticketRepository.findByPnr(pnr)
				.orElseThrow(() -> new ResourceNotFoundException("No ticket with this PNR"));

		// avoid NPE from Feign response
		ResponseEntity<PassengerDetailsResponse> passengerResp = passengerInterface
				.getPassengerDetails(ticket.getPassengerId());
		if (passengerResp == null || passengerResp.getBody() == null) {
			throw new ResourceNotFoundException("Passenger details unavailable");
		}
		PassengerDetailsResponse passenger = passengerResp.getBody();

		ResponseEntity<FlightResponse> flightResp = flightInterface.getByID(ticket.getFlightId());
		if (flightResp == null || flightResp.getBody() == null) {
			throw new ResourceNotFoundException("Flight details unavailable");
		}
		FlightResponse flight = flightResp.getBody();

		TicketResponse res = TicketResponse.builder().name(passenger.getName()).email(passenger.getEmail())
				.origin(flight.getOrigin()).destination(flight.getDestination()).pnr(ticket.getPnr())
				.arrivalTime(flight.getArrivalTime()).departureTime(flight.getDepartureTime()).build();

		return ResponseEntity.ok(res);
	}

	public ResponseEntity<TicketResponse> getByPnrFallback(String pnr, Throwable ex) {
		logger.warn("Fallback for getByPnrService for PNR {}: {}", pnr, ex.getMessage());
		return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(null);
	}

	@CircuitBreaker(name = "passengerService", fallbackMethod = "getTicketsByEmailFallback")
	public ResponseEntity<List<TicketResponse>> getTicketsByEmailService(String email) {

		ResponseEntity<Integer> idResp = passengerInterface.getIdByEmail(email);
		Integer passengerId = (idResp != null) ? idResp.getBody() : null;

		if (passengerId == null)
			return ResponseEntity.status(HttpStatus.NOT_FOUND).body(List.of());

		// safety check
		ResponseEntity<PassengerDetailsResponse> passengerResp = passengerInterface.getPassengerDetails(passengerId);
		if (passengerResp == null || passengerResp.getBody() == null) {
			throw new ResourceNotFoundException("Passenger details unavailable");
		}
		PassengerDetailsResponse passenger = passengerResp.getBody();

		List<Ticket> tickets = ticketRepository.findAllByPassengerId(passengerId);

		List<TicketResponse> responseList = tickets.stream().map(ticket -> {

			// safety check
			ResponseEntity<FlightResponse> fResp = flightInterface.getByID(ticket.getFlightId());
			if (fResp == null || fResp.getBody() == null) {
				throw new ResourceNotFoundException("Flight details unavailable");
			}
			FlightResponse flight = fResp.getBody();

			return TicketResponse.builder().name(passenger.getName()).email(passenger.getEmail())
					.origin(flight.getOrigin()).destination(flight.getDestination()).pnr(ticket.getPnr())
					.arrivalTime(flight.getArrivalTime()).departureTime(flight.getDepartureTime()).build();

		}).toList();

		return ResponseEntity.ok(responseList);
	}

	public ResponseEntity<List<TicketResponse>> getTicketsByEmailFallback(String email, Throwable ex) {
		logger.warn("Fallback for getTicketsByEmailService for email {}: {}", email, ex.getMessage());
		return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(List.of());
	}
}
