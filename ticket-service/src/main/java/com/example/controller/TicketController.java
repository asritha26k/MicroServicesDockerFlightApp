package com.example.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.exception.ResourceNotFoundException;
import com.example.request.BookTicketRequest;
import com.example.response.TicketResponse;
import com.example.service.TicketService;

import jakarta.validation.Valid;

@RestController
@RequestMapping("ticket")
public class TicketController {

	private final TicketService ticketService;

	TicketController(@Autowired TicketService ticketService) {
		this.ticketService = ticketService;
	}

	// we return pnr
	@PostMapping("book")
	public ResponseEntity<String> bookTicket(@Valid @RequestBody BookTicketRequest req) {
		return ticketService.bookTicketService(req);

	}

	@GetMapping("getByPnr/{pnr}")
	public ResponseEntity<TicketResponse> getByPnr(@PathVariable String pnr) throws ResourceNotFoundException {
		return ticketService.getByPnrService(pnr);
	}

	@GetMapping("getTicketsByEmail/{email}")
	public ResponseEntity<List<TicketResponse>> getTicketsByEmail(@PathVariable String email)
			throws ResourceNotFoundException {
		return ticketService.getTicketsByEmailService(email);
	}
}
