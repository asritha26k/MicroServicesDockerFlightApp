package com.example.exception;

import java.util.HashMap;
import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class TicketExceptionHandler {

	@ExceptionHandler(SeatAlreadyBookedException.class)
	public ResponseEntity<Map<String, String>> handleSeatAlreadyBooked(SeatAlreadyBookedException ex) {
		Map<String, String> error = new HashMap<>();
		error.put("error", ex.getMessage());
		return ResponseEntity.status(409).body(error);
	}
}
