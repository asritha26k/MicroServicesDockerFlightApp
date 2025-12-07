package com.example;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import com.example.exception.ResourceNotFoundException;
import com.example.exception.SeatAlreadyBookedException;

@RestControllerAdvice
public class GlobalExceptionHandler {

	private record ErrorResponse(String message, String errors) {
	}

	@ExceptionHandler(MethodArgumentNotValidException.class)
	public ResponseEntity<ErrorResponse> onValidation(MethodArgumentNotValidException ex) {

		Map<String, String> validationMap = ex.getBindingResult().getFieldErrors().stream()
				.collect(Collectors.toMap(FieldError::getField, FieldError::getDefaultMessage));

		ErrorResponse er = new ErrorResponse("Validation failed", validationMap.toString());

		return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(er);
	}

	@ExceptionHandler(ResourceNotFoundException.class)
	public ResponseEntity<Map<String, String>> onNotFound(ResourceNotFoundException ex) {
		return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("message", ex.getMessage()));
	}

	@ExceptionHandler(SeatAlreadyBookedException.class)
	public ResponseEntity<Map<String, String>> handleSeatAlreadyBooked(SeatAlreadyBookedException ex) {
		Map<String, String> error = new HashMap<>();
		error.put("error", ex.getMessage());
		return ResponseEntity.status(409).body(error); // 409 = Conflict
	}
}
