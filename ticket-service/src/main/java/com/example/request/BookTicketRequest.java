package com.example.request;

import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor

public class BookTicketRequest {
	@NotNull
	private Integer flightId;
	@NotNull
	private Integer passengerId;
	@NotNull
	private String seatNo;
}
