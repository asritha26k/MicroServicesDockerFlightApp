package com.example.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "tickets", uniqueConstraints = { @UniqueConstraint(columnNames = { "flight_id", "seat_no" }) })
public class Ticket {
	@Id
	@GeneratedValue(strategy = GenerationType.SEQUENCE)
	private int ticketId;
	@Column(name = "pnr", unique = true)
	private String pnr;

	@Column(name = "seat_no")
	private String seatNo;

	@Column(name = "flight_id")
	private int flightId;

	@Column(name = "passenger_id")
	private int passengerId;

	@Column(name = "booked")
	private boolean booked;

}
