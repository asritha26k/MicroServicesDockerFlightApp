package com.example.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.example.model.Ticket;

@Repository
public interface TicketRepository extends JpaRepository<Ticket, Integer> {
	Optional<Ticket> findByPnr(String pnr);

	List<Ticket> findAllByPassengerId(int passengerId);

	boolean existsByFlightIdAndSeatNo(Integer flightId, String seatNo);

	boolean existsByFlightIdAndPassengerId(Integer flightId, Integer passengerId);
}
