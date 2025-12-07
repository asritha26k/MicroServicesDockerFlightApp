package com.example.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.example.model.Flight;

@Repository
public interface FlightRepository extends JpaRepository<Flight, Integer> {
	List<Flight> findByOrigin(String origin);

	List<Flight> findByDestination(String destination);

	List<Flight> findByOriginAndDestination(String origin, String destination);
}
