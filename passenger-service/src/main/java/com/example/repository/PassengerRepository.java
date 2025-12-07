package com.example.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.example.model.Passenger;

@Repository
public interface PassengerRepository extends JpaRepository<Passenger, Integer> {
	Optional<Passenger> findByEmail(String email);

}
