package com.example.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;

import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import com.example.exception.ResourceNotFoundException;
import com.example.model.Address;
import com.example.model.Passenger;
import com.example.repository.AddressRepository;
import com.example.repository.PassengerRepository;
import com.example.request.PassengerDetailsRequest;
import com.example.response.PassengerDetailsResponse;

@ExtendWith(MockitoExtension.class)
class PassengerServiceTest {
	@InjectMocks
	private PassengerService passengerService;

	@Mock
	private PassengerRepository passengerRepository;

	@Mock
	private AddressRepository addressRepository;

	@Test
	void testGetPassengerDetailsService_Success() throws Exception {
		Passenger passenger = Passenger.builder().passengerId(1).name("John").email("john@gmail.com")
				.phoneNumber("12345").build();

		Mockito.when(passengerRepository.findById(1)).thenReturn(Optional.of(passenger));

		ResponseEntity<PassengerDetailsResponse> response = passengerService.getPassengerDetailsService(1);

		assertEquals(HttpStatus.OK, response.getStatusCode());
		assertEquals("John", response.getBody().getName());
		assertEquals("john@gmail.com", response.getBody().getEmail());
	}

	@Test
	void testGetPassengerDetailsService_NotFound() {
		Mockito.when(passengerRepository.findById(1)).thenReturn(Optional.empty());

		assertThrows(ResourceNotFoundException.class, () -> {
			passengerService.getPassengerDetailsService(1);
		});
	}

	@Test
	void testRegisterPassengerService() {

		PassengerDetailsRequest req = PassengerDetailsRequest.builder().name("John").email("john@gmail.com")
				.phoneNumber("12345").city("Hyd").houseNo("10-2").state("TS").build();

		Passenger saved = Passenger.builder().passengerId(100).name("John").email("john@gmail.com").phoneNumber("12345")
				.address(new Address()).build();

		Mockito.when(passengerRepository.save(any(Passenger.class))).thenReturn(saved);

		ResponseEntity<Integer> response = passengerService.registerPassengerService(req);

		assertEquals(HttpStatus.CREATED, response.getStatusCode());
		assertEquals(100, response.getBody());
		Mockito.verify(passengerRepository, times(1)).save(any(Passenger.class));
	}

	@Test
	void testDeletePassengerService_NotFound() {
		Mockito.when(passengerRepository.findById(1)).thenReturn(Optional.empty());

		assertThrows(ResourceNotFoundException.class, () -> {
			passengerService.deletePassengerService(1);
		});
	}

	@Test
	void testGetIdByEmailService_Success() throws Exception {

		Passenger passenger = Passenger.builder().passengerId(15).email("abc@gmail.com").build();

		Mockito.when(passengerRepository.findByEmail("abc@gmail.com")).thenReturn(Optional.of(passenger));

		ResponseEntity<Integer> response = passengerService.getIdByEmailService("abc@gmail.com");

		assertEquals(HttpStatus.OK, response.getStatusCode());
		assertEquals(15, response.getBody());
	}

	@Test
	void testGetIdByEmailService_NotFound() {

		Mockito.when(passengerRepository.findByEmail("abc@gmail.com")).thenReturn(Optional.empty());

		assertThrows(ResourceNotFoundException.class, () -> {
			passengerService.getIdByEmailService("abc@gmail.com");
		});
	}

	@Test
	void testDeletePassengerService_Success() throws Exception {

		Passenger passenger = Passenger.builder().passengerId(1).name("John").email("john@gmail.com")
				.phoneNumber("12345").build();

		Mockito.when(passengerRepository.findById(1)).thenReturn(Optional.of(passenger));

		ResponseEntity<String> response = passengerService.deletePassengerService(1);

		assertEquals(HttpStatus.OK, response.getStatusCode());
		assertEquals("deleted", response.getBody());

		Mockito.verify(passengerRepository, times(1)).deleteById(1);
	}

}
