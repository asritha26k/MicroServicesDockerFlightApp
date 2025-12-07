package com.example.controller;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import com.example.GlobalExceptionHandler;
import com.example.exception.ResourceNotFoundException;
import com.example.model.Address;
import com.example.model.Passenger;
import com.example.request.PassengerDetailsRequest;
import com.example.response.PassengerDetailsResponse;
import com.example.service.PassengerService;
import com.fasterxml.jackson.databind.ObjectMapper;

@ExtendWith(MockitoExtension.class)
class PassengerControllerTest {
	MockMvc mockMvc;
	@Mock
	PassengerService passengerService;
	@InjectMocks
	PassengerController passengerController;
	ObjectMapper mapper;

	@BeforeEach
	void setUp() {
		mapper = new ObjectMapper();
		mockMvc = MockMvcBuilders.standaloneSetup(passengerController).setControllerAdvice(new GlobalExceptionHandler())
				.build();

	}

	public Passenger createPassenger() {
		Passenger passenger = Passenger.builder().email("test@example.com").name("test").phoneNumber("123").build();
		Address address = Address.builder().city("city").state("state").houseNo("1").build();
		passenger.setAddress(address);
		return passenger;
	}

	public PassengerDetailsResponse createResponse() {
		Passenger passenger = createPassenger();
		return PassengerDetailsResponse.builder().email(passenger.getEmail()).name(passenger.getName())
				.phoneNum(passenger.getPhoneNumber()).build();
	}

	public PassengerDetailsRequest createRequest() {
		Passenger passenger = createPassenger();
		return PassengerDetailsRequest.builder().city(passenger.getAddress().getCity())
				.houseNo(passenger.getAddress().getState()).email(passenger.getEmail()).name(passenger.getName())
				.state(passenger.getAddress().getState()).phoneNumber(passenger.getPhoneNumber()).build();

	}

	@Test
	void testPassengerDetails() throws Exception {

		PassengerDetailsResponse response = createResponse();

		Mockito.when(passengerService.getPassengerDetailsService(anyInt()))
				.thenReturn(ResponseEntity.status(HttpStatus.CREATED).body(response));

		mockMvc.perform(get("/passenger/getByPassengerId/1")).andExpect(status().isCreated())
				.andExpect(jsonPath("$.name").value("test"));
	}

	@Test
	void testGetIdByEmail() throws Exception {

		Mockito.when(passengerService.getIdByEmailService(anyString()))
				.thenReturn(ResponseEntity.status(HttpStatus.OK).body(1));

		mockMvc.perform(get("/passenger/getPassengerIdByEmail/test@example.com")).andExpect(status().isOk())
				.andExpect(jsonPath("$").value(1));
	}

	@Test
	void testRegisterPassenger() throws Exception {

		PassengerDetailsRequest request = createRequest();

		Mockito.when(passengerService.registerPassengerService(any(PassengerDetailsRequest.class)))
				.thenReturn(ResponseEntity.status(HttpStatus.OK).body(1));

		mockMvc.perform(post("/passenger/register").contentType(MediaType.APPLICATION_JSON)
				.content(mapper.writeValueAsString(request))).andExpect(status().isOk())
				.andExpect(jsonPath("$").value(1));
	}

	@Test
	void testDeletePassenger() throws Exception {

		Mockito.when(passengerService.deletePassengerService(anyInt()))
				.thenReturn(ResponseEntity.status(HttpStatus.OK).body("deleted"));

		mockMvc.perform(delete("/passenger/delete/1")).andExpect(status().isOk())
				.andExpect(content().string("deleted"));
	}

	@Test
	void testHandleValidationErrors() throws Exception {

		String invalidJson = "{}";

		mockMvc.perform(post("/passenger/register").contentType(MediaType.APPLICATION_JSON).content(invalidJson))
				.andExpect(status().isBadRequest()).andExpect(jsonPath("$.errors").exists());
	}

	@Test
	void testHandleResourceNotFound() throws Exception {

		Mockito.when(passengerService.getPassengerDetailsService(1))
				.thenThrow(new ResourceNotFoundException("Passenger not found"));

		mockMvc.perform(get("/passenger/getByPassengerId/1")).andExpect(status().isNotFound())
				.andExpect(jsonPath("$.message").value("Passenger not found"));
	}

}
